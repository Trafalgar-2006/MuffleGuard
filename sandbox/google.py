"""Read-only Google Workspace OAuth and API access for an explicitly connected run."""

from __future__ import annotations

import base64
import json
import secrets
import threading
import time
from email.header import decode_header, make_header
from urllib.parse import urlencode, quote

import httpx

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GMAIL_URL = "https://gmail.googleapis.com/gmail/v1/users/me"
DRIVE_URL = "https://www.googleapis.com/drive/v3"
SCOPES = (
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
)
MAX_FILE_BYTES = 1_000_000
MAX_GOOGLE_JSON_BYTES = 2_000_000


class GoogleAuthError(RuntimeError):
    """A safe, user-facing connection or Google API error."""


class GoogleConnector:
    """Keep Google credentials in memory and bind them to an unguessable cookie."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        client: httpx.Client | None = None,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.enabled = bool(client_id and client_secret and redirect_uri.startswith("https://"))
        self.client = client or httpx.Client(timeout=20, follow_redirects=False)
        self._tokens: dict[str, dict] = {}
        self._pending: dict[str, tuple[str, float]] = {}
        self._lock = threading.RLock()

    def begin(self, session_id: str) -> str:
        if not self.enabled:
            raise GoogleAuthError("Google connection is not configured.")
        state = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._pending = {key: value for key, value in self._pending.items() if value[1] > now}
            if len(self._pending) >= 256:
                oldest = min(self._pending, key=lambda key: self._pending[key][1])
                del self._pending[oldest]
            self._pending[state] = (session_id, now + 600)
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(SCOPES),
            "access_type": "offline",
            "include_granted_scopes": "true",
            "prompt": "consent",
            "state": state,
        }
        return f"{AUTH_URL}?{urlencode(params)}"

    def finish(self, session_id: str, state: str, code: str) -> None:
        with self._lock:
            pending = self._pending.get(state)
            if not pending or pending[1] <= time.time() or not secrets.compare_digest(pending[0], session_id):
                raise GoogleAuthError("Google sign-in expired or could not be verified. Try again.")
            del self._pending[state]
        try:
            response = self.client.post(
                TOKEN_URL,
                data={
                    "code": code,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "redirect_uri": self.redirect_uri,
                    "grant_type": "authorization_code",
                },
            )
            response.raise_for_status()
            token = response.json()
            access_token = token.get("access_token")
            granted = token.get("scope")
            if granted is not None and (
                not isinstance(granted, str) or not set(SCOPES).issubset(granted.split())
            ):
                raise GoogleAuthError("Google did not grant all required read-only access.")
            if not isinstance(access_token, str) or not access_token or len(access_token) > 2048:
                raise ValueError("missing access token")
        except GoogleAuthError:
            raise
        except Exception as exc:
            raise GoogleAuthError("Google sign-in failed. Check the OAuth client settings and try again.") from exc
        with self._lock:
            self._tokens[session_id] = {
                "access_token": token["access_token"],
                "refresh_token": token.get("refresh_token", ""),
                "expires_at": time.time() + int(token.get("expires_in", 3600)),
                "last_used": time.time(),
            }
            while len(self._tokens) > 100:
                oldest = min(self._tokens, key=lambda key: self._tokens[key]["last_used"])
                del self._tokens[oldest]

    def is_connected(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self._tokens

    def workspace(self, session_id: str) -> GoogleWorkspace | None:
        return GoogleWorkspace(self, session_id) if self.is_connected(session_id) else None

    def disconnect(self, session_id: str) -> None:
        with self._lock:
            token = self._tokens.pop(session_id, None)
        if token:
            try:
                self.client.post(REVOKE_URL, data={"token": token.get("refresh_token") or token["access_token"]})
            except Exception:
                pass

    def _access_token(self, session_id: str) -> str:
        with self._lock:
            token = self._tokens.get(session_id)
            if not token:
                raise GoogleAuthError("Reconnect your Google account and try again.")
            token["last_used"] = time.time()
            if token["expires_at"] > time.time() + 60:
                return token["access_token"]
            refresh = token["refresh_token"]
            if not refresh:
                del self._tokens[session_id]
                raise GoogleAuthError("Reconnect your Google account and try again.")
            try:
                response = self.client.post(
                    TOKEN_URL,
                    data={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "refresh_token": refresh,
                        "grant_type": "refresh_token",
                    },
                )
                response.raise_for_status()
                renewed = response.json()
                token["access_token"] = renewed["access_token"]
                token["expires_at"] = time.time() + int(renewed.get("expires_in", 3600))
                return token["access_token"]
            except Exception as exc:
                del self._tokens[session_id]
                raise GoogleAuthError("Google access expired. Reconnect your account and try again.") from exc

    def _get_json(self, session_id: str, url: str, **kwargs) -> dict:
        for attempt in range(2):
            try:
                with self.client.stream(
                    "GET", url, headers={"Authorization": f"Bearer {self._access_token(session_id)}"}, **kwargs
                ) as response:
                    if response.status_code == 401 and attempt == 0:
                        with self._lock:
                            token = self._tokens.get(session_id)
                            if token:
                                token["expires_at"] = 0
                        continue
                    response.raise_for_status()
                    if int(response.headers.get("content-length", "0") or 0) > MAX_GOOGLE_JSON_BYTES:
                        raise GoogleAuthError("Google response is larger than 2 MB; try a smaller request.")
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > MAX_GOOGLE_JSON_BYTES:
                            raise GoogleAuthError("Google response is larger than 2 MB; try a smaller request.")
                result = json.loads(content)
                if not isinstance(result, dict):
                    raise ValueError("invalid response")
                return result
            except GoogleAuthError:
                raise
            except Exception as exc:
                raise GoogleAuthError("Google could not read that data. Reconnect and try again.") from exc
        raise GoogleAuthError("Google access expired. Reconnect your account and try again.")

    def _get_bytes(self, session_id: str, url: str, **kwargs) -> bytes:
        for attempt in range(2):
            try:
                with self.client.stream(
                    "GET", url, headers={"Authorization": f"Bearer {self._access_token(session_id)}"}, **kwargs
                ) as response:
                    if response.status_code == 401 and attempt == 0:
                        with self._lock:
                            token = self._tokens.get(session_id)
                            if token:
                                token["expires_at"] = 0
                        continue
                    response.raise_for_status()
                    if int(response.headers.get("content-length", "0") or 0) > MAX_FILE_BYTES:
                        raise GoogleAuthError("That file is larger than the 1 MB read limit.")
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > MAX_FILE_BYTES:
                            raise GoogleAuthError("That file is larger than the 1 MB read limit.")
                    return bytes(content)
            except GoogleAuthError:
                raise
            except Exception as exc:
                raise GoogleAuthError("Google could not read that file. Check access and try again.") from exc
        raise GoogleAuthError("Google access expired. Reconnect your account and try again.")


class GoogleWorkspace:
    """Per-run read-only Gmail and Drive tools; sends and posts remain simulated."""

    def __init__(self, connector: GoogleConnector, session_id: str) -> None:
        self.connector = connector
        self.session_id = session_id
        self.message_ids: dict[int, str] = {}

    def inbox_list(self, unread_only: bool) -> tuple[str, str]:
        params = {"maxResults": 10, "q": "in:inbox is:unread" if unread_only else "in:inbox"}
        listing = self.connector._get_json(self.session_id, f"{GMAIL_URL}/messages", params=params)
        self.message_ids = {}
        lines = []
        for index, item in enumerate(listing.get("messages", [])[:10], start=1):
            message_id = item.get("id")
            if not isinstance(message_id, str):
                continue
            self.message_ids[index] = message_id
            metadata = self.connector._get_json(
                self.session_id,
                f"{GMAIL_URL}/messages/{quote(message_id, safe='')}",
                params={"format": "metadata", "metadataHeaders": ["From", "Subject"]},
            )
            headers = {h.get("name", "").lower(): h.get("value", "")
                       for h in metadata.get("payload", {}).get("headers", [])}
            lines.append(f"#{index} from {headers.get('from', 'unknown')}: {headers.get('subject', '(no subject)')}")
        if listing.get("nextPageToken"):
            lines.append("Only the first 10 messages are listed in this run.")
        return "\n".join(lines), "your Gmail inbox listing"

    def inbox_read(self, email_id: int) -> tuple[str, str]:
        message_id = self.message_ids.get(int(email_id))
        if not message_id:
            return "No such email. List your inbox first.", "your Gmail inbox"
        message = self.connector._get_json(
            self.session_id,
            f"{GMAIL_URL}/messages/{quote(message_id, safe='')}",
            params={"format": "full"},
        )
        payload = message.get("payload", {})
        headers = {h.get("name", "").lower(): h.get("value", "") for h in payload.get("headers", [])}
        sender = _decode_header(headers.get("from", "unknown"))
        subject = _decode_header(headers.get("subject", "(no subject)"))
        body = _message_text(payload) or str(message.get("snippet", ""))
        return f"From: {sender}\nSubject: {subject}\n\n{body[:30000]}", f"Gmail message from {sender}"

    def files_read(self, name: str) -> tuple[str, str]:
        name = name.strip()
        if not name or len(name) > 200:
            return "Enter a file name of 1 to 200 characters.", "your Google Drive"
        escaped = name.replace("\\", "\\\\").replace("'", "\\'")
        listing = self.connector._get_json(
            self.session_id,
            f"{DRIVE_URL}/files",
            params={
                "q": f"name = '{escaped}' and trashed = false",
                "pageSize": 2,
                "fields": "files(id,name,mimeType,size)",
            },
        )
        files = listing.get("files", [])
        if not files:
            return f"No Drive file named {name!r} was found.", "your Google Drive"
        if len(files) != 1:
            raise GoogleAuthError("more than one Drive file has that name; use a unique file name.")
        item = files[0]
        mime = item.get("mimeType", "")
        if mime == "application/vnd.google-apps.document":
            url, params = f"{DRIVE_URL}/files/{quote(item['id'], safe='')}/export", {"mimeType": "text/plain"}
        elif mime == "application/vnd.google-apps.spreadsheet":
            url, params = f"{DRIVE_URL}/files/{quote(item['id'], safe='')}/export", {"mimeType": "text/csv"}
        elif mime in {"text/plain", "text/markdown", "text/csv", "application/json"}:
            try:
                if int(item.get("size", 0) or 0) > MAX_FILE_BYTES:
                    raise GoogleAuthError("That file is larger than the 1 MB read limit.")
            except (TypeError, ValueError):
                pass
            url, params = f"{DRIVE_URL}/files/{quote(item['id'], safe='')}", {"alt": "media"}
        else:
            raise GoogleAuthError("Only text, CSV, JSON, Google Docs, and Google Sheets files can be read.")
        content = self.connector._get_bytes(self.session_id, url, params=params).decode("utf-8", errors="replace")
        return content[:30000], f"your Google Drive file {name}"


def _decode_header(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except (LookupError, UnicodeError, ValueError):
        return value


def _message_text(payload: dict) -> str:
    plain, html = [], []
    pending = [payload]
    while pending:
        part = pending.pop()
        pending.extend(part.get("parts", []))
        body = part.get("body", {}).get("data")
        if not body or part.get("mimeType") not in ("text/plain", "text/html"):
            continue
        try:
            decoded = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8", errors="replace")
        except (ValueError, TypeError):
            continue
        (plain if part["mimeType"] == "text/plain" else html).append(decoded[:30000])
    return "\n".join(plain or html)
