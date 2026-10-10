from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from sandbox.google import GoogleAuthError, GoogleConnector


def test_oauth_state_is_bound_to_one_browser_session_and_one_use():
    client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"access_token": "access", "expires_in": 3600})
    ))
    connector = GoogleConnector(
        "client", "secret", "https://lab.example/auth/google/callback", client=client
    )
    url = connector.begin("session-a")
    query = parse_qs(urlparse(url).query)
    state = query["state"][0]

    assert set(query["scope"][0].split()) == {
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/drive.readonly",
    }
    assert query["access_type"] == ["offline"]
    with pytest.raises(GoogleAuthError):
        connector.finish("session-b", state, "code")
    connector.finish("session-a", state, "code")
    with pytest.raises(GoogleAuthError):
        connector.finish("session-a", state, "code")


def test_oauth_rejects_a_partial_scope_grant():
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={
        "access_token": "access",
        "expires_in": 3600,
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
    })))
    connector = GoogleConnector("client", "secret", "https://lab.example/callback", client=client)
    session = "session-a"
    state = parse_qs(urlparse(connector.begin(session)).query)["state"][0]

    with pytest.raises(GoogleAuthError, match="did not grant all required read-only access"):
        connector.finish(session, state, "code")
    assert not connector.is_connected(session)


def test_oauth_token_exchange_reports_only_a_safe_google_error_code():
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(401, json={
        "error": "invalid_client",
        "error_description": "private provider detail",
    })))
    connector = GoogleConnector("client", "secret", "https://lab.example/callback", client=client)
    session = "session-a"
    state = parse_qs(urlparse(connector.begin(session)).query)["state"][0]

    with pytest.raises(GoogleAuthError) as error:
        connector.finish(session, state, "code")

    assert error.value.reason == "invalid_client"
    assert "private provider detail" not in str(error.value)
    assert "secret" not in str(error.value)


def test_google_workspace_reads_limited_mail_and_text_files_only():
    message_body = base64.urlsafe_b64encode(b"Synthetic message body").decode().rstrip("=")

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": "access", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer access"
        if request.url.path.endswith("/messages"):
            return httpx.Response(200, json={"messages": [{"id": "mail-id-1"}]})
        if request.url.path.endswith("/messages/mail-id-1"):
            return httpx.Response(200, json={
                "id": "mail-id-1",
                "labelIds": ["UNREAD"],
                "snippet": "Synthetic preview",
                "payload": {
                    "headers": [
                        {"name": "From", "value": "sender@example.test"},
                        {"name": "Subject", "value": "Synthetic subject"},
                    ],
                    "mimeType": "text/plain",
                    "body": {"data": message_body},
                },
            })
        if request.url.path.endswith("/files"):
            return httpx.Response(200, json={"files": [{
                "id": "file-id-1", "name": "notes.txt", "mimeType": "text/plain", "size": "23"
            }]})
        if request.url.path.endswith("/files/file-id-1"):
            return httpx.Response(200, text="Synthetic drive file contents")
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(respond))
    connector = GoogleConnector(
        "client", "secret", "https://lab.example/auth/google/callback", client=client
    )
    session = "session-a"
    state = parse_qs(urlparse(connector.begin(session)).query)["state"][0]
    connector.finish(session, state, "code")
    workspace = connector.workspace(session)

    listing, _ = workspace.inbox_list(True)
    mail, _ = workspace.inbox_read(1)
    file_contents, _ = workspace.files_read("notes.txt")

    assert "Synthetic subject" in listing
    assert "Synthetic message body" in mail
    assert file_contents == "Synthetic drive file contents"


def test_google_workspace_rejects_ambiguous_or_unsupported_drive_files():
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": "access", "expires_in": 3600})
        if request.url.path.endswith("/files"):
            return httpx.Response(200, json={"files": [
                {"id": "1", "name": "same.txt", "mimeType": "text/plain", "size": "1"},
                {"id": "2", "name": "same.txt", "mimeType": "text/plain", "size": "1"},
            ]})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(respond))
    connector = GoogleConnector("client", "secret", "https://lab.example/callback", client=client)
    session = "session-a"
    state = parse_qs(urlparse(connector.begin(session)).query)["state"][0]
    connector.finish(session, state, "code")

    with pytest.raises(GoogleAuthError, match="more than one"):
        connector.workspace(session).files_read("same.txt")


def test_google_json_responses_are_size_limited():
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": "access", "expires_in": 3600})
        return httpx.Response(200, content=b"{" + b" " * 2_000_000 + b"}")

    client = httpx.Client(transport=httpx.MockTransport(respond))
    connector = GoogleConnector("client", "secret", "https://lab.example/callback", client=client)
    session = "session-a"
    state = parse_qs(urlparse(connector.begin(session)).query)["state"][0]
    connector.finish(session, state, "code")

    with pytest.raises(GoogleAuthError, match="larger than 2 MB"):
        connector._get_json(session, "https://gmail.googleapis.com/test")


def test_expired_google_access_token_is_refreshed_server_side():
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com":
            if "grant_type=authorization_code" in request.read().decode():
                return httpx.Response(200, json={
                    "access_token": "expired-access", "refresh_token": "private-refresh", "expires_in": 0,
                })
            return httpx.Response(200, json={"access_token": "fresh-access", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer fresh-access"
        return httpx.Response(200, json={"messages": []})

    client = httpx.Client(transport=httpx.MockTransport(respond))
    connector = GoogleConnector("client", "secret", "https://lab.example/callback", client=client)
    session = "session-a"
    state = parse_qs(urlparse(connector.begin(session)).query)["state"][0]
    connector.finish(session, state, "code")

    listing, _ = connector.workspace(session).inbox_list(True)
    assert listing == ""
    assert connector._tokens[session]["access_token"] == "fresh-access"


class FakeWorkspace:
    def inbox_list(self, unread_only):
        return "LIVE TEST INBOX", "test Gmail"

    def inbox_read(self, email_id):
        return "LIVE TEST MESSAGE", "test message"

    def files_read(self, name):
        return "LIVE TEST FILE", "test Drive file"


class FakeConnector:
    def __init__(self, *_args):
        self.enabled = True
        self.sessions = set()

    def begin(self, session_id):
        self.pending_session = session_id
        return "https://accounts.google.com/o/oauth2/v2/auth?state=state-value"

    def finish(self, session_id, state, code):
        assert session_id == self.pending_session
        assert state == "state-value" and code == "test-code"
        self.sessions.add(session_id)

    def is_connected(self, session_id):
        return session_id in self.sessions

    def workspace(self, session_id):
        return FakeWorkspace() if self.is_connected(session_id) else None

    def disconnect(self, session_id):
        self.sessions.discard(session_id)


def test_oauth_routes_set_an_http_only_session_and_allow_disconnect(monkeypatch):
    import web.app as web_app

    monkeypatch.setattr(web_app, "load_env", lambda path=None: {
        "GOOGLE_CLIENT_ID": "client-id",
        "GOOGLE_CLIENT_SECRET": "secret",
        "GOOGLE_REDIRECT_URI": "https://testserver/auth/google/callback",
    })
    monkeypatch.setattr(web_app, "GoogleConnector", FakeConnector)
    client = TestClient(web_app.create_app(passcode="", replay=True), base_url="https://testserver")

    started = client.get("/auth/google/start", follow_redirects=False)
    assert started.status_code == 302
    assert "accounts.google.com" in started.headers["location"]
    cookie = started.cookies.get("muffle_google_session")
    assert cookie and len(cookie) >= 40
    assert "httponly" in started.headers["set-cookie"].lower()
    assert "secure" in started.headers["set-cookie"].lower()

    callback = client.get("/auth/google/callback?state=state-value&code=test-code", follow_redirects=False)
    assert callback.status_code == 303
    assert callback.headers["location"] == "/live?google=connected"
    config = client.get("/api/config")
    assert config.json()["google_connected"] is True
    assert "secret" not in config.text

    cross_site = client.post("/api/google/disconnect", headers={"Origin": "https://evil.example"})
    assert cross_site.status_code == 403
    assert client.get("/api/config").json()["google_connected"] is True

    disconnected = client.post("/api/google/disconnect", headers={"Origin": "https://testserver"})
    assert disconnected.status_code == 200
    assert client.get("/api/config").json()["google_connected"] is False


def test_oauth_callback_preserves_only_the_safe_failure_reason(monkeypatch):
    import web.app as web_app

    class FailedConnector(FakeConnector):
        def finish(self, session_id, state, code):
            raise GoogleAuthError("Google sign-in failed", reason="invalid_client")

    monkeypatch.setattr(web_app, "load_env", lambda path=None: {
        "GOOGLE_CLIENT_ID": "client-id",
        "GOOGLE_CLIENT_SECRET": "secret",
        "GOOGLE_REDIRECT_URI": "https://testserver/auth/google/callback",
    })
    monkeypatch.setattr(web_app, "GoogleConnector", FailedConnector)
    client = TestClient(web_app.create_app(passcode="", replay=True), base_url="https://testserver")
    client.get("/auth/google/start", follow_redirects=False)

    callback = client.get("/auth/google/callback?state=state-value&code=test-code", follow_redirects=False)

    assert callback.status_code == 303
    assert callback.headers["location"] == "/live?google=failed&reason=invalid_client"


def test_run_uses_google_workspace_only_after_an_explicit_opt_in(monkeypatch):
    import web.app as web_app

    monkeypatch.setattr(web_app, "load_env", lambda path=None: {
        "GOOGLE_CLIENT_ID": "client-id",
        "GOOGLE_CLIENT_SECRET": "secret",
        "GOOGLE_REDIRECT_URI": "https://testserver/auth/google/callback",
    })
    monkeypatch.setattr(web_app, "GoogleConnector", FakeConnector)

    class PromptLLM:
        calls = 0
        cache_flags = []

        def __init__(self, replay=False, on_live_call=None, use_cache=None):
            type(self).cache_flags.append(use_cache)

        @staticmethod
        def message_of(response):
            return response["choices"][0]["message"]

        def complete(self, *_args, **_kwargs):
            type(self).calls += 1
            if type(self).calls == 1:
                return {"choices": [{"message": {"tool_calls": [{
                    "id": "call-1", "type": "function", "function": {
                        "name": "inbox_list", "arguments": '{"unread_only":true}'
                    }
                }]}}]}
            return {"choices": [{"message": {"content": "Live inbox summary."}}]}

    monkeypatch.setattr(web_app, "LLM", PromptLLM)
    client = TestClient(web_app.create_app(passcode="", replay=False), base_url="https://testserver")
    client.get("/auth/google/start", follow_redirects=False)
    client.get("/auth/google/callback?state=state-value&code=test-code")

    refused = client.post("/api/run", json={"request": "summarize", "use_google": False})
    assert refused.status_code == 200
    assert "LIVE TEST INBOX" not in refused.text

    PromptLLM.calls = 0
    response = client.post("/api/run", json={
        "request": "summarize", "guarded": False, "use_google": True,
    })
    assert response.status_code == 200
    assert "LIVE TEST INBOX" in response.text
    assert "Live inbox summary." in response.text
    assert PromptLLM.cache_flags == [None, False]


def test_google_data_cannot_be_selected_without_a_connected_session(monkeypatch):
    import web.app as web_app

    monkeypatch.setattr(web_app, "load_env", lambda path=None: {})
    client = TestClient(web_app.create_app(passcode="", replay=True))
    response = client.post("/api/run", json={"request": "summarize", "use_google": True})
    assert response.status_code == 409


def test_page_discloses_google_access_and_model_provider_transfer():
    import web.app as web_app

    client = TestClient(web_app.create_app(passcode="", replay=True))
    page = client.get("/live").text
    assert "Use connected Google data" in page
    assert "Read-only access across Gmail and Drive" in page
    assert "configured model provider" in page


def test_real_google_data_never_falls_back_to_recorded_replay(monkeypatch):
    import web.app as web_app

    monkeypatch.setattr(web_app, "load_env", lambda path=None: {
        "GOOGLE_CLIENT_ID": "client-id",
        "GOOGLE_CLIENT_SECRET": "secret",
        "GOOGLE_REDIRECT_URI": "https://testserver/auth/google/callback",
        "LLM_API_KEY": "test-key",
        "DEMO_DAILY_RUNS": "200",
    })
    monkeypatch.setattr(web_app, "GoogleConnector", FakeConnector)
    client = TestClient(web_app.create_app(passcode="", replay=True), base_url="https://testserver")
    client.get("/auth/google/start", follow_redirects=False)
    client.get("/auth/google/callback?state=state-value&code=test-code")

    response = client.post("/api/run", json={"request": "summarize", "use_google": True})
    assert response.status_code == 503
    assert "live model" in response.json()["detail"].lower()


def test_google_data_is_not_read_when_the_model_budget_is_too_small(monkeypatch):
    import web.app as web_app

    monkeypatch.setattr(web_app, "load_env", lambda path=None: {
        "GOOGLE_CLIENT_ID": "client-id",
        "GOOGLE_CLIENT_SECRET": "secret",
        "GOOGLE_REDIRECT_URI": "https://testserver/auth/google/callback",
        "LLM_API_KEY": "test-key",
        "DEMO_DAILY_RUNS": "7",
    })
    monkeypatch.setattr(web_app, "GoogleConnector", FakeConnector)
    client = TestClient(web_app.create_app(passcode="", replay=False), base_url="https://testserver")
    client.get("/auth/google/start", follow_redirects=False)
    client.get("/auth/google/callback?state=state-value&code=test-code")

    response = client.post("/api/run", json={"request": "summarize", "use_google": True})
    assert response.status_code == 429
    assert "Google data was not read" in response.json()["detail"]


def test_google_run_can_read_eight_messages_and_still_return_an_answer(monkeypatch):
    import json
    import web.app as web_app

    monkeypatch.setattr(web_app, "load_env", lambda path=None: {
        "GOOGLE_CLIENT_ID": "client-id",
        "GOOGLE_CLIENT_SECRET": "secret",
        "GOOGLE_REDIRECT_URI": "https://testserver/auth/google/callback",
        "LLM_API_KEY": "test-key",
        "DEMO_DAILY_RUNS": "200",
    })
    monkeypatch.setattr(web_app, "GoogleConnector", FakeConnector)

    class MailboxLLM:
        calls = 0

        def __init__(self, **_kwargs):
            pass

        @staticmethod
        def message_of(response):
            return response["choices"][0]["message"]

        def complete(self, *_args, **_kwargs):
            type(self).calls += 1
            if type(self).calls == 1:
                function = {"name": "inbox_list", "arguments": '{"unread_only":true}'}
            elif type(self).calls <= 9:
                function = {"name": "inbox_read", "arguments": json.dumps({"email_id": type(self).calls - 1})}
            else:
                return {"choices": [{"message": {"content": "All eight messages summarized."}}]}
            return {"choices": [{"message": {"tool_calls": [{
                "id": f"call-{type(self).calls}", "type": "function", "function": function,
            }]}}]}

    monkeypatch.setattr(web_app, "LLM", MailboxLLM)
    client = TestClient(web_app.create_app(passcode="", replay=False), base_url="https://testserver")
    client.get("/auth/google/start", follow_redirects=False)
    client.get("/auth/google/callback?state=state-value&code=test-code")

    response = client.post("/api/run", json={
        "request": "summarize all unread emails", "guarded": False, "use_google": True,
    })
    events = [json.loads(line) for line in response.text.splitlines()]
    assert events[-1]["answer"] == "All eight messages summarized."


def test_google_oauth_entry_points_are_rate_limited(monkeypatch):
    import web.app as web_app

    monkeypatch.setattr(web_app, "load_env", lambda path=None: {})
    client = TestClient(web_app.create_app(passcode="", replay=True, rate_limit=2))
    statuses = [client.get("/auth/google/start", follow_redirects=False).status_code for _ in range(3)]
    assert statuses == [303, 303, 429]
