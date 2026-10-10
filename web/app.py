"""The Attack Lab: the demo, served over HTTP.

The page runs the same request twice, undefended and defended, and streams each
step as it happens so a live run can be watched rather than waited for.

This is a security demo that will sit on a public URL, so the server is treated
as exposed: a passcode on the API, a per-IP rate limit, security headers, input
limits, and a log-corrupting route that does not exist unless the demo switches
it on.
"""

from __future__ import annotations

import json
import queue
import secrets
import threading
import time
import uuid
from collections import OrderedDict, deque
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.background import BackgroundTask

from muffleguard.audit import AuditLog
from muffleguard.guard import Guard
from sandbox.agent import Step, run_agent
from sandbox.google import GoogleAuthError, GoogleConnector
from sandbox.llm import LLM, LLMError, load_env
from sandbox.tools import DESCRIPTIONS, SPECS
from sandbox.world import DEMO_REQUEST, World

STATIC = Path(__file__).resolve().parent / "static"
SITE = Path(__file__).resolve().parent.parent / "site"
# The frozen evaluation. The server reads it; it never runs the suite on
# request, because a number produced to order is not a measurement.
RESULTS = Path(__file__).resolve().parent.parent / "evaluation" / "results.json"

MAX_API_BODY = 32 * 1024
MAX_AGENT_STEPS = 8
MAX_GOOGLE_AGENT_STEPS = 12
MAX_ACTIVE_RUNS = 8

# Everything is served from here: the pages, their scripts, the animation
# bundles and the web fonts. Nothing is fetched from a CDN, so the demo also
# works on a venue network that blocks one.
#
# script-src stays strict: no inline script, no remote origin, which is the
# half that stops an injected <script>. style-src has to allow inline, because
# the marketing pages carry their layout in style attributes exported from the
# design tool; an attacker who could set one of those already controls the
# markup, and no script runs from it.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request: str = Field(default=DEMO_REQUEST, max_length=2000)
    guarded: bool = True
    muffle: bool = True
    detector: bool = False
    use_google: bool = False

    @field_validator("request")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("the request cannot be empty")
        return value.strip()


class RunRegistry:
    """The audit logs of recent runs, newest last.

    Bounded, because a public demo would otherwise hold every run it has ever
    served. Asking for a run that has aged out is a 404, not a silent empty log.
    """

    def __init__(self, keep: int = 20) -> None:
        self.keep = keep
        self.logs: OrderedDict[str, AuditLog] = OrderedDict()
        self.lock = threading.Lock()

    def add(self, run_id: str, log: AuditLog) -> None:
        with self.lock:
            self.logs[run_id] = log
            while len(self.logs) > self.keep:
                self.logs.popitem(last=False)

    def get(self, run_id: str) -> AuditLog | None:
        """The named run only.

        Without a name this is an empty log, never "the most recent one". On a
        shared URL that convenience would hand one visitor the decisions, block
        reasons and muffled text from another visitor's run, which is somebody
        else's session. The page knows its own id and sends it.
        """
        with self.lock:
            if run_id:
                return self.logs.get(run_id)
            return AuditLog()


class DailyBudget:
    """A ceiling on live model calls per day, for a URL anyone can reach.

    The per-IP rate limit bounds one visitor; it does nothing about a thousand
    of them, or a crawler that finds the link. This bounds the bill instead of
    the visitor. Reaching it does not break the demo: the run falls back to the
    recorded one, which is what most visitors press anyway. shortcut: process-local;
    use shared storage before adding workers or replicas.
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.day = date.today()
        self.spent = 0
        self.reserved = 0
        self.lock = threading.Lock()

    def reserve(self, calls: int) -> DailyBudgetLease | None:
        with self.lock:
            self._rollover()
            available = self.limit - self.spent - self.reserved
            if available < calls:
                return None
            self.reserved += calls
            return DailyBudgetLease(self, calls)

    def _rollover(self) -> None:
        today = date.today()
        if today != self.day:
            self.day, self.spent, self.reserved = today, 0, 0

    @property
    def remaining(self) -> int:
        with self.lock:
            self._rollover()
            return max(0, self.limit - self.spent - self.reserved)


class DailyBudgetLease:
    def __init__(self, budget: DailyBudget, calls: int) -> None:
        self.budget = budget
        self.calls = calls
        self.day = budget.day

    def take(self) -> bool:
        with self.budget.lock:
            self.budget._rollover()
            if self.day != self.budget.day or self.calls == 0:
                return False
            self.calls -= 1
            self.budget.reserved -= 1
            self.budget.spent += 1
            return True

    def release(self) -> None:
        with self.budget.lock:
            self.budget._rollover()
            if self.day == self.budget.day:
                self.budget.reserved -= self.calls
            self.calls = 0


class RateLimiter:
    """A fixed window per client address.

    shortcut: the 4096 most recent addresses only; address churn can evict a
    counter. Use shared storage before scaling beyond one process.
    """

    def __init__(self, limit: int, window: float = 60.0) -> None:
        self.limit = limit
        self.window = window
        self.seen: OrderedDict[str, deque] = OrderedDict()
        self.lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self.lock:
            hits = self.seen.pop(client, None)
            if hits is None:
                if len(self.seen) >= 4096:
                    self.seen.popitem(last=False)
                hits = deque()
            while hits and now - hits[0] > self.window:
                hits.popleft()
            self.seen[client] = hits
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


class RunSlot:
    def __init__(self, slots: threading.BoundedSemaphore) -> None:
        self.slots = slots
        self.started = False
        self.released = False
        self.lock = threading.Lock()

    def worker_started(self) -> bool:
        with self.lock:
            if self.released:
                return False
            self.started = True
            return True

    def release_if_unstarted(self) -> None:
        with self.lock:
            unstarted = not self.started
        if unstarted:
            self.release()

    def release(self) -> None:
        with self.lock:
            if self.released:
                return
            self.released = True
        self.slots.release()


class RequestBodyLimit:
    """Bound API bodies before JSON parsing, including chunked requests."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith("/api/"):
            await self.app(scope, receive, send)
            return

        headers = dict(scope["headers"])
        length = headers.get(b"content-length")
        if length:
            try:
                if int(length) > MAX_API_BODY:
                    await _json(413, {"detail": "request body is too large"})(scope, receive, send)
                    return
            except ValueError:
                await _json(400, {"detail": "invalid content length"})(scope, receive, send)
                return

        messages = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            messages.append(message)
            size += len(message.get("body", b""))
            if size > MAX_API_BODY:
                await _json(413, {"detail": "request body is too large"})(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        async def replay_body():
            if messages:
                return messages.pop(0)
            return await receive()

        await self.app(scope, replay_body, send)


def create_app(
    passcode: str | None = None,
    replay: bool | None = None,
    rate_limit: int = 30,
    allow_tamper: bool | None = None,
    trust_proxy: bool | None = None,
) -> FastAPI:
    env = load_env()
    if replay is None:
        # Replay only when there is nothing to call. With a key configured,
        # refusing to use it would make every request but the shipped one fail
        # on a machine that could perfectly well answer it.
        replay = not env.get("LLM_API_KEY")
    if passcode is None:
        passcode = env.get("DEMO_PASSCODE", "")
    if allow_tamper is None:
        # Off unless asked for. The route corrupts a log and the shipped
        # .env.example leaves the passcode blank, so defaulting it on would put
        # an unauthenticated log-corrupting route on the public URL.
        allow_tamper = env.get("DEMO_TAMPER", "") == "1"
    if trust_proxy is None:
        trust_proxy = env.get("TRUST_PROXY", "") == "1"

    app = FastAPI(title="MuffleGuard Attack Lab", docs_url=None, redoc_url=None)
    app.add_middleware(RequestBodyLimit)
    limiter = RateLimiter(rate_limit)
    budget = DailyBudget(int(env.get("DEMO_DAILY_RUNS", "200")))
    # shortcut: this cap is per worker; use a shared limiter when scaling out.
    active_runs = threading.BoundedSemaphore(MAX_ACTIVE_RUNS)
    # One audit log per run, keyed by the id handed to the page that started it.
    # A single shared log would be overwritten by whoever ran last, so two
    # people opening the demo at once would each see the other's decisions.
    runs = RunRegistry()
    google = GoogleConnector(
        env.get("GOOGLE_CLIENT_ID", ""),
        env.get("GOOGLE_CLIENT_SECRET", ""),
        env.get("GOOGLE_REDIRECT_URI", ""),
    )

    @app.middleware("http")
    async def secure(request: Request, call_next):
        if request.scope["path"].startswith("/auth/google/") and not limiter.allow(
            _client_of(request, trust_proxy)
        ):
            return _harden(_json(429, {"detail": "too many requests; wait a minute"}))
        if request.scope["path"].startswith("/api/"):
            # Rate limit first. Checking the passcode first would leave wrong
            # guesses uncounted, so the only authentication on the API could be
            # guessed at as fast as the network allowed.
            if not limiter.allow(_client_of(request, trust_proxy)):
                return _harden(_json(429, {"detail": "too many requests; wait a minute"}))
            if passcode and not _passcode_ok(request.headers.get("x-demo-passcode", ""), passcode):
                return _harden(_json(401, {"detail": "a passcode is required for this demo"}))

        return _harden(await call_next(request))

    @app.get("/")
    def landing() -> FileResponse:
        return FileResponse(SITE / "index.html")

    @app.get("/docs")
    def docs_page() -> FileResponse:
        return FileResponse(SITE / "docs.html")

    @app.get("/lab")
    def lab_page() -> RedirectResponse:
        """One Attack Lab, not two.

        A scripted replica of the lab used to live here. Two pages showing the
        same thing is one too many, and the static one would drift away from
        the app it was imitating: a visitor landing on it would be reading a
        picture of a result rather than a result. Old links still work.
        """
        return RedirectResponse("/live", status_code=307)

    @app.get("/live")
    def live_lab() -> FileResponse:
        """The real thing: every line on this page is a decision the guard made."""
        return FileResponse(STATIC / "index.html")

    @app.get("/auth/google/start")
    def google_start():
        if not google.enabled:
            return _harden(RedirectResponse("/live?google=not-configured", status_code=303))
        session_id = secrets.token_urlsafe(32)
        response = RedirectResponse(google.begin(session_id), status_code=302)
        response.set_cookie(
            "muffle_google_session", session_id, max_age=60 * 60 * 24 * 30,
            httponly=True, secure=True, samesite="lax", path="/",
        )
        return _harden(response)

    @app.get("/auth/google/callback")
    def google_callback(request: Request):
        session_id = _google_session(request)
        state, code = request.query_params.get("state", ""), request.query_params.get("code", "")
        if request.query_params.get("error"):
            return _harden(RedirectResponse("/live?google=failed&reason=cancelled", status_code=303))
        if not session_id or len(state) > 256 or len(code) > 8192:
            return _harden(RedirectResponse("/live?google=failed&reason=state", status_code=303))
        try:
            google.finish(session_id, state, code)
        except GoogleAuthError as exc:
            return _harden(RedirectResponse(f"/live?google=failed&reason={exc.reason}", status_code=303))
        return _harden(RedirectResponse("/live?google=connected", status_code=303))

    @app.get("/api/config")
    def config(request: Request) -> dict:
        """What the page needs to know. Never anything from the environment."""
        return {
            "request": DEMO_REQUEST,
            "passcode_required": bool(passcode),
            "tamper_enabled": allow_tamper,
            "replay_only": replay or budget.remaining < MAX_AGENT_STEPS,
            "google_run_available": not replay and budget.remaining >= MAX_GOOGLE_AGENT_STEPS,
            "model": env.get("LLM_MODEL", "openai/gpt-4o-mini"),
            "google_configured": google.enabled,
            "google_connected": google.is_connected(_google_session(request)),
        }

    @app.post("/api/run")
    def run(body: RunRequest, request: Request):
        workspace = google.workspace(_google_session(request)) if body.use_google else None
        if body.use_google and workspace is None:
            return _json(409, {"detail": "Connect your Google test account before using Gmail or Drive data."})
        if body.use_google and replay:
            return _json(503, {"detail": "A live model is required before using Google data; recorded replay cannot read your account."})
        if not active_runs.acquire(blocking=False):
            return _json(503, {"detail": "too many active runs; retry shortly"})
        slot = RunSlot(active_runs)
        # Google runs need room to read up to ten messages and still return an answer.
        step_limit = MAX_GOOGLE_AGENT_STEPS if body.use_google else MAX_AGENT_STEPS
        lease = None if replay else budget.reserve(step_limit)
        if body.use_google and lease is None:
            slot.release()
            return _json(429, {"detail": "The live model call budget is exhausted; Google data was not read."})
        return StreamingResponse(
            _stream(body, runs, replay=lease is None, lease=lease, slot=slot, google_workspace=workspace),
            media_type="application/x-ndjson",
            background=BackgroundTask(slot.release_if_unstarted),
        )

    @app.post("/api/google/disconnect")
    def google_disconnect(request: Request):
        origin = request.headers.get("origin", "")
        if not origin or urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
            raise HTTPException(403, "same-origin request required")
        google.disconnect(_google_session(request))
        response = JSONResponse({"connected": False})
        response.delete_cookie("muffle_google_session", path="/", httponly=True, secure=True, samesite="lax")
        return response

    @app.get("/api/scorecard")
    def scorecard() -> dict:
        """The recorded evaluation, minus the per-run detail the page ignores."""
        if not RESULTS.exists():
            raise HTTPException(404, "no evaluation has been recorded yet")
        try:
            data = json.loads(RESULTS.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            raise HTTPException(404, "the recorded evaluation could not be read")
        errored = sum(1 for r in data.get("runs", []) if r.get("error"))
        return {
            "generated": data.get("generated", ""),
            "model": data.get("model", ""),
            "tasks": data.get("tasks", 0),
            "attacks": data.get("attacks", 0),
            "runs": len(data.get("runs", [])),
            "errored": errored,
            "conditions": data.get("conditions", []),
        }

    @app.get("/api/audit")
    def audit(run_id: str = "") -> dict:
        log = runs.get(run_id)
        if log is None:
            raise HTTPException(404, "that run is not in memory any more; run it again")
        check = log.verify()
        return {
            "verified": check.ok,
            "broken_at": check.broken_at,
            "detail": check.detail,
            "entries": [
                {
                    "seq": e.seq,
                    "kind": e.kind,
                    "payload": e.payload,
                    "prev_hash": e.prev_hash[:16],
                    "hash": e.hash[:16],
                }
                for e in log.entries()
            ],
        }

    if allow_tamper:

        @app.post("/api/audit/tamper")
        def tamper(seq: int = Body(embed=True, default=2), run_id: str = Body(embed=True, default="")) -> dict:
            """Edit one entry in place, the way an attacker covering tracks would.

            Present only when the demo enables it, because it corrupts the log.
            """
            if not run_id:
                raise HTTPException(400, "name the run to edit")
            log = runs.get(run_id)
            if log is None:
                raise HTTPException(404, "that run is not in memory any more; run it again")
            cursor = log.conn.execute(
                "UPDATE entries SET payload = ? WHERE seq = ?",
                (json.dumps({"decision": "allow", "note": "nothing to see here"}), seq),
            )
            log.conn.commit()
            # Without this the demo can claim to have edited an entry that does
            # not exist, and then report the chain intact a line later.
            if cursor.rowcount == 0:
                raise HTTPException(404, f"this run has no entry {seq}")
            check = log.verify()
            return {"verified": check.ok, "broken_at": check.broken_at, "detail": check.detail}

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    app.mount("/assets", StaticFiles(directory=SITE / "assets"), name="assets")
    return app


def _harden(response):
    """The headers every response carries, refusals included."""
    response.headers["content-security-policy"] = CSP
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "DENY"
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["permissions-policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["cache-control"] = "no-store"
    # Railway terminates TLS and serves this origin over HTTPS only, so a
    # browser should refuse to try plain HTTP again. Without it the very first
    # request of a session is downgradeable.
    response.headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"
    return response


def _passcode_ok(supplied: str, expected: str) -> bool:
    """Constant-time comparison that survives a non-ASCII header.

    Starlette decodes headers as latin-1 and compare_digest rejects a str with
    any character above 127, so comparing the raw strings turns a odd passcode
    attempt into a 500 from the middleware.
    """
    return secrets.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


def _google_session(request: Request) -> str:
    value = request.cookies.get("muffle_google_session", "")
    return value if 40 <= len(value) <= 100 else ""


def _client_of(request: Request, trust_proxy: bool) -> str:
    """Who to count this request against.

    Behind a platform proxy every request carries the proxy's address, so the
    per-client limit would be one bucket shared by every visitor. The forwarded
    header is only believed when the deployment says it sits behind a proxy,
    since anyone can send it otherwise.
    """
    if trust_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _scrub(message: str) -> str:
    """Remove the credential from anything on its way to a browser.

    No current path puts the key in an exception, but an error message is
    assembled from a library's words, not ours, so this is checked rather than
    assumed.
    """
    key = load_env().get("LLM_API_KEY", "")
    return message.replace(key, "[redacted]") if key else message


def _json(status: int, body: dict):
    return JSONResponse(status_code=status, content=body)


def _stream(
    body: RunRequest,
    runs: RunRegistry,
    replay: bool,
    slot: RunSlot,
    lease: DailyBudgetLease | None = None,
    google_workspace=None,
):
    """Run the agent on a worker thread and yield each step as it is produced.

    The agent loop is synchronous, so a thread plus a queue is what turns it
    into something the page can render as it happens.
    """
    steps: queue.Queue = queue.Queue()
    world = World(google=google_workspace)
    guard = (
        Guard(tools=SPECS, detector=_detector(body.detector), muffle=body.muffle, descriptions=DESCRIPTIONS)
        if body.guarded
        else None
    )
    run_id = uuid.uuid4().hex
    if guard is not None:
        runs.add(run_id, guard.audit)

    result: dict = {}

    def work() -> None:
        try:
            llm_options = {"replay": replay, "on_live_call": lease.take if lease else None}
            if body.use_google:
                llm_options["use_cache"] = False
            result["run"] = run_agent(
                body.request,
                world=world,
                guard=guard,
                max_steps=MAX_GOOGLE_AGENT_STEPS if body.use_google else MAX_AGENT_STEPS,
                llm=LLM(**llm_options),
                on_step=steps.put,
            )
        except LLMError as exc:
            result["error"] = _scrub(str(exc))
        except Exception as exc:  # a bug here must not hang the page
            result["error"] = _scrub(f"{type(exc).__name__}: {exc}")
        finally:
            if lease is not None:
                lease.release()
            slot.release()
            steps.put(None)

    worker = threading.Thread(target=work, daemon=True)
    if not slot.worker_started():
        return
    try:
        worker.start()
    except Exception:
        if lease is not None:
            lease.release()
        slot.release()
        raise

    # The id goes out first, so the page can ask for this run's log by name
    # even if the run then fails.
    yield json.dumps({"type": "start", "run_id": run_id, "guarded": body.guarded}) + "\n"

    while True:
        step = steps.get()
        if step is None:
            break
        yield json.dumps({"type": "step", **_as_dict(step)}) + "\n"

    worker.join(timeout=5)
    run_result = result.get("run")
    yield json.dumps(
        {
            "type": "done",
            "run_id": run_id,
            "error": result.get("error", "") or (run_result.error if run_result else ""),
            "answer": run_result.answer if run_result else "",
            # Read from the world, not from the run result. A run that raised
            # after the data had already left would otherwise report itself
            # safe, which is the one direction this must never be wrong in.
            "breached": bool(world.attacker_received),
            "attacker_received": [
                {
                    "to": item.get("to") or item.get("url", ""),
                    "content": str(item.get("body") or item.get("data") or "")[:400],
                }
                for item in world.attacker_received
            ],
            "guarded": body.guarded,
        }
    ) + "\n"


def _as_dict(step: Step) -> dict:
    return {
        "kind": step.kind,
        "tool": step.tool,
        "args": {k: str(v)[:200] for k, v in step.args.items()},
        "text": step.text[:1200],
        "decision": step.decision,
        "reasons": step.reasons,
        "muffled": step.muffled,
    }


def _detector(enabled: bool):
    if not enabled:
        return None
    from muffleguard.detectors.injection import InjectionDetector

    detector = InjectionDetector()
    return detector if detector.available() else None


app = create_app()
