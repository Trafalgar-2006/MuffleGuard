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
from collections import OrderedDict, defaultdict, deque
from datetime import date
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from muffleguard.audit import AuditLog
from muffleguard.guard import Guard
from sandbox.agent import Step, run_agent
from sandbox.llm import LLM, LLMError, load_env
from sandbox.tools import SPECS
from sandbox.world import DEMO_REQUEST, World

STATIC = Path(__file__).resolve().parent / "static"

# One page, one script, one stylesheet, all served from here. No inline script
# or style, so the policy below can forbid both outright.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class RunRequest(BaseModel):
    request: str = Field(default=DEMO_REQUEST, max_length=2000)
    guarded: bool = True
    muffle: bool = True
    detector: bool = False
    approve: bool = False  # what a human chose when the guard asked

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
    recorded one, which is what most visitors press anyway.
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.day = date.today()
        self.spent = 0
        self.lock = threading.Lock()

    def take(self) -> bool:
        with self.lock:
            today = date.today()
            if today != self.day:
                self.day, self.spent = today, 0
            if self.spent >= self.limit:
                return False
            self.spent += 1
            return True

    @property
    def remaining(self) -> int:
        with self.lock:
            return max(0, self.limit - self.spent) if date.today() == self.day else self.limit


class RateLimiter:
    """A fixed window per client address.

    ponytail: in-process and in-memory, so it resets on redeploy and does not
    span replicas. Enough for one demo box; a shared store if it ever scales.
    """

    def __init__(self, limit: int, window: float = 60.0) -> None:
        self.limit = limit
        self.window = window
        self.seen: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self.lock:
            hits = self.seen[client]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            # Drop clients that have gone quiet, or the table grows by one
            # entry per address seen, for as long as the process lives.
            for address in [a for a, h in self.seen.items() if not h and a != client]:
                del self.seen[address]
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


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
    limiter = RateLimiter(rate_limit)
    budget = DailyBudget(int(env.get("DEMO_DAILY_RUNS", "200")))
    # One audit log per run, keyed by the id handed to the page that started it.
    # A single shared log would be overwritten by whoever ran last, so two
    # people opening the demo at once would each see the other's decisions.
    runs = RunRegistry()

    @app.middleware("http")
    async def secure(request: Request, call_next):
        if request.url.path.startswith("/api/"):
            # Rate limit first. Checking the passcode first would leave wrong
            # guesses uncounted, so the only authentication on the API could be
            # guessed at as fast as the network allowed.
            if not limiter.allow(_client_of(request, trust_proxy)):
                return _harden(_json(429, {"detail": "too many requests; wait a minute"}))
            if passcode and not _passcode_ok(request.headers.get("x-demo-passcode", ""), passcode):
                return _harden(_json(401, {"detail": "a passcode is required for this demo"}))

        return _harden(await call_next(request))

    @app.get("/")
    def page() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/config")
    def config() -> dict:
        """What the page needs to know. Never anything from the environment."""
        return {
            "request": DEMO_REQUEST,
            "passcode_required": bool(passcode),
            "tamper_enabled": allow_tamper,
            "replay_only": replay or budget.remaining == 0,
            "model": env.get("LLM_MODEL", "openai/gpt-4o-mini"),
        }

    @app.post("/api/run")
    def run(body: RunRequest) -> StreamingResponse:
        # A cached run costs nothing, so it never touches the budget. Only a
        # run that would actually call the model does, and once the day's
        # allowance is gone the rest fall back to the recording.
        live = not replay and budget.take()
        return StreamingResponse(
            _stream(body, runs, replay=not live), media_type="application/x-ndjson"
        )

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
    return app


def _harden(response):
    """The headers every response carries, refusals included."""
    response.headers["content-security-policy"] = CSP
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "DENY"
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["permissions-policy"] = "geolocation=(), microphone=(), camera=()"
    return response


def _passcode_ok(supplied: str, expected: str) -> bool:
    """Constant-time comparison that survives a non-ASCII header.

    Starlette decodes headers as latin-1 and compare_digest rejects a str with
    any character above 127, so comparing the raw strings turns a odd passcode
    attempt into a 500 from the middleware.
    """
    return secrets.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


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


def _stream(body: RunRequest, runs: RunRegistry, replay: bool):
    """Run the agent on a worker thread and yield each step as it is produced.

    The agent loop is synchronous, so a thread plus a queue is what turns it
    into something the page can render as it happens.
    """
    steps: queue.Queue = queue.Queue()
    world = World()
    guard = (
        Guard(tools=SPECS, detector=_detector(body.detector), muffle=body.muffle)
        if body.guarded
        else None
    )
    run_id = uuid.uuid4().hex[:12]
    if guard is not None:
        runs.add(run_id, guard.audit)

    result: dict = {}

    def work() -> None:
        try:
            result["run"] = run_agent(
                body.request,
                world=world,
                guard=guard,
                llm=LLM(replay=replay),
                approve=(lambda *_: True) if body.approve else None,
                on_step=steps.put,
            )
        except LLMError as exc:
            result["error"] = _scrub(str(exc))
        except Exception as exc:  # a bug here must not hang the page
            result["error"] = _scrub(f"{type(exc).__name__}: {exc}")
        finally:
            steps.put(None)

    worker = threading.Thread(target=work, daemon=True)
    worker.start()

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
