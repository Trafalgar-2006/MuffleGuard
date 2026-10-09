"""The Attack Lab's HTTP surface.

Tested through the API a browser would use, not through the app's internals, so
the page can be rebuilt without rewriting any of this.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sandbox.world import DEMO_REQUEST
from web.app import RateLimiter, create_app


def lines(response) -> list[dict]:
    """The NDJSON stream as a list of objects."""
    return [json.loads(line) for line in response.text.splitlines() if line.strip()]


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(passcode="", replay=True, allow_tamper=True))


def run(client: TestClient, **body) -> list[dict]:
    payload = {"request": DEMO_REQUEST, **body}
    response = client.post("/api/run", json=payload)
    assert response.status_code == 200, response.text
    return lines(response)


def test_the_page_is_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "MuffleGuard" in response.text


def test_an_unguarded_run_reaches_the_attacker(client):
    """The left-hand side of the demo must actually break."""
    events = run(client, guarded=False)
    done = events[-1]
    assert done["type"] == "done"
    assert done["breached"] is True
    assert done["attacker_received"]


def test_a_guarded_run_blocks_and_says_why(client):
    events = run(client, guarded=True, muffle=False, detector=False)
    done = events[-1]

    assert done["breached"] is False
    blocked = [e for e in events if e.get("kind") == "blocked"]
    assert blocked, "the exfiltration must be refused"
    assert any("not from you" in r for step in blocked for r in step["reasons"])


def test_muffling_shows_what_was_removed(client):
    events = run(client, guarded=True, muffle=True, detector=False)
    muffled = [e for e in events if e.get("muffled")]
    assert muffled, "the hidden instruction should be reported as muffled"
    assert any("send" in m.lower() or "post" in m.lower() for e in muffled for m in e["muffled"])


def test_every_step_arrives_as_its_own_line(client):
    """The page renders steps as they arrive, so each must be a complete object."""
    events = run(client, guarded=True)
    assert len(events) > 3
    assert all("type" in e for e in events)


def test_the_audit_log_is_returned_and_verifies(client):
    run_id = run(client, guarded=True)[0]["run_id"]
    response = client.get(f"/api/audit?run_id={run_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is True
    assert body["entries"]
    assert all({"seq", "kind", "hash"} <= set(e) for e in body["entries"])


def test_a_tampered_audit_log_fails_verification_at_that_entry(client):
    """The demo edits one line and verification names it."""
    run_id = run(client, guarded=True)[0]["run_id"]
    response = client.post("/api/audit/tamper", json={"seq": 2, "run_id": run_id})
    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is False
    assert body["broken_at"] == 2


# --- the parts that make it safe to expose ----------------------------------


def test_the_api_key_is_never_returned(client):
    """Nothing the server sends may contain the credential."""
    events = run(client, guarded=True)
    blob = json.dumps(events) + client.get("/").text + client.get("/api/audit").text
    assert "sk-or-v1" not in blob
    assert "LLM_API_KEY" not in blob


def test_security_headers_are_set(client):
    headers = client.get("/").headers
    assert "default-src" in headers.get("content-security-policy", "")
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert "referrer-policy" in headers


def test_a_passcode_gates_every_route_when_set():
    guarded = TestClient(create_app(passcode="s3cret", replay=True))
    assert guarded.get("/api/audit").status_code == 401
    assert guarded.post("/api/run", json={"request": "hi"}).status_code == 401

    ok = guarded.get("/api/audit", headers={"X-Demo-Passcode": "s3cret"})
    assert ok.status_code == 200


def test_a_wrong_passcode_is_refused():
    guarded = TestClient(create_app(passcode="s3cret", replay=True))
    assert guarded.get("/api/audit", headers={"X-Demo-Passcode": "wrong"}).status_code == 401


def test_requests_are_rate_limited_per_client():
    limited = TestClient(create_app(passcode="", replay=True, rate_limit=3))
    codes = [limited.post("/api/run", json={"request": "hi", "guarded": True}).status_code for _ in range(5)]
    assert 429 in codes, codes
    assert codes.count(200) <= 3


def test_an_over_long_request_is_refused(client):
    response = client.post("/api/run", json={"request": "x" * 10_000, "guarded": True})
    assert response.status_code == 422


def test_an_empty_request_is_refused(client):
    assert client.post("/api/run", json={"request": "   ", "guarded": True}).status_code == 422


def test_the_tamper_route_is_absent_unless_the_demo_enables_it():
    """A route that corrupts the log must not exist on a normal deployment."""
    locked = TestClient(create_app(passcode="", replay=True, allow_tamper=False))
    assert locked.post("/api/audit/tamper", json={"seq": 2}).status_code == 404


def test_two_runs_keep_separate_audit_logs(client):
    """Two people using the demo at once must not share one log.

    Before runs were keyed, whoever finished last overwrote the viewer for
    everyone, so a judge could be shown another judge's decisions.
    """
    first = run(client, guarded=True)[0]["run_id"]
    second = run(client, guarded=True)[0]["run_id"]
    assert first != second

    client.post("/api/audit/tamper", json={"seq": 2, "run_id": first})

    assert client.get(f"/api/audit?run_id={first}").json()["verified"] is False
    assert client.get(f"/api/audit?run_id={second}").json()["verified"] is True


def test_asking_for_a_run_that_is_gone_says_so(client):
    assert client.get("/api/audit?run_id=deadbeef0000").status_code == 404


def test_the_audit_view_is_empty_before_anything_runs(client):
    body = client.get("/api/audit").json()
    assert body["verified"] is True and body["entries"] == []


def test_the_audit_view_never_hands_over_another_visitors_run():
    """Without a run id the viewer is empty, not "whoever ran last".

    On a shared URL that convenience would show one visitor another visitor's
    decisions, block reasons and muffled text.
    """
    shared = TestClient(create_app(passcode="", replay=True, allow_tamper=True))
    run(shared, guarded=True)
    assert shared.get("/api/audit").json()["entries"] == []


# --- regressions found by review, each fixed ---------------------------------


def test_wrong_passcode_attempts_are_rate_limited():
    """The limiter must run before the passcode check.

    Checking the passcode first left wrong guesses uncounted, so the only
    authentication on the API could be guessed at network speed.
    """
    app = TestClient(create_app(passcode="s3cret", replay=True, rate_limit=3))
    codes = [app.get("/api/audit", headers={"X-Demo-Passcode": "wrong"}).status_code for _ in range(5)]
    assert 429 in codes, codes


def test_a_non_ascii_passcode_is_refused_not_a_crash():
    """Starlette decodes headers as latin-1; compare_digest rejects such a str."""
    app = TestClient(create_app(passcode="s3cret", replay=True))
    raw = bytes([0x63, 0x61, 0x66, 0xE9])  # "cafe" with an accent, as the wire carries it
    assert app.get("/api/audit", headers={b"X-Demo-Passcode": raw}).status_code == 401


def test_refusals_carry_the_security_headers_too():
    app = TestClient(create_app(passcode="s3cret", replay=True))
    refused = app.get("/api/audit")
    assert refused.status_code == 401
    assert refused.headers.get("x-frame-options") == "DENY"
    assert "default-src" in refused.headers.get("content-security-policy", "")


def test_the_tamper_route_is_off_unless_the_environment_asks_for_it():
    """A blank passcode plus a log-corrupting route is not a default."""
    assert TestClient(create_app(passcode="", replay=True)).post(
        "/api/audit/tamper", json={"seq": 2, "run_id": "x"}
    ).status_code == 404


def test_editing_an_entry_that_does_not_exist_says_so(client):
    """It used to report success, then report the chain intact a line later."""
    run_id = run(client, guarded=True)[0]["run_id"]
    assert client.post("/api/audit/tamper", json={"seq": 99, "run_id": run_id}).status_code == 404


def test_editing_without_naming_a_run_is_refused(client):
    assert client.post("/api/audit/tamper", json={"seq": 2}).status_code == 400


def test_every_setting_can_be_set_from_the_environment(monkeypatch):
    """A deployment has no .env file, so the environment is the only way in.

    DEMO_PASSCODE was missing from the list once, and the live demo served its
    API unauthenticated while the platform showed the variable as set.
    """
    from sandbox.llm import SETTINGS, load_env

    for name in ("DEMO_PASSCODE", "DEMO_TAMPER", "TRUST_PROXY"):
        assert name in SETTINGS

    monkeypatch.setenv("DEMO_PASSCODE", "from-the-environment")
    assert load_env()["DEMO_PASSCODE"] == "from-the-environment"

    gated = TestClient(create_app(replay=True))
    assert gated.get("/api/config").status_code == 401
    assert gated.get(
        "/api/config", headers={"X-Demo-Passcode": "from-the-environment"}
    ).status_code == 200


def test_a_key_in_the_environment_turns_replay_off(monkeypatch):
    """Replay is for having nothing to call, not for having a key and refusing.

    Hardcoding it on meant a machine with a working key still answered every
    request but the shipped one with "no cached response".
    """
    monkeypatch.setenv("LLM_API_KEY", "sk-test-not-used-offline")
    assert TestClient(create_app(passcode="")).get("/api/config").json()["replay_only"] is False

    monkeypatch.delenv("LLM_API_KEY", raising=False)
    import sandbox.llm as llm

    monkeypatch.setattr(llm, "load_env", lambda path=None: {})
    import web.app as web_app

    monkeypatch.setattr(web_app, "load_env", lambda path=None: {})
    assert TestClient(create_app(passcode="")).get("/api/config").json()["replay_only"] is True


def test_the_replay_message_says_what_to_do(client):
    """The page shows this verbatim, so it has to be an instruction."""
    done = run(client, guarded=False, request="a request nobody has cached")[-1]
    assert "Run both without changing the request" in done["error"]


def test_the_daily_budget_falls_back_to_the_recording_instead_of_spending(monkeypatch):
    """A public URL with a live key needs a ceiling on the bill, not just on one visitor.

    When the remaining allowance cannot cover a full run, the demo switches to
    the recording before that run makes any provider calls.
    """
    monkeypatch.setenv("LLM_API_KEY", "sk-test-never-called")
    import web.app as web_app

    class OneCallLLM:
        live_calls = 0

        def __init__(self, replay=False, on_live_call=None):
            self.replay = replay
            self.on_live_call = on_live_call

        def complete(self, *_args, **_kwargs):
            if not self.replay:
                assert self.on_live_call()
                type(self).live_calls += 1
            return {"choices": [{"message": {"content": "recorded answer"}}]}

    monkeypatch.setattr(web_app, "LLM", OneCallLLM)
    monkeypatch.setenv("DEMO_DAILY_RUNS", "8")
    app = TestClient(create_app(passcode=""))
    OneCallLLM.live_calls = 0

    assert app.get("/api/config").json()["replay_only"] is False
    app.post("/api/run", json={"request": DEMO_REQUEST, "guarded": True})

    # Seven calls remain, too few to reserve an eight-step run.
    events = lines(app.post("/api/run", json={"request": DEMO_REQUEST, "guarded": True}))
    assert OneCallLLM.live_calls == 1
    assert events[-1]["error"] == ""
    assert app.get("/api/config").json()["replay_only"] is True


def test_a_cached_run_never_spends_the_budget(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "sk-test-never-called")
    monkeypatch.setenv("DEMO_DAILY_RUNS", "1")
    app = TestClient(create_app(passcode="", replay=True))
    for _ in range(3):
        app.post("/api/run", json={"request": DEMO_REQUEST, "guarded": True})
    assert app.get("/api/config").json()["replay_only"] is True


# --- the scorecard ----------------------------------------------------------


def test_the_scorecard_serves_the_recorded_evaluation(client):
    """The page shows the frozen result file, not a run it does on request."""
    body = client.get("/api/scorecard").json()
    assert body["model"]
    assert body["generated"]
    names = {c["name"] for c in body["conditions"]}
    assert {"none", "policy", "full"} <= names


def test_the_scorecard_reports_the_policy_stopping_every_attempt(client):
    """The headline claim, read back from the measured file."""
    body = client.get("/api/scorecard").json()
    policy = next(c for c in body["conditions"] if c["name"] == "policy")
    none = next(c for c in body["conditions"] if c["name"] == "none")

    assert none["attack_success"]["successes"] > 0, "the baseline must actually break"
    assert policy["attack_success"]["successes"] == 0
    assert policy["stopped_when_attempted"]["value"] == 1.0


def test_the_scorecard_carries_intervals_not_bare_rates(client):
    body = client.get("/api/scorecard").json()
    for condition in body["conditions"]:
        rate = condition["attack_success"]
        assert rate["low"] <= rate["value"] <= rate["high"]


def test_a_missing_results_file_says_so_rather_than_inventing_numbers(monkeypatch):
    import web.app as web_app

    monkeypatch.setattr(web_app, "RESULTS", Path("no-such-results.json"))
    assert TestClient(create_app(passcode="", replay=True)).get("/api/scorecard").status_code == 404

def test_the_shipped_replay_cache_matches_the_default_request():
    """A replay cache miss should not make the built-in demo fail offline."""
    from sandbox.agent import SYSTEM_PROMPT
    from sandbox.llm import LLM, Message
    from sandbox.tools import SCHEMA

    llm = LLM(replay=True)
    response = llm.complete(
        [Message("system", SYSTEM_PROMPT), Message("user", DEMO_REQUEST)],
        tools=SCHEMA,
    )
    assert LLM.message_of(response)


def test_unique_client_addresses_do_not_grow_the_rate_limiter_forever():
    limiter = RateLimiter(limit=30)
    for i in range(5000):
        limiter.allow(f"client-{i}")
    assert len(limiter.seen) <= 4096


def test_oversized_json_is_rejected_even_when_extra_fields_are_ignored(client):
    response = client.post(
        "/api/run",
        content=json.dumps({"request": "hello", "unused": "x" * 40_000}),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


def test_chunked_oversized_json_is_rejected_without_content_length(client):
    chunks = iter([b'{"request":"hello","unused":"', b"x" * 40_000, b'"}'])
    response = client.post(
        "/api/run", content=chunks, headers={"content-type": "application/json"}
    )
    assert response.status_code == 413


def test_public_run_cannot_accept_a_client_supplied_approval(client):
    response = client.post(
        "/api/run",
        json={"request": DEMO_REQUEST, "guarded": True, "approve": True},
    )
    assert response.status_code == 422


def test_malformed_host_cannot_bypass_api_passcode():
    gated = TestClient(create_app(passcode="required", replay=True))
    response = gated.get(
        "/api/config", headers={"host": "attacker.example/not-api"}
    )
    assert response.status_code == 401


def test_run_ids_have_128_bits_of_randomness(client):
    run_id = run(client, guarded=True)[0]["run_id"]
    assert len(run_id) == 32
    assert all(character in "0123456789abcdef" for character in run_id)


def test_api_responses_cannot_be_cached_between_visitors(client):
    response = client.get("/api/audit")
    assert response.headers.get("cache-control") == "no-store"


def test_daily_limit_caps_actual_model_calls_not_run_requests(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    import web.app as web_app

    class ManyCallLLM:
        live_calls = 0

        def __init__(self, replay=False, on_live_call=None):
            self.replay = replay
            self.on_live_call = on_live_call
            self.calls = 0

        def complete(self, *_args, **_kwargs):
            self.calls += 1
            if not self.replay:
                assert self.on_live_call()
                type(self).live_calls += 1
            return {
                "choices": [{
                    "message": {
                        "tool_calls": [{
                            "id": f"call-{self.calls}",
                            "type": "function",
                            "function": {
                                "name": "inbox_list",
                                "arguments": '{"unread_only":true}',
                            },
                        }]
                    }
                }]
            }

    monkeypatch.setattr(
        web_app, "load_env", lambda path=None: {
            "LLM_API_KEY": "test-only",
            "DEMO_DAILY_RUNS": "8",
        }
    )
    monkeypatch.setattr(web_app, "LLM", ManyCallLLM)
    ManyCallLLM.live_calls = 0
    client = TestClient(create_app(passcode="", replay=False))

    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [
            pool.submit(
                client.post,
                "/api/run",
                json={"request": DEMO_REQUEST, "guarded": False},
            )
            for _ in range(2)
        ]
        assert [response.result().status_code for response in pending] == [200, 200]

    assert ManyCallLLM.live_calls <= 8


def test_cache_hits_do_not_spend_the_live_model_call_budget(monkeypatch):
    import web.app as web_app

    class CacheHitLLM:
        def __init__(self, replay=False, on_live_call=None):
            self.replay = replay
            self.on_live_call = on_live_call

        def complete(self, *_args, **_kwargs):
            return {"choices": [{"message": {"content": "recorded answer"}}]}

    monkeypatch.setattr(
        web_app, "load_env", lambda path=None: {
            "LLM_API_KEY": "test-only",
            "DEMO_DAILY_RUNS": "8",
        }
    )
    monkeypatch.setattr(web_app, "LLM", CacheHitLLM)
    client = TestClient(create_app(passcode="", replay=False))

    for _ in range(8):
        response = client.post(
            "/api/run", json={"request": DEMO_REQUEST, "guarded": False}
        )
        assert response.status_code == 200

    assert client.get("/api/config").json()["replay_only"] is False


def test_small_remaining_budget_replays_before_starting_a_live_run(monkeypatch):
    import web.app as web_app

    class TrackingLLM:
        live_calls = 0

        def __init__(self, replay=False, on_live_call=None):
            self.replay = replay
            self.on_live_call = on_live_call

        def complete(self, *_args, **_kwargs):
            if not self.replay:
                assert self.on_live_call()
                type(self).live_calls += 1
            return {"choices": [{"message": {"content": "recorded answer"}}]}

    monkeypatch.setattr(
        web_app, "load_env", lambda path=None: {
            "LLM_API_KEY": "test-only",
            "DEMO_DAILY_RUNS": "7",
        }
    )
    monkeypatch.setattr(web_app, "LLM", TrackingLLM)
    client = TestClient(create_app(passcode="", replay=False))

    assert client.get("/api/config").json()["replay_only"] is True
    events = lines(
        client.post("/api/run", json={"request": DEMO_REQUEST, "guarded": False})
    )
    assert events[-1]["error"] == ""
    assert TrackingLLM.live_calls == 0


def test_concurrent_runs_are_bounded_even_when_they_hit_the_replay_cache(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, Lock

    import web.app as web_app

    started = Event()
    release = Event()
    lock = Lock()
    calls = 0

    class BlockingLLM:
        def __init__(self, replay=False, on_live_call=None):
            pass

        def complete(self, *_args, **_kwargs):
            nonlocal calls
            with lock:
                calls += 1
                if calls >= 8:
                    started.set()
            release.wait(2)
            return {"choices": [{"message": {"content": "done"}}]}

    monkeypatch.setattr(
        web_app, "load_env", lambda path=None: {"DEMO_DAILY_RUNS": "200"}
    )
    monkeypatch.setattr(web_app, "LLM", BlockingLLM)
    client = TestClient(create_app(passcode="", replay=True))

    with ThreadPoolExecutor(max_workers=8) as pool:
        pending = [
            pool.submit(
                client.post,
                "/api/run",
                json={"request": DEMO_REQUEST, "guarded": False},
            )
            for _ in range(8)
        ]
        assert started.wait(3)
        overflow = client.post(
            "/api/run", json={"request": DEMO_REQUEST, "guarded": False}
        )
        release.set()
        assert overflow.status_code == 503
        assert [response.result().status_code for response in pending] == [200] * 8
    assert client.post(
        "/api/run", json={"request": DEMO_REQUEST, "guarded": False}
    ).status_code == 200


def test_disconnected_response_keeps_its_worker_slot_until_work_finishes():
    from threading import BoundedSemaphore

    from web.app import RunSlot

    slots = BoundedSemaphore(1)
    assert slots.acquire(blocking=False)
    slot = RunSlot(slots)
    slot.worker_started()

    slot.release_if_unstarted()
    assert slots.acquire(blocking=False) is False

    slot.release()
    assert slots.acquire(blocking=False)
