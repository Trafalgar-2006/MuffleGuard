"""The Attack Lab's HTTP surface.

Tested through the API a browser would use, not through the app's internals, so
the page can be rebuilt without rewriting any of this.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from sandbox.world import DEMO_REQUEST
from web.app import create_app


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

    Past the day's allowance the run still works: it replays the recorded one,
    which is what most visitors press anyway.
    """
    monkeypatch.setenv("LLM_API_KEY", "sk-test-never-called")
    monkeypatch.setenv("DEMO_DAILY_RUNS", "2")
    app = TestClient(create_app(passcode=""))

    assert app.get("/api/config").json()["replay_only"] is False
    for _ in range(2):
        app.post("/api/run", json={"request": DEMO_REQUEST, "guarded": True})

    # The allowance is gone, so the next run replays rather than calling out.
    events = lines(app.post("/api/run", json={"request": DEMO_REQUEST, "guarded": True}))
    assert events[-1]["error"] == ""
    assert app.get("/api/config").json()["replay_only"] is True


def test_a_cached_run_never_spends_the_budget(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "sk-test-never-called")
    monkeypatch.setenv("DEMO_DAILY_RUNS", "1")
    app = TestClient(create_app(passcode="", replay=True))
    for _ in range(3):
        app.post("/api/run", json={"request": DEMO_REQUEST, "guarded": True})
    assert app.get("/api/config").json()["replay_only"] is True
