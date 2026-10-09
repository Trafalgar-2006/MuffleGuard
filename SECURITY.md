# Security policy

## Status

MuffleGuard is a hackathon prototype, built for TatHack '26. It is a working
guard with a measured property and a real test suite, but it has not had an
external audit, and the tools it ships operate on an in-memory fake world. Do
not put it in front of real inboxes or real outbound calls without the
deployment work listed under "Privacy and integration limits" in
[README.md](README.md).

There is no release stream to patch: the supported version is `main`.

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button under the
repository's Security tab, which opens a private advisory visible only to the
maintainers. Please do not open a public issue for a working bypass first.

Useful report: the request, the attacker-written content, the tool call you
expected to be refused, and what happened instead. A failing test against
[tests/test_redteam.py](tests/test_redteam.py) is the fastest possible report,
because that is the file the fix will land next to.

We are two students and will answer as fast as we can, which during the event
means hours and afterwards may mean days.

## In scope

The things that would actually break the design:

- Any outbound tool call that acts on a target the user did not choose and that
  no human approved. This is the invariant, and a counterexample is the most
  serious report possible.
- A provenance gap: content that reaches the model without being recorded in
  the ledger, so a target traced from it looks user-chosen. Two bugs of exactly
  this shape were found during the build.
- An egress path that moves a recognized secret or private excerpt past
  R3-EGRESS-SECRET or R3-EGRESS-PRIVATE.
- A hidden carrier that survives decoding in `detectors/hidden.py` and reaches
  the model intact.
- Forging the audit chain so verification reports intact, within the stated
  tamper-**evident** limit: anyone who can write the database can rewrite the
  chain and the recorded head, and we say so rather than claim otherwise.
- A false positive that blocks ordinary work. A guard people switch off defends
  nothing, so these matter.
- A credential committed to this repository, which
  [tools/check_secrets.py](tools/check_secrets.py) is meant to prevent.

## Out of scope

Prompt injection that merely persuades the model (the whole design assumes it
succeeds); classifier detection rates and thresholds, which are untuned and
excluded from every reported number; the realism of the fake inbox; denial of
service; the absence of network, SSRF, host and multi-user controls, which are
documented non-goals rather than oversights; findings that require write access
to our code, our tool specs or the environment.

## Security-relevant configuration

| Setting | Why it matters |
| --- | --- |
| `LLM_API_KEY` | provider credential. Environment or a git-ignored `.env` only. Never the repository, never the browser. |
| `LLM_BASE_URL`, `LLM_MODEL` | choose the provider that receives requests and tool results. |
| `LLM_CACHE` | off by default. On, it writes live model responses, which may contain user data, to local disk. |
| `MUFFLEGUARD_AUDIT_PATH` | in memory by default. Set it for a persistent log, then restrict access and set a retention period: reasons can contain addresses and file names. |
| `DEMO_DAILY_RUNS` | caps provider spend on a public deployment; past the cap the demo replays its committed cache. |
| `DEMO_PASSCODE` | gates the public Attack Lab if you do not want it open. |
| `DEMO_TAMPER` | demo aid: lets the audit viewer edit one of its own entries so verification can be seen catching it. Leave unset otherwise. |
| `TRUST_PROXY` | only set behind a proxy you control, since it decides whether client IPs are believed. |

## What we run against ourselves

- `python -m pytest`: 212 tests, no network needed, including property tests of
  the invariant and the recorded bypass attempts in `tests/test_redteam.py`.
- `python tools/check_secrets.py`: scans every tracked file with our own secret
  detector, so the thing we built to find credentials is pointed at us.
- `python -m evaluation.run --adversary`: reproduces the published numbers
  offline and free.
- GitHub Actions runs the suite and the secret scan on a clean checkout.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the boundaries these checks assume.
