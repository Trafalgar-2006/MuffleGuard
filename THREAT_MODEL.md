# Threat model

This is the document to read before the code. It states what MuffleGuard
defends, against whom, where the checks sit, and what it deliberately does not
try to do. [README.md](README.md) has the results; this file has the reasoning.

## 1. The system

A sandboxed assistant reads a user's inbox, files and web pages, and can send
email and make HTTP requests. MuffleGuard is a library the agent loop must call
at four points. `Guard.check(event)` in [muffleguard/guard.py](muffleguard/guard.py)
is the only entry point; there is no second way in.

## 2. Assets

| Asset | Why an attacker wants it |
| --- | --- |
| Private tool results (the fake `.env`, salary file, contracts) | the payload worth stealing |
| The user's authority over outbound actions | sending as the user is the whole attack |
| The audit record | a breach you cannot reconstruct is a breach you cannot answer for |

## 3. The adversary

**Can:** write any content the agent reads, which is email bodies and
subjects, file contents, and web pages. Can use any carrier that survives to
the model: invisible Unicode tag characters, white-on-white CSS, HTML comments,
base64, homograph lookalikes, instructions split across fields. Can retry, and
can write text designed to read as if it came from the user or the system.

**Cannot:** modify this repository, the policy rules, the tool specs, the
user's typed request, or the process environment. Cannot read the audit
database or reach the host.

That split is the point. The adversary owns the *content*; the guard's
decisions depend only on *provenance*, which the adversary does not own.

## 4. Trust boundaries

```
  user request                   .- trusted: our code, tool specs, the ledger
       |                         |
       v                         v
  +---------+   request   +-------------+   tool_call   +---------+
  |  agent  |------------>|    GUARD    |-------------->|  tools  |
  |  loop   |<------------|  check()    |<--------------| (fake   |
  +---------+   answer    +-------------+  tool_result  |  world) |
       |                         ^                      +---------+
       v                         |                           ^
  model provider            audit log                attacker-written
  (outside the trust        (hash chain)             content arrives here
   boundary: it sees
   requests and results)
```

The model is **not** a trust boundary. It is assumed to be fully persuadable:
every measured result treats the model as already having obeyed the injection.

## 5. The invariant

> An outbound tool call may only act on a target the user chose,
> unless a human approves it.

No model is consulted to apply it, so there is no prompt to argue with. A
target present only in attacker-written content is refused, and the refusal
names where it came from. `Guard(muffle=False, detector=None)` runs this layer
alone, which is how the headline number is produced.

## 6. Where the checks sit

| Checkpoint | Rule | Decision | What it catches |
| --- | --- | --- | --- |
| `request` | R4-HIDDEN-IN-REQUEST | ASK | hidden carriers in what was typed; stops before the first model call |
| `request` | R4-JAILBREAK | ASK | the user's own text aimed at the model's instructions |
| `tool_result` | R5-HIDDEN-CONTENT | MUFFLE | invisible Unicode, white-on-white CSS, HTML comments, base64 |
| `tool_result` | R5-INJECTION | MUFFLE | sentences addressed to the model, removed per sentence |
| `tool_call` | R0-UNKNOWN-TOOL | BLOCK | a tool that is not declared |
| `tool_call` | R0-INVALID-TOOL-ARGS | BLOCK | malformed arguments, before any rule reads them |
| `tool_call` | R7-TOOL-CHANGED | BLOCK | a tool description mutated at runtime |
| `tool_call` | R1-DANGEROUS-COMMAND | BLOCK | destructive command patterns in any argument |
| `tool_call` | R1-DANGEROUS-TOOL | ASK | a tool that can destroy data |
| `tool_call` | R2-TARGET-UNTRUSTED | BLOCK | **the main rule**: target came from content the agent read |
| `tool_call` | R2-HOMOGRAPH | BLOCK | a target mixing alphabets to impersonate a real one |
| `tool_call` | R2-TARGET-PRIVATE | ASK | target read out of a private file, not named by the user |
| `tool_call` | R2-TARGET-UNKNOWN | ASK | target traceable to nothing the user or tools provided |
| `tool_call` | R2-TARGET-MISSING | ASK | blank target, so no rule could apply to it |
| `tool_call` | R3-EGRESS-SECRET | BLOCK | a recognized secret format in an outbound argument |
| `tool_call` | R3-EGRESS-PRIVATE | BLOCK | a copied run of meaningful words from a private result |
| `answer` | R6-ANSWER-SECRET | MUFFLE | a secret about to be shown to the user |
| `answer` | R6-IMAGE-EXFILTRATION | MUFFLE | remote image URLs that leak on render |

Content sources are labelled in the ledger ([muffleguard/trace.py](muffleguard/trace.py))
as USER, SYSTEM, PRIVATE, UNTRUSTED or MODEL, in that order of trust. Every
decision, with its rule ID and reason, is appended to a hash-chained SQLite log
([muffleguard/audit.py](muffleguard/audit.py)).

## 7. What has to hold for this to work

1. The agent loop calls the guard at all four points. A loop that calls tools
   directly is unguarded, and nothing here can detect that.
2. `ToolSpec` labels are honest: a tool that returns attacker-written content
   must declare `reads_untrusted`, and one that can move data out must declare
   `outbound`. A mislabelled tool is the realistic way to break this design.
3. The ledger sees content before the model does, including decoded hidden
   text. A path that reaches the model without being recorded is a provenance
   gap, which is how two real bugs in this repo were found.
4. The process, the repository and the audit database are not attacker-writable.

## 8. Out of scope

Prompt injection reaching the *model* (assumed to succeed); model jailbreaks
and refusal quality; the realism of the fake world; multi-user authorization;
network, host and container security; availability and denial of service;
supply-chain integrity of the pinned dependencies; anything that needs an
external signing key or checkpoint we do not hold.

## 9. Residual risk

Named in full under "What is not claimed" in [README.md](README.md), and
asserted as live tests in [tests/test_redteam.py](tests/test_redteam.py) so a
later change cannot quietly widen them. In short: the audit log is tamper-evident
rather than tamper-proof; URL provenance binds the host name only; egress
checks are format and word-run heuristics, not semantic; an address the user
pastes is trusted because they chose it; classifier thresholds are untuned and
excluded from every reported number.

## 10. Adding a tool

Declare a `ToolSpec` with honest labels and name its `target_args`. Do not add
a rule. Every rule above reads the spec, so a correctly labelled tool is
covered on arrival, and a new rule is a sign something was mislabelled.
