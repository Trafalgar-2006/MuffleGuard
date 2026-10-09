# MuffleGuard Security and Architecture Review

**Reviewed:** 2026-10-09
**Snapshot:** local `MuffleGuard` worktree based on `fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be`
**Scope:** Full repository source, tests, README, reviewer checklist, offline demo, adversarial probes, and current dependency advisories. At review time, changes were uncommitted and had not been pushed.

## Recheck Summary

The original findings below describe the pre-fix snapshot. Findings 1-5 and 8 are fixed with regression tests. Finding 6 was re-audited: unused FastAPI/Starlette dependencies were removed, pytest is pinned to 9.0.3, `tokenizers` was moved from vulnerable 0.23.2 to 0.22.2, and BPE merge data is checked before native parsing. Finding 7 is mitigated by a persistent audit-path option, while in-memory remains the demo default.

This pass also fixed a secret split across outbound fields, short private excerpts from longer records, mutable approval arguments, cleartext LLM endpoints, HTTP error-body reflection, response caching by default, and raw muffled content being copied into the audit log. The fresh review found three gaps: split-secret scanning depended on field order, percent escapes were decoded only once, and different IPv6 hosts collapsed to the same provenance value. Those are fixed, malformed provider responses now fail safely, and detector, URL-component, audit-privacy, and host-parsing regression coverage was added. The current suite reports **129 passed**. A fresh `pip-audit -r requirements.txt -r requirements-dev.txt` reports **no known vulnerabilities**.

### Findings added in this recheck

1. **Split secrets depended on field order.** A valid email call with `body="AKIAIOSFODNN7"` and `subject="EXAMPLE"` was allowed because only input-order joins were scanned. The egress check now tries every ordering of the current outbound fields; reversed AWS and OpenAI key fragments are covered by tests.
2. **Nested URL encoding bypassed the scan.** A key encoded twice as percent escapes survived the single decode pass. The scanner now checks up to three decode layers; one-, two-, and three-layer cases are covered. Deeper/custom encodings remain part of the heuristic limitation.
3. **IPv6 targets shared a false host value.** `host_of()` returned `"["` for every bracketed IPv6 address, so a different IPv6 URL inherited a user-approved target. It now extracts the bracketed address and the regression confirms a different address needs approval.
4. **Malformed provider output crashed the agent.** A successful HTTP response with a missing/empty `choices` list or non-text answer could raise `KeyError`, `IndexError`, or `TypeError`. The client now rejects malformed chat responses with a generic error; the agent returns the error without running tools.
5. **The audit log retained muffled text.** Hidden instructions, including any data inside them, were copied into persistent audit payloads. The log now records only the number of muffled spans and their carrier kinds; a regression verifies removed text is absent.
6. **New cache files could be staged accidentally.** The response cache lives under the repository and contains full model responses. `.llm_cache/` is now ignored for new files; existing tracked cache files are synthetic demo fixtures and must stay free of real user data.

Coverage also now exercises the detector's missing-weight status, sentence scoring path, and CLI early exit, plus private excerpts in URL query and user-info fields. These tests use a deterministic local scorer; they do not validate the real ONNX snapshots.

The project is still a demo with heuristic egress checks and in-memory fake tools. The configured model provider receives user requests and tool results; the detector pipeline was tested with a deterministic scorer, but real ONNX snapshots were not available. The dependency set still has no committed lockfile, so future transitive resolutions are not reproducible. New response-cache files are now ignored by Git; the existing tracked cache entries are demo fixtures and should remain synthetic.

The `tokenizers` change addresses a published BPE merge-load panic: the advisory identifies the unsafe loader and the upstream issue documents the malformed merge case. The advisory does not list a patched release, so the project now pins the older stable parser and rejects overlong merges and invalid prefixes before native parsing. See the [GitHub advisory](https://github.com/advisories/GHSA-jrf5-f6jp-7vxc) and [upstream issue](https://github.com/huggingface/tokenizers/issues/2094).

## Dependency advisory research recheck

**Checked:** 2026-10-09 against the exact direct pins in `requirements.txt` and `requirements-dev.txt`: `onnxruntime==1.31.0`, `tokenizers==0.22.2`, `numpy==2.4.6`, `httpx==0.28.1`, `pytest==9.0.3`, and `hypothesis==6.145.1`.

- **`tokenizers` remains the one material dependency concern.** [GHSA-jrf5-f6jp-7vxc](https://github.com/advisories/GHSA-jrf5-f6jp-7vxc) describes a BPE merge-load out-of-bounds write/panic but currently gives no affected or fixed version range; the [upstream report](https://github.com/huggingface/tokenizers/issues/2094) reproduces it on 0.23.1. The [0.23.2 source](https://github.com/huggingface/tokenizers/blob/v0.23.2/tokenizers/src/models/bpe/model.rs#L2572-L2656) still sizes a scratch buffer from the longest vocabulary entry and writes merged text into it. By contrast, the pinned [0.22.2 source](https://github.com/huggingface/tokenizers/blob/v0.22.2/tokenizers/src/models/bpe/model.rs#L2428-L2520) constructs merge text with dynamically allocated `format!`, so the specific fixed-buffer overflow path is absent in that tag. MuffleGuard also rejects overlong merges and invalid prefixes before calling the native loader in [`injection.py`](muffleguard/detectors/injection.py). This supports keeping the 0.22.2 pin and pre-parser for this known flaw, but does not prove the package or parser safe against other malformed tokenizer inputs. The advisory's version range remains unresolved.
- **The development pin `pytest==9.0.3` is the patched release** for [GHSA-6w46-j5rx-g56g](https://github.com/advisories/GHSA-6w46-j5rx-g56g), which affects versions below 9.0.3 and describes unsafe temporary-directory handling on Unix. It is development-only; the reviewed test run used Windows, so that Unix-specific behavior was not exercised.
- **The other pins have no applicable public advisory found in this check.** The old [httpx advisory](https://github.com/advisories/GHSA-h8pj-cxx2-jfg2) affects versions below 0.23.0, not 0.28.1. The disputed NumPy pickle advisory affects versions below 1.16.3, not 2.4.6 ([GHSA-9fq2-x9r6-wfmf](https://github.com/advisories/GHSA-9fq2-x9r6-wfmf)). The upstream security pages for [ONNX Runtime](https://github.com/microsoft/onnxruntime/security/advisories), [Hypothesis](https://github.com/HypothesisWorks/hypothesis/security/advisories), and the [httpx project](https://github.com/encode/httpx/security/advisories) list no published project advisories at check time. Absence from public advisories is not a guarantee of no defects.
- **A non-security compatibility drawback:** an open upstream [BPE trainer issue](https://github.com/huggingface/tokenizers/issues/2320) reports malformed merge ordering from `BpeTrainer` on 0.22.2 as well as 0.23.1. MuffleGuard loads existing tokenizer snapshots and does not train tokenizers, so this reported path is not used here.

This is an advisory/source recheck of the six direct pins. A fresh `pip-audit -r requirements.txt -r requirements-dev.txt` also reported no known vulnerabilities for the resolved graph during this pass. The requirements have no lockfile, so future transitive versions can vary between installations; rerun the audit after dependency resolution or updates.

### Current residual risks

- Egress detection is heuristic. It catches recognized secret formats and copied runs of at least three meaningful words, but cannot guarantee detection of every encoding, short fragment, or paraphrase.
- Percent decoding is bounded to three layers. Outbound-field permutation scanning covers the current tools, whose schemas have at most three fields; wider schemas need a bounded matcher to avoid factorial work.
- URL provenance matches the hostname only; scheme, port, path, DNS result, and redirect destination need separate controls in any real network adapter.
- The model provider receives request text and tool results. Do not send data to a provider that is not approved to process it.
- Detector snapshots come from external model repositories and are not pinned to immutable revisions or checked against signed hashes. The preflight only covers the known BPE merge-load panic cases.
- The audit head is stored in the same SQLite database. A writer who can edit both rows and metadata can rewrite the chain; the environment-configured persistent path also remains optional.
- Persistent audit logs omit full tool results and muffled content, but reason text and labels can still contain target addresses or file names; access and retention need deployment policy.
- The shipped tools only use an in-memory fake world. A real mailbox, filesystem, or HTTP adapter needs separate access controls and SSRF protections.
- `pip-audit` found no known vulnerabilities for the resolved requirements at review time, but there is no committed lockfile. Future transitive dependency resolution can change.
- No real model-provider run or ONNX detector run was performed in this recheck; those require credentials and local model snapshots.

## Original Findings (pre-fix snapshot)

### 1. [Fixed] High: URL query/path data was not inspected for secrets

**Evidence:** [`policy.py`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/muffleguard/policy.py#L244-L263) scans only `ToolSpec.payload_args`. [`_targets_in`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/muffleguard/policy.py#L320-L330) reduces a URL to its host for provenance, leaving path, query, and user-info out of secret checks. The README says secret-bearing payloads never leave ([`README.md`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/README.md#L33-L39)).

**Reproduction:** Put `https://corp.example/intake` in a `Source.USER` ledger record, then check `http_post` with URL `https://corp.example/intake?leak=<REDACTED>` and innocuous `data="ok"`. The observed verdict is `allow` with no rules. The host is user-sourced, and the URL itself is not scanned for the credential.

**Correction:** Keep host provenance separate, but scan every outbound value that can cross the process/network boundary, including URL path/query/user-info and payload fields. Add regression cases for secrets and private-file excerpts in each URL component.

### 2. [Fixed] High: Non-string payloads bypassed scanning

**Evidence:** [`policy.py`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/muffleguard/policy.py#L247-L263) includes only `str`, `int`, or `float` payload values; nested dicts/lists are omitted. The agent parses model JSON without validating it against the tool schema ([`agent.py`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/sandbox/agent.py#L108-L120)). The sandbox send adapter stores the full args object ([`tools.py`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/sandbox/tools.py#L143-L146)).

**Reproduction:** In a guarded `run_agent` call, ask to email a user-named recipient; script `files_read(.env)` followed by `email_send(to="priya@corp.example", body={"attachment": "<REDACTED>"})`. The run has no blocked calls and the structured body reaches `world.sent` unchanged. The sandbox does not transmit real mail, but this proves the guard permits the data to reach the outbound adapter record.

**Correction:** Validate every tool call against a strict schema before policy evaluation (including types and unknown keys), fail closed on malformed args, and scan a canonical recursive representation of every outbound field. Add a full agent-loop regression test with nested dict/list values.

### 3. [Fixed] Medium: Request-screen `ASK` was not enforced

**Evidence:** [`Guard._on_request`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/muffleguard/guard.py#L114-L141) returns `Decision.ASK` for imperative hidden text and detected jailbreaks. [`run_agent`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/sandbox/agent.py#L77-L83) stops only for `BLOCK`, then sends the original request to the model.

**Reproduction:** Submit a request containing an imperative Unicode-tag hidden span. `Guard.check` returns `ask`; `run_agent` still calls the scripted LLM and returns its answer. No request approval callback or sanitization is performed.

**Correction:** Handle request `ASK` as an actual approval/denial state before calling the model, or return a non-executable result. Add an end-to-end test asserting the model is not called until approval. Do not treat a detection result as enforced merely because it is logged.

### 4. [Fixed] Medium: Audit-chain tail truncation verified clean

**Evidence:** [`AuditLog.verify`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/muffleguard/audit.py#L97-L110) validates links among rows that remain, but has no externally anchored expected head or row count.

**Reproduction:** Append three entries, delete the row with the largest sequence number, and call `verify()`. Observed result: `Verification(ok=True, checked=2, broken_at=None, detail='')`.

**Correction:** If suffix deletion must be detectable, anchor the latest sequence/hash outside the writable SQLite file (for example, signed checkpoints or a remote append-only sink). Otherwise explicitly document that truncation is undetectable, in addition to full-chain recomputation by a writer. Add a tail-deletion test so the boundary is explicit.

### 5. [Fixed] Medium: Detector mode silently degraded when weights were absent

**Evidence:** [`injection.py`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/muffleguard/detectors/injection.py#L48-L54) only looks for existing local Hugging Face snapshots; it contains no model download path. `available()` reports whether a model loaded ([`injection.py`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/muffleguard/detectors/injection.py#L196-L197)), but [`hero_attack.py`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/tools/hero_attack.py#L81-L87) discards the result and prints `detectors=on` based only on the flag ([line 78](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/tools/hero_attack.py#L78)). This conflicts with the first-run download claim in [`REVIEW.md`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/REVIEW.md#L15-L16).

**Reproduction:** On this clean model cache, `InjectionDetector().available()` returned `False`. Nevertheless, `tools/hero_attack.py --detector` printed `detectors=on` and `GATE: PASS`. The gate confirms no simulated breach, not that classifiers ran.

**Correction:** Either implement and document an explicit model-fetch/setup step, or clearly require local snapshots. Check `available()` and fail/warn in the CLI; make detector-mode tests assert the expected classifier is loaded and flags a known injection.

### 6. [Superseded] Medium, latent: Vulnerable pinned dependencies

**Evidence:** [`requirements.txt`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/requirements.txt#L6-L9) pins FastAPI 0.120.4, which resolved to Starlette 0.49.3. `pip-audit` reports five unique Starlette advisories: CVE-2026-48710 (Host/request URL parsing), CVE-2026-48818 (Windows UNC SSRF in `StaticFiles`), CVE-2026-48817 (non-standard method dispatch), CVE-2026-54283 (form parser DoS), and CVE-2026-54282 (request URL path/authority parsing). Fixed versions reported were 1.0.1 through 1.3.1 depending on advisory. [`requirements-dev.txt`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/requirements-dev.txt#L1-L3) also pins pytest 9.0.2, affected by CVE-2025-71176 / GHSA-6w46-j5rx-g56g, fixed in 9.0.3.

**Reachability:** The repository has no ASGI application or Starlette imports, so the Starlette advisories are latent dependency risk rather than demonstrated exploitable routes in this snapshot. The pytest issue concerns Unix `/tmp/pytest-of-{user}` handling; this verification ran on Windows, and pytest is development-only. `requirements.txt` pins direct dependencies but has no lockfile for a reproducible transitive graph.

**Correction:** Upgrade FastAPI and resolve a compatible fixed Starlette, then commit a fully resolved lockfile and rerun tests plus `pip-audit`. PyPI currently lists FastAPI 0.143.0 with `starlette>=0.46.0` and Starlette 1.7.0; verify project compatibility before adopting current versions. Raise pytest to at least 9.0.3. References: [FastAPI on PyPI](https://pypi.org/project/fastapi/), [Starlette on PyPI](https://pypi.org/project/starlette/), [Starlette security advisories](https://github.com/Kludex/starlette/security/advisories).

### 7. [Mitigated; in-memory remains default] Medium: Audit log was ephemeral by default

**Evidence:** [`AuditLog.__init__`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/muffleguard/audit.py#L67-L74) defaults to SQLite `:memory:`; [`Guard`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/muffleguard/guard.py#L65-L80) creates that default when no audit adapter is supplied. The chain is available only while that connection/process remains alive, despite the README describing a log of every decision.

**Impact and correction:** For production accountability, configure a persistent path or an external append-only sink and verify entries survive process restart. If this is intentionally demo-only, state that explicitly; in-memory storage is suitable for isolated tests but not durable audit evidence.

### 8. [Fixed] Low: Audit SQLite connection had no close lifecycle

**Evidence:** [`AuditLog`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/muffleguard/audit.py#L67-L74) opens a connection but exposes no `close()` or context-manager protocol. The coverage run emitted repeated `ResourceWarning: unclosed database` messages while garbage-collecting guards/audit logs.

**Correction:** Add an explicit close/context-manager lifecycle and ensure the owning agent/run closes it. Add a fixture that closes audit logs so tests do not rely on garbage collection; test both in-memory and file-backed audit storage.

## Architecture Notes

- **Good seam and locality:** `Guard.check(Event)` is a compact entry point for four checkpoints; `PolicyEngine` and `Ledger` keep deterministic provenance decisions testable without an LLM.
- **Strong test strategy:** scripted LLM runs separate guard behavior from model quality; property tests and red-team cases cover normalization, target provenance, secret shapes, and documented gaps.
- **Argument interface:** `ToolSpec` declares argument types and required keys. The same declaration builds the model schema and validates calls before policy evaluation and execution; unsupported nested types fail closed.
- **Audit assurance boundary:** the chain detects edits/deletions that break links, but without an external head anchor it cannot establish that the current file contains the complete history.

## Initial Security Pass (pre-fix snapshot)

**Method used:** threat-boundary/STRIDE analysis and dependency triage from `security-and-hardening`; AAA, deterministic Hypothesis probing, coverage, and fixture-isolation review from `python-testing-patterns`; reproduce/minimize/check loops from `diagnosing-bugs`; seam, interface, and locality analysis from `codebase-design`.

### Initial STRIDE Threat Model (pre-fix)

| Threat | Relevant trust boundary and result |
| --- | --- |
| Spoofing | No real identity/authentication surface exists in this checkout. Content provenance is inferred from tool metadata and ledger records, not authenticated source signatures. |
| Tampering | Normalization and whole-address matching mitigate casing, width, zero-width, and homograph tricks. Interior audit edits are detected; suffix truncation and full-chain recomputation are not. |
| Repudiation | Decisions are logged, but default in-memory storage disappears at process exit and there is no external head anchor. |
| Information disclosure | The initial pass reproduced URL-component and nested-payload gaps; those are fixed. Current egress checks remain heuristic, and simulated outbound actions are recorded in memory rather than sent to a real service. |
| Denial of service | `run_agent` caps model turns at eight, but there is no general size cap on request/tool-result/tool-argument text. This was not load-tested and needs limits at any real service boundary. |
| Elevation of privilege | The initial pass found that request-level `ASK` was ignored; `run_agent` now stops before the model call. Real tools still need their own authorization. |

### Original Scanner and Test Results (before fixes)

- Bandit 1.9.4: **1 High-severity, Medium-confidence B613 Trojan Source warning** at [`normalize.py`](https://github.com/Trafalgar-2006/MuffleGuard/blob/fadb6f2d1a1f21c0c192c6cc85781a9c4392f7be/muffleguard/normalize.py#L21-L25). The literal bidi controls are intentionally detector data, not a demonstrated malicious control-flow change; write them as `\u` escapes so source review is unambiguous and verify the behavior remains identical.
- `pip-audit -r requirements.txt -r requirements-dev.txt`: **12 advisory rows, 6 unique vulnerability IDs across 2 packages**. Some identifiers appear more than once in the output; see finding 6 for the unique IDs and applicability.
- `pytest --cov=muffleguard --cov=sandbox --cov-report=term-missing`: **93 passed, 74% total coverage**. `muffleguard/detectors/injection.py` is **0%**, and `sandbox/llm.py` is **33%**; the rest of the detector and guard/policy surfaces are mostly covered. Add offline tests with fake ONNX snapshots/sessions and mocked HTTP/cache responses rather than requiring model downloads or live credentials.
- The coverage run additionally surfaced repeated unclosed-SQLite `ResourceWarning`s and the existing `normalize.py:115` positional-`maxsplit` `DeprecationWarning`.
- Credential-shape scan found 38 matches in tracked files and 38 in added history lines across the full three-commit history. Manual path review places them in `sandbox/world.py` and `tests/*` synthetic fixtures only; no values were emitted in the scan output. This scanner is pattern-based and does not prove that no other type of secret exists.

## Original Verification Performed (before fixes)

- `python -m pytest`: **93 passed**, 12 `DeprecationWarning`s from positional `maxsplit` in `muffleguard/normalize.py:115`.
- `tools/hero_attack.py --no-muffle`: `GATE: PASS`; baseline leaked, policy-only run blocked the attacker URL and named email #5; audit chain verified.
- `tools/hero_attack.py`: `GATE: PASS`; hidden instructions were muffled and no attacker data was recorded.
- `tools/hero_attack.py --detector`: `GATE: PASS`, but classifiers were unavailable as described in finding 5.
- Additional policy/agent probes reproduced findings 1-4. These used fake credentials only; all credential-shaped values are redacted here.
- **Playwright:** not run. There is no browser application or Playwright target in the tracked repository. The relevant E2E path is Python `run_agent` plus the sandbox CLI, which was exercised above.

## Original Suggested Fix Order (superseded by the recheck above)

1. Strictly validate tool args and inspect every outbound field, including URL components and nested data.
2. Enforce request-level `ASK` before any model call.
3. Upgrade vulnerable dependency pins, resolve and commit a lockfile, and rerun `pip-audit`.
4. Make detector readiness explicit and align setup docs with actual loading behavior.
5. Give audit logs a persistent production configuration and explicit connection lifecycle; decide whether truncation needs an external checkpoint.
6. Add regression tests for each reproduction and offline coverage for the model/network adapters before changing implementation.
