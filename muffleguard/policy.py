"""The policy engine: deterministic rules over provenance. No model is consulted.

The detectors can be fooled, because any classifier can be. This layer cannot be
argued with, because it never reads the content as instructions: it only asks
where each value came from. That is what keeps the guard standing when a
detector misses, and it is the property the red-team suite measures with the
classifiers switched off.

One invariant carries the design:

    An outbound tool call may only act on a target the user chose,
    unless a human approves it.

Everything else here is detail.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from enum import Enum

from .detectors.secrets import Finding, scan
from .normalize import emails_in, host_of, mixed_script, normalize, urls_in
from .trace import Ledger, Source


class Decision(str, Enum):
    """What the guard does with an event, in increasing severity."""

    ALLOW = "allow"
    MUFFLE = "muffle"  # the content passes, with the injected part removed
    ASK = "ask"  # a human decides
    BLOCK = "block"

    @property
    def severity(self) -> int:
        return {"allow": 0, "muffle": 1, "ask": 2, "block": 3}[self.value]


@dataclass(frozen=True)
class ToolSpec:
    """What a tool can reach, which is what decides how its calls are judged."""

    name: str
    reads_untrusted: bool = False  # returns content an attacker can write
    reads_private: bool = False  # returns the user's own secrets or files
    outbound: bool = False  # can move data or effects out of the sandbox
    target_args: tuple[str, ...] = ()  # args naming who or what is acted on
    payload_args: tuple[str, ...] = ()  # args carrying content out
    dangerous: bool = False  # destructive even inside the sandbox


@dataclass(frozen=True)
class Reason:
    """One rule that fired, in the words shown to the user."""

    rule: str
    decision: Decision
    text: str
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reasons: tuple[Reason, ...] = ()

    @property
    def headline(self) -> str:
        """The single line a person reads: the most severe reason that fired."""
        if not self.reasons:
            return "Allowed."
        worst = max(self.reasons, key=lambda r: r.decision.severity)
        return worst.text

    @property
    def rules(self) -> list[str]:
        return [r.rule for r in self.reasons]


# Commands that destroy data or hand over a shell. Matched on the normalised
# argument so that spacing and case cannot hide them.
_DANGEROUS_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\brm\s+-[a-z]*[rf]", "a recursive delete"),
    (r"\bdel\s+/[sfq]", "a recursive delete"),
    (r"\bformat\s+[a-z]:", "a disk format"),
    (r"\bmkfs(\.|\s)", "a filesystem format"),
    (r"\bdd\s+if=", "a raw disk write"),
    (r">\s*/dev/sd[a-z]", "a raw disk write"),
    (r":\(\)\s*\{.*\|.*&\s*\}\s*;?\s*:", "a fork bomb"),
    (r"\b(?:curl|wget)\b[^|]*\|\s*(?:ba|z|k)?sh", "piping a download into a shell"),
    (r"\bpowershell\b.*\s-e(?:nc|ncodedcommand)\b", "an encoded PowerShell command"),
    (r"\bdrop\s+(?:table|database)\b", "a database drop"),
    (r"\bchmod\s+777\s+/", "opening the filesystem"),
    (r"\bgit\s+push\b.*--force", "a force push"),
)

_STOP_TOKENS = frozenset(
    "a an and are as at be by for from has have i in is it its me my of on or "
    "please that the their them to us was we were with you your".split()
)


class PolicyEngine:
    """Judges tool calls and tool results against the ledger."""

    def __init__(self, tools: dict[str, ToolSpec], scanner=scan) -> None:
        self.tools = tools
        self.scan = scanner

    # -- tool calls ----------------------------------------------------------

    def check_tool_call(self, name: str, args: dict, ledger: Ledger) -> Verdict:
        """Decide whether this tool call may run.

        Every rule is evaluated so the audit log and the UI can show all of
        them; the verdict takes the most severe.
        """
        spec = self.tools.get(name)
        if spec is None:
            return Verdict(
                Decision.BLOCK,
                (
                    Reason(
                        "R0-UNKNOWN-TOOL",
                        Decision.BLOCK,
                        f"No policy is defined for the tool {name!r}, so it cannot run.",
                        {"tool": name},
                    ),
                ),
            )

        reasons: list[Reason] = []
        reasons += self._dangerous_commands(spec, args)
        if spec.outbound:
            reasons += self._target_provenance(spec, args, ledger)
            reasons += self._egress(spec, args, ledger)

        decision = max((r.decision for r in reasons), key=lambda d: d.severity, default=Decision.ALLOW)
        return Verdict(decision, tuple(reasons))

    def _dangerous_commands(self, spec: ToolSpec, args: dict) -> list[Reason]:
        reasons = []
        for key, value in args.items():
            if not isinstance(value, str):
                continue
            probe = normalize(value)
            for pattern, description in _DANGEROUS_PATTERNS:
                if re.search(pattern, probe):
                    reasons.append(
                        Reason(
                            "R1-DANGEROUS-COMMAND",
                            Decision.BLOCK,
                            f"The {key} argument contains {description}.",
                            {"arg": key, "pattern": pattern},
                        )
                    )
                    break
        if spec.dangerous and not reasons:
            reasons.append(
                Reason(
                    "R1-DANGEROUS-TOOL",
                    Decision.ASK,
                    f"{spec.name} can destroy data, so it needs your approval.",
                    {"tool": spec.name},
                )
            )
        return reasons

    def _target_provenance(self, spec: ToolSpec, args: dict, ledger: Ledger) -> list[Reason]:
        """Who chose the recipient, the URL or the path?

        This is the rule that stops exfiltration even when nothing detected the
        injection that asked for it: the attacker's address is in the attacker's
        email, and the user never typed it.
        """
        reasons: list[Reason] = []
        for key in spec.target_args:
            raw = args.get(key)
            if not isinstance(raw, str) or not raw.strip():
                # A missing or blank target is malformed, not harmless: skipping
                # it would let an outbound call through with no rule applied.
                reasons.append(
                    Reason(
                        "R2-TARGET-MISSING",
                        Decision.ASK,
                        f"{spec.name} was called with no {key}, so it needs your approval.",
                        {"arg": key},
                    )
                )
                continue
            for kind, target in _targets_in(raw):
                if mixed_script(target):
                    reasons.append(
                        Reason(
                            "R2-HOMOGRAPH",
                            Decision.BLOCK,
                            f"The {key} {target!r} mixes alphabets, which is how a "
                            "lookalike address is disguised.",
                            {"arg": key, "target": target, "kind": kind},
                        )
                    )
                    continue

                source, records = ledger.source_of(target, kind)
                if source in (Source.USER, Source.SYSTEM):
                    continue
                if source is Source.UNTRUSTED:
                    origin = records[0].label if records else "content the agent read"
                    reasons.append(
                        Reason(
                            "R2-TARGET-UNTRUSTED",
                            Decision.BLOCK,
                            f"The {key} {target!r} came from {origin}, not from you.",
                            {"arg": key, "target": target, "origin": origin},
                        )
                    )
                elif source is Source.PRIVATE:
                    origin = records[0].label if records else "a private file"
                    reasons.append(
                        Reason(
                            "R2-TARGET-PRIVATE",
                            Decision.ASK,
                            f"The {key} {target!r} was read from {origin}; you did not "
                            "name it.",
                            {"arg": key, "target": target, "origin": origin},
                        )
                    )
                else:
                    reasons.append(
                        Reason(
                            "R2-TARGET-UNKNOWN",
                            Decision.ASK,
                            f"The {key} {target!r} appears nowhere you or the tools "
                            "provided, so it needs your approval.",
                            {"arg": key, "target": target},
                        )
                    )
        return reasons

    def _egress(self, spec: ToolSpec, args: dict, ledger: Ledger) -> list[Reason]:
        """Is private data leaving in the payload?"""
        reasons: list[Reason] = []
        payload = "\n".join(
            str(args[k]) for k in spec.payload_args if isinstance(args.get(k), (str, int, float))
        )
        if not payload.strip():
            return reasons

        # Scan what the payload *means*, not only how it is written. A base64
        # blob carries the same credential past a pattern match, so decode first
        # and judge the result as well.
        # Also judge the fields run together, so a credential split across the
        # subject and the body is seen whole.
        joined = "".join(
            str(args[k]) for k in spec.payload_args if isinstance(args.get(k), (str, int, float))
        )
        payload = "\n".join([payload, joined, *_decoded_blobs(payload)])

        findings: list[Finding] = self.scan(payload)
        if findings:
            kinds = sorted({f.kind for f in findings})
            reasons.append(
                Reason(
                    "R3-EGRESS-SECRET",
                    Decision.BLOCK,
                    "The message carries " + _english_list(kinds) + ".",
                    {"kinds": kinds, "masked": [f.masked for f in findings]},
                )
            )

        quoted = _private_overlap(payload, ledger)
        if quoted:
            record, snippet = quoted
            reasons.append(
                Reason(
                    "R3-EGRESS-PRIVATE",
                    Decision.BLOCK,
                    f"The message quotes {record.label}, which is private.",
                    {"origin": record.label, "snippet": snippet},
                )
            )
        return reasons

    # -- tool results --------------------------------------------------------

    def classify_result(self, name: str) -> Source:
        """The label content from this tool carries once it enters the ledger."""
        spec = self.tools.get(name)
        if spec is None:
            return Source.UNTRUSTED
        if spec.reads_private:
            return Source.PRIVATE
        if spec.reads_untrusted:
            return Source.UNTRUSTED
        return Source.SYSTEM


_B64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def _decoded_blobs(payload: str) -> list[str]:
    """Readable text hiding inside base64 blobs in the payload."""
    out = []
    for m in _B64_BLOB_RE.finditer(payload):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            text = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if text and sum(c.isprintable() or c.isspace() for c in text) / len(text) > 0.9:
            out.append(text)
    return out


def _targets_in(raw: str) -> list[tuple[str, str]]:
    """The addressable things inside an argument: addresses, hosts, else itself.

    A URL is judged on its host, because the path is chosen by whoever controls
    the host anyway.
    """
    targets = [("email", e) for e in emails_in(raw)]
    targets += [("host", host_of(u)) for u in urls_in(raw)]
    if not targets:
        targets = [("value", raw.strip())]
    return targets


def _english_list(items: list[str]) -> str:
    words = [i.replace("_", " ") for i in items]
    if len(words) == 1:
        return f"a {words[0]}"
    return "a " + ", a ".join(words[:-1]) + f" and a {words[-1]}"


def _private_overlap(payload: str, ledger: Ledger, window: int = 6) -> tuple | None:
    """Find a run of words copied out of private content.

    Comparing runs of words rather than whole blocks means a leak still shows
    when the model paraphrases around it or sends only the interesting line.
    """
    payload_tokens = [t for t in normalize(payload).split() if t not in _STOP_TOKENS]
    if not payload_tokens:
        return None
    payload_text = " ".join(payload_tokens)

    for record in ledger.of_source(Source.PRIVATE):
        tokens = [t for t in record.normalized.split() if t not in _STOP_TOKENS]
        if not tokens:
            continue
        # Compare the two stripped token streams. Matching the stripped record
        # against the raw payload would miss a quote the model rewrapped with
        # different filler words, which is most of them.
        size = min(window, len(tokens))
        for i in range(len(tokens) - size + 1):
            run = " ".join(tokens[i : i + size])
            if run in payload_text:
                return record, run
    return None
