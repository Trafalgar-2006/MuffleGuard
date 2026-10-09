"""Guard.check(event): the one seam every checkpoint goes through.

The agent calls this four times per step, and nothing else in the system is
allowed to decide anything:

    request      what the user typed            -> jailbreak screen
    tool_result  what a tool returned           -> muffle injected sentences
    tool_call    what the model wants to do     -> the policy engine
    answer       what the user is about to read -> leak screen

Keeping it to one function is what makes the guard testable, auditable and
possible to switch off a layer at a time, which the red-team suite relies on:
`Guard(detector=None)` is the honest simulation of a classifier that missed.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Literal

from .audit import AuditLog
from .detectors.hidden import HiddenFinding, find_hidden
from .detectors.secrets import redact, scan
from .policy import Decision, PolicyEngine, Reason, ToolSpec, Verdict
from .trace import Ledger, Source

EventKind = Literal["request", "tool_result", "tool_call", "answer"]


@dataclass
class Event:
    """One thing happening at a checkpoint."""

    kind: EventKind
    text: str = ""
    tool: str = ""
    args: dict = field(default_factory=dict)
    label: str = ""  # where the content came from, in the user's words


@dataclass
class GuardResult:
    decision: Decision
    reasons: tuple[Reason, ...] = ()
    content: str = ""  # the content as it should now be used
    hidden: tuple[HiddenFinding, ...] = ()
    muffled: tuple[str, ...] = ()  # sentences removed before the model read them
    pending_id: str = ""  # set when a human must approve

    @property
    def headline(self) -> str:
        if not self.reasons:
            return "Allowed."
        return max(self.reasons, key=lambda r: r.decision.severity).text

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK


class Guard:
    """Holds the ledger, the policy and the log for one agent run."""

    def __init__(
        self,
        tools: dict[str, ToolSpec],
        detector=None,
        audit: AuditLog | None = None,
        ledger: Ledger | None = None,
        muffle: bool = True,
    ) -> None:
        self.policy = PolicyEngine(tools)
        self.detector = detector  # None means: run on the policy engine alone
        # muffle=False strips nothing, so the model reads the injection in full.
        # It is how the red-team suite simulates every content defence failing
        # at once, leaving only the policy engine to stop the exfiltration.
        self.muffle = muffle
        self._owns_audit = audit is None
        self.audit = audit if audit is not None else AuditLog(
            os.environ.get("MUFFLEGUARD_AUDIT_PATH") or ":memory:"
        )
        self.ledger = Ledger() if ledger is None else ledger
        self.pending: dict[str, tuple[str, dict]] = {}

    def close(self) -> None:
        """Close the audit database when this guard created it."""
        if self._owns_audit:
            self.audit.close()

    def __enter__(self) -> Guard:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # -- the seam ------------------------------------------------------------

    def check(self, event: Event) -> GuardResult:
        result = self._dispatch(event)
        self.audit.append(
            f"check.{event.kind}",
            {
                "tool": event.tool,
                "label": event.label,
                "decision": result.decision.value,
                "rules": [r.rule for r in result.reasons],
                "reasons": [r.text for r in result.reasons],
                "muffled_count": len(result.muffled),
                "hidden": [h.kind for h in result.hidden],
            },
        )
        return result

    def _dispatch(self, event: Event) -> GuardResult:
        if event.kind == "request":
            return self._on_request(event)
        if event.kind == "tool_result":
            return self._on_tool_result(event)
        if event.kind == "tool_call":
            return self._on_tool_call(event)
        if event.kind == "answer":
            return self._on_answer(event)
        raise ValueError(f"unknown event kind: {event.kind!r}")

    # -- checkpoint 1: what the user typed -----------------------------------

    def _on_request(self, event: Event) -> GuardResult:
        """Record the request, and screen it for a jailbreak.

        The request is the one thing the user chose, so it is recorded as USER
        and becomes the basis every outbound target is judged against.
        """
        self.ledger.add(Source.USER, event.label or "your request", event.text)
        reasons: list[Reason] = []
        hidden = tuple(find_hidden(event.text))
        if any(h.imperative for h in hidden):
            reasons.append(
                Reason(
                    "R4-HIDDEN-IN-REQUEST",
                    Decision.ASK,
                    "Your message contains hidden text, which usually means it was "
                    "pasted from somewhere else.",
                    {"kinds": [h.kind for h in hidden]},
                )
            )
        if self.detector is not None:
            spans = self.detector.scan(event.text)
            if spans:
                reasons.append(
                    Reason(
                        "R4-JAILBREAK",
                        Decision.ASK,
                        "This request looks like an attempt to override the agent's rules.",
                        {"scores": [round(s.score, 3) for s in spans]},
                    )
                )
        decision = max((r.decision for r in reasons), key=lambda d: d.severity, default=Decision.ALLOW)
        return GuardResult(decision, tuple(reasons), event.text, hidden)

    # -- checkpoint 2: what a tool returned ----------------------------------

    def _on_tool_result(self, event: Event) -> GuardResult:
        """Muffle instructions hiding in content, then record what is left.

        The content is recorded *before* muffling, because provenance is about
        what the attacker wrote, not about what survived the filter. Removing an
        address from the text the model sees must not remove it from the ledger,
        or the policy would stop recognising it as attacker-chosen.
        """
        source = self.policy.classify_result(event.tool)
        label = event.label or f"the result of {event.tool}"
        content, hidden = _strip_carriers(event.text)

        # Record the decoded hidden text alongside the visible text. An address
        # written in invisible Unicode is normalised out of the raw text, so
        # without this the ledger could not place it and the policy would treat
        # the attacker's recipient as merely unknown, asking instead of refusing.
        revealed = "\n".join(h.revealed for h in hidden)
        self.ledger.add(source, label, f"{event.text}\n{revealed}" if revealed else event.text)

        if not self.muffle:
            return GuardResult(Decision.ALLOW, (), event.text, hidden)

        reasons: list[Reason] = []
        muffled: list[str] = []

        imperative_hidden = [h for h in hidden if h.imperative]
        if imperative_hidden:
            reasons.append(
                Reason(
                    "R5-HIDDEN-CONTENT",
                    Decision.MUFFLE,
                    f"{label} hides {len(imperative_hidden)} instruction(s) in text you "
                    "cannot see.",
                    {"revealed": [h.revealed[:200] for h in imperative_hidden]},
                )
            )
            muffled += [h.revealed for h in imperative_hidden]

        if self.detector is not None and source is Source.UNTRUSTED:
            spans = self.detector.scan(content)
            for span in spans:
                content = content.replace(span.text, "[MUFFLED: instruction removed]")
                muffled.append(span.text)
            if spans:
                reasons.append(
                    Reason(
                        "R5-INJECTION",
                        Decision.MUFFLE,
                        f"{label} contains {len(spans)} sentence(s) addressed to the "
                        "agent rather than to you.",
                        {"scores": [round(s.score, 3) for s in spans]},
                    )
                )

        decision = Decision.MUFFLE if reasons else Decision.ALLOW
        return GuardResult(decision, tuple(reasons), content, tuple(hidden), tuple(muffled))

    # -- checkpoint 3: what the model wants to do ----------------------------

    def _on_tool_call(self, event: Event) -> GuardResult:
        """The policy engine decides. No model is consulted here."""
        verdict: Verdict = self.policy.check_tool_call(event.tool, event.args, self.ledger)
        pending_id = ""
        if verdict.decision is Decision.ASK:
            pending_id = uuid.uuid4().hex[:12]
            self.pending[pending_id] = (event.tool, dict(event.args))
        return GuardResult(verdict.decision, verdict.reasons, pending_id=pending_id)

    # -- checkpoint 4: what the user is about to read ------------------------

    def _on_answer(self, event: Event) -> GuardResult:
        """Redact secrets the answer would print, and strip remote images.

        An image whose URL carries the data is exfiltration that needs no send
        at all: the request to fetch it leaves the moment the answer renders.
        """
        content, findings = redact(event.text)
        content, images = _strip_remote_images(content)
        reasons: list[Reason] = []
        if findings:
            reasons.append(
                Reason(
                    "R6-ANSWER-SECRET",
                    Decision.MUFFLE,
                    "The answer contained " + ", ".join(sorted({f.kind for f in findings}))
                    + ", which has been redacted.",
                    {"masked": [f.masked for f in findings]},
                )
            )
        if images:
            reasons.append(
                Reason(
                    "R6-IMAGE-EXFILTRATION",
                    Decision.MUFFLE,
                    f"{len(images)} remote image(s) were removed; loading one would send "
                    "data to the host in its address.",
                    {"urls": images[:3]},
                )
            )
        decision = Decision.MUFFLE if reasons else Decision.ALLOW
        return GuardResult(decision, tuple(reasons), content)

    # -- approvals -----------------------------------------------------------

    def approve(self, pending_id: str) -> tuple[str, dict]:
        """Release a call the user approved. One use only."""
        if pending_id not in self.pending:
            raise KeyError("this approval has already been used or never existed")
        tool, args = self.pending.pop(pending_id)
        self.audit.append("approval.granted", {"tool": tool, "pending_id": pending_id})
        return tool, args

    def deny(self, pending_id: str) -> None:
        self.pending.pop(pending_id, None)
        self.audit.append("approval.denied", {"pending_id": pending_id})


_IMAGE_RE = __import__("re").compile(
    r"""(?ix)
    !\[[^\]]*\]\(\s*(https?://[^)\s]+)[^)]*\)   # markdown image
    | <img\b[^>]*\bsrc\s*=\s*["'](https?://[^"']+)["'][^>]*>
    """
)


def _strip_remote_images(text: str) -> tuple[str, list[str]]:
    urls: list[str] = []

    def take(match):
        urls.append(match.group(1) or match.group(2))
        return "[remote image removed]"

    return _IMAGE_RE.sub(take, text), urls


def _strip_carriers(text: str) -> tuple[str, tuple[HiddenFinding, ...]]:
    findings = tuple(find_hidden(text))
    cleaned = text
    for f in findings:
        if f.imperative or f.kind in ("unicode_tags", "zero_width"):
            cleaned = cleaned.replace(f.carrier, "")
    return cleaned, findings


__all__ = ["Guard", "Event", "GuardResult", "Decision", "ToolSpec", "scan"]
