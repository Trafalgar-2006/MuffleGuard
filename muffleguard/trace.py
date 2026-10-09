"""The provenance ledger: every piece of text the agent has seen, and its origin.

The guard's central question about a tool call is not "does this look safe?" but
"who chose this?". Answering it needs a record of what entered the agent's
context and where each part came from, which is what the ledger holds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .normalize import emails_in, hosts_in, normalize


class Source(str, Enum):
    """Where a piece of content came from, ordered by how far it is trusted."""

    USER = "user"  # typed by the person the agent works for
    SYSTEM = "system"  # our own prompts and tool descriptions
    PRIVATE = "private"  # the user's own secrets and files: never leaves
    UNTRUSTED = "untrusted"  # email bodies, web pages, anything an attacker can write
    MODEL = "model"  # produced by the model, traceable to nothing it read


@dataclass(frozen=True)
class Record:
    """One block of text that entered the agent's context."""

    source: Source
    label: str  # shown to the user: "email #4 from attacker@evil.example"
    text: str

    @property
    def normalized(self) -> str:
        return normalize(self.text)


@dataclass
class Ledger:
    """Everything the agent has read this run, with where each part came from."""

    records: list[Record] = field(default_factory=list)

    def add(self, source: Source, label: str, text: str) -> Record:
        record = Record(source=source, label=label, text=text)
        self.records.append(record)
        return record

    def of_source(self, *sources: Source) -> list[Record]:
        return [r for r in self.records if r.source in sources]

    def origins_of(self, value: str, kind: str = "value") -> list[Record]:
        """Every record this value came from.

        Addresses and hosts are compared as whole units, never as substrings.
        Substring matching would make "lice@corp.example" count as coming from a
        user who typed "alice@corp.example", which is exactly how a lookalike
        address would get itself approved.

        Free text falls back to containment, because a path or a command sits
        inside a sentence. An attacker who rewrites a value so that it no longer
        matches gains nothing: anything the ledger cannot place counts as
        model-invented, and that still needs a human.
        """
        if kind == "email":
            needle = value.casefold()
            return [r for r in self.records if needle in emails_in(r.text)]
        if kind == "host":
            needle = value.casefold()
            return [r for r in self.records if needle in hosts_in(r.text)]
        needle = normalize(value)
        if not needle:
            return []
        return [r for r in self.records if needle in r.normalized]

    def source_of(self, value: str, kind: str = "value") -> tuple[Source, list[Record]]:
        """The effective origin of a value, and the records it was found in.

        A value the user typed is user-sourced even when it also appears in an
        email, because the user chose it; that is the only way an outbound
        target is allowed without a human. A value found nowhere is MODEL.
        """
        found = self.origins_of(value, kind)
        if not found:
            return Source.MODEL, []
        for source in (Source.USER, Source.SYSTEM, Source.PRIVATE, Source.UNTRUSTED):
            matching = [r for r in found if r.source is source]
            if matching:
                return source, matching
        return Source.MODEL, found
