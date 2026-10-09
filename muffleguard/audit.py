"""A tamper-evident record of every decision the guard made.

Each entry stores the hash of the one before it, and a recorded head detects a
missing suffix while its metadata remains intact. This lets the demo detect an
edited row or a deleted tail entry.

It is tamper-*evident*, not tamper-proof: anyone who can write the file can
recompute the whole chain. Making that impossible needs a signature with a key
the writer does not hold, which is noted in the limitations rather than claimed.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    seq       INTEGER PRIMARY KEY,
    ts        REAL    NOT NULL,
    kind      TEXT    NOT NULL,
    payload   TEXT    NOT NULL,
    prev_hash TEXT    NOT NULL,
    hash      TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_head (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    seq       INTEGER NOT NULL,
    hash      TEXT    NOT NULL
)
"""


@dataclass(frozen=True)
class Entry:
    seq: int
    ts: float
    kind: str
    payload: dict
    prev_hash: str
    hash: str


def entry_hash(seq: int, ts: float, kind: str, payload: dict, prev_hash: str) -> str:
    """The hash of one entry, over a canonical encoding of all of its fields.

    sort_keys makes the encoding independent of dict order, so a chain verifies
    the same way in another process.
    """
    body = json.dumps(
        {"seq": seq, "ts": ts, "kind": kind, "payload": payload, "prev_hash": prev_hash},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass
class Verification:
    ok: bool
    checked: int
    broken_at: int | None = None
    detail: str = ""


class AuditLog:
    """An append-only log of guard decisions, in SQLite."""

    def __init__(self, path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        head = self.conn.execute("SELECT seq FROM audit_head WHERE id = 1").fetchone()
        if head is None:
            # Seed an anchor for databases created before audit_head existed.
            last = self.conn.execute("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
            self.conn.execute(
                "INSERT INTO audit_head (id, seq, hash) VALUES (1, ?, ?)",
                (last["seq"], last["hash"]) if last else (0, GENESIS),
            )
        self.conn.commit()
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            self.conn.close()
            self._closed = True

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def append(self, kind: str, payload: dict) -> Entry:
        head = self.conn.execute("SELECT seq, hash FROM audit_head WHERE id = 1").fetchone()
        if head is None:
            raise RuntimeError("recorded audit head is missing")
        seq = head["seq"] + 1
        prev_hash = head["hash"]
        ts = time.time()
        digest = entry_hash(seq, ts, kind, payload, prev_hash)
        self.conn.execute(
            "INSERT INTO entries (seq, ts, kind, payload, prev_hash, hash) VALUES (?,?,?,?,?,?)",
            (seq, ts, kind, json.dumps(payload, sort_keys=True, default=str), prev_hash, digest),
        )
        self.conn.execute("UPDATE audit_head SET seq = ?, hash = ? WHERE id = 1", (seq, digest))
        self.conn.commit()
        return Entry(seq, ts, kind, payload, prev_hash, digest)

    def entries(self) -> list[Entry]:
        rows = self.conn.execute("SELECT * FROM entries ORDER BY seq").fetchall()
        return [
            Entry(r["seq"], r["ts"], r["kind"], json.loads(r["payload"]), r["prev_hash"], r["hash"])
            for r in rows
        ]

    def verify(self) -> Verification:
        """Walk the chain and compare it with the separately maintained DB head."""
        prev_hash = GENESIS
        entries = self.entries()
        head = self.conn.execute("SELECT seq, hash FROM audit_head WHERE id = 1").fetchone()
        if head is None:
            return Verification(False, 0, 1, "recorded audit head is missing")
        for i, e in enumerate(entries):
            if e.seq != i + 1:
                return Verification(False, i, e.seq, f"entry {i + 1} is missing")
            if e.prev_hash != prev_hash:
                return Verification(
                    False, i, e.seq, f"entry {e.seq} does not follow entry {e.seq - 1}"
                )
            expected = entry_hash(e.seq, e.ts, e.kind, e.payload, e.prev_hash)
            if expected != e.hash:
                return Verification(False, i, e.seq, f"entry {e.seq} was altered after it was written")
            prev_hash = e.hash
        last_seq = entries[-1].seq if entries else 0
        if head["seq"] != last_seq or head["hash"] != prev_hash:
            return Verification(
                False,
                len(entries),
                min(head["seq"], last_seq) + 1,
                "entries do not reach the recorded audit head",
            )
        return Verification(True, len(entries))
