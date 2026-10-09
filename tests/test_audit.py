"""The audit chain: it must notice any edit, in the right place."""

from __future__ import annotations

import json

from muffleguard.audit import AuditLog


def filled(n: int = 5) -> AuditLog:
    log = AuditLog()
    for i in range(n):
        log.append("check.tool_call", {"tool": "email_send", "decision": "block", "i": i})
    return log


def test_a_clean_chain_verifies():
    log = filled()
    result = log.verify()
    assert result.ok and result.checked == 5


def test_an_empty_chain_verifies():
    assert AuditLog().verify().ok


def test_editing_an_entry_is_detected_at_that_entry():
    log = filled()
    log.conn.execute(
        "UPDATE entries SET payload = ? WHERE seq = 3",
        (json.dumps({"tool": "email_send", "decision": "allow", "i": 2}),),
    )
    log.conn.commit()

    result = log.verify()
    assert not result.ok
    assert result.broken_at == 3
    assert "altered" in result.detail


def test_deleting_an_entry_breaks_the_chain():
    log = filled()
    log.conn.execute("DELETE FROM entries WHERE seq = 3")
    log.conn.commit()
    assert not log.verify().ok


def test_each_entry_links_to_the_one_before_it():
    entries = filled(3).entries()
    assert entries[1].prev_hash == entries[0].hash
    assert entries[2].prev_hash == entries[1].hash


def test_hash_covers_the_payload_not_just_the_order():
    """Two logs that differ only in content must differ in their final hash."""
    a, b = AuditLog(), AuditLog()
    a.append("check", {"decision": "block"})
    b.append("check", {"decision": "allow"})
    assert a.entries()[0].hash != b.entries()[0].hash
