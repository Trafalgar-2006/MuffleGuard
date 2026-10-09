"""The invariant, checked on inputs nobody thought to write by hand.

    An outbound tool call may only be allowed when its target
    appears in what the user typed.

Hypothesis searches for a counterexample instead of trusting the cases we
happened to imagine, which is the difference between "our attacks are blocked"
and "this rule holds".
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from muffleguard.normalize import normalize
from muffleguard.policy import Decision, PolicyEngine, ToolSpec
from muffleguard.trace import Ledger, Source

ENGINE = PolicyEngine(
    {
        "email_send": ToolSpec(
            "email_send", outbound=True, target_args=("to",), payload_args=("subject", "body")
        )
    }
)

# Address-shaped text, including the odd spellings an attacker would try.
local = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789._-", min_size=1, max_size=12)
domain = st.sampled_from(["evil.example", "corp.example", "elsewhere.example", "x.co"])
address = st.builds(lambda l, d: f"{l}@{d}", local, domain)
prose = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=120)


@settings(max_examples=300, deadline=None)
@given(target=address, user_text=prose, email_text=prose)
def test_allow_implies_the_user_typed_the_target(target, user_text, email_text):
    """No input may produce ALLOW unless the target is in the user's own words."""
    led = Ledger()
    led.add(Source.USER, "your request", user_text)
    led.add(Source.UNTRUSTED, "email #1", email_text)

    verdict = ENGINE.check_tool_call(
        "email_send", {"to": target, "subject": "s", "body": "b"}, led
    )
    if verdict.decision is Decision.ALLOW:
        assert normalize(target) in normalize(user_text)


@settings(max_examples=200, deadline=None)
@given(target=address, before=prose, after=prose)
def test_an_address_only_in_untrusted_content_is_never_allowed(target, before, after):
    led = Ledger()
    led.add(Source.USER, "your request", "Summarise my unread emails.")
    led.add(Source.UNTRUSTED, "email #4", f"{before} {target} {after}")

    verdict = ENGINE.check_tool_call(
        "email_send", {"to": target, "subject": "s", "body": "b"}, led
    )
    assert verdict.decision is not Decision.ALLOW


@settings(max_examples=200, deadline=None)
@given(secret_tail=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=16, max_size=16))
def test_an_aws_key_in_the_body_is_never_allowed_out(secret_tail):
    """Whoever the recipient is, a credential does not leave."""
    led = Ledger()
    led.add(Source.USER, "your request", "Email priya@corp.example the details.")

    verdict = ENGINE.check_tool_call(
        "email_send",
        {"to": "priya@corp.example", "subject": "s", "body": f"key AKIA{secret_tail}"},
        led,
    )
    assert verdict.decision is Decision.BLOCK


@settings(max_examples=200, deadline=None)
@given(text=prose)
def test_normalisation_is_idempotent(text):
    """Normalising twice changes nothing, or matching would depend on how often it ran."""
    once = normalize(text)
    assert normalize(once) == once
