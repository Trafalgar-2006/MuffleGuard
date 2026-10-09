"""The agent's tools: what each one can reach, and what it does.

The ToolSpec beside each function is the security half: it says whether the tool
returns attacker-controlled content, whether it touches private data, and which
of its arguments name a target. The policy engine reads only that, so adding a
tool means declaring its reach, not writing a new rule.
"""

from __future__ import annotations

from muffleguard.policy import ToolSpec

from .world import World

SPECS: dict[str, ToolSpec] = {
    "inbox_list": ToolSpec(
        "inbox_list", reads_untrusted=True, argument_types={"unread_only": "boolean"}
    ),
    "inbox_read": ToolSpec(
        "inbox_read", reads_untrusted=True, argument_types={"email_id": "integer"},
        required_args=("email_id",),
    ),
    "web_fetch": ToolSpec(
        "web_fetch", reads_untrusted=True, target_args=("url",),
        argument_types={"url": "string"}, required_args=("url",),
    ),
    "files_read": ToolSpec(
        "files_read", reads_private=True, argument_types={"path": "string"},
        required_args=("path",),
    ),
    "email_send": ToolSpec(
        "email_send",
        outbound=True,
        target_args=("to",),
        argument_types={"to": "string", "subject": "string", "body": "string"},
        required_args=("to", "subject", "body"),
    ),
    "http_post": ToolSpec(
        "http_post", outbound=True, target_args=("url",),
        argument_types={"url": "string", "data": "string"}, required_args=("url", "data"),
    ),
    "shell_run": ToolSpec(
        "shell_run", outbound=True, dangerous=True, target_args=("cmd",),
        argument_types={"cmd": "string"}, required_args=("cmd",),
    ),
}

# What the model is told is generated from the same argument declarations that
# the policy and adapter validate. shell_run stays private to the sandbox.
_DESCRIPTIONS = {
    "inbox_list": "List emails in the user's inbox.",
    "inbox_read": "Read the full body of one email by its id.",
    "files_read": "Read one of the user's private files by name.",
    "web_fetch": "Fetch the text of a web page.",
    "email_send": "Send an email on the user's behalf.",
    "http_post": "Post data to a URL.",
}
SCHEMA: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {
                    key: {"type": value} for key, value in SPECS[name].argument_types.items()
                },
                "required": list(SPECS[name].required_args),
                "additionalProperties": False,
            },
        },
    }
    for name, description in _DESCRIPTIONS.items()
]


def validate_tool_args(name: str, args: object) -> str | None:
    spec = SPECS.get(name)
    return spec.validate_args(args) if spec is not None else f"unknown tool {name!r}"


def run_tool(world: World, name: str, args: dict) -> tuple[str, str]:
    """Execute a tool against the fake world.

    Returns the result text and a label naming where it came from, which is what
    the ledger and every block reason quote back to the user.
    """
    invalid = validate_tool_args(name, args)
    if invalid:
        return f"Invalid arguments: {invalid}.", "the tool runner"

    if name == "inbox_list":
        emails = [e for e in world.emails if e.unread or not args.get("unread_only")]
        listing = "\n".join(e.header for e in emails)
        return listing, "your inbox listing"

    if name == "inbox_read":
        email = world.email(int(args.get("email_id", 0)))
        if email is None:
            return "No such email.", "your inbox"
        return (
            f"From: {email.sender}\nSubject: {email.subject}\n\n{email.body}",
            f"email #{email.id} from {email.sender}",
        )

    if name == "files_read":
        path = str(args.get("path", "")).strip()
        if path not in world.files:
            return f"No such file: {path}", "your files"
        return world.files[path], f"your private file {path}"

    if name == "web_fetch":
        url = str(args.get("url", ""))
        return world.pages.get(url, "404 Not Found"), f"the web page {url}"

    if name == "email_send":
        world.sent.append(dict(args))
        return f"Sent to {args.get('to')}.", "the mail server"

    if name == "http_post":
        world.posted.append(dict(args))
        return f"Posted to {args.get('url')}.", "the network"

    if name == "shell_run":
        return "(shell disabled in the sandbox)", "the shell"

    return f"Unknown tool {name}.", "the tool runner"
