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
    "inbox_list": ToolSpec("inbox_list", reads_untrusted=True),
    "inbox_read": ToolSpec("inbox_read", reads_untrusted=True),
    "web_fetch": ToolSpec("web_fetch", reads_untrusted=True, target_args=("url",)),
    "files_read": ToolSpec("files_read", reads_private=True),
    "email_send": ToolSpec(
        "email_send",
        outbound=True,
        target_args=("to",),
        payload_args=("subject", "body"),
    ),
    "http_post": ToolSpec(
        "http_post", outbound=True, target_args=("url",), payload_args=("data",)
    ),
    "shell_run": ToolSpec("shell_run", outbound=True, dangerous=True, target_args=("cmd",)),
}

# What the model is told. Hashed at startup so a change is detectable (P4).
SCHEMA: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "inbox_list",
            "description": "List emails in the user's inbox.",
            "parameters": {
                "type": "object",
                "properties": {"unread_only": {"type": "boolean"}},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "inbox_read",
            "description": "Read the full body of one email by its id.",
            "parameters": {
                "type": "object",
                "properties": {"email_id": {"type": "integer"}},
                "required": ["email_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "files_read",
            "description": "Read one of the user's private files by name.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_fetch",
            "description": "Fetch the text of a web page.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "email_send",
            "description": "Send an email on the user's behalf.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_post",
            "description": "Post data to a URL.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}, "data": {"type": "string"}},
                "required": ["url", "data"],
            },
        },
    },
]


def run_tool(world: World, name: str, args: dict) -> tuple[str, str]:
    """Execute a tool against the fake world.

    Returns the result text and a label naming where it came from, which is what
    the ledger and every block reason quote back to the user.
    """
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
