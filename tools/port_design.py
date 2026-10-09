"""Turn the design-canvas exports into pages a browser can actually run.

The `.dc.html` files the design tool exports are not web pages. Their markup
sits inside an `<x-dc>` wrapper, their head sits inside `<helmet>`, and all of
their behaviour lives in a `<script type="text/x-dc">` that no browser will
ever execute. Opening one shows the layout and nothing else: no theme toggle,
no terminal, no animation. That is why the exported site looked static.

This script does the mechanical half of the port once, so the design markup
stays exactly as it was drawn and only the plumbing changes:

    <helmet> ...        -> a real <head>, with the CDN tags swapped for the
                           vendored copies in assets/vendor and assets/fonts
    ref="{{ setRoot }}" -> dropped; the script finds its own root
    onClick="{{ fn }}"  -> data-action="fn", wired up in assets/motion.js
    <sc-for list=...>   -> an empty container plus a <template>, so the row
                           markup the designer wrote is what JS clones
    {{ name }}          -> <span data-bind="name"></span>

Re-runnable: it reads the exports and overwrites site/*.html.
"""

from __future__ import annotations

import html
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"

PAGES = {
    "MuffleGuard.dc.html": (
        "index.html",
        "MuffleGuard — stop your AI agent obeying the attacker's email",
        "A guard between an AI agent and its tools: it muffles instructions hidden in "
        "content the agent reads, and refuses any action whose target came from that "
        "content rather than from you.",
    ),
    "MuffleGuard Docs.dc.html": (
        "docs.html",
        "MuffleGuard — documentation",
        "Install, flags, the audit log, privacy limits and credits for MuffleGuard.",
    ),
}

# The Attack Lab export is deliberately not built. There is one Attack Lab, and
# it is the running app at /live; a static replica of it would drift away from
# the thing it imitates until a visitor was reading a picture of a result
# rather than a result. Links that pointed at the replica go to the app.
LINKS = {
    "MuffleGuard Docs.dc.html": "docs.html",
    "MuffleGuard%20Docs.dc.html": "docs.html",
    "MuffleGuard Attack Lab.dc.html": "/live",
    "MuffleGuard%20Attack%20Lab.dc.html": "/live",
    "MuffleGuard.dc.html": "index.html",
    "assets/logo-light-bg.png": "assets/logo-light.png",
    "assets/logo-dark-bg.png": "assets/logo-dark.png",
}

HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="assets/logo-light.png">
<link rel="stylesheet" href="assets/fonts.css">
<link rel="stylesheet" href="assets/ds.css">
{style}
<script src="assets/vendor/gsap.min.js" defer></script>
<script src="assets/vendor/ScrollTrigger.min.js" defer></script>
<script src="assets/vendor/anime.min.js" defer></script>
<script src="assets/vendor/motion.js" defer></script>
<script src="assets/motion.js" defer></script>
</head>
<body>
"""

TAIL = "</body>\n</html>\n"


def port(source: Path, out_name: str, title: str, description: str) -> int:
    text = source.read_text(encoding="utf-8")

    style = re.search(r"<style>.*?</style>", text, re.S)
    style = style.group(0) if style else ""

    body = text.split("</helmet>", 1)[1].split('<script type="text/x-dc"', 1)[0]
    body = body.replace("</x-dc>", "")

    # 1. the component ref, which the ported script does not need
    body = re.sub(r'\s*ref="\{\{ setRoot \}\}"', "", body)

    # 2. handlers become declarative, so one delegated listener can serve them
    body = re.sub(r'onClick="\{\{\s*([A-Za-z]+)\s*\}\}"', r'data-action="\1"', body)

    # 3. list rendering: keep the designer's row markup as a <template>.
    #    The template is also the anchor the rows are inserted before, because
    #    a wrapper element cannot be used here: one of these lists sits inside
    #    a <tbody>, and the parser throws any <div> there straight back out of
    #    the table, taking the rows with it. <template> is legal anywhere.
    def unroll(match: re.Match) -> str:
        name, inner = match.group(1), match.group(3)
        return f'<template data-list="{name}" data-tpl="{name}">{inner.strip()}</template>'

    body, lists = re.subn(
        r'<sc-for\s+list="\{\{\s*(\w+)\s*\}\}"\s+as="(\w+)"[^>]*>(.*?)</sc-for>',
        unroll,
        body,
        flags=re.S,
    )

    # 4. remaining single-word bindings become spans the script fills
    body = re.sub(r"\{\{\s*([A-Za-z]\w*)\s*\}\}", r'<span data-bind="\1"></span>', body)

    for old, new in LINKS.items():
        body = body.replace(old, new).replace(html.escape(old), new)

    leftover = re.findall(r"\{\{[^}]*\}\}", body)
    leftover = [x for x in leftover if "." not in x]  # dotted ones live in templates
    if leftover:
        raise SystemExit(f"{out_name}: unresolved bindings {sorted(set(leftover))}")
    if "<x-dc" in body or "sc-for" in body:
        raise SystemExit(f"{out_name}: design wrapper survived the port")

    page = HEAD.format(title=html.escape(title), description=html.escape(description), style=style)
    (SITE / out_name).write_text(page + body.strip() + "\n" + TAIL, encoding="utf-8")
    return lists



LIVE = "https://attack-lab-production.up.railway.app"

# The cropped logo is 20:3. The export sized its box 248x40, which is 6.2:1
# around what was then a 3:1 image, so object-fit:contain shrank the wordmark
# to a third of the height it had room for. Matching the box to the art is the
# whole fix.
LOGO_HEADER = ('style="position:relative;display:block;width:clamp(208px,23vw,304px);'
               'aspect-ratio:20/3;flex:0 0 auto"')
LOGO_FOOTER = ('style="position:relative;display:block;width:clamp(176px,18vw,232px);'
               'aspect-ratio:20/3"')


def _bar(value: int, hot: bool) -> str:
    colour = "var(--mg-hot)" if hot else "var(--mg-ink)"
    return ('<span style="display:block;height:6px;margin-top:10px;background:var(--mg-faint)">'
            f'<span data-fill="{value}" style="display:block;height:100%;background:{colour}'
            ';transform-origin:left center;transform:scaleX(0)"></span></span>')


def fixups(path: Path) -> None:
    """The edits the export needs before it is a page we would ship."""
    t = path.read_text(encoding="utf-8")

    t = t.replace('style="position:relative;display:block;width:248px;height:40px"', LOGO_HEADER)
    t = t.replace('style="position:relative;display:block;width:170px;height:28px"', LOGO_FOOTER)

    # empty custom elements the export left in the portrait grid
    t = t.replace("<g-wrap></g-wrap>", "")

    # the pages are served at /, /docs and /lab, and this deployment's own
    # hostname is now the landing page, so the working lab moved to /live
    t = t.replace('href="index.html"', 'href="/"')
    t = t.replace('href="docs.html"', 'href="/docs"')
    t = t.replace('href="lab.html"', 'href="/live"')
    t = t.replace(LIVE, "/live")
    t = t.replace('href="assets/', 'href="/assets/').replace('src="assets/', 'src="/assets/')

    if path.name == "index.html":
        # the scorecard's first column gets a bar, so the unguarded row fills
        # solid red and the two guarded rows stay visibly empty
        unguarded = '<td style="color:var(--mg-hot);font-weight:700">100% (64/64)</td>'
        guarded = '<td style="font-weight:700">0% (0/64)</td>'
        t = t.replace(unguarded, unguarded[:-5] + _bar(100, True) + "</td>", 1)
        t = t.replace(guarded, guarded[:-5] + _bar(0, False) + "</td>", 2)
        # the terminal panel, so the BLOCK stamp can jolt the whole card
        t = t.replace('<div style="padding:22px 20px;min-height:360px;overflow-x:auto">',
                      '<div data-term-card style="padding:22px 20px;min-height:360px;overflow-x:auto">', 1)

    path.write_text(t, encoding="utf-8")


def main() -> int:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if not src or not src.is_dir():
        raise SystemExit("usage: port_design.py <folder holding the .dc.html exports>")

    SITE.mkdir(exist_ok=True)
    for name, (out_name, title, description) in PAGES.items():
        found = src / name
        if not found.exists():
            raise SystemExit(f"missing export: {name}")
        lists = port(found, out_name, title, description)
        fixups(SITE / out_name)
        print(f"{name} -> site/{out_name} ({lists} list region(s))")

    ds = next(src.glob("_ds/*/styles.css"), None)
    if ds:
        shutil.copyfile(ds, SITE / "assets" / "ds.css")
        print(f"design system -> site/assets/ds.css")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
