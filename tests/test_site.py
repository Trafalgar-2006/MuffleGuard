"""The marketing site: its routes, and the two promises the port has to keep.

The pages are generated from design-canvas exports by tools/port_design.py.
Two things about that port are worth a test rather than a careful eye:

  - nothing may be fetched from a CDN. The demo has to survive a venue network
    that blocks one, so every script, stylesheet and font is served from here.
  - no design-canvas wrapper may survive. `<x-dc>`, `<sc-for>` and a
    `text/x-dc` script are inert in a browser: a page that still carries them
    is a page whose behaviour silently does nothing, which is exactly the bug
    the port exists to fix.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from web.app import create_app

SITE = Path(__file__).resolve().parent.parent / "site"
# Derived from what is actually shipped, so deleting or adding a page cannot
# leave the suite testing a file that is gone or skipping one that is new.
PAGES = sorted(p.name for p in SITE.glob("*.html"))


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


@pytest.mark.parametrize(
    "path, needle",
    [
        ("/", "MuffleGuard makes"),
        ("/docs", "MuffleGuard"),
        ("/lab", "Attack Lab"),
        ("/live", "<!doctype html>"),
    ],
)
def test_every_page_is_served(client, path, needle):
    response = client.get(path)
    assert response.status_code == 200
    assert needle.lower() in response.text.lower()


def test_the_landing_page_is_the_root_and_the_working_lab_is_at_live(client):
    """The deployment's own hostname serves the site, so the links must agree."""
    body = client.get("/").text
    assert 'href="/live"' in body
    # a link back to the bare deployment hostname would be a loop
    assert "attack-lab-production.up.railway.app" not in body


def test_assets_are_served(client):
    for asset in ["/assets/motion.js", "/assets/ds.css", "/assets/vendor/gsap.min.js"]:
        assert client.get(asset).status_code == 200, asset


@pytest.mark.parametrize("name", PAGES)
def test_no_page_reaches_for_a_cdn(name):
    body = (SITE / name).read_text(encoding="utf-8")
    for host in ["cdn.jsdelivr.net", "fonts.googleapis.com", "fonts.gstatic.com", "unpkg.com"]:
        assert host not in body, f"{name} still loads from {host}"


def test_the_stylesheet_does_not_import_a_remote_font():
    """An @import is easy to miss and the CSP blocks it, so the page loses its type."""
    assert "fonts.googleapis.com" not in (SITE / "assets" / "ds.css").read_text(encoding="utf-8")


@pytest.mark.parametrize("name", PAGES)
def test_no_design_canvas_wrapper_survived(name):
    body = (SITE / name).read_text(encoding="utf-8")
    for leftover in ["<x-dc", "</x-dc>", "<sc-for", "text/x-dc", "<g-wrap", "support.js"]:
        assert leftover not in body, f"{name} still carries {leftover}"
    # a binding the port missed would render as literal braces on the page
    assert not re.search(r"\{\{\s*[A-Za-z]\w*\s*\}\}", body), f"{name} has an unresolved binding"


@pytest.mark.parametrize("name", PAGES)
def test_every_list_renders_from_a_template_anchor(name):
    """A wrapper element here breaks the audit table: <div> is evicted from <tbody>."""
    body = (SITE / name).read_text(encoding="utf-8")
    assert "<div data-list" not in body
    for match in re.finditer(r'data-list="(\w+)"', body):
        assert f'data-tpl="{match.group(1)}"' in body, f"{name}: {match.group(1)} has no template"


def test_the_page_still_reads_without_javascript():
    """Nothing may start hidden in CSS waiting for a tween that might not run."""
    body = (SITE / "index.html").read_text(encoding="utf-8")
    hidden = re.findall(r"opacity:\s*0[;\"]", body)
    # the only deliberate one is the dark logo, cross-faded by the theme toggle
    assert len(hidden) <= 3, f"{len(hidden)} elements start invisible"


def test_the_policy_allows_what_the_pages_actually_load(client):
    csp = client.get("/").headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert "font-src 'self'" in csp


def test_there_is_one_attack_lab_not_two():
    """A scripted replica of the lab used to be served at /lab.

    Two pages showing the same thing is one too many, and a static copy drifts
    away from the app it imitates until it is quietly lying. The route stays as
    a redirect so older links keep working.
    """
    from fastapi.testclient import TestClient

    from web.app import create_app

    client = TestClient(create_app(passcode="", replay=True), follow_redirects=False)
    response = client.get("/lab")
    # Temporary, not permanent: a 308 is cached by the browser, so restoring a
    # page at /lab later would be unreachable for anyone who had visited once.
    assert response.status_code == 307
    assert response.headers["location"] == "/live"

    assert not (SITE / "lab.html").exists(), "the replica should be gone, not hidden"

    # Nothing in the site should still send a reader to the replica.
    for page in SITE.glob("*.html"):
        assert 'href="/lab"' not in page.read_text(encoding="utf-8"), page.name
