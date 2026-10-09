"""Redraw the five portraits in the "Nobody in this row did anything wrong" row.

The exported figures were all one person: the same head, the same body blob,
the same pair of circles for glasses, five times over. The row only works if
the five read as five different people, because the sentence underneath it is
that four of them are ordinary and one of them chose something.

Each portrait keeps the contract the animation code depends on:
  - every shape carries data-draw, so the outline inks itself on
  - a shape with stroke="none" is a solid and fades in behind the line
  - pupils carry data-eye, which is the radius they may travel for the
    cursor-tracking pass
Written as a script rather than by hand-editing the page so the row can be
regenerated if the markup around it moves.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "site" / "index.html"

NECK = '<path data-draw d="M52 84 L52 103 M68 84 L68 103"></path>'


def eyes(left: str = "50", right: str = "70", y: str = "59", r: str = "2.7") -> str:
    return (
        f'<circle data-draw data-eye="2.2" cx="{left}" cy="{y}" r="{r}" fill="currentColor" stroke="none"></circle>'
        f'<circle data-draw data-eye="2.2" cx="{right}" cy="{y}" r="{r}" fill="currentColor" stroke="none"></circle>'
    )


# 1. reading: bob, round spectacles, striped shirt
READER = (
    NECK
    + '<path data-draw d="M7 157 C7 121 27 103 60 103 C93 103 113 121 113 157 Z" fill="currentColor" stroke="none"></path>'
    + '<path data-draw d="M14 134 H106 M11 146 H109" stroke="var(--mg-panel)" stroke-width="3.4"></path>'
    + '<ellipse data-draw cx="60" cy="58" rx="24" ry="27" fill="var(--mg-panel)"></ellipse>'
    + '<path data-draw d="M33 58 C33 25 87 25 87 58 L87 72 C87 52 78 43 60 43 C42 43 33 52 33 72 Z" fill="currentColor" stroke="none"></path>'
    + '<circle data-draw cx="50" cy="59" r="8"></circle>'
    + '<circle data-draw cx="70" cy="59" r="8"></circle>'
    + '<path data-draw d="M58 59 H62 M42 57 L34 55 M78 57 L86 55"></path>'
    + eyes("50", "70", "59", "2.4")
    + '<path data-draw d="M54 75 C57 78 63 78 66 75"></path>'
)

# 2. running the agent: beanie, plain tee, headphones round the neck
OPERATOR = (
    NECK
    + '<path data-draw d="M7 157 C7 121 27 103 60 103 C93 103 113 121 113 157 Z" fill="currentColor" stroke="none"></path>'
    + '<path data-draw d="M44 104 C44 126 76 126 76 104" stroke="var(--mg-panel)" stroke-width="3.2"></path>'
    + '<ellipse data-draw cx="60" cy="58" rx="24" ry="27" fill="var(--mg-panel)"></ellipse>'
    + '<path data-draw d="M34 45 C34 20 86 20 86 45 Z" fill="currentColor" stroke="none"></path>'
    + '<path data-draw d="M32 44 H88 V51 H32 Z" fill="currentColor" stroke="none"></path>'
    + eyes("51", "69", "62")
    + '<path data-draw d="M53 76 C57 80 63 80 67 76"></path>'
    + '<path data-draw d="M36 64 C33 66 33 70 36 72"></path>'
)

# 3. owns the file: top knot, long hair, collared shirt drawn in line only
OWNER = (
    NECK
    + '<path data-draw d="M7 157 C7 121 27 103 60 103 C93 103 113 121 113 157 Z" fill="var(--mg-panel)"></path>'
    + '<path data-draw d="M60 103 L50 120 L60 132 L70 120 Z" fill="currentColor" stroke="none"></path>'
    + '<path data-draw d="M31 60 C31 96 24 110 24 110 L36 110 C36 110 33 92 33 62 Z" fill="currentColor" stroke="none"></path>'
    + '<path data-draw d="M89 60 C89 96 96 110 96 110 L84 110 C84 110 87 92 87 62 Z" fill="currentColor" stroke="none"></path>'
    + '<ellipse data-draw cx="60" cy="58" rx="24" ry="27" fill="var(--mg-panel)"></ellipse>'
    + '<path data-draw d="M33 57 C33 26 87 26 87 57 C87 44 76 38 60 38 C44 38 33 44 33 57 Z" fill="currentColor" stroke="none"></path>'
    + '<circle data-draw cx="60" cy="24" r="9" fill="currentColor" stroke="none"></circle>'
    + eyes("51", "69", "60")
    + '<path data-draw d="M55 74 H65"></path>'
)

# 4. approves nothing: afro, roll-neck, level mouth
APPROVER = (
    NECK
    + '<path data-draw d="M7 157 C7 121 27 103 60 103 C93 103 113 121 113 157 Z" fill="currentColor" stroke="none"></path>'
    + '<path data-draw d="M44 98 C44 112 76 112 76 98 L76 106 C76 120 44 120 44 106 Z" fill="currentColor" stroke="none"></path>'
    + '<ellipse data-draw cx="60" cy="60" rx="23" ry="26" fill="var(--mg-panel)"></ellipse>'
    + '<path data-draw d="M60 15 C80 15 92 28 92 44 C92 54 86 60 86 60 C86 40 76 33 60 33 C44 33 34 40 34 60 C34 60 28 54 28 44 C28 28 40 15 60 15 Z" fill="currentColor" stroke="none"></path>'
    + eyes("51", "69", "61")
    + '<path data-draw d="M54 76 H66"></path>'
)

# 5. sent the mail: hood, a solid bar where the eyes should be, a smirk
VILLAIN = (
    NECK
    + '<path data-draw d="M8 156 C8 120 28 102 60 102 C92 102 112 120 112 156 Z" fill="currentColor" stroke="none"></path>'
    + '<path data-draw d="M24 118 C24 104 40 96 60 96 C80 96 96 104 96 118 L88 118 C88 108 76 103 60 103 C44 103 32 108 32 118 Z" fill="currentColor" stroke="none"></path>'
    + '<ellipse data-draw cx="60" cy="60" rx="24" ry="27" fill="var(--mg-bg)"></ellipse>'
    + '<path data-draw d="M30 50 C30 20 90 20 90 50 L90 56 C90 34 78 28 60 28 C42 28 30 34 30 56 Z" fill="currentColor" stroke="none"></path>'
    + '<path data-draw d="M36 58 H84 V68 H36 Z" fill="currentColor" stroke="none"></path>'
    + '<path data-draw d="M34 56 L30 52 M86 56 L90 52"></path>'
    + '<path data-draw d="M52 80 C57 76 65 78 68 82"></path>'
)

CAST = [
    ("Reads the mail", READER, "var(--mg-ink)"),
    ("Runs the agent", OPERATOR, "var(--mg-ink)"),
    ("Owns the file", OWNER, "var(--mg-ink)"),
    ("Approves nothing", APPROVER, "var(--mg-ink)"),
    ("Sent the mail", VILLAIN, "var(--mg-hot)"),
]


def main() -> int:
    page = PAGE.read_text(encoding="utf-8")
    block = re.compile(r'(<g data-fig(?: data-villain-fig)? style="color:var\(--mg-(?:ink|hot)\)")>.*?</g>', re.S)

    region_start = page.index("<div data-figures")
    region_end = page.index("</div>", page.index("Only the last one chose"))
    head, region, tail = page[:region_start], page[region_start:region_end], page[region_end:]

    found = block.findall(region)
    if len(found) != len(CAST):
        raise SystemExit(f"expected {len(CAST)} portraits in the row, found {len(found)}")

    seen = {"i": 0}

    def swap(match: re.Match) -> str:
        name, body, _ = CAST[seen["i"]]
        seen["i"] += 1
        return match.group(1) + ">" + body + "</g>"

    region = block.sub(swap, region)
    PAGE.write_text(head + region + tail, encoding="utf-8")
    print(f"redrew {seen['i']} portraits; {region.count('data-eye')} pupils track the cursor")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
