#!/usr/bin/env python3
"""
roadmap-progress.py - draws the progress bars at the top of README.md from the
checkboxes in ROADMAP.md.

It counts the "- [x]" and "- [ ]" items under each "## " heading in ROADMAP.md,
then rewrites whatever sits between the <!-- progress:start --> and
<!-- progress:end --> markers in README.md. Nothing else in either file is
touched.

How to run it (from the repo root):
    python3 scripts/roadmap-progress.py            update README.md in place
    python3 scripts/roadmap-progress.py --check    exit 1 if README.md is stale

The GitHub Action in .github/workflows/roadmap-progress.yml runs this on every
push to main, so normally you just tick a box in ROADMAP.md and push.
"""

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ROADMAP = ROOT / "ROADMAP.md"
README = ROOT / "README.md"

START = "<!-- progress:start -->"
END = "<!-- progress:end -->"

DONE_CHAR = "#"
TODO_CHAR = "."
OVERALL_WIDTH = 28
PHASE_WIDTH = 16

HEADING_RE = re.compile(r"^##\s+(.*\S)\s*$")
CHECKBOX_RE = re.compile(r"^\s*[-*]\s*\[([ xX])\]")


def parse_roadmap(text):
    """Return one dict per '## ' section that contains checkboxes."""
    sections = []
    current = None
    for line in text.splitlines():
        heading = HEADING_RE.match(line)
        if heading:
            current = {"title": heading.group(1), "done": 0, "total": 0}
            sections.append(current)
            continue
        if current is None:
            continue
        box = CHECKBOX_RE.match(line)
        if box:
            current["total"] += 1
            if box.group(1) in "xX":
                current["done"] += 1
    return [s for s in sections if s["total"]]


def bar(done, total, width):
    """A text bar that never looks finished until it actually is."""
    if total == 0:
        return TODO_CHAR * width
    filled = round(width * done / total)
    if done and filled == 0:
        filled = 1
    if done < total and filled == width:
        filled = width - 1
    return DONE_CHAR * filled + TODO_CHAR * (width - filled)


def percent(done, total):
    return round(100 * done / total) if total else 0


def short_title(title):
    """'Phase 1: Roots (Oct 26 - Dec 20)' -> 'Phase 1: Roots'."""
    return re.sub(r"\s*\([^()]*\)\s*$", "", title)


def render(sections):
    done = sum(s["done"] for s in sections)
    total = sum(s["total"] for s in sections)
    lines = [
        "```",
        f"[{bar(done, total, OVERALL_WIDTH)}]  {percent(done, total)}%"
        f"   {done} of {total} done",
        "```",
        "",
        "| Phase | Progress | Done |",
        "|---|---|---|",
    ]
    for s in sections:
        lines.append(
            f"| {short_title(s['title'])} "
            f"| `{bar(s['done'], s['total'], PHASE_WIDTH)}` {percent(s['done'], s['total'])}% "
            f"| {s['done']}/{s['total']} |"
        )
    return "\n".join(lines)


def splice(readme, block):
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(readme):
        sys.exit(f"error: {START} / {END} markers not found in README.md")
    return pattern.sub(lambda _: f"{START}\n{block}\n{END}", readme, count=1)


def main():
    parser = argparse.ArgumentParser(description="Update the README progress bars.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="don't write anything, just exit 1 if README.md is out of date",
    )
    args = parser.parse_args()

    sections = parse_roadmap(ROADMAP.read_text(encoding="utf-8"))
    if not sections:
        sys.exit("error: no checkboxes found in ROADMAP.md")

    readme = README.read_text(encoding="utf-8")
    updated = splice(readme, render(sections))

    if updated == readme:
        print("README.md progress bars already up to date")
        return
    if args.check:
        sys.exit("README.md progress bars are out of date: run scripts/roadmap-progress.py")

    README.write_text(updated, encoding="utf-8")
    print("README.md progress bars updated")


if __name__ == "__main__":
    main()
