#!/usr/bin/env python3
"""Render docs/RULES.md as the standalone Documentation-style Rules page.

The Dashboard opens renderer/rules.html in the system browser.  This keeps that
page derived from the rule register instead of maintaining a second copy by
hand.  Run with --check in CI or release checks to detect drift.
"""
from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "RULES.md"
TARGET = ROOT / "renderer" / "rules.html"
DOCS = ROOT / "renderer" / "docs.html"


def slug(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return value or "section"


def inline(text: str) -> str:
    """Render the inline Markdown used by the register."""
    pieces = re.split(r"(`[^`]*`)", text.strip())
    rendered: list[str] = []
    for piece in pieces:
        if len(piece) >= 2 and piece.startswith("`") and piece.endswith("`"):
            rendered.append(f"<code>{html.escape(piece[1:-1])}</code>")
            continue
        value = html.escape(piece)
        value = re.sub(
            r"\[([^\]]+)\]\(([^)]+)\)",
            r'<a href="\2">\1</a>',
            value,
        )
        value = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", value)
        rendered.append(value)
    return "".join(rendered)


def is_table(lines: list[str], index: int) -> bool:
    return (
        index + 1 < len(lines)
        and lines[index].lstrip().startswith("|")
        and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[index + 1]) is not None
    )


def table(lines: list[str], index: int) -> tuple[str, int]:
    rows: list[list[str]] = []
    while index < len(lines) and lines[index].lstrip().startswith("|"):
        line = lines[index].strip()
        if not re.match(r"^\|[\s:|-]+\|$", line):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            rows.append(cells)
        index += 1
    if not rows:
        return "", index
    header, body = rows[0], rows[1:]
    out = ['          <div class="table-wrap">', '            <table class="rules-table">',
           "              <thead>", "                <tr>"]
    out.extend(f"                  <th>{inline(cell)}</th>" for cell in header)
    out.extend(["                </tr>", "              </thead>", "              <tbody>"])
    for row in body:
        out.append("                <tr>")
        for position, cell in enumerate(row):
            css = ' class="state"' if position == 0 and re.fullmatch(r"`[^`]+`", cell) else ""
            out.append(f"                  <td{css}>{inline(cell)}</td>")
        out.append("                </tr>")
    out.extend(["              </tbody>", "            </table>", "          </div>"])
    return "\n".join(out), index


def list_block(lines: list[str], index: int, ordered: bool) -> tuple[str, int]:
    marker = re.compile(r"^\s*\d+\.\s+" if ordered else r"^\s*-\s+")
    items: list[list[str]] = []
    while index < len(lines):
        line = lines[index]
        if marker.match(line):
            items.append([marker.sub("", line, count=1).strip()])
            index += 1
            continue
        if line.startswith(("  ", "\t")) and items and line.strip():
            items[-1].append(line.strip())
            index += 1
            continue
        break
    tag = "ol" if ordered else "ul"
    out = [f'          <{tag} class="rules-kinds">']
    for item in items:
        out.append(f"            <li>{inline(' '.join(item))}</li>")
    out.append(f"          </{tag}>")
    return "\n".join(out), index


def paragraph(lines: list[str], index: int) -> tuple[str, int]:
    collected: list[str] = []
    while index < len(lines):
        line = lines[index]
        if not line.strip() or line.startswith(("#", "|", "- ")) or re.match(r"^\d+\.\s+", line):
            break
        collected.append(line.strip())
        index += 1
    return f"          <p>{inline(' '.join(collected))}</p>", index


def render(markdown: str) -> str:
    lines = markdown.splitlines()
    title = "Rules and Checks"
    subtitle = ""
    index = 0
    if lines and lines[0].startswith("# "):
        title = re.sub(
            r"^QA Sentinels\s+", "", lines[0][2:].strip(), flags=re.IGNORECASE
        )
        if title.lower() == "rules and checks":
            title = "Rules and Checks"
        index = 1

    sections: list[str] = []
    intro: list[str] = []
    current: list[str] | None = None
    current_title = ""
    first_paragraph = False

    def close_section() -> None:
        nonlocal current
        if current is not None:
            sections.append(
                '        <div class="panel" id="%s">\n          <h3>%s</h3>\n%s\n        </div>'
                % (slug(current_title), html.escape(current_title), "\n".join(current))
            )
        current = None

    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if line.startswith("## ") and not line.startswith("### "):
            close_section()
            current_title = line[3:].strip()
            current = []
            first_paragraph = True
            index += 1
            continue
        if line.startswith("### "):
            if current is None:
                close_section()
                current_title = line[4:].strip()
                current = []
            else:
                current.append(f'          <h4 id="{slug(line[4:].strip())}">'
                               f'{inline(line[4:].strip())}</h4>')
            first_paragraph = True
            index += 1
            continue
        if line.startswith("# "):
            index += 1
            continue
        if is_table(lines, index):
            block, index = table(lines, index)
            first_paragraph = False
        elif re.match(r"^\s*-\s+", line):
            block, index = list_block(lines, index, ordered=False)
            first_paragraph = False
        elif re.match(r"^\s*\d+\.\s+", line):
            block, index = list_block(lines, index, ordered=True)
            first_paragraph = False
        else:
            block, index = paragraph(lines, index)
            if current is None:
                intro.append(block)
                continue
            if first_paragraph:
                block = block.replace('<p>', '<p class="rules-note">', 1)
                first_paragraph = False
        if current is None:
            intro.append(block)
        else:
            current.append(block)
    close_section()

    if not subtitle:
        subtitle = ("Every finding rule, severity, threshold, and operational "
                    "check implemented by QA Sentinels.")
    logo = re.search(
        r'<img class="brand-logo"[^>]*?src="(data:image/png;base64,[^"]+)"',
        DOCS.read_text(encoding="utf-8"),
        re.DOTALL,
    )
    if logo is None:
        raise SystemExit("brand logo not found in renderer/docs.html")

    intro_html = "\n".join(intro) or "          <p>Rule register.</p>"
    if intro_html.startswith("          <p>"):
        intro_html = intro_html.replace('<p>', '<p class="rules-note">', 1)
    intro_html = '          <h3>About this register</h3>\n' + intro_html
    body = "\n\n".join(sections)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; style-src 'self'; img-src 'self' data:;">
  <title>Rules and Checks · QA Dashboard</title>
  <link rel="stylesheet" href="style.css">
</head>
<body data-module="rules">
  <div class="shell">
    <main>
      <header class="topbar">
        <div class="topbar-title">
          <img class="brand-logo" width="34" height="34" alt=""
               src="{logo.group(1)}">
          <div>
            <h2>{html.escape(title)}</h2>
            <p>{html.escape(subtitle)}</p>
          </div>
        </div>
      </header>

      <section class="view active">
        <div class="panel">
{intro_html}
        </div>

{body}

        <div class="panel">
          <h3>Source</h3>
          <p class="rules-note">
            This page is generated from <code>docs/RULES.md</code> by
            <code>tools/build_rules_html.py</code>. The
            <a href="https://github.com/scripting-drafts/QA-Sentinels/blob/main/docs/RULES.md">source register</a>
            remains the authoritative copy.
          </p>
        </div>
      </section>
    </main>
  </div>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail if renderer/rules.html is out of date")
    args = parser.parse_args()
    output = render(SOURCE.read_text(encoding="utf-8"))
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != output:
            print("renderer/rules.html is out of date; run tools/build_rules_html.py",
                  file=sys.stderr)
            return 1
        print("rules-html: renderer/rules.html matches docs/RULES.md")
        return 0
    TARGET.write_text(output, encoding="utf-8")
    print(f"wrote {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
