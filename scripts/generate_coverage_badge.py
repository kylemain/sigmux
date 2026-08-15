#!/usr/bin/env python3
"""Generate a self-hosted, shields.io-style coverage badge SVG.

Deliberately not a wrapper around a third-party badge-generator package
(the obvious one, `coverage-badge`, turned out to be broken against modern
setuptools -- no `pkg_resources`) or a third-party badge *service*
(shields.io dynamic badges, Codecov, ...), both of which mean depending on
something outside this repo just to render two colored rectangles and some
text. This reads coverage's own `--format=total` output and renders the
SVG directly, so the badge has zero moving parts beyond `coverage` itself.

Usage:
    coverage run -m unittest discover
    python scripts/generate_coverage_badge.py [--out coverage.svg]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

_CHAR_WIDTH = 6.5  # approximate average glyph width for the badge font at 11px
_PAD = 10


def _text_width(text: str) -> float:
    return len(text) * _CHAR_WIDTH + _PAD


def _color_for(pct: int) -> str:
    if pct >= 90:
        return "#4c1"  # bright green
    if pct >= 75:
        return "#97ca00"  # green
    if pct >= 60:
        return "#dfb317"  # yellow
    return "#e05d44"  # red


def _render_svg(label: str, value: str, color: str) -> str:
    label_w = round(_text_width(label))
    value_w = round(_text_width(value))
    total_w = label_w + value_w
    label_x = label_w / 2
    value_x = label_w + value_w / 2
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" role="img" aria-label="{label}: {value}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="m"><rect width="{total_w}" height="20" rx="3" fill="#fff"/></mask>
  <g mask="url(#m)">
    <rect width="{label_w}" height="20" fill="#555"/>
    <rect x="{label_w}" width="{value_w}" height="20" fill="{color}"/>
    <rect width="{total_w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_x}" y="14">{label}</text>
    <text x="{value_x}" y="15" fill="#010101" fill-opacity=".3">{value}</text>
    <text x="{value_x}" y="14">{value}</text>
  </g>
</svg>
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("coverage.svg"))
    parser.add_argument("--label", default="coverage")
    args = parser.parse_args()

    result = subprocess.run(
        ["coverage", "report", "--format=total"], capture_output=True, text=True
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        raise SystemExit("`coverage report` failed -- run `coverage run -m unittest discover` first")

    pct = int(result.stdout.strip())
    svg = _render_svg(args.label, f"{pct}%", _color_for(pct))
    args.out.write_text(svg, encoding="utf-8")
    print(f"{args.label}: {pct}% -> wrote {args.out}")


if __name__ == "__main__":
    main()
