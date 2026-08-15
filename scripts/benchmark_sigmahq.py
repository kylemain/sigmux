#!/usr/bin/env python3
"""Benchmark sigmux against the real, public SigmaHQ rule corpus.

Clones (or reuses) SigmaHQ/sigma and runs every rule under `rules/` (the
project's primary, actively-maintained ruleset -- not the emerging-threats/
threat-hunting/placeholder/deprecated sets, which lean more experimental)
through every sigmux backend. A rule counts as a pass only if it parses
*and* renders cleanly on every registered target -- a much stronger bar
than "sigmux never crashes."

This is deliberately a separate, informational script rather than part of
the unit test suite: it needs network access to clone a many-thousand-file
external repo, which the rest of this project's tests explicitly avoid
requiring (see the README's Testing section).

Usage:
    python scripts/benchmark_sigmahq.py [--corpus-dir PATH] [--limit N] [--json OUT]

Without --corpus-dir, clones a shallow copy of SigmaHQ/sigma into a temp
directory (network required).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sigmux.backends import REGISTRY  # noqa: E402
from sigmux.rule import SigmaRule  # noqa: E402

SIGMAHQ_REPO = "https://github.com/SigmaHQ/sigma.git"


def _clone_corpus(dest: Path) -> Path:
    print(f"Cloning {SIGMAHQ_REPO} (shallow) into {dest} ...", file=sys.stderr)
    subprocess.run(
        ["git", "clone", "--depth", "1", SIGMAHQ_REPO, str(dest)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return dest


def _normalize_error(exc: Exception) -> str:
    msg = str(exc)
    # Collapse rule-specific details (field names, values) so genuinely
    # distinct failure *shapes* group together instead of each rule
    # producing its own unique-looking bucket.
    if "Unsupported modifier" in msg:
        return "Unsupported field modifier (base64/base64offset/cidr/...)"
    if "detection.condition" in msg or "detection" in msg and "block" in msg:
        return "Missing/malformed detection block"
    if "Unexpected" in msg or "Expected" in msg:
        return "Condition-language parse error (correlation rules, timeframe aggregates, ...)"
    if "Unsupported selection shape" in msg:
        return "Unsupported selection shape"
    return msg.splitlines()[0][:120]


def run_benchmark(corpus_dir: Path, limit: Optional[int] = None):
    rule_files = sorted((corpus_dir / "rules").rglob("*.yml"))
    if limit:
        rule_files = rule_files[:limit]

    total = len(rule_files)
    passed = 0
    failures: Counter = Counter()
    failing_examples: dict = {}

    for path in rule_files:
        try:
            text = path.read_text(encoding="utf-8")
            rule = SigmaRule.from_yaml(text)
            for backend in REGISTRY.values():
                backend.render(rule)
            passed += 1
        except Exception as exc:  # noqa: BLE001 - deliberately broad, this is a survey
            key = _normalize_error(exc)
            failures[key] += 1
            failing_examples.setdefault(key, str(path.relative_to(corpus_dir)))

    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": round(100 * passed / total, 1) if total else 0.0,
        "failure_breakdown": [
            {"reason": reason, "count": count, "example": failing_examples[reason]}
            for reason, count in failures.most_common()
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, default=None, help="Existing local checkout of SigmaHQ/sigma")
    parser.add_argument("--limit", type=int, default=None, help="Only process the first N rule files (for quick runs)")
    parser.add_argument("--json", type=Path, default=None, help="Write the full JSON report to this path")
    args = parser.parse_args()

    if args.corpus_dir:
        corpus_dir = args.corpus_dir
    else:
        tmp = Path(tempfile.mkdtemp(prefix="sigmahq-"))
        corpus_dir = _clone_corpus(tmp)

    report = run_benchmark(corpus_dir, args.limit)

    print(f"\nsigmux vs. SigmaHQ/sigma `rules/` corpus")
    print(f"  {report['passed']}/{report['total']} rules converted cleanly to all {len(REGISTRY)} targets ({report['pass_rate']}%)")
    if report["failure_breakdown"]:
        print("\n  Failure breakdown:")
        for item in report["failure_breakdown"]:
            print(f"    {item['count']:>4}  {item['reason']}  (e.g. {item['example']})")

    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n  Full report written to {args.json}")


if __name__ == "__main__":
    main()
