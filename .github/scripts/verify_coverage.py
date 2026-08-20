#!/usr/bin/env python3
"""Fail CI when a Cobertura report drops below the repository baseline."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--minimum-line-rate", type=float, required=True)
    parser.add_argument("--minimum-branch-rate", type=float, required=True)
    return parser.parse_args()


def read_rate(root: ET.Element, attribute: str) -> float:
    raw = root.get(attribute)
    if raw is None:
        raise ValueError(f"Cobertura report is missing '{attribute}'.")
    return float(raw)


def main() -> int:
    args = parse_args()
    if not args.report.is_file():
        print(f"Coverage report does not exist: {args.report}", file=sys.stderr)
        return 2

    try:
        root = ET.parse(args.report).getroot()
        line_rate = read_rate(root, "line-rate")
        branch_rate = read_rate(root, "branch-rate")
    except (ET.ParseError, OSError, ValueError) as error:
        print(f"Cannot read coverage report {args.report}: {error}", file=sys.stderr)
        return 2

    print(
        "Coverage: "
        f"lines={line_rate:.2%} (minimum {args.minimum_line_rate:.2%}), "
        f"branches={branch_rate:.2%} (minimum {args.minimum_branch_rate:.2%})"
    )

    failures: list[str] = []
    if line_rate < args.minimum_line_rate:
        failures.append("line coverage")
    if branch_rate < args.minimum_branch_rate:
        failures.append("branch coverage")
    if failures:
        print(f"Coverage baseline failed: {', '.join(failures)}.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
