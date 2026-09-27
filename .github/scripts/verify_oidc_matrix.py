#!/usr/bin/env python3
"""Require complete, passing database reports and the exact OIDC case inventory."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


NS = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}
REPORTS = (
    "signacore-database-contracts.trx",
    "signacore-reference-bff-database-contracts.trx",
)
CLASSES = (
    "SignaCore.Tests.Integration.OidcAttackRateLimitDatabaseContractTests",
    "SignaCore.Tests.Integration.OidcSensitiveCanaryMatrixDatabaseContractTests",
    "SignaCore.Tests.Integration.OidcNamedRevocationDatabaseContractTests",
)
MANIFEST = Path(__file__).with_name("oidc-matrix-cases.json")


class InvalidReport(Exception):
    """A report cannot establish successful execution."""


def read_report(path: Path) -> dict[str, list[tuple[str, str]]]:
    root = ET.parse(path).getroot()
    if root.tag != f"{{{NS['t']}}}TestRun":
        raise InvalidReport

    definitions = {}
    for definition in root.findall("t:TestDefinitions/t:UnitTest", NS):
        test_id = definition.get("id")
        method = definition.find("t:TestMethod", NS)
        if not test_id or test_id in definitions or method is None:
            raise InvalidReport
        definitions[test_id] = (method.get("className"), definition.get("name"))

    results = root.findall("t:Results/t:UnitTestResult", NS)
    seen = set()
    classes: dict[str, list[tuple[str, str]]] = {}
    for result in results:
        test_id = result.get("testId")
        if test_id not in definitions or test_id in seen:
            raise InvalidReport
        seen.add(test_id)
        class_name, name = definitions[test_id]
        if not class_name or not name or name != result.get("testName"):
            raise InvalidReport
        classes.setdefault(class_name, []).append((name, result.get("outcome", "")))
    if not results or seen != definitions.keys():
        raise InvalidReport

    summary = root.find("t:ResultSummary", NS)
    counters = root.find("t:ResultSummary/t:Counters", NS)
    if summary is None or summary.get("outcome") not in ("Completed", "Passed") or counters is None:
        raise InvalidReport
    # A run-level error or incomplete execution must fail even when target rows passed.
    for key in ("total", "executed", "passed"):
        if int(counters.get(key, "-1")) != len(results):
            raise InvalidReport
    if any(int(value) != 0 for key, value in counters.attrib.items()
           if key not in ("total", "executed", "passed")):
        raise InvalidReport
    if any(result.get("outcome") != "Passed" for result in results):
        raise InvalidReport
    return classes


def verify(directory: Path) -> int:
    expected = json.loads(MANIFEST.read_text())
    if set(expected) != set(CLASSES) or any(
        not names or len(names) != len(set(names))
        or any(not name.startswith(class_name + ".") for name in names)
        for class_name, names in expected.items()
    ):
        raise InvalidReport

    reports = []
    for filename in REPORTS:
        paths = list(directory.rglob(filename))
        if len(paths) != 1:
            print(f"OIDC matrix: reports={len(paths)} expected=1 status=invalid")
            return 1
        reports.append(read_report(paths[0]))

    valid = True
    for class_name in CLASSES:
        rows = reports[0].get(class_name, [])
        actual = Counter(name for name, _ in rows)
        wanted = Counter(expected[class_name])
        missing = sum((wanted - actual).values())
        unexpected = sum((actual - wanted).values())
        passed = sum(outcome == "Passed" for _, outcome in rows)
        matches = missing == unexpected == 0 and passed == len(rows)
        valid &= matches
        # Only trusted class names, counts and fixed statuses may reach the log.
        print(f"{class_name}: expected={len(wanted)} executed={len(rows)} "
              f"passed={passed} skipped=0 failed=0 missing={missing} unexpected={unexpected} "
              f"status={'passed' if matches else 'invalid'}")
    return 0 if valid else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path)
    args = parser.parse_args()
    try:
        return verify(args.reports)
    except Exception:
        # XML, paths, case names, exception text and test output may contain secrets.
        # Unexpected validator errors also fail closed without a traceback.
        print("OIDC matrix: status=invalid", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
