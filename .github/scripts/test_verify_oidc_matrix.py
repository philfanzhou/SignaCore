"""Synthetic CLI acceptance tests; no database, network or third-party modules."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

import verify_oidc_matrix as gate


CANARY = "synthetic-value-must-not-reach-validator-output"


def element(parent, tag, **attributes):
    return ET.SubElement(parent, f"{{{gate.NS['t']}}}{tag}", attributes)


def report(cases):
    root = ET.Element(f"{{{gate.NS['t']}}}TestRun")
    definitions = element(root, "TestDefinitions")
    results = element(root, "Results")
    for class_name, names in cases.items():
        for name in names:
            test_id = str(len(results))
            definition = element(definitions, "UnitTest", id=test_id, name=name)
            element(definition, "TestMethod", className=class_name)
            result = element(results, "UnitTestResult", testId=test_id,
                             testName=name, outcome="Passed")
            output = element(result, "Output")
            element(output, "StdOut").text = CANARY
            error = element(output, "ErrorInfo")
            element(error, "Message").text = CANARY
            element(error, "StackTrace").text = CANARY
    summary = element(root, "ResultSummary", outcome="Completed")
    element(summary, "Counters", total=str(len(results)), executed=str(len(results)),
            passed=str(len(results)), failed="0", notExecuted="0")
    return root


class MatrixGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.cases = json.loads(gate.MANIFEST.read_text())
        self.integration = report(self.cases)
        self.bff = report({"OtherClass": ["OtherClass.Case"]})

    def check(self, succeeds=False, raw=None, omit=None, duplicate=False, script=None):
        for index, root in enumerate((self.integration, self.bff)):
            if index == omit:
                continue
            path = self.directory / gate.REPORTS[index]
            ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
            if index == 0 and raw is not None:
                path.write_text(raw)
        if duplicate:
            nested = self.directory / "nested"
            nested.mkdir()
            (nested / gate.REPORTS[0]).write_bytes((self.directory / gate.REPORTS[0]).read_bytes())
        result = subprocess.run(
            [sys.executable, str(script or Path(gate.__file__)), str(self.directory)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode == 0, succeeds)
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_complete_inventory_passes(self):
        self.assertEqual([len(self.cases[c]) for c in gate.CLASSES], [30, 13, 5])
        self.check(succeeds=True)

    def test_missing_reports_fail(self):
        for index in range(2):
            with self.subTest(report=index):
                for path in self.directory.glob("*.trx"):
                    path.unlink()
                self.check(omit=index)

    def test_missing_each_class_fails(self):
        for class_name in gate.CLASSES:
            with self.subTest(class_name=class_name):
                self.integration = report({c: n for c, n in self.cases.items() if c != class_name})
                self.check()

    def test_non_passing_results_fail_in_both_reports(self):
        for index in range(2):
            for outcome in ("NotExecuted", "Skipped", "Failed", "Aborted", "Timeout", "", CANARY):
                with self.subTest(report=index, outcome=outcome):
                    self.integration = report(self.cases)
                    self.bff = report({"OtherClass": ["OtherClass.Case"]})
                    root = (self.integration, self.bff)[index]
                    root.find("t:Results/t:UnitTestResult", gate.NS).set("outcome", outcome)
                    self.check()

    def test_malformed_or_wrong_schema_fails(self):
        for raw in ("", "<" + CANARY, "<TestRun/>", '<TestRun xmlns="urn:wrong"/>'):
            with self.subTest(raw=raw):
                self.check(raw=raw)

    def test_duplicate_report_fails(self):
        self.check(duplicate=True)

    def test_missing_case_or_same_count_replacement_fails(self):
        for replacement in (None, CANARY, self.cases[gate.CLASSES[0]][1]):
            with self.subTest(replacement=replacement):
                cases = copy.deepcopy(self.cases)
                cases[gate.CLASSES[0]].pop(0)
                if replacement is not None:
                    cases[gate.CLASSES[0]].append(replacement)
                self.integration = report(cases)
                self.check()

    def test_extra_case_fails(self):
        self.cases[gate.CLASSES[0]].append(CANARY)
        self.integration = report(self.cases)
        self.check()

    def test_unexecuted_definition_fails(self):
        results = self.integration.find("t:Results", gate.NS)
        results.remove(results[0])
        self.check()

    def test_duplicate_or_unknown_result_id_fails(self):
        for test_id in ("1", CANARY):
            with self.subTest(test_id=test_id):
                self.integration = report(self.cases)
                self.integration.find("t:Results/t:UnitTestResult", gate.NS).set("testId", test_id)
                self.check()

    def test_result_name_must_match_definition(self):
        self.integration.find("t:Results/t:UnitTestResult", gate.NS).set("testName", CANARY)
        self.check()

    def test_failed_summary_or_inconsistent_counters_fail(self):
        for attribute, value in (("outcome", "Failed"), ("total", "49"),
                                 ("executed", "47"), ("passed", "47"),
                                 ("failed", "1"), ("notExecuted", "1"), ("total", CANARY)):
            with self.subTest(attribute=attribute):
                self.integration = report(self.cases)
                path = "t:ResultSummary" if attribute == "outcome" else "t:ResultSummary/t:Counters"
                self.integration.find(path, gate.NS).set(attribute, value)
                self.check()

    def test_missing_summary_fails(self):
        self.integration.remove(self.integration.find("t:ResultSummary", gate.NS))
        self.check()

    def test_validator_exception_fails_without_disclosing_details(self):
        script = self.directory / "verify_oidc_matrix.py"
        script.write_text(Path(gate.__file__).read_text())
        # An invalid manifest type raises an unexpected TypeError inside the validator.
        (self.directory / gate.MANIFEST.name).write_text(json.dumps({c: None for c in gate.CLASSES}))
        self.check(script=script)


if __name__ == "__main__":
    unittest.main()
