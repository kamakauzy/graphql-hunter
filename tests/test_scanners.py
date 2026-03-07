import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "scanners"))

from xss_scanner import XSSScanner
from injection_scanner import InjectionScanner


SCHEMA = {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {
            "kind": "OBJECT",
            "name": "Query",
            "fields": [
                {
                    "name": "echo",
                    "args": [{"name": "message", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}}}],
                    "type": {"kind": "OBJECT", "name": "EchoResponse"},
                },
                {
                    "name": "lookup",
                    "args": [{"name": "term", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}}}],
                    "type": {"kind": "OBJECT", "name": "LookupResponse"},
                },
            ],
        },
        {
            "kind": "OBJECT",
            "name": "Mutation",
            "fields": [],
        },
        {
            "kind": "OBJECT",
            "name": "EchoResponse",
            "fields": [
                {"name": "message", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
            ],
        },
        {
            "kind": "OBJECT",
            "name": "LookupResponse",
            "fields": [
                {"name": "message", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
            ],
        },
        {"kind": "SCALAR", "name": "String"},
        {"kind": "SCALAR", "name": "ID"},
        {"kind": "SCALAR", "name": "Int"},
        {"kind": "SCALAR", "name": "Float"},
        {"kind": "SCALAR", "name": "Boolean"},
    ],
}


class _DummyReporter:
    def print_info(self, *_args, **_kwargs):
        return None

    def print_warning(self, *_args, **_kwargs):
        return None


class _FakeClient:
    def __init__(self):
        self.schema = SCHEMA
        self.url = "https://api.example.com/graphql"

    def get_queries(self):
        return self.schema["types"][0]["fields"]

    def get_mutations(self):
        return []

    def get_types(self):
        return self.schema["types"]

    def query(self, query, variables=None, operation_name=None, **_kwargs):
        variables = variables or {}
        if operation_name and operation_name.startswith("AutoQueryEcho"):
            return {"data": {"echo": {"message": variables.get("message", "")}}, "_status_code": 200}
        if operation_name and operation_name.startswith("AutoQueryLookup"):
            term = variables.get("term", "")
            if "'" in term or "UNION SELECT" in term or "WAITFOR" in term:
                return {"errors": [{"message": "SQLSTATE syntax error near SELECT"}], "_status_code": 200}
            return {"data": {"lookup": {"message": "ok"}}, "_status_code": 200}
        return {"errors": [{"message": "Unexpected operation"}], "_status_code": 400}


class TestScanners(unittest.TestCase):
    def test_xss_scanner_marks_reflection_as_manual_review(self):
        scanner = XSSScanner(_FakeClient(), _DummyReporter(), {"max_xss_tests": 5})

        findings = scanner.scan()

        self.assertTrue(findings)
        finding = findings[0]
        self.assertEqual(finding["scanner"], "xss")
        self.assertEqual(finding["status"], "manual_review")
        self.assertTrue(finding["manual_verification_required"])
        self.assertEqual(finding["severity"], "MEDIUM")

    def test_injection_scanner_uses_potential_vulnerability_status(self):
        scanner = InjectionScanner(_FakeClient(), _DummyReporter(), {"enable_deep_injection": False})

        findings = scanner.scan()

        self.assertTrue(findings)
        finding = findings[0]
        self.assertEqual(finding["scanner"], "injection")
        self.assertEqual(finding["status"], "potential")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["classification"]["family"], "injection")


if __name__ == "__main__":
    unittest.main()
