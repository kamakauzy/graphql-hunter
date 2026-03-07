import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "scanners"))

from xss_scanner import XSSScanner
from injection_scanner import InjectionScanner
from file_upload_scanner import FileUploadScanner


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
            "fields": [
                {
                    "name": "uploadPaste",
                    "args": [
                        {"name": "filename", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}}},
                        {"name": "content", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}}},
                    ],
                    "type": {"kind": "OBJECT", "name": "UploadPasteResponse"},
                }
            ],
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
        {
            "kind": "OBJECT",
            "name": "UploadPasteResponse",
            "fields": [
                {"name": "result", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
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
        return self.schema["types"][1]["fields"]

    def get_types(self):
        return self.schema["types"]

    def introspect(self, force=False):
        return self.schema

    def query(self, query, variables=None, operation_name=None, **_kwargs):
        variables = variables or {}
        if operation_name and operation_name.startswith("AutoQueryEcho"):
            return {"data": {"echo": {"message": variables.get("message", "")}}, "_status_code": 200}
        if operation_name and operation_name.startswith("AutoQueryLookup"):
            term = variables.get("term", "")
            if "'" in term or "UNION SELECT" in term or "WAITFOR" in term:
                if "WAITFOR" in term:
                    return {"data": {"lookup": {"message": "ok"}}, "_status_code": 200, "_elapsed_seconds": 5.2}
                return {"errors": [{"message": "SQLSTATE syntax error near SELECT"}], "_status_code": 200, "_elapsed_seconds": 0.11}
            return {"data": {"lookup": {"message": "ok"}}, "_status_code": 200, "_elapsed_seconds": 0.1}
        if operation_name and operation_name.startswith("AutoMutationUploadPaste"):
            return {"data": {"uploadPaste": {"result": variables.get("content", "")}}, "_status_code": 200}
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

    def test_injection_scanner_detects_time_based_sqli(self):
        scanner = InjectionScanner(_FakeClient(), _DummyReporter(), {"enable_deep_injection": False})

        findings = scanner.scan()

        self.assertTrue(any("Time-Based" in finding["title"] for finding in findings))

    def test_file_upload_scanner_detects_string_based_upload_surface(self):
        scanner = FileUploadScanner(_FakeClient(), _DummyReporter(), {"safe_mode": True})

        findings = scanner.scan()

        self.assertTrue(findings)
        self.assertEqual(findings[0]["scanner"], "file_upload")
        self.assertIn(findings[0]["status"], {"potential", "manual_review"})

    def test_scanners_can_self_introspect_when_schema_not_preloaded(self):
        client = _FakeClient()
        client.schema = None
        client.introspect = lambda force=False: setattr(client, "schema", SCHEMA) or SCHEMA

        scanner = InjectionScanner(client, _DummyReporter(), {"enable_deep_injection": False})
        findings = scanner.scan()

        self.assertTrue(findings)


if __name__ == "__main__":
    unittest.main()
