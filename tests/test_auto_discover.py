import json
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from auto_discover import AutoDiscover


class TestAutoDiscover(unittest.TestCase):
    def test_preserves_authorization_header(self):
        notes = "Authorization: Bearer abc.def.ghi\nurl: https://api.example.com/graphql"

        results = AutoDiscover().analyze_notes(notes)

        self.assertIn("Authorization", results["headers"])
        self.assertEqual(results["headers"]["Authorization"], "Bearer abc.def.ghi")

    def test_extracts_distinct_uid_keys(self):
        notes = "\n".join([
            "pdtUid: PDT123",
            "patientUid: PAT456",
            "careteamsUid: CARE789",
        ])

        results = AutoDiscover().analyze_notes(notes)

        self.assertEqual(results["credentials"]["pdt_uid"], "PDT123")
        self.assertEqual(results["credentials"]["patient_uid"], "PAT456")
        self.assertEqual(results["credentials"]["careteams_uid"], "CARE789")

    def test_postman_collection_analysis_uses_in_memory_parser(self):
        collection = {
            "info": {"name": "Example", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": [
                {
                    "name": "ViewerRequest",
                    "request": {
                        "method": "POST",
                        "url": {
                            "protocol": "https",
                            "host": ["api", "example", "com"],
                            "path": ["graphql"],
                        },
                        "header": [{"key": "Authorization", "value": "Bearer TOKEN123"}],
                        "body": {
                            "mode": "raw",
                            "raw": json.dumps({"query": "{ __typename }"}),
                        },
                    },
                }
            ],
        }

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as handle:
            json.dump(collection, handle)
            path = handle.name

        try:
            results = AutoDiscover().analyze_json_file(path)
        finally:
            Path(path).unlink(missing_ok=True)

        self.assertEqual(results["url"], "https://api.example.com/graphql")
        self.assertIn("Authorization", results["headers"])
        self.assertEqual(len(results["queries"]), 1)

    def test_state_resets_between_auto_discover_runs(self):
        discoverer = AutoDiscover()
        first = dict(discoverer.auto_discover(["url: https://first.example/graphql"]))
        second = dict(discoverer.auto_discover(["url: https://second.example/graphql"]))

        self.assertEqual(first["url"], "https://first.example/graphql")
        self.assertEqual(second["url"], "https://second.example/graphql")

    def test_generated_command_prefers_gqlh(self):
        results = AutoDiscover().auto_discover([
            "email: user@example.com",
            "password: YOUR_PASSWORD",
            "url: https://api.example.com/graphql",
        ])

        self.assertTrue(results["recommendations"]["command_simple"].startswith("gqlh "))


if __name__ == "__main__":
    unittest.main()
