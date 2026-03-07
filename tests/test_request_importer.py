import json
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from request_importer import RequestImporter


class TestRequestImporter(unittest.TestCase):
    def test_from_curl_command_parses_common_post(self):
        curl_cmd = (
            "curl -X POST https://api.example.com/graphql "
            "-H 'Authorization: Bearer TOKEN123' "
            "-H 'Content-Type: application/json' "
            "-d '{\"query\":\"query Viewer { viewer { id } }\",\"variables\":{\"id\":\"123\"}}'"
        )

        req = RequestImporter.from_curl_command(curl_cmd)

        self.assertEqual(req["url"], "https://api.example.com/graphql")
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["headers"]["Authorization"], "Bearer TOKEN123")
        self.assertEqual(req["query"], "query Viewer { viewer { id } }")
        self.assertEqual(req["variables"], {"id": "123"})
        self.assertEqual(req["operation_name"], "Viewer")

    def test_from_postman_collection_data_extracts_requests(self):
        collection = {
            "info": {"name": "Example", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": [
                {
                    "name": "Folder",
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
                                    "raw": json.dumps({
                                        "query": "query Viewer { viewer { id } }",
                                        "variables": {"id": "123"},
                                    }),
                                },
                            },
                        }
                    ],
                }
            ],
        }

        requests = RequestImporter.from_postman_collection_data(collection)

        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["url"], "https://api.example.com/graphql")
        self.assertEqual(requests[0]["folder"], "Folder")
        self.assertEqual(requests[0]["headers"]["Authorization"], "Bearer TOKEN123")
        self.assertEqual(requests[0]["variables"], {"id": "123"})

    def test_auto_detect_imports_text_curl_file(self):
        curl_cmd = (
            "curl https://api.example.com/graphql "
            "-H 'Content-Type: application/json' "
            "--data-raw '{\"query\":\"{ __typename }\"}'"
        )

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as handle:
            handle.write(curl_cmd)
            path = handle.name

        try:
            req = RequestImporter.auto_detect_and_import(path)
        finally:
            Path(path).unlink(missing_ok=True)

        self.assertEqual(req["url"], "https://api.example.com/graphql")
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["query"], "{ __typename }")


if __name__ == "__main__":
    unittest.main()
