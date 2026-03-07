import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import graphql_client as gqlc


class _FakeResponse:
    def __init__(self, status_code=200, json_obj=None, text="", headers=None):
        self.status_code = status_code
        self._json_obj = json_obj or {"data": {"ok": True}}
        self.text = text or '{"data":{"ok":true}}'
        self.headers = headers or {"Content-Type": "application/json"}

    def json(self):
        return self._json_obj


class _RecordingSession:
    def __init__(self):
        self.calls = []
        self.cookies = {}

    def post(self, url, headers=None, json=None, data=None, files=None, proxies=None, timeout=None, verify=None):
        self.calls.append({
            "url": url,
            "headers": headers or {},
            "json": json,
            "data": data,
            "files": files,
        })
        return _FakeResponse()


class TestGraphQLClientUploads(unittest.TestCase):
    def test_query_without_uploads_uses_json(self):
        session = _RecordingSession()
        with patch.object(gqlc.requests, "Session", return_value=session):
            client = gqlc.GraphQLClient(url="https://x/graphql", headers={"Content-Type": "application/json"}, test_connection=False)
            client.query("query { ping }")

        self.assertEqual(len(session.calls), 1)
        self.assertIsNotNone(session.calls[0]["json"])
        self.assertIsNone(session.calls[0]["data"])
        self.assertIsNone(session.calls[0]["files"])

    def test_query_with_uploads_uses_graphql_multipart_spec(self):
        session = _RecordingSession()
        with patch.object(gqlc.requests, "Session", return_value=session):
            client = gqlc.GraphQLClient(url="https://x/graphql", headers={"Content-Type": "application/json"}, test_connection=False)
            client.query(
                "mutation Upload($file: Upload!) { upload(file: $file) { ok } }",
                variables={"file": "placeholder"},
                operation_name="Upload",
                uploads={
                    "variables.file": {
                        "filename": "proof.txt",
                        "content": b"hello",
                        "content_type": "text/plain",
                    }
                }
            )

        self.assertEqual(len(session.calls), 1)
        call = session.calls[0]
        self.assertIsNone(call["json"])
        self.assertIn("operations", call["data"])
        self.assertIn("map", call["data"])
        self.assertIn("0", call["files"])
        self.assertNotIn("Content-Type", call["headers"])
        self.assertIn('"file": null', call["data"]["operations"])
        self.assertEqual(call["data"]["map"], '{"0": ["variables.file"]}')


if __name__ == "__main__":
    unittest.main()
