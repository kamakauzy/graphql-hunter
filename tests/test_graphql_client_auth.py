import io
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
        self._json_obj = json_obj
        self.text = text
        self.headers = headers or {"Content-Type": "application/json"}

    def json(self):
        if isinstance(self._json_obj, Exception):
            raise self._json_obj
        return self._json_obj


class _FakeSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self.cookies = {}

    def post(self, url, headers=None, json=None, proxies=None, timeout=None, verify=None):
        self.calls.append({"url": url, "headers": headers or {}, "json": json})
        if not self._responses:
            raise AssertionError("No more responses queued")
        return self._responses.pop(0)


class _FakeAuthManager:
    def __init__(self):
        self.prepared = 0
        self.refreshed = 0

    def ensure_prepared(self, client):
        self.prepared += 1

    def get_request_headers(self):
        return {"Authorization": "Bearer SECRET123456"}

    def redact_headers(self, headers):
        # naive mask for test
        out = dict(headers)
        if "Authorization" in out:
            out["Authorization"] = "***REDACTED***"
        return out

    def maybe_refresh_and_retry(self, client, status_code, result):
        if status_code == 401:
            self.refreshed += 1
            return True
        return False


class TestGraphQLClientAuth(unittest.TestCase):
    def test_retry_on_auth_failure(self):
        sess = _FakeSession(
            responses=[
                _FakeResponse(status_code=401, json_obj={"errors": [{"message": "unauthorized"}]}, text="unauthorized"),
                _FakeResponse(status_code=200, json_obj={"data": {"__typename": "X"}}, text='{"data":{}}'),
            ]
        )
        am = _FakeAuthManager()

        with patch.object(gqlc.requests, "Session", return_value=sess):
            c = gqlc.GraphQLClient(url="https://x/graphql", headers={"Content-Type": "application/json"}, auth_manager=am, test_connection=False)
            out = c.query("{__typename}")

        self.assertEqual(out.get("_status_code"), 200)
        self.assertEqual(len(sess.calls), 2)
        self.assertEqual(am.refreshed, 1)

    def test_bypass_auth_skips_prepare_and_retry(self):
        sess = _FakeSession(
            responses=[_FakeResponse(status_code=200, json_obj={"data": {"ok": True}}, text="ok")]
        )
        am = _FakeAuthManager()

        with patch.object(gqlc.requests, "Session", return_value=sess):
            c = gqlc.GraphQLClient(url="https://x/graphql", headers={"Content-Type": "application/json"}, auth_manager=am, test_connection=False)
            out = c.query("{__typename}", bypass_auth=True)

        self.assertEqual(out.get("_status_code"), 200)
        self.assertEqual(am.prepared, 0)

    def test_verbose_redacts_headers_and_payload(self):
        sess = _FakeSession(
            responses=[_FakeResponse(status_code=200, json_obj={"data": {"ok": True}}, text="Bearer abc.def.ghi")]
        )
        am = _FakeAuthManager()

        buf = io.StringIO()
        with patch.object(gqlc.requests, "Session", return_value=sess), patch("sys.stdout", buf):
            c = gqlc.GraphQLClient(url="https://x/graphql", headers={"Content-Type": "application/json"}, auth_manager=am, test_connection=False, verbose=True)
            c.query("query Q($password:String!){x}", variables={"password": "supersecret"})

        s = buf.getvalue()
        self.assertIn("***REDACTED***", s)
        self.assertNotIn("supersecret", s)
        self.assertNotIn("Bearer abc.def.ghi", s)


if __name__ == "__main__":
    unittest.main()


