import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from auth.flows import FlowRunner, extract_json_path, render_template


class _FakeCookieJar(dict):
    def get(self, name, default=None):
        return super().get(name, default)


class _FakeSession:
    def __init__(self):
        self.cookies = _FakeCookieJar()
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))

        class Resp:
            status_code = 200
            headers = {"x-csrf-token": "csrf123"}
            text = '{"ok": true}'

            def json(self):
                return {"ok": True}

        return Resp()


class _FakeClient:
    def __init__(self):
        self.session = _FakeSession()
        self.proxies = {}
        self.timeout = 30
        self.verify = True
        self.delay = 0
        self._query_calls = []

    def query(self, query, variables=None, operation_name=None, extra_headers=None, bypass_auth=False):
        self._query_calls.append(
            {
                "query": query,
                "variables": variables,
                "operation_name": operation_name,
                "extra_headers": extra_headers,
                "bypass_auth": bypass_auth,
            }
        )
        return {"data": {"login": {"accessToken": "tok123"}}, "_status_code": 200, "_headers": {"h": "v"}}


class TestFlows(unittest.TestCase):
    def test_render_template_recursive(self):
        obj = {"a": "{{x}}", "b": [{"c": "hi {{y}}"}]}
        out = render_template(obj, {"x": "1", "y": "there"})
        self.assertEqual(out["a"], "1")
        self.assertEqual(out["b"][0]["c"], "hi there")

    def test_extract_json_path(self):
        obj = {"data": {"tokens": [{"access_token": "a1"}]}}
        self.assertEqual(extract_json_path(obj, "data.tokens[0].access_token"), "a1")

    def test_http_step_and_header_extractor(self):
        client = _FakeClient()
        runner = FlowRunner(verbose=False)
        vars_ = {}
        runner.run(
            client=client,
            steps=[
                {
                    "type": "http",
                    "method": "GET",
                    "url": "https://example.local/csrf",
                    "extract": [{"var": "csrf_token", "from": "header", "name": "X-CSRF-Token"}],
                }
            ],
            variables=vars_,
        )
        self.assertEqual(vars_["csrf_token"], "csrf123")

    def test_cookie_extractor(self):
        client = _FakeClient()
        client.session.cookies["sessionid"] = "s123"
        runner = FlowRunner(verbose=False)
        vars_ = {}
        runner.run(
            client=client,
            steps=[
                {
                    "type": "http",
                    "method": "GET",
                    "url": "https://example.local/",
                    "extract": [{"var": "sid", "from": "cookie", "name": "sessionid"}],
                }
            ],
            variables=vars_,
        )
        self.assertEqual(vars_["sid"], "s123")

    def test_graphql_step_bypasses_auth(self):
        client = _FakeClient()
        runner = FlowRunner(verbose=False)
        vars_ = {"username": "u", "password": "p"}
        runner.run(
            client=client,
            steps=[
                {
                    "type": "graphql",
                    "query": "mutation { login { accessToken } }",
                    "extract": [{"var": "access_token", "from": "json", "path": "data.login.accessToken"}],
                }
            ],
            variables=vars_,
        )
        self.assertEqual(vars_["access_token"], "tok123")
        self.assertTrue(client._query_calls[0]["bypass_auth"])


if __name__ == "__main__":
    unittest.main()


