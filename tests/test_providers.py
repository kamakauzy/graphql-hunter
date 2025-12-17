import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from auth.providers import (
    APIKeyProvider,
    BearerTokenProvider,
    CookieSessionProvider,
    OAuth2Provider,
    ProviderError,
    ScriptedProvider,
)


class _DummyReporter:
    def __init__(self):
        self.messages = []

    def print_info(self, m):
        self.messages.append(("info", m))

    def print_warning(self, m):
        self.messages.append(("warn", m))


class _DummyClient:
    def __init__(self):
        class S:
            def __init__(self):
                self.cookies = {}

            def post(self, *a, **k):
                raise AssertionError("should not be called in these unit tests")

        self.session = S()
        self.proxies = {}
        self.timeout = 30
        self.verify = True
        self.delay = 0


class TestProviders(unittest.TestCase):
    def test_api_key_missing_raises(self):
        p = APIKeyProvider({"type": "api_key", "header_name": "x-api-key", "var": "api_key"}, variables={})
        with self.assertRaises(ProviderError):
            p.headers_for_request()

    def test_api_key_injects_header(self):
        p = APIKeyProvider({"type": "api_key", "header_name": "x-api-key", "var": "api_key"}, variables={"api_key": "k1"})
        h = p.headers_for_request()
        self.assertEqual(h["x-api-key"], "k1")

    def test_bearer_prefix_normalization(self):
        p = BearerTokenProvider({"type": "bearer", "prefix": "Bearer", "var": "access_token"}, variables={"access_token": "t1"})
        h = p.headers_for_request()
        self.assertEqual(h["Authorization"], "Bearer t1")

    def test_oauth2_client_credentials_builds_grant(self):
        reporter = _DummyReporter()
        client = _DummyClient()
        prov = OAuth2Provider(
            {"type": "oauth2_client_credentials", "token_url": "https://issuer/token", "auth_method": "body"},
            variables={"client_id": "id", "client_secret": "sec"},
            reporter=reporter,
        )

        captured = {}

        def fake_token_request(_client, *, token_url, data, client_id, client_secret, auth_method, headers=None):
            captured["token_url"] = token_url
            captured["data"] = dict(data)
            return {"access_token": "at", "token_type": "Bearer", "expires_in": 3600}

        with patch.object(prov, "_token_request", side_effect=fake_token_request):
            prov.prepare(client)

        self.assertEqual(captured["token_url"], "https://issuer/token")
        self.assertEqual(captured["data"]["grant_type"], "client_credentials")

    def test_cookie_session_runs_login_steps_once(self):
        client = _DummyClient()
        reporter = _DummyReporter()
        profile = {"type": "cookie_session", "login_steps": [{"type": "http", "method": "GET", "url": "https://x"}]}
        prov = CookieSessionProvider(profile, variables={}, reporter=reporter)

        with patch.object(prov._flow, "run", wraps=prov._flow.run) as run_spy:
            # The run() call will fail because DummyClient.session.post isn't used;
            # but our login step uses method GET and will call session.request, which DummyClient lacks.
            # So patch run to just set a var.
            run_spy.side_effect = lambda **kwargs: kwargs["variables"].update({"csrf_token": "c1"})
            prov.prepare(client)
            prov.prepare(client)
            self.assertEqual(run_spy.call_count, 1)

    def test_scripted_provider_renders_headers(self):
        prov = ScriptedProvider(
            {"type": "scripted", "inject_headers": {"Authorization": "Bearer {{access_token}}"}},
            variables={"access_token": "t2"},
        )
        h = prov.headers_for_request()
        self.assertEqual(h["Authorization"], "Bearer t2")


if __name__ == "__main__":
    unittest.main()


