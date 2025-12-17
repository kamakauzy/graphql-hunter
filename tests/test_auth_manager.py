import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from auth.manager import AuthConfigError, AuthManager


class TestAuthManager(unittest.TestCase):
    def test_selects_static_headers_when_token_or_headers(self):
        m = AuthManager(reporter=None, auth_config_path=None, auth_profile=None)
        sel = m.select_provider(token="t1", headers={"X": "Y"})
        self.assertIsNotNone(sel.provider)
        h = sel.provider.headers_for_request()
        # StaticHeadersProvider returns the merged header set created at selection time.
        self.assertIn("Authorization", h)
        self.assertEqual(h["X"], "Y")

    def test_loads_profile_from_yaml(self):
        cfg = """profiles:\n  p1:\n    type: api_key\n    header_name: x-api-key\n    var: api_key\n"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as f:
            f.write(cfg)
            path = f.name
        try:
            m = AuthManager(reporter=None, auth_config_path=path, auth_profile="p1")
            m.select_provider(token=None, headers={})
            self.assertIsNotNone(m._selection.provider)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_missing_profile_raises(self):
        cfg = "profiles: {}\n"
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as f:
            f.write(cfg)
            path = f.name
        try:
            m = AuthManager(reporter=None, auth_config_path=path, auth_profile="nope")
            with self.assertRaises(AuthConfigError):
                m.select_provider(token=None, headers={})
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()


