import io
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from auth.wizard import _build_result, run_auth_wizard


class TestWizard(unittest.TestCase):
    def test_build_result_bearer(self):
        r = _build_result(url="https://x/graphql", auth_type="b")
        self.assertEqual(r.auth_profile, "bearer")
        self.assertIn("GQLH_ACCESS_TOKEN", r.env_vars)

    def test_run_wizard_prints_command(self):
        # Provide URL, then choose default (bearer) by sending empty choice at menu.
        inputs = iter(["https://example.com/graphql", ""])
        buf = io.StringIO()
        with patch("builtins.input", side_effect=lambda *a, **k: next(inputs)), patch("sys.stdout", buf):
            rc = run_auth_wizard(args=type("A", (), {"url": None})(), reporter=None)
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("python graphql-hunter.py -u", out)
        self.assertIn("--auth-profile bearer", out)
        self.assertIn("GQLH_ACCESS_TOKEN", out)


if __name__ == "__main__":
    unittest.main()


