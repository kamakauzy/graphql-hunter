import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from auth.redact import redact_headers, redact_text, sanitize_finding


class TestRedact(unittest.TestCase):
    def test_redact_headers_masks_sensitive(self):
        h = {
            "Authorization": "Bearer SECRET_TOKEN_123456",
            "X-API-Key": "KEY_abcdef",
            "Token": "TOKEN_abcdef_123456",
            "Content-Type": "application/json",
        }
        out = redact_headers(h)
        self.assertIn("Content-Type", out)
        self.assertEqual(out["Content-Type"], "application/json")
        self.assertNotEqual(out["Authorization"], h["Authorization"])
        self.assertIn("REDACTED", out["Authorization"])
        self.assertIn("REDACTED", out["X-API-Key"])
        self.assertIn("REDACTED", out["Token"])

    def test_redact_text_masks_bearer_and_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.sgn"
        s = f"Authorization: Bearer {jwt}"
        out = redact_text(s)
        self.assertNotIn(jwt, out)
        self.assertIn("Bearer ***REDACTED***", out)

    def test_sanitize_finding_deep(self):
        finding = {
            "title": "Test",
            "evidence": {
                "headers": {"Authorization": "Bearer abcdef"},
                "password": "supersecret",
                "token": "TOKEN_SECRET_123",
                "cookie": "csrftoken=abcdef1234567890",
            },
            "poc": 'curl -H "Authorization: Bearer abcdef" ...',
        }
        safe = sanitize_finding(finding, extra_sensitive_headers=["Authorization"])
        self.assertNotIn("abcdef", str(safe))
        self.assertNotIn("supersecret", str(safe))
        self.assertNotIn("TOKEN_SECRET_123", str(safe))


if __name__ == "__main__":
    unittest.main()


