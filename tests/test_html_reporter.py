import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from html_reporter import HTMLReporter


class TestHTMLReporter(unittest.TestCase):
    def test_generate_includes_scan_coverage_and_finding_metadata(self):
        metadata = {
            "target": "https://api.example.com/graphql",
            "profile": "quick",
            "safe_mode": True,
            "timestamp": "2026-03-07T00:00:00+00:00",
            "status": "completed",
        }
        findings = [
            {
                "title": "GraphQL Introspection Enabled",
                "severity": "MEDIUM",
                "description": "desc",
                "impact": "impact",
                "remediation": "fix",
                "scanner": "introspection",
                "status": "confirmed",
                "confidence": {"level": "confirmed"},
                "evidence": {"introspection_response": "Full schema retrieved successfully"},
            }
        ]
        summary = {
            "total": 1,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0},
            "by_status": {"confirmed": 1, "potential": 0, "manual_review": 0},
            "confirmed_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0},
            "risk_level": "MEDIUM",
        }
        scan_info = {
            "status": "completed",
            "executed_scanners": ["Introspection", "Injection"],
            "skipped_scanners": [{"scanner": "Rate Limiting", "reason": "disabled by profile"}],
            "failed_scanners": [],
        }

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as handle:
            output_path = handle.name

        try:
            HTMLReporter.generate(metadata, findings, summary, output_path, scan_info=scan_info)
            html = Path(output_path).read_text(encoding="utf-8")
        finally:
            Path(output_path).unlink(missing_ok=True)

        self.assertIn("Scan Status", html)
        self.assertIn("Scanner Coverage", html)
        self.assertIn("completed", html)
        self.assertIn("2 executed / 1 skipped / 0 failed", html)
        self.assertIn("Scanner: introspection", html)
        self.assertIn("Status: confirmed", html)
        self.assertIn("Confidence: confirmed", html)


if __name__ == "__main__":
    unittest.main()
