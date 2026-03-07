import io
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from reporter import Reporter


class TestReporter(unittest.TestCase):
    def test_summary_stats_include_statuses_and_confirmed_counts(self):
        reporter = Reporter(use_colors=False, verbose=False)
        findings = [
            {"severity": "HIGH", "status": "confirmed"},
            {"severity": "MEDIUM", "status": "potential"},
            {"severity": "INFO", "status": "manual_review", "manual_verification_required": True},
        ]

        summary = reporter.get_summary_stats(findings)

        self.assertEqual(summary["by_status"]["confirmed"], 1)
        self.assertEqual(summary["by_status"]["potential"], 1)
        self.assertEqual(summary["by_status"]["manual_review"], 1)
        self.assertEqual(summary["confirmed_by_severity"]["HIGH"], 1)
        self.assertEqual(summary["risk_level"], "HIGH")

    def test_print_finding_shows_metadata(self):
        reporter = Reporter(use_colors=False, verbose=False)
        finding = {
            "severity": "LOW",
            "title": "Sample Finding",
            "description": "desc",
            "impact": "impact",
            "remediation": "fix",
            "scanner": "xss",
            "status": "manual_review",
            "confidence": {"level": "low"},
        }

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            reporter.print_finding(finding)

        output = buf.getvalue()
        self.assertIn("scanner=xss", output)
        self.assertIn("status=manual_review", output)
        self.assertIn("confidence=low", output)


if __name__ == "__main__":
    unittest.main()
