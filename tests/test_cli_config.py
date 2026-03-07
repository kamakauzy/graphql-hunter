import importlib.util
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_main_module():
    module_path = ROOT / "graphql-hunter.py"
    spec = importlib.util.spec_from_file_location("graphql_hunter_main", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestCliConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_main_module()

    def test_get_profile_config_reads_yaml_backed_settings(self):
        profile = self.module.get_profile_config("stealth")

        self.assertEqual(profile["delay"], 1.0)
        self.assertEqual(profile["rate_limit_concurrency"], 10)
        self.assertEqual(profile["timeout"], 30)

    def test_determine_exit_code_uses_confirmed_findings_only(self):
        summary = {
            "confirmed_by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            }
        }
        self.assertEqual(self.module.determine_exit_code(summary), 0)

        summary["confirmed_by_severity"]["HIGH"] = 1
        self.assertEqual(self.module.determine_exit_code(summary), 1)

        summary["confirmed_by_severity"]["CRITICAL"] = 1
        self.assertEqual(self.module.determine_exit_code(summary), 2)


if __name__ == "__main__":
    unittest.main()
