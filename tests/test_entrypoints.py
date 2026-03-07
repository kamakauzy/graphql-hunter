import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import gqlh


class TestEntrypoints(unittest.TestCase):
    def test_gqlh_wrapper_invokes_legacy_main(self):
        class _Module:
            @staticmethod
            def main():
                return 7

        with patch.object(gqlh, "_load_legacy_cli", return_value=_Module()):
            self.assertEqual(gqlh.main(), 7)


if __name__ == "__main__":
    unittest.main()
