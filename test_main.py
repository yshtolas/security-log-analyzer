
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from main import analyze_log, display_results, generate_report


class TestLogAnalyzer(unittest.TestCase):

    def test_sample_log(self):
        failed_attempts, failed_usernames = analyze_log("sample_auth.log")

        self.assertEqual(failed_attempts, {
            "192.0.2.10": 4,
            "203.0.113.20": 3,
            "198.51.100.5": 1
        })

        self.assertEqual(failed_usernames, {
            "admin": 5,
            "gilgamesh": 3
        })

    def test_malformed_log(self):
        failed_attempts, failed_usernames = analyze_log("test_malformed.log")

        self.assertEqual(failed_attempts, {
            "192.0.2.10": 2,
            "203.0.113.20": 2
        })

        self.assertEqual(failed_usernames, {
            "admin": 1,
            "gilgamesh": 1
        })

    def test_no_valid_usernames(self):
        failed_attempts, failed_usernames = analyze_log("test_no_usernames.log")

        self.assertEqual(sum(failed_attempts.values()), 2)
        self.assertEqual(failed_usernames, {})

    def test_suspicious_activity(self):
        failed_attempts = {
            "192.0.2.10": 4,
            "203.0.113.20": 3,
            "198.51.100.5": 1
        }

        with patch("builtins.print"):
            suspicious_count = display_results(failed_attempts, {})

        self.assertEqual(suspicious_count, 2)

    def test_no_suspicious_activity(self):
        failed_attempts = {
            "192.0.2.10": 2,
            "203.0.113.20": 1
        }

        with patch("builtins.print"):
            suspicious_count = display_results(failed_attempts, {})

        self.assertEqual(suspicious_count, 0)

    def test_report_generation(self):
        failed_attempts = {"192.0.2.10": 4}
        failed_usernames = {"admin": 4}

        with TemporaryDirectory() as temporary_folder:

            # Run report generation in a temporary directory.
            import os
            original_directory = os.getcwd()

            try:
                os.chdir(temporary_folder)
                generate_report(failed_attempts, failed_usernames, 1)

                report = Path("security_report.txt").read_text(
                    encoding="utf-8"
                )

                self.assertIn("Security Log Analysis Report", report)
                self.assertIn("192.0.2.10: 4 failed attempts", report)
                self.assertIn("admin: 4 failed attempts", report)
                self.assertIn("Total suspicious IP addresses: 1", report)

            finally:
                os.chdir(original_directory)


if __name__ == "__main__":
    unittest.main()
