import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch

# Directory containing the test script
SCRIPT_DIR = Path(__file__).resolve().parent

# Test data configuration
file_to_scan = str(SCRIPT_DIR / "vulnerabilities.txt")
line_count = 20

# Module and report paths
MODULE = "secrets_hunter.cli"
report_json = str(SCRIPT_DIR / "results.json")
report_sarif = str(SCRIPT_DIR / "results.sarif")


class TestE2E(unittest.TestCase):
    """End-to-end tests for secrets hunter CLI"""

    def setUp(self):
        """Set up test environment before each test"""
        # Clean up any existing reports before running tests
        self._cleanup_reports()

    def tearDown(self):
        """Clean up test environment after each test"""
        # Clean up generated reports after each test
        self._cleanup_reports()

    def _cleanup_reports(self):
        """
        Fixture: Remove generated scan report files if they exist.
        This ensures a clean state before and after each test.
        """
        for report_path in [report_json, report_sarif]:
            path = Path(report_path)
            if path.exists():
                try:
                    path.unlink()
                    print(f"Cleaned up report: {report_path}")
                except Exception as e:
                    print(f"Warning: Could not delete {report_path}: {e}")

    def _validate_report_structure(self, findings, report_type="generic"):
        """
        Helper method to validate common report structure.

        Args:
            findings: List of findings from the report
            report_type: Type of report for error messages
        """
        self.assertEqual(
            len(findings),
            line_count,
            msg=f"{report_type} report: Expected {line_count} findings, got {len(findings)}"
        )

    def _validate_line_numbers(self, findings, line_extractor, report_type="generic"):
        """
        Helper method to validate that findings have correct line numbers.

        Args:
            findings: List of findings from the report
            line_extractor: Function to extract line number from a finding
            report_type: Type of report for error messages
        """
        for i, finding in enumerate(findings):
            expected_line = i + 1
            actual_line = line_extractor(finding)
            self.assertEqual(
                actual_line,
                expected_line,
                msg=f"{report_type} report: Finding {i} - Expected line {expected_line}, got {actual_line}"
            )

    def run_main(self, argv):
        """
        Execute the secrets-hunter CLI with given arguments.

        Args:
            argv: List of command-line arguments

        Returns:
            Exit code from the CLI execution
        """
        print(f"Running command: secrets-hunter {' '.join(argv)}")
        with patch(f"{MODULE}.sys.argv", ["secrets-hunter"] + argv):
            with self.assertRaises(SystemExit) as cm:
                __import__(MODULE, fromlist=["main"]).main()
            return cm.exception.code

    @patch(f"{MODULE}.RuntimeConfigReporter.pretty_runtime_cfg")
    @patch(f"{MODULE}.load_runtime_config")
    def test_json(self, m_load_cfg, m_pretty):
        """
        Test JSON report generation.
        Verifies that the JSON report contains the expected number of findings
        and that each finding has the correct line number.
        """
        # Execute scanner with JSON output
        self.run_main([file_to_scan, "--json", report_json])

        # Wait for file system to flush (if needed)
        time.sleep(0.1)

        # Verify JSON report was created
        self.assertTrue(
            Path(report_json).exists(),
            msg=f"JSON report was not created at {report_json}"
        )

        # Load and validate JSON report
        with open(report_json, "r", encoding="utf-8") as f:
            report = json.load(f)

            # Validate report structure
            self._validate_report_structure(report, "JSON")

            # Validate line numbers
            self._validate_line_numbers(
                report,
                lambda finding: finding["line"],
                "JSON"
            )

    @patch(f"{MODULE}.RuntimeConfigReporter.pretty_runtime_cfg")
    @patch(f"{MODULE}.load_runtime_config")
    def test_sarif(self, m_load_cfg, m_pretty):
        """
        Test SARIF report generation.
        Verifies that the SARIF report contains the expected number of findings
        and that each finding has the correct line number in the proper format.
        """
        # Execute scanner with SARIF output
        self.run_main([file_to_scan, "--sarif", report_sarif])

        # Wait for file system to flush
        time.sleep(0.1)

        # Verify SARIF report was created
        self.assertTrue(
            Path(report_sarif).exists(),
            msg=f"SARIF report was not created at {report_sarif}"
        )

        # Load and validate SARIF report
        with open(report_sarif, "r", encoding="utf-8") as f:
            report = json.load(f)

            # Extract findings from SARIF structure
            findings = report["runs"][0]["results"]

            # Validate report structure
            self._validate_report_structure(findings, "SARIF")

            # Validate line numbers in SARIF format
            self._validate_line_numbers(
                findings,
                lambda finding: finding["locations"][0]["physicalLocation"]["region"]["startLine"],
                "SARIF"
            )


if __name__ == '__main__':
    unittest.main()