import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from secrets_hunter.models import Confidence

# Directory containing the test script
SCRIPT_DIR = Path(__file__).resolve().parent

# Test data configuration
secrets = str(SCRIPT_DIR / "secrets.txt")
mid_secrets = str(SCRIPT_DIR / "secrets.txt")
zero_secrets = str(SCRIPT_DIR / "secrets.txt")

# Module and report paths
MODULE = "secrets_hunter.cli"
report_json = str(SCRIPT_DIR / "results.json")
report_sarif = str(SCRIPT_DIR / "results.sarif")


class TestE2E(unittest.TestCase):
    """End-to-end tests for secrets hunter CLI"""

    def setUp(self):
        """Set up test environment before each test"""
        self._cleanup_reports()

    def tearDown(self):
        """Clean up test environment after each test"""
        self._cleanup_reports()

    def _load_source_lines(self, file_to_scan):
        """
        Load and cache lines from the source file being scanned.
        This allows us to show actual content of missing lines.
        """
        try:
            with open(file_to_scan, "r", encoding="utf-8") as f:
                self.source_lines = f.readlines()
            print(f"Loaded {len(self.source_lines)} lines from {file_to_scan}")
        except Exception as e:
            print(f"Warning: Could not load source file: {e}")
            self.source_lines = []

    def _get_line_content(self, line_number):
        """
        Get content of a specific line from the source file.

        Args:
            line_number: Line number (1-indexed)

        Returns:
            String content of the line, or error message if not available
        """
        if not self.source_lines:
            return "<source file not loaded>"

        if 1 <= line_number <= len(self.source_lines):
            content = self.source_lines[line_number - 1].rstrip('\n')
            max_length = 100
            if len(content) > max_length:
                content = content[:max_length] + "..."
            return content
        else:
            return "<line number out of range>"

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

    def _validate_line_numbers(self, findings, line_extractor, line_count):
        """
        Helper method to validate that findings have correct line numbers.
        Collects all missing lines and reports them together with their content.

        Args:
            findings: List of findings from the report
            line_extractor: Function to extract line number from a finding
            line_count: Awaited line count
        """
        expected_lines = set(range(1, line_count + 1))

        actual_lines = set()
        for finding in findings:
            try:
                line_num = line_extractor(finding)
                actual_lines.add(line_num)
            except (KeyError, IndexError, TypeError) as e:
                print(f"Warning: Could not extract line number from finding: {e}")

        missing_lines = expected_lines - actual_lines

        extra_lines = actual_lines - expected_lines

        error_messages = []

        if missing_lines:
            sorted_missing = sorted(missing_lines)

            error_messages.append("\nContent of missing lines:")
            for line_num in sorted_missing:
                content = self._get_line_content(line_num)
                error_messages.append(f"Missed line || Line {line_num}: {content}")

        if extra_lines:
            sorted_extra = sorted(extra_lines)
            error_messages.append(
                f"\nUnexpected lines in report: {sorted_extra} "
                f"(total: {len(extra_lines)})"
            )

        return error_messages

    def _check_confidence(self,
                          findings,
                          confidence_extractor,
                          line_extractor,
                          awaited_confidence,
                          ):
        error_messages = []
        for finding in findings:
            try:
                confidence = confidence_extractor(finding)
                if confidence != awaited_confidence:
                    line_num = line_extractor(finding)

                    content = self._get_line_content(line_num)
                    error_messages.append(
                        f"Confidence {confidence} != awaited {awaited_confidence} || Line {line_num}: {content}")
            except (KeyError, IndexError, TypeError) as e:
                print(f"Warning: Could not extract line number from finding: {e}")
        return error_messages
        self.assertFalse(
            error_messages,
            msg="\n".join(error_messages) if error_messages else ""
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
        self.run_main([secrets, "--json", report_json])
        self._load_source_lines(secrets)
        time.sleep(0.1)

        self.assertTrue(
            Path(report_json).exists(),
            msg=f"JSON report was not created at {report_json}"
        )

        with open(report_json, "r", encoding="utf-8") as f:
            report = json.load(f)

            # self._validate_report_structure(report, "JSON")

            line_numbers_errors = self._validate_line_numbers(
                report,
                lambda finding: finding["line"],
                len(self.source_lines),
            )
            confidence_error = self._check_confidence(
                report,
                lambda finding: finding["confidence"],
                lambda finding: finding["line"],
                awaited_confidence=Confidence.VERIFIED,
            )
            error_messages = line_numbers_errors + confidence_error
            if error_messages:
                self.assertFalse(
                    error_messages,
                    msg="\n".join(error_messages) if error_messages else ""
                )

    @patch(f"{MODULE}.RuntimeConfigReporter.pretty_runtime_cfg")
    @patch(f"{MODULE}.load_runtime_config")
    def test_sarif(self, m_load_cfg, m_pretty):
        """
        Test SARIF report generation.
        Verifies that the SARIF report contains the expected number of findings
        and that each finding has the correct line number in the proper format.
        """
        self.run_main([secrets, "--sarif", report_sarif])
        self._load_source_lines(secrets)
        time.sleep(0.1)

        self.assertTrue(
            Path(report_sarif).exists(),
            msg=f"SARIF report was not created at {report_sarif}"
        )

        with open(report_sarif, "r", encoding="utf-8") as f:
            report = json.load(f)["runs"][0]["results"]

            #  self._validate_report_structure(findings, "SARIF")

            line_numbers_errors = self._validate_line_numbers(
                report,
                lambda finding: finding["locations"][0]["physicalLocation"]["region"]["startLine"],
                len(self.source_lines),
            )
            confidence_error = self._check_confidence(
                report,
                lambda finding: finding["properties"]["confidence"],
                lambda finding: finding["locations"][0]["physicalLocation"]["region"]["startLine"],
                awaited_confidence=Confidence.VERIFIED,
            )
            error_messages = line_numbers_errors + confidence_error

            if error_messages:
                self.assertFalse(
                    error_messages,
                    msg="\n".join(error_messages) if error_messages else ""
                )


if __name__ == '__main__':
    unittest.main()
