import io
import sys
import shlex
import unittest
import tempfile

from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch
from pathlib import Path

from secrets_hunter.cli import CLI
from secrets_hunter.config import settings


class TestCLIParse(unittest.TestCase):
    @staticmethod
    def parse_ok(argv):
        print(f"\n[cli-test] cmd  = {shlex.join(argv)}", file=sys.__stderr__)
        with patch("sys.argv", argv):
            return CLI().parse()

    def parse_expect_exit(self, argv):
        print(f"\n[cli-test] cmd  = {shlex.join(argv)}", file=sys.__stderr__)
        out_buf = io.StringIO()
        err_buf = io.StringIO()

        with patch("sys.argv", argv), redirect_stdout(out_buf), redirect_stderr(err_buf):
            with self.assertRaises(SystemExit) as cm:
                CLI().parse()

        return cm.exception.code, out_buf.getvalue(), err_buf.getvalue()

    def assertParseError(self, argv, expected_stderr_fragment, expected_code=2):
        code, out, err = self.parse_expect_exit(argv)

        self.assertEqual(
            code, expected_code,
            msg=f"\nARGV: {argv}\nExpected exit code: {expected_code}\nGot: {code}\nSTDOUT:\n{out}\nSTDERR:\n{err}\n"
        )
        self.assertIn(
            expected_stderr_fragment, err,
            msg=f"\nARGV: {argv}\nExpected STDERR to contain: {expected_stderr_fragment!r}\nSTDOUT:\n{out}\nSTDERR:\n{err}\n"
        )

    def assertHelpExit0(self, argv, expected_stdout_fragment=None):
        code, out, err = self.parse_expect_exit(argv)

        self.assertEqual(
            code, 0,
            msg=f"\nARGV: {argv}\nExpected exit code: 0\nGot: {code}\nSTDOUT:\n{out}\nSTDERR:\n{err}\n"
        )

        self.assertEqual(
            err.strip(), "",
            msg=f"\nARGV: {argv}\nExpected empty STDERR for help.\nSTDOUT:\n{out}\nSTDERR:\n{err}\n"
        )

        if expected_stdout_fragment:
            self.assertIn(
                expected_stdout_fragment, out,
                msg=f"\nARGV: {argv}\nExpected STDOUT to contain: {expected_stdout_fragment!r}\nSTDOUT:\n{out}\n"
            )

    # ---------------- injection behavior ----------------
    def test_injects_scan_when_no_args(self):
        args = self.parse_ok(["secrets-hunter"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.target, ".")

    def test_injects_scan_when_first_arg_is_target(self):
        args = self.parse_ok(["secrets-hunter", "some_dir"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.target, "some_dir")

    def test_injects_scan_when_first_arg_is_option(self):
        args = self.parse_ok(["secrets-hunter", "--workers", "2"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.target, ".")
        self.assertEqual(args.workers, 2)

    def test_unknown_word_is_treated_as_scan_target(self):
        # any unknown first token becomes target (scan injected)
        args = self.parse_ok(["secrets-hunter", "not_a_command"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.target, "not_a_command")

    # ---------------- help behavior ----------------
    def test_help_top_level_exits_0(self):
        self.assertHelpExit0(["secrets-hunter", "--help"], expected_stdout_fragment="Available commands")

    def test_help_top_level_short_exits_0(self):
        self.assertHelpExit0(["secrets-hunter", "-h"], expected_stdout_fragment="Available commands")

    def test_help_scan_exits_0(self):
        self.assertHelpExit0(["secrets-hunter", "scan", "--help"], expected_stdout_fragment="--min-confidence")

    def test_help_showconfig_exits_0(self):
        self.assertHelpExit0(["secrets-hunter", "showconfig", "--help"], expected_stdout_fragment="sections")

    def test_help_with_injection_exits_0(self):
        self.assertHelpExit0(["secrets-hunter", "--workers", "2", "--help"], expected_stdout_fragment="--workers")

    # ---------------- argparse-level errors ----------------
    def test_unknown_flag_errors(self):
        self.assertParseError(
            ["secrets-hunter", "scan", "--nope"],
            "unrecognized arguments: --nope"
        )

    def test_invalid_choice_log_level_errors(self):
        code, out, err = self.parse_expect_exit(["secrets-hunter", "scan", "--log-level", "NOPE"])
        self.assertEqual(code, 2, msg=f"STDERR:\n{err}\nSTDOUT:\n{out}\n")
        self.assertIn("invalid choice", err)
        self.assertIn("--log-level", err)

    def test_invalid_type_workers_errors(self):
        self.assertParseError(
            ["secrets-hunter", "scan", "--workers", "abc"],
            "invalid int value"
        )

    def test_showconfig_invalid_section_choice_errors(self):
        code, out, err = self.parse_expect_exit(["secrets-hunter", "showconfig", "nope_section"])
        self.assertEqual(code, 2, msg=f"STDERR:\n{err}\nSTDOUT:\n{out}\n")
        self.assertIn("invalid choice", err)

    # ---------------- validator: workers ----------------
    def test_workers_invalid_values(self):
        cases = [
            (["secrets-hunter", "scan", "--workers", "0"], "--workers must be > 0"),
            (["secrets-hunter", "scan", "--workers", "-1"], "--workers must be > 0"),
        ]
        for argv, msg in cases:
            with self.subTest(argv=argv):
                self.assertParseError(argv, msg)

    def test_workers_valid_values(self):
        for val in (1, 2):
            with self.subTest(val=val):
                args = self.parse_ok(["secrets-hunter", "scan", "--workers", str(val)])
                self.assertEqual(args.workers, val)

    # ---------------- validator: min-confidence ----------------
    def test_min_confidence_invalid_values(self):
        cases = [
            (["secrets-hunter", "scan", "--min-confidence", "-1"], "--min-confidence must be between 0 and 100"),
            (["secrets-hunter", "scan", "--min-confidence", "101"], "--min-confidence must be between 0 and 100"),
        ]
        for argv, msg in cases:
            with self.subTest(argv=argv):
                self.assertParseError(argv, msg)

    def test_min_confidence_valid_values(self):
        for val in (0, 50, 100):
            with self.subTest(val=val):
                args = self.parse_ok(["secrets-hunter", "scan", "--min-confidence", str(val)])
                self.assertEqual(args.min_confidence, val)

    # ---------------- validator: min-length ----------------
    def test_min_length_invalid_values(self):
        cases = [
            (["secrets-hunter", "scan", "--min-length", "0"], "--min-length must be > 0"),
            (["secrets-hunter", "scan", "--min-length", "-5"], "--min-length must be > 0"),
        ]
        for argv, msg in cases:
            with self.subTest(argv=argv):
                self.assertParseError(argv, msg)

    def test_min_length_valid_value(self):
        args = self.parse_ok(["secrets-hunter", "scan", "--min-length", "1"])
        self.assertEqual(args.min_length, 1)

    # ---------------- validator: entropy bounds ----------------
    def test_hex_entropy_invalid_values(self):
        too_high = settings.HEX_ENTROPY_MAX + 0.01
        cases = [
            (["secrets-hunter", "scan", "--hex-entropy", "-0.1"],
             f"--hex-entropy must be between 0.0 and {settings.HEX_ENTROPY_MAX}"),
            (["secrets-hunter", "scan", "--hex-entropy", str(too_high)],
             f"--hex-entropy must be between 0.0 and {settings.HEX_ENTROPY_MAX}"),
        ]
        for argv, msg in cases:
            with self.subTest(argv=argv):
                self.assertParseError(argv, msg)

    def test_b64_entropy_invalid_values(self):
        too_high = settings.B64_ENTROPY_MAX + 0.01
        cases = [
            (["secrets-hunter", "scan", "--b64-entropy", "-0.1"],
             f"--b64-entropy must be between 0.0 and {settings.B64_ENTROPY_MAX}"),
            (["secrets-hunter", "scan", "--b64-entropy", str(too_high)],
             f"--b64-entropy must be between 0.0 and {settings.B64_ENTROPY_MAX}"),
        ]
        for argv, msg in cases:
            with self.subTest(argv=argv):
                self.assertParseError(argv, msg)

    def test_entropy_valid_boundary_values(self):
        args = self.parse_ok(["secrets-hunter", "scan", "--hex-entropy", "0.0", "--b64-entropy", "0.0"])
        self.assertEqual(args.hex_entropy, 0.0)
        self.assertEqual(args.b64_entropy, 0.0)

        args = self.parse_ok([
            "secrets-hunter", "scan",
            "--hex-entropy", str(settings.HEX_ENTROPY_MAX),
            "--b64-entropy", str(settings.B64_ENTROPY_MAX),
        ])

        self.assertEqual(args.hex_entropy, settings.HEX_ENTROPY_MAX)
        self.assertEqual(args.b64_entropy, settings.B64_ENTROPY_MAX)

    # ---------------- validator: log level (valid) ----------------
    def test_log_level_valid_choice(self):
        args = self.parse_ok(["secrets-hunter", "scan", "--log-level", "DEBUG"])
        self.assertEqual(args.log_level, "DEBUG")

    # ---------------- validator: config files ----------------
    def test_config_must_exist(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "missing.toml"  # doesn't exist
            self.assertParseError(
                ["secrets-hunter", "scan", "--config", str(p)],
                "--config file does not exist:"
            )

    def test_config_must_be_toml(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cfg.txt"
            p.write_text("x", encoding="utf-8")
            self.assertParseError(
                ["secrets-hunter", "scan", "--config", str(p)],
                "--config must be a .toml file:"
            )

    def test_config_multiple_files_ok(self):
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "a.toml"
            p2 = Path(td) / "b.toml"
            p1.write_text("k = 1\n", encoding="utf-8")
            p2.write_text("k = 2\n", encoding="utf-8")
            args = self.parse_ok(["secrets-hunter", "scan", "--config", str(p1), "--config", str(p2)])
            self.assertEqual(args.config, [str(p1), str(p2)])

    # ---------------- validator: output file parent dir ----------------
    def test_json_parent_dir_missing_errors(self):
        with tempfile.TemporaryDirectory() as td:
            missing_dir = Path(td) / "no_such_dir"
            out = missing_dir / "out.json"
            self.assertParseError(
                ["secrets-hunter", "scan", ".", "--json", str(out)],
                "--json parent dir does not exist:"
            )

    def test_sarif_parent_dir_missing_errors(self):
        with tempfile.TemporaryDirectory() as td:
            missing_dir = Path(td) / "no_such_dir"
            out = missing_dir / "out.sarif"
            self.assertParseError(
                ["secrets-hunter", "scan", ".", "--sarif", str(out)],
                "--sarif parent dir does not exist:"
            )

    def test_output_parent_is_file_errors(self):
        with tempfile.TemporaryDirectory() as td:
            parent_file = Path(td) / "not_a_dir"
            parent_file.write_text("x", encoding="utf-8")
            out = parent_file / "out.json"  # parent is a file, not dir
            self.assertParseError(
                ["secrets-hunter", "scan", ".", "--json", str(out)],
                "--json parent dir does not exist:"
            )

    def test_json_parent_dir_exists_ok(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.json"
            args = self.parse_ok(["secrets-hunter", "scan", ".", "--json", str(out)])
            self.assertEqual(args.json_output, str(out))
            self.assertEqual(args.command, "scan")

    def test_sarif_parent_dir_exists_ok(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.sarif"
            args = self.parse_ok(["secrets-hunter", "scan", ".", "--sarif", str(out)])
            self.assertEqual(args.sarif_output, str(out))
            self.assertEqual(args.command, "scan")


if __name__ == "__main__":
    unittest.main()
