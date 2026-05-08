import re
import tempfile
import unittest

from pathlib import Path
from unittest.mock import MagicMock

from secrets_hunter.config import CLIArgs
from secrets_hunter.detection.fragmenter import GenericStringFragment
from secrets_hunter.models import Confidence, DetectionMethod, Finding, Severity
from secrets_hunter.models.config import RuntimeConfig
from secrets_hunter.scan_modes.git_history.reader import GitHistoryReader
from secrets_hunter.scan_modes.git_history.scanner import GitBlobRef, GitHistoryScanner

TOKEN = "ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN"
COMMIT_A = "4f3c2b1a9e8d7c6b5a4f302918273645abcdef12"
COMMIT_B = "8e2f4d9a6c1b3f507a92d4e6b8c0f13579abcde0"


def runtime_config_with_ignores() -> RuntimeConfig:
    return RuntimeConfig(
        secret_patterns={},
        exclude_patterns=[],
        exclude_keywords=[],
        secret_keywords=[],
        assignment_patterns=[re.compile(r"unused")],
        ignore_files=("ignored.env",),
        ignore_extensions=(".bin",),
        ignore_dirs=("vendor",)
    )


def finding(line: int) -> Finding:
    return Finding(
        title="Hardcoded API key",
        file="repo/.env",
        line=line,
        type="API Key",
        match=TOKEN,
        context=f"GITHUB_TOKEN={TOKEN}",
        severity=Severity.HIGH,
        confidence_reasoning="pattern",
        detection_method=DetectionMethod.PATTERN,
        confidence=Confidence.VERIFIED,
        fragment=GenericStringFragment(TOKEN)
    )


def make_git_reader(
    repo_root: Path,
    commits: list[str],
    changed_files: dict[str, list[str]],
    matching_paths: set[str] | None = None,
) -> GitHistoryReader:
    reader = MagicMock(spec=GitHistoryReader)
    reader.repo_root = repo_root
    reader.list_commits.side_effect = lambda revset, max_count=None: (
        commits if max_count is None else commits[:max_count]
    )
    reader.list_changed_files.side_effect = lambda commit_sha: changed_files.get(commit_sha, [])
    reader.target_matches.side_effect = lambda target_path, repo_rel_path: (
        True if matching_paths is None else repo_rel_path in matching_paths
    )
    return reader


class TestGitHistoryScanner(unittest.TestCase):
    def test_collect_git_blobs_sets_empty_message_when_no_commits_selected(self):
        with tempfile.TemporaryDirectory() as td:
            scanner = GitHistoryScanner(runtime_config_with_ignores(), CLIArgs(), td, "HEAD")
            reader = make_git_reader(Path(td), [], {})

            blobs = scanner.collect_git_blobs(reader)

        self.assertEqual(blobs, [])
        self.assertEqual(scanner.empty_message, "No commits selected")

    def test_collect_git_blobs_filters_target_mismatches_and_ignored_paths(self):
        with tempfile.TemporaryDirectory() as td:
            scanner = GitHistoryScanner(runtime_config_with_ignores(), CLIArgs(), td, "HEAD")
            reader = make_git_reader(
                Path(td),
                commits=[COMMIT_A],
                changed_files={
                    COMMIT_A: [
                        ".env",
                        "ignored.env",
                        "image.bin",
                        "vendor/config.env",
                        "other/.env",
                    ],
                },
                matching_paths={".env", "ignored.env", "image.bin", "vendor/config.env"}
            )

            blobs = scanner.collect_git_blobs(reader)

        self.assertEqual(blobs, [GitBlobRef(COMMIT_A, ".env")])

    def test_collect_git_blobs_honors_max_count(self):
        with tempfile.TemporaryDirectory() as td:
            scanner = GitHistoryScanner(runtime_config_with_ignores(), CLIArgs(), td, "HEAD", max_count=1)
            reader = make_git_reader(
                Path(td),
                commits=[COMMIT_A, COMMIT_B],
                changed_files={COMMIT_A: ["a.env"], COMMIT_B: ["b.env"]}
            )

            blobs = scanner.collect_git_blobs(reader)

        self.assertEqual(blobs, [GitBlobRef(COMMIT_A, "a.env")])

    def test_scan_git_blob_returns_failure_when_blob_is_missing(self):
        git_reader = MagicMock()
        git_reader.read_blob.return_value = None
        scanner = GitHistoryScanner(runtime_config_with_ignores(), CLIArgs(), ".", "HEAD")

        findings, success = scanner.scan_git_blob(git_reader, COMMIT_A, ".env")

        self.assertEqual(findings, [])
        self.assertFalse(success)

    def test_scan_git_blob_skips_binary_blob_as_success(self):
        git_reader = MagicMock()
        git_reader.read_blob.return_value = b"\x00\x01\x02"
        scanner = GitHistoryScanner(runtime_config_with_ignores(), CLIArgs(), ".", "HEAD")
        scanner.scan_lines = MagicMock()

        findings, success = scanner.scan_git_blob(git_reader, COMMIT_A, ".env")

        self.assertEqual(findings, [])
        self.assertTrue(success)
        scanner.scan_lines.assert_not_called()

    def test_scan_git_blob_keeps_findings_only_on_added_lines_and_attaches_commit(self):
        with tempfile.TemporaryDirectory() as td:
            git_reader = MagicMock()
            git_reader.repo_root = Path(td)
            git_reader.read_blob.return_value = b"line1\nline2\nline3\n"
            git_reader.list_added_lines.return_value = {2}
            scanner = GitHistoryScanner(runtime_config_with_ignores(), CLIArgs(), td, "HEAD")
            scanner.scan_lines = MagicMock(return_value=([finding(1), finding(2), finding(3)], True))

            findings, success = scanner.scan_git_blob(git_reader, COMMIT_A, ".env")

        self.assertTrue(success)
        self.assertEqual([f.line for f in findings], [2])
        self.assertEqual(findings[0].commit, COMMIT_A)
        scanner.scan_lines.assert_called_once()
        lines_arg, display_path_arg = scanner.scan_lines.call_args.args
        self.assertEqual(list(lines_arg), ["line1\n", "line2\n", "line3\n"])
        self.assertEqual(display_path_arg, Path(td) / ".env")

    def test_scan_git_blob_returns_no_findings_when_no_added_lines(self):
        with tempfile.TemporaryDirectory() as td:
            git_reader = MagicMock()
            git_reader.repo_root = Path(td)
            git_reader.read_blob.return_value = b"line1\n"
            git_reader.list_added_lines.return_value = set()
            scanner = GitHistoryScanner(runtime_config_with_ignores(), CLIArgs(), td, "HEAD")
            scanner.scan_lines = MagicMock(return_value=([finding(1)], True))

            findings, success = scanner.scan_git_blob(git_reader, COMMIT_A, ".env")

        self.assertEqual(findings, [])
        self.assertTrue(success)
