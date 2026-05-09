import re
import tempfile
import unittest

from pathlib import Path
from unittest.mock import MagicMock

from secrets_hunter.config import CLIArgs
from secrets_hunter.models.config import RuntimeConfig
from secrets_hunter.scan_modes.filesystem.scanner import FilesystemScanner


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


class TestFilesystemScanner(unittest.TestCase):
    def test_invalid_target_is_not_valid(self):
        scanner = FilesystemScanner(runtime_config_with_ignores(), CLIArgs(), "/definitely/missing")
        self.assertFalse(scanner.is_valid_target())

    def test_collect_files_to_scan_skips_ignored_and_binary_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keep = root / "keep.env"
            keep.write_text("GITHUB_TOKEN=ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN\n", encoding="utf-8")
            ignored_name = root / "ignored.env"
            ignored_name.write_text("GITHUB_TOKEN=ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN\n", encoding="utf-8")
            ignored_ext = root / "image.bin"
            ignored_ext.write_bytes(b"text but ignored by extension")
            binary = root / "binary.txt"
            binary.write_bytes(b"\x00\x01\x02")
            vendor = root / "vendor"
            vendor.mkdir()
            vendor_file = vendor / "config.env"
            vendor_file.write_text("GITHUB_TOKEN=ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN\n", encoding="utf-8")
            nested = root / "nested"
            nested.mkdir()
            nested_keep = nested / "settings.env"
            nested_keep.write_text("GITHUB_TOKEN=ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN\n", encoding="utf-8")

            scanner = FilesystemScanner(runtime_config_with_ignores(), CLIArgs(), str(root))
            files = scanner.collect_files_to_scan(root)

        self.assertEqual(set(files), {keep, nested_keep})

    def test_collect_files_to_scan_returns_single_file_when_text_and_not_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "keep.env"
            path.write_text("GITHUB_TOKEN=ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN\n", encoding="utf-8")
            scanner = FilesystemScanner(runtime_config_with_ignores(), CLIArgs(), str(path))

            files = scanner.collect_files_to_scan(path)

        self.assertEqual(files, [path])

    def test_collect_files_to_scan_skips_single_ignored_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ignored.env"
            path.write_text("GITHUB_TOKEN=ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN\n", encoding="utf-8")
            scanner = FilesystemScanner(runtime_config_with_ignores(), CLIArgs(), str(path))

            files = scanner.collect_files_to_scan(path)

        self.assertEqual(files, [])

    def test_single_file_target_scans_directly_with_progress(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "keep.env"
            path.write_text("GITHUB_TOKEN=ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN\n", encoding="utf-8")
            scanner = FilesystemScanner(runtime_config_with_ignores(), CLIArgs(), str(path))
            scanner.scan_file = MagicMock(return_value=(["finding"], True))

            findings, success = scanner.scan()

        self.assertEqual(findings, ["finding"])
        self.assertTrue(success)
        scanner.scan_file.assert_called_once_with(path, show_progress=True)

    def test_directory_work_item_lambdas_bind_each_filepath(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first = root / "a.env"
            second = root / "b.env"
            first.write_text("A=secret\n", encoding="utf-8")
            second.write_text("B=secret\n", encoding="utf-8")
            scanner = FilesystemScanner(runtime_config_with_ignores(), CLIArgs(), str(root))
            scanner.collect_files_to_scan = MagicMock(return_value=[first, second])
            scanner.scan_file = MagicMock(side_effect=lambda path, show_progress=False: ([str(path)], True))

            items = scanner.collect_work_items()
            results = [item.run() for item in items]

        self.assertEqual([item.label for item in items], [str(first), str(second)])
        self.assertEqual(results, [([str(first)], True), ([str(second)], True)])

        scanner.scan_file.assert_any_call(first, show_progress=False)
        scanner.scan_file.assert_any_call(second, show_progress=False)
