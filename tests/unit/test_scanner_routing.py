import re
import unittest

from secrets_hunter.config import CLIArgs
from secrets_hunter.models.config import RuntimeConfig
from secrets_hunter.scan_modes import DomainScanner, FilesystemScanner, GitHistoryScanner
from secrets_hunter.scanner import SecretsHunter


def minimal_runtime_config() -> RuntimeConfig:
    return RuntimeConfig(
        secret_patterns={},
        exclude_patterns=[],
        exclude_keywords=[],
        secret_keywords=[],
        assignment_patterns=[re.compile(r"unused")],
        ignore_files=(),
        ignore_extensions=(),
        ignore_dirs=()
    )


class TestScannerRouting(unittest.TestCase):
    def test_uses_filesystem_scanner_by_default(self):
        scanner_router = SecretsHunter(minimal_runtime_config(), CLIArgs())
        scanner = scanner_router.get_scanner_for(".")
        self.assertIsInstance(scanner, FilesystemScanner)

    def test_uses_git_history_scanner_when_revset_is_set(self):
        args = CLIArgs(git_revset="HEAD~1..HEAD", git_max_count=1)
        scanner_router = SecretsHunter(minimal_runtime_config(), args)
        scanner = scanner_router.get_scanner_for(".")
        self.assertIsInstance(scanner, GitHistoryScanner)
        self.assertEqual(scanner.revset, "HEAD~1..HEAD")
        self.assertEqual(scanner.max_count, 1)

    def test_uses_domain_scanner_when_domain_is_set(self):
        args = CLIArgs(domain="fvlcn.dev")
        scanner_router = SecretsHunter(minimal_runtime_config(), args)
        scanner = scanner_router.get_scanner_for(".")
        self.assertIsInstance(scanner, DomainScanner)
        self.assertEqual(scanner.domain, "fvlcn.dev")
