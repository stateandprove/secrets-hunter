import re
import unittest

from unittest.mock import MagicMock

from secrets_hunter.config import CLIArgs, DOMAIN_SCAN_PATHS
from secrets_hunter.detection.fragmenter import GenericStringFragment
from secrets_hunter.models import Confidence, DetectionMethod, Finding, Severity
from secrets_hunter.models.config import RuntimeConfig
from secrets_hunter.scan_modes.domain.client import DomainClient
from secrets_hunter.scan_modes.domain.scanner import DomainScanner

TOKEN = "ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN"


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


def finding(line: int = 1) -> Finding:
    return Finding(
        title="Hardcoded API key",
        file="https://fvlcn.dev/.env",
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


class TestDomainScanner(unittest.TestCase):
    def test_collect_urls_to_scan_joins_known_paths_to_base_url(self):
        client = DomainClient("https://fvlcn.dev/app")

        urls = DomainScanner.collect_urls_to_scan(client)

        self.assertEqual(len(urls), len(DOMAIN_SCAN_PATHS))
        self.assertEqual(urls[0], "https://fvlcn.dev/app/.env")
        self.assertIn("https://fvlcn.dev/app/config.json", urls)

    def test_collect_work_items_uses_skip_tls_flag_and_binds_each_url(self):
        scanner = DomainScanner(
            minimal_runtime_config(),
            CLIArgs(skip_tls_verify=True),
            "fvlcn.dev"
        )
        scanner.collect_urls_to_scan = MagicMock(return_value=[
            "https://fvlcn.dev/.env",
            "https://fvlcn.dev/config.json"
        ])
        scanner.scan_url_response = MagicMock(side_effect=lambda client, url: ([url], True))

        items = scanner.collect_work_items()
        results = [item.run() for item in items]

        self.assertEqual([item.label for item in items], [
            "https://fvlcn.dev/.env",
            "https://fvlcn.dev/config.json"
        ])
        self.assertEqual(results, [
            (["https://fvlcn.dev/.env"], True),
            (["https://fvlcn.dev/config.json"], True)
        ])
        first_client = scanner.scan_url_response.call_args_list[0].args[0]
        self.assertIsNotNone(first_client.ssl_context)

    def test_scan_url_response_returns_fetch_failure(self):
        domain_client = MagicMock()
        domain_client.read_url.return_value = (None, False)
        scanner = DomainScanner(minimal_runtime_config(), CLIArgs(), "fvlcn.dev")

        findings, success = scanner.scan_url_response(domain_client, "https://fvlcn.dev/.env")

        self.assertEqual(findings, [])
        self.assertFalse(success)

    def test_scan_url_response_skips_missing_url_as_success(self):
        domain_client = MagicMock()
        domain_client.read_url.return_value = (None, True)
        scanner = DomainScanner(minimal_runtime_config(), CLIArgs(), "fvlcn.dev")

        findings, success = scanner.scan_url_response(domain_client, "https://fvlcn.dev/.env")

        self.assertEqual(findings, [])
        self.assertTrue(success)

    def test_scan_url_response_skips_binary_body(self):
        domain_client = MagicMock()
        domain_client.read_url.return_value = (b"\x00\x01\x02", True)
        scanner = DomainScanner(minimal_runtime_config(), CLIArgs(), "fvlcn.dev")
        scanner.scan_lines = MagicMock()

        findings, success = scanner.scan_url_response(domain_client, "https://fvlcn.dev/.env")

        self.assertEqual(findings, [])
        self.assertTrue(success)
        scanner.scan_lines.assert_not_called()

    def test_scan_url_response_attaches_vulnerable_url_to_findings(self):
        domain_client = MagicMock()
        domain_client.read_url.return_value = (
            f"GITHUB_TOKEN={TOKEN}\n".encode(),
            True
        )
        domain_client.display_path.return_value = "https://fvlcn.dev/.env"
        scanner = DomainScanner(minimal_runtime_config(), CLIArgs(), "fvlcn.dev")
        scanner.scan_lines = MagicMock(return_value=([finding()], True))

        findings, success = scanner.scan_url_response(domain_client, "https://fvlcn.dev/.env")

        self.assertTrue(success)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerable_url, "https://fvlcn.dev/.env")

        scanner.scan_lines.assert_called_once()
        lines_arg, display_path_arg = scanner.scan_lines.call_args.args

        self.assertEqual(
            list(lines_arg),
            [f"GITHUB_TOKEN={TOKEN}\n"]
        )
        self.assertEqual(display_path_arg, "https://fvlcn.dev/.env")
