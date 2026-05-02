import logging
import urllib.parse

from secrets_hunter.config import CLIArgs, DOMAIN_SCAN_PATHS
from secrets_hunter.models import Finding, ScanWorkItem
from secrets_hunter.models.config import RuntimeConfig
from secrets_hunter.scan_modes.base import BaseScanner
from secrets_hunter.scan_modes.domain.client import DomainClient
from secrets_hunter.validators import TextContentValidator

logger = logging.getLogger(__name__)


class DomainScanner(BaseScanner):
    def __init__(self, runtime_cfg: RuntimeConfig, cli_args: CLIArgs | None, domain: str):
        super().__init__(runtime_cfg, cli_args)
        self.domain = domain

    def found_message(self, total_items: int) -> str:
        return f"Found {total_items} URL(s) to scan"

    @property
    def empty_message(self) -> str:
        return "No URLs to scan"

    @property
    def finished_message(self) -> str:
        return "Domain scan finished"

    @property
    def failed_unit_label(self) -> str:
        return "URL"

    def collect_work_items(self) -> list[ScanWorkItem]:
        domain_client = DomainClient(
            self.domain,
            skip_tls_verify=self.cli_args.skip_tls_verify
        )
        logger.info(f"Collecting likely sensitive URLs from {domain_client.base_url}...")
        return [
            ScanWorkItem(
                label=url,
                run=lambda url=url: self.scan_url_response(domain_client, url)
            )
            for url in self.collect_urls_to_scan(domain_client)
        ]

    @staticmethod
    def collect_urls_to_scan(domain_client: DomainClient) -> list[str]:
        return [
            urllib.parse.urljoin(domain_client.base_url, path)
            for path in DOMAIN_SCAN_PATHS
        ]

    def scan_url_response(
        self,
        domain_client: DomainClient,
        url: str
    ) -> tuple[list[Finding], bool]:
        response_body, fetch_success = domain_client.read_url(url)

        if response_body is None:
            return [], fetch_success

        if not TextContentValidator.is_text_content(response_body):
            return [], True

        findings, scan_success = self.scan_lines(
            self.source_text_reader.bytes_to_lines(response_body),
            domain_client.display_path(url),
        )

        if not scan_success:
            return findings, scan_success

        return [finding.with_vulnerable_url(url) for finding in findings], True
