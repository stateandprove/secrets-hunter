import logging
import time

from collections import Counter

from secrets_hunter.config import CLIArgs
from secrets_hunter.models import Finding, Severity
from secrets_hunter.models.config import RuntimeConfig
from secrets_hunter.reporters.findings_output_processor import FindingsOutputProcessor
from secrets_hunter.scan_modes import BaseScanner, DomainScanner, FilesystemScanner, GitHistoryScanner

logger = logging.getLogger(__name__)


class SecretsHunter:
    def __init__(self, runtime_cfg: RuntimeConfig, cli_args: CLIArgs = None):
        self.cli_args = cli_args or CLIArgs()
        self.runtime_cfg = runtime_cfg

    def scan(self, target: str) -> tuple[list[Finding], bool]:
        scanner = self.get_scanner_for(target)

        start_time = time.monotonic()
        findings, success = scanner.scan()

        elapsed = time.monotonic() - start_time
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        milliseconds = int((elapsed % 1) * 1000)
        duration = f"{minutes}m {seconds}s {milliseconds}ms" if minutes else f"{seconds}s {milliseconds}ms"
        logger.info(f"Scan duration: {duration}")

        if success:
            findings = FindingsOutputProcessor.prepare(findings, self.cli_args)
            self.log_findings_summary(findings)

        return findings, success

    def get_scanner_for(self, target: str) -> BaseScanner:
        if self.cli_args.domain:
            return DomainScanner(self.runtime_cfg, self.cli_args, self.cli_args.domain)

        if self.cli_args.git_revset:
            return GitHistoryScanner(
                self.runtime_cfg,
                self.cli_args,
                target,
                self.cli_args.git_revset,
                self.cli_args.git_max_count
            )

        return FilesystemScanner(self.runtime_cfg, self.cli_args, target)

    def log_findings_summary(self, findings: list[Finding]) -> None:
        severity_counts = Counter(f.severity for f in findings)
        total_findings = len(findings)

        if total_findings == 0:
            logger.info("No secrets found")
        elif total_findings == 1:
            finding = findings[0]
            logger.info(f"1 {finding.severity.lower()} severity secret was found")
        else:
            severity_summary = " ".join(
                f"{severity_counts[severity]} {severity.lower()},"
                for severity in Severity
                if severity_counts[severity]
            )

            if severity_summary.endswith(","):
                severity_summary = severity_summary[:-1]

            logger.info(f"Found {total_findings} secrets: {severity_summary}")

        if total_findings > 0 and not self.cli_args.min_confidence:
            logger.info("Showing all findings, including rejected ones. "
                        "Use the --min-confidence flag to exclude them from the report.")
