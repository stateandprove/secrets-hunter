from typing import List

from secrets_hunter.models import Finding
from secrets_hunter.config.settings import ScannerConfig


class OutputFormatter:
    @staticmethod
    def format(findings: List[Finding], config: ScannerConfig) -> List[Finding]:
        output_findings = []

        for finding in findings:
            if finding.confidence < config.MIN_CONFIDENCE:
                continue

            if not config.REVEAL_FINDINGS:
                finding.match = "***MASKED***"
                finding.context = "***MASKED***"

            output_findings.append(finding)

        output_findings.sort(key=lambda f: f.confidence, reverse=True)
        return output_findings
