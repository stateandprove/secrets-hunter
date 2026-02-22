from secrets_hunter.models import Finding
from secrets_hunter.config.settings import CLIArgs


class FindingsProcessor:
    @staticmethod
    def process(findings: list[Finding], config: CLIArgs) -> list[Finding]:
        """Filter, mask, and sort findings."""
        output_findings: list[Finding] = []

        for finding in findings:
            if finding.confidence < config.min_confidence:
                continue

            if not config.reveal_findings:
                finding = finding.mask()

            output_findings.append(finding)

        output_findings.sort(key=lambda f: f.confidence, reverse=True)
        return output_findings
