import json
import logging

from secrets_hunter.models import Finding

logger = logging.getLogger(__name__)


class JSONReporter:
    @staticmethod
    def export(findings: list[Finding], output_file: str) -> None:
        logger.info(f"Exporting results to {output_file}...")
        findings_dict = [finding.to_display() for finding in findings] if findings else []

        with open(output_file, 'w') as f:
            json.dump(findings_dict, f, indent=4)

        logger.info(f"Results exported to {output_file}")
