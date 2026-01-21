import json
import logging

from typing import List

from secrets_hunter import __version__
from secrets_hunter.models import Finding

logger = logging.getLogger(__name__)


class SARIFReporter:
    @staticmethod
    def export(findings: List[Finding], output_file: str) -> None:
        logger.info(f"Exporting results to {output_file}...")

        results = []
        for finding in findings:
            result = {
                "ruleId": finding.type,
                "message": {
                    "text": f"{finding.type} found in {finding.file}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file
                        },
                        "region": {
                            "startLine": finding.line,
                            "snippet": {
                                "text": finding.context
                            }
                        }
                    }
                }],
                "properties": {
                    "match": finding.match,
                    "detection_method": finding.detection_method,
                    "confidence": finding.confidence,
                    "context_var": finding.context_var,
                    "severity": finding.severity
                }
            }
            results.append(result)

        sarif_output = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "fvlcn_secrets_hunter",
                        "informationUri": "https://github.com/FVLCN/secrets-hunter",
                        "version": __version__
                    }
                },
                "results": results
            }]
        }

        with open(output_file, 'w') as f:
            json.dump(sarif_output, f, indent=4)

        logger.info(f"Results exported to {output_file}")
