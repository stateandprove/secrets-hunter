import re

from typing import List

from secrets_hunter.detectors.base import BaseDetector
from secrets_hunter.models import Finding, DetectionMethod, Severity


class PatternDetector(BaseDetector):
    """Detects secrets using regex patterns"""

    def __init__(self, secret_patterns):
        super().__init__()
        self.secret_patterns = secret_patterns

    def detect(
        self,
        line: str,
        line_num: int,
        filepath: str,
        strings: List[str]
    ) -> List[Finding]:
        findings = []

        for string in strings:
            for secret_type, pattern in self.secret_patterns.items():
                if not re.search(pattern, string):
                    continue

                findings.append(Finding(
                    file=self.format_filepath(filepath),
                    line=line_num,
                    severity=str(Severity.CRITICAL.value),
                    type=secret_type,
                    match=string,
                    context=line.strip()[:100],
                    detection_method=DetectionMethod.PATTERN,
                    confidence=100
                ))

        return findings
