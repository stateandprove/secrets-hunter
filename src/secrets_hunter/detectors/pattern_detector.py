import re

from secrets_hunter.detectors.base import BaseDetector
from secrets_hunter.models import Finding, DetectionMethod, Severity, Confidence


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
        strings: list[str]
    ) -> list[Finding]:
        findings = []

        for string in strings:
            for secret_type, pattern in self.secret_patterns.items():
                if not re.search(pattern, string):
                    continue

                file = self.format_filepath(filepath)

                findings.append(Finding(
                    title=f"Hardcoded {secret_type} at {file}:{line_num}",
                    file=file,
                    line=line_num,
                    severity=Severity.CRITICAL,
                    type=secret_type,
                    match=string,
                    context=line.strip()[:100],
                    detection_method=DetectionMethod.PATTERN,
                    confidence=Confidence.VERIFIED,
                    confidence_reasoning="Pattern Match"
                ))

        return findings
