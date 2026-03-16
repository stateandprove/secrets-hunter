import re

from secrets_hunter.detectors.base import BaseDetector
from secrets_hunter.models import (
    Finding, DetectionMethod, Severity, Confidence, LineFragment, StringSource
)


class PatternDetector(BaseDetector):
    """Detects secrets using regex patterns"""

    def __init__(self, secret_patterns):
        super().__init__()
        self.secret_patterns = secret_patterns

    def _create_finding(
        self,
        secret_type: str,
        fragment: LineFragment,
        line: str,
        line_num: int,
        filepath: str
    ) -> Finding:
        file = self.format_filepath(filepath)
        return Finding(
            title=f"Hardcoded {secret_type} at {file}:{line_num}",
            file=file,
            line=line_num,
            severity=Severity.CRITICAL,
            type=secret_type,
            match=fragment.text,
            source=fragment.source,
            context=line.strip()[:100],
            detection_method=DetectionMethod.PATTERN,
            confidence=Confidence.VERIFIED,
            confidence_reasoning="Pattern Match"
        )

    def detect(
        self,
        line: str,
        line_num: int,
        filepath: str,
        fragments: list[LineFragment]
    ) -> list[Finding]:
        findings = []

        for fragment in fragments:
            if fragment.source in (StringSource.PEM_HEADER, StringSource.DB_CONNECTION):
                finding = self._create_finding(fragment.source, fragment, line, line_num, filepath)
                findings.append(finding)
                continue

            for secret_type, pattern in self.secret_patterns.items():
                if re.search(pattern, fragment.text):
                    finding = self._create_finding(secret_type, fragment, line, line_num, filepath)
                    findings.append(finding)

        return findings
