from typing import List

from secrets_hunter.detectors.base import BaseDetector
from secrets_hunter.models import Finding, DetectionMethod, Severity
from secrets_hunter.config import CliArgs
from secrets_hunter.detectors.utils import entropy as entropy_utils


class EntropyDetector(BaseDetector):
    """Detect secrets using entropy analysis"""

    def __init__(self, cli_args: CliArgs):
        super().__init__()
        self.cli_args = cli_args

    def detect(
        self,
        line: str,
        line_num: int,
        filepath: str,
        strings: List[str]
    ) -> List[Finding]:
        findings = []

        for string in strings:
            entropy = entropy_utils.calculate_shannon_entropy(string)
            is_hex = entropy_utils.is_hex_string(string)
            is_base64 = entropy_utils.is_base64_string(string)

            is_high_entropy = False
            string_type = None

            if is_hex and entropy >= self.cli_args.HEX_ENTROPY_THRESHOLD:
                is_high_entropy = True
                string_type = "High Entropy Hex String"
            elif is_base64 and entropy >= self.cli_args.B64_ENTROPY_THRESHOLD:
                is_high_entropy = True
                string_type = "High Entropy Base64 String"

            if not is_high_entropy:
                continue

            findings.append(Finding(
                file=self.format_filepath(filepath),
                line=line_num,
                severity=str(Severity.LOW.value),
                type=string_type,
                match=string,
                context=line.strip()[:100],
                detection_method=DetectionMethod.ENTROPY,
                confidence=20
            ))

        return findings
