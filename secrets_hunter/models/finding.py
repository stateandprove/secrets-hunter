from dataclasses import dataclass
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DetectionMethod(str, Enum):
    PATTERN = "pattern"
    ENTROPY = "entropy"


@dataclass
class Finding:
    file: str
    line: int
    type: str
    match: str
    context: str
    severity: str
    confidence_reasoning: str
    detection_method: DetectionMethod
    confidence: int
    context_var: Optional[str] = None

    def reject(self, confidence_reasoning: str):
        self.severity = str(Severity.LOW.value)
        self.confidence = 0
        self.confidence_reasoning = confidence_reasoning
