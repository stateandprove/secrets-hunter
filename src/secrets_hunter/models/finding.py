from dataclasses import dataclass, replace, asdict
from enum import Enum, IntEnum

from .line_fragment import StringSource

DISPLAY_EXCLUDED_FIELDS = {"source"}


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    def __str__(self) -> str:
        return self.name


class DetectionMethod(str, Enum):
    PATTERN = "pattern"
    ENTROPY = "entropy"


class Confidence(IntEnum):
    REJECTED                           = 0
    HIGH_ENTROPY_NO_ASSIGNMENT_CONTEXT = 5
    HIGH_ENTROPY_WITH_ASSIGNMENT       = 75
    VERIFIED                           = 100


@dataclass(frozen=True)
class Finding:
    title: str
    file: str
    line: int
    type: str
    match: str
    context: str
    severity: Severity
    confidence_reasoning: str
    detection_method: DetectionMethod
    confidence: Confidence
    source: StringSource = StringSource.GENERIC
    context_var: str | None = None

    def to_display(self) -> dict[str, object]:
        data = asdict(self)

        for field in DISPLAY_EXCLUDED_FIELDS:
            data.pop(field, None)

        return data

    def reject(self, confidence_reasoning: str) -> 'Finding':
        return replace(
            self,
            severity=Severity.INFO,
            confidence=Confidence.REJECTED,
            confidence_reasoning=confidence_reasoning
        )

    def mask(self) -> 'Finding':
        return replace(
            self,
            match="***MASKED***",
            context="***MASKED***"
        )

    def with_context(
        self,
        var: str,
        severity: Severity,
        confidence: Confidence,
        reasoning: str | None = None
    ) -> 'Finding':
        kwargs = {
            'context_var': var,
            'severity': severity,
            'confidence': confidence,
            'title': f'Hardcoded {var.replace("_", " ")} at {self.file}:{self.line}'
        }

        if reasoning:
            kwargs['confidence_reasoning'] = reasoning

        return replace(self, **kwargs)
