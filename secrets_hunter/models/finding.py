from dataclasses import dataclass
from typing import Optional
from enum import IntEnum


class DetectionMethod(IntEnum):
    PATTERN = 0
    ENTROPY = 1


@dataclass
class Finding:
    file: str
    line: int
    type: str
    match: str
    context: str
    detection_method: DetectionMethod
    confidence: int
    context_var: Optional[str] = None
