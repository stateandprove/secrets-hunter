from dataclasses import dataclass
from typing import Optional
from enum import Enum


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
    detection_method: DetectionMethod
    confidence: int
    context_var: Optional[str] = None
