from dataclasses import dataclass
from enum import Enum


class StringKind(Enum):
    STRUCTURED = "structured"
    RANDOM     = "random"


@dataclass(frozen=True)
class StringClassification:
    string: str
    tokens: list[str]
    word_match_ratio: float
    bigram_score: float
    combined_score: float
    kind: StringKind

    @property
    def structured(self) -> bool:
        return self.kind is StringKind.STRUCTURED
