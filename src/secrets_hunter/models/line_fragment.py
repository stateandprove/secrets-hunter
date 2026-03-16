from dataclasses import dataclass
from enum import Enum


class StringSource(str, Enum):
    PEM_HEADER    = "PEM Header"
    DB_CONNECTION = "DB Connection String"
    GENERIC       = "Generic"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class LineFragment:
    text: str
    source: StringSource = StringSource.GENERIC
