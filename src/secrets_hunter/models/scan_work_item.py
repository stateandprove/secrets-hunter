from collections.abc import Callable
from dataclasses import dataclass

from .finding import Finding


@dataclass(frozen=True)
class ScanWorkItem:
    label: str
    run: Callable[[], tuple[list[Finding], bool]]
