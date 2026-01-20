from abc import ABC, abstractmethod
from typing import List
from pathlib import Path

from secrets_hunter.models import Finding


class BaseDetector(ABC):
    def __init__(self):
        self.base_path: Path | None = None

    @abstractmethod
    def detect(self, line: str, line_num: int, filepath: str, strings: List[str]) -> List[Finding]:
        pass

    def set_base_path(self, target: str) -> None:
        target_path = Path(target).resolve()
        self.base_path = target_path if target_path.is_dir() else target_path.parent

    def format_filepath(self, filepath: str) -> str:
        fpath = Path(filepath)

        if not fpath.is_absolute():
            fpath = Path.cwd() / fpath

        fpath = fpath.resolve()

        base = self.base_path

        if base and fpath.is_relative_to(base):
            return str(fpath.relative_to(base))

        return str(fpath)
