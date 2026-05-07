import logging

from pathlib import Path
from typing import Iterator

from secrets_hunter.scan_modes.base.reader import SourceTextReader

logger = logging.getLogger(__name__)


class FileReader:
    @staticmethod
    def read_file(filepath: Path) -> Iterator[str]:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in SourceTextReader.safe_lines(f):
                    yield line

        except OSError as e:
            print("\n")
            logger.error(f"Error reading {filepath}: {e}")
