import logging

from typing import Iterable
from pathlib import Path

from secrets_hunter.config import PEM_BEGIN_RE, PEM_END_RE

logger = logging.getLogger(__name__)


class LinesReader:
    def read(self, lines: Iterable[str], filtepath: Path):
        yield from enumerate(lines, 1)


class PEMAwareLinesReader(LinesReader):
    def read(self, lines: Iterable[str], filepath: Path):
        iterator = enumerate(lines, 1)

        for line_num, line in iterator:
            if not PEM_BEGIN_RE.search(line):
                yield line_num, line
                continue

            yield line_num, line

            if PEM_END_RE.search(line):
                continue

            found_end = False

            for _, skipped_line in iterator:
                if PEM_END_RE.search(skipped_line):
                    found_end = True
                    break

            if not found_end:
                print()
                logger.warning(f"{filepath}: truncated PEM block detected after line {line_num}")
