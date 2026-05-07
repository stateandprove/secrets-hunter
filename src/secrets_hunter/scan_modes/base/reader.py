from typing import Iterator

from secrets_hunter.config.settings import FileSettings


class SourceTextReader:
    @staticmethod
    def bytes_to_lines(content: bytes) -> Iterator[str]:
        text = content.decode("utf-8", errors="replace")
        return SourceTextReader.safe_lines(text.splitlines(keepends=True))

    @staticmethod
    def safe_lines(lines) -> Iterator[str]:
        for line in lines:
            if len(line) > FileSettings.MAX_LINE_LENGTH:
                return

            run = 1
            for i in range(1, len(line)):
                if line[i] == line[i - 1]:
                    run += 1
                    if run >= FileSettings.MAX_REPEAT_RUN:
                        return
                else:
                    run = 1

            yield line
