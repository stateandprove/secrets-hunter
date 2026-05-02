from pathlib import Path

from secrets_hunter.config.settings import FileSettings


class TextContentValidator:
    @staticmethod
    def is_text_file(path: Path) -> bool:
        try:
            with open(path, 'rb') as f:
                chunk = f.read(FileSettings.BINARY_DETECTION_CHUNK_SIZE)

            return TextContentValidator.is_text_content(chunk)
        except OSError:
            return False

    @staticmethod
    def is_text_content(content: bytes) -> bool:
        chunk = content[:FileSettings.BINARY_DETECTION_CHUNK_SIZE]

        # Empty file = text
        if not chunk:
            return True

        # NULL byte indicates binary file
        if b'\x00' in chunk:
            return False

        # Count control bytes: <32 excluding \t \n \r, plus DEL (127)
        bad = 0
        for b in chunk:
            if b == 127:
                bad += 1
            elif b < 32 and b not in (9, 10, 13):  # tab, LF, CR are fine
                bad += 1

        return (bad / len(chunk)) < FileSettings.CONTROL_CHARS_RATIO_THRESHOLD
