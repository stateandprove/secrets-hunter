from pathlib import Path

from secrets_hunter.config.settings import FileSettings

class FileValidator:
    def __init__(
        self,
        ignore_files: set[str],
        ignore_extensions: set[str],
        ignore_dirs: set[str]
    ):
        self.ignore_files = ignore_files
        self.ignore_extensions = ignore_extensions
        self.ignore_dirs = ignore_dirs

    def is_valid_file(self, path: Path) -> bool:
        if path.name in self.ignore_files:
            return False
        if path.suffix.lower() in self.ignore_extensions:
            return False
        if not self.is_text_file(path):
            return False
        return True

    def is_valid_dir(self, path: Path) -> bool:
        return path.name not in self.ignore_dirs

    @staticmethod
    def is_text_file(path: Path) -> bool:
        try:
            with open(path, 'rb') as f:
                chunk = f.read(FileSettings.BINARY_DETECTION_CHUNK_SIZE)

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
        except OSError:
            return False
