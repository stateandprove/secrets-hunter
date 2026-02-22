import logging

from pathlib import Path
from typing import Iterator

from secrets_hunter.config.settings import FileSettings
from secrets_hunter.validators import FileValidator

logger = logging.getLogger(__name__)


class FileHandler:
    """Handle file operations for scanning"""
    
    def __init__(
        self,
        ignore_files: set[str],
        ignore_extensions: set[str],
        ignore_dirs: set[str]
    ):
        self.ignore_files = ignore_files
        self.ignore_extensions = {ext.lower() for ext in ignore_extensions}
        self.ignore_dirs = ignore_dirs
        self.file_validator = FileValidator(
            self.ignore_files,
            self.ignore_extensions,
            self.ignore_dirs,
        )

    @staticmethod
    def read_file(filepath: Path) -> Iterator[str]:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
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

        except OSError as e:
            print("\n")
            logger.error(f"Error reading {filepath}: {e}")

    def get_files_to_scan(self, target_path: Path) -> list[Path]:
        if target_path.is_file():
            return [target_path] if self.file_validator.is_valid_file(target_path) else []

        files: list[Path] = []
        dirs_to_process = [target_path]

        while dirs_to_process:
            current_dir = dirs_to_process.pop()

            try:
                for item in current_dir.iterdir():
                    if item.is_dir():
                        if self.file_validator.is_valid_dir(item):
                            dirs_to_process.append(item)
                    elif self.file_validator.is_valid_file(item):
                        files.append(item)
            except (PermissionError, OSError):
                pass

        return files
