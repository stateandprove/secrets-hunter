import logging

from pathlib import Path

from secrets_hunter.config import CLIArgs
from secrets_hunter.models import Finding, ScanWorkItem
from secrets_hunter.models.config import RuntimeConfig
from secrets_hunter.scan_modes.base import BaseScanner
from secrets_hunter.scan_modes.filesystem.reader import FileReader


logger = logging.getLogger(__name__)


class FilesystemScanner(BaseScanner):
    def __init__(self, runtime_cfg: RuntimeConfig, cli_args: CLIArgs | None, target: str):
        super().__init__(runtime_cfg, cli_args)
        self.file_reader = FileReader()
        self.target = target
        self.target_path = Path(target)

        if self.target_path.is_file() or self.target_path.is_dir():
            self.set_base_path(target)

    def should_scan_directly(self, items: list[ScanWorkItem]) -> bool:
        return self.target_path.is_file() and len(items) == 1

    def found_message(self, total_items: int) -> str:
        return f"Found {total_items} files to scan"

    @property
    def empty_message(self) -> str:
        return "No files to scan"

    @property
    def finished_message(self) -> str:
        return "Scan finished"

    @property
    def failed_unit_label(self) -> str:
        return "file"

    def is_valid_target(self) -> bool:
        if self.target_path.is_file() or self.target_path.is_dir():
            return True

        logger.error(f"'{self.target}' is not a valid file or directory")
        return False

    def collect_work_items(self) -> list[ScanWorkItem]:
        if self.target_path.is_file():
            return [
                ScanWorkItem(
                    label=str(self.target_path),
                    run=lambda: self.scan_file(self.target_path, show_progress=True)
                )
            ]

        display_path = Path.cwd() if self.target == "." else self.target
        logger.info(f"Collecting files from {display_path}...")
        files = self.collect_files_to_scan(self.target_path)

        return [
            ScanWorkItem(
                label=str(filepath),
                run=lambda filepath=filepath: self.scan_file(filepath, show_progress=False)
            )
            for filepath in files
        ]

    def collect_files_to_scan(self, target_path: Path) -> list[Path]:
        if target_path.is_file():
            if self.path_filter.is_ignored_path(target_path):
                return []

            return [target_path] if self.text_content_validator.is_text_file(target_path) else []

        files: list[Path] = []
        dirs_to_process = [target_path]

        while dirs_to_process:
            current_dir = dirs_to_process.pop()

            try:
                for item in current_dir.iterdir():
                    if self.path_filter.is_ignored_path(item):
                        continue

                    if item.is_dir():
                        dirs_to_process.append(item)
                    elif self.text_content_validator.is_text_file(item):
                        files.append(item)
            except (PermissionError, OSError):
                pass

        return files

    def scan_file(self, filepath: Path, show_progress: bool = False) -> tuple[list[Finding], bool]:
        lines = self.file_reader.read_file(filepath)
        return self.scan_lines(lines, filepath, show_progress)
