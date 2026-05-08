import logging

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

from secrets_hunter.config import CLIArgs
from secrets_hunter.detection.detectors.entropy_detector import EntropyDetector
from secrets_hunter.detection.detectors.pattern_detector import PatternDetector
from secrets_hunter.detection.engine import DetectionEngine
from secrets_hunter.detection.false_positive_validator import FalsePositiveFindingsValidator
from secrets_hunter.detection.fragmenter.fragmenter import SourceFragmenter
from secrets_hunter.detection.fragmenter.lines_reader import PEMAwareLinesReader
from secrets_hunter.filters import PathFilter
from secrets_hunter.models import Finding, ScanWorkItem
from secrets_hunter.models.config import RuntimeConfig
from secrets_hunter.scan_modes.base.progress_bar import FileProgressBar, FolderProgressBar
from secrets_hunter.scan_modes.base.reader import SourceTextReader
from secrets_hunter.detection.semantics import StringSemanticsClassifier
from secrets_hunter.validators import TextContentValidator

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    def __init__(self, runtime_cfg: RuntimeConfig, cli_args: CLIArgs | None = None):
        self.cli_args = cli_args or CLIArgs()
        self.runtime_cfg = runtime_cfg
        self.path_filter = PathFilter(
            set(self.runtime_cfg.ignore_files),
            set(self.runtime_cfg.ignore_extensions),
            set(self.runtime_cfg.ignore_dirs)
        )
        self.pattern_detector = PatternDetector(self.runtime_cfg.secret_patterns)
        self.entropy_detector = EntropyDetector(self.cli_args)
        self.lines_reader = PEMAwareLinesReader()
        self.source_text_reader = SourceTextReader()
        self.text_content_validator = TextContentValidator()
        self.false_positive_validator = FalsePositiveFindingsValidator(
            exclude_patterns=self.runtime_cfg.exclude_patterns,
            exclude_keywords=self.runtime_cfg.exclude_keywords,
            string_semantics_classifier=StringSemanticsClassifier()
        )
        self.source_fragmenter = SourceFragmenter(
            assignment_patterns=self.runtime_cfg.assignment_patterns,
            min_token_length=self.cli_args.min_string_length,
            entropy_detector=self.entropy_detector
        )
        self.detection_engine = DetectionEngine(
            runtime_cfg=self.runtime_cfg,
            pattern_detector=self.pattern_detector,
            entropy_detector=self.entropy_detector,
            source_fragmenter=self.source_fragmenter,
            false_positive_validator=self.false_positive_validator
        )

    @abstractmethod
    def collect_work_items(self) -> list[ScanWorkItem]:
        pass

    @abstractmethod
    def found_message(self, total_items: int) -> str:
        pass

    @property
    @abstractmethod
    def empty_message(self) -> str:
        pass

    @property
    @abstractmethod
    def finished_message(self) -> str:
        pass

    @property
    @abstractmethod
    def failed_unit_label(self) -> str:
        pass

    def is_valid_target(self) -> bool:
        return True

    def should_scan_directly(self, items: list[ScanWorkItem]) -> bool:
        return False

    def set_base_path(self, target: str) -> None:
        self.pattern_detector.set_base_path(target)
        self.entropy_detector.set_base_path(target)

    def scan(self) -> tuple[list[Finding], bool]:
        try:
            if not self.is_valid_target():
                return [], False

            items = self.collect_work_items()

            if self.should_scan_directly(items):
                return items[0].run()

            return self.scan_work_items(
                items=items,
                found_message=self.found_message(len(items)),
                empty_message=self.empty_message,
                finished_message=self.finished_message,
                failed_unit_label=self.failed_unit_label
            )
        except KeyboardInterrupt:
            print("\n")
            logger.info("Scan aborted.")
            return [], False
        except Exception as e:
            logger.error(f"Error collecting scan work items: {e}")
            return [], False

    def scan_lines(
        self,
        lines: Iterable[str],
        display_path: Path | str,
        show_progress: bool = False
    ) -> tuple[list[Finding], bool]:
        findings, success = [], False
        progress_bar = None
        last_line_number = 0

        if show_progress:
            logger.info(f"Scanning {display_path}...")
            progress_bar = FileProgressBar()

        try:
            if lines is None:
                logger.error(f"Failed to read source: {display_path}")
            else:
                for source_fragment in self.lines_reader.read(lines):
                    fragment_findings = self.detection_engine.scan_fragment(source_fragment, display_path)
                    findings.extend(fragment_findings)
                    last_line_number = source_fragment.end_line

                    if progress_bar and (
                        source_fragment.end_line % progress_bar.STEP == 0 or source_fragment.start_line == 1
                    ):
                        progress_bar.render(source_fragment.end_line)

                if progress_bar and last_line_number:
                    progress_bar.render(last_line_number)

                success = True

        except Exception as e:
            logger.error(f"Error scanning source {display_path}: {e}", exc_info=True)

        if show_progress:
            success_msg = "finished" if success else "failed"
            print("")
            logger.info(f"Scan {success_msg}.")

        return findings, success

    def scan_work_items(
        self,
        items: list[ScanWorkItem],
        found_message: str,
        empty_message: str,
        finished_message: str,
        failed_unit_label: str
    ) -> tuple[list[Finding], bool]:
        all_findings: list[Finding] = []
        total_items = len(items)

        if not items:
            logger.warning(empty_message)
            return all_findings, True

        logger.info(found_message)
        logger.info(f"Scanning with {self.cli_args.max_workers} workers...\n")

        processed_count = 0
        failed_count = 0
        progress_bar = FolderProgressBar()

        try:
            with ThreadPoolExecutor(max_workers=self.cli_args.max_workers) as executor:
                futures = {executor.submit(item.run): item for item in items}

                for future in as_completed(futures):
                    item = futures[future]

                    try:
                        item_findings, item_success = future.result()

                        if not item_success:
                            failed_count += 1
                            print("\n")
                            logger.error(f"Error scanning {failed_unit_label} {item.label}, skipping...")
                            continue

                        all_findings.extend(item_findings)
                    except Exception as e:
                        failed_count += 1
                        print("\n")
                        logger.error(
                            f"Error scanning {failed_unit_label} {item.label}: {e}, skipping...",
                            exc_info=True
                        )
                        continue
                    finally:
                        processed_count += 1
                        progress_bar.render(processed_count, total_items)

            print("\n")

            if failed_count:
                logger.warning(f"{finished_message} with {failed_count} {failed_unit_label}(s) skipped.")
            else:
                logger.info(f"{finished_message}.")

        except KeyboardInterrupt:
            print("\n")
            logger.info("Scan aborted.")
            return all_findings, False

        return all_findings, True
