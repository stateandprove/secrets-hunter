import logging

from dataclasses import dataclass
from functools import partial
from pathlib import Path

from secrets_hunter.config import CLIArgs
from secrets_hunter.models import Finding, ScanWorkItem
from secrets_hunter.models.config import RuntimeConfig
from secrets_hunter.scan_modes.base import BaseScanner
from secrets_hunter.scan_modes.git_history.reader import GitHistoryReader
from secrets_hunter.validators import TextContentValidator

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GitBlobRef:
    commit_sha: str
    repo_rel_path: str


class GitHistoryScanner(BaseScanner):
    def __init__(
        self,
        runtime_cfg: RuntimeConfig,
        cli_args: CLIArgs | None,
        target: str,
        revset: str,
        max_count: int | None = None
    ):
        super().__init__(runtime_cfg, cli_args)
        self.target = target
        self.target_path = Path(target)
        self.revset = revset
        self.max_count = max_count
        self._empty_message = "No changed files to scan"

    def found_message(self, total_items: int) -> str:
        return f"Got {total_items} git blob(s) to scan"

    @property
    def empty_message(self) -> str:
        return self._empty_message

    @property
    def finished_message(self) -> str:
        return "Git history scan finished"

    @property
    def failed_unit_label(self) -> str:
        return "git blob"

    def collect_work_items(self) -> list[ScanWorkItem]:
        git_reader = GitHistoryReader(self.target_path)
        self.set_base_path(str(git_reader.repo_root))

        logger.info(f"Collecting commits from git revset {self.revset!r}...")
        blobs = self.collect_git_blobs(git_reader)

        return [
            ScanWorkItem(
                label=f"{blob.commit_sha[:12]}:{blob.repo_rel_path}",
                run=partial(
                    self.scan_git_blob,
                    git_reader,
                    blob.commit_sha,
                    blob.repo_rel_path
                )
            )
            for blob in blobs
        ]

    def collect_git_blobs(self, git_reader: GitHistoryReader) -> list[GitBlobRef]:
        commits = git_reader.list_commits(self.revset, max_count=self.max_count)

        if not commits:
            self._empty_message = "No commits selected"
            return []

        blobs: list[GitBlobRef] = []

        for commit_sha in commits:
            for repo_rel_path in git_reader.list_changed_files(commit_sha):
                if not git_reader.target_matches(self.target_path, repo_rel_path):
                    continue

                if self.path_filter.is_ignored_path(Path(repo_rel_path)):
                    continue

                blobs.append(GitBlobRef(commit_sha, repo_rel_path))

        return blobs

    def scan_git_blob(
        self,
        git_reader: GitHistoryReader,
        commit_sha: str,
        repo_rel_path: str
    ) -> tuple[list[Finding], bool]:
        blob = git_reader.read_blob(commit_sha, repo_rel_path)

        if blob is None:
            return [], False

        if not TextContentValidator.is_text_content(blob):
            return [], True

        display_path = git_reader.repo_root / repo_rel_path
        findings, success = self.scan_lines(self.source_text_reader.bytes_to_lines(blob), display_path)

        if not success:
            return findings, success

        added_lines = git_reader.list_added_lines(commit_sha, repo_rel_path)

        if not added_lines:
            return [], True

        introduced_findings = [
            finding.with_commit(commit_sha)
            for finding in findings
            if finding.line in added_lines
        ]

        return introduced_findings, True
