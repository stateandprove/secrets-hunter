import logging
import re
import subprocess

from pathlib import Path

logger = logging.getLogger(__name__)

DIFF_HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


class GitHistoryReader:
    """Read commit-selected file blobs from a git repository."""

    def __init__(self, target: Path):
        self.target = Path(target).resolve()
        self._repo_root = self._find_repo_root(self._git_cwd())

    @property
    def repo_root(self) -> Path:
        return self._repo_root

    def list_commits(self, revset: str, max_count: int | None = None) -> list[str]:
        args = ["rev-list", "--reverse"]

        if max_count is not None:
            args.extend(["--max-count", str(max_count)])

        args.append(revset)
        output = self._run_git_text(args)

        if not output:
            return []

        return [line for line in output.splitlines() if line]

    def list_changed_files(self, commit_sha: str) -> list[str]:
        output = self._run_git_bytes([
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-only",
            "-r",
            "-z",
            "--diff-filter=AM",
            commit_sha
        ])

        if not output:
            return []

        return [
            path.decode("utf-8", errors="replace")
            for path in output.split(b"\0")
            if path
        ]

    def read_blob(self, commit_sha: str, repo_rel_path: str) -> bytes | None:
        result = subprocess.run(
            ["git", "show", f"{commit_sha}:{repo_rel_path}"],
            cwd=self.repo_root,
            capture_output=True,
            check=False
        )

        if result.returncode == 0:
            return result.stdout

        logger.debug(
            "Unable to read git blob %s:%s: %s",
            commit_sha,
            repo_rel_path,
            result.stderr.decode("utf-8", errors="replace").strip(),
        )
        return None

    def list_added_lines(self, commit_sha: str, repo_rel_path: str) -> set[int]:
        diff = self._run_git_text([
            "diff-tree",
            "--root",
            "--unified=0",
            "--no-ext-diff",
            "--no-renames",
            "-p",
            commit_sha,
            "--",
            repo_rel_path
        ])

        added_lines: set[int] = set()

        for line in diff.splitlines():
            match = DIFF_HUNK_RE.match(line)

            if not match:
                continue

            start_line = int(match.group(1))
            line_count = int(match.group(2) or "1")

            for line_number in range(start_line, start_line + line_count):
                added_lines.add(line_number)

        return added_lines

    def target_matches(self, target_path: Path, repo_rel_path: str) -> bool:
        resolved_target = target_path.resolve()

        try:
            target_rel = resolved_target.relative_to(self.repo_root)
        except ValueError:
            return False

        if target_rel == Path("."):
            return True

        normalized_repo_rel_path = Path(repo_rel_path).as_posix()
        normalized_target = target_rel.as_posix()

        if resolved_target.is_dir():
            return (
                normalized_repo_rel_path == normalized_target
                or normalized_repo_rel_path.startswith(f"{normalized_target}/")
            )

        return normalized_repo_rel_path == normalized_target

    def _git_cwd(self) -> Path:
        return self.target if self.target.is_dir() else self.target.parent

    def _find_repo_root(self, cwd: Path) -> Path:
        output = self._run_git_text(["rev-parse", "--show-toplevel"], cwd=cwd)
        return Path(output).resolve()

    def _run_git_text(self, args: list[str], cwd: Path | None = None) -> str:
        return self._run_git_bytes(args, cwd=cwd).decode("utf-8", errors="replace").strip()

    def _run_git_bytes(self, args: list[str], cwd: Path | None = None) -> bytes:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd or self.repo_root,
            capture_output=True,
            check=False
        )

        if result.returncode == 0:
            return result.stdout

        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {stderr}")
