import subprocess
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from secrets_hunter.scan_modes.git_history.reader import GitHistoryReader

TOKEN = "ghp_aB7xY2nQ9mK4pL6rT8vW1zC3dE5fG0hJ2sN"


class TestGitHistoryReader(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self._initialize_git_repo()
        self.commit_sha = self._commit_secret_file()

    def tearDown(self):
        self.tmp.cleanup()

    def _initialize_git_repo(self):
        self._git("init")
        self._git("branch", "-M", "main")
        self._git("config", "user.email", "test@fvlcn.dev")
        self._git("config", "user.name", "Test User")

    def _commit_secret_file(self) -> str:
        return self._commit_file(
            "secrets.txt",
            f"GITHUB_TOKEN='{TOKEN}'\n",
            "add secrets file"
        )

    def _commit_file(self, repo_rel_path: str, contents: str, message: str) -> str:
        path = self.repo / repo_rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        self._git("add", repo_rel_path)
        self._git("commit", "-m", message)
        return self._git("rev-parse", "HEAD").stdout.strip()

    def test_scans_single_commit(self):
        reader = GitHistoryReader(self.repo)
        commits = reader.list_commits(f"{self.commit_sha}^!")
        self.assertEqual(commits, [self.commit_sha])

    def test_scans_pr_commit_range(self):
        self._git("checkout", "-b", "feature/pr-scan")
        feature_commit = self._commit_file(
            "pr.env",
            f"GITHUB_TOKEN='{TOKEN}'\n",
            "add pr secret"
        )
        reader = GitHistoryReader(self.repo)
        commits = reader.list_commits("main..HEAD")
        self.assertEqual(commits, [feature_commit])
        self.assertEqual(reader.list_changed_files(feature_commit), ["pr.env"])

    def test_scans_named_branch(self):
        self._git("checkout", "-b", "feature/random-branch")
        branch_commit = self._commit_file(
            "branch.env",
            f"GITHUB_TOKEN='{TOKEN}'\n",
            "add branch secret"
        )
        self._git("checkout", "main")
        reader = GitHistoryReader(self.repo)
        commits = reader.list_commits("feature/random-branch")
        self.assertIn(branch_commit, commits)

    def test_detects_repo_root_from_file_target(self):
        handler = GitHistoryReader(self.repo / "secrets.txt")
        self.assertEqual(handler.repo_root, self.repo.resolve())

    def test_lists_commits_with_max_count(self):
        handler = GitHistoryReader(self.repo)
        self.assertEqual(handler.list_commits("HEAD", max_count=1), [self.commit_sha])

    def test_option_like_revset_is_not_treated_as_git_option(self):
        handler = GitHistoryReader(self.repo)

        with self.assertRaises(RuntimeError):
            handler.list_commits("--all")

    def test_lists_changed_files(self):
        handler = GitHistoryReader(self.repo)
        self.assertEqual(handler.list_changed_files(self.commit_sha), ["secrets.txt"])

    def test_reads_blob(self):
        handler = GitHistoryReader(self.repo)
        self.assertEqual(
            handler.read_blob(self.commit_sha, "secrets.txt"),
            f"GITHUB_TOKEN='{TOKEN}'\n".encode(),
        )

    def test_missing_blob_returns_none(self):
        handler = GitHistoryReader(self.repo)
        self.assertIsNone(handler.read_blob(self.commit_sha, "missing.txt"))

    def test_rejects_invalid_commit_for_changed_files_before_subprocess(self):
        handler = GitHistoryReader(self.repo)

        with patch("subprocess.run") as run:
            with self.assertRaises(ValueError):
                handler.list_changed_files("--help")

        run.assert_not_called()

    def test_rejects_invalid_commit_for_blob_before_subprocess(self):
        handler = GitHistoryReader(self.repo)

        with patch("subprocess.run") as run:
            with self.assertRaises(ValueError):
                handler.read_blob("--help", "secrets.txt")

        run.assert_not_called()

    def test_rejects_invalid_commit_for_added_lines_before_subprocess(self):
        handler = GitHistoryReader(self.repo)

        with patch("subprocess.run") as run:
            with self.assertRaises(ValueError):
                handler.list_added_lines("--help", "secrets.txt")

        run.assert_not_called()

    def _git(self, *args):
        result = subprocess.run(
            ["git", *args],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            self.fail(f"git {' '.join(args)} failed: {result.stderr}")

        return result
