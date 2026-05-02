import subprocess
import tempfile
import unittest

from pathlib import Path

from secrets_hunter.scan_modes.git_history.reader import GitHistoryReader


class TestGitHistoryReader(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)

        self._git("init")
        self._git("config", "user.email", "test@example.com")
        self._git("config", "user.name", "Test User")

        (self.repo / "secrets.txt").write_text("api_key = 'abc123SECRETtoken'\n", encoding="utf-8")
        self._git("add", "secrets.txt")
        self._git("commit", "-m", "add secrets file")

        self.commit_sha = self._git("rev-parse", "HEAD").stdout.strip()

    def tearDown(self):
        self.tmp.cleanup()

    def test_detects_repo_root_from_file_target(self):
        handler = GitHistoryReader(self.repo / "secrets.txt")

        self.assertEqual(handler.repo_root, self.repo.resolve())

    def test_lists_commits_with_max_count(self):
        handler = GitHistoryReader(self.repo)

        self.assertEqual(handler.list_commits("HEAD", max_count=1), [self.commit_sha])

    def test_lists_changed_files(self):
        handler = GitHistoryReader(self.repo)

        self.assertEqual(handler.list_changed_files(self.commit_sha), ["secrets.txt"])

    def test_reads_blob(self):
        handler = GitHistoryReader(self.repo)

        self.assertEqual(
            handler.read_blob(self.commit_sha, "secrets.txt"),
            b"api_key = 'abc123SECRETtoken'\n",
        )

    def test_missing_blob_returns_none(self):
        handler = GitHistoryReader(self.repo)

        self.assertIsNone(handler.read_blob(self.commit_sha, "missing.txt"))

    def _git(self, *args):
        result = subprocess.run(
            ["git", *args],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            self.fail(f"git {' '.join(args)} failed: {result.stderr}")

        return result
