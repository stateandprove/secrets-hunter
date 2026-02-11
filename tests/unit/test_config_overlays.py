import re
import unittest

from pathlib import Path
from tempfile import TemporaryDirectory

from secrets_hunter.config import load_runtime_config


def _write(td: Path, name: str, text: str) -> str:
    p = td / name
    p.write_text(text.strip() + "\n", encoding="utf-8")
    return str(p)


def normalize_list_entries(items):
    out = []

    for x in items:
        if hasattr(x, "pattern") and isinstance(getattr(x, "pattern"), str):
            out.append(x.pattern)
        else:
            out.append(x)

    return out


class TestConfigOverlays(unittest.TestCase):
    def test_secret_patterns_add_new(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            overlay = _write(td, "add.toml", r"""
            [[secret_patterns]]
            name = "UT New Pattern"
            pattern = '''\but_new_[A-Za-z0-9]{8}\b'''
            """)

            cfg = load_runtime_config([overlay])
            self.assertIn("UT New Pattern", cfg.secret_patterns)

            pat = cfg.secret_patterns["UT New Pattern"]
            self.assertEqual(pat.pattern, r"\but_new_[A-Za-z0-9]{8}\b")

    def test_secret_patterns_override_replaces_pattern_and_flags(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            overlay1 = _write(td, "a.toml", r"""
            [[secret_patterns]]
            name = "UT Override Me"
            pattern = '''\but_ovr_[A-Za-z0-9]{10}\b'''
            flags = ["ASCII"]
            """)

            overlay2 = _write(td, "b.toml", r"""
            [[secret_patterns]]
            name = "UT Override Me"
            pattern = '''\but_ovr_[A-Za-z0-9]{12}\b'''
            # no flags here on purpose: should replace flags too
            """)

            cfg = load_runtime_config([overlay1, overlay2])
            pat = cfg.secret_patterns["UT Override Me"]

            self.assertEqual(pat.pattern, r"\but_ovr_[A-Za-z0-9]{12}\b")
            # If flags were truly replaced, ASCII should be gone
            self.assertFalse(bool(pat.flags & re.ASCII))

    def test_remove_secret_patterns_by_name(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            add = _write(td, "add.toml", r"""
            [[secret_patterns]]
            name = "UT Remove Pattern"
            pattern = '''\but_rm_[A-Za-z0-9]{8}\b'''
            """)

            rm = _write(td, "rm.toml", r"""
            remove_secret_patterns = ["UT Remove Pattern"]
            """)

            cfg = load_runtime_config([add, rm])
            self.assertNotIn("UT Remove Pattern", cfg.secret_patterns)

    def test_remove_secret_patterns_nonexistent_is_noop(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            rm = _write(td, "rm.toml", r"""
            remove_secret_patterns = ["UT Does Not Exist"]
            """)

            # should not raise
            cfg = load_runtime_config([rm])
            self.assertIsNotNone(cfg)

    # ---- exclude_keywords ----
    def test_exclude_keywords_append_and_dedupe_first_wins(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            a = _write(td, "a.toml", r"""
            exclude_keywords = ["ut_keep", "ut_only_a"]
            """)
            b = _write(td, "b.toml", r"""
            exclude_keywords = ["ut_keep", "ut_only_b"]
            """)

            cfg = load_runtime_config([a, b])
            kws = list(cfg.exclude_keywords)

            self.assertEqual(kws.count("ut_keep"), 1)
            self.assertIn("ut_only_a", kws)
            self.assertIn("ut_only_b", kws)
            self.assertLess(kws.index("ut_only_a"), kws.index("ut_only_b"))

    def test_remove_exclude_keywords_exact_match(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            a = _write(td, "a.toml", r"""
            exclude_keywords = ["ut_rm_kw", "ut_stays"]
            """)
            b = _write(td, "b.toml", r"""
            remove_exclude_keywords = ["ut_rm_kw"]
            """)

            cfg = load_runtime_config([a, b])
            self.assertNotIn("ut_rm_kw", cfg.exclude_keywords)
            self.assertIn("ut_stays", cfg.exclude_keywords)

    def test_remove_before_add_order_matters_exclude_keywords(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            rm_first = _write(td, "a.toml", r"""
            remove_exclude_keywords = ["ut_later"]
            """)
            add_later = _write(td, "b.toml", r"""
            exclude_keywords = ["ut_later"]
            """)

            cfg = load_runtime_config([rm_first, add_later])
            self.assertIn("ut_later", cfg.exclude_keywords)

    def test_add_and_remove_same_overlay_exclude_keywords_keeps_added_item(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            both = _write(td, "both.toml", r"""
            exclude_keywords = ["ut_same_file"]
            remove_exclude_keywords = ["ut_same_file"]
            """)

            cfg = load_runtime_config([both])
            self.assertIn("ut_same_file", cfg.exclude_keywords)

    # ---- secret_keywords ----
    def test_secret_keywords_append_dedupe_and_removal(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            a = _write(td, "a.toml", r"""
            secret_keywords = ["ut_sec_keep", "ut_sec_a"]
            """)
            b = _write(td, "b.toml", r"""
            secret_keywords = ["ut_sec_keep", "ut_sec_b"]
            """)
            c = _write(td, "c.toml", r"""
            remove_secret_keywords = ["ut_sec_a"]
            """)

            cfg = load_runtime_config([a, b, c])
            kws = list(cfg.secret_keywords)

            self.assertEqual(kws.count("ut_sec_keep"), 1)
            self.assertNotIn("ut_sec_a", kws)
            self.assertIn("ut_sec_b", kws)

    # ---- exclude_patterns ----
    def test_exclude_patterns_append_dedupe_first_wins(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            a = _write(td, "a.toml", r"""
            exclude_patterns = [
              "ut_dummy",
              '''^ut_exact$'''
            ]
            """)
            b = _write(td, "b.toml", r"""
            exclude_patterns = [
              "ut_dummy",         # duplicate
              '''^ut_exact$''',    # duplicate
              "ut_new"
            ]
            """)

            cfg = load_runtime_config([a, b])
            pats = normalize_list_entries(cfg.exclude_patterns)

            self.assertEqual(pats.count("ut_dummy"), 1)
            self.assertEqual(pats.count(r"^ut_exact$"), 1)
            self.assertIn("ut_new", pats)

            # order: first occurrences kept
            self.assertLess(pats.index("ut_dummy"), pats.index("ut_new"))

    def test_remove_exclude_patterns_exact_string_match(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            a = _write(td, "a.toml", r"""
            exclude_patterns = [
              "ut_dummy",
              '''^ut_exact$'''
            ]
            """)
            b = _write(td, "b.toml", r"""
            remove_exclude_patterns = ["ut_dummy"]
            """)

            cfg = load_runtime_config([a, b])
            pats = normalize_list_entries(cfg.exclude_patterns)

            self.assertNotIn("ut_dummy", pats)
            self.assertIn(r"^ut_exact$", pats)

    def test_remove_exclude_patterns_does_not_remove_similar(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            a = _write(td, "a.toml", r"""
            exclude_patterns = [
              "ut_dummy",
              '''^ut_dummy$'''
            ]
            """)
            b = _write(td, "b.toml", r"""
            remove_exclude_patterns = ["ut_dummy"]
            """)

            cfg = load_runtime_config([a, b])
            pats = normalize_list_entries(cfg.exclude_patterns)

            self.assertNotIn("ut_dummy", pats)
            self.assertIn(r"^ut_dummy$", pats)

    # ---- assignment_patterns ----
    def test_assignment_patterns_add_dedupe_remove(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            p1 = r'''ut_assign_([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["']([^"']+)["']'''
            p2 = r'''ut_export\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["']([^"']+)["']'''

            a = _write(td, "a.toml", rf"""
            assignment_patterns = [
              '''{p1}''',
              '''{p2}'''
            ]
            """)
            b = _write(td, "b.toml", rf"""
            assignment_patterns = [
              '''{p1}'''  # duplicate
            ]
            """)
            c = _write(td, "c.toml", rf"""
            remove_assignment_patterns = [
              '''{p2}'''
            ]
            """)

            cfg = load_runtime_config([a, b, c])
            aps = normalize_list_entries(cfg.assignment_patterns)

            self.assertEqual(aps.count(p1), 1)
            self.assertNotIn(p2, aps)

    # ---- ignore rules ----
    def test_ignore_rules_append_dedupe_first_wins(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            a = _write(td, "a.toml", r"""
            [ignore]
            dirs = ["ut_vendor", "ut_dup"]
            extensions = [".utbin", ".utdup"]
            files = ["ut-lock.json", "utdup.lock"]
            """)
            b = _write(td, "b.toml", r"""
            [ignore]
            dirs = ["ut_dup", "ut_cache"]
            extensions = [".utdup", ".utmisc"]
            files = ["utdup.lock", "ut2.lock"]
            """)

            cfg = load_runtime_config([a, b])

            dirs = cfg.ignore_dirs
            exts = cfg.ignore_extensions
            files = cfg.ignore_files

            self.assertEqual(dirs.count("ut_dup"), 1)
            self.assertIn("ut_vendor", dirs)
            self.assertIn("ut_cache", dirs)
            self.assertLess(dirs.index("ut_dup"), dirs.index("ut_cache"))

            self.assertEqual(exts.count(".utdup"), 1)
            self.assertIn(".utbin", exts)
            self.assertIn(".utmisc", exts)

            self.assertEqual(files.count("utdup.lock"), 1)
            self.assertIn("ut-lock.json", files)
            self.assertIn("ut2.lock", files)

    def test_ignore_rules_remove(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            a = _write(td, "a.toml", r"""
            [ignore]
            dirs = ["ut_rm_dir"]
            extensions = [".utrm"]
            files = ["utrm.lock"]
            """)
            b = _write(td, "b.toml", r"""
            remove_ignore_dirs = ["ut_rm_dir"]
            remove_ignore_extensions = [".utrm"]
            remove_ignore_files = ["utrm.lock"]
            """)

            cfg = load_runtime_config([a, b])

            self.assertNotIn("ut_rm_dir", cfg.ignore_dirs)
            self.assertNotIn(".utrm", cfg.ignore_extensions)
            self.assertNotIn("utrm.lock", cfg.ignore_files)

    def test_ignore_remove_before_add_order_matters(self):
        with TemporaryDirectory() as td:
            td = Path(td)

            rm_first = _write(td, "a.toml", r"""
            remove_ignore_dirs = ["ut_late_dir"]
            """)
            add_later = _write(td, "b.toml", r"""
            [ignore]
            dirs = ["ut_late_dir"]
            """)

            cfg = load_runtime_config([rm_first, add_later])
            self.assertIn("ut_late_dir", cfg.ignore_dirs)


if __name__ == "__main__":
    unittest.main()
