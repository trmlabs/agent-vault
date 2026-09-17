#!/usr/bin/env python3
"""Local Git fixtures for the upstream merge boundary; no network or credentials."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("updater", Path(__file__).with_name("upstream-update.py"))
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = self.temp.name
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        self.write("base", "original")
        self.git("checkout", "-b", "upstream")
        self.write("upstream", "new")
        self.upstream = self.git("rev-parse", "HEAD")
        self.git("checkout", "main")
        self.write("downstream", "retained")
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.directory, check=True,
                              text=True, capture_output=True).stdout.strip()

    def write(self, filename, value):
        (Path(self.directory) / filename).write_text(value)
        self.git("add", filename)
        self.git("commit", "-m", filename)

    def test_merge_preserves_both_histories_and_is_idempotent(self):
        head = updater.merge(self.directory, self.upstream)
        self.assertEqual(self.git("rev-list", "--parents", "-n", "1", head).split(),
                         [head, self.base, self.upstream])
        self.assertEqual((Path(self.directory) / "downstream").read_text(), "retained")
        self.assertEqual(updater.merge(self.directory, self.upstream), "")
        self.assertEqual(self.git("rev-parse", "HEAD"), head)

    def test_conflict_aborts_without_rewriting_downstream(self):
        self.git("checkout", "upstream")
        self.write("base", "upstream conflict")
        upstream = self.git("rev-parse", "HEAD")
        self.git("checkout", "main")
        self.write("base", "downstream conflict")
        before = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(RuntimeError, "conflicts"):
            updater.merge(self.directory, upstream)
        self.assertEqual(self.git("rev-parse", "HEAD"), before)
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_merge_does_not_execute_repository_hook(self):
        marker = Path(self.directory) / "hook-ran"
        hook = Path(self.directory) / ".git/hooks/post-merge"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        hook.chmod(0o755)
        updater.merge(self.directory, self.upstream)
        self.assertFalse(marker.exists())

    def test_retry_after_push_reuses_existing_commit(self):
        branch, head = updater.proposal(self.directory, self.base, self.upstream)
        self.git("update-ref", f"refs/remotes/origin/{branch}", head)
        self.git("checkout", "--detach", self.base)
        self.assertEqual(updater.proposal(self.directory, self.base, self.upstream), (branch, head))
        self.assertEqual(self.git("rev-parse", "HEAD"), self.base)

    def test_existing_branch_missing_history_is_rejected(self):
        branch = f"upstream-sync/{self.base[:12]}-{self.upstream[:12]}"
        self.git("update-ref", f"refs/remotes/origin/{branch}", self.upstream)
        with self.assertRaisesRegex(RuntimeError, "both histories"):
            updater.proposal(self.directory, self.base, self.upstream)


if __name__ == "__main__":
    unittest.main()
