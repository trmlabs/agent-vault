#!/usr/bin/env python3
"""Local Git fixtures for the upstream tag copy; no network or credentials."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("tags", Path(__file__).with_name("upstream-tags.py"))
tags = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tags)


class MirrorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.upstream, self.origin, self.work = (str(root / n) for n in ("upstream", "origin.git", "work.git"))
        self.git(root, "init", "-q", "-b", "main", self.upstream)
        self.git(self.upstream, "config", "user.name", "Test")
        self.git(self.upstream, "config", "user.email", "test@example.invalid")
        self.commit("one")
        self.git(self.upstream, "tag", "v0.1.0")
        self.commit("two")
        self.git(self.upstream, "tag", "-a", "-m", "release", "v0.2.0")
        self.git(self.upstream, "tag", "node-sdk/v0.1.0")
        self.git(root, "init", "-q", "--bare", self.origin)
        self.git(root, "init", "-q", "--bare", self.work)

    def git(self, cwd, *args):
        return subprocess.run(["git", *args], cwd=cwd, check=True, text=True, capture_output=True).stdout.strip()

    def commit(self, name):
        (Path(self.upstream) / name).write_text(name)
        self.git(self.upstream, "add", name)
        self.git(self.upstream, "commit", "-q", "-m", name)

    def kept(self):
        return tags.refs(self.git(self.origin, "for-each-ref", "--format=%(objectname) %(refname)", tags.PREFIX),
                         tags.PREFIX)

    def test_copies_every_tag_under_prefix_with_its_objects(self):
        pushed, failures = tags.mirror(self.work, self.origin, self.upstream)
        self.assertEqual(failures, [])
        self.assertEqual(sorted(pushed), ["node-sdk/v0.1.0", "v0.1.0", "v0.2.0"])
        upstream = tags.refs(self.git(self.upstream, "for-each-ref", "--format=%(objectname) %(refname)",
                                      "refs/tags/"), "refs/tags/")
        self.assertEqual(self.kept(), upstream)
        # The annotated tag keeps its tag object, and its commit is present.
        self.assertEqual(self.git(self.origin, "cat-file", "-t", "refs/tags/upstream/v0.2.0"), "tag")
        self.assertEqual(self.git(self.origin, "rev-parse", "refs/tags/upstream/v0.2.0^{commit}"),
                         self.git(self.upstream, "rev-parse", "v0.2.0^{commit}"))
        # Nothing outside the prefix is created.
        self.assertEqual(self.git(self.origin, "for-each-ref", "--format=%(refname)", "refs/tags/v0.1.0"), "")

    def test_rerun_copies_only_new_tags(self):
        tags.mirror(self.work, self.origin, self.upstream)
        self.commit("three")
        self.git(self.upstream, "tag", "v0.3.0")
        pushed, failures = tags.mirror(self.work, self.origin, self.upstream)
        self.assertEqual((pushed, failures), (["v0.3.0"], []))

    def test_moved_upstream_tag_never_moves_the_kept_copy(self):
        tags.mirror(self.work, self.origin, self.upstream)
        before = self.kept()["v0.1.0"]
        self.git(self.upstream, "tag", "-f", "v0.1.0", "HEAD")
        pushed, failures = tags.mirror(self.work, self.origin, self.upstream)
        self.assertEqual(pushed, [])
        self.assertEqual(len(failures), 1)
        self.assertIn("v0.1.0", failures[0])
        self.assertEqual(self.kept()["v0.1.0"], before)

    def test_deleted_upstream_tag_stays_kept(self):
        tags.mirror(self.work, self.origin, self.upstream)
        self.git(self.upstream, "tag", "-d", "v0.1.0")
        tags.mirror(self.work, self.origin, self.upstream)
        self.assertIn("v0.1.0", self.kept())

    def test_unsupported_names_are_reported_not_pushed(self):
        to_push, conflicts = tags.plan({"v1": "a" * 40, "-x": "b" * 40, "a..b": "c" * 40, "x.lock": "d" * 40}, {})
        self.assertEqual(to_push, {"v1": "a" * 40})
        self.assertEqual(len(conflicts), 3)


if __name__ == "__main__":
    unittest.main()
