#!/usr/bin/env python3
"""Keep every upstream release tag in this fork under upstream/; never move or delete one."""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

UPSTREAM = "https://github.com/Infisical/agent-vault.git"
PREFIX = "refs/tags/upstream/"
TAG_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*")


def git(directory, *args, check=True):
    return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c",
                           "credential.helper=!gh auth git-credential", *args],
                          cwd=directory, check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def refs(text, prefix):
    """Map ref name (without prefix) to object ID from ls-remote or for-each-ref output."""
    found = {}
    for line in text.splitlines():
        oid, name = line.split(None, 1)
        if name.startswith(prefix) and not name.endswith("^{}"):
            found[name[len(prefix):]] = oid
    return found


def plan(upstream, mirrored):
    """Return (to_push, conflicts): new tags to copy, and tags upstream moved."""
    to_push, conflicts = {}, []
    for name, oid in sorted(upstream.items()):
        if not TAG_NAME.fullmatch(name) or ".." in name or name.endswith(".lock"):
            conflicts.append(f"{name}: unsupported tag name")
        elif name not in mirrored:
            to_push[name] = oid
        elif mirrored[name] != oid:
            conflicts.append(f"{name}: upstream now points elsewhere; the kept copy is unchanged")
    return to_push, conflicts


def mirror(directory, origin, upstream_url=UPSTREAM):
    """Copy missing upstream tags to origin. Return (pushed, failures)."""
    git(directory, "fetch", "--no-tags", upstream_url, "+refs/tags/*:refs/upstream-tags/*")
    upstream = refs(git(directory, "for-each-ref", "--format=%(objectname) %(refname)",
                        "refs/upstream-tags/").stdout, "refs/upstream-tags/")
    mirrored = refs(git(directory, "ls-remote", origin, PREFIX + "*").stdout, PREFIX)
    to_push, failures = plan(upstream, mirrored)
    pushed = []
    # One push per tag, so one refused tag does not hold back the rest.
    # A plain push never overwrites: an existing tag is refused, not moved.
    for name, oid in to_push.items():
        result = git(directory, "push", origin, f"{oid}:{PREFIX}{name}", check=False)
        if result.returncode:
            reason = (result.stderr.strip().splitlines() or ["push refused"])[-1]
            failures.append(f"{name}: {reason}")
        else:
            pushed.append(name)
    return pushed, failures


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or repository.lower() == "infisical/agent-vault":
        raise RuntimeError("Expected a downstream repository")
    # Ignore machine-level Git filters and hooks. Only fixed Git operations run.
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
    os.environ["GIT_CONFIG_GLOBAL"] = "/dev/null"
    origin = f"https://github.com/{repository}.git"
    with tempfile.TemporaryDirectory(prefix="upstream-tags-") as temp:
        git(temp, "init", "--bare", "-q")
        # Fetch the fork's main first so pushes send only objects it lacks.
        git(temp, "fetch", "--no-tags", origin, "+refs/heads/main:refs/heads/main")
        pushed, failures = mirror(temp, origin)
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as f:
        f.write(f"Copied {len(pushed)} upstream tag(s) under `upstream/`.\n\n")
        for name in pushed:
            f.write(f"- `upstream/{name}`\n")
        if failures:
            f.write("\nNot copied:\n\n")
            for line in failures:
                f.write(f"- {line}\n")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
