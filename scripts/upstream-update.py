#!/usr/bin/env python3
"""Propose one ordinary upstream merge; never run fetched code or rewrite history."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def run(args, cwd=None, check=True):
    return subprocess.run(args, cwd=cwd, check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def git(directory, *args, check=True):
    return run(["git", "-c", "core.hooksPath=/dev/null", "-c",
                "credential.helper=!gh auth git-credential", *args], directory, check)


def merge(directory, upstream):
    """Return an immutable merge SHA, empty for no change; abort conflicts."""
    if git(directory, "merge-base", "--is-ancestor", upstream, "HEAD", check=False).returncode == 0:
        return ""
    result = git(directory, "merge", "--no-ff", "--no-edit", upstream, check=False)
    if result.returncode:
        git(directory, "merge", "--abort", check=False)
        raise RuntimeError("Upstream merge conflicts. Resolve in a maintainer branch; no branch was pushed.")
    return git(directory, "rev-parse", "HEAD").stdout.strip()


def proposal(directory, base, upstream):
    branch = f"upstream-sync/{base[:12]}-{upstream[:12]}"
    existing = git(directory, "rev-parse", "--verify", f"refs/remotes/origin/{branch}", check=False)
    if existing.returncode == 0:
        head = existing.stdout.strip()
        for parent in (base, upstream):
            if git(directory, "merge-base", "--is-ancestor", parent, head, check=False).returncode:
                raise RuntimeError("Existing proposal does not preserve both histories; maintainer review required.")
        # Recover a successful push followed by a failed PR API request.
        # Never recreate or overwrite its merge commit on retry.
        return branch, head
    return branch, merge(directory, upstream)


def output(head, pr=""):
    if head and not re.fullmatch(r"[0-9a-f]{40}", head):
        raise RuntimeError("Invalid proposed commit")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as f:
        f.write(f"head={head}\n")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as f:
        f.write(f"Proposed commit: `{head}`\n\n{pr}\n" if head else "Already contains upstream main.\n")
        if head:
            f.write("\nVerification pending: approve normal pull-request CI in GitHub. If no run is offered, a maintainer must close and reopen the PR to generate a normal PR event. Require green checks on its current head. This proposal run does not execute tests or permit merging.\n")


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or repository.lower() == "infisical/agent-vault":
        raise RuntimeError("Expected a downstream repository")
    # Ignore machine-level Git filters and hooks. Only fixed Git operations run.
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
    os.environ["GIT_CONFIG_GLOBAL"] = "/dev/null"
    pending = json.loads(run(["gh", "pr", "list", "--repo", repository, "--state", "open",
                              "--limit", "100", "--json", "headRefName,headRefOid,url"]).stdout)
    for pr in pending:
        if pr["headRefName"].startswith("upstream-sync/"):
            output(pr["headRefOid"], pr["url"])
            return
    with tempfile.TemporaryDirectory(prefix="upstream-merge-") as temp:
        git(temp, "clone", "--no-checkout", f"https://github.com/{repository}.git", "source")
        directory = str(Path(temp) / "source")
        git(directory, "checkout", "--detach", "origin/HEAD")
        base = git(directory, "rev-parse", "HEAD").stdout.strip()
        git(directory, "config", "user.name", "github-actions[bot]")
        git(directory, "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
        git(directory, "fetch", "--no-tags", "https://github.com/Infisical/agent-vault.git", "refs/heads/main")
        upstream = git(directory, "rev-parse", "FETCH_HEAD").stdout.strip()
        branch, head = proposal(directory, base, upstream)
        if not head:
            output("")
            return
        # Ordinary push only. A pre-existing divergent branch causes failure.
        git(directory, "push", "origin", f"{head}:refs/heads/{branch}")
        body = Path(temp) / "pr.md"
        body.write_text(f"Merge upstream main `{upstream}` into downstream `{base}`.\n\n"
                        "The automation runs no fetched code while holding its write token. "
                        "Verification is pending normal pull-request CI. "
                        "Review workflow, dependency, authentication and migration changes; "
                        "approve normal PR checks if GitHub requests it. "
                        "Deployment configuration and secrets are outside this change.\n\n"
                        "Maintainer review and green checks on the current PR head are required. "
                        "No automatic merge, rebase or force-push.\n")
        pr = run(["gh", "pr", "create", "--repo", repository, "--head", branch,
                  "--title", "Review upstream updates", "--body-file", str(body)]).stdout.strip()
        output(head, pr)


if __name__ == "__main__":
    main()
