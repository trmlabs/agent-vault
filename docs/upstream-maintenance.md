# Review upstream updates

Keep downstream security changes while reviewing improvements from Infisical's
Agent Vault. Incoming changes become an ordinary pull request. Nothing merges
into protected branches, rebases published history or publishes automatically.

## Enable incoming proposals

1. Review `.github/workflows/upstream-update.yml` and the trusted default-branch
   script `scripts/upstream-update.py`. Set the repository variable
   `UPSTREAM_UPDATES_ENABLED=true` only after this workflow reaches the default
   branch. Permit GitHub Actions to create pull requests in repository settings.
2. Require maintainer review and `ci-summary` on the current pull request head.
   Keep deployment credentials in a separate deployment repository or protected
   environment. Untrusted tests must never receive them or run on production
   runners. The proposal job uses repository write permissions but never runs
   fetched code; normal pull-request verification receives read-only permissions and no
   deployment secrets. The scheduled job does not execute proposed code.
3. Run **Review upstream updates** manually for the first proposal. Thereafter
   it checks weekly. It merges upstream `main` into the downstream default
   branch in a temporary checkout. Conflicts stop before push and require a
   maintainer to resolve them. An existing open `upstream-sync/` proposal is
   reused without changing its head; complete its normal PR checks and review,
   or close it before proposing a newer update.
4. Verification starts as **Pending**. A successful proposal run means only
   that a branch and PR exist. Approve the normal PR workflow runs in GitHub.
   If GitHub offers no runs, a maintainer must close and reopen the PR to create
   a normal PR event. Verify that `CI` actually runs in `pull_request` context
   against the current head, and require its green `ci-summary` before merging.
   A changed head requires fresh results. Do not dispatch untrusted verification
   from a scheduled/default-branch workflow: runner cache credentials can remain
   privileged even when its GitHub token is read-only.

GitHub documents token-triggered event behavior in
[Triggering a workflow](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow).
Do not use `pull_request_target` to run proposed code with a write token, or add
a broad personal token merely to bypass workflow approval.

## Review and record the result

Review authentication, destination restrictions, audit durability, database
cleanup, migrations, dependencies and workflow changes. Preserve the downstream
release guards and test jobs. Confirm that both histories remain present and
that migration/restart behavior still passes. A conflict is review work, never
permission to discard downstream changes.

Normal PR CI runs Go race tests, lint, module consistency, frontend
and SDK checks, and disposable real-service fixtures. Real Kubernetes identity
and deployed isolation remain separate checks described in
`examples/credential-proxy/README.md`.

Record in the PR description: upstream and downstream revisions, proposed head,
test-run links, conflicts resolved, relevant compatibility changes, reviewer
decision and next action. Complete when a maintainer accepts the change and all
required checks pass on the current head. Revert a bad merge through a reviewed
revert PR; do not rewrite published history.

Local automation checks:

```sh
python3 scripts/upstream-update-test.py
actionlint .github/workflows/*.yml
```

## Propose focused changes upstream

Prepare a small branch against current upstream `main` with a general-purpose
fix, regression test and explanation. Remove organization-specific deployment
values, policies, identity mappings and incident references. Check upstream's
current contribution and security-reporting instructions before submission.
Have a maintainer approve the target repository, proposed patch and description
before opening an upstream contribution. This repository does not automatically
open upstream contributions.

Retain upstream copyright and license notices. The top-level license contains
third-party and possible enterprise-directory exceptions; review the actual
files being distributed rather than assuming every future import is MIT.

## Publication boundary

Generic code, synthetic fixtures and reusable setup instructions can be proposed
for public review. Actual cluster configuration, service-account identifiers,
Vault paths, private endpoints, credentials, operator evidence and deployment
state belong in the deployment repository or protected evidence store.

Inherited binary/container and SDK release jobs run only in the original
upstream repository. A downstream release needs a separate reviewed change for
package ownership, registry destinations, signing identity and protected
publication approval. Tagging the downstream repository must not publish to
upstream namespaces. Keeping the upstream module name does not grant publishing
authority or imply upstream endorsement.
