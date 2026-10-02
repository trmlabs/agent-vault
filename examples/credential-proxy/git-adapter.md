# Git adapter

The git adapter lets a worker clone, fetch and push over HTTPS without ever holding a GitHub credential. The worker runs ordinary git through the broker with no token. The broker checks that the repository is in the catalog for the worker's pool, and that a push is allowed. It then adds a short-lived GitHub App installation token minted for that one repository and records the call in the signed audit trail. GitHub's branch protection still applies to every push.

## Catalog entry

A git entry in `AGENT_VAULT_HTTP_CATALOG_FILE` lists repositories, not paths:

```json
{"name": "github", "host": "github.com", "kind": "git", "pools": ["<pool agent ID>"],
 "git": {"appID": 0, "installationID": 0, "repos": [
   {"repo": "trmlabs/trm-b2b", "access": "write", "refPrefixes": ["refs/heads/cursor/"]},
   {"repo": "trmlabs/docs", "access": "read"}]}}
```

| Field | Rule |
| --- | --- |
| `repos[].access` | `read` allows clone and fetch. `write` also allows push. |
| `maxRequestBytes` | Default 1 GiB, the largest push accepted. Fetch negotiation may be gzip-compressed; it passes through unchanged. |
| `repos[].refPrefixes` | Optional, write only. A push that would create, update or delete any ref outside these prefixes is refused before it reaches GitHub. Push certificates are refused when prefixes are set. |
| `appID`, `installationID` | The GitHub App installation that mints tokens. |

Only git's three smart-HTTP endpoints are served: `info/refs` with one `service` parameter, `git-upload-pack` and `git-receive-pack`. Git LFS, the REST API and every other path are refused. A host cannot mix git and header entries.

## Tokens

For each request the broker uses a token scoped to exactly one repository, with `metadata: read` plus `contents: read`, or `contents: write` only for a push to a `write` binding. A token GitHub returns with any wider scope is revoked and refused. Tokens are reused until ten minutes before their one-hour expiry. One mint is shared across concurrent requests, and a failed mint is not retried for five seconds. A 401 or 403 from GitHub drops the token, at most once per repository every 30 seconds. The worker sends no `Authorization` header; a request that carries one is refused. Responses that echo the token in any encoding are cut off.

## The App key

Import the App's private key into Vault Transit, so it never leaves Vault, and give the broker only:

```hcl
path "transit/sign/github-app/sha2-256" { capabilities = ["update"] }
```

Set `AGENT_VAULT_GITHUB_APP_TRANSIT_KEY=github-app` (mount `AGENT_VAULT_GITHUB_APP_TRANSIT_MOUNT`, default `transit`). `AGENT_VAULT_GITHUB_API_URL` overrides `https://api.github.com`, for GitHub Enterprise Server or a test server. The fallback, `AGENT_VAULT_GITHUB_APP_KV_PATH`, reads a PEM from field `private_key` on the `gatehouse` KV mount into broker memory for each signature. Creating the App, and choosing its permissions and installation, is a separate decision.

## Branch protection

The App acts as itself on GitHub, so branch protection and rulesets govern its pushes like any other actor's. Never add the App to a bypass list. Protect the default and release branches, and keep `refPrefixes` to agent branch names such as `refs/heads/cursor/`, so the broker refuses a push to a protected branch before GitHub has to.

## Worker setup (Cursor)

- Turn off `--mint-github-token` and the dashboard's GitHub token minting, so the worker gets no token.
- Route `github.com` through the worker's sidecar (`HTTPS_PROXY`) and trust the broker CA (`GIT_SSL_CAINFO` or `http.sslCAInfo`).
- Use `https://github.com/<owner>/<repo>.git` remotes, and remove any credential helper, `http.extraHeader` or `url.<token URL>.insteadOf` rewrite.
- Open risk: the Cursor README says runs fail to clone without the minting toggle. How Cursor's worker applies its token is not visible in our repositories, so confirm a run clones with the toggle off before relying on this.

## Opening pull requests (GitHub REST)

A `github-api` entry lets agents open pull requests and comment on them, and nothing else:

```json
{"name": "github-api", "host": "api.github.com", "kind": "github-api", "pools": ["<pool agent ID>"],
 "git": {"appID": 0, "installationID": 0, "repos": [{"repo": "trmlabs/trm-b2b", "access": "write"}]}}
```

Only `POST` to these paths is served, for a listed repository: `/repos/{owner}/{repo}/pulls`, `/repos/{owner}/{repo}/issues/{n}/comments`, `/repos/{owner}/{repo}/pulls/{n}/comments` and `.../comments/{id}/replies`. Reviews, approvals, merges, reads and every other path are refused, so an agent can never approve or merge its own change. The broker mints a token for that one repository with `pull_requests: write` and `metadata: read` only. The request body is JSON and limited to 1 MiB; a placeholder anywhere in it is refused. The worker sends no token, or the placeholder `__vault_GITHUB_TOKEN__`, so `gh` works with `GH_TOKEN=__vault_GITHUB_TOKEN__`. A worker's own token is refused.
