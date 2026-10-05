# Building against Gatehouse

Gatehouse lets an agent use a database, an HTTP API, a GitHub repository, a
Cloud Storage prefix or a staging web app without ever holding the password,
key or token. Each destination is one entry in one catalog file. The agent
connects to a local address and sends a placeholder where the credential
would go; Gatehouse swaps in the real one on the way out. Anything not in the
catalog is refused, and every request lands in a signed audit trail that names
the person behind the agent when there is one.

Not all of this is live yet:

| Part | Status |
|---|---|
| Gatehouse support for all six destination kinds | Added by agent-vault #22 to #24; not in a release yet |
| Adding an entry with one trm-infra pull request | The module is trm-infra #1041. Nothing calls it yet; a follow-up pull request adds the catalog file and connects it to Vault |
| Entries limited to named people (tiers T1 and T2) | Refused today. The live Entra group lookup stays off until its app registration exists. |
| Database entries above T0 | The database path carries the person's session, so T1 and T2 databases work once the Entra lookup is on, as for HTTP |
| Repository and pull request entries | Wait for the GitHub App, which is not created yet |

## Add a destination with one catalog entry

Once the trm-infra module is wired in, the catalog is `gatehouse-catalog.yaml`,
read by `vault/terraform/modules/gatehouse-catalog` in trm-infra. You add one
entry and open one pull request; Atlantis, the Terraform pull request bot,
creates the Vault access the entry needs, and Gatehouse picks up the change
within 30 seconds with no restart. Check an entry locally first, with an
`agent-vault` binary built from this repository (the command is not in a
release yet):

```sh
agent-vault broker-catalog validate --require-pools gatehouse-catalog.yaml
```

| To reach | `kind` | You also need |
|---|---|---|
| A PostgreSQL database | `postgres` | Its `-readonly` or `-readwrite` Vault role. The existing role modules issue `-readonly` by default. |
| An HTTP API with a key | (leave unset) | The key, written by an operator to the `gatehouse` key-value mount in Vault |
| A GitHub repository (clone, push) | `git` | The GitHub App, installed on the repository |
| Opening and commenting on GitHub pull requests | `github-api` | The same App |
| A Cloud Storage prefix or a BigQuery dataset | `gcp` | A second pull request in trm-global-infrastructure for the Google Cloud access grants. See `examples/credential-proxy/gcp-tokens.md`. |
| A staging web app as a test user | `browser-session` | A test user and an Auth0 login client. See `examples/credential-proxy/browser-session.md`. |

The module grants Vault access for `postgres`, HTTP, `git` and `github-api`
entries only. A `browser-session` entry also needs Vault read access to its
test user and login client, which the module does not grant yet.

A catalog defines its pools, then its entries. This example passes
`agent-vault broker-catalog validate --require-pools` once the `REPLACE`
value and the group ID are real:

```yaml
pools:
  - {name: cursor-agents, namespace: cursor-agents, serviceAccount: cursor-worker}
  - name: claude-developers                # sessions that name a person
    namespace: claude-developers
    serviceAccount: worker
    identity: claude-session
    ccpoolID: ccpool_REPLACE               # the runner pool's ID
    ceiling: T1

entries:
  - name: b2bcore                          # a database
    kind: postgres
    host: p.abc.db.postgresbridge.com
    pools: [cursor-agents]
    postgres: {database: core, mount: database, role: staging.us.crunchy.core-readonly}

  - name: serpapi                          # an HTTP API; tier T0 by default
    host: serpapi.com
    pathPrefixes: [/search]
    methods: [GET]
    header: X-Api-Key
    placeholder: __vault_SERPAPI_KEY__
    key: {mount: gatehouse, path: vendors/serpapi, field: key}
    pools: [cursor-agents]

  - name: insights-repo                    # a repository; pushes only under cursor/
    kind: git
    host: github.com
    pools: [cursor-agents]
    # appID and installationID come from the GitHub App installation
    git: {appID: 123456, installationID: 7890123, repos: [{repo: trmlabs/trm-insights, access: write, refPrefixes: [refs/heads/cursor/]}]}

  - name: team-files                       # one Cloud Storage prefix, people only
    kind: gcp
    host: storage.googleapis.com
    tier: T1
    requires: [00000000-0000-0000-0000-000000000000]   # the Entra group's object ID
    placeholder: __vault_GCP__
    pools: [claude-developers]
    gcp: {bucket: trm-agent-files, prefix: teams/analytics/, role: roles/storage.objectViewer}
```

## Tiers decide who may use an entry

Every entry has a tier and every pool has a ceiling, the highest tier it may
reach. Gatehouse refuses a grant above a pool's ceiling when it loads the
catalog, and checks again on every request.

| Tier | Who may use it |
|---|---|
| T0 (default) | Any worker in a granted pool, including Cursor's, which has no person behind its agents |
| T1 | A verified person in every group the entry `requires`, from a Claude pool; or an automation pool whose fixed groups include them all. Never Cursor. |
| T2 | As T1, from a Claude pool only, with the groups granted for a limited time through P0 |

`gcp` entries are always T1 or T2. When the Entra lookup is on, a person's
groups are cached for at most 5 minutes, so adding or removing someone takes
effect within 5 minutes.

## Time-limited access goes through P0

P0 is TRM's time-limited access request tool. This works once the Entra group
lookup is on and P0 can grant the entry's groups.

1. Find the entry's `requires` groups in the catalog.
2. Request the group in P0, with the reason and how long you need it.
3. After approval, Gatehouse sees the group within 5 minutes. No restart is needed.
4. When the grant expires, P0 removes the group, and Gatehouse refuses within 5 minutes.

## Agents connect to the sidecar on loopback

Each worker has a Gatehouse sidecar listening on its loopback address. Your
pool's worker template sets the real addresses; the values below are the
end-to-end test harness's.

| Destination | Point the client at | Credential to send |
|---|---|---|
| HTTP API | `HTTPS_PROXY=http://127.0.0.1:14443` | The entry's `header` set to its `placeholder` (after its `scheme`, if set), or no header |
| GitHub pull requests | The same proxy | `GH_TOKEN=__vault_GITHUB_TOKEN__`, or no token |
| Git | `git clone https://github.com/trmlabs/<repo>` through the proxy | Nothing. Any `Authorization` header is refused. |
| Google | The same proxy, with `CLOUDSDK_AUTH_ACCESS_TOKEN=__vault_GCP__` | `Authorization: Bearer` and the entry's placeholder |
| PostgreSQL | `host=127.0.0.1`, one port per database (15000 for the harness's first, 15001 for the next), with that binding's `dbname` and `user` (`workload` in the harness) | The binding's placeholder password (`gatehouse-relay-placeholder` in the harness) |
| Staging app | A Playwright storage state from `https://<api host>/.gatehouse/browser-seed` | Nothing |

- **Trust:** the worker must trust Gatehouse's interception certificate authority, at `/public/mitm-ca.crt` in the harness. Point `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE` at it.
- **Database startup settings:** `application_name`, `client_encoding`, `DateStyle`, `extra_float_digits`, `search_path`, `standard_conforming_strings`, `statement_timeout` and `TimeZone` (so `PGTZ` works) are accepted. Anything else, including `options`, is refused; use `SET` after connecting.

## From a Cursor self-hosted worker

Pick the Gatehouse pool in Cursor's environment picker and use the standard
connection strings and environment variables the pool's worker template sets;
there is no SDK. The staging pool, its variables and its limits are in
trm-internal-apps, `apps/gatehouse/runbooks/cursor-developer.md`.

- **Tier T0 only:** Cursor does not tell Gatehouse who started a task, so a
  Cursor pool has no person behind it and a ceiling of T0. A catalog that
  grants a Cursor pool an entry above T0 is refused when Gatehouse loads it.
- **No group control on the pool:** anyone in the Cursor team who can use
  self-hosted machines can pick any team pool. Grant a Cursor pool only data
  every such person may read.
- **Group-limited entries:** use a Claude pool, where Gatehouse verifies the
  person and checks their groups on each request.

## Every refusal names its cause

HTTP refusals carry an `X-Request-Id` header. Give it to Security to find the
exact audit row. Database refusals reach the client from the sidecar with the
fixed text below, at connect time and inside a session; Gatehouse's own text
never reaches the worker. Refusing one query inside a session leaves the
session open, unless earlier messages of the same batch had already reached
the database; then the session ends. Errors from PostgreSQL itself, such as
a syntax error or a PostgreSQL permission error, pass through unchanged. For
anything unclear, give Security the pool and the time to find the audit row.

| You see | Usually means | Fix |
|---|---|---|
| 403 | The host or path is not in the catalog, your pool has no grant, or the tier check refused: no person behind the session, not in the group, a session from another pool, or the group lookup is unavailable | Add the entry or the grant, or request the group |
| 405 | The method is not listed for that path | Add the method to the entry |
| 400 | Something other than the exact placeholder in the key header, a placeholder anywhere else, plain HTTP, or an unsupported request (an upgrade, a compressed body) | Send only the placeholder, in the entry's header, over HTTPS |
| 413 | The request is larger than the entry allows | Raise `maxRequestBytes` |
| 429 | This worker's rate limit for that entry | Slow down |
| 502 | The service could not be reached, or its response was refused, for example because it echoed the credential | Check the service |
| 503 | Gatehouse could not get the credential, or its audit trail is down | Retry; tell Security if it persists |
| Postgres 53300 "this worker reached its session cap" | This worker has as many sessions open as it may | Close idle sessions, or retry |
| Postgres 53300 "the database's Gatehouse connection budget is full; retry shortly" | The database's connection budget is in use, at connect time or on a query | Retry shortly |
| Postgres 53300 "Gatehouse is at capacity; retry shortly" | Gatehouse's overall connection cap is reached | Retry shortly |
| Postgres 53300 "no session-mode database connection is free for session state (SET, temp tables, LISTEN, advisory locks); retry shortly" | The query needs session state and no dedicated connection is free | Retry, or avoid session state |
| Postgres 57P03 "Gatehouse is starting; retry in a few seconds" | The Gatehouse replica you reached is not ready yet | Retry; another replica answers |
| Postgres 3D000 "this database isn't in the Gatehouse catalog for your pool" | No catalog entry for that database, or it is not granted to your pool | Add the entry or the grant |
| Postgres 28000 "Gatehouse could not verify this worker" | Gatehouse refused the worker's Pod identity, or the sidecar could not read its identity proof | Retry; tell Security if it persists |
| Postgres 42501 "Gatehouse: this session's person is not authorized for this database" | The tier check refused this database for this session | Request the group, or use a pool with a person behind it |
| Postgres 25006 "this database login is read-only: Gatehouse allows only reads, transaction control and a few settings such as search_path, and refuses temporary tables" | A read-only login sent something other than a read: a write, a temporary table, `DO`, `set_config`, or a `SET` outside the allowed settings. Pooled, the session continues; unpooled, it ends | Use a read; use a CTE or subquery instead of a temporary table; reconnect if the session ended |
| Postgres 42501 "Gatehouse refuses changing standard_conforming_strings or client_encoding mid-session; only on and UTF8 at connect" | The session tried to change how the server reads text, which could hide a statement from Gatehouse | Leave both at their defaults; set client_encoding at connect |
| Postgres 28P01 "Gatehouse: wrong placeholder password for this binding" | Wrong placeholder password | Use the binding's placeholder |
| Postgres 08006 "Gatehouse could not reach the database; retry" | The database is unreachable, at connect time or on a query | Retry; tell Security if it persists |
| Postgres 08006 "Gatehouse could not get a database credential; retry shortly" | Gatehouse could not obtain a credential for the database | Retry shortly; tell Security if it persists |
| Postgres 08006 "Gatehouse ended the session (deadline or revocation)" | The worker is past its deadline, or Gatehouse ended the session (revocation, or a failed recheck) | Reconnect; a worker past its deadline is not admitted again |
| Postgres 08001 "cannot reach Gatehouse" | The sidecar could not reach Gatehouse | Retry; tell Security if it persists |
| Postgres 08004 "Gatehouse: connection refused: use this binding's database and user, and only the ... startup parameters" | A database or user other than the binding's, or a startup setting outside the accepted list | Use the binding's database and user; set other settings with `SET` |
| Postgres 08004 "Gatehouse: the broker refused this connection" | Any other refusal | Retry; tell Security the pool and time if it persists |
| Connection closed with no error | The worker's task was withdrawn | Start a new task |
