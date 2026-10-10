# Gatehouse

Gatehouse lets AI agents use databases, APIs and code repositories without ever
holding a password, key or token. An agent sends a placeholder where the
credential would go. Gatehouse checks that the agent is allowed to reach that
destination, adds the real credential on the way out, and records the request
in a signed audit trail that names the person behind the agent when there is
one. Anything not explicitly allowed is refused.

> Gatehouse is a fork of Infisical's open-source
> [Agent Vault](https://github.com/Infisical/agent-vault), MIT licensed. We're
> grateful for their work and contribute generic fixes back. Gatehouse is
> maintained by TRM Labs and is not an Infisical product; Infisical has not
> reviewed or endorsed this fork.

## Status

| Part | State today |
|---|---|
| Broker support for every destination below | On `main`. There is no tagged release |
| Staging | Running, with broker images built from `main` commits |
| Production | Not live. No release has been designated as supported ([SECURITY.md](SECURITY.md)) |

## Why Gatehouse

An agent that holds a credential can leak it: through a prompt injection, a
log line, a transcript or a commit. Gatehouse removes the credential from the
agent entirely.

- **Agents never hold a credential.** The agent's environment contains only
  placeholders and public connection settings. A compromised agent has no
  credential to steal; it can use only what the catalog grants its pool, and
  every use is recorded.
- **Short-lived credentials, added on the way out.** Where a service supports
  it, Gatehouse issues a credential that lives from minutes to an hour, for one
  destination: a database login, a GitHub App token for one repository, a
  narrowed Google Cloud token. API keys stay in HashiCorp Vault; the broker
  re-reads them every minute, so a rotated or removed key takes effect within
  a minute.
- **One catalog decides access.** Every destination is one entry in one
  reviewed catalog, granted to named agent pools. Gatehouse checks the agent's
  workload identity, its pool and the entry's tier on every request.
- **A signed audit trail that names the person.** Every request and database
  session is recorded in a tamper-evident chain with signed checkpoints. When a
  person started the agent, the record names them.

## What agents can reach

| Destination | What the agent sends | What Gatehouse adds |
|---|---|---|
| PostgreSQL databases | A placeholder password | A temporary database login issued by HashiCorp Vault, revoked when no longer needed |
| HTTP APIs | A placeholder in the key header, or no key | The real key, for the catalog's host, paths and methods only |
| GitHub repositories (clone, push) | Nothing | A short-lived GitHub App token for that one repository; pushes can be limited to branch prefixes |
| GitHub pull requests | A placeholder token, or none | The same App token, for the pull request API |
| Google Cloud (Cloud Storage, BigQuery) | A placeholder token | A short-lived token narrowed to one bucket prefix or one service account |
| Staging web apps as a test user | Nothing | A sign-in for the test user; the browser holds only placeholders |

HTTP responses are screened for the credential, so a service that echoes it
back is cut off.

## How it's deployed

Gatehouse runs as a broker inside a Kubernetes cluster, separate from the
agents. Agents reach it through a sidecar or relay that proves which workload
is calling. A **harness** is one kind of agent runtime; each is declared in the
catalog with how its agents prove who they are and how they reach the broker.

| Harness | How agents connect | Who is named in the audit |
|---|---|---|
| Cursor self-hosted workers | A Gatehouse sidecar on each worker's loopback address | The worker pool. The staging Cursor pool does not name a person, so it reaches only entries open to the whole pool |
| agent-sandbox | A shared relay that matches each connection to a live sandbox Pod and the images it runs | The person who started the sandbox, when the pool runs in person mode; otherwise the pool |

Entries can be limited to people in specific groups. Cursor pools never reach
those entries.

## Try it

The local demonstration runs real HashiCorp Vault and PostgreSQL with
synthetic credentials, no network and no host directories. From the root of
this checkout, with Docker running:

```sh
docker build -f examples/credential-proxy/Dockerfile -t credential-proxy-verification .
docker run --rm --network none credential-proxy-verification
```

A nonzero exit is a failed demonstration. To build and test from source:

```sh
make build      # Build the web UI and the Go binary
make test       # Run the Go tests
```

Check a catalog file before proposing it:

```sh
./agent-vault broker-catalog validate --require-pools --environment staging catalog.yaml
```

The binary, Go module path and environment variables still use the upstream
`agent-vault` and `AGENT_VAULT_` names, so upstream fixes merge cleanly.

## Documentation

Gatehouse documentation lives in [examples/credential-proxy](examples/credential-proxy/):

| Read this | To learn |
|---|---|
| [Building against Gatehouse](examples/credential-proxy/developer-guide.md) | How to add a destination, connect an agent and read refusals. Start here |
| [Broker catalog](examples/credential-proxy/broker-catalog.md) | The catalog format, pools, tiers and harness profiles |
| [HTTP header adapter](examples/credential-proxy/http-header-adapter.md) | API keys behind placeholders |
| [Git adapter](examples/credential-proxy/git-adapter.md) | Clone and push with GitHub App tokens |
| [Google Cloud tokens](examples/credential-proxy/gcp-tokens.md) | Narrowed tokens for Cloud Storage and BigQuery |
| [Browser sessions](examples/credential-proxy/browser-session.md) | Staging web apps as a test user |
| [Signed audit](examples/credential-proxy/signed-audit.md) | The audit chain, checkpoints and verification |
| [Task relay](examples/credential-proxy/task-relay/README.md) | How sandboxes reach the broker without an identity token |
| [Workload identity](examples/credential-proxy/kubernetes/README.md) | Kubernetes identity setup and fixtures |
| [Running a fleet](examples/credential-proxy/broker-fleet.md) and [database recovery](examples/credential-proxy/database-recovery.md) | Operating several replicas and recovering interrupted credential requests |
| [Credential proxy verification](examples/credential-proxy/README.md) | The strict profile and its deployment requirements |
| [Upstream maintenance](docs/upstream-maintenance.md) | How upstream changes come in and generic fixes go back |

The [docs](docs/) directory is Infisical's Agent Vault documentation site.
It describes the features Gatehouse inherits, such as vaults, the management UI,
the CLI and the TypeScript SDK.

## Contributing

- Open a pull request against `main`.
- Run `go test -race ./...` before you push. It includes a check that keeps
  internal hostnames, cloud project names and similar identifiers out of this
  public repository; use `example.com` style placeholders instead.
- The required CI checks (`ci-summary`) and a maintainer review must pass
  before merge. Fix or reply to every automated review comment.
- Keep credentials, internal endpoints and deployment details out of code,
  docs, commits and pull request descriptions.
- When behavior changes, update the matching guide in
  [examples/credential-proxy](examples/credential-proxy/) in the same pull
  request.
- Fixes that help any Agent Vault user are offered upstream, following
  [upstream maintenance](docs/upstream-maintenance.md).

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Do not open a public issue with exploit details.

## License

MIT, as in the upstream project. See [LICENSE](LICENSE), which keeps
Infisical's copyright notice.
