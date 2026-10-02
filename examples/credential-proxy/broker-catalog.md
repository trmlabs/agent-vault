# Broker catalog

The broker catalog is the one list of everything workers may reach through the broker: databases, HTTP services, git repositories and the GitHub pull request API, each granted to named worker pools. Adding a destination is one entry in one reviewed file. Terraform writes the catalog to Vault, and the broker picks up the new version within 30 seconds, with no restart.

## Where it lives and how it loads

- **Source:** a YAML file in trm-infra, next to the Vault roles and key paths its entries use, so one Atlantis pull request creates both. The `gatehouse-catalog` module validates it at plan time and writes it as JSON to the KV version 2 secret `gatehouse/catalog`, field `catalog`.
- **Broker:** `AGENT_VAULT_CATALOG_VAULT_PATH=gatehouse/catalog`. The broker refuses to start without a valid catalog, then polls every 30 seconds. A new version that passes the broker's parser replaces the old one atomically, and the next request or connection uses it. A version that fails is logged as `broker catalog version rejected` with its number, and the last good catalog stays in force. Alert on that log line.
- **Fixed file:** `AGENT_VAULT_HTTP_CATALOG_FILE` still works for local fixtures. It is read once at start.

## Format

```yaml
pools:
  - {name: cursor-agents, namespace: cursor-agents, serviceAccount: cursor-worker}
entries:
  - name: b2bcore                     # the database name a worker connects to
    kind: postgres
    host: p.abc.db.postgresbridge.com
    pools: [cursor-agents]
    postgres: {database: core, mount: database, role: staging.us.crunchy.core-readonly}
  - name: serpapi
    host: serpapi.com
    pathPrefixes: [/search]
    methods: [GET]
    header: X-Api-Key
    placeholder: __vault_SERPAPI_KEY__
    key: {mount: gatehouse, path: vendors/serpapi, field: key}
    pools: [cursor-agents]
```

Entry kinds: `postgres` (defaults: port 5432, `sslmode: verify-full`), HTTP (no kind; see the HTTP header adapter guide), `git` and `github-api` (see the git adapter guide). When `pools` is defined, an entry can grant only defined pool names. Grants match the scope's pool, which the broker's attestation sets from the worker Pod's approved controller. The agent ID stays the broker's own identifier for revocation, Vault roles, cleanup and audit. A scope with no pool matches no grant. Audit rows carry both `pool` and `agent`.

## Validation

`agent-vault broker-catalog validate catalog.yaml --require-pools --allowed-host-suffix .postgresbridge.com --allowed-host-suffix serpapi.com` runs the broker's own parser. It checks the schema, exact hosts with no wildcards or IP addresses, unique routes, methods, key locations and pool grants, and keeps every host inside the allowed domains. Run it in CI before Atlantis applies. For CI without access to this repository, `Dockerfile.catalog-validator` builds the same command into a small image (glibc base with a shell, so it can serve as a CI job container), at the broker's reviewed commit, through the same build, review, publish and Artifact Registry mirror path as the broker image; pin it by digest.

## Egress

The broker's network policy allows the approved data-plane ranges once. Inside the broker, `AGENT_VAULT_EGRESS_RANGES` (comma-separated CIDRs) confines every resolved destination address to those ranges, public or private. An unparseable value allows nothing. A destination is reachable only when its host is in the catalog and its address is in these ranges. A new database in an existing range needs no network change. Only a new range needs a second change, in the broker's network policy.
