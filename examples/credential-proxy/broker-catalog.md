# Broker catalog

The broker catalog is the one list of everything workers may reach through the broker: databases, HTTP services, git repositories and the GitHub pull request API, each granted to named worker pools. Adding a destination is one entry in one reviewed file. Terraform writes the catalog to Vault, and the broker picks up the new version within 30 seconds, with no restart.

## Where it lives and how it loads

- **Source:** a YAML file in trm-infra, next to the Vault roles and key paths its entries use, so one Atlantis pull request creates both. The `gatehouse-catalog` module validates it at plan time and writes it as JSON to the KV version 2 secret `gatehouse/catalog`, field `catalog`.
- **Broker:** `AGENT_VAULT_CATALOG_VAULT_PATH=gatehouse/catalog`. The broker refuses to start without a valid catalog, then polls every 30 seconds. A new version that passes the broker's parser replaces the old one atomically, and the next request or connection uses it. A version that fails is logged as `broker catalog version rejected` with its number, and the last good catalog stays in force. Alert on that log line.
- **One secret per entry:** `AGENT_VAULT_CATALOG_VAULT_PREFIX=gatehouse/catalog` reads the same catalog split so no single secret holds all of it, which is how a catalog grows past Vault's size limit for one secret. The layout is below. Set this or `AGENT_VAULT_CATALOG_VAULT_PATH`, never both; the single document stays accepted while catalogs move.
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

Entry kinds: `postgres` (port 5432 by default; `sslmode` is `verify-full`, the only mode the catalog accepts; `access` is `read` by default and must be `write` exactly for a `-readwrite` role; the broker needs `AGENT_VAULT_CATALOG_ENVIRONMENT`, and `validate` needs `--environment`, such as `staging`, and every role must then be `staging.<region>.<cluster>.<name>-readonly` or `-readwrite`; with no environment set, a catalog with any `postgres` entry is refused), HTTP (no kind; see the HTTP header adapter guide), `git` and `github-api` (see the git adapter guide). When `pools` is defined, an entry can grant only defined pool names. Grants match the scope's pool, which the broker's attestation sets from the worker Pod's approved controller. The agent ID stays the broker's own identifier for revocation, Vault roles, cleanup and audit. A scope with no pool matches no grant. Audit rows carry both `pool` and `agent`.

## External pools

A pool with `ceiling: external` is below T0: its workers serve people outside the company, so it reaches nothing. The catalog refuses any entry that grants it, and an external pool takes no verified identity. It exists so a harness for customer-facing sandboxes can be declared before entries can be scoped to a tenant.

## Harness profiles

A harness is one kind of agent runtime: Cursor workers, Claude sessions, agent-sandbox. Each is one `harnesses` entry that answers three questions: how its agents prove who they are, how they reach the broker, and whether access is decided for the pool or for the person. A new runtime needs a new entry, and code only if it brings a new identity kind.

```yaml
harnesses:
  - name: cursor
    trustDomain: {issuer: https://container.googleapis.com/v1/projects/P/locations/L/clusters/C, keys: in-cluster, audience: gatehouse}
    identity: {kind: pod-token, ownerKind: ReplicaSet, namespaces: [cursor-agents], imageDigests: [sha256:...]}
    path: {kind: sidecar}
    authorization: {mode: pool, poolName: cursor-agents}
    client: {proxyEnv: GATEHOUSE_HTTPS_PROXY, caFileEnv: GATEHOUSE_CA_FILE, caSpkiEnv: GATEHOUSE_CA_SPKI}
```

| Field | Values |
|---|---|
| `trustDomain` | `issuer` (HTTPS), `keys` (`in-cluster`: the broker's own cluster API; `remote`: the issuer's published keys; `pinned`: the issuer's public keys held in the broker's identity configuration, no fetch), `audience` |
| `identity.kind` | `pod-token` (the Pod's own token, live Pod and source address), `session-jwt` (the same, plus a runner session naming the person, pinned to its first Pod), `proxy-attested` (a shared proxy in the agent's cluster checks the Pod and presents its own token) |
| `identity` | `ownerKind` (the controller kind that must own the agent Pod), `namespaces`, `imageDigests`, optional `imagePrefix` (proxy-attested only: an agent-sandbox repository or tenant path ending in `/`; `imageDigests` may then be empty or list platform containers; two harnesses may not overlap), optional `requester` (`session-jwt` or `signed-assertion`) |
| `path` | `kind` (`sidecar` or `shared-proxy`), `crossCluster` |
| `authorization` | `mode` (`pool` or `person`), `poolName` |
| `client` | Environment variable names the worker render sets: `proxyEnv` (Gatehouse's proxy URL), `caFileEnv` (its CA file), optional `caSpkiEnv` (the CA's SPKI hash, for a browser launched with a trust flag). Cursor keeps `HTTPS_PROXY` for its own gateway, so it uses the `GATEHOUSE_` names; harnesses that leave the standard names free use `HTTPS_PROXY` and `SSL_CERT_FILE`. Every harness sets `caSpkiEnv` to `GATEHOUSE_CA_SPKI`, because Chromium on Linux trusts only its own certificate store: browsers trust Gatehouse by key hash everywhere, with no `certutil` in the image. The broker does not read these |

Every field is required except `requester`, `crossCluster` and `caSpkiEnv`, and the catalog is refused when an entry is incomplete or contradictory: a `pod-token` harness runs a sidecar and decides for the pool; `session-jwt` decides for the person; `proxy-attested` runs a shared proxy; a cross-cluster path uses remote keys and is proxy-attested; `person` needs a requester. `signed-assertion` is refused until the broker verifies assertions. Once a catalog declares harnesses, each pool belongs to exactly one, its namespace is listed, and its `identity` agrees with the mode (`claude-session` exactly for `person`). A catalog without harnesses keeps today's behavior: each pool's profile is derived from its `identity`.

## Validation

`agent-vault broker-catalog validate catalog.yaml --require-pools --allowed-host-suffix .postgresbridge.com --allowed-host-suffix serpapi.com` runs the broker's own parser. It checks the schema, exact hosts with no wildcards or IP addresses, unique routes, methods, key locations and pool grants, and keeps every host inside the allowed domains. Run it in CI before Atlantis applies. For CI without access to this repository, `Dockerfile.catalog-validator` builds the same command into a small image (glibc base with a shell, so it can serve as a CI job container), at the broker's reviewed commit, through the same build, review, publish and Artifact Registry mirror path as the broker image; pin it by digest.

## Egress

The broker's network policy allows the approved data-plane ranges once. Inside the broker, `AGENT_VAULT_EGRESS_RANGES` (comma-separated CIDRs) confines every resolved destination address to those ranges, public or private. An unparseable value allows nothing. A destination is reachable only when its host is in the catalog and its address is in these ranges. A new database in an existing range needs no network change. Only a new range needs a second change, in the broker's network policy.

## One secret per entry

Under `AGENT_VAULT_CATALOG_VAULT_PREFIX=<mount>/<prefix>`:

| Secret | Field | Holds |
|---|---|---|
| `<prefix>/head` | `catalog` | The catalog document without `entries`, for example the `pools` list. |
| `<prefix>/head` | `entries_sha256` | SHA-256, lowercase hex, over every entry in byte order of name: the name, a newline, the stored entry JSON, a newline. |
| `<prefix>/entries/<name>` | `entry` | One entry's JSON. Its `name` must equal `<name>`. |

Write every changed entry first and the head last. The head's KV version is the catalog version: each poll reads only the head, and reads every entry only when that version changes. If the entries read do not hash to the head's digest, because an apply is part way through, the broker logs `broker catalog version rejected`, keeps the last good catalog and tries again at the next poll. A head that carries `entries` is refused.

The broker's Vault policy needs `read` on `<mount>/data/<prefix>/head` and `<mount>/data/<prefix>/entries/*`, and `list` on `<mount>/metadata/<prefix>/entries`. Reads run 64 at a time; that sets reload speed, not how many entries the catalog may hold. The tests load 20,000 entries.
