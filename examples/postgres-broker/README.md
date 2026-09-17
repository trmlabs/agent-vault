# PostgreSQL credential broker — end-to-end demo

Agent Vault's PostgreSQL broker lets an agent connect to a database carrying
**only its Agent Vault token**. Agent Vault mints a
short-lived, dynamic credential from **HashiCorp Vault's database secrets
engine**, authenticates to the real database over SCRAM-SHA-256 on the agent's
behalf, and relays the session. Every connection uses a distinct, least-privilege
role whose lease the broker attempts to revoke when the connection ends.

```
  agent (psql / libpq)            Agent Vault                 HashiCorp Vault
  ───────────────────             ───────────                 ───────────────
  connect, password =                 │                             │
    <Agent Vault token> ───────────►  │  validate token (vault      │
                                       │   scope), resolve service   │
                                       │                             │
                                       │  GET database/creds/<role> ►│  CREATE ROLE
                                       │ ◄── username/password/lease │   (short TTL)
                                       │                             │
                                       │  SCRAM-SHA-256 to Postgres  │
                                       │   as the minted role ──────────────►  PostgreSQL
                                       │ ◄─────────── AuthenticationOk ───────
  ◄──── AuthenticationOk ─────────────│                             │
  SELECT ... ─────────────────────►   │ ═══════ raw relay ═════════════════►  PostgreSQL
                                       │                             │
  (disconnect) ──────────────────►    │  revoke lease ─────────────►│  DROP ROLE
```

The broker does not send the minted password to the agent. The ephemeral username
is visible through SQL. Credential containment also requires the network controls below.

## Reproduce the owner-to-agent workflow

From the repository root, with Docker running:

```bash
bash examples/postgres-broker/demo.sh
```

Docker is the only host dependency. The example builds Agent Vault from this
checkout and starts real PostgreSQL 16 and HashiCorp Vault 1.19.4 in one disposable
container. Image downloads and the Go build need network access; the running
container has external networking disabled, no published ports, and no host
mounts. It creates synthetic records, a local owner and a dedicated agent.
If your environment sets `SSL_CERT_FILE` (for example, a TRM-managed Zscaler
CA bundle), the launcher supplies that bundle to the build; certificate
verification remains enabled. The bundle is not copied into the runtime image.
Your local Agent Vault configuration is untouched. Exit or Ctrl+C removes the
container, its volumes and the per-run image tag; Docker build caches remain.

The example verifies the complete CLI-to-database path:

1. The owner registers an analytics binding and creates an agent with a vault grant.
2. Two connections using that same agent token receive distinct PostgreSQL users.
   Reads succeed and a write is rejected by the database role.
3. The owner adds two more database bindings without restarting the broker.
   Exact name selection works; unknown and removed names fail.
4. Revoking the agent rejects new connections.
5. PostgreSQL inspection confirms generated roles and sessions return to zero.

`demo.sh` is the Docker launcher; `smoke.sh` performs the checks inside the
container. Nonzero exit means a failed assertion. It uses per-database inherited
SELECT grants rather than a cluster-wide reader grant. The Vault administrator
is privileged only inside this disposable fixture. This is a functional smoke
test, not a production network-isolation proof or a managed-vendor certification.
The separate `verify.sh` suite covers renewal, cancellation, active-query cleanup,
load and PostgreSQL-backed store behavior.

## Supported identity flow

Use a dedicated agent identity with a grant to the intended Agent Vault vault:

```bash
# Run as an authenticated owner. The token is captured rather than printed.
AGENT_VAULT_TOKEN=$(agent-vault agent create database-agent --vault demo:proxy --token-only)
export AGENT_VAULT_TOKEN
```

This PR does **not** support the `agent-vault vault token` scoped-session path for
PostgreSQL connections. Those sessions currently lack the actor ID required by
the broker for per-actor limits and audit attribution, and fail authentication.
Do not remove the actor check to make such tokens work. Supporting scoped sessions
requires an explicit attribution/authorization design and regression coverage.
The example uses an agent with one vault grant, so the broker can infer the vault.

## Managing databases at runtime

Enable the broker with an empty store, then add databases with the CLI — the
broker resolves them live, so there is no restart:

```bash
# Enable the broker with no databases configured:
AGENT_VAULT_DB_BROKER=1 agent-vault server --postgres-port 14323   # VAULT_ADDR set

# Add/update requires an instance owner; list requires membership and remove permits a vault admin:
agent-vault vault database add --vault demo --name analytics \
  --upstream db.internal:5432 --database appdb --mount database --role app-ro --sslmode verify-full
agent-vault vault database list --vault demo
agent-vault vault database remove analytics --vault demo
```

An agent then connects with libpq using its Agent Vault token as the password,
**selecting the database by name**:

```bash
PGPASSWORD="$AGENT_VAULT_TOKEN" psql "host=127.0.0.1 port=14323 dbname=analytics user=agent"
```

The same operations are available over the API at
`/v1/vaults/{vault}/databases` (GET/POST list/add, DELETE remove), and the
vault's databases appear in `/discover` (names and upstream host only — never the
Vault mount, role, or any credential).

> `AGENT_VAULT_DB_SERVICES` (a vault-name-keyed JSON map) still works as an
> optional startup **bootstrap seed** for vaults that already exist (for example
> the built-in `default` vault, or any vault from a prior run). Seeding is
> insert-if-absent, so it never clobbers a database edited at runtime.

> An upstream database on a private network also requires
> `AGENT_VAULT_ALLOW_PRIVATE_RANGES=true` or an `AGENT_VAULT_NETWORK_ALLOWLIST`
> entry, the same egress guard the HTTP proxy uses.

## Security boundary and deployment

The frontend exchanges a reusable Agent Vault token in a PostgreSQL password
message. It therefore **only binds loopback**; enabling it with a non-loopback
`--host` fails. Use a local client or an authenticated encrypted tunnel for remote
clients. Frontend TLS is not implemented. Query cancellation is brokered with a fresh,
session-specific capability; the upstream cancellation secret stays inside the broker.

The database must accept traffic **only from the broker's trusted network
identity**, never directly from agent workloads. PostgreSQL allows an ordinary
LOGIN role to change its own password, including a role with `pg_read_all_data`.
An agent can run `SELECT current_user` and `ALTER ROLE CURRENT_USER PASSWORD ...`.
A transparent SQL relay cannot prevent this reliably with string filtering.
Restrict database ingress using firewall rules, security groups or `pg_hba.conf`
with broker-only source CIDRs. Test access from the actual agent workload, not
just from the broker host. An agent and broker sharing a pod/network namespace
are not isolated by a pod-level NetworkPolicy; use separate trust domains or
process-level egress controls. The disposable `demo.sh` container shows functionality; its shared network
namespace does not provide production agent/broker isolation.

Use `sslmode=verify-full` for remote upstreams, with their certificate authority
in the broker's system trust store. `prefer` can fall back to plaintext;
`require` encrypts without verifying the server. In those weaker modes the
broker accepts SCRAM but refuses cleartext-password authentication even when
TLS encryption is present. SCRAM iteration counts above 1,000,000 are rejected
to bound CPU work from upstream challenges. SCRAM channel binding is not supported.

Only instance owners may add or update database bindings, because the configured
mount/role uses the server's shared Vault identity. Give that identity only the
required database-role read, renewal, and revocation permissions. Vault admins
may remove their vault's services; members may list them. Permissions granted by
the Vault role remain the source of SQL authorization.

## Selection, capacity, and lease semantics

- `dbname` selects an exact service name first, or a unique upstream database
  alias. Unknown names and ambiguous aliases fail, including in single-service
  vaults. A deleted name never falls back to another service merely because it
  is the only remaining one. When an upstream database is omitted, the selected
  name is also sent as the upstream database; set `--database` for an override.
- Reuse bounded client-side connection pools within one agent identity instead
  of opening a new connection for every query. Each physical connection still
  receives its own Vault lease; never share a pool across agent identities.
- Limits are **per process**. Each client holds one upstream connection, without
  broker-side pooling. The global limit must account for every replica and other database
  users. Per-database limits do not reserve capacity against the global ceiling.
- Services across vaults using the same literal upstream address share the lowest
  nonzero `max_conns`, bounded by the global limit. Use one canonical address for
  a physical upstream; different DNS aliases are not automatically consolidated.
  Reductions reject new admissions until occupancy falls below the new limit;
  increases are seen on subsequent resolution. Existing sessions are not evicted.
- Pending handshakes retain their own budget until global admission. An
  authenticated connection waits at most two seconds for a global slot, allowing
  brief revocation backlogs to drain without immediately rejecting a burst.
  Waiting does not mint credentials; the pending cap bounds queue size. Actor
  and per-upstream quotas still reject excess admissions immediately. Serving
  slots bound authenticated resolution, minting, upstream connections and cleanup.
- An independent expiry timer closes a session even if Vault renewal stalls.
  Renewal cannot revive an expired session. Very short leases whose remaining TTL
  is below the renewal cadence floor expire normally rather than overrunning it.
- Disconnect/shutdown cancels renewal, closes sockets, and attempts revocation
  with a four-second timeout. Vault outages or a process crash can leave a lease
  until Vault successfully revokes it; there is no persistent orphan sweep. TTL
  alone is not proof of role deletion when Vault or PostgreSQL is unavailable.
- Established sessions recheck their token and selected binding every 30 seconds,
  with a five-second timeout. Revoked/expired tokens, lost instance-token grants,
  deleted services, changed upstream/role/TLS configuration and failed checks close
  the session. This is bounded revocation (normally within 35 seconds), not an
  authorization lookup on every query. Capacity changes only affect admission.
  The token remains in process memory for rechecks and is never persisted/logged.
- Credential issuance is never automatically retried: a lost response may already
  have created a role. An unknown lease must be recovered by Vault's lifecycle
  machinery; blindly retrying issuance would amplify database DDL and orphan roles.
- Cancellation pins to the established upstream peer, authenticates an opaque
  capability, and limits concurrent cancel delivery to one per session. Reserve
  headroom for at most one additional short-lived cancel connection per session.
  Query cancellation is best-effort PostgreSQL semantics, not transaction rollback
  of already committed work. A separate cancel connection must reach the same
  broker process; arbitrary replica load balancing cannot route its local key.
- Lease IDs are logged as audit join keys; passwords are not logged or stored.

## Repeatable real-infrastructure verification

Run `bash examples/postgres-broker/verify.sh` from the repository. It requires
Go, PostgreSQL server/client binaries, Vault and OpenSSL on PATH, and a non-root
user. It creates and removes disposable databases and a Vault dev server. It
never changes your Agent Vault home. `AV_VERIFY_PG_PORT` and
`AV_VERIFY_VAULT_PORT` override its default ports 55439 and 18349.

The script runs the real SCRAM, dynamic-role/revocation, churn, saturation,
renewal and abrupt-close tests, plus the PostgreSQL-backed store migration/CRUD
check. Packages run sequentially so generated-role baseline measurements do not
interfere with each other.

It also exercises a controlled `pg_hba.conf` isolation fixture: the broker uses
IPv6 loopback, while the simulated agent's direct database route uses IPv4 and
is denied for read-only roles. The test changes its own password through the
broker, confirms that password works on the trusted route, and checks that the
agent route is rejected while the broker session still works. These loopback
routes are a local test of the policy boundary, not a production network design.

## Production acceptance criteria

This is a PostgreSQL protocol broker. Multiple PostgreSQL databases and Vault
roles are supported; MySQL and other database protocols are not implemented.

Before enabling a real agent workload:

1. Verify the actual agent cannot reach either the database or Vault directly.
   Use verified TLS from broker to database and Vault; keep tokens out of process
   arguments, logs and crash dumps. Run the broker in a separate trust domain.
2. Review each Vault role's SQL grants. Prefer inherited grants to existing
   application tables. Avoid persistent object ownership, schema CREATE,
   CREATEROLE, superuser, BYPASSRLS, unsafe functions and grants permitting access
   beyond the intended database. Never use an unrestricted reader role on a
   cluster whose other databases contain unrelated data.
3. Validate revocation against an **active long-running query**, not just an idle
   connection. Closing TCP does not guarantee immediate query termination.
   The verification fixture terminates backends belonging to the exact minted
   username before dropping that role. Give the Vault database administrator only
   the privileges needed for these operations. Adapt and test statements for your
   managed PostgreSQL vendor; do not use broad DROP OWNED/CASCADE cleanup that
   could remove application objects.
4. Budget each physical upstream across the maximum replica count: serving
   connections + cancellation headroom + Vault admin pools + existing workloads
   must remain below the database limit. Limits are per broker process and literal
   address, not a distributed capacity reservation. Measure role DDL throughput
   and p95/p99 connection latency with the intended agent churn and query workload.
5. Alert on revoke failures, failed authorization rechecks, capacity rejections,
   Vault lease-expiration failures and accumulating generated roles. Test Vault
   outage, database failover and broker restart in staging. Do not force-revoke
   Vault lease records without first reconciling the corresponding database role.

Role creation/revocation and authorized SQL necessarily affect the database.
The broker cannot guarantee no database side effects, exactly-once issuance over
an unreliable network, or zero security incidents. It also does not undo
committed writes when access expires. These limits must remain explicit.

References: [PostgreSQL cancellation](https://www.postgresql.org/docs/17/protocol-flow.html),
[connection-loss detection](https://www.postgresql.org/docs/18/runtime-config-connection.html),
and [Vault irrevocable leases](https://docs.hashicorp.com/vault/tutorials/monitoring/troubleshoot-irrevocable-leases).
