# Running the broker as a fleet

Several broker replicas can share one PostgreSQL store. Each replica keeps its
own list of the database credentials it handed out. If a replica dies, another
one notices within about 30 seconds and revokes everything the dead replica
held, so no database login is left behind. A replica that loses contact with
the store stops serving before anyone else can take over its credentials, so
no credential is ever served by two replicas at once.

A single replica on SQLite works as before.

## How ownership works

| Setting | Value | Meaning |
|---|---|---|
| Owner row | one per broker process, named `<replica>/<random>` | A restarted Pod is a new owner and never inherits its predecessor's records |
| Heartbeat | every 5 s | Renews the owner row, counts live replicas, claims orphaned records |
| Fence | 20 s without a successful renewal | The replica stops accepting, closes every session and exits, so Kubernetes restarts it |
| Takeover | 30 s after the last renewal | Survivors may claim the records; every replica tries once a second |

- **Clock.** Expiry is written and compared with the database clock (`now()`), never a replica's clock. The fence uses the replica's own elapsed time since it sent the last successful renewal, counting both monotonic and wall time, so a suspended host still fences.
- **Claim.** A claim is one SQL statement that moves each record only from the owner it read. When two survivors race, each record moves once. Revocation is idempotent anyway.
- **Drain.** On SIGTERM a replica starts no new issuance and lets one under way finish and journal its lease before it gives up ownership, so a restart does not leave an unknown issuance.
- **Quarantine.** An issuance whose lease ID never arrived quarantines its binding for every replica until Vault's lease list shows no credential from it remains (see [automatic reconciliation](database-recovery.md#automatic-reconciliation)) or an operator confirms cleanup.
- **Budgets.** Pooled server-connection budgets divide by the live replica count. When a replica joins, the others close idle connections down to their new share.
- **Sessions.** The `broker_sessions` table counts a Pod's sessions fleet-wide. A session counts only while its replica is live.

Evidence:

| Test | What it shows |
|---|---|
| `TestDurableLeaseFencesBeforeTakeoverWhenPartitioned` | A replica cut off from the store closes its session while its owner row is still live; the survivor revokes only after the row expires |
| `TestRealVault_FleetSurvivorRevokesCrashedReplica` | Real Vault and PostgreSQL with these timings: the survivor revoked a SIGKILLed replica's role and session 31 s after the kill |
| `TestRealPostgres_DatabaseCleanupJournal` | Racing survivors claim each of 200 records exactly once, over 20 rounds |
| e2e scene `replica_crash` | Kills a replica mid-session in Kind |

## Moving a live SQLite broker to PostgreSQL

> **Warning.** Move a store only with a binary that includes the `migrate-db`
> fix for broker tables (`fix(store): migrate-db carries the broker's tables`).
> Older binaries copy no pending cleanup records, so every credential still
> waiting for revocation would be forgotten and its database login left
> behind. The live staging store needs this fix before any move.

1. Create an empty PostgreSQL database for the store. Put its URL in a Secret; it holds a password, so never pass it on a command line you log.
2. Stop the broker: `kubectl scale statefulset <broker> --replicas=0`. Wait until its Pod is gone. Records left by a crash are safe: they move with the data.
3. Back up the SQLite volume.
4. Run a one-off Pod on the broker's data volume, with the URL from the Secret in `STORE_URL`:
   `agent-vault migrate-db --from /data/.agent-vault/agent-vault.db --to "$STORE_URL" --dry-run`, then again with `--yes`.
5. Compare the row counts from both runs. Pending cleanup records, the audit boot counter and the proxy audit copy too.
6. Set `DATABASE_URL` from the Secret on the StatefulSet. Allow each replica's Pod name in the Vault JWT role's `bound_claims`.
7. Scale to the replica count you want. Each replica registers an owner row. The first one claims and revokes the migrated cleanup records, because they arrive without an owner.
8. Check `SELECT owner FROM database_cleanup_replica` lists one row per replica, and that `database_cleanup` drains.

The migration only adds tables, columns and indexes. Old and new binaries must
not run at the same time against one store: the old single-owner row is not
consulted. A StatefulSet rolling update with one replica already guarantees this.

## Operating the fleet

- **Restart after a fence.** A replica that loses its owner row exits; Kubernetes restarts it as a new owner. It takes no traffic until it holds a fresh owner row of its own: the process registers the row before the broker listens, `GET /ready` returns 503 without a fresh row, and the broker refuses new sessions with SQLSTATE 57P03. Point the readiness probe at `GET /ready` on the API port and keep `GET /health` for liveness.
- **Readiness.** A row is fresh when it was claimed at start or renewed within the last 10 seconds. A replica whose renewals are failing goes unready and refuses new sessions about 10 seconds before it fences, so the Service stops routing to it first.
- **Joining.** A joining replica counts itself at once. The others shrink their pool budgets at their next heartbeat, so the fleet can exceed a database budget by one replica's share for up to 5 seconds.
- **Disruption.** Allow one replica down at a time. A graceful stop releases the owner row at once, so its leftover records move within a second.
- **Partition.** A replica that cannot reach the store exits within about 20 seconds. Its credentials are revoked by a survivor about 10 seconds later.
