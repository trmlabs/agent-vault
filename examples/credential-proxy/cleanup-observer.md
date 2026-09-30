# Observe broker cleanup

A trusted manager can check whether a dedicated database broker has finished its own cleanup. The response contains counts, not credentials or lease identifiers. This is an optional staging integration surface, disabled unless configured. It does not prove that the database contains no residual roles or sessions.

## Configure the trusted observer

Set `AGENT_VAULT_CLEANUP_OBSERVER_FILE` to an operator-owned workload policy and `AGENT_VAULT_CLEANUP_OBSERVER_PORT` to a separate numeric port, for example `14324`. Both settings are required. The listener binds only `127.0.0.1`; a bind failure stops broker startup. Use the same trust fields as the proxy workload policy, but a different audience and service account. Observer bindings contain `namespace`, `serviceAccount`, `serviceAccountUID` and optional `podUID`; they must omit `agentID` and `vaultID`. Startup rejects an audience or account shared with proxy admission.

The observer uses projected, bounded Kubernetes proof. Every request performs TokenReview and a live Pod read; deleted, replaced or terminating Pods are denied. No owner session, standing API key or proxy grant substitutes for that proof. Mount it only in the trusted manager, never the worker.

Expose only this dedicated loopback observer listener through verified encrypted transport restricted to the manager. It serves only the cleanup path; registration, login, settings and cleanup-confirmation routes return 404. Keep the owner management listener private, including during bootstrap and empty-store recovery. Pin the expected broker endpoint and current backend identity in the manager's trusted configuration.

## Read and interpret the result

Send `GET /v1/runtime/cleanup-status` with `Authorization: Bearer <projected observer proof>` over that protected transport. No query, body or mutation is supported. Responses are not cacheable.

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Currently `1`. Reject unsupported versions. |
| `status` | `ready`, `pending` or `unknown`. |
| `activeConnections` | Current database frontend handlers, including handshakes. |
| `unfinishedCleanup` | Durable cleanup records, including active leases. |
| `unknownCleanup` | Records whose credential-issuance outcome remains unknown. |
| `observedAt` | Server observation time, not a substitute for a fresh authenticated request. |

`ready` requires initialized, healthy cleanup authority, valid parent Vault authorization, consistent connection counts and zero records. `pending` means active connections or known cleanup records remain. `unknown` and HTTP 503 mean the manager must not admit a replacement. Authentication failure returns 401 without state. Without configuration, no observer listener opens. The owner listener never serves this route.

Before checking, withdraw the old relay and confirm its Pod is gone so existing connections cannot continue or create new work. Keep new admission stopped through the handover. Fetch a fresh observation from the expected broker after withdrawal; a previous zero-count response cannot authorize a later replacement. This initial scope is the whole dedicated broker, with one admitted worker lease. It provides no per-worker attribution or concurrent handover guarantee.

The observation serializes with issuance/reconciliation, checks the existing cleanup-owner heartbeat without extending it and reads durable records. It neither issues nor revokes credentials, confirms unknown cleanup nor grants authority to modify records. Independent database-side checks remain necessary to establish release acceptance. Unknown issuance requires the existing operator reconciliation procedure.

## Verification scope

Automated tests cover isolated-listener routing, occupied-port refusal, graceful shutdown and forced-close cancellation, plus live-verifier request contracts, TLS trust refusal, separate observer/proxy audiences, parent authorization failure, lost cleanup ownership, unknown records and changed frontend generations. Disposable fixtures do not establish deployed policy, actual manager recovery or independent database absence. Complete those checks before enabling unattended admission.
