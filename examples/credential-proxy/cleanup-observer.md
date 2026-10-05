# Observe broker cleanup

A trusted manager can check whether a dedicated database broker has finished its own cleanup. The response contains counts, not credentials or lease identifiers. This is an optional staging integration surface, disabled unless configured. It does not prove that the database contains no residual roles or sessions.

## Configure the trusted observer

Set `AGENT_VAULT_CLEANUP_OBSERVER_FILE` to an operator-owned workload policy and `AGENT_VAULT_CLEANUP_OBSERVER_PORT` to a separate numeric port, for example `14324`. Both settings are required. The listener binds only `127.0.0.1`; a bind failure stops broker startup. Use the same trust fields as the proxy workload policy, but a different audience and service account. Observer bindings contain `namespace`, `serviceAccount`, `serviceAccountUID`, optional `podUID` and optional `listAgents`; they must omit `agentID` and `vaultID`. Set `listAgents` only on the admission controller's binding. Proxy bindings reject it. Startup rejects an audience or account shared with proxy admission.

The observer uses projected, bounded Kubernetes proof. Every request performs TokenReview and a live Pod read; deleted, replaced or terminating Pods are denied. No owner session, standing API key or proxy grant substitutes for that proof. Mount it only in the trusted manager, never the worker.

Expose only this dedicated loopback observer listener through verified encrypted transport restricted to the manager. It serves only the cleanup path; registration, login, settings and cleanup-confirmation routes return 404. Keep the owner management listener private, including during bootstrap and empty-store recovery. Pin the expected broker endpoint and current backend identity in the manager's trusted configuration.

## Read and interpret the result

Send `GET /v1/runtime/cleanup-status` with `Authorization: Bearer <projected observer proof>` over that protected transport. The only supported queries are a single `agent` parameter or `agents=all`, described below; any other query, both at once, a body or a mutation is rejected. Responses are not cacheable.

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Currently `1`. Reject unsupported versions. |
| `status` | `ready`, `pending` or `unknown`. |
| `activeConnections` | Current database frontend handlers, including handshakes. |
| `unfinishedCleanup` | Durable cleanup records, including active leases. |
| `unknownCleanup` | Records whose credential-issuance outcome remains unknown. |
| `observedAt` | Server observation time, not a substitute for a fresh authenticated request. |

`ready` requires initialized, healthy cleanup authority, valid parent Vault authorization, consistent connection counts and zero records. `pending` means active connections or known cleanup records remain. `unknown` and HTTP 503 mean the manager must not admit a replacement. Authentication failure returns 401 without state. Without configuration, no observer listener opens. The owner listener never serves this route.

Before checking, withdraw the old relay and confirm its Pod is gone so existing connections cannot continue or create new work. Keep new admission stopped through the handover. Fetch a fresh observation from the expected broker after withdrawal; a previous zero-count response cannot authorize a later replacement.

## Check one agent

A manager that owns one worker slot sends `GET /v1/runtime/cleanup-status?agent=<agent ID>`, where the agent ID is the `agentID` of that slot's proxy workload binding. The top-level fields keep their whole-broker meaning, and the response gains an `agent` object with its own `status`, `activeConnections`, `unfinishedCleanup` and `unknownCleanup`. The HTTP status then follows `agent.status`: 200 for `ready` or `pending`, 503 for `unknown`. Admit or replace that slot's worker only when `agent.status` is `ready`.

The agent counts include everything the broker cannot attribute: connections that have not yet authenticated, and cleanup records written before attribution existed. They count against every agent, so a legacy record blocks all slots until it is reconciled. The response never names another agent. A malformed, empty or repeated `agent` parameter returns 400 without reading state.

## List every agent

The admission controller sends `GET /v1/runtime/cleanup-status?agents=all`. Its binding must set `listAgents`; any other verified observer receives 403 without state being read. The top-level fields and HTTP status keep their whole-broker meaning, and the response adds:

| Field | Meaning |
| --- | --- |
| `agents` | Entries of `agentID`, `workloadUID` (the Pod UID), `activeConnections`, `unfinishedCleanup` and `unknownCleanup`, sorted by agent then Pod. Only entries with a nonzero count appear; an absent agent or Pod has no work of its own. |
| `unattributedConnections` | Connections that have not yet authenticated. |
| `unattributedCleanup` | Cleanup records with no agent, written before attribution existed. |
| `unattributedUnknownCleanup` | The subset of those records whose issuance outcome is unknown. |

Unattributed work appears once at the top level and is not repeated in any entry. Treat any unattributed count as blocking every agent, and an entry with an empty `workloadUID` as blocking every Pod of its agent. A retired Pod is clean when it has no entry and nothing is unattributed. When the broker cannot account for every item by agent, the list fields are omitted and `status` is `unknown` with HTTP 503.

The observation serializes with issuance/reconciliation, checks the existing cleanup-owner heartbeat without extending it and reads durable records. It neither issues nor revokes credentials, confirms unknown cleanup nor grants authority to modify records. Independent database-side checks remain necessary to establish release acceptance. Unknown issuance requires the existing operator reconciliation procedure.

## Verification scope

Automated tests cover isolated-listener routing, occupied-port refusal, graceful shutdown and forced-close cancellation, plus live-verifier request contracts, TLS trust refusal, separate observer/proxy audiences, parent authorization failure, lost cleanup ownership, unknown records and changed frontend generations. Disposable fixtures do not establish deployed policy, actual manager recovery or independent database absence. Complete those checks before enabling unattended admission.
