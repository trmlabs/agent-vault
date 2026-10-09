# Signed broker audit

The PostgreSQL broker can record every session in a tamper-evident trail. Each row names the worker pool, the worker's Pod, the database binding and the outcome. Rows go to stdout as JSON, so the cluster's logging agent ships them as they are written. A verifier detects a missing, moved or edited row. Rows never contain a credential, token, query or upstream error text.

## How it works

- **One row per event.** `session_open` before the first query can run, `session_close` when it ends, and `denied` for every refusal, with a fixed outcome code such as `authentication`, `capacity` or `credential`. An identity refusal also names the check in `decision` (`identity_<reason>`); one at the token's signing key (`token_signature`, `token_keys_pinned_mismatch`, `token_keys_unavailable`, `token_keys_in_cluster_unknown`) adds the token's `kid` and the connection's `peer` address, which on the cross-cluster listener is the PROXY header's source. The kid is chosen by whoever made the token, so one that is not a plain identifier (`[A-Za-z0-9._-]`, 1 to 128 characters) is recorded as `invalid` with `kidSHA256`, the first 12 hex characters of its SHA-256. A refusal on the HTTP path also records `target`, the host and port the caller asked for, in canonical lower-case form, or `invalid` when it is not a DNS name or IP address; never a path, query or header. Each `http_response` row records `durationMs`, the milliseconds from admission to the end of the response, as `transaction` rows already do; the row for a browser sign-in's refresh-token revocation records how long the revocation took, retries included. Identity comes only from the verified workload proof. Refusals before authentication are capped at 10 rows a second, after a burst of 20; the operational log counts the rest.
- **A chain per replica boot.** Each row carries a sequence number, the previous row's MAC and its own MAC: HMAC-SHA256 over every field, under a key version read from Vault. Rows carry `macVersion: 5`, whose MAC covers every field: the authorization decision; on an identity refusal at the token's signing key, `kid` and `peer`; on a `proxy_certificate` row, the issued certificate's `serial` and `notAfter`; and on a refusal, `target`. A test fails if a new field is left out. Version 4 rows (written before `target`), version 3 rows (written before `serial` and `notAfter`), version 2 rows (before `kid` and `peer`) and rows without a version (before the authorization fields) verify under their older input; the verifier rejects such a row if it carries a field its version does not cover, and rejects a chain that steps down a version.
- **Boots link to each other.** The store keeps a counter per replica name and the last checkpoint row each boot persisted. A restart takes the next boot number, and its `chain_start` row names the previous boot and that boot's last checkpoint row. Deleting a whole boot, or cutting a boot's tail back past that checkpoint, breaks the link. A boot never starts under an older key than its predecessor ended on.
- **The store holds each replica's head.** The newest boot has no successor to link to it, so `audit verify --heads` checks it against the store: the boot must be in the export and reach the checkpoint the store persisted for it. This needs a stable replica name, so `AGENT_VAULT_REPLICA` (or the older `AGENT_VAULT_AUDIT_REPLICA`) is required; set it from the Pod name.
- **A signed checkpoint every minute.** The broker asks Vault Transit to sign the chain head with an ed25519 key that never leaves Vault, writes the signature as a `checkpoint` row and persists that row in the store. A broker that holds the HMAC key can rewrite rows only after its last checkpoint; anything older fails verification.
- **Key rotation.** Writing a new version of the KV secret rotates the HMAC key. The broker picks it up within five minutes and records a `key_rotated` row; the verifier rejects any later row under an older key. Rotate the Transit key with `transit/keys/<name>/rotate`.

## Failure behavior

| Failure | Behavior |
| --- | --- |
| HMAC key or store unreadable at start | The broker does not start. |
| stdout write fails | The chain stops, every open session ends and every new session is refused. |
| `AGENT_VAULT_AUDIT_CHAIN` unset | The broker starts unaudited and logs a warning saying so. |
| Transit or store unavailable | Each missed checkpoint is recorded as `checkpoint_failed`. Sessions continue for five minutes after the last signed and persisted checkpoint, then new sessions are refused until one succeeds. |
| Session row cannot be written | That session is refused before any query, and its credential is revoked. |

## Configure

1. Keep the HMAC key on the `gatehouse` KV version 2 mount. Create it without the value touching a file, an argument or shell history: `openssl rand -base64 32 | vault kv put gatehouse/audit-hmac key=-`.
2. Create the signing key: `vault write transit/keys/gatehouse-audit type=ed25519`.
3. Give the broker's Vault role a sign-only Transit policy for that one key, plus read on the HMAC key. In TRM's Vault this is a trm-infra change, which waits until the PR freeze lifts:

   ```hcl
   path "transit/sign/gatehouse-audit" { capabilities = ["update"] }
   path "gatehouse/data/audit-hmac"    { capabilities = ["read"] }
   ```

   The broker gets no `transit/keys`, `export` or `rotate` access. Grant the verifier `read` on `gatehouse/data/audit-hmac` (including versions) and on `transit/keys/gatehouse-audit`.
4. Set `AGENT_VAULT_AUDIT_CHAIN=1`, `AGENT_VAULT_AUDIT_HMAC_PATH=audit-hmac`, `AGENT_VAULT_AUDIT_TRANSIT_KEY=gatehouse-audit` and `AGENT_VAULT_AUDIT_REPLICA` to the Pod name (from the downward API). The HMAC mount defaults to `gatehouse`.
5. Route rows with the Cloud Logging filter `jsonPayload.type="gatehouse.audit.v1"` to a bucket with locked retention.

## Verify

```
agent-vault audit heads > heads.jsonl
agent-vault audit verify --hmac-path audit-hmac --transit-key gatehouse-audit --heads heads.jsonl --input export.jsonl
```

`audit heads` reads the store (`DATABASE_URL`) and prints each replica's current boot and newest persisted checkpoint; it prints no secrets. Take it after the export so the export can reach every head. The input is newline-delimited rows, bare or as exported Cloud Logging entries. Rows are checked in input order per replica chain. If the export does not preserve order, add `--sort-by-seq`: a moved row then cannot be reported as a reorder, but it still cannot hide an edit, because sequence numbers and links are inside the MAC. The command prints each finding and exits 1 on any finding or an empty input:

| Finding | Meaning |
| --- | --- |
| `edit` | A row's MAC does not match its contents. |
| `gap` | A sequence number is missing. |
| `reorder` | A row appears before one it follows. |
| `duplicate` | A sequence number appears twice. |
| `broken_link` | A row does not link to the row before it. |
| `no_chain_start` | A chain is missing its first row. |
| `bad_checkpoint` | A checkpoint signature or the head it signs does not verify. |
| `key_change` | The key version changed without a `key_rotated` row. |
| `missing_boot` | A boot that a later boot links to is absent. |
| `truncated_tail` | A boot ends before the checkpoint row its successor recorded for it. |
| `boot_link` | A boot's link to its predecessor does not match. |
| `missing_head` | A replica's newest boot, or the checkpoint the store holds for it, is not in the export. |
| `unknown_boot` | A boot newer than the store's head, or a replica the store never saw. |
| `key_downgrade` | A boot starts under an older key than its predecessor ended on. |
| `unsigned_tail` | A boot has no valid checkpoint at all, or more than `--max-unsigned` (default five minutes) of rows follow its last checkpoint. |
| `key_unavailable`, `malformed` | A row cannot be checked. |

An export that starts partway through a replica's history needs `--partial-history`, which lets each replica's earliest boot link outside the export. Boots inside the export must still link.

Rows written after the last persisted checkpoint, at most one minute of them, are protected by the chain alone until the next checkpoint; with `--heads`, that is the only window a cut can hide in. Run `audit heads` and the verifier on a schedule and alert on any finding.
