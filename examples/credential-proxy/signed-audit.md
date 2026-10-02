# Signed broker audit

The PostgreSQL broker can record every session in a tamper-evident trail. Each row names the worker pool, the worker's Pod, the database binding and the outcome. Rows go to stdout as JSON, so the cluster's logging agent ships them as they are written. A verifier detects a missing, moved or edited row. Rows never contain a credential, token, query or upstream error text.

## How it works

- **One row per event.** `session_open` before the first query can run, `session_close` when it ends, and `denied` for every refusal, with a fixed outcome code such as `authentication`, `capacity` or `credential`. Identity comes only from the verified workload proof.
- **A chain per replica boot.** Each row carries a sequence number, the previous row's MAC and its own MAC: HMAC-SHA256 over every field, under a key version read from Vault. A restart begins a new chain with a `chain_start` row.
- **A signed checkpoint every minute.** The broker asks Vault Transit to sign the chain head with an ed25519 key that never leaves Vault, and writes the signature as a `checkpoint` row. A broker that holds the HMAC key can rewrite rows only after its last checkpoint; anything older fails verification.
- **Key rotation.** Writing a new version of the KV secret rotates the HMAC key. The broker picks it up within five minutes and records a `key_rotated` row; the verifier rejects any later row under an older key. Rotate the Transit key with `transit/keys/<name>/rotate`.

## Failure behavior

| Failure | Behavior |
| --- | --- |
| HMAC key unreadable at start | The broker does not start. |
| stdout write fails | The chain stops and every new session is refused. |
| Transit unavailable | Each missed checkpoint is recorded as `checkpoint_failed`. Sessions continue for five minutes after the last signed checkpoint, then new sessions are refused until signing succeeds. |
| Session row cannot be written | That session is refused before any query, and its credential is revoked. |

## Configure

1. Create the HMAC key without it touching a file, an argument or shell history: `openssl rand -base64 32 | vault kv put secret/gatehouse/audit-hmac key=-`.
2. Create the signing key: `vault write transit/keys/gatehouse-audit type=ed25519`.
3. Grant the broker's Vault role `read` on `secret/data/gatehouse/audit-hmac` and `update` on `transit/sign/gatehouse-audit`. Grant the verifier `read` on the KV path (including versions) and on `transit/keys/gatehouse-audit`.
4. Set `AGENT_VAULT_AUDIT_CHAIN=1`, `AGENT_VAULT_AUDIT_HMAC_PATH=gatehouse/audit-hmac` and `AGENT_VAULT_AUDIT_TRANSIT_KEY=gatehouse-audit`.
5. Route rows with the Cloud Logging filter `jsonPayload.type="gatehouse.audit.v1"` to a bucket with locked retention.

## Verify

```
agent-vault audit verify --hmac-path gatehouse/audit-hmac --transit-key gatehouse-audit --input export.jsonl
```

The input is newline-delimited rows, bare or as exported Cloud Logging entries. Rows are checked in input order per replica chain. If the export does not preserve order, add `--sort-by-seq`: a moved row then cannot be reported as a reorder, but it still cannot hide an edit, because sequence numbers and links are inside the MAC. The command prints each finding and exits 1 on any finding or an empty input:

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
| `unsigned_tail` | More than `--max-unsigned` (default five minutes) of rows follow the last checkpoint. |
| `key_unavailable`, `malformed` | A row cannot be checked. |

Rows written after the last checkpoint are protected by the chain alone until the next checkpoint. Run the verifier on a schedule and alert on any finding.
