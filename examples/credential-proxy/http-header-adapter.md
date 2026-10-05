# HTTP header adapter

The header adapter lets a worker call an approved vendor or internal API without ever holding its key. The worker sends its request through the broker with a placeholder, or with no key at all. The broker checks that the destination, path and method are in an operator catalog and that the worker's pool is granted it. It then adds the key from Vault and records the call in the signed audit trail. Anything not in the catalog is refused.

## What the worker does

Point the worker's HTTPS proxy at its local relay, trust the broker's CA, and either omit the key header or set it to the catalog placeholder:

```
Authorization: Bearer __vault_LLM_KEY__
```

SDKs that insist on a key get the placeholder as their key value. The worker never sees the real key, so it cannot reach a transcript, a log or a commit.

## Catalog

Set `AGENT_VAULT_HTTP_CATALOG_FILE` to a JSON file. One entry per binding:

```json
{"entries": [{
  "name": "litellm",
  "host": "litellm.example.internal",
  "pathPrefixes": ["/v1/chat/completions", "/v1/models"],
  "methods": ["GET", "POST"],
  "header": "Authorization",
  "scheme": "Bearer",
  "placeholder": "__vault_LLM_KEY__",
  "key": {"mount": "gatehouse", "path": "vendors/litellm", "field": "key"},
  "pools": ["<pool agent ID>"],
  "forwardHeaders": ["OpenAI-Beta"]
}]}
```

| Field | Rule |
| --- | --- |
| `host`, `port` | One exact DNS name; no wildcards or IP addresses. Port defaults to 443. A tunnel to any other host is refused before it opens. |
| `pathPrefixes` | Matched on whole path segments: `/v1/chat` allows `/v1/chat/completions`, not `/v1/chatx`. The longest matching prefix wins. A path with `;`, a segment starting with `..`, or `.` is refused before matching. |
| `methods` | Any of GET, HEAD, POST, PUT, PATCH, DELETE. |
| `header`, `scheme`, `placeholder` | Where the key goes. A worker may send exactly the placeholder there, or nothing. A worker's own value is refused. |
| `basicUser` | The key is an HTTP Basic user name with an empty password, as axios `auth.username` and `curl -u key:` send it. The header is `Authorization` and `scheme` is unset. The worker sends its placeholder encoded the same way (set the client's key to the placeholder), or nothing. |
| `key` | A KV version 2 secret on the `gatehouse` mount, at a path under `vendors/` (lower-case segments, at most 127 characters). Writing a new version rotates the key. |
| `pools` | Broker agent IDs of the worker pools granted this entry. |
| `forwardHeaders` | Extra caller headers the vendor needs. Only Accept, Accept-Language, Content-Type and User-Agent pass otherwise; routing headers such as `X-Forwarded-Host` or `X-HTTP-Method-Override` can never be listed. |
| `maxRequestBytes`, `maxResponseBytes` | Default 1 MiB and 32 MiB. |

## Guarantees

- **No key to the worker.** A placeholder anywhere other than the catalog header, including the body or query, is refused, so it can never reach the vendor verbatim. Responses stream to the worker, including server-sent events, but the broker holds back any tail that could be the start of the key. A response that echoes the key in any of nine encodings is cut off before that part is sent, and is recorded as `secret_echo`.
- **Signed audit.** Each call records an `http_request` row before the vendor is contacted and an `http_response` row with the status and outcome. Each refusal records a `denied` row with its reason: `unlisted`, `method`, `pool`, `request_shape`, `placeholder_misplaced` and the rest. Rows name the pool, the Pod, the binding and a request ID returned to the worker as `X-Request-Id`.
- **Fail closed.** No catalog entry, no pool grant, no key from Vault, or an overdue audit checkpoint: the call is refused before the vendor is contacted.

## Keys and rotation

The broker reads each key from Vault at most once a minute and shares that read across concurrent requests. A new KV version takes effect within a minute, or at once when the vendor answers 401 or 403, which drops the cached key. If Vault is unreachable, a cached key keeps working for five minutes past its minute, then calls are refused.

Grant the broker read on each key path, for example `gatehouse/data/vendors/*`. In TRM's Vault this is a trm-infra change.

## Requirements

`AGENT_VAULT_CREDENTIAL_PROXY=true`, workload identity, a Vault client and `AGENT_VAULT_AUDIT_CHAIN` (see the signed audit guide). The broker refuses to start with a catalog but without any of these.
