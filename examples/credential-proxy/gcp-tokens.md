# Google Cloud tokens per catalog entry

An agent can read a bucket prefix or query a BigQuery dataset without ever
holding a Google credential. The worker sends at most a placeholder. Gatehouse
mints a short-lived token for that one catalog entry from its own Google
identity and adds it on the entry's host and paths only. Each entry gets its
own narrow token, so an agent allowed one prefix or dataset cannot reach
another, even with the token Gatehouse used.

## Two ways to mint

| Mode | Set | What the token can do | How |
|---|---|---|---|
| Downscope | `bucket`, `prefix`, `role` | Objects under one prefix of one bucket, with one object role (viewer, creator or user) | A Credential Access Boundary on the broker's own token, through Google STS. Google supports boundaries for Cloud Storage only. |
| Impersonate | `serviceAccount`, `scopes` | Whatever that one service account holds, such as reader on one dataset | `generateAccessToken` for the entry's own service account |

- Tokens are used for `lifetimeSeconds` (default 900, at most 3600). They are cached until a quarter of that is left, and dropped after Google answers 401 or 403.
- A downscoped token also ends when the broker's own token ends, at most an hour.
- Every response is screened for the token.

## Catalog entries

```json
{"name": "team-files", "kind": "gcp", "host": "storage.googleapis.com", "tier": "T1",
 "requires": ["<Entra group object ID>"], "placeholder": "__vault_GCP__", "pools": ["claude"],
 "gcp": {"bucket": "trm-agent-files", "prefix": "teams/analytics/", "role": "roles/storage.objectViewer"}}

{"name": "bq-cases", "kind": "gcp", "host": "bigquery.googleapis.com", "tier": "T1",
 "requires": ["<Entra group object ID>"], "placeholder": "__vault_GCP__", "pools": ["claude"],
 "pathPrefixes": ["/bigquery/v2/projects/trm-analytics/"],
 "gcp": {"serviceAccount": "gh-bq-cases@trm-analytics.iam.gserviceaccount.com",
         "scopes": ["https://www.googleapis.com/auth/bigquery"]}}
```

- **Tier:** gcp entries are T1 or T2. Under the authorization model they are never granted to a pool without a person behind it, such as the Cursor pool, and every request needs a verified person in the `requires` groups.
- **Hosts:** must be `*.googleapis.com`. Hosts that mint or manage credentials (STS, IAM Credentials, IAM, OAuth) are refused.
- **Paths:** downscoped entries default to the bucket's JSON API paths. Impersonating entries must list their paths.
- **On the worker:** set the client's access token to the placeholder, for example `CLOUDSDK_AUTH_ACCESS_TOKEN=__vault_GCP__`, and send HTTPS through the Gatehouse sidecar.

## IAM, a second-repo step

The service accounts and grants are GCP IAM. They live in
**trm-global-infrastructure**, beside the existing service accounts in
`gcp/folders/trm-b2b/trm-b2b-production/trm-b2b-api/infrastructure/service-accounts/`,
not in trm-infra. Each new entry is a PR there, then a catalog PR.

1. **Broker identity:** one service account for the broker, bound to its Kubernetes service account through Workload Identity (`roles/iam.workloadIdentityUser` on that service account only).
2. **Impersonating entry:**
   - Create a service account for the entry, holding only the entry's role on the entry's resource (for example `roles/bigquery.dataViewer` on one dataset, plus `roles/bigquery.jobUser` where queries run).
   - Grant the broker `roles/iam.serviceAccountTokenCreator` on that service account alone, with `google_service_account_iam_member`.
   - **Never grant TokenCreator at project or folder level.** The broker may mint only for the accounts the catalog names.
3. **Downscoped entry:**
   - A boundary only narrows what the broker already holds. Grant the broker the entry's object role on that bucket alone, with `google_storage_bucket_iam_member`, never at project level.
   - Keep each such bucket for agent data only, because the broker's base grant covers the whole bucket.

## Deferred: AWS

AWS requests are signed per request (SigV4), so Gatehouse would have to
re-sign each request rather than add a header, from an STS AssumeRole session
with a session policy. TRM's AWS use is small today, so this waits for demand.
