# Kubernetes workload identity reference

These direct-proof fixtures exercise broker identity and service behavior. For a
sandbox without identity credentials, use the [separate task relay](../task-relay/README.md)
and complete its deployed network acceptance checks.

The agent presents a short-lived proof of the running pod instead of a standing Agent Vault token. The broker verifies that proof and the current pod, then checks the agent's existing access to the selected vault before either proxy admits work.

These files prepare identity configuration only. They do not deploy a complete protected service. Kubernetes is a supported adapter protocol; GKE remains a proposed deployment until Infra confirms the runtime. A sandbox inside a shared runner is not a Kubernetes pod identity. Do not distribute a runner's service-account token to its sandboxes.

## Local implementation check

From the repository root:

```bash
go test -race ./internal/workloadidentity -count=1
```

The tests use a real TLS client and both real proxy listeners against a synthetic Kubernetes API, a synthetic PostgreSQL server and a synthetic credential issuer. They cover positive requests, standing-token rejection, current grant checks, issuer/audience/account/expiry policy, verifier failures and deleted or replaced pods. They do not establish runtime-issued token validation or deployed network isolation.

## Real local identity test

[verify-local.sh](verify-local.sh) creates one disposable kind cluster using an explicit local Docker socket and an isolated temporary configuration. It pins kind 0.33.0 and its Kubernetes 1.37.0 image from the [official release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0). Prerequisites: Go, Docker, kubectl, ripgrep and a running disposable Docker daemon with about 2 GB available memory.

```bash
bash examples/credential-proxy/kubernetes/verify-local.sh unix:///path/to/disposable/docker.sock
```

Allow 15 minutes: the test waits for a real 600-second projected token to expire. It checks runtime-issued proof through both local listeners, wrong issuer/audience/account, removed grants, revoked agents, verifier outage, deleted/replaced pods, actual expiry and projection rotation. It records that copying a valid bearer proof still permits replay. Tokens stay in test memory and temporary private files; test output reports decisions only. The script removes its cluster and temporary configuration on exit and refuses to replace an existing cluster with the same name.

To use an already-created disposable cluster named `credential-proxy-identity`, pass its isolated configuration directly:

```bash
go test -race -tags realkubernetes ./internal/workloadidentity \
  -run '^TestRealKubernetesProjectedIdentity$' -count=1 -v -timeout 15m \
  -args -workload-kubeconfig /path/to/isolated/kubeconfig
```

The test rejects a missing configuration or a non-loopback API address. It creates and removes its own namespace and review permissions. Projected proof is read from actual pods into the local test process; HTTP/PostgreSQL destinations and database credential issuance remain synthetic. This is real Kubernetes identity evidence, not proof that a deployed agent can reach the broker safely. The default kind network does not enforce network policy.

## Prepare a disposable cluster

Use an explicitly selected disposable Kubernetes context. Do not use a production cluster for these examples. A Kubernetes version that returns pod name and UID in the TokenReview `status.user.extra` fields is required; missing fields deny access.

1. Inspect [identity-rbac.yaml](identity-rbac.yaml), then apply it to the selected test context. The broker identity can create TokenReviews and read individual pods in the test namespace. The agent receives neither permission.
2. Read the live service-account UID and issuer from that cluster:

   ```bash
   kubectl --context "$TEST_CONTEXT" apply -f examples/credential-proxy/kubernetes/identity-rbac.yaml
   kubectl --context "$TEST_CONTEXT" -n credential-proxy-demo get serviceaccount credential-proxy-agent -o jsonpath='{.metadata.uid}'
   kubectl --context "$TEST_CONTEXT" get --raw /.well-known/openid-configuration
   ```

3. Copy [workload-identity.example.json](workload-identity.example.json) outside the checkout and replace every `REPLACE_WITH_...` value. Use the live issuer and service-account UID, an existing active broker agent ID, and a vault ID to which that agent currently has `proxy`, `member` or `admin` access. The file contains authorization metadata, never token values.
4. Mount the completed file into the trusted broker and set `AGENT_VAULT_WORKLOAD_IDENTITY_FILE` to its path. Run the broker under `credential-proxy-reviewer`. The default API address is `https://kubernetes.default.svc`; the default CA and reviewer token files are the standard Kubernetes service-account mount. External test brokers must explicitly configure `apiServer`, `caFile` and `reviewerTokenFile`. HTTPS and verified certificates are mandatory. The broker rereads its reviewer token on each API call to accept Kubernetes rotation.
5. Replace the image placeholder in [agent-pod.yaml](agent-pod.yaml) with an approved image digest before creating a test pod. Its dedicated projected token is available at `/var/run/credential-proxy/token`, has audience `credential-proxy`, and requests a 600-second lifetime. Reopen this file for each new request or connection so rotation takes effect. The example has no `AGENT_VAULT_TOKEN`.

Proof must contain exactly one audience, matching the configured broker audience. This is an intentional restriction beyond standard token audience membership; multi-audience proofs are rejected.

One namespace/service-account binding maps to one agent and one vault. `serviceAccountUID` prevents a recreated account from inheriting access. An optional `podUID` further pins the binding to one pod. Without that optional field, replacement pods under the approved account may authenticate with their own new proof; the deleted pod's old proof remains invalid. The verified pod UID is carried as `WorkloadID` for auditing and ongoing PostgreSQL authorization checks.

## Connect the two entry points

- HTTP clients send the projected token in `Proxy-Authorization: Bearer <proof>`. Do not put it in the destination's `Authorization` header or a URL. The broker removes proxy authorization before forwarding.
- PostgreSQL clients read the same projected file into the password field in memory. The broker replaces it with its separately issued destination credential.
- Existing CONNECT tunnels and PostgreSQL connections retain their admission proof. Reopen the connection with freshly read proof before it expires; projected-file rotation does not renew an existing connection. PostgreSQL reauthorization checks enforce expiry at the configured polling interval.
- When this configuration is enabled, both entry points use the workload resolver exclusively. A standing Agent Vault session or agent token cannot substitute for runtime proof. Management endpoints retain their separate administrator authentication.

The current PostgreSQL listener is restricted to loopback, and the proxy ingress protocols do not themselves encrypt the caller-to-broker hop. Infra must choose and verify an encrypted authenticated tunnel or equivalent protected ingress before separate pods can use these listeners. Do not publish either plaintext listener or send bearer proof over an unprotected network. The runtime design must also deny direct agent access to destinations, Vault, broker storage and runtime sockets; these identity examples do not supply that enforcement.

## Other clusters (trust domains)

The top-level `issuer`, `audience` and `apiServer` are the broker's own cluster. `trustDomains` lists other clusters, each verified locally against the signing keys it publishes:

```json
"trustDomains": [{"name": "agent-sandbox", "issuer": "https://container.googleapis.com/v1/projects/P/locations/L/clusters/C",
  "audience": "gatehouse-edge", "keys": "remote", "jwksURL": "https://container.googleapis.com/v1/projects/P/locations/L/clusters/C/jwks"}]
```

A token's exact issuer picks its domain, and only that domain's keys can verify it. With `"keys": "pinned"` the domain holds the issuer's public key set in `jwks` instead of `jwksURL` (RSA RS256 of at least 2048 bits, or EC P-256 ES256; 1 to 16 keys, each with a unique kid). The broker then never fetches keys, so it needs no egress to the issuer; a kid outside the set refuses with `token_keys_pinned_mismatch` until the set is updated. A remote domain refuses an unfetched or unknown kid with `token_keys_unavailable`, the broker's own cluster with `token_keys_in_cluster_unknown`, and a bad signature is `token_signature`. Each of these logs `msg="workload identity refused" reason=<code> count=<n> kid=<kid> peer=<address>` and writes the kid and peer into the audit row; see [signed audit](../signed-audit.md). Any private or unknown key member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`, ...) refuses the whole configuration, as does `jwksURL` or `caFile` beside a pinned set. Keys are cached for an hour, refetched at most every 30 seconds for an unknown key ID, and a failed fetch keeps the last good set. `jwksURL` must be HTTPS; `caFile` optionally replaces the system roots for it. The broker cannot read another cluster's Pods, so a remote domain admits only a proxy binding (a shared proxy there checks the Pod), and its token lifetime (`maxTokenLifetimeSeconds`, 600 to 3600, default 3600) is the revocation window. A binding names its domain with `trustDomain`; empty is the broker's own cluster. The broker's egress must reach `jwksURL`.

## Proxy-attested agents

A binding with `proxy` trusts exactly one shared proxy: its `namespace`, `serviceAccount` and `serviceAccountUID`, in its `trustDomain`, with that domain's issuer and audience. The proxy runs the Pod check in its own cluster and sends an attestation of the agent Pod with each connection: the `Gatehouse-Attestation` header on CONNECT, or a `GHATTS1 <attestation>` line before any `GHSESS1` line on PostgreSQL.

```json
{"namespace": "gatehouse-edge", "serviceAccount": "gatehouse-edge", "serviceAccountUID": "UID", "agentID": "A", "vaultID": "V",
 "trustDomain": "agent-sandbox",
 "proxy": {"profiles": [{"namespace": "agent-sandboxes-staging", "profile": "agent-sandbox-orion-staging", "pool": "orion"},
                        {"namespace": "developers-sandboxes-staging", "profile": "agent-sandbox-developers-staging", "pool": "sandbox-developers"}],
           "ownerKind": "Sandbox", "imageDigests": ["sha256:..."], "sourceCIDRs": ["10.200.0.0/28"]}}
```

Each profile entry may add `imagePrefix`, an agent-sandbox repository or tenant path; the binding's `imageDigests` then lists only platform containers, and every pulled image (the attestation's `images`, repository and digest) must lie under the namespace's prefix or match a listed digest. The attested namespace picks the profile and pool: the proxy names the profile it maps the namespace to, and the broker refuses a namespace it does not list or a profile its own map does not give that namespace. Within one trust domain, a namespace belongs to one proxy binding. The broker admits the attested Pod only when the connection comes from `sourceCIDRs` (the private link's range), its controller is `ownerKind`, every image is listed, its deadline has not passed, and the catalog declares that profile, from the trust domain that verified the proxy's token; with no catalog profile a proxy admits nothing. The session ends at that deadline or `maxSessionSeconds` after the proxy token was issued, whichever is first (optional; it defaults to, and may not pass, the policy's top-level `maxSessionSeconds`, a day unless set, at most 30 days, which also caps every pool binding's `maxPodSeconds`), and a recheck accepts an expired proxy token for at most one token lifetime past its expiry. The scope's workload is the attested Pod UID. Any other binding presenting an attestation is refused, and the token-only path never admits a proxy binding. When the catalog declares a harness for the pool, every admission, pool or proxy, must also match it: issuer, audience, key source, identity kind, namespace, controller kind and images.

## Listeners admit identity kinds

Every scope records how the workload proved itself: `pod-token`, `token-review` or `proxy-attested`. The HTTP proxy and PostgreSQL listeners (behind TLS 14443 and 15443) admit pool and legacy identities and refuse `proxy-attested`. Agents in another cluster arrive on the cross-cluster listener instead: set `AGENT_VAULT_CROSS_CLUSTER_PORT` (14325, always on 127.0.0.1, behind TLS front 16443 in the same Pod, which must send a PROXY header), which needs the credential proxy, `AGENT_VAULT_MITM_PROXY_PROTOCOL` and, with PostgreSQL, `AGENT_VAULT_DB_PROXY_PROTOCOL`. It carries both protocols on one port: after the front's PROXY header, a stream opening with `GHATTS1 ` goes to the PostgreSQL broker and one opening with `CONNECT ` to the HTTP proxy, each admitting only `proxy-attested`. Anything else is closed within 5 seconds.

## Proxy serving certificates

The hop from an agent sandbox to its shared proxy runs inside the sandbox cluster, so the proxy serves it over TLS with a certificate the broker issues. The proxy makes an ECDSA P-256 key in memory, never on disk, and posts a certificate request to `POST /v1/proxy/certificate` on the cross-cluster listener, with its own service-account token as `Authorization: Bearer`. A stream opening with `POST /v1` there goes to this endpoint, and nothing else of the broker's API is reachable. The broker admits only a proxy binding's own current token from the binding's source ranges, and accepts a request only if every DNS name in it is one of `AGENT_VAULT_PROXY_CERT_NAMES`, with no IP, URI or email name and an ECDSA P-256 key. The only extensions a request may carry are subject alternative names, server authentication as its sole extended key usage, and key usage limited to digital signature and key agreement; anything else, such as a request to be a CA, is refused. A Vault PKI role then signs it (`<AGENT_VAULT_PROXY_PKI_MOUNT>/sign/<AGENT_VAULT_PROXY_PKI_ROLE>`), so the CA key never reaches the broker, and the response carries the certificate and its chain. Restrict the role to the same names. The broker checks what Vault returns before handing it out: the requested key, exactly the requested names, server authentication only and not a CA. Each certificate issued is a `proxy_certificate` row in the signed audit trail with its `serial`, `notAfter`, `dnsNames`, the proxy's `peer` and its binding (trust domain, namespace and service account UID), written before the response. Issuance is limited per proxy binding (`AGENT_VAULT_PROXY_CERT_PER_HOUR` and `AGENT_VAULT_PROXY_CERT_BURST`, 1,000 each by default), so a looping proxy gets 429 instead of flooding Vault PKI; the endpoint needs `AGENT_VAULT_AUDIT_CHAIN` and refuses while the trail cannot record. `AGENT_VAULT_PROXY_CERT_TTL` is 1 to 24 hours (default 24h); the proxy renews at two thirds of it. `AGENT_VAULT_PROXY_CERT_NAMES` takes any number of names. Set the mount, role and names together, or none; the endpoint also needs the cross-cluster listener, workload identity and the signed audit trail. Each issue and refusal is logged with its reason.

The same `POST /v1` streams also carry shared proxies' Sandbox activity, for the idle janitor. A proxy posts `{"sandboxes": [{namespace, ownerUID, lastSeen}]}` (at most 5,000 rows a request) to `/v1/proxy/activity` and reads the view back, 2,000 rows a page, from `/v1/proxy/activity/read`. Both admit only a proxy binding's own current token from its source ranges. A proxy writes and reads only its own binding's rows, and only for the namespaces in its binding's profiles; a time more than a minute ahead of the broker's clock is refused. Rows live in the shared store's `proxy_activity` table, keep the latest time per Sandbox, and are pruned after `AGENT_VAULT_PROXY_ACTIVITY_RETENTION` (1 hour to a year, default 24h). A binding holds at most `AGENT_VAULT_PROXY_ACTIVITY_MAX_ROWS` rows (default 100,000, ten times a 10,000-sandbox fleet); a report that would pass it is refused with 507, though updates to rows it already holds still land. The broker records when each binding's history began and, per replica stream (`replica`, an identifier the replica picks when it starts), a sequence each accepted report advances; it prunes a stream unused for twice the retention period and never prunes the history time. A binding holds at most `AGENT_VAULT_PROXY_ACTIVITY_MAX_STREAMS` streams (default 10,000 replica starts in twice the retention); a report that would start one past it is refused with 507. The read returns them as `historyStarted` and `streams`. A report carries its stream and the last sequence acknowledged on it (`ackedSeq`) and gets `{"seq", "lost", "retentionSeconds"}` back: a sequence the store no longer reaches means the store lost acknowledged writes (a database restored to an earlier point), so the history restarts and `lost` asks the replica to send everything again. This is on whenever the cross-cluster listener and workload identity are.

## Verification and remaining limits

TokenReview runs for each authorization decision, followed by a live Pod read that rejects missing pods, deletion timestamps, changed UIDs or an unexpected account. The Pod read closes TokenReview's deletion grace period. Any API error, timeout, untrusted certificate or incomplete identity denies the request. Current broker agent status and vault permission are checked after proof verification. No positive authentication result is cached.

These projected tokens are bearer credentials. Another process holding the same token can replay it while the pod is live and the proof remains valid. Account/pod binding and short lifetimes do not prove which process presented a copied token. Protect the projected file and caller-to-broker transport, then record the accepted replay limit in the deployment review.

### Runtime evidence to return

- [ ] Infra and Security select the disposable runtime, protected ingress and bypass controls, with contributor assignments accepted by those teams.
  - Complete when: configuration identifies the cluster, namespace, image revision, token issuer/audience/lifetime, destination and database bindings, and network/storage boundaries.
  - Result: Pending. Contributor and environment: __. Configuration/evidence link: __.
  - Review and next action: __.
- [ ] Run a fresh workload with no standing agent token through both entry points using real runtime-issued proof.
  - Complete when: both positive controls succeed, and wrong account/audience, expired proof, removed grant, revoked agent, deleted pod, same-name replacement with old proof, verifier outage and copied-token behavior have recorded expected/observed results. Every pre-forward denial must leave destination and credential-issuance counts unchanged.
  - Result: Not run. Contributor, revision, commands and environment: __. Evidence link: __.
  - Review and next action: __.
- [ ] Verify placement and isolation before release.
  - Complete when: direct destination/Vault access, broker secret/storage access and runtime-socket access are denied from the actual agent while both broker workflows still succeed. Reviewers accept the remaining bearer replay limit.
  - Result: Not run. Contributor, revision, commands and environment: __. Evidence link: __.
  - Review and next action: __.

If these checks pass, the selected runtime can use both entry points without a standing agent token. Support for other runtime identities and process-bound replay prevention remains outside this adapter.
