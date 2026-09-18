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
