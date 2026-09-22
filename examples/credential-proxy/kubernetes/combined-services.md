# Verify workload proof with live credential services

These direct-proof fixtures exercise broker identity and service behavior. For a
sandbox without identity credentials, use the [separate task relay](../task-relay/README.md)
and complete its deployed network acceptance checks.

This disposable fixture sends actual Kubernetes pod proof through encrypted broker ingress to a TLS HTTP destination and PostgreSQL. Vault supplies the HTTP secret and temporary database credentials. The caller never receives those destination credentials.

## Run

From the repository root, install Go, Docker with Buildx, kubectl, Python 3 and ripgrep. Select an isolated local Docker daemon with at least 4 GB available memory. The fixture creates its own kind cluster and test container, refuses existing names, and removes both on exit.

```bash
bash examples/credential-proxy/kubernetes/verify-combined.sh unix:///path/to/disposable/docker.sock
```

Allow 10 minutes for image preparation and execution. If the build network requires an organizational certificate, set `AV_DEMO_CA_FILE` to its trusted PEM certificate file. Never disable TLS verification. The fixture uses the disposable Linux Docker host network to reach its loopback Kubernetes API. It mounts no host directories and publishes no Vault, HTTP or database ports.

## What must pass

- Actual projected proof admits HTTP and PostgreSQL requests through verified TLS tunnels.
- HTTP rotation takes effect on the next request. Destination counters establish successful substitution and zero forwarding for rejected proofs.
- Standing tokens and wrong-audience proof fail on both paths without issuing database credentials. Untrusted transport certificates fail; plaintext ingress cannot reach a destination.
- Revoking the broker agent denies new HTTP and PostgreSQL work and removes its existing database role and session.
- Two live PostgreSQL sessions reject mixed cancellation capabilities. Canceling one query leaves the other intact; replay after closing the first session has no effect.
- The persistent database seed regression runs against real PostgreSQL.
- With the caller still authorized, broker Vault login expiry denies new HTTP and PostgreSQL work and ends the active proxied query. Cleanup records survive closing and reopening the store; fresh Vault authentication and recreated brokers restore the same caller's access. This is broker lifecycle recovery with local clients, not an executable process restart or the separate caller-pod fixture.

Any missing prerequisite or failed assertion fails the run. Record the source revision, command, sanitized output, reviewer decision and remaining deployment work in the release review.

## Verify a separate caller pod and enforced routes

The additional fixture needs curl and a disposable Docker daemon with 6 GB memory. It uses Kubernetes 1.36.4 with Calico 3.32.2, following the [official kind setup](https://docs.tigera.io/calico/latest/getting-started/kubernetes/kind) and [supported Kubernetes versions](https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements). The runner verifies the pinned manifest checksum and preloads its versioned images through the trusted host daemon. It never disables certificate checks to pull images.

```bash
bash examples/credential-proxy/kubernetes/verify-inpod.sh unix:///path/to/disposable/docker.sock
```

The caller reads proof from its own projected volume and completes both broker workflows over TLS. Before applying network policies, it must reach disposable direct HTTP, Vault and PostgreSQL ports. After default-deny and explicit broker allowances are applied, those same routes must fail using both pod and service addresses while permitted broker workflows still succeed. This prevents a missing service or broken DNS from masquerading as isolation.

The broker fixture also hosts its destination services. This test does not establish independently deployed destination policy, broker storage protection or TRM deployment acceptance. Its Go TLS forwarding fixture does not validate production stunnel configuration. The runner removes its cluster on success or failure.

## Evidence boundary

The first fixture reads pod proof into local test clients and uses default kind networking without network-policy enforcement. The separate-caller fixture adds observed route denial with Calico. Both use Go TLS fixtures, not deployed stunnel configuration or native PostgreSQL encrypted ingress. Vault and database connections use isolated local plaintext routes. Neither proves TRM storage isolation, rollback or production readiness. Verify those controls from the actual deployed agent environment. Copied valid bearer proof remains replayable until withdrawal or expiry.
