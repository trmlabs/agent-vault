# Credential proxy verification

Run an approved HTTPS request and PostgreSQL query without putting their
credentials in the agent. The broker verifies the agent's workload identity,
reads or issues credentials through Vault, and refuses requests it cannot
safely authorize or record.

This directory supplies local verification and a proposed deployment profile.
It does not establish that a TRM production deployment has passed acceptance.

## Run the local demonstration

From the root of this checkout, with Docker running:

```sh
docker build -f examples/credential-proxy/Dockerfile -t credential-proxy-verification .
docker run --rm --network none credential-proxy-verification
```

The image includes pinned Vault and PostgreSQL versions, builds tests from this
checkout and runs without host directories, published ports or real secrets.
It checks HTTP authorization, request-time secret rotation/deletion, strict
forwarding, audit failures, and PostgreSQL permissions and cleanup. A nonzero
exit is a failed demonstration, including a failed prerequisite.

For the actual Kubernetes token issuer, follow [the identity fixture](kubernetes/README.md).
That separate test exercises projected tokens, pod deletion, renewal and expiry.
It does not prove production network isolation. Unit fixtures using a synthetic
identity verifier or destination are labeled in their source.

## Supported release profile

Set `AGENT_VAULT_CREDENTIAL_PROXY=true` and
`AGENT_VAULT_WORKLOAD_IDENTITY_FILE` to the reviewed configuration. The server
rejects invalid mode values, a missing verifier, failed Vault initialization,
an unavailable proxy listener and disabled TLS verification. Listeners must be
loopback addresses; remote clients require a verified TLS transport terminating
inside the trusted broker pod.

The initial HTTP workflow is HTTPS GET or HEAD with no query or body. Put a
configured `__vault_KEY__` placeholder in `Authorization` or `X-Api-Key`.
Configure an exact destination, a passthrough service authentication strategy,
and a header substitution mapping that marker to a field of the authorized
Vault path. All configured markers must appear in allowed headers. Other
formats are rejected, not passed through. This is not general browser or API
coverage.

Vault-backed destination values are fetched once for each admitted request.
There is no local-value fallback or periodic synchronization in this profile.
Existing synchronized rows are cleared before startup, but that does not erase
old files or backups. Use a fresh store for first deployment and rotate any
previously persisted destination secrets.

Audit attempts are committed before forwarding. Failure to store the attempt
prevents forwarding. An interrupted or unrecordable outcome remains unknown;
the proxy does not replay it. Responses are limited to 1 MiB before any body is returned and checked for
direct and common encoded secret echoes. Approved upstreams must still be trusted with
their credential: arbitrary malicious transformations cannot be recognized
universally. Strict mode admits at most 128 pending or open CONNECT tunnels;
saturation returns 429, or 503 if its denial cannot be durably recorded.

PostgreSQL uses a separate temporary database credential per connection,
continues checking authorization, and journals cleanup before issuing a
credential. Cleanup uncertainty refuses new access to the affected binding.
Follow [database recovery](database-recovery.md) before clearing a quarantine.

## Deployment requirements

- Run one broker with persistent state, no overlapping active replacement, and
  monitoring for disk pressure, unknown audit outcomes and pending cleanup.
- Keep agent containers in separate pods. Never share broker memory, volumes,
  Vault authorization or administrative access with agent code.
- Expose only encrypted proxy entry points. PostgreSQL's loopback protocol needs
  a compatible client/server tunnel; an ordinary public HTTP ingress does not
  solve this. Verify certificates and server names on every remote leg.
- Restrict agent egress to approved DNS and proxy paths. Prove direct database,
  Vault, metadata and alternate-address access fails from the real agent.
- Grant the broker only the Vault paths and database roles it needs, plus the
  lifecycle permissions documented by the recovery fixture. Never use its
  disposable development root token in deployment.
- Use the actual caller's identity. A Daytona sandbox inside a shared runner
  is not a separate Kubernetes pod. It needs its own trusted session integration.
- Start with a staging opt-in and deliberately promote the tested image.
  Rollback disables access if the replacement cannot preserve these controls.

## Record acceptance

Record results in the shared implementation document beside each requirement.
Include revision, environment, exact command, expected/observed result, and a
private test-run or review link. Local fixtures do not close deployed routing,
managed-database behavior or production operational checks.

When the required deployed checks pass, the approved workload can perform its
HTTP and PostgreSQL tasks without receiving destination credentials, and access
ends when its identity or permission is withdrawn.
