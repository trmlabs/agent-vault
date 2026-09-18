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

For real proof with live Vault and PostgreSQL, including a separate caller pod
and enforced network policies, follow the [combined service fixtures](kubernetes/combined-services.md).
These disposable tests establish the exercised paths; deployed storage,
rollback and managed destinations still require acceptance.

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
Vault path. All configured markers must appear in allowed headers. For HTTP
Basic authentication, send the placeholder as the username with an empty
password, for example `curl --user "__vault_API_KEY__:"`. The proxy substitutes
the request-time value and encodes the Basic header. The secret must not contain
a colon. Keep the service configured as passthrough plus header substitution;
the legacy `basic` service authentication strategy is not this profile. Other
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
HTTP and PostgreSQL tasks without receiving destination credentials. Withdrawal
denies new HTTP requests and ends database sessions; stopping an HTTP request
already in progress remains outside this release.

### Database bootstrap and removals

Workload bindings require the stable agent ID, not its display name. After
creating the agent, an authenticated instance owner can read `id` from
`GET /v1/agents/{name}` through the protected management connection. This read
does not return an agent token. Keep caller admission disabled until the agent,
vault grant and reviewed workload binding exist; never give the caller an owner
session or a standing agent token.

Verify that sequence against the actual executable with Python 3, Go, OpenSSL and an
explicitly selected disposable Docker daemon:

```sh
python3 examples/credential-proxy/verify-bootstrap.py --docker-host unix:///path/to/disposable/docker.sock
```

This check creates a fresh store and disposable Vault, then observes a short
Vault login expire and a controlled restart obtain a fresh login. The current
broker does not renew that login automatically. No caller is admitted in this
check. The default real-service demo separately checks HTTP denial, failed new
database credential issuance, active database cleanup and recovery with fresh
clients after parent authorization expires. Its caller identity is synthetic
and its database connections are direct. Verify the selected deployment's
expiry timing and restart procedure before activation.

Startup database entries are applied once per vault and name. Seed history and binding deletion are committed durably, so restarting with unchanged configuration does not restore a removed binding. Explicit CLI/API additions can restore access intentionally. New names in bootstrap configuration can still be created; runtime edits are preserved.

Before upgrading a store created without seed history, remove previously deleted bindings from startup configuration. The migration cannot infer old deletions from absent rows. Keep the broker disabled until that configuration is reviewed.
