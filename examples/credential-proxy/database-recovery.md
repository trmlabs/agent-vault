# Recover an interrupted database credential request

The broker keeps a database binding closed when it cannot prove that an interrupted request was cleaned up. Known leases are revoked synchronously and retried. If the credential response was lost, the broker reopens the binding by itself only when Vault shows that no credential from the request remains (see [automatic reconciliation](#automatic-reconciliation)). Otherwise an instance owner must identify the affected database role, verify its removal and record that evidence before reopening the binding.

This procedure is for the single-broker deployment. It does not establish production readiness or support multiple broker replicas. Never clear a record because its expected lifetime elapsed or because token revocation returned success.

## Automatic reconciliation

A graceful stop does not create an unknown issuance: on SIGTERM the broker starts no new credential request, and one already under way finishes and journals its lease, bounded by the 15 s issuance limit and the shutdown budget. A request whose caller left meanwhile has its credential revoked at once. What remains is a broker killed mid-request (out of memory, node loss, a grace period exceeded) or a Vault reply lost in transit.

For those, each record keeps the Vault mount and role it read from, and the database-clock time its child token expires. A replica that holds the record clears it, with no operator, only when both hold:

1. The child token has been dead for 3 minutes by the database clock: revoked by the token itself in the process that held it, or past its maximum lifetime. No request made with the token can still register a lease, because Vault's default `max_request_duration` is 90 s. A Vault with a longer limit needs a longer `UnknownSettle`.
2. A list of Vault's leases under `<mount>/creds/<role>/`, read after that, contains no lease that the broker fleet's journal does not account for.

Vault returns a credential only after registering its lease, and deletes a lease only after the database engine has removed its user. A lease whose revocation is pending or failing, including one Vault marked irrevocable, stays listed. So a credential from the lost request that still exists would appear as an unaccounted lease. This is why the warnings below still hold for operators: token revocation success means only that Vault queued the lease revocations, and an elapsed lifetime means only that the token can do no more. Neither clears a record here; they only decide when the list is worth reading. The list is the evidence.

The broker leaves the record for this procedure, and logs why, when the list is refused or not recognizably Vault's, when any lease under the role is unaccounted (another Vault client's lease on a shared role counts), or when the record predates this behavior and names no mount or role. It never inspects the database itself, so a database role that Vault created and then failed to register a lease for, whose password Vault never returned to anyone, is outside what it can see. The cleared record keeps `"verification": "automated_vault_lease_absence"` and the time of the check as its evidence.

## Identify the exact request

Proposed contributors: the broker operator and a database administrator. Record who accepted the work, the environment, incident reference and reviewer in the incident record. Use a protected owner session for the management API, an approved Vault operator identity for audit lookup and a database administrator connection. Keep credentials out of commands copied into tickets or logs.

1. List recovery records using the authenticated management API:

   ```sh
   curl --fail --silent --show-error \
     --header "Authorization: Bearer $AGENT_VAULT_OWNER_SESSION" \
     "$AGENT_VAULT_ADDR/v1/database-cleanup"
   ```

   Select one record with `operator_reconciliation_required: true`. Set `pending_accessor` to its accessor and `pending_binding` to its binding, which is `<vault ID>/<service name>`. Pause the affected workflow. Map the vault ID to its name, preserve the configuration and remove only that binding:

   ```sh
   binding_vault_id=${pending_binding%%/*}
   binding_service=${pending_binding#*/}
   vault_name=$(curl --fail --silent --show-error \
     --header "Authorization: Bearer $AGENT_VAULT_OWNER_SESSION" \
     "$AGENT_VAULT_ADDR/v1/vaults" |
     jq -er --arg id "$binding_vault_id" '.vaults[] | select(.id == $id) | .name')
   vault_component=$(jq -rn --arg name "$vault_name" '$name | @uri')
   service_component=$(jq -rn --arg name "$binding_service" '$name | @uri')
   binding_url="$AGENT_VAULT_ADDR/v1/vaults/$vault_component/databases/$service_component"
   binding_backup=$(mktemp "${TMPDIR:-/tmp}/agent-vault-binding.XXXXXX")
   curl --fail --silent --show-error \
     --header "Authorization: Bearer $AGENT_VAULT_OWNER_SESSION" "$binding_url" |
     jq -e '.database | {name,upstream,database,mount,role,sslmode,max_conns}' > "$binding_backup"
   curl --fail --silent --show-error --request DELETE \
     --header "Authorization: Bearer $AGENT_VAULT_OWNER_SESSION" "$binding_url"
   ```

   Stop if any command fails. Review the saved configuration before proceeding. Keep the broker and management API running: confirmation requires the active cleanup owner and serializes with any unfinished issuance. If restarting after a crash, allow the previous 30-second owner claim to expire; do not delete its ownership record.

2. Revoke the child token by its exact accessor. This denies future credential issuance but does **not** prove that database cleanup completed:

   ```sh
   vault token revoke -accessor "$pending_accessor"
   ```

3. Find the credential response for that accessor in the approved Vault audit source. Audit values may be hashed. For a file audit device, obtain the matching accessor hash without printing a token:

   ```sh
   accessor_hash=$(vault write -field=hash "sys/audit-hash/$VAULT_AUDIT_DEVICE" input="$pending_accessor")
   jq --arg accessor "$accessor_hash" '
     select(.type == "response" and .auth.accessor == $accessor)
     | select(.response.data.username != null)
     | {request_id: .request.id, path: .request.path,
        username: .response.data.username, lease_id: .response.secret.lease_id}
   ' "$VAULT_AUDIT_LOG"
   ```

   Use the actual audit device and approved log source. If that device records the accessor without hashing, match its exact value instead. Do not print the full credential response. If the response is missing or ambiguous, keep the record unresolved and investigate the corresponding request and database logs. Absence of an audit response does not prove absence of a role.

4. Match the returned username to the exact database role. If the username is hashed, calculate candidate hashes with the same audit device and compare them to the response. Set `issued_role` only after an exact match. For example, given `audited_username_hash` from step 3:

   ```sh
   while IFS= read -r candidate; do
     candidate_hash=$(vault write -field=hash "sys/audit-hash/$VAULT_AUDIT_DEVICE" input="$candidate")
     if [ "$candidate_hash" = "$audited_username_hash" ]; then
       printf '%s\n' "$candidate"
     fi
   done < <(psql "$RECOVERY_DB_ADMIN_DSN" -Atc 'SELECT rolname FROM pg_roles')
   ```

   This is a read-only comparison. Do not delete roles by prefix, shared Vault role, creation time or similarity of names. If the role is already absent, use the audit record plus a recorded earlier exact mapping to establish its name; do not guess from an unmatched hash.

**Result to record:** accepted operator and administrator, binding, accessor, audit request reference, exact role mapping and any unresolved evidence. Keep passwords and tokens out of the record.

## Remove only the affected role and sessions

If the audit response identifies the exact lease, first retry ordinary synchronous revocation:

```sh
vault write "sys/leases/revoke/$issued_lease_id" sync=true
```

If database dependencies prevent removal, inspect them with the database administrator. After resolving those dependencies, retry normal revocation. Do not use force-revoke or drop unrelated objects to make the check pass.

For an identified orphan whose lease cannot be recovered, the administrator can terminate its sessions and remove only that role:

```sh
psql "$RECOVERY_DB_ADMIN_DSN" -v ON_ERROR_STOP=1 -v role="$issued_role" <<'SQL'
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity WHERE usename = :'role';
DROP ROLE IF EXISTS :"role";
SELECT count(*) AS remaining_roles FROM pg_roles WHERE rolname = :'role';
SELECT count(*) AS remaining_sessions FROM pg_stat_activity WHERE usename = :'role';
SQL
```

Both counts must be zero. Repeat the observation after token revocation, and verify that a separate authorized workflow still works. A role with unresolved dependencies keeps the binding closed. Record the database environment, exact role, commands, counts, observation time, unrelated-workflow result and reviewer in the incident evidence.

## Record the operator assertion

The owner submits the durable evidence reference only after the database administrator verifies removal. This action records a manual assertion; the management API does not query the database itself.

```sh
jq -n --arg evidence "$RECOVERY_EVIDENCE_URL" \
  '{evidence_reference: $evidence, confirmed_no_database_roles_or_sessions: true}' |
  curl --fail --silent --show-error \
    --request POST --header 'Content-Type: application/json' \
    --header "Authorization: Bearer $AGENT_VAULT_OWNER_SESSION" \
    --data-binary @- \
    "$AGENT_VAULT_ADDR/v1/database-cleanup/$pending_accessor/confirm"
```

Expected response: `manual_assertion_recorded: true` and `automated_verification: false`. The journal retains the owner, time and evidence reference. Confirmation fails if issuance completed with a known lease, the cleanup owner lost authority, or no active minter is attached. Re-list pending records and verify that only this accessor was cleared. Restore the reviewed configuration:

```sh
curl --fail --silent --show-error --request POST \
  --header 'Content-Type: application/json' \
  --header "Authorization: Bearer $AGENT_VAULT_OWNER_SESSION" \
  --data-binary "@$binding_backup" \
  "$AGENT_VAULT_ADDR/v1/vaults/$vault_component/databases"
```

Resume one authorized workflow and confirm success plus unauthorized denial. Remove the temporary backup after the reviewed configuration and recovery evidence are recorded.

**Completion record:** operator / reviewer: __. Evidence reference and expected versus observed counts: __. Other workflow result: __. Remaining correction or next action: __.

If these checks succeed, this binding can admit work again. Missing audit correlation, residual roles or sessions, and failed removal remain unresolved recovery work.

## Vault permissions and bounded lifetime

The broker creates non-renewable child service tokens with a one-hour maximum lifetime. It stores their accessors, never the child tokens or database passwords. Each child has one pre-provisioned policy named `agent-vault-db-` plus the full lowercase SHA-256 of `<mount>/creds/<role>`. That policy grants `read` on that exact credential path and `update` on `auth/token/revoke-self`, so a session the broker still holds ends itself with its own token.

The parent needs those child policies, `update` on `auth/token/create`, and lease renewal/lookup. It does not need `auth/token/revoke-accessor`, which no policy can limit to the broker's own tokens: a survivor revokes a dead replica's credentials by path, and that replica's child tokens, whose values only its process held, expire within their hour, taking any credential they issued with them. Scope synchronous revocation to `sys/leases/revoke/<mount>/creds/<role>/*`. Restrict generic lease lookup and renewal to the selected lease prefixes with Vault policy parameter constraints. Automatic reconciliation needs `list` and `sudo` on `sys/leases/lookup/<mount>/creds/<role>/` for the broker's own roles (Vault requires `sudo` to list leases; on that path it grants nothing else); without it an unknown issuance waits for this procedure. Grant it only for roles no other Vault client uses: a shared role's list always holds other clients' leases, so it never clears, and the list would show the broker lease IDs it could then revoke. The broker does not need force-revoke, policy editing or token-accessor listing. Operator audit lookup and database-administration permissions are separate from the broker's permissions.

The broker's own JWT login needs `read` on `auth/token/lookup-self` and `update` on `auth/token/renew-self`, and a fixed maximum lifetime (`token_explicit_max_ttl`). `update` on `auth/token/revoke-self` is optional. With it, an older login ends as soon as its last session ends. Without it, Vault answers 403, and the broker releases that login and lets it expire at its maximum lifetime instead of retrying. Older logins have no count ceiling: one is held only while a session it created is live, and never past its maximum lifetime. A login is made at each 20-minute refresh. A refused session policy can add one more login, at most once a minute and once per distinct missing policy per refresh, since a policy that a fresh login also lacks waits for the next refresh. So the logins held are at most the lifetime over the refresh interval, times one plus the number of distinct missing policies: three for a one-hour lifetime with none missing, six with one.

Vault queues dynamic-credential cleanup when a token is revoked. The explicit lease API supports `sync=true`; token success alone is not database confirmation. See [Vault lease API](https://developer.hashicorp.com/vault/api-docs/system/leases) and [Vault 1.19.4 token cleanup implementation](https://github.com/hashicorp/vault/blob/v1.19.4/vault/expiration.go).
