#!/usr/bin/env bash
# Disposable local verification. Requires go, vault, PostgreSQL tools, openssl.
# Run as a non-root user; never touches the user's Agent Vault home or services.
set -euo pipefail
cd "$(dirname "$0")/../.."
for tool in go vault initdb pg_ctl psql openssl; do command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }; done
[[ $(id -u) != 0 ]] || { echo "Run as a non-root user (PostgreSQL requirement)." >&2; exit 1; }
review_work=$(mktemp -d "${TMPDIR:-/tmp}/av-pg-verify.XXXXXX")
pg_port=${AV_VERIFY_PG_PORT:-55439}
vault_port=${AV_VERIFY_VAULT_PORT:-18349}
vault_pid=
cleanup() {
  [[ -z "$vault_pid" ]] || { kill "$vault_pid" 2>/dev/null || true; wait "$vault_pid" 2>/dev/null || true; }
  pg_ctl -D "$review_work/pg" -m fast -w stop >/dev/null 2>&1 || true
  rm -rf "$review_work"
}
trap cleanup EXIT
admin_pw=$(openssl rand -hex 16)
printf '%s' "$admin_pw" > "$review_work/admin-pw"
chmod 600 "$review_work/admin-pw"
initdb -D "$review_work/pg" -U review_admin --auth-local=trust --auth-host=scram-sha-256 --pwfile="$review_work/admin-pw" > "$review_work/init.log"
# Test-only network separation: agents take IPv4, broker takes IPv6. The same
# principle must be implemented with workload source CIDRs/firewall rules in production.
cat > "$review_work/pg/pg_hba.conf" <<'HBA'
local all all trust
host all +pg_read_all_data 127.0.0.1/32 reject
host all all 127.0.0.1/32 scram-sha-256
host all all ::1/128 scram-sha-256
HBA
pg_ctl -D "$review_work/pg" -l "$review_work/postgres.log" -o "-h 127.0.0.1,::1 -p $pg_port -k $review_work" -w start >/dev/null
pg() { psql -h "$review_work" -p "$pg_port" -U review_admin -v ON_ERROR_STOP=1 "$@"; }
pg -d postgres -c 'CREATE DATABASE appdb;' -c 'CREATE DATABASE brokerstore;' -c 'CREATE DATABASE appdb2;' >/dev/null
pg -d appdb -c "CREATE TABLE customers(id serial PRIMARY KEY,name text); INSERT INTO customers(name) VALUES ('Acme'),('Globex'),('Initech');" >/dev/null
# The fixture's inherited reader grant must not allow persistent object ownership.
pg -d appdb -c 'REVOKE CREATE ON SCHEMA public FROM PUBLIC;' >/dev/null
pg -d appdb2 -c 'REVOKE CREATE ON SCHEMA public FROM PUBLIC;' >/dev/null
export VAULT_ADDR="http://127.0.0.1:$vault_port" VAULT_TOKEN="$(openssl rand -hex 16)"
vault server -dev -dev-no-store-token -dev-root-token-id="$VAULT_TOKEN" -dev-listen-address="127.0.0.1:$vault_port" > "$review_work/vault.log" 2>&1 &
vault_pid=$!
ready=false
for _ in {1..50}; do
  kill -0 "$vault_pid" 2>/dev/null || { echo "Vault could not start; check port $vault_port" >&2; exit 1; }
  if vault status >/dev/null 2>&1; then ready=true; break; fi
  sleep .1
done
$ready || { echo "Vault startup timed out" >&2; exit 1; }
vault secrets enable database >/dev/null
vault write database/config/appdb plugin_name=postgresql-database-plugin allowed_roles=readonly connection_url="postgresql://{{username}}:{{password}}@127.0.0.1:$pg_port/appdb?sslmode=disable" username=review_admin password="$admin_pw" >/dev/null
vault write database/roles/readonly db_name=appdb creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE pg_read_all_data;" revocation_statements="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP ROLE IF EXISTS \"{{name}}\";" default_ttl=8s max_ttl=90s >/dev/null
vault write database/config/appdb2 plugin_name=postgresql-database-plugin allowed_roles=readonly2 connection_url="postgresql://{{username}}:{{password}}@127.0.0.1:$pg_port/appdb2?sslmode=disable" username=review_admin password="$admin_pw" >/dev/null
vault write database/roles/readonly2 db_name=appdb2 creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE pg_read_all_data;" revocation_statements="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP ROLE IF EXISTS \"{{name}}\";" default_ttl=8s max_ttl=90s >/dev/null
export AV_TEST_PG_SECOND_DB=appdb2 AV_TEST_VAULT_SECOND_ROLE=readonly2
export AV_TEST_PG_UPSTREAM="[::1]:$pg_port" AV_TEST_PG_DENIED_UPSTREAM="127.0.0.1:$pg_port" AV_TEST_PG_DB=appdb
export AV_TEST_PG_ADMIN="postgres://review_admin:$admin_pw@127.0.0.1:$pg_port/appdb?sslmode=disable"
export AV_TEST_STORE_PG_URL="postgres://review_admin:$admin_pw@127.0.0.1:$pg_port/brokerstore?sslmode=disable"
# Serial packages: generated-role baseline measurements must not overlap.
go test -p 1 -tags 'realpg realvault loadpg' ./internal/pgproxy ./internal/hashicorp ./internal/server ./internal/store -run 'RealPostgres|RealVault|TestLoadPG_' -count=1 -v -timeout 5m
