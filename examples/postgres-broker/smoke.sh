#!/usr/bin/env bash
# Runs only inside the disposable demo image; never point this at production.
set -euo pipefail
umask 077
work=$(mktemp -d /tmp/av-demo.XXXXXX)
server_pid= vault_pid=
cleanup() {
  set +e
  [[ -z "$server_pid" ]] || { kill "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null; }
  [[ -z "$vault_pid" ]] || { kill "$vault_pid" 2>/dev/null; wait "$vault_pid" 2>/dev/null; }
  pg_ctl -D "$work/pg" -m fast -w stop >/dev/null 2>&1
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
pg() { psql -X -h "$work" -p 55439 -U demo_admin -v ON_ERROR_STOP=1 "$@"; }
q() { PGPASSWORD="$AGENT_VAULT_TOKEN" psql -X "host=127.0.0.1 port=14423 dbname=$1 user=agent sslmode=disable" -At -v ON_ERROR_STOP=1 -c "$2"; }
add() { agent-vault vault database add --vault demo --name "$1" --upstream 127.0.0.1:55439 --database "$2" --mount database --role "$3" --sslmode disable; }
wait_ready() {
  local pid=$1 kind=$2
  for ((i=0;i<100;i++)); do
    kill -0 "$pid" 2>/dev/null || { echo "$kind failed to start (private logs withheld)."; exit 1; }
    if [[ "$kind" == Vault ]]; then
      vault status >/dev/null 2>&1 && return
    else
      grep -q 'postgres broker listening' "$work/server.log" && return
    fi
    sleep .2
  done
  echo "$kind startup timed out."; exit 1
}
echo 'Preparing PostgreSQL, HashiCorp Vault, and Agent Vault. No host ports or credentials are exposed.'
admin_pw=$(openssl rand -hex 24)
printf '%s' "$admin_pw" > "$work/admin-pw"
initdb -D "$work/pg" -U demo_admin --auth-local=trust --auth-host=scram-sha-256 --pwfile="$work/admin-pw" > "$work/init.log"
pg_ctl -D "$work/pg" -l "$work/postgres.log" -o "-h 127.0.0.1 -p 55439 -k $work" -w start >/dev/null
for db in analytics_db transactions_db reporting_db; do
  pg -d postgres -c "CREATE DATABASE $db" >/dev/null
  pg -d "$db" -c "CREATE TABLE demo_records(id int,label text); INSERT INTO demo_records VALUES (1,'synthetic record A'),(2,'synthetic record B');" >/dev/null
done
export VAULT_ADDR=http://127.0.0.1:18349 VAULT_TOKEN="$(openssl rand -hex 24)"
vault server -dev -dev-no-store-token -dev-root-token-id="$VAULT_TOKEN" -dev-listen-address=127.0.0.1:18349 > "$work/vault.log" 2>&1 &
vault_pid=$!
wait_ready "$vault_pid" Vault
vault secrets enable database >/dev/null
for binding in 'analytics_db analytics_ro' 'transactions_db transactions_ro' 'reporting_db reporting_ro'; do
  read -r db role <<< "$binding"
  # Explicit per-database grants rather than cluster-wide pg_read_all_data.
  pg -d "$db" -c "REVOKE CREATE ON SCHEMA public FROM PUBLIC; CREATE ROLE ${role}_grants NOLOGIN; GRANT CONNECT ON DATABASE $db TO ${role}_grants; GRANT USAGE ON SCHEMA public TO ${role}_grants; GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${role}_grants;" >/dev/null
  vault write "database/config/$db" plugin_name=postgresql-database-plugin allowed_roles="$role" connection_url="postgresql://{{username}}:{{password}}@127.0.0.1:55439/$db?sslmode=disable" username=demo_admin password="$admin_pw" >/dev/null
  vault write "database/roles/$role" db_name="$db" creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE ${role}_grants;" revocation_statements="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP ROLE IF EXISTS \"{{name}}\";" default_ttl=30s max_ttl=5m >/dev/null
done
export AGENT_VAULT_MASTER_PASSWORD="$(openssl rand -hex 24)" AGENT_VAULT_ALLOW_PRIVATE_RANGES=true AGENT_VAULT_TELEMETRY=false AGENT_VAULT_ADDR=http://127.0.0.1:14421 AGENT_VAULT_DB_BROKER=true
agent-vault server --port 14421 --mitm-port 0 --postgres-port 14423 > "$work/server.log" 2>&1 &
server_pid=$!
wait_ready "$server_pid" Broker
owner_pw=$(openssl rand -hex 24)
printf '%s\n' "$owner_pw" | agent-vault auth register --address "$AGENT_VAULT_ADDR" --email owner@demo.test --password-stdin >/dev/null
printf '%s\n' "$owner_pw" | agent-vault auth login --address "$AGENT_VAULT_ADDR" --email owner@demo.test --password-stdin >/dev/null
agent-vault vault create demo >/dev/null

echo '[1/5] Owner registers analytics; creates an agent with a proxy grant.'
add analytics analytics_db analytics_ro
AGENT_VAULT_TOKEN=$(agent-vault agent create demo-agent --vault demo:proxy --token-only)
export AGENT_VAULT_TOKEN

echo '[2/5] Same agent identity, two connections, two temporary PostgreSQL users.'
u1=$(q analytics 'SELECT current_user')
u2=$(q analytics 'SELECT current_user')
[[ "$u1" == v-* && "$u2" == v-* && "$u1" != "$u2" ]]
printf 'Connection 1: %s\nConnection 2: %s\n' "$u1" "$u2"
[[ $(q analytics 'SELECT count(*) FROM demo_records') == 2 ]]
if q analytics "BEGIN; UPDATE demo_records SET label='changed' WHERE id=1; ROLLBACK;" > "$work/denied" 2>&1; then
  echo 'FAIL: read-only role allowed an update'; exit 1
fi
grep -q 'permission denied for table demo_records' "$work/denied"
[[ $(q analytics 'SELECT label FROM demo_records WHERE id=1') == 'synthetic record A' ]]
echo 'PASS: reads succeed; writes are denied and the record is unchanged.'

echo '[3/5] Add two databases live; select each over the same broker port.'
if q reporting 'SELECT 1' > "$work/missing" 2>&1; then echo 'FAIL: unknown service accepted'; exit 1; fi
add transactions transactions_db transactions_ro
add reporting reporting_db reporting_ro
agent-vault vault database list --vault demo
for name in analytics transactions reporting; do
  [[ $(q "$name" 'SELECT current_database()') == "${name}_db" ]]
  [[ $(q "$name" 'SELECT count(*) FROM demo_records') == 2 ]]
done
agent-vault vault database remove reporting --vault demo --yes
if q reporting 'SELECT 1' > "$work/removed" 2>&1; then echo 'FAIL: removed service accepted'; exit 1; fi
[[ $(q transactions 'SELECT count(*) FROM demo_records') == 2 ]]
echo 'PASS: exact routing, live onboarding and removal; other services still work.'

echo '[4/5] Revoke the agent and reject its next connection.'
agent-vault agent revoke demo-agent
if q analytics 'SELECT 1' > "$work/revoked" 2>&1; then echo 'FAIL: revoked agent accepted'; exit 1; fi

echo '[5/5] Inspect PostgreSQL for leftover generated roles and sessions.'
for ((i=0;i<100;i++)); do
  roles=$(pg -d postgres -Atc "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'v-%'")
  sessions=$(pg -d postgres -Atc "SELECT count(*) FROM pg_stat_activity WHERE usename LIKE 'v-%'")
  [[ "$roles" == 0 && "$sessions" == 0 ]] && break
  sleep .2
done
[[ "$roles" == 0 && "$sessions" == 0 ]]
printf 'Generated roles remaining: %s; agent sessions remaining: %s\n' "$roles" "$sessions"
echo 'PASS: real CLI → identity resolver → broker → Vault → PostgreSQL lifecycle.'
