#!/usr/bin/env bash
# Disposable fixture runner. The container supplies real Vault and PostgreSQL.
set -euo pipefail
cd "$(dirname "$0")/../.."
printf '\nHTTP: request-time rotation, deletion, authorization and strict forwarding\n'
bash examples/credential-proxy/verify-required.sh
printf '\nPostgreSQL: permissions, lifecycle and durable cleanup\n'
bash examples/postgres-broker/verify.sh
printf '\nPASS: local HTTP and PostgreSQL fixtures.\n'
printf 'Deployment acceptance still requires the actual runtime identity, encrypted ingress and bypass checks.\n'
