#!/usr/bin/env bash
# Reproducible developer smoke test: Docker is the only host dependency.
set -euo pipefail
cd "$(dirname "$0")/../.."
command -v docker >/dev/null || { echo 'Install/start Docker, then rerun this script.' >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo 'Docker is not running.' >&2; exit 1; }
# Names are unique so simultaneous runs never stop one another's resources.
image="agent-vault-pg-demo:run-$(date +%s)-$$"
container="agent-vault-pg-demo-$(date +%s)-$$"
cleanup() {
  local status=$?
  docker rm -f -v "$container" >/dev/null 2>&1 || true
  docker image rm "$image" >/dev/null 2>&1 || true
  return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
build_options=(-f examples/postgres-broker/Dockerfile -t "$image")
if [[ -n "${SSL_CERT_FILE:-}" ]]; then
  [[ -r "$SSL_CERT_FILE" ]] || { echo 'SSL_CERT_FILE is not readable.' >&2; exit 1; }
  build_options+=(--secret "id=demo_ca,src=$SSL_CERT_FILE")
fi
docker build "${build_options[@]}" .
# All services communicate over container-local loopback. No host configuration,
# ports, or credentials are mounted; the running demo has no external network.
docker run --rm --name "$container" --network none "$image"
