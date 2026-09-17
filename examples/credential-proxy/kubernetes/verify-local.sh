#!/usr/bin/env bash
# Disposable identity acceptance only, not deployment or network-policy proof.
set -euo pipefail

docker_host=${1:?Usage: verify-local.sh unix:///path/to/disposable/docker.sock}
case "$docker_host" in
  unix://*) ;;
  *) echo 'Use an explicit local disposable Docker socket.' >&2; exit 1 ;;
esac
for tool in go docker kubectl rg; do
  command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 1; }
done
root=$(cd "$(dirname "$0")/../../.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/credential-proxy-identity.XXXXXX")
chmod 700 "$scratch"
export DOCKER_HOST="$docker_host"
export KUBECONFIG="$scratch/kubeconfig"
cluster=credential-proxy-identity
mkdir "$scratch/bin"
GOBIN="$scratch/bin" go install sigs.k8s.io/kind@v0.33.0
kind="$scratch/bin/kind"
if "$kind" get clusters | rg -qx "$cluster"; then
  echo 'The disposable cluster name already exists; leave it intact and use the documented direct test command.' >&2
  rm -rf "$scratch"
  exit 1
fi
cleanup() {
  "$kind" delete cluster --name "$cluster" >/dev/null 2>&1 || true
  docker image rm credential-proxy-identity-fixture:local >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT
"$kind" create cluster --name "$cluster" --kubeconfig "$KUBECONFIG" \
  --image kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5 --wait 180s

# Preload through the trusted host Docker daemon. This also works when the
# disposable node lacks an organization's registry-proxy CA. Do not skip TLS.
image=busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0
docker pull "$image"
architecture=$(docker info --format '{{.Architecture}}')
case "$architecture" in
  aarch64|arm64) platform=linux/arm64 ;;
  x86_64|amd64) platform=linux/amd64 ;;
  *) echo 'The fixture requires an ARM64 or AMD64 Docker daemon.' >&2; exit 1 ;;
esac
docker tag "$image" credential-proxy-identity-fixture:local
docker image save credential-proxy-identity-fixture:local | docker exec -i "$cluster-control-plane" \
  ctr --namespace=k8s.io images import --platform "$platform" --digests -
docker exec "$cluster-control-plane" ctr --namespace=k8s.io images tag \
  docker.io/library/credential-proxy-identity-fixture:local \
  docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0
cd "$root"
go test -race -tags realkubernetes ./internal/workloadidentity \
  -run '^TestRealKubernetesProjectedIdentity$' -count=1 -v -timeout 15m \
  -args -workload-kubeconfig "$KUBECONFIG"
