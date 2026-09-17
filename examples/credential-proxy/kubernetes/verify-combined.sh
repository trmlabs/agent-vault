#!/usr/bin/env bash
# Actual pod proof with live services and verified loopback TLS transport.
set -euo pipefail
docker_host=${1:?Usage: verify-combined.sh unix:///path/to/disposable/docker.sock}
case "$docker_host" in unix://*) ;; *) echo 'Use an explicit disposable local Docker socket.' >&2; exit 1 ;; esac
for tool in go docker kubectl python3 rg; do command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 1; }; done
export DOCKER_HOST="$docker_host"
docker buildx version >/dev/null || { echo 'Docker Buildx is required for the fixture image.' >&2; exit 1; }
root=$(cd "$(dirname "$0")/../../.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/credential-proxy-combined.XXXXXX")
chmod 700 "$scratch"
export KUBECONFIG="$scratch/kubeconfig"
cluster=credential-proxy-combined
container=credential-proxy-combined-services
mkdir "$scratch/bin" "$scratch/proof"
chmod 700 "$scratch/proof"
GOBIN="$scratch/bin" go install sigs.k8s.io/kind@v0.33.0
kind="$scratch/bin/kind"
if "$kind" get clusters | rg -qx "$cluster" || docker container inspect "$container" >/dev/null 2>&1; then
  echo 'Disposable fixture name already exists; leave it intact and use a fresh daemon.' >&2
  rm -rf "$scratch"
  exit 1
fi
cleanup() {
  local result=$?
  docker rm -f "$container" >/dev/null 2>&1 || true
  "$kind" delete cluster --name "$cluster" >/dev/null 2>&1 || true
  rm -rf "$scratch"
  trap - EXIT
  exit "$result"
}
trap cleanup EXIT
if [[ -n ${AV_DEMO_CA_FILE:-} ]]; then
  docker build --secret "id=demo_ca,src=$AV_DEMO_CA_FILE" -f "$root/examples/credential-proxy/Dockerfile" -t credential-proxy-combined:local "$root"
else
  docker build -f "$root/examples/credential-proxy/Dockerfile" -t credential-proxy-combined:local "$root"
fi
"$kind" create cluster --name "$cluster" --image kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5 --wait 180s
image=busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0
docker pull "$image"
case "$(docker info --format '{{.Architecture}}')" in aarch64|arm64) platform=linux/arm64 ;; x86_64|amd64) platform=linux/amd64 ;; *) echo 'ARM64 or AMD64 Docker required.' >&2; exit 1 ;; esac
docker tag "$image" credential-proxy-combined-agent:local
docker image save credential-proxy-combined-agent:local | docker exec -i "$cluster-control-plane" ctr --namespace=k8s.io images import --platform "$platform" --digests -
docker exec "$cluster-control-plane" ctr --namespace=k8s.io images tag docker.io/library/credential-proxy-combined-agent:local "docker.io/library/busybox@${image#*@}"
kubectl create namespace combined
for account in agent reviewer; do kubectl -n combined create serviceaccount "$account"; done
kubectl create clusterrole combined-review --verb=create --resource=tokenreviews.authentication.k8s.io
kubectl create clusterrolebinding combined-review --clusterrole=combined-review --serviceaccount=combined:reviewer
kubectl -n combined create role pod-check --verb=get --resource=pods
kubectl -n combined create rolebinding pod-check --role=pod-check --serviceaccount=combined:reviewer
cat > "$scratch/pod.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: agent
  namespace: combined
spec:
  serviceAccountName: agent
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: agent
      image: busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0
      command: [sleep, '1200']
      resources:
        requests: {cpu: 10m, memory: 16Mi}
        limits: {cpu: 100m, memory: 32Mi}
      volumeMounts:
        - {name: proof, mountPath: /proof, readOnly: true}
  volumes:
    - name: proof
      projected:
        sources:
          - serviceAccountToken: {path: allowed, audience: credential-proxy, expirationSeconds: 600}
          - serviceAccountToken: {path: wrong, audience: wrong-audience, expirationSeconds: 600}
YAML
kubectl apply -f "$scratch/pod.yaml"
kubectl -n combined wait --for=condition=Ready pod/agent --timeout=90s
umask 077
kubectl -n combined exec agent -- cat /proof/allowed > "$scratch/proof/allowed"
kubectl -n combined exec agent -- cat /proof/wrong > "$scratch/proof/wrong"
kubectl -n combined create token reviewer --duration=15m > "$scratch/proof/reviewer"
kubectl config view --raw --minify -o json > "$scratch/kube.json"
kubectl get --raw /.well-known/openid-configuration > "$scratch/discovery.json"
kubectl -n combined get serviceaccount agent -o json > "$scratch/account.json"
python3 - "$scratch" <<'PY'
import base64,json,pathlib,sys,urllib.parse
p=pathlib.Path(sys.argv[1]); cluster=json.loads((p/'kube.json').read_text())['clusters'][0]['cluster']
u=urllib.parse.urlparse(cluster['server'])
if u.scheme!='https' or u.hostname not in ('127.0.0.1','localhost'): raise SystemExit('Fixture API must use verified loopback HTTPS')
(p/'proof/ca').write_bytes(base64.b64decode(cluster['certificate-authority-data']))
config={'apiServer':cluster['server'],'caFile':'/tmp/combined-proof/ca','reviewerTokenFile':'/tmp/combined-proof/reviewer','issuer':json.loads((p/'discovery.json').read_text())['issuer'],'audience':'credential-proxy','maxTokenLifetimeSeconds':600,'bindings':[{'namespace':'combined','serviceAccount':'agent','serviceAccountUID':json.loads((p/'account.json').read_text())['metadata']['uid'],'agentID':'fixture','vaultID':'fixture'}]}
(p/'proof/config.json').write_text(json.dumps(config))
PY
# Shares only the disposable Linux VM network so its loopback kind API is reachable.
# No host directories are mounted and no service ports are published.
docker create --name "$container" --network host --cpus 2 --memory 2g --entrypoint sleep credential-proxy-combined:local infinity >/dev/null
docker start "$container" >/dev/null
docker cp "$scratch/proof" "$container:/tmp/combined-proof"
docker exec --user root "$container" chown -R postgres:postgres /tmp/combined-proof
docker exec -e AV_VERIFY_COMBINED=true -e AV_TEST_WORKLOAD_CONFIG=/tmp/combined-proof/config.json -e AV_TEST_WORKLOAD_PROOF=/tmp/combined-proof/allowed -e AV_TEST_WORKLOAD_WRONG_PROOF=/tmp/combined-proof/wrong "$container" bash examples/postgres-broker/verify.sh '^TestRealPostgres_TwoSessionCancellationIsolation$|^TestRealPostgres_DatabaseSeedHistory$'
printf 'PASS: composed runtime proof, live services and verified TLS transport. Local clients only; no deployed bypass or network-policy claim.\n'
