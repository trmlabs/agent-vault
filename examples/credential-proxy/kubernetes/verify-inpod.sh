#!/usr/bin/env bash
# Two disposable pods, real projected proof/services and enforced network policy.
set -euo pipefail
docker_host=${1:?Usage: verify-inpod.sh unix:///path/to/disposable/docker.sock}
case "$docker_host" in unix://*) ;; *) echo 'Use an explicit disposable local Docker socket.' >&2; exit 1 ;; esac
for tool in go docker kubectl python3 curl rg; do command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 1; }; done
export DOCKER_HOST="$docker_host"
docker buildx version >/dev/null || { echo 'Docker Buildx is required.' >&2; exit 1; }
root=$(cd "$(dirname "$0")/../../.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/credential-proxy-inpod.XXXXXX")
chmod 700 "$scratch"
umask 077
export KUBECONFIG="$scratch/kubeconfig"
cluster=credential-proxy-inpod
mkdir "$scratch/bin"
GOBIN="$scratch/bin" go install sigs.k8s.io/kind@v0.33.0
kind="$scratch/bin/kind"
if "$kind" get clusters | rg -qx "$cluster"; then echo 'Fixture cluster already exists; leave it intact.' >&2; rm -rf "$scratch"; exit 1; fi
fixture_pid=
cleanup() {
  local result=$?
  if [[ -n "$fixture_pid" ]]; then kill "$fixture_pid" 2>/dev/null || true; wait "$fixture_pid" 2>/dev/null || true; fi
  "$kind" delete cluster --name "$cluster" >/dev/null 2>&1 || true
  rm -rf "$scratch"
  trap - EXIT
  exit "$result"
}
trap cleanup EXIT
if [[ -n ${AV_DEMO_CA_FILE:-} ]]; then
  docker build --secret "id=demo_ca,src=$AV_DEMO_CA_FILE" -f "$root/examples/credential-proxy/Dockerfile" -t credential-proxy-inpod:local "$root"
else
  docker build -f "$root/examples/credential-proxy/Dockerfile" -t credential-proxy-inpod:local "$root"
fi
cat > "$scratch/kind.yaml" <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
nodes:
  - role: control-plane
YAML
# Calico 3.32 documents support through Kubernetes 1.36. Do not use the separate
# identity-only fixture's newer Kubernetes version for this enforcement proof.
"$kind" create cluster --name "$cluster" --config "$scratch/kind.yaml" --image kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed
curl --fail --silent --show-error --location https://raw.githubusercontent.com/projectcalico/calico/db255c554b929afd73552fd3ac81d691107a1607/manifests/calico.yaml -o "$scratch/calico.yaml"
python3 - "$scratch/calico.yaml" <<'PY'
import hashlib,pathlib,sys
if hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()!='a8c828a06a87c629a282ebbc424895b77f3a030251993e41ea400a743675bb02': raise SystemExit('Calico manifest digest mismatch')
PY
case "$(docker info --format '{{.Architecture}}')" in aarch64|arm64) platform=linux/arm64 ;; x86_64|amd64) platform=linux/amd64 ;; *) echo 'ARM64 or AMD64 Docker required.' >&2; exit 1 ;; esac
python3 - "$scratch/calico.yaml" > "$scratch/calico-images" <<'PY'
import pathlib,re,sys
for image in sorted(set(re.findall(r'^\s*image:\s*(\S+)\s*$',pathlib.Path(sys.argv[1]).read_text(),re.M))): print(image)
PY
# The host daemon supplies registry trust without weakening node TLS checks.
while IFS= read -r image; do
  docker pull "$image"
  docker image save "$image" | docker exec -i "$cluster-control-plane" ctr --namespace=k8s.io images import --platform "$platform" --digests - >/dev/null
done < "$scratch/calico-images"
kubectl create -f "$scratch/calico.yaml" >/dev/null
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
kubectl wait --for=condition=Ready nodes --all --timeout=180s
kubectl -n kube-system rollout status deployment/calico-kube-controllers --timeout=180s
docker image save credential-proxy-inpod:local | docker exec -i "$cluster-control-plane" ctr --namespace=k8s.io images import --platform "$platform" --digests - >/dev/null
kubectl create namespace combined
for account in agent reviewer; do kubectl -n combined create serviceaccount "$account"; done
kubectl create clusterrole combined-review --verb=create --resource=tokenreviews.authentication.k8s.io
kubectl create clusterrolebinding combined-review --clusterrole=combined-review --serviceaccount=combined:reviewer
kubectl -n combined create role pod-check --verb=get --resource=pods
kubectl -n combined create rolebinding pod-check --role=pod-check --serviceaccount=combined:reviewer
python3 - "$scratch/pods.json" <<'PY'
import json,sys
items=[]
for name,account in [('agent','agent'),('broker','reviewer')]:
 spec={'serviceAccountName':account,'automountServiceAccountToken':name=='broker','restartPolicy':'Never','securityContext':{'runAsNonRoot':True,'runAsUser':999,'runAsGroup':999,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':name,'image':'credential-proxy-inpod:local','imagePullPolicy':'Never','command':['sleep','1200'],'securityContext':{'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}},'resources':{'requests':{'cpu':'100m','memory':'128Mi'},'limits':{'cpu':'2','memory':'2Gi'}}}]}
 if name=='agent':
  spec['volumes']=[{'name':'proof','projected':{'defaultMode':292,'sources':[{'serviceAccountToken':{'path':'allowed','audience':'credential-proxy','expirationSeconds':600}},{'serviceAccountToken':{'path':'wrong','audience':'wrong-audience','expirationSeconds':600}}]}}]
  spec['containers'][0]['volumeMounts']=[{'name':'proof','mountPath':'/proof','readOnly':True}]
 items.append({'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'combined','labels':{'fixture-role':name}},'spec':spec})
items.append({'apiVersion':'v1','kind':'Service','metadata':{'name':'broker','namespace':'combined'},'spec':{'selector':{'fixture-role':'broker'},'ports':[{'name':'port-'+str(p),'port':p,'targetPort':p} for p in [14443,15443,14444,15444,18444]]}})
open(sys.argv[1],'w').write(json.dumps({'apiVersion':'v1','kind':'List','items':items}))
PY
kubectl apply -f "$scratch/pods.json"
kubectl -n combined wait --for=condition=Ready pod/agent pod/broker --timeout=120s
kubectl get --raw /.well-known/openid-configuration > "$scratch/discovery.json"
kubectl -n combined get serviceaccount agent -o json > "$scratch/account.json"
kubectl -n default get service kubernetes -o json > "$scratch/api-service.json"
kubectl -n default get endpoints kubernetes -o json > "$scratch/api-endpoints.json"
python3 - "$scratch" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); api=json.loads((p/'api-service.json').read_text())['spec']['clusterIP']
config={'apiServer':'https://'+api,'caFile':'/var/run/secrets/kubernetes.io/serviceaccount/ca.crt','reviewerTokenFile':'/var/run/secrets/kubernetes.io/serviceaccount/token','issuer':json.loads((p/'discovery.json').read_text())['issuer'],'audience':'credential-proxy','maxTokenLifetimeSeconds':600,'bindings':[{'namespace':'combined','serviceAccount':'agent','serviceAccountUID':json.loads((p/'account.json').read_text())['metadata']['uid'],'agentID':'fixture','vaultID':'fixture'}]}
(p/'config.json').write_text(json.dumps(config))
endpoint=json.loads((p/'api-endpoints.json').read_text())['subsets'][0]['addresses'][0]['ip']
policies=[{'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'default-deny','namespace':'combined'},'spec':{'podSelector':{},'policyTypes':['Ingress','Egress']}},
{'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'agent-broker','namespace':'combined'},'spec':{'podSelector':{'matchLabels':{'fixture-role':'agent'}},'policyTypes':['Egress'],'egress':[{'to':[{'podSelector':{'matchLabels':{'fixture-role':'broker'}}}],'ports':[{'protocol':'TCP','port':14443},{'protocol':'TCP','port':15443}]}]}},
{'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'broker-ingress','namespace':'combined'},'spec':{'podSelector':{'matchLabels':{'fixture-role':'broker'}},'policyTypes':['Ingress','Egress'],'ingress':[{'from':[{'podSelector':{'matchLabels':{'fixture-role':'agent'}}}],'ports':[{'protocol':'TCP','port':14443},{'protocol':'TCP','port':15443}]}],'egress':[{'to':[{'ipBlock':{'cidr':api+'/32'}},{'ipBlock':{'cidr':endpoint+'/32'}}],'ports':[{'protocol':'TCP','port':443},{'protocol':'TCP','port':6443}]}]}}]
(p/'policies.json').write_text(json.dumps({'apiVersion':'v1','kind':'List','items':policies}))
PY
kubectl -n combined exec -i broker -- sh -c 'cat > /tmp/combined-config.json' < "$scratch/config.json"
kubectl -n combined exec agent -- cat /proof/allowed | kubectl -n combined exec -i broker -- sh -c 'cat > /tmp/combined-proof'
kubectl -n combined exec agent -- cat /proof/wrong | kubectl -n combined exec -i broker -- sh -c 'cat > /tmp/combined-wrong-proof'
# Compile once, then run the same caller helper binary in the separate agent pod.
kubectl -n combined exec broker -- go test -c -tags realcombined ./internal/mitm -o /tmp/combined.test
kubectl -n combined exec broker -- cat /tmp/combined.test | kubectl -n combined exec -i agent -- sh -c 'cat > /tmp/combined.test; chmod 700 /tmp/combined.test'
pod_ip=$(kubectl -n combined get pod broker -o jsonpath='{.status.podIP}')
service_ip=$(kubectl -n combined get service broker -o jsonpath='{.spec.clusterIP}')
kubectl -n combined exec broker -- env AV_VERIFY_COMBINED=true AV_COMBINED_POD_IP="$pod_ip" AV_COMBINED_SERVICE_IP="$service_ip" AV_TEST_WORKLOAD_CONFIG=/tmp/combined-config.json AV_TEST_WORKLOAD_PROOF=/tmp/combined-proof AV_TEST_WORKLOAD_WRONG_PROOF=/tmp/combined-wrong-proof bash examples/postgres-broker/verify.sh '^TestRealPostgres_DatabaseSeedHistory$' > "$scratch/broker.log" 2>&1 &
fixture_pid=$!
ready=false
for _ in {1..90}; do
  if kubectl -n combined exec broker -- test -f /tmp/combined-public.json 2>/dev/null; then ready=true; break; fi
  kill -0 "$fixture_pid" 2>/dev/null || { cat "$scratch/broker.log"; echo 'Broker fixture ended before readiness.' >&2; exit 1; }
  sleep 2
done
$ready || { cat "$scratch/broker.log"; echo 'Broker fixture readiness timed out.' >&2; exit 1; }
kubectl -n combined exec broker -- cat /tmp/combined-public.json | kubectl -n combined exec -i agent -- sh -c 'cat > /tmp/combined-public.json'
kubectl -n combined exec agent -- env AV_COMBINED_CLIENT_ACTION=control /tmp/combined.test -test.run '^TestRealCombinedAgentClient$' -test.v -test.timeout 30s
kubectl apply -f "$scratch/policies.json"
enforced=false
for _ in {1..10}; do
  if kubectl -n combined exec agent -- env AV_COMBINED_CLIENT_ACTION=isolated /tmp/combined.test -test.run '^TestRealCombinedAgentClient$' -test.v -test.timeout 30s; then enforced=true; break; fi
  sleep 1
done
$enforced || { echo 'Policy enforcement or brokered positive control failed.' >&2; exit 1; }
kubectl -n combined exec broker -- touch /tmp/combined-agent-complete
if ! wait "$fixture_pid"; then fixture_pid=; cat "$scratch/broker.log"; exit 1; fi
fixture_pid=
cat "$scratch/broker.log"
printf 'PASS: separate caller pod, real projected proof, TLS broker workflows, and observed Calico denial of direct HTTP/Vault/PostgreSQL routes by pod/service IP. Destinations colocated in broker fixture; TRM deployment and storage/rollback acceptance remain open.\n'
