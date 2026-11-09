#!/usr/bin/env bash
# Installs the chart in each setup mode into the current kubectl context and
# checks the result from outside: served certificate, admin login, SSH host key.
# The image must already be on the cluster's nodes (e.g. `kind load docker-image`).
#
# Usage: helm/e2e.sh <image repository> <image tag>
set -euo pipefail

CHART=$(cd "$(dirname "$0")" && pwd)/warpgate
REPOSITORY=$1
TAG=$2
WORK=$(mktemp -d)
PASSWORD=$(openssl rand -hex 16)
NAMESPACES=()
PORT=30080
FORWARD=

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

on_exit() {
    local status=$?
    # A failed check exits with its port-forward still running
    [[ -z $FORWARD ]] || kill "$FORWARD" 2>/dev/null || true
    if [[ $status -ne 0 && ${#NAMESPACES[@]} -gt 0 ]]; then
        local ns=${NAMESPACES[-1]}
        echo "::group::$ns"
        kubectl -n "$ns" get all,pvc -o wide || true
        kubectl -n "$ns" get events --sort-by=.lastTimestamp | tail -30 || true
        for pod in $(kubectl -n "$ns" get pods -o name); do
            kubectl -n "$ns" logs "$pod" --all-containers --prefix --tail=100 || true
        done
        echo "::endgroup::"
    elif [[ ${#NAMESPACES[@]} -gt 0 ]]; then
        kubectl delete namespace "${NAMESPACES[@]}" --wait=false >/dev/null
    fi
    rm -rf "$WORK"
}
trap on_exit EXIT

for key in host-ed25519 client-ed25519; do
    ssh-keygen -q -t ed25519 -N '' -f "$WORK/$key"
done
for key in host-rsa client-rsa; do
    ssh-keygen -q -t rsa -b 2048 -N '' -f "$WORK/$key"
done
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=e2e-provided -keyout "$WORK/tls.key" -out "$WORK/tls.crt" 2>/dev/null

namespace() {
    local ns=$1
    NAMESPACES+=("$ns")
    kubectl create namespace "$ns" >/dev/null
    kubectl -n "$ns" create secret generic warpgate-secret \
        --from-literal=adminPassword="$PASSWORD" --from-literal=httpPort=8888 >/dev/null
    kubectl -n "$ns" create secret tls provided-tls \
        --cert="$WORK/tls.crt" --key="$WORK/tls.key" >/dev/null
    kubectl -n "$ns" create secret generic legacy-ssh-keys \
        --from-file="$WORK/host-ed25519" --from-file="$WORK/host-rsa" \
        --from-file="$WORK/client-ed25519" --from-file="$WORK/client-rsa" >/dev/null
}

install() {
    local ns=$1
    shift
    helm install wg "$CHART" --namespace "$ns" --wait --timeout 5m \
        --set image.repository="$REPOSITORY" --set image.tag="$TAG" \
        --set image.pullPolicy=Never --set podSecurityContext.fsGroup=1000 "$@" >/dev/null
}

# check <namespace> <expected certificate CN> [expected SSH host key .pub]
check() {
    local ns=$1 cn=$2 host_key=${3:-}
    local http=$((PORT += 2)) ssh=$((PORT + 1))
    kubectl -n "$ns" port-forward service/wg-warpgate "$http:8888" "$ssh:2222" >/dev/null &
    FORWARD=$!
    for _ in $(seq 20); do
        curl -sk -o /dev/null "https://localhost:$http/@warpgate/api/info" && break
        sleep 1
    done

    local subject
    subject=$(openssl s_client -connect "localhost:$http" </dev/null 2>/dev/null |
        openssl x509 -noout -subject -nameopt RFC2253)
    [[ $subject == "subject=CN=$cn" ]] || fail "$ns: served $subject, expected CN=$cn"

    local body code
    body=$(jq -cn --arg password "$PASSWORD" '{username: "admin", password: $password}')
    code=$(curl -sk -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
        -d "$body" "https://localhost:$http/@warpgate/api/auth/login")
    [[ $code == 201 ]] || fail "$ns: admin login returned HTTP $code"

    if [[ -n $host_key ]]; then
        local expected served
        expected=$(ssh-keygen -lf "$host_key" | awk '{print $2}')
        served=$(ssh-keyscan -t ed25519 -p "$ssh" localhost 2>/dev/null | ssh-keygen -lf -)
        [[ $served == *"$expected"* ]] || fail "$ns: SSH host key is not the one from ssh_keys_secret"
    fi

    kill "$FORWARD"
    FORWARD=""
    echo "$ns: ok"
}

echo "== image version gate"
helm template wg "$CHART" --set image.tag=0.29.1 >/dev/null 2>&1 && fail "image.tag 0.29.1 was accepted"
helm template wg "$CHART" --set image.tag=branch-main >/dev/null || fail "a branch tag was rejected"

echo "== bundled PostgreSQL, two replicas, rendered config"
namespace e2e-bundled-pg
install e2e-bundled-pg --set postgresql.enabled=true --set replicaCount=2
check e2e-bundled-pg wg-warpgate

echo "== emptyDir with every input"
namespace e2e-emptydir
cat >"$WORK/emptydir.yaml" <<'EOF'
setup:
  disableIpV6: true
  envFromSecret:
    WARPGATE_ADMIN_PASSWORD: warpgate-secret/adminPassword
    HTTP_PORT: warpgate-secret/httpPort
ssh_keys_secret: legacy-ssh-keys
tls_cert_secret: provided-tls
# The HTTP listener (and so the readiness probe) only comes up if this is substituted
config_env_var_replace: HTTP_PORT
overrides_config: |
  database_url: "sqlite:/data/db"
  http:
    listen: "0.0.0.0:$HTTP_PORT"
    certificate: /data/tls.certificate.pem
    key: /data/tls.key.pem
  ssh:
    enable: true
    listen: "0.0.0.0:2222"
EOF
install e2e-emptydir -f "$WORK/emptydir.yaml"
check e2e-emptydir e2e-provided "$WORK/host-ed25519.pub"

echo "== PVC, then reinstalled onto it"
namespace e2e-pvc
kubectl -n e2e-pvc apply -f - >/dev/null <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: warpgate-data
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
EOF
pvc_values=(--set data.pvc.enabled=true --set data.pvc.claimName=warpgate-data
    --set tls_cert_secret=provided-tls --set setup.disableIpV6=true)
install e2e-pvc "${pvc_values[@]}"
check e2e-pvc e2e-provided
helm uninstall wg --namespace e2e-pvc --wait >/dev/null
install e2e-pvc "${pvc_values[@]}"
setup_log=$(kubectl -n e2e-pvc logs deployment/wg-warpgate -c warpgate-setup)
[[ $setup_log == *"nothing to do"* ]] ||
    fail "e2e-pvc: setup did not keep the existing config and database"
check e2e-pvc e2e-provided
