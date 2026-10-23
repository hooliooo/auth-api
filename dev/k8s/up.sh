#!/usr/bin/env bash
# Creates or updates the local Kubernetes cluster (kind) and deploys Keycloak to it, served at
# https://keycloak-api with a certificate from the local development CA.
#
# Once per machine: brew install kind helm mkcert nss && mkcert -install
# and in /etc/hosts:  127.0.0.1 keycloak-api
#
#   dev/k8s/up.sh       # idempotent: rerun after changing manifests or images
#   dev/k8s/down.sh     # deletes the cluster
#
# Every kubectl and helm call names the cluster's own context, so no other cluster (such as a
# shared one your kubeconfig points at) is ever touched.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cluster=auth-api
ctx="kind-$cluster"
k() { kubectl --context "$ctx" "$@"; }
h() { helm --kube-context "$ctx" "$@"; }
step() { printf '\n==> %s\n' "$*"; }

# ---- Preflight: everything a first run needs, each with what to do about it ----
problems=()
for tool in docker kind kubectl helm mkcert openssl; do
  command -v "$tool" >/dev/null || problems+=("$tool is not installed: see deploy/README.md, 'Once per machine'")
done
if ! command -v docker >/dev/null; then
  :
elif ! docker info >/dev/null 2>&1; then
  problems+=("Docker is not running: start Docker Desktop (or the Docker daemon)")
else
  memory=$(docker info --format '{{.MemTotal}}')
  if (( memory < 3 * 1024 * 1024 * 1024 )); then
    problems+=("Docker has $((memory / 1024 / 1024)) MiB of memory; Keycloak and PostgreSQL need at least 3 GiB (Docker Desktop: Settings > Resources)")
  fi
fi
if ! grep -Eq '^[[:space:]]*127\.0\.0\.1[[:space:]]([^#]*[[:space:]])?keycloak-api([[:space:]]|$)' /etc/hosts; then
  problems+=("/etc/hosts has no '127.0.0.1 keycloak-api': echo '127.0.0.1 keycloak-api' | sudo tee -a /etc/hosts")
fi
ca_root="$(command -v mkcert >/dev/null && mkcert -CAROOT || true)"
if [[ -z "$ca_root" || ! -f "$ca_root/rootCA.pem" || ! -f "$ca_root/rootCA-key.pem" ]]; then
  problems+=("no local CA yet: run 'mkcert -install' (it asks for your password)")
elif [[ "$(uname)" == Darwin ]] && ! security verify-cert -c "$ca_root/rootCA.pem" -p ssl >/dev/null 2>&1; then
  problems+=("the local CA is not trusted by macOS: run 'mkcert -install'")
fi
# Ports 80 and 443 must be free unless this cluster already holds them.
if command -v kind >/dev/null && ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
  for port in 80 443; do
    if command -v lsof >/dev/null && lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      problems+=("port $port is already in use on this machine (lsof -nP -iTCP:$port -sTCP:LISTEN shows by what); stop it first")
    fi
  done
fi
if (( ${#problems[@]} > 0 )); then
  echo "Cannot set up the cluster yet:"
  for problem in "${problems[@]}"; do echo "  - $problem"; done
  exit 1
fi

step "Cluster $cluster"
if ! kind get clusters | grep -qx "$cluster"; then
  # kind makes its new cluster the default context; keep whatever was the default before.
  previous="$(kubectl config current-context 2>/dev/null || true)"
  kind create cluster --config "$root/deploy/kind/cluster.yaml"
  if [[ -n "$previous" ]]; then kubectl config use-context "$previous" >/dev/null; fi
fi

step "Ingress controller (Traefik)"
helm repo add traefik https://traefik.github.io/charts >/dev/null 2>&1 || true
helm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1 || true
helm repo update traefik jetstack >/dev/null
h upgrade --install traefik traefik/traefik --namespace traefik --create-namespace \
  --version 42.1.3 --values "$root/deploy/platform/traefik-values.yaml" --wait

step "Certificates (cert-manager, local CA)"
h upgrade --install cert-manager jetstack/cert-manager --namespace cert-manager \
  --create-namespace --version v1.21.2 --set crds.enabled=true --wait
k -n cert-manager create secret tls local-ca \
  --cert="$ca_root/rootCA.pem" --key="$ca_root/rootCA-key.pem" \
  --dry-run=client -o yaml | k apply -f -
k apply -f "$root/deploy/platform/cluster-issuer.yaml"

step "In-cluster DNS: the public names resolve to the ingress"
# Pods then reach https://keycloak-api exactly as browsers do, like split-horizon DNS in
# production. Each name gets a rewrite block ahead of the kubernetes plugin.
corefile="$(k -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')"
if ! grep -q 'auth-api public names' <<<"$corefile"; then
  rewrites="    # auth-api public names, answered with the ingress controller's address\n"
  for name in keycloak-api auth-api; do
    rewrites+="    rewrite stop {\n        name exact $name traefik.traefik.svc.cluster.local\n        answer name traefik.traefik.svc.cluster.local $name\n    }\n"
  done
  corefile="$(awk -v r="$rewrites" '/^ *kubernetes cluster.local/ && !done { printf "%s", r; done=1 } { print }' <<<"$corefile")"
  k -n kube-system create configmap coredns --from-literal=Corefile="$corefile" \
    --dry-run=client -o yaml | k apply -f -
  k -n kube-system rollout restart deployment coredns
  k -n kube-system rollout status deployment coredns --timeout=120s
fi

step "Images"
docker build -t auth-api/keycloak:dev "$root/iam-config/keycloak"
docker build -t auth-api/keycloak-config:dev "$root/iam-config/keycloak-config"
kind load docker-image --name "$cluster" auth-api/keycloak:dev auth-api/keycloak-config:dev

step "Namespace, secrets and realm scripts"
k apply -f "$root/deploy/k8s/namespace.yaml"
# Random secrets, created once and kept across reruns; read them back with kubectl.
secret_once() { # <name> <key=value>...
  local name=$1; shift
  k -n auth-api get secret "$name" >/dev/null 2>&1 && return
  local args=()
  for pair in "$@"; do args+=(--from-literal="$pair"); done
  k -n auth-api create secret generic "$name" "${args[@]}"
}
random() { openssl rand -base64 24 | tr -d '/+=' | head -c 24; }
secret_once keycloak-admin username=admin "password=$(random)"
secret_once keycloak-db "password=$(random)"
secret_once keycloak-clients "api-client-secret=$(random)" "end-to-end-client-secret=$(random)"
k -n auth-api create configmap keycloak-config-scripts \
  --from-file="$root/iam-config/keycloak-config/setup-scripts" \
  --dry-run=client -o yaml | k apply -f -

step "Keycloak"
k apply -k "$root/deploy/k8s"
# A rebuilt image under the same tag is only picked up by new pods.
k -n auth-api rollout restart deployment keycloak
k -n auth-api rollout status statefulset keycloak-postgres --timeout=180s
k -n auth-api rollout status deployment keycloak --timeout=600s
k -n auth-api wait certificate keycloak-api-tls --for=condition=Ready --timeout=120s

step "Realm setup"
if [[ "$(k -n auth-api get job keycloak-config -o jsonpath='{.status.succeeded}' 2>/dev/null)" == "1" ]]; then
  echo "already done"
else
  k -n auth-api delete job keycloak-config --ignore-not-found
  k apply -f "$root/deploy/k8s/keycloak-config-job.yaml"
  if ! k -n auth-api wait job keycloak-config --for=condition=Complete --timeout=600s; then
    k -n auth-api logs job/keycloak-config --all-containers | tail -40
    echo "Realm setup failed; see above."
    exit 1
  fi
fi

cat <<DONE

Keycloak:       https://keycloak-api            (admin console: https://keycloak-api/admin)
Test realm:     https://keycloak-api/realms/test/account   (user alice, password test)
Admin password: kubectl --context $ctx -n auth-api get secret keycloak-admin -o jsonpath='{.data.password}' | base64 -d
Emails:         kubectl --context $ctx -n auth-api port-forward service/smtp-server 1080, then http://localhost:1080
DONE
