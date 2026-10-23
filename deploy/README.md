# Local Kubernetes

Keycloak in a local Kubernetes cluster (kind), as close to production as a laptop allows: an
ingress controller terminating TLS with cert-manager certificates, one public address that
browsers and pods share, and secrets generated at setup rather than kept in the repo.

## Once per machine

```sh
brew install kind helm mkcert nss
mkcert -install                     # a local CA, trusted by macOS, Chrome, Safari and Firefox
echo "127.0.0.1 keycloak-api" | sudo tee -a /etc/hosts   # if not there yet
```

Docker needs at least 3 GiB of memory (Docker Desktop: Settings > Resources), and ports 80 and
443 on this machine must be free. `up.sh` checks all of this first and says what to fix.

The first run downloads about 1-2 GB (images, Helm charts, Debian packages) and takes several
minutes; later runs take about one.

**Behind a company proxy that inspects TLS**, downloads inside Docker builds and Helm fail with
certificate errors. Add the company's root CA to Docker Desktop (Settings > Docker Engine, or the
proxy settings) and to this machine's trust store, as your IT department describes.

**Linux** works the same way with Docker installed; rootless Docker cannot bind ports 80 and 443,
so use rootful Docker. The CA trust check in `up.sh` is macOS-only; on Linux `mkcert -install`
is still required. **Windows**: run everything inside WSL2, with Docker Desktop's WSL
integration, and add the hosts entry to Windows' own hosts file
(`C:\Windows\System32\drivers\etc\hosts`) as well, for the browser.

## Up and down

```sh
dev/k8s/up.sh       # creates or updates the cluster; safe to rerun
dev/k8s/down.sh     # deletes the cluster, database included
```

`up.sh` prints the addresses and how to read the generated admin password. Every `kubectl` and
`helm` call in it names the cluster's own context (`kind-auth-api`), and creating the cluster
leaves your default context as it was, so a shared cluster in your kubeconfig is never touched.

## What runs

| Piece | Where | Stands in for |
|---|---|---|
| Traefik | `deploy/platform/traefik-values.yaml` | the production ingress; serves standard `Ingress` resources and redirects HTTP to HTTPS |
| cert-manager, `local-ca` issuer | `deploy/platform/cluster-issuer.yaml` | the production issuer (e.g. Let's Encrypt or the company CA); only the issuer resource differs |
| CoreDNS rewrite | `dev/k8s/up.sh` | split-horizon DNS: `keycloak-api` resolves to the ingress inside the cluster too |
| PostgreSQL | `deploy/k8s/keycloak-postgres.yaml` | the managed database |
| Keycloak | `deploy/k8s/keycloak.yaml` | Keycloak, from `iam-config/keycloak`, at `https://keycloak-api` |
| Realm setup | `deploy/k8s/keycloak-config-job.yaml` | `iam-config/keycloak-config/setup-scripts`, run once |
| Mail catcher | `deploy/k8s/smtp.yaml` | the SMTP server |

Keycloak's issuer is `https://keycloak-api/realms/test` for browsers and pods alike, so services
need no separate discovery address. Pods that call `https://keycloak-api` must trust the local
CA: it is the `ca.crt` of the `keycloak-api-tls` secret.

## How the certificates work

There is one local certificate authority (CA), made by mkcert, and every certificate in the
cluster chains up to it.

1. **The CA.** mkcert creates it on its first run: a self-signed root certificate valid for 10
   years, allowed only to sign certificates (`CA:TRUE, pathlen:0`). It lives in
   `$(mkcert -CAROOT)` (`~/Library/Application Support/mkcert`): `rootCA.pem` is the public
   certificate, `rootCA-key.pem` the private key (readable only by you). It is unique to this
   machine; another developer gets their own.
2. **Trust on this machine.** `mkcert -install` adds the *public* certificate to every trust
   store it finds: the macOS system keychain (Chrome, Safari, `curl`), Java's `cacerts` when a
   JDK is present, and Firefox's store when Firefox is installed. From then on anything those
   programs see signed by this CA is accepted. The private key is never added anywhere.
3. **Signing inside the cluster.** `up.sh` copies the CA certificate *and its private key* into
   the cluster as the secret `local-ca` (namespace `cert-manager`), so cert-manager can sign
   with it. The `local-ca` ClusterIssuer points at that secret.
4. **A certificate per Ingress.** An Ingress with `cert-manager.io/cluster-issuer: local-ca` and a
   `tls` section makes cert-manager create a Certificate for its hosts, sign it with the CA, and
   store it as the secret named in `secretName` (for Keycloak: `keycloak-api-tls`, holding
   `tls.crt`, `tls.key` and the CA's `ca.crt`). It is valid for 90 days and renewed automatically
   a month before it expires.
5. **Serving it.** Traefik serves that certificate when a client asks for `keycloak-api` (TLS
   SNI). A browser checks that the name matches (`DNS:keycloak-api`) and that it chains to a CA
   it trusts: step 2 makes that true.
6. **Pods.** Containers do not use this machine's trust stores. A pod calling
   `https://keycloak-api` trusts the CA by mounting `ca.crt` from the `keycloak-api-tls` secret
   (e.g. through `SSL_CERT_FILE`).

Keep the CA private key private: anyone who copies it can impersonate any site to the programs
that trust it on this machine. `dev/k8s/down.sh` deletes the cluster and the copy in it;
`mkcert -uninstall` removes the trust, and deleting `$(mkcert -CAROOT)` removes the CA itself.

## Adding a service

Add its manifests to `deploy/k8s/` and its image build to `up.sh`; give it an `Ingress` with the
`cert-manager.io/cluster-issuer: local-ca` annotation and a hosts entry for its name (the CoreDNS
rewrite already covers `auth-api`).
