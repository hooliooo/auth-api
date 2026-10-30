# Local Kubernetes

Keycloak and the BFF in a local Kubernetes cluster (kind), as close to production as a laptop
allows: an ingress controller terminating TLS with cert-manager certificates, one public address
per service that browsers and pods share, and secrets generated at setup rather than kept in the
repo.

## Once per machine

```sh
brew install kind helm mkcert nss
mkcert -install                     # a local CA, trusted by macOS, Chrome, Safari and Firefox
echo "127.0.0.1 keycloak-api auth-api" | sudo tee -a /etc/hosts   # if not there yet
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
dev/k8s/up.sh        # creates or updates the cluster; safe to rerun
dev/k8s/up.sh --e2e  # the same plus the BFF e2e tests' helpers (see "E2E tests")
dev/k8s/down.sh      # deletes the cluster, database included
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
| BFF | `deploy/k8s/bff.yaml` | the BFF, from `crates/bff`, at `https://auth-api` |
| Redis | `deploy/k8s/redis.yaml` | the managed Redis holding the BFF's sessions |

Keycloak's issuer is `https://keycloak-api/realms/test` for browsers and pods alike, so services
need no separate discovery address. Pods that call `https://keycloak-api` must trust the local
CA: mount the `local-ca` ConfigMap's `ca.crt` (its public certificate, which `up.sh` creates) and
point `SSL_CERT_FILE` at it, as the BFF does.

The BFF signs in with its own key (`private_key_jwt`): `up.sh` runs
`crates/bff/dev/generate-client-key.sh` once, which writes this machine's key to
`crates/bff/dev/client-key.pem` (never committed), and copies it into the `bff-client-key`
secret. Keycloak fetches the matching public key from the BFF itself.

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
   `https://keycloak-api` trusts the CA by mounting `ca.crt` from the `local-ca` ConfigMap,
   which holds only the CA's public certificate, and pointing `SSL_CERT_FILE` at it.

Keep the CA private key private: anyone who copies it can impersonate any site to the programs
that trust it on this machine. `dev/k8s/down.sh` deletes the cluster and the copy in it;
`mkcert -uninstall` removes the trust, and deleting `$(mkcert -CAROOT)` removes the CA itself.

## Adding a service

Add its manifests to `deploy/k8s/` and its image build to `up.sh`; give it an `Ingress` with the
`cert-manager.io/cluster-issuer: local-ca` annotation and a hosts entry for its name (the CoreDNS
rewrite already covers `auth-api`).

## E2E tests

The BFF's end-to-end tests (`crates/bff/tests/e2e.rs`) run against this cluster, through the
ingress, so they sign in the way a browser does: across sites, over HTTPS, with Keycloak at its
one public address.

```sh
dev/k8s/up.sh --e2e
cargo test -p bff --features e2e --test e2e
```

`--e2e` applies `deploy/e2e` instead of `deploy/k8s`: everything above plus

| Piece | Where | What for |
|---|---|---|
| echo-api | `deploy/e2e/echo-api.yaml`, from `crates/echo-api` | the BFF's API: answers with what it received; records Keycloak's back-channel logouts; a proxy in front of Keycloak that fails a request once when told to |
| BFF settings | `deploy/e2e/bff-patch.yaml` | the BFF under test uses the echo API, reads each simulated browser's address from `cf-connecting-ip`, and reaches Keycloak through the proxy |
| `bff-oidc`, `bff-untrusted` | `deploy/e2e/bff-variants.yaml` | BFFs treating Keycloak as any OpenID Connect provider, and trusting no proxy, at `https://auth-api-oidc` and `https://auth-api-untrusted` |
| Test access | `deploy/e2e/test-access.yaml` | Redis, the BFF's metrics and the helpers' controls on `127.0.0.1:16379`, `:19100` and `:19199` |

- **The Keycloak proxy keeps one address.** It answers as `https://keycloak-api`, with a
  certificate for that name from the local CA, on a Service with a fixed address; the BFF under
  test resolves `keycloak-api` to it (`hostAliases`). The BFF code runs unchanged: only where
  the name leads differs.
- **No extra hosts entries.** The tests resolve `auth-api`, `auth-api-oidc`,
  `auth-api-untrusted` and `keycloak-api` to the ingress themselves (`E2E_INGRESS_ADDR`, default
  `127.0.0.1:443`).
- **Keycloak admin calls** use the realm's end-to-end client; its secret is read from the
  cluster with kubectl unless `E2E_CLIENT_SECRET` is set. The tests register `bff-oidc`'s
  addresses with the `bff` client on their first run.
- **Back to a normal cluster:** `up.sh` without `--e2e` restores the BFF's own settings; the
  helpers stay until `dev/k8s/down.sh`.
