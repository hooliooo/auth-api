# BFF

A backend-for-frontend for a single-page app: it signs users in with an OpenID Connect provider
such as Keycloak (authorization code flow with PKCE), keeps their tokens server-side in Redis,
and gives the browser only an opaque `HttpOnly` session cookie. The SPA calls `/api/*` on the
BFF, which forwards to the API with the user's access token.

## Routes

| Route | Called by | Does |
|---|---|---|
| `GET /auth/login?returnUrl=/path` | browser navigation | starts a sign-in, redirects to the provider |
| `GET /auth/callback` | provider redirect | finishes the sign-in, sets the session cookie; on failure redirects to `/?login_error=1` |
| `GET /auth/session` | SPA | who is signed in, or 401 |
| `POST /auth/logout` | SPA (`x-bff-csrf: 1`) | ends the session here and at the provider (see [Identity providers](#identity-providers)); returns `logoutUrl`, where the SPA goes next: the app's start page, or the provider's logout page (no token in it) |
| `POST /auth/backchannel-logout` | provider | ends every session of one provider sign-in |
| `ANY /api/*` | SPA (`x-bff-csrf: 1` for writes) | forwards to `API_BASE_URL` with a fresh bearer token; paths with `.` or `..` segments are refused (400) |
| `GET /.well-known/jwks.json` | provider | the BFF's public client keys, with `private_key_jwt` (404 otherwise) |
| `GET /health`, `GET /health/ready` | orchestrator | process up; Redis reachable |

Every response carries an `x-request-id`, also logged and forwarded to the API.

With Keycloak, a session lasts exactly as long as the user's Keycloak session: each sign-in and
token refresh sets its expiry from Keycloak's `refresh_expires_in`, so the realm's SSO idle and
maximum lifetimes apply without being configured twice. Other providers do not report their
session's lifetime, so there a session lasts an hour past its last sign-in or refresh. Reading
the session does not extend it; a token refresh does. The BFF additionally ends every session
24 hours after sign-in.

## Identity providers

The BFF uses only standard OpenID Connect (discovery, authorization code with PKCE, token
refresh, back-channel logout) except where `IDENTITY_PROVIDER` says otherwise:

| | `oidc`: any provider | `keycloak` |
|---|---|---|
| ID token type | not checked: standard ID tokens carry none; the audience, `azp` and nonce checks keep other tokens out | `typ` must be `ID`, as Keycloak signs every token type with the same keys |
| Session lifetime | an hour past the last sign-in or refresh | Keycloak's `refresh_expires_in` |
| Logout | revokes the refresh token (RFC 7009), then `logoutUrl` is the provider's logout page, where its session ends; the start page if the provider publishes none | ends the Keycloak session server to server with the refresh token; `logoutUrl` is the start page, or Keycloak's logout page if Keycloak could not be reached |

A provider need not publish a revocation or logout endpoint; the step that needs one is then
skipped and logged.

## Configuration

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ISSUER_URI` | yes | | the provider's issuer as tokens name it, e.g. a Keycloak realm `https://id.example.com/realms/main` |
| `IDENTITY_PROVIDER` | yes | | `oidc` for any OpenID Connect provider, or `keycloak`; see [Identity providers](#identity-providers). No default, so a Keycloak deployment never silently loses Keycloak's checks |
| `DISCOVERY_URI` | no | `ISSUER_URI` | where the BFF reaches the provider itself, e.g. an in-cluster address; token, key and revocation calls go there too |
| `CLIENT_ID` | yes | | the BFF's confidential client at the provider |
| `CLIENT_AUTH` | no | `client_secret` | how the BFF authenticates to the provider: `client_secret` or `private_key_jwt` (signed assertions; preferred) |
| `CLIENT_SECRET` | with `client_secret` | | the client secret |
| `CLIENT_KEY_FILE` | with `private_key_jwt` | | the EC P-256 private key (PEM) assertions are signed with |
| `CLIENT_KEY_ID` | no | the key's JWK thumbprint | the key's `kid` |
| `CLIENT_NEXT_KEY_FILE`, `CLIENT_NEXT_KEY_ID` | no | | a key published ahead of a rotation, not yet used |
| `REDIRECT_URI` | yes | | the BFF's public callback, e.g. `https://app.example.com/auth/callback` |
| `REDIS_URI` | yes | | e.g. `redis://redis:6379` |
| `API_BASE_URL` | no | | where `/api/*` goes; without it `/api/*` fails |
| `OIDC_SCOPES` | no | `openid` | scopes every sign-in requests, space-separated; must include `openid`, never `offline_access`. The browser cannot change them |
| `LISTEN_ADDR` | no | `0.0.0.0:5100` | address and port to listen on |
| `METRICS_ADDR` | no | `0.0.0.0:9100` | where Prometheus metrics are served (`GET /metrics`), apart from the public port (needs the `metrics` feature) |
| `ALLOW_INSECURE_HTTP` | no | `false` | `true` accepts `http://` provider URLs and redirect URI; local development only |
| `CLIENT_IP_HEADER` | no | | header a reverse proxy puts the client's IP in, e.g. `x-real-ip` or `cf-connecting-ip`; see below |
| `TRUSTED_PROXIES` | with `CLIENT_IP_HEADER` | | comma-separated addresses or ranges (`10.42.0.0/16`) allowed to set that header |
| `LOGIN_RATE_LIMIT_PER_MINUTE` | no | `10` | sign-in starts per client IP and minute; `0` turns it off (needs the `rate-limit` feature) |
| `RUST_LOG` | no | `info` | log filter, e.g. `bff=debug,info` |

### The Keycloak client

`iam-config/keycloak-config/setup-scripts/setup_realm.sh` sets all of this up for the dev realm.

- **Flow:** standard flow with PKCE (S256), the redirect URI above, and back-channel logout to
  `<BFF>/auth/backchannel-logout` with "session required" on.
- **Client authentication:** "Signed JWT" (`private_key_jwt`) with algorithm ES256 and a JWKS
  URL of `<BFF>/.well-known/jwks.json`, where the BFF publishes its public key; no client
  secret. A client secret still works with `CLIENT_AUTH=client_secret`.
- **Scopes:** default client scopes only `basic`, `roles` and `acr` (default scopes are in every
  token, whatever is requested); `profile` and `email` optional; `web-origins`,
  `offline_access` and the rest not assigned.
- **Audience:** an audience mapper adding the API's audience (`authentication.layer.api`) to
  access tokens, not ID tokens, so the API accepts the tokens the BFF forwards.
- **Roles:** "Full scope allowed" off, so tokens carry only the roles mapped to the client: in
  the dev realm, `multi-tenancy-admin`, the one role the API acts on.
- **Refresh tokens:** the dev realm rotates them and accepts each only once
  (`revokeRefreshToken`, `refreshTokenMaxReuse=0`); the BFF refreshes each session under a
  Redis lock, so parallel requests never spend the same token twice.

### Rotating the client key

1. Set `CLIENT_NEXT_KEY_FILE` to the new key and restart: the BFF publishes both public keys
   and still signs with the old one.
2. Wait until Keycloak has picked up the new key set, then make the new key `CLIENT_KEY_FILE`
   (dropping `CLIENT_NEXT_KEY_FILE`) and restart: the BFF signs with the new key.

Keys are EC P-256 in PEM, e.g. `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8
-topk8 -nocrypt`.


### Build features

| Feature | Default | Meaning |
|---|---|---|
| `rate-limit` | on | per-IP limit on `/auth/login`, kept in Redis; leave it out if e.g. Cloudflare already limits it |
| `metrics` | on | Prometheus metrics on `METRICS_ADDR`: requests by route and status, request durations, sign-ins, token refreshes, logouts, back-channel logouts and rate-limit refusals; no extra dependencies |
| `e2e` | on | compiles the end-to-end tests |

The Docker image builds with `--build-arg FEATURES=metrics,rate-limit` (the default); pass e.g.
`--build-arg FEATURES=metrics` for an image without the rate limit.

## Running behind a reverse proxy

Behind any proxy (an ingress controller, a load balancer, Cloudflare), connections come from the
proxy, so the BFF sees the proxy's address unless told where the client's is:

- Set `CLIENT_IP_HEADER` to the header the proxy writes the client's address to (nginx:
  usually `x-real-ip`; Cloudflare: `cf-connecting-ip`), and `TRUSTED_PROXIES` to the proxy's
  own addresses (e.g. the pod network `cloudflared` or the ingress runs in). From any other
  address the header is ignored, so it cannot be forged by connecting directly.
- Without these the BFF uses the connection's address. That is safe, but behind a proxy the
  rate limit then sees one address for everyone: rely on the proxy's rate limiting instead and
  build without `rate-limit`.
- Better still, accept traffic only from the proxy (e.g. a Cloudflare Tunnel plus a
  NetworkPolicy allowing only `cloudflared`).
- The BFF strips `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `CF-Connecting-IP` and
  `True-Client-IP` from requests to the API and sets its own `X-Forwarded-For`.

## Local development

From the workspace root, once, create your own client key (`crates/bff/dev/client-key.pem`,
ignored by git; the stack refuses to start without it):

```sh
crates/bff/dev/generate-client-key.sh
```

Then:

```sh
docker compose -f crates/bff/docker-compose.yml up -d --build
```

Starts Keycloak (with the `test` realm and user `alice` / `test`), Redis and the BFF on
`http://localhost:5100`. This stack sets `ALLOW_INSECURE_HTTP=true`.

## Tests

```sh
cargo test -p bff --bins                       # unit tests, no Docker needed

docker compose -f crates/bff/docker-compose.yml -f crates/bff/docker-compose.test.yml up -d --build
cargo test -p bff --test e2e                   # end-to-end, against the test stack
```

The test stack adds a second BFF on `localhost:5102` (`E2E_UNTRUSTED_BFF_URL`) that trusts no
proxy, to check a forged client IP header is ignored, and `echo-api`, which plays three parts: a stand-in API behind `/api/*`, a
proxy in front of Keycloak that tests can make fail (to check refresh errors keep the
session), and a recorder for back-channel logout tokens (to check a token is accepted once).
The tests reach it on `localhost:5199` (`E2E_HELPERS_URL`). Other overrides: `E2E_BFF_URL`,
`E2E_REDIS_URL`, `E2E_KEYCLOAK_URL`.

Keycloak's brute-force protection disables a user whose sign-ins overlap, so the tests sign
in one at a time; a run takes about 15 seconds.
