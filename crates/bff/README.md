# BFF

A backend-for-frontend for a single-page app: it signs users in with Keycloak (authorization
code flow with PKCE), keeps their tokens server-side in Redis, and gives the browser only an
opaque `HttpOnly` session cookie. The SPA calls `/api/*` on the BFF, which forwards to the API
with the user's access token.

## Routes

| Route | Called by | Does |
|---|---|---|
| `GET /auth/login?returnUrl=/path` | browser navigation | starts a sign-in, redirects to Keycloak |
| `GET /auth/callback` | Keycloak redirect | finishes the sign-in, sets the session cookie; on failure redirects to `/?login_error=1` |
| `GET /auth/session` | SPA | who is signed in, or 401 |
| `POST /auth/logout` | SPA (`x-bff-csrf: 1`) | ends the session, revokes the refresh token, returns Keycloak's `logoutUrl` for the SPA to navigate to |
| `POST /auth/backchannel-logout` | Keycloak | ends every session of one Keycloak sign-in |
| `ANY /api/*` | SPA (`x-bff-csrf: 1` for writes) | forwards to `API_BASE_URL` with a fresh bearer token |
| `GET /health`, `GET /health/ready` | orchestrator | process up; Redis reachable |

Every response carries an `x-request-id`, also logged and forwarded to the API.

## Configuration

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ISSUER_URI` | yes | | Keycloak realm as tokens name it, e.g. `https://id.example.com/realms/main` |
| `DISCOVERY_URI` | no | `ISSUER_URI` | where the BFF reaches Keycloak itself, e.g. an in-cluster address; token, key and revocation calls go there too |
| `CLIENT_ID`, `CLIENT_SECRET` | yes | | the BFF's confidential Keycloak client |
| `REDIRECT_URI` | yes | | the BFF's public callback, e.g. `https://app.example.com/auth/callback` |
| `REDIS_URI` | yes | | e.g. `redis://redis:6379` |
| `API_BASE_URL` | no | | where `/api/*` goes; without it `/api/*` fails |
| `LISTEN_ADDR` | no | `0.0.0.0:5100` | address and port to listen on |
| `ALLOW_INSECURE_HTTP` | no | `false` | `true` accepts `http://` Keycloak URLs and redirect URI; local development only |
| `CLIENT_IP_HEADER` | no | | header a reverse proxy puts the client's IP in, e.g. `x-real-ip` or `cf-connecting-ip`; see below |
| `TRUSTED_PROXIES` | with `CLIENT_IP_HEADER` | | comma-separated addresses or ranges (`10.42.0.0/16`) allowed to set that header |
| `LOGIN_RATE_LIMIT_PER_MINUTE` | no | `10` | sign-in starts per client IP and minute; `0` turns it off (needs the `rate-limit` feature) |
| `RUST_LOG` | no | | log filter, e.g. `bff=info,oidc=info` |

The Keycloak client needs standard flow with PKCE (S256), the redirect URI above, and a
back-channel logout URL of `<BFF>/auth/backchannel-logout` with "session required" on;
`iam-config/keycloak-config/setup-scripts/setup_realm.sh` sets these up for the dev realm. For
the API to accept the forwarded tokens, the client also needs an audience mapper adding the
API's audience; the dev realm does not have one yet.

### Build features

| Feature | Default | Meaning |
|---|---|---|
| `rate-limit` | on | per-IP limit on `/auth/login`, kept in Redis; leave it out if e.g. Cloudflare already limits it |
| `e2e` | on | compiles the end-to-end tests |

The Docker image builds with `--build-arg FEATURES=rate-limit` (the default); pass
`--build-arg FEATURES=` for an image without the rate limit.

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

From the workspace root:

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

The test stack adds `echo-api`, which plays three parts: a stand-in API behind `/api/*`, a
proxy in front of Keycloak that tests can make fail (to check refresh errors keep the
session), and a recorder for back-channel logout tokens (to check a token is accepted once).
The tests reach it on `localhost:5199` (`E2E_HELPERS_URL`). Other overrides: `E2E_BFF_URL`,
`E2E_REDIS_URL`, `E2E_KEYCLOAK_URL`.

Keycloak's brute-force protection disables a user whose sign-ins overlap, so the tests sign
in one at a time; a run takes about 15 seconds.
