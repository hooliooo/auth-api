# OAuth agent variants

Two more OAuth agents the e2e tests compare against, each built from the OAuth agent's own
manifest (`deploy/k8s/oauth-agent`) with only what differs patched in. They share Redis,
Keycloak, the client key and the internal secret with the OAuth agent under test, each at its own
address behind the ingress:

- `oidc/`, `oauth-agent-oidc` at `https://auth-api-oidc`: treats Keycloak as any OpenID Connect
  provider (`IDENTITY_PROVIDER=oidc`), to check what the OAuth agent does without Keycloak's
  extensions.
- `untrusted/`, `oauth-agent-untrusted` at `https://auth-api-untrusted`: trusts no proxy, so its
  client address header is ignored whoever sets it.

The tests reach both names without hosts-file entries: they resolve them to the ingress
themselves.
