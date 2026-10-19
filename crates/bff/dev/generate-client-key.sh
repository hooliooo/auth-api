#!/usr/bin/env bash
# Creates the BFF's private client key for the local compose stacks, next to this script:
# client-key.pem (EC P-256, PEM). Each developer generates their own; it is never committed.
# Keycloak reads the matching public key from the BFF's /.well-known/jwks.json, so nothing
# else needs changing. Restart the BFF after replacing the key.
#
#   crates/bff/dev/generate-client-key.sh            # creates the key if there is none
#   crates/bff/dev/generate-client-key.sh --force    # replaces an existing key
set -euo pipefail

key="$(dirname "$0")/client-key.pem"

if [[ -e "$key" && "${1:-}" != "--force" ]]; then
  echo "$key already exists; pass --force to replace it."
  exit 0
fi

openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$key.tmp"
# Readable by the BFF container's own user. A local test key only: production keys come from
# a secret store.
chmod 644 "$key.tmp"
mv "$key.tmp" "$key"
echo "Created $key"
