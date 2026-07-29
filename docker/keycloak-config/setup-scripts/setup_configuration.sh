#!/bin/bash
set -eu
echo "checking keycloak_url $keycloak_url"
until curl --silent --fail --head "$keycloak_url"; do
  sleep 0.1
done
echo 'exporting KC_OPTS'
export KC_OPTS='-Duser.home=/tmp' # The script is run with the host system's user (to ensure that the mounted directory is accessible), the user might not have a home directory.
$kcadm config credentials --server "$keycloak_url" --realm master --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD"
$kcadm update realms/master -s sslRequired=NONE

cd "$(dirname "$0")"
(
  bash setup_realm.sh
) 2>&1 | tee "$(date +logs/%Y-%m-%d_%H:%M:%S.log)"

