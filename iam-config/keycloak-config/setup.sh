#!/bin/bash
set -eux

cd "$(dirname $0)"

dockerImage=keycloak-config
docker image inspect "$dockerImage" &> /dev/null || docker build . -t "$dockerImage"

hostDirInContainer=/mnt/host
docker run \
  --volume ./container:"$hostDirInContainer" \
  --env keycloak_url="${keycloak_url:-http://localhost:8080}" \
  --env KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}" \
  --env KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-test}" \
  --env realm="${realm:-test}" \
  --env smtp_host="${smtp_host:-smtp-server}" \
  --env smtp_port="${smtp_port:-1025}" \
  --env api_client_id="${api_client_id:-authentication.layer.api}" \
  --env api_client_secret="${api_client_secret:-authentication.layer.api.secret}" \
  --user "$(id --user)" \
  "$dockerImage" \
  bash "$hostDirInContainer/setup_in_container.sh"