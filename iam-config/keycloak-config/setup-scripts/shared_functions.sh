realm_url="$keycloak_url/realms/$realm"

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq (lightweight and flexible command-line JSON processor; https://jqlang.github.io/jq/) not available"
  exit 1
fi

create_private_client() {
  clientId=$1
  client_secret=$2
  name=$3
  description=${4:-name}
  echo "Creating client '$clientId'..."
  client_id=$(
    $kcadm create -r $realm clients -i -f - <<<"
      {
        \"clientId\": \"$clientId\",
        \"name\": \"$name\",
        \"description\": \"$description\",
        \"secret\": \"$client_secret\",
        \"authorizationServicesEnabled\": false,
        \"serviceAccountsEnabled\": true,
        \"implicitFlowEnabled\": false,
        \"directAccessGrantsEnabled\": false,
        \"standardFlowEnabled\": false,
        \"frontchannelLogout\": true
      }
    "
  )
  $kcadm update -r $realm "clients/$client_id" -s publicClient=false
}

add_auth_layer_aud_mapper_to_client() {
  client_id=$1
  client_name=$2
  echo "Adding Auth Layer API as audience to $client_name"
  $kcadm create -r $realm clients/$client_id/protocol-mappers/models -f - <<EOF
    {
     "name": "$client_name-auth-layer-aud",
     "protocol": "openid-connect",
     "protocolMapper": "oidc-audience-mapper",
     "config": {
       "included.client.audience": "$api_client_id",
       "id.token.claim": "true",
       "access.token.claim": "true"
     }
    }
EOF
}
