#!/bin/bash
# pipefail: a pipeline fails if any command in it does, not only the last one (e.g. a failing
# setup piped into tee, or a failing kcadm piped into jq).
set -euo pipefail
source shared_functions.sh

if $kcadm get realms/$realm &>/dev/null; then
  echo "Realm $realm already exists, skipping setup"
  exit 0
fi

echo "
#
# Setting up $realm realm
#
"

$kcadm create realms \
  -s realm=$realm \
  -s enabled=true \
  -s registrationAllowed=false \
  -s registrationEmailAsUsername=false \
  -s verifyEmail=true \
  -s resetPasswordAllowed=true \
  -s loginWithEmailAllowed=true \
  -s sslRequired=NONE \
  \
  $(: 'Admin Console -> Realm Settings -> Events -> Admin events settings') \
  -s eventsEnabled=true \
  -s adminEventsEnabled=true \
  \
  $(: 'Admin Console -> Realm Settings -> Security defenses -> Brute force detection') \
  -s bruteForceProtected=true \
  -s failureFactor=3 $(: 'How many failures before wait is triggered.') \
  -s waitIncrementSeconds=60 $(: 'When failure threshold has been met, how much time should the user be locked out?') \
  -s maxFailureWaitSeconds=900 $(: 'Max time a user will be locked out.') \
  -s maxDeltaTimeSeconds=43200 $(: 'When will failure count be reset?') \
  \
  $(: 'Admin Console -> Realm Settings -> Localization') \
  -s internationalizationEnabled=true -s supportedLocales='["de", "en"]' \
  -s defaultLocale='de' \
  \
  -s accessTokenLifespan=300 \
  -s ssoSessionIdleTimeout=600 $(: 'refresh token (cf. https://stackoverflow.com/q/52040265/') \
  -s ssoSessionMaxLifespan=864000 \
  \
  $(: 'Realm Settings -> Tokens -> Refresh tokens: every refresh returns a new refresh token,') \
  $(: 'and each one can be used exactly once (a replayed one is refused).') \
  -s revokeRefreshToken=true \
  -s refreshTokenMaxReuse=0 \
  \
  -s organizationsEnabled=true

# Login and admin events are kept for 7 days
$kcadm update realms/$realm -s eventsExpiration=604800 -s attributes='{ "adminEventsExpiration": "604800" }'

#### Keycloak SMTP configuration (Realm Settings -> Email)
$kcadm update realms/$realm -s smtpServer="{
         \"starttls\": \"false\",
         \"port\": \"$smtp_port\",
         \"host\": \"$smtp_host\",
         \"from\": \"$IAM_email\",
         \"fromDisplayName\": \"$IAM_email_display_name\",
         \"ssl\": \"false\"
     }"

# Adding isLegacy and isEmailMFAEnabled attributes to the user profile
$kcadm update users/profile -r $realm -s 'attributes=[{"name":"username","displayName":"${username}","validations":{"length":{"min":3,"max":255},"username-prohibited-characters":{},"up-username-not-idn-homograph":{}},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"email","displayName":"${email}","validations":{"email":{},"length":{"max":255}},"required":{"roles":["user"]},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"firstName","displayName":"${firstName}","validations":{"length":{"max":255},"person-name-prohibited-characters":{}},"required":{"roles":["user"]},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"lastName","displayName":"${lastName}","validations":{"length":{"max":255},"person-name-prohibited-characters":{}},"required":{"roles":["user"]},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"isLegacy","displayName":"${isLegacy}","validations":{"pattern":{"pattern":"^(true|false)$","error-message":"Value must be true or false."}},"annotations":{},"permissions":{"view":[],"edit":["admin"]},"multivalued":false},{"name":"isEmailMFAEnabled","displayName":"${isEmailMFAEnabled}","validations":{"pattern":{"pattern":"^(true|false)$","error-message":"Value must be true or false."}},"annotations":{},"permissions":{"view":[],"edit":["admin"]},"multivalued":false}]'

$kcadm update events/config -r $realm -s 'eventsListeners=["jboss-logging"]'

echo '
# Realm roles
'
$kcadm create roles -r $realm -s name=multi-tenancy-admin -s description="IAM Admin for all tenants"
$kcadm create roles -r $realm -s name=multi-tenancy-app -s description="Multi-tenancy capable application (does not need to log in to a specific tenant)"

echo '
# Clients
'
echo "* $api_client_id"
create_private_client "$api_client_id" "$api_client_secret" 'Authentication Layer API'
$kcadm add-roles -r $realm --uusername service-account-$api_client_id --cclientid realm-management \
  --rolename manage-users --rolename view-users --rolename query-users --rolename query-groups \
  --rolename manage-organizations --rolename view-organizations
$kcadm add-roles -r $realm --uusername service-account-$api_client_id --rolename multi-tenancy-admin

echo "* $end_to_end_client_id"
create_private_client "$end_to_end_client_id" "$end_to_end_client_secret" 'E2E Client'
$kcadm add-roles -r $realm --uusername service-account-$end_to_end_client_id --rolename realm-admin --cclientid realm-management
$kcadm add-roles -r $realm --uusername service-account-$end_to_end_client_id --rolename multi-tenancy-admin
end_to_end_client_uuid=$($kcadm get -r $realm clients -q clientId="$end_to_end_client_id" --fields id 2>/dev/null | jq -r '.[0].id')
echo "e2e client uuid: $end_to_end_client_uuid"
add_auth_layer_aud_mapper_to_client "$end_to_end_client_uuid" "$end_to_end_client_id"

echo "* $bff_client_id"
  # Client scopes: the defaults are in every token whatever the BFF asks for, so only what the
  # API needs: the subject and session (basic), roles, and acr. profile and email are optional,
  # for a BFF configured to request them (OIDC_SCOPES); web-origins, offline_access, phone,
  # address and the rest are not available to this client at all.
  # No client secret: the BFF authenticates with assertions signed by its private key
  # (private_key_jwt); Keycloak fetches the public key from the BFF's JWKS URL.
  # Every BFF origin that may sign in: the BFF, plus any in space-separated
  # `bff_extra_base_urls` (e.g. the e2e stack's BFF for a standard OpenID Connect provider).
  bff_redirect_uris=""
  bff_post_logout_uris=""
  for url in $bff_base_url ${bff_extra_base_urls:-}; do
    bff_redirect_uris+="${bff_redirect_uris:+,}\"$url/auth/callback\""
    bff_post_logout_uris+="${bff_post_logout_uris:+##}$url/"
  done

  bff_client_uuid=$($kcadm create -r $realm clients -i -f - <<<"
  {
    \"clientId\": \"$bff_client_id\",
    \"name\": \"BFF\",
    \"clientAuthenticatorType\": \"client-jwt\",
    \"publicClient\": false,
    \"standardFlowEnabled\": true,
    \"implicitFlowEnabled\": false,
    \"directAccessGrantsEnabled\": false,
    \"serviceAccountsEnabled\": false,
    \"frontchannelLogout\": false,
    \"fullScopeAllowed\": false,
    \"defaultClientScopes\": [\"basic\", \"roles\", \"acr\"],
    \"optionalClientScopes\": [\"profile\", \"email\"],
    \"redirectUris\": [$bff_redirect_uris],
    \"attributes\": {
      \"pkce.code.challenge.method\": \"S256\",
      \"post.logout.redirect.uris\": \"$bff_post_logout_uris\",
      \"backchannel.logout.url\": \"$bff_internal_url/auth/backchannel-logout\",
      \"backchannel.logout.session.required\": \"true\",
      \"use.jwks.url\": \"true\",
      \"jwks.url\": \"$bff_internal_url/.well-known/jwks.json\",
      \"token.endpoint.auth.signing.alg\": \"ES256\"
    }
  }")

  # The BFF forwards its users' access tokens to the API, so they must name the API as audience.
  # Access tokens only: ID tokens stay addressed to the BFF alone.
  $kcadm create -r $realm clients/$bff_client_uuid/protocol-mappers/models -f - <<EOF
    {
     "name": "$bff_client_id-auth-layer-aud",
     "protocol": "openid-connect",
     "protocolMapper": "oidc-audience-mapper",
     "config": {
       "included.client.audience": "$api_client_id",
       "id.token.claim": "false",
       "access.token.claim": "true"
     }
    }
EOF

  # Full scope is off: tokens carry only the roles mapped here, i.e. the ones the API acts on.
  $kcadm create -r $realm clients/$bff_client_uuid/scope-mappings/realm \
    -b "[$($kcadm get -r $realm roles/multi-tenancy-admin)]"

  echo "* test user"
  $kcadm create users -r $realm -s username=alice -s email=alice@example.com \
    -s firstName=Alice -s lastName=Test -s enabled=true -s emailVerified=true
  $kcadm set-password -r $realm --username alice --new-password test
