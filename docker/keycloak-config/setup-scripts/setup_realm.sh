#!/bin/bash
set -eu
source shared_functions.sh

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
  -s organizationsEnabled=true

$kcadm update realms/$realm -s attributes='{ "adminEventsExpiration": "0" }'

#### Keycloak SMTP configuration (Realm Settings -> Email)
$kcadm update realms/$realm -s smtpServer="{
         \"starttls\": \"false\",
         \"port\": \"$smtp_port\",
         \"host\": \"$smtp_host\",
         \"from\": \"$IAM_email\",
         \"fromDisplayName\": \"$IAM_email_display_name\",
         \"ssl\": \"false\"
     }"

# Adding isLegacy attribute to the user profile
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
$kcadm add-roles -r $realm --uusername service-account-$api_client_id --rolename realm-admin --cclientid realm-management
$kcadm add-roles -r $realm --uusername service-account-$api_client_id --rolename multi-tenancy-admin

echo "* $end_to_end_client_id"
create_private_client "$end_to_end_client_id" "$end_to_end_client_secret" 'E2E Client'
$kcadm add-roles -r $realm --uusername service-account-$end_to_end_client_id --rolename realm-admin --cclientid realm-management
$kcadm add-roles -r $realm --uusername service-account-$end_to_end_client_id --rolename multi-tenancy-admin
end_to_end_client_uuid=$($kcadm get -r $realm clients 2>/dev/null | jq -r '.[] | select(.clientId == "'"$end_to_end_client_id"'") | .id')
echo "e2e client uuid: $end_to_end_client_uuid"
add_auth_layer_aud_mapper_to_client "$end_to_end_client_uuid" "$end_to_end_client_id"
