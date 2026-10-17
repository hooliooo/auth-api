//! What is specific to Keycloak: it marks token types in `typ`, and puts realm roles under
//! `realm_access`.

use auth_core::application::authentication::Claims;
use oidc::{OidcJwtVerifier, ProviderClaims, oidc::JwtVerificationError};
use serde_json::Value;

use crate::{claims_with_roles, roles_from};

/// Where Keycloak publishes the realm roles of the token's subject.
const REALM_ROLES_POINTER: &str = "/realm_access/roles";

/// Keycloak's `typ` for access tokens. ID, refresh and logout tokens are signed by the same
/// realm keys and can carry the same audience, so the type is what keeps them out.
const ACCESS_TOKEN_TYPE: &str = "Bearer";

pub type KeycloakJwtVerifier = OidcJwtVerifier<Keycloak>;

/// Reads Keycloak's token payload into [`Claims`].
pub struct Keycloak;

impl ProviderClaims for Keycloak {
    type Claims = Claims;

    fn claims(payload: Value) -> Result<Claims, JwtVerificationError> {
        let token_type = payload.get("typ").and_then(Value::as_str);
        if token_type != Some(ACCESS_TOKEN_TYPE) {
            return Err(JwtVerificationError::Invalid(format!(
                "not an access token (typ {token_type:?})"
            )));
        }
        let realm_roles = roles_from(payload.pointer(REALM_ROLES_POINTER));
        claims_with_roles(&payload, &realm_roles)
    }
}

#[cfg(test)]
mod tests {
    use auth_core::application::authorization::authorized_scope::AuthorizedScope;
    use oidc::{ProviderClaims, oidc::JwtVerificationError};
    use serde_json::json;

    use crate::keycloak::Keycloak;

    #[test]
    fn given_a_token_that_is_not_an_access_token_then_it_should_be_refused() {
        for token_type in [Some("ID"), Some("Refresh"), Some("Logout"), None] {
            let mut payload = json!({
                "azp": "web.client", "sub": "some-id", "realm_access": { "roles": ["realm-admin"] }
            });
            if let Some(token_type) = token_type {
                payload["typ"] = token_type.into();
            }
            assert!(
                matches!(
                    Keycloak::claims(payload),
                    Err(JwtVerificationError::Invalid(_))
                ),
                "typ {token_type:?} must be refused"
            );
        }
    }

    #[test]
    fn given_a_jwt_when_parsed_it_should_include_azp_or_client_id() {
        let payload = json!({
            "typ": "Bearer", "azp": "web.client", "sub": "some-id", "realm_access": { "roles": ["realm-admin"] }
        });

        let claims = Keycloak::claims(payload).unwrap();
        assert_eq!(claims.client_id, "web.client");

        let payload = json!({
            "typ": "Bearer", "client_id": "web.client-a", "sub": "some-id", "realm_access": { "roles": ["realm-admin"] }
        });

        let claims = Keycloak::claims(payload).unwrap();
        assert_eq!(claims.client_id, "web.client-a");
    }

    #[test]
    fn given_a_realm_admin_jwt_when_parsed_then_it_should_be_a_super_admin() {
        let payload = json!({
            "typ": "Bearer", "azp": "web.client", "sub": "some-id", "realm_access": { "roles": ["realm-admin"] }
        });

        let claims = Keycloak::claims(payload).unwrap();
        assert_eq!(claims.authorized_scope, AuthorizedScope::SuperAdmin);
        assert_eq!(claims.user_id, "some-id");
    }

    #[test]
    fn given_a_multi_tenancy_admin_jwt_when_parsed_then_it_should_be_a_super_admin() {
        let payload = json!({
            "typ": "Bearer", "azp": "web.client", "sub": "some-id-a", "realm_access": { "roles": ["multi-tenancy-admin"] }
        });

        let claims = Keycloak::claims(payload).unwrap();
        assert_eq!(claims.authorized_scope, AuthorizedScope::SuperAdmin);
        assert_eq!(claims.user_id, "some-id-a");
    }

    #[test]
    fn given_no_admin_jwt_when_parsed_then_it_should_be_a_user() {
        let payload = json!({
            "typ": "Bearer", "azp": "web.client", "sub": "some-id-b", "realm_access": { "roles": ["role-b"] }
        });

        let claims = Keycloak::claims(payload).unwrap();
        assert_eq!(claims.authorized_scope, AuthorizedScope::User);
        assert_eq!(claims.user_id, "some-id-b");
    }

    #[test]
    fn given_no_user_id_when_parsed_then_it_should_be_an_error() {
        let payload = json!({
            "typ": "Bearer", "azp": "web.client", "realm_access": { "roles": ["role-b"] }
        });

        let result = Keycloak::claims(payload);
        assert!(matches!(
            result,
            Err(JwtVerificationError::MissingClaim("sub"))
        ));
    }

    #[test]
    fn given_no_azp_or_client_id_when_parsed_then_it_should_be_an_error() {
        let payload = json!({
            "typ": "Bearer", "sub": "some-id-b", "realm_access": { "roles": ["role-b"] }
        });

        let result = Keycloak::claims(payload);
        assert!(matches!(
            result,
            Err(JwtVerificationError::MissingClaim("azp or client_id"))
        ));
    }
}
