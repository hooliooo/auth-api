//! What is specific to Keycloak: which claims name the client and user, and the shape of its
//! roles claim.
//!
//! Verification is plain OIDC and lives in [`crate::oidc`]. Supporting another provider means
//! another file like this one — a claims reader and an alias — not another verifier.

use std::collections::HashSet;

use auth_core::application::{
    authentication::Claims, authorization::authorized_scope::AuthorizedScope,
};
use kern::application::role::Role;
use oidc::{OidcJwtVerifier, ProviderClaims, oidc::JwtVerificationError};
use serde_json::Value;

/// Where Keycloak publishes the realm roles of the token's subject.
const REALM_ROLES_POINTER: &str = "/realm_access/roles";

/// Keycloak's `typ` for access tokens. ID, refresh and logout tokens are signed by the same
/// realm keys and can carry the same audience, so the type is what keeps them out.
const ACCESS_TOKEN_TYPE: &str = "Bearer";

/// The Keycloak realm roles that grant unrestricted access.
const REALM_ADMIN_ROLE: &str = "realm-admin";
const MULTI_TENANCY_ADMIN_ROLE: &str = "multi-tenancy-admin";

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

        // `azp` names the client in every token; `client_id` only appears in the tokens of
        // service accounts, so it is the fallback, not the source
        let client_id = ["azp", "client_id"]
            .into_iter()
            .find_map(|claim| payload.get(claim).and_then(Value::as_str))
            .ok_or(JwtVerificationError::MissingClaim("azp or client_id"))?;

        let user_id = payload
            .get("sub")
            .and_then(Value::as_str)
            .ok_or(JwtVerificationError::MissingClaim("sub"))?;

        let realm_roles: HashSet<Role> = payload
            .pointer(REALM_ROLES_POINTER)
            .and_then(|roles| roles.as_array())
            .map(|roles| {
                roles
                    .iter()
                    .filter_map(|value| value.as_str())
                    .map(|str| Role::new(str.to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        let is_super_admin = realm_roles.contains(REALM_ADMIN_ROLE)
            || realm_roles.contains(MULTI_TENANCY_ADMIN_ROLE);
        let authorized_scope = if is_super_admin {
            AuthorizedScope::SuperAdmin
        } else {
            AuthorizedScope::User
        };

        Ok(Claims {
            user_id: user_id.to_owned(),
            client_id: client_id.to_owned(),
            authorized_scope,
        })
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
