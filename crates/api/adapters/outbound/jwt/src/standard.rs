//! Any OpenID Connect provider issuing JWT access tokens (RFC 9068): roles in a top-level
//! `roles` claim, and no token type in the payload. RFC 9068 marks access tokens with
//! `typ: at+jwt` in the header instead, which not every provider sets; what keeps ID tokens out
//! is the audience, which must be the API's, never a client's.

use auth_core::application::authentication::Claims;
use oidc::{ProviderClaims, oidc::JwtVerificationError};
use serde_json::Value;

use crate::{claims_with_roles, roles_from};

/// Reads a standard access token's payload into [`Claims`].
pub struct StandardOidc;

impl ProviderClaims for StandardOidc {
    type Claims = Claims;

    fn claims(payload: Value) -> Result<Claims, JwtVerificationError> {
        let roles = roles_from(payload.get("roles"));
        claims_with_roles(&payload, &roles)
    }
}

#[cfg(test)]
mod tests {
    use auth_core::application::authorization::authorized_scope::AuthorizedScope;
    use oidc::{ProviderClaims, oidc::JwtVerificationError};
    use serde_json::json;

    use crate::standard::StandardOidc;

    #[test]
    fn given_an_admin_role_in_the_roles_claim_then_it_should_be_a_super_admin() {
        let payload = json!({ "azp": "web.client", "sub": "some-id", "roles": ["realm-admin"] });

        let claims = StandardOidc::claims(payload).unwrap();
        assert_eq!(claims.authorized_scope, AuthorizedScope::SuperAdmin);
        assert_eq!(claims.client_id, "web.client");
        assert_eq!(claims.user_id, "some-id");
    }

    #[test]
    fn given_roles_only_where_keycloak_puts_them_then_it_should_be_a_user() {
        let payload = json!({
            "client_id": "web.client", "sub": "some-id", "realm_access": { "roles": ["realm-admin"] }
        });

        let claims = StandardOidc::claims(payload).unwrap();
        assert_eq!(claims.authorized_scope, AuthorizedScope::User);
        assert_eq!(claims.client_id, "web.client");
    }

    #[test]
    fn given_no_user_id_when_parsed_then_it_should_be_an_error() {
        let result = StandardOidc::claims(json!({ "azp": "web.client" }));
        assert!(matches!(
            result,
            Err(JwtVerificationError::MissingClaim("sub"))
        ));
    }
}
