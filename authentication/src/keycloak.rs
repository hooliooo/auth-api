//! What is specific to Keycloak: the shape of its roles claim.
//!
//! Verification is plain OIDC and lives in [`crate::oidc`]. Supporting another provider means
//! another file like this one — a claims type and an alias — not another verifier.

use std::collections::HashSet;

use auth_core::domain::authorization::authorized_scope::AuthorizedScope;
use kern::application::role::Role;
use serde_json::Value;

use crate::{
    claims::Claims,
    error::JwtVerificationError,
    oidc::{OidcJwtVerifier, ProviderClaims},
    verifier::ClaimsExtractor,
};

/// Where Keycloak publishes the realm roles of the token's subject.
const REALM_ROLES_POINTER: &str = "/realm_access/roles";

/// The Keycloak realm role that grants unrestricted access.
const REALM_ADMIN_ROLE: &str = "realm-admin";
const MULTI_TENANCY_ADMIN_ROLE: &str = "multi-tenancy-admin";

pub type KeycloakJwtVerifier = OidcJwtVerifier<KeycloakClaims>;

/// The payload of a verified Keycloak token, before it is read into [`Claims`].
#[derive(Clone, Debug)]
pub struct KeycloakClaims(Value);

impl ProviderClaims for KeycloakClaims {
    fn from_payload(payload: Value) -> Self {
        Self(payload)
    }
}

impl ClaimsExtractor for KeycloakClaims {
    fn extract(self: Box<Self>) -> Result<Claims, JwtVerificationError> {
        let payload = self.0;

        let client_id = payload
            .get("client_id")
            .and_then(Value::as_str)
            .ok_or(JwtVerificationError::MissingClaim("client_id"))?;

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
            client_id: client_id.to_owned(),
            user_id: user_id.to_owned(),
            authorized_scope,
        })
    }
}
