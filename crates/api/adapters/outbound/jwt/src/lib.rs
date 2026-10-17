//! Reads verified access tokens into [`Claims`]. Verification is plain OIDC and lives in the
//! `oidc` crate; what differs between providers is only where the roles are and how token types
//! are marked, so each provider is a claims reader: [`standard`] for any OpenID Connect
//! provider, [`keycloak`] for Keycloak. [`IdentityProvider`] picks one at startup.

use std::{collections::HashSet, sync::Arc};

use auth_core::application::{
    authentication::Claims, authorization::authorized_scope::AuthorizedScope,
};
use kern::application::role::Role;
use oidc::{
    OidcJwtVerifier, OidcSetupError, Transport,
    oidc::{JwtVerificationError, JwtVerifier},
};
use serde_json::Value;

pub mod keycloak;
pub mod standard;

/// The roles that grant unrestricted access.
const REALM_ADMIN_ROLE: &str = "realm-admin";
const MULTI_TENANCY_ADMIN_ROLE: &str = "multi-tenancy-admin";

/// The identity provider whose access tokens the API accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityProvider {
    /// Any OpenID Connect provider issuing JWT access tokens: [`standard::StandardOidc`].
    StandardOidc,
    /// Keycloak: [`keycloak::Keycloak`].
    Keycloak,
}

impl IdentityProvider {
    /// The provider `setting` (the value of `IDENTITY_PROVIDER`) names: `oidc` or `keycloak`;
    /// `None` for anything else. There is no default: a Keycloak deployment that fell back to
    /// `oidc` would silently stop checking token types.
    pub fn from_setting(setting: &str) -> Option<Self> {
        match setting {
            "oidc" => Some(Self::StandardOidc),
            "keycloak" => Some(Self::Keycloak),
            _ => None,
        }
    }

    /// A verifier for this provider at `issuer_url`, discovered with `client`, accepting
    /// access tokens for `audience` over the URLs `transport` allows.
    pub async fn verifier(
        self,
        issuer_url: &str,
        client: reqwest::Client,
        audience: String,
        transport: Transport,
    ) -> Result<Arc<dyn JwtVerifier<Claims = Claims>>, OidcSetupError> {
        Ok(match self {
            Self::StandardOidc => Arc::new(
                OidcJwtVerifier::<standard::StandardOidc>::new(
                    issuer_url, client, audience, transport,
                )
                .await?,
            ),
            Self::Keycloak => Arc::new(
                OidcJwtVerifier::<keycloak::Keycloak>::new(issuer_url, client, audience, transport)
                    .await?,
            ),
        })
    }
}

/// The strings in JSON array `roles` as roles; none for anything else.
fn roles_from(roles: Option<&Value>) -> HashSet<Role> {
    roles
        .and_then(Value::as_array)
        .map(|roles| {
            roles
                .iter()
                .filter_map(Value::as_str)
                .map(|role| Role::new(role.to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

/// [`Claims`] from a verified access token's `payload` whose subject holds `roles`.
fn claims_with_roles(
    payload: &Value,
    roles: &HashSet<Role>,
) -> Result<Claims, JwtVerificationError> {
    // `azp` names the client in OpenID Connect tokens; `client_id` (RFC 9068) is the fallback,
    // e.g. for Keycloak service accounts.
    let client_id = ["azp", "client_id"]
        .into_iter()
        .find_map(|claim| payload.get(claim).and_then(Value::as_str))
        .ok_or(JwtVerificationError::MissingClaim("azp or client_id"))?;

    let user_id = payload
        .get("sub")
        .and_then(Value::as_str)
        .ok_or(JwtVerificationError::MissingClaim("sub"))?;

    let is_super_admin =
        roles.contains(REALM_ADMIN_ROLE) || roles.contains(MULTI_TENANCY_ADMIN_ROLE);
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

#[cfg(test)]
mod tests {
    use crate::IdentityProvider;

    #[test]
    fn given_a_setting_then_it_names_the_provider() {
        assert_eq!(
            IdentityProvider::from_setting("oidc"),
            Some(IdentityProvider::StandardOidc)
        );
        assert_eq!(
            IdentityProvider::from_setting("keycloak"),
            Some(IdentityProvider::Keycloak)
        );
        for setting in ["okta", "", "Keycloak"] {
            assert_eq!(IdentityProvider::from_setting(setting), None, "{setting:?}");
        }
    }
}
