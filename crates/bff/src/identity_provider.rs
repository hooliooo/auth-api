//! What the BFF needs to know about its identity provider beyond standard OpenID Connect: how
//! ID tokens are marked, whether token responses say how long the provider's session lasts,
//! and how a session is ended there. Chosen with `IDENTITY_PROVIDER`.

use crate::{env, error::StartupError};

/// Keycloak's `typ` for ID tokens.
const KEYCLOAK_ID_TOKEN_TYPE: &str = "ID";

/// How the BFF ends a session at the provider when the user logs out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Logout {
    /// Server to server: the session's refresh token, with client authentication, to the
    /// end-session endpoint (Keycloak). The browser then goes straight to the app.
    RefreshTokenAtEndSession,
    /// Revoke the refresh token (RFC 7009), then send the browser to the provider's
    /// end-session page (RP-Initiated Logout), where the provider's own session ends.
    RevokeThenBrowser,
}

/// The identity provider the BFF signs users in with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityProvider {
    /// Any OpenID Connect provider, using only what the standards define.
    StandardOidc,
    /// Keycloak: marks token types in `typ`, reports its session lifetime as
    /// `refresh_expires_in`, and ends sessions with a refresh token.
    Keycloak,
}

impl IdentityProvider {
    /// Reads the required `IDENTITY_PROVIDER`: `oidc` or `keycloak`. There is no default: a
    /// Keycloak deployment that fell back to `oidc` would silently drop Keycloak's checks.
    pub fn from_env() -> Result<Self, StartupError> {
        Self::from_setting(&env::env("IDENTITY_PROVIDER")?)
    }

    /// The provider `setting` names.
    fn from_setting(setting: &str) -> Result<Self, StartupError> {
        match setting {
            "oidc" => Ok(Self::StandardOidc),
            "keycloak" => Ok(Self::Keycloak),
            _ => Err(StartupError::InvalidSetting("IDENTITY_PROVIDER")),
        }
    }

    /// Whether an ID token with type claim `typ` can be an ID token. Standard ID tokens carry
    /// no type; they come straight from the token endpoint, and the audience and nonce checks
    /// keep other tokens out. Keycloak signs every token type with the same keys, so there the
    /// type must say `ID`.
    pub fn is_id_token(self, typ: Option<&str>) -> bool {
        match self {
            Self::StandardOidc => true,
            Self::Keycloak => typ == Some(KEYCLOAK_ID_TOKEN_TYPE),
        }
    }

    /// How long the provider's session lasts after a token response with
    /// `refresh_expires_in`, if the provider says; only Keycloak does.
    pub fn session_lifetime_secs(self, refresh_expires_in: Option<u64>) -> Option<u64> {
        match self {
            Self::StandardOidc => None,
            Self::Keycloak => refresh_expires_in,
        }
    }

    /// How a session ends at this provider.
    pub fn logout(self) -> Logout {
        match self {
            Self::StandardOidc => Logout::RevokeThenBrowser,
            Self::Keycloak => Logout::RefreshTokenAtEndSession,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_a_setting_then_it_names_the_provider() {
        assert_eq!(
            IdentityProvider::from_setting("oidc").unwrap(),
            IdentityProvider::StandardOidc
        );
        assert_eq!(
            IdentityProvider::from_setting("keycloak").unwrap(),
            IdentityProvider::Keycloak
        );
        for setting in ["okta", "", "Keycloak"] {
            assert!(
                IdentityProvider::from_setting(setting).is_err(),
                "{setting:?}"
            );
        }
    }

    #[test]
    fn given_keycloak_then_only_tokens_typed_id_are_id_tokens() {
        let keycloak = IdentityProvider::Keycloak;
        assert!(keycloak.is_id_token(Some("ID")));
        for typ in [Some("Bearer"), Some("Logout"), None] {
            assert!(!keycloak.is_id_token(typ), "typ {typ:?}");
        }
    }

    #[test]
    fn given_a_standard_provider_then_id_tokens_need_no_type() {
        assert!(IdentityProvider::StandardOidc.is_id_token(None));
    }

    #[test]
    fn given_a_standard_provider_then_it_reports_no_session_lifetime_and_logs_out_by_revoking() {
        let standard = IdentityProvider::StandardOidc;
        assert_eq!(standard.session_lifetime_secs(Some(600)), None);
        assert_eq!(standard.logout(), Logout::RevokeThenBrowser);
        let keycloak = IdentityProvider::Keycloak;
        assert_eq!(keycloak.session_lifetime_secs(Some(600)), Some(600));
        assert_eq!(keycloak.logout(), Logout::RefreshTokenAtEndSession);
    }
}
