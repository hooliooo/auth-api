use auth_core::application::authentication::Claims;
use auth_core::application::authorization::AuthzContext;
use kern::application::ids::AuthorizedParty;
use uuid::Uuid;

use crate::error::authentication::JwtHeaderError;

/// Turns verified JWT claims into the core's authorization context.
/// This service identifies users by UUID; providers are free to use any subject format.
pub fn authz_context(claims: Claims) -> Result<AuthzContext, JwtHeaderError> {
    let Ok(user_id) = Uuid::try_from(claims.user_id) else {
        return Err(JwtHeaderError::UnsupportedSubject);
    };
    Ok(AuthzContext::new(
        Uuid::now_v7(),
        user_id,
        AuthorizedParty::new(claims.client_id),
        claims.authorized_scope,
    ))
}

#[cfg(test)]
mod tests {
    use auth_core::application::authentication::Claims;
    use auth_core::application::authorization::authorized_scope::AuthorizedScope;
    use uuid::Uuid;

    use super::authz_context;
    use crate::error::authentication::JwtHeaderError;

    fn claims(user_id: String) -> Claims {
        Claims {
            client_id: "test.client".to_string(),
            user_id,
            authorized_scope: AuthorizedScope::SuperAdmin,
        }
    }

    #[test]
    fn given_a_uuid_subject_when_converted_then_it_should_succeed() {
        let context = authz_context(claims(Uuid::now_v7().to_string()));
        assert!(context.is_ok());
    }

    #[test]
    fn given_a_non_uuid_subject_when_converted_then_it_should_be_rejected() {
        let context = authz_context(claims("not-a-uuid".to_string()));
        assert!(matches!(context, Err(JwtHeaderError::UnsupportedSubject)));
    }
}
