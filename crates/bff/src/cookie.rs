//! Reading and writing the BFF's cookies.

use axum::http::{
    HeaderMap, HeaderValue,
    header::{COOKIE, InvalidHeaderValue},
};

use crate::crypto::hash_key;

/// Prefix of the per-sign-in login cookies; see [`login_cookie`].
pub const LOGIN: &str = "__Host-bff-login";
/// Name of the session cookie; its value is the session id.
pub const SESSION: &str = "__Host-bff";

/// The login cookie of one sign-in, named after its `state`, so sign-ins started in two tabs
/// do not overwrite each other's cookie.
pub fn login_cookie(state: &str) -> String {
    format!("{LOGIN}-{}", &hash_key(state)[..16])
}

/// The value of cookie `name` in the request's `headers`, if sent.
pub fn get(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}

/// A `Set-Cookie` value for cookie `name` holding `value`, with `same_site` (`Strict` or
/// `Lax`) and a lifetime of `max_age` seconds. Always `HttpOnly`, `Secure` and `Path=/`.
pub fn set(
    name: &str,
    value: &str,
    same_site: &str,
    max_age: u64,
) -> Result<HeaderValue, InvalidHeaderValue> {
    Ok(HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; Secure; Samesite={same_site}; Max-Age={max_age}"
    )))?
}

/// A `Set-Cookie` value that deletes cookie `name`; `same_site` must match how it was set.
pub fn clear(name: &str, same_site: &str) -> Result<HeaderValue, InvalidHeaderValue> {
    set(name, "", same_site, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_two_states_then_their_login_cookies_differ_and_are_stable() {
        assert_ne!(login_cookie("state-a"), login_cookie("state-b"));
        assert_eq!(login_cookie("state-a"), login_cookie("state-a"));
        assert!(login_cookie("state-a").starts_with("__Host-bff-login-"));
    }
}
