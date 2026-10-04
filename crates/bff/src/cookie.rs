use axum::http::{
    HeaderMap, HeaderValue,
    header::{COOKIE, InvalidHeaderValue},
};

pub const LOGIN: &str = "__Host-bff-login";
pub const SESSION: &str = "__Host-bff";

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

pub fn clear(name: &str, same_site: &str) -> Result<HeaderValue, InvalidHeaderValue> {
    set(name, "", same_site, 0)
}

#[cfg(test)]
mod tests {}
