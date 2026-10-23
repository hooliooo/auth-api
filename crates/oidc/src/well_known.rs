//! The metadata derived from the /.well-known/openid-configuration endpoint

use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;

/// The path OIDC Discovery 1.0 mandates for the document, relative to the issuer.
const DISCOVERY_PATH: &str = ".well-known/openid-configuration";

/// A failure reading the discovery document at startup.
#[derive(Debug, Error)]
pub enum WellKnownEndpointError {
    /// The connection failed.
    #[error("Could not reach the well-known endpoint: {0}")]
    Unreachable(reqwest::Error),
    /// The endpoint answered with an error status.
    #[error("The well-known endpoint returned an error: {0}")]
    ErrorStatus(reqwest::Error),
    /// The body is not a discovery document.
    #[error("The well-known endpoint is not valid JSON: {0}")]
    Malformed(reqwest::Error),
}

/// The discovery document served from `/.well-known/openid-configuration`.
#[derive(Clone, Debug, Deserialize)]
pub struct WellKnownEndpoint {
    /// The issuer tokens must name in `iss`.
    pub issuer: String,
    /// Where the browser signs in.
    pub authorization_endpoint: String,
    /// Where codes and refresh tokens are exchanged.
    pub token_endpoint: String,
    /// Where the browser signs out (RP-Initiated Logout); not every provider publishes one.
    pub end_session_endpoint: Option<String>,
    /// The provider's public signing keys.
    pub jwks_uri: String,
    /// Where tokens are revoked (RFC 7009); not every provider publishes one.
    pub revocation_endpoint: Option<String>,
}

impl WellKnownEndpoint {
    /// Reads the discovery document of `issuer_url` (e.g.
    /// `https://keycloak.example.com/realms/some-realm`) with `client`; the well-known path is
    /// appended here.
    pub async fn fetch(client: &Client, issuer_url: &str) -> Result<Self, WellKnownEndpointError> {
        let url = format!("{}/{}", issuer_url.trim_end_matches("/"), DISCOVERY_PATH);

        client
            .get(url)
            .send()
            .await
            .map_err(WellKnownEndpointError::Unreachable)?
            .error_for_status()
            .map_err(WellKnownEndpointError::ErrorStatus)?
            .json()
            .await
            .map_err(WellKnownEndpointError::Malformed)
    }

    /// Requires every published endpoint to satisfy `transport`, including the ones only the
    /// browser follows.
    pub(crate) fn check_transport(&self, transport: Transport) -> Result<(), InsecureUrlError> {
        transport.check("authorization_endpoint", &self.authorization_endpoint)?;
        transport.check("token_endpoint", &self.token_endpoint)?;
        transport.check("jwks_uri", &self.jwks_uri)?;
        for (name, endpoint) in [
            ("end_session_endpoint", &self.end_session_endpoint),
            ("revocation_endpoint", &self.revocation_endpoint),
        ] {
            if let Some(endpoint) = endpoint {
                transport.check(name, endpoint)?;
            }
        }
        Ok(())
    }
}

/// A provider URL is not HTTPS and plain HTTP was not allowed.
#[derive(Debug, Error)]
#[error("The provider's {name} '{url}' is not HTTPS")]
pub struct InsecureUrlError {
    /// Which URL, e.g. `jwks_uri`.
    name: &'static str,
    /// The URL itself.
    url: String,
}

/// Which URL schemes the provider may use. Over plain HTTP anyone on the network path can
/// swap the signing keys or read tokens, so HTTP is only for local development.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    /// Only `https://` provider URLs.
    #[default]
    HttpsOnly,
    /// Accepts `http://` provider URLs, e.g. a Keycloak container in a dev stack.
    AllowInsecureHttp,
}

impl Transport {
    /// Refuses `url`, reported as `name`, unless it is HTTPS or this policy allows HTTP.
    pub(crate) fn check(self, name: &'static str, url: &str) -> Result<(), InsecureUrlError> {
        let scheme = reqwest::Url::parse(url)
            .map(|url| url.scheme().to_owned())
            .unwrap_or_default();
        match (scheme.as_str(), self) {
            ("https", _) | ("http", Transport::AllowInsecureHttp) => Ok(()),
            _ => Err(InsecureUrlError {
                name,
                url: url.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    /// A discovery document with every endpoint under `base`.
    fn document(base: &str) -> Value {
        json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/auth"),
            "token_endpoint": format!("{base}/token"),
            "end_session_endpoint": format!("{base}/logout"),
            "jwks_uri": format!("{base}/certs"),
            "revocation_endpoint": format!("{base}/revoke"),
        })
    }

    /// `document` parsed.
    fn parse(document: Value) -> Result<WellKnownEndpoint, serde_json::Error> {
        serde_json::from_value(document)
    }

    #[test]
    fn given_a_document_without_logout_or_revocation_endpoints_then_it_parses() {
        let mut doc = document("https://idp.example");
        let fields = doc.as_object_mut().unwrap();
        fields.remove("end_session_endpoint");
        fields.remove("revocation_endpoint");
        let endpoints = parse(doc).unwrap();
        assert_eq!(endpoints.end_session_endpoint, None);
        assert_eq!(endpoints.revocation_endpoint, None);
    }

    #[test]
    fn given_a_document_missing_a_required_endpoint_then_it_does_not_parse() {
        for field in [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
        ] {
            let mut doc = document("https://idp.example");
            doc.as_object_mut().unwrap().remove(field);
            assert!(parse(doc).is_err(), "{field} is required");
        }
    }

    #[test]
    fn given_https_only_then_any_plain_http_endpoint_is_refused_the_optional_ones_included() {
        assert!(
            parse(document("https://idp.example"))
                .unwrap()
                .check_transport(Transport::HttpsOnly)
                .is_ok()
        );
        for field in [
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "end_session_endpoint",
            "revocation_endpoint",
        ] {
            let mut doc = document("https://idp.example");
            doc[field] = json!("http://idp.example/downgraded");
            let error = parse(doc)
                .unwrap()
                .check_transport(Transport::HttpsOnly)
                .unwrap_err();
            assert_eq!(error.name, field);
        }
    }

    #[test]
    fn given_plain_http_allowed_then_http_endpoints_pass() {
        let endpoints = parse(document("http://keycloak:8080/realms/test")).unwrap();
        assert!(
            endpoints
                .check_transport(Transport::AllowInsecureHttp)
                .is_ok()
        );
        assert!(endpoints.check_transport(Transport::HttpsOnly).is_err());
    }

    #[test]
    fn given_a_url_that_is_neither_https_nor_allowed_http_then_it_is_refused() {
        for transport in [Transport::HttpsOnly, Transport::AllowInsecureHttp] {
            for url in [
                "ftp://idp.example",
                "not a url",
                "",
                "idp.example/realms/test",
            ] {
                assert!(
                    transport.check("issuer", url).is_err(),
                    "{url} with {transport:?}"
                );
            }
            assert!(transport.check("issuer", "https://idp.example").is_ok());
        }
    }
}
