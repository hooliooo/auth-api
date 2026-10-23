//! Discovery and key loading over real HTTP, against a small local server that answers each
//! path with a scripted sequence of responses: how the verifier starts against a provider that
//! is still starting, misconfigured, or answering nonsense. (How the key fetch reports each kind
//! of failure is tested inside the crate, in `jwks.rs`.)

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use oidc::{
    OidcVerifier, OidcVerifierError,
    well_known::{Transport, WellKnownEndpointError},
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// The realm path the tests' issuer has on the local server.
const REALM: &str = "/realms/test";

/// Scripted responses by path; the last one of each path repeats.
type Routes = Arc<Mutex<HashMap<String, VecDeque<(u16, String)>>>>;

/// A local HTTP server answering each path from its script, counting requests per path.
struct TestServer {
    base: String,
    routes: Routes,
    hits: Arc<Mutex<HashMap<String, usize>>>,
}

impl TestServer {
    /// Starts a server on a free local port.
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (routes, hits): (Routes, Arc<Mutex<HashMap<String, usize>>>) = Default::default();
        let (r, h) = (routes.clone(), hits.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let (r, h) = (r.clone(), h.clone());
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buffer[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&request);
                    let path = text.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    *h.lock().unwrap().entry(path.clone()).or_default() += 1;
                    let (status, body) = {
                        let mut routes = r.lock().unwrap();
                        match routes.get_mut(&path) {
                            Some(script) if script.len() > 1 => script.pop_front().unwrap(),
                            Some(script) => script.front().cloned().unwrap(),
                            None => (404, String::new()),
                        }
                    };
                    let response = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self { base, routes, hits }
    }

    /// The issuer URL of the test realm on this server.
    fn issuer(&self) -> String {
        format!("{}{REALM}", self.base)
    }

    /// Answers `path` with `script`, in order, repeating the last response.
    fn script(&self, path: &str, script: Vec<(u16, String)>) {
        self.routes
            .lock()
            .unwrap()
            .insert(path.to_owned(), script.into());
    }

    /// How many requests `path` received.
    fn hits(&self, path: &str) -> usize {
        self.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }

    /// A discovery document for issuer `issuer`, with its keys on this server.
    fn document(&self, issuer: &str) -> String {
        let base = self.issuer();
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base}/auth"),
            "token_endpoint": format!("{base}/token"),
            "end_session_endpoint": format!("{base}/logout"),
            "jwks_uri": format!("{base}/certs"),
        })
        .to_string()
    }
}

/// The discovery document's path on the server.
fn discovery() -> String {
    format!("{REALM}/.well-known/openid-configuration")
}

/// The key set's path on the server.
fn certs() -> String {
    format!("{REALM}/certs")
}

/// A key set with one (placeholder) Ed25519 signing key.
fn key_set() -> String {
    json!({ "keys": [{
        "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": "k1",
        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }]})
    .to_string()
}

/// Starts a verifier against `server`'s test realm.
async fn verifier(server: &TestServer) -> Result<OidcVerifier<()>, OidcVerifierError> {
    verifier_at(&server.issuer()).await
}

/// Starts a verifier for issuer `issuer`, over plain HTTP (the local server has no TLS).
async fn verifier_at(issuer: &str) -> Result<OidcVerifier<()>, OidcVerifierError> {
    OidcVerifier::new(
        issuer,
        reqwest::Client::new(),
        "api".into(),
        Transport::AllowInsecureHttp,
    )
    .await
}

#[tokio::test]
async fn given_a_provider_still_starting_then_the_verifier_waits_and_then_starts() {
    let server = TestServer::start().await;
    let document = server.document(&server.issuer());
    server.script(
        &discovery(),
        vec![(503, String::new()), (503, String::new()), (200, document)],
    );
    server.script(&certs(), vec![(200, key_set())]);

    let started = Instant::now();
    let verifier = verifier(&server)
        .await
        .expect("starts once the provider answers");
    assert_eq!(server.hits(&discovery()), 3);
    // Waits of 0.5 s and 1 s before the second and third attempts.
    assert!(
        started.elapsed() >= Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(verifier.well_known_endpoint().issuer, server.issuer());
}

#[tokio::test]
async fn given_a_key_endpoint_still_starting_then_the_verifier_waits_for_it_too() {
    let server = TestServer::start().await;
    server.script(&discovery(), vec![(200, server.document(&server.issuer()))]);
    server.script(&certs(), vec![(503, String::new()), (200, key_set())]);

    assert!(verifier(&server).await.is_ok());
    assert_eq!(server.hits(&certs()), 2);
}

#[tokio::test]
async fn given_a_discovery_document_for_another_issuer_then_the_verifier_refuses_at_once() {
    let server = TestServer::start().await;
    server.script(
        &discovery(),
        vec![(
            200,
            server.document("https://elsewhere.example/realms/test"),
        )],
    );
    server.script(&certs(), vec![(200, key_set())]);

    let started = Instant::now();
    let result = verifier(&server).await;
    assert!(
        matches!(result, Err(OidcVerifierError::IssuerMismatch { .. })),
        "{:?}",
        result.err()
    );
    assert_eq!(
        server.hits(&discovery()),
        1,
        "a configuration mistake is not retried"
    );
    assert!(started.elapsed() < Duration::from_millis(400));
}

#[tokio::test]
async fn given_no_discovery_document_then_the_verifier_fails_at_once() {
    let server = TestServer::start().await;
    // Nothing scripted: every path answers 404.
    let result = verifier(&server).await;
    assert!(
        matches!(
            result,
            Err(OidcVerifierError::Discovery(
                WellKnownEndpointError::ErrorStatus(_)
            ))
        ),
        "{:?}",
        result.err()
    );
    assert_eq!(server.hits(&discovery()), 1, "a 404 is not retried");
}

#[tokio::test]
async fn given_a_discovery_document_that_is_not_json_then_the_verifier_fails_at_once() {
    let server = TestServer::start().await;
    server.script(&discovery(), vec![(200, "<html>sign in</html>".into())]);
    let result = verifier(&server).await;
    assert!(
        matches!(
            result,
            Err(OidcVerifierError::Discovery(
                WellKnownEndpointError::Malformed(_)
            ))
        ),
        "{:?}",
        result.err()
    );
    assert_eq!(server.hits(&discovery()), 1);
}

#[tokio::test]
async fn given_an_issuer_with_a_trailing_slash_then_discovery_still_finds_the_document() {
    let server = TestServer::start().await;
    server.script(&discovery(), vec![(200, server.document(&server.issuer()))]);
    server.script(&certs(), vec![(200, key_set())]);
    assert!(verifier_at(&format!("{}/", server.issuer())).await.is_ok());
}
