//! Test-only API behind the BFF proxy. `/echo/...` answers with what it received, so tests can
//! see exactly which headers the BFF forwarded; `/slow` streams one chunk a second.

use std::{collections::BTreeMap, time::Duration};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::Query,
    http::{HeaderMap, HeaderValue, Method, Uri, header::SET_COOKIE},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use futures_util::stream;
use serde_json::json;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/echo", any(echo))
        .route("/echo/{*rest}", any(echo))
        .route("/slow", get(slow));
    let listener = TcpListener::bind("0.0.0.0:8000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn echo(method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let headers: BTreeMap<String, String> = headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let mut response = Json(json!({
        "method": method.as_str(),
        "path": uri.path(),
        "query": uri.query(),
        "headers": headers,
        "body": String::from_utf8_lossy(&body),
    }))
    .into_response();
    // The BFF must strip this before it reaches the browser.
    response
        .headers_mut()
        .insert(SET_COOKIE, HeaderValue::from_static("planted=1; Path=/"));
    response
        .headers_mut()
        .insert("x-echo", HeaderValue::from_static("1"));
    response
}

/// `?secs=N`: N chunks, one per second, so the total exceeds any short total timeout while
/// the connection is never silent for long.
async fn slow(Query(query): Query<BTreeMap<String, String>>) -> Response {
    let secs: u64 = query.get("secs").and_then(|s| s.parse().ok()).unwrap_or(12);
    let chunks = stream::unfold(0, move |sent| async move {
        if sent == secs {
            return None;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        Some((
            Ok::<_, std::io::Error>(Bytes::from(format!("{sent}\n"))),
            sent + 1,
        ))
    });
    Body::from_stream(chunks).into_response()
}
