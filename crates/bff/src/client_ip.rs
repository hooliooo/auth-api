//! Works out which IP address a request came from, for rate limiting and for the API.

use std::net::{IpAddr, SocketAddr};

use axum::http::{HeaderMap, HeaderName};

/// The client's address: the configured header (e.g. `cf-connecting-ip` behind Cloudflare)
/// when it holds a valid IP, otherwise the connection's peer address.
///
/// Only configure the header if every request reaches the BFF through that proxy; anyone who
/// can connect to the BFF directly could otherwise pick their own address.
pub fn client_ip(headers: &HeaderMap, peer: SocketAddr, header: Option<&HeaderName>) -> IpAddr {
    header
        .and_then(|name| headers.get(name))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| peer.ip())
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    const PEER: &str = "172.18.0.1:40000";

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn given_a_configured_header_with_an_ip_then_it_is_used() {
        let name = HeaderName::from_static("cf-connecting-ip");
        let ip = client_ip(&headers("203.0.113.7"), PEER.parse().unwrap(), Some(&name));
        assert_eq!(ip, "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn given_no_configured_header_then_the_header_is_ignored() {
        let ip = client_ip(&headers("203.0.113.7"), PEER.parse().unwrap(), None);
        assert_eq!(ip, "172.18.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn given_a_header_that_is_not_an_ip_then_the_peer_is_used() {
        let name = HeaderName::from_static("cf-connecting-ip");
        let ip = client_ip(&headers("not-an-ip"), PEER.parse().unwrap(), Some(&name));
        assert_eq!(ip, "172.18.0.1".parse::<IpAddr>().unwrap());
    }
}
