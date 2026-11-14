//! Error messages that keep their causes, for logs and error values in both services.

/// `error` followed by each of its causes, separated by `: `. reqwest's own message leaves the
/// cause out, such as a server certificate signed by an authority this machine does not trust,
/// and Redis's leaves out why a connection failed.
pub fn with_causes(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use thiserror::Error;

    use super::with_causes;

    #[derive(Debug, Error)]
    #[error("error sending request")]
    struct Outer(#[source] Middle);

    #[derive(Debug, Error)]
    #[error("client error (Connect)")]
    struct Middle(#[source] std::io::Error);

    #[test]
    fn given_an_error_with_causes_then_every_cause_is_described() {
        let error = Outer(Middle(std::io::Error::other(
            "invalid peer certificate: UnknownIssuer",
        )));
        assert_eq!(
            with_causes(&error),
            "error sending request: client error (Connect): invalid peer certificate: UnknownIssuer"
        );
    }
}
