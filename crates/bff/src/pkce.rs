use core::fmt;
use std::marker::PhantomData;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::digest::{self, Algorithm};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::random::{RandomUnvailable, random_token};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PkceError {
    #[error("Invalid character in PKCE component")]
    InvalidCharacters,
    #[error("Invalid length. Must be between 43 and 128 characters: Have '{0}' chars")]
    InvalidLength(usize),
}

/// The code verifier used during authentication via authorization code flow with Proof Key for Code Exchange (PKCE)
/// The string within the CodeVerifier is redacted by design to prevent leaks via logging
#[derive(Deserialize, Serialize)]
pub struct CodeVerifier(String);

impl CodeVerifier {
    /// Generate a new CodeVerifier with a randomized string
    pub fn new_random() -> Result<Self, RandomUnvailable> {
        let str = random_token()?;
        Ok(CodeVerifier(str))
    }

    /// Return the CodeVerifier as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Generates a code challenge with the specified algorithm derived from this CodeVerifier
    pub fn to_challenge<A: PkceAlgorithm>(&self) -> CodeChallenge<A> {
        CodeChallenge {
            challenge: A::hash(self.as_str()),
            _marker: PhantomData,
        }
    }
}

impl TryFrom<String> for CodeVerifier {
    type Error = PkceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !(43..=128).contains(&value.len()) {
            return Err(PkceError::InvalidLength(value.len()));
        }

        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
        {
            return Err(PkceError::InvalidCharacters);
        }

        Ok(Self(value))
    }
}

impl fmt::Debug for CodeVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CodeVerifier(----REDACTED----)")
    }
}

/// The code challenge for the authorization code flow with PKCE
pub struct CodeChallenge<A: PkceAlgorithm> {
    challenge: String,
    _marker: PhantomData<A>,
}

impl<A: PkceAlgorithm> CodeChallenge<A> {
    /// The code challenge as a string slice
    pub fn as_str(&self) -> &str {
        &self.challenge
    }

    /// The name of the algorithm used to create the code challenge
    pub fn name(&self) -> &'static str {
        A::NAME
    }
}

impl<A: PkceAlgorithm> fmt::Debug for CodeChallenge<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeChallenge")
            .field("challenge", &self.challenge)
            .field("method", &A::NAME)
            .finish()
    }
}

/// The algorithm used to hash the CodeVerifier into a CodeChallenge
pub trait PkceAlgorithm {
    /// Name of the algorithm
    const NAME: &'static str;

    /// The algorithm used for hashing
    fn algorithm() -> &'static Algorithm;

    fn hash(verifier: &str) -> String {
        let result = digest::digest(Self::algorithm(), verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(result.as_ref())
    }
}

pub struct S256;
impl PkceAlgorithm for S256 {
    const NAME: &'static str = "S256";
    fn algorithm() -> &'static Algorithm {
        &digest::SHA256
    }
}

pub struct PkceValidator;
impl PkceValidator {
    /// Verifies the code challenge with the code verifier
    pub fn verify<A: PkceAlgorithm>(
        verifier: &CodeVerifier,
        expected_challenge: &CodeChallenge<A>,
    ) -> bool {
        let challenge = verifier.to_challenge::<A>();

        challenge
            .as_str()
            .as_bytes()
            .ct_eq(expected_challenge.as_str().as_bytes())
            .unwrap_u8()
            == 1
    }
}

#[cfg(test)]
mod tests {
    use crate::pkce::{CodeVerifier, PkceError, PkceValidator, S256};

    #[test]
    fn given_a_code_verifier_when_generated_and_derived_from_output_then_it_should_succeed() {
        let verifier = CodeVerifier::new_random().unwrap();
        assert!((43..=128).contains(&verifier.as_str().len()));
        let result = CodeVerifier::try_from(verifier.as_str().to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn given_invalid_length_and_invalid_chars_when_try_from_is_called_then_it_should_fail() {
        assert_eq!(
            CodeVerifier::try_from("short_string".to_string()).unwrap_err(),
            PkceError::InvalidLength(12)
        );
        let invalid_input = "a".repeat(43) + "!";
        assert_eq!(
            CodeVerifier::try_from(invalid_input).unwrap_err(),
            PkceError::InvalidCharacters
        );
    }

    #[test]
    fn given_a_verifier_when_printing_then_it_should_be_redacted() {
        let verifier = CodeVerifier::new_random().unwrap();
        let str = format!("{:?}", verifier);
        assert!(!str.contains(verifier.as_str()));
        assert!(str.contains("----REDACTED----"));
    }

    #[test]
    fn given_a_verifier_when_generating_a_challenge_with_an_algorithm_then_it_should_be_correct() {
        let verifier = CodeVerifier::new_random().unwrap();
        let challenge = verifier.to_challenge::<S256>();

        assert_eq!(challenge.name(), "S256");
        assert!(PkceValidator::verify(&verifier, &challenge));
    }

    #[test]
    fn given_a_different_challenge_when_verifying_then_it_should_fail() {
        let verifier = CodeVerifier::new_random().unwrap();
        let other = CodeVerifier::new_random().unwrap();
        let other_challenge = other.to_challenge::<S256>();

        assert!(!PkceValidator::verify(&verifier, &other_challenge));
    }
}
