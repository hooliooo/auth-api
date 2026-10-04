use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Could not generate random")]
pub struct RandomUnvailable;

/// Generates a random string encoded in base64
pub fn random_token() -> Result<String, RandomUnvailable> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| RandomUnvailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
