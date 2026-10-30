//! Encrypts values stored in Redis with a key derived from the cookie value they belong to,
//! so a Redis dump alone reveals nothing, and a value cannot be moved to another key or purpose.

use ring::{
    aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    hkdf::{HKDF_SHA256, Salt},
    rand::{SecureRandom, SystemRandom},
};
use std::sync::LazyLock;

use crate::random::RandomUnvailable;

/// What a sealed value is for. Part of the key and the authenticated data, so a value sealed
/// for one purpose never opens as another.
#[derive(Clone, Copy)]
pub enum Purpose {
    /// A sign-in in progress, sealed with its `state`.
    PendingLogin,
    /// A session, sealed with its session id.
    Session,
}

impl Purpose {
    /// The versioned label used as HKDF info and AEAD associated data.
    fn label(&self) -> &'static [u8] {
        match self {
            Purpose::PendingLogin => b"bff:pending-login:v1",
            Purpose::Session => b"bff:session:v1",
        }
    }
}

/// Fixed per application; built once because constructing a `Salt` precomputes an HMAC key.
static SALT: LazyLock<Salt> = LazyLock::new(|| Salt::new(HKDF_SHA256, b"bff-sealed-v1"));

/// The ChaCha20-Poly1305 key for `purpose`, derived from `secret` with HKDF-SHA256.
fn key_for(secret: &str, purpose: Purpose) -> LessSafeKey {
    let prk = SALT.extract(secret.as_bytes());
    let info = [purpose.label()];
    let okm = prk
        .expand(&info, &CHACHA20_POLY1305)
        .expect("ChaCha20-Poly1305 key length should be valid for HKDF-SHA256");
    LessSafeKey::new(UnboundKey::from(okm))
}

/// Encrypts `plaintext` for `purpose` under a key derived from `secret` (the cookie value).
/// Returns nonce, ciphertext and tag.
pub fn seal(secret: &str, purpose: Purpose, plaintext: &[u8]) -> Result<Vec<u8>, RandomUnvailable> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| RandomUnvailable)?;
    let mut buffer = plaintext.to_vec();
    key_for(secret, purpose)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(purpose.label()),
            &mut buffer,
        )
        .map_err(|_| RandomUnvailable)?;

    let mut sealed = nonce.to_vec();
    sealed.extend(buffer);
    Ok(sealed)
}

/// Decrypts `sealed` with the key for `secret` and `purpose`; `None` if it was sealed with
/// anything else or altered.
pub fn open(secret: &str, purpose: Purpose, sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < NONCE_LEN {
        return None;
    }

    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let mut buffer = ciphertext.to_vec();
    let plaintext = key_for(secret, purpose)
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).ok()?,
            Aad::from(purpose.label()),
            &mut buffer,
        )
        .ok()?;
    Some(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use crate::sealed::{Purpose, open, seal};

    #[test]
    fn given_a_sealed_value_when_opened_with_same_secret_and_purpose_then_it_should_be_the_same() {
        let sealed = seal("sid", Purpose::Session, b"payload").unwrap();
        assert_eq!(
            open("sid", Purpose::Session, &sealed).as_deref(),
            Some(&b"payload"[..])
        );
    }

    #[test]
    fn given_a_sealed_value_when_opened_with_another_secret_or_purpose_then_it_should_fail() {
        let sealed = seal("sid", Purpose::Session, b"payload").unwrap();
        assert!(open("other", Purpose::Session, &sealed).is_none());
        assert!(open("sid", Purpose::PendingLogin, &sealed).is_none());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open("sid", Purpose::Session, &tampered).is_none());
    }
}
