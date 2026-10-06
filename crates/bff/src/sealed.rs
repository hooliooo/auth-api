use ring::{
    aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    hkdf::{HKDF_SHA256, Salt},
    rand::{SecureRandom, SystemRandom},
};

use crate::random::RandomUnvailable;

#[derive(Clone, Copy)]
pub enum Purpose {
    PendingLogin,
    Session,
}

impl Purpose {
    fn label(&self) -> &'static [u8] {
        match self {
            Purpose::PendingLogin => b"bff:pending-login:v1",
            Purpose::Session => b"bff:session:v1",
        }
    }
}

fn key_for(secret: &str, purpose: Purpose) -> LessSafeKey {
    let prk = Salt::new(HKDF_SHA256, b"bff-sealed-v1").extract(secret.as_bytes());
    let info = [purpose.label()];
    let okm = prk
        .expand(&info, &CHACHA20_POLY1305)
        .expect("ChaCha20-Poly1305 key length should be valid for HKDF-SHA256");
    LessSafeKey::new(UnboundKey::from(okm))
}

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
