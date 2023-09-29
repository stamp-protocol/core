use chacha20poly1305::aead::{Aead, NewAead};
use crate::{
    error::{Error, Result},
    util::ser::{Binary, BinarySecret, BinaryVec, SerdeBinary},
};
use rand::{RngCore, rngs::OsRng};
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// A symmetric encryption key nonce
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum SecretKeyNonce {
    #[rasn(tag(0))]
    XChaCha20Poly1305(Binary<24>),
}

/// A symmetric encryption key
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum SecretKey {
    #[rasn(tag(0))]
    XChaCha20Poly1305(BinarySecret<32>),
}

/// A self-describing, encrypted object that can be opened with the right key.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Sealed {
    /// Our heroic nonce
    #[rasn(tag(0))]
    nonce: SecretKeyNonce,
    /// The ciphertext
    #[rasn(tag(1))]
    ciphertext: BinaryVec,
}

impl Sealed {
    fn new(nonce: SecretKeyNonce, ciphertext: Vec<u8>) -> Self {
        Self {
            nonce,
            ciphertext: BinaryVec::from(ciphertext),
        }
    }
}

impl SerdeBinary for Sealed {}

impl SecretKey {
    /// Create a new xchacha20poly1305 key
    pub fn new_xchacha20poly1305() -> Result<Self> {
        let mut randbuf = [0u8; 32];
        OsRng.fill_bytes(&mut randbuf);
        Ok(Self::XChaCha20Poly1305(BinarySecret::new(randbuf)))
    }

    /// Try to create a SecretKey from a byte slice
    pub fn new_xchacha20poly1305_from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes.try_into()
            .map_err(|_| Error::BadLength)?;
        Ok(Self::XChaCha20Poly1305(BinarySecret::new(arr)))
    }

    /// Create a nonce for use with this secret key
    pub fn gen_nonce(&self) -> Result<SecretKeyNonce> {
        match self {
            SecretKey::XChaCha20Poly1305(_) => {
                let mut randbuf = [0u8; 24];
                OsRng.fill_bytes(&mut randbuf);
                Ok(SecretKeyNonce::XChaCha20Poly1305(Binary::new(randbuf)))
            }
        }
    }

    /// Encrypt a value with a secret key/nonce
    pub fn seal<'a>(&'a self, data: &[u8]) -> Result<Sealed> {
        match self {
            SecretKey::XChaCha20Poly1305(ref key) => {
                let nonce = self.gen_nonce()?;
                let nonce_bin = match nonce {
                    SecretKeyNonce::XChaCha20Poly1305(ref bin) => bin.deref(),
                };
                let secret: &'a [u8; 32] = key.expose_secret();
                let cipher = chacha20poly1305::XChaCha20Poly1305::new(secret.into());
                let enc = cipher.encrypt(chacha20poly1305::XNonce::from_slice(nonce_bin.as_slice()), data).map_err(|_| Error::CryptoSealFailed)?;
                Ok(Sealed::new(nonce, enc))
            }
        }
    }

    /// Decrypt a value with a secret key/nonce
    pub fn open(&self, sealed: &Sealed) -> Result<Vec<u8>> {
        match (self, sealed.nonce()) {
            (SecretKey::XChaCha20Poly1305(ref key), SecretKeyNonce::XChaCha20Poly1305(ref nonce)) => {
                let cipher = chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.expose_secret().as_slice().clone()));
                let dec = cipher.decrypt(chacha20poly1305::XNonce::from_slice(nonce.as_slice()), sealed.ciphertext().deref().as_slice()).map_err(|_| Error::CryptoOpenFailed)?;
                Ok(dec)
            }
        }
    }

    /// Get the raw bytes for this key
    pub fn as_ref(&self) -> &[u8] {
        match self {
            SecretKey::XChaCha20Poly1305(ref key) => key.expose_secret().as_ref(),
        }
    }
}

#[cfg(test)]
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SecretKey::XChaCha20Poly1305(inner1), SecretKey::XChaCha20Poly1305(inner2)) => {
                inner1.expose_secret() == inner2.expose_secret()
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn secretkey_xchacha20poly1305_enc_dec() {
        let key = SecretKey::new_xchacha20poly1305().unwrap();
        let val = String::from("get a job");
        let enc = key.seal(val.as_bytes()).unwrap();
        let dec_bytes = key.open(&enc).unwrap();
        let dec = String::from_utf8(dec_bytes).unwrap();
        assert_eq!(dec, String::from("get a job"));
    }

    #[test]
    fn secretkey_xchacha20poly1305_from_slice() {
        let sealed = Sealed::new(
            SecretKeyNonce::XChaCha20Poly1305(Binary::new([33, 86, 38, 93, 180, 121, 32, 51, 21, 36, 74, 137, 32, 165, 2, 99, 111, 179, 32, 242, 56, 9, 254, 1])),
            vec![8, 175, 83, 132, 142, 229, 0, 29, 187, 23, 223, 152, 164, 120, 206, 13, 240, 105, 184, 47, 228, 239, 34, 85, 79, 242, 230, 150, 186, 203, 156, 26],
        );
        let key = SecretKey::new_xchacha20poly1305_from_slice(vec![120, 111, 109, 233, 7, 27, 205, 94, 55, 95, 248, 113, 138, 246, 244, 109, 147, 168, 117, 163, 48, 193, 100, 103, 43, 205, 212, 197, 110, 111, 105, 1].as_slice()).unwrap();
        let dec = key.open(&sealed).unwrap();
        assert_eq!(dec.as_slice(), b"HI HUNGRY IM DAD");
    }
}

