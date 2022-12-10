//! The crypto base wraps a set of algorithms for encryption and decryption (both
//! symmetric and asymmetric) as well as cryptographic signing and hashing of data.
//!
//! The idea here is that specific algorithms are wrapped in descriptive
//! interfaces that allow high-level use of the encapsulated cryptographic
//! algorithms without needing to know the details of those algorithms.
//!
//! For instance, you have a `SignKeypair` which has a standard interface, but
//! can describe any number of signing algorithms. This allows expansion of the
//! cryptographic primitives used without needing to build new interfaces around
//! them.

use crate::{
    error::{Error, Result},
    util::ser::{self, BinarySecret},
};
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

mod secret_key;
mod sign_key;
mod crypto_key;
mod hash;
mod mac;

pub use secret_key::*;
pub use sign_key::*;
pub use crypto_key::*;
pub use hash::*;
pub use mac::*;

/// A constant that provides a default for CPU difficulty for interactive key derivation
pub const KDF_OPS_INTERACTIVE: u32 = 2;
/// A constant that provides a default for mem difficulty for interactive key derivation
pub const KDF_MEM_INTERACTIVE: u32 = 65536;

/// A constant that provides a default for CPU difficulty for moderate key derivation
pub const KDF_OPS_MODERATE: u32 = 3;
/// A constant that provides a default for mem difficulty for moderate key derivation
pub const KDF_MEM_MODERATE: u32 = 262144;

/// A constant that provides a default for CPU difficulty for sensitive key derivation
pub const KDF_OPS_SENSITIVE: u32 = 4;
/// A constant that provides a default for mem difficulty for sensitive key derivation
pub const KDF_MEM_SENSITIVE: u32 = 1048576;

/// A value that lets us reference keys by a unique identifier (pubkey for asymc keypairs
/// and MAC for secret keys).
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum KeyID {
    #[rasn(tag(explicit(0)))]
    SignKeypair(SignKeypairPublic),
    #[rasn(tag(explicit(1)))]
    CryptoKeypair(CryptoKeypairPublic),
    #[rasn(tag(explicit(2)))]
    SecretKey(Mac),
}

impl KeyID {
    pub fn as_string(&self) -> String {
        match self {
            Self::SignKeypair(SignKeypairPublic::Ed25519(pubkey)) => {
                ser::base64_encode(pubkey.as_ref())
            }
            Self::CryptoKeypair(CryptoKeypairPublic::Curve25519XChaCha20Poly1305(pubkey)) => {
                ser::base64_encode(pubkey.as_ref())
            }
            Self::SecretKey(mac) => {
                ser::base64_encode(mac.deref())
            }
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_sign() -> Self {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        Self::SignKeypair(SignKeypair::new_ed25519(&master_key).unwrap().into())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_crypto() -> Self {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        Self::CryptoKeypair(CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap().into())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_secret() -> Self {
        Self::SecretKey(Mac::new_blake2b(&MacKey::new_blake2b().unwrap(), b"get a job").unwrap())
    }
}

impl std::fmt::Display for KeyID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

/// Generate a secret key from a passphrase/salt
pub fn derive_secret_key(passphrase: &[u8], salt_bytes: &[u8], ops: u32, mem: u32) -> Result<SecretKey> {
    const LEN: usize = 32;
    let salt: &[u8; 16] = salt_bytes[0..16].try_into()
        .map_err(|_| Error::CryptoBadSalt)?;
    let mut key = [0u8; 32];
    let argon2_ctx = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(mem, ops, 1, Some(LEN)).map_err(|_| Error::CryptoKDFFailed)?
    );
    argon2_ctx.hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| Error::CryptoKDFFailed)?;
    Ok(SecretKey::XChaCha20Poly1305(BinarySecret::new(key)))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn derives_secret_key() {
        let id = Hash::new_blake2b("my key".as_bytes()).unwrap();
        let salt = Hash::new_blake2b(id.as_bytes()).unwrap();
        let master_key = derive_secret_key("ZONING IS COMMUNISM".as_bytes(), &salt.as_bytes(), KDF_OPS_INTERACTIVE, KDF_MEM_INTERACTIVE).unwrap();
        assert_eq!(master_key.as_ref(), &[148, 34, 57, 50, 168, 111, 176, 114, 120, 168, 159, 158, 96, 119, 14, 194, 52, 224, 58, 194, 77, 44, 168, 25, 54, 138, 172, 91, 164, 86, 190, 89]);
    }
}

