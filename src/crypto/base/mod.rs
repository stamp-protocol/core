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
use rand::{RngCore, SeedableRng, rngs::OsRng};
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

mod secret_key;
mod sign_key;
mod crypto_key;
mod hash;
mod hmac;

pub use secret_key::*;
pub use sign_key::*;
pub use crypto_key::*;
pub use hash::*;
pub use hmac::*;

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

/// A convenience function that returns a ChaCha20 CSRNG seeded with OS random bytes. Use this if
/// you want a nice, strong random number generator, you don't want to wire one up yourself, and
/// your platform provides good entropy.
///
/// This can be used as an input to any Stamp function that accepts `&mut rng`. Otherwise, you can
/// bring your own RNG that implements [`RngCore`].
pub fn rng_chacha20() -> rand_chacha::ChaCha20Rng { 
    let mut seed_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut seed_bytes);
    rand_chacha::ChaCha20Rng::from_seed(seed_bytes)
}

/// A value that lets us reference keys by a unique identifier (pubkey for asymc keypairs
/// and HMAC for secret keys).
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum KeyID {
    #[rasn(tag(explicit(0)))]
    SignKeypair(SignKeypairPublic),
    #[rasn(tag(explicit(1)))]
    CryptoKeypair(CryptoKeypairPublic),
    #[rasn(tag(explicit(2)))]
    SecretKey(Hmac),
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
            Self::SecretKey(hmac) => {
                ser::base64_encode(hmac.deref())
            }
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_sign() -> Self {
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        Self::SignKeypair(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap().into())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_crypto() -> Self {
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        Self::CryptoKeypair(CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap().into())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_secret() -> Self {
        let mut rng = crate::util::test::rng();
        Self::SecretKey(Hmac::new(&HmacKey::new_blake3(&mut rng).unwrap(), b"get a job").unwrap())
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

/// Given the bytes from a secret key, derive some other key of N length in a secure manner.
pub fn stretch_key<const N: usize>(input: &[u8], output: &mut [u8; N], info: Option<&[u8]>, salt: Option<&[u8]>) -> Result<()> {
    let hkdf = hkdf::SimpleHkdf::<blake3::Hasher>::new(salt, input);
    hkdf.expand(info.unwrap_or(b"stamp/hkdf"), output)
        .map_err(|_| Error::CryptoHKDFFailed)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn derives_secret_key() {
        let id = Hash::new_blake3("my key".as_bytes()).unwrap();
        let salt = Hash::new_blake3(id.as_bytes()).unwrap();
        let master_key = derive_secret_key("ZONING IS COMMUNISM".as_bytes(), &salt.as_bytes(), KDF_OPS_INTERACTIVE, KDF_MEM_INTERACTIVE).unwrap();
        assert_eq!(master_key.as_ref(), &[176, 89, 132, 109, 145, 106, 124, 212, 160, 159, 89, 16, 49, 17, 126, 129, 183, 249, 118, 100, 31, 54, 74, 163, 164, 7, 98, 224, 17, 196, 201, 123]);
    }

    #[test]
    fn key_stretcher() {
        let secret1: [u8; 32] = [182, 32, 38, 195, 3, 106, 177, 19, 174, 37, 56, 19, 163, 193, 155, 49, 112, 238, 93, 96, 149, 145, 69, 19, 187, 251, 76, 227, 111, 136, 180, 43];

        let mut output1 = [0u8; 42];
        stretch_key(&secret1, &mut output1, None, None).unwrap();
        assert_eq!(output1, [181, 55, 17, 131, 160, 112, 88, 125, 252, 2, 83, 112, 231, 24, 133, 118, 101, 164, 193, 3, 35, 239, 197, 187, 108, 59, 7, 215, 178, 162, 46, 151, 221, 99, 101, 52, 202, 39, 248, 74, 6, 227]);

        let mut output2 = [0u8; 16];
        stretch_key(&secret1, &mut output2, None, None).unwrap();
        assert_eq!(output2, [181, 55, 17, 131, 160, 112, 88, 125, 252, 2, 83, 112, 231, 24, 133, 118]);

        let secret2: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

        let mut output3 = [0u8; 16];
        stretch_key(&secret2, &mut output3, None, None).unwrap();
        assert_eq!(output3, [236, 153, 148, 81, 215, 159, 176, 254, 171, 59, 106, 69, 28, 231, 50, 115]);

        let mut output4 = [0u8; 32];
        stretch_key(&secret2, &mut output4, Some(b"andrew_is_cool/0"), None).unwrap();
        assert_eq!(output4, [98, 155, 219, 70, 138, 71, 67, 210, 120, 32, 75, 72, 223, 17, 249, 174, 177, 235, 77, 144, 25, 141, 88, 58, 141, 74, 86, 67, 105, 56, 226, 237]);

        let mut output5 = [0u8; 32];
        stretch_key(&secret2, &mut output5, Some(b"andrew_is_cool/1"), None).unwrap();
        assert_eq!(output5, [194, 245, 136, 152, 243, 224, 63, 218, 52, 141, 232, 90, 229, 188, 48, 157, 238, 107, 233, 75, 109, 142, 223, 95, 149, 101, 199, 6, 151, 78, 41, 232]);
    }
}

