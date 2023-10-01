//! Sealing allows an identity owner to encrypt and decrypt data using a secret key.

use crate::{
    crypto::base::{Sealed, SecretKey},
    error::{Result},
};

/// Uses a secret key to seal a set of binary data. Returns a ((de)serializable) self-contained
/// object that can be used to decrypt the data.
pub fn seal(encrypting_key: &SecretKey, plaintext: &[u8]) -> Result<Sealed> {
    encrypting_key.seal(plaintext)
}

/// Open a sealed container (created with [`seal`]) and return the data contained within.
pub fn open(encrypting_key: &SecretKey, sealed: &Sealed) -> Result<Vec<u8>> {
    encrypting_key.open(sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal() {
        let plain = b"omg lol wtf";
        let key  = SecretKey::new_xchacha20poly1305_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let sealed = seal(&key, plain.as_slice()).unwrap();
        let plain2 = open(&key, &sealed).unwrap();
        assert_eq!(plain2, plain);
    }
}

