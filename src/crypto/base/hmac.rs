use blake2::digest::{Mac as DigestMac};
use crate::{
    error::{Error, Result},
    util::{
        ser::{Binary, BinarySecret},
    },
};
use hmac::{SimpleHmac};
use rand::{RngCore, rngs::OsRng};
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// A key for deriving an HMAC.
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum HmacKey {
    /// Blake2b HMAC key
    #[rasn(tag(explicit(0)))]
    Blake2b(BinarySecret<64>),
}

impl HmacKey {
    /// Create a new blake2b HMAC key
    pub fn new_blake2b() -> Result<Self> {
        let mut randbuf = [0u8; 64];
        OsRng.fill_bytes(&mut randbuf);
        Ok(Self::Blake2b(BinarySecret::new(randbuf)))
    }

    /// Create a new blake2b HMAC key from a byte array
    pub fn new_blake2b_from_bytes(keybytes: [u8; 64]) -> Self {
        Self::Blake2b(BinarySecret::new(keybytes))
    }
}

/// An HMAC
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Hmac {
    /// Blake2b HMAC
    #[rasn(tag(explicit(0)))]
    Blake2b(Binary<64>),
}

impl Hmac {
    /// Create a new HMAC-blake2b from a key and a set of data.
    pub fn new_blake2b(hmac_key: &HmacKey, data: &[u8]) -> Result<Self> {
        match hmac_key {
            HmacKey::Blake2b(hmac_key) => {
                let mut hmac = SimpleHmac::<blake2::Blake2b512>::new_from_slice(hmac_key.expose_secret().as_slice())
                    .map_err(|_| Error::CryptoBadKey)?;
                hmac.update(data);
                let result = hmac.finalize();
                let gen_arr = result.into_bytes();
                let arr: &[u8; 64] = gen_arr.as_ref();
                Ok(Hmac::Blake2b(Binary::new(arr.clone())))
            }
        }
    }

    /// Verify an HMAC against a set of data.
    pub fn verify(&self, hmac_key: &HmacKey, data: &[u8]) -> Result<()> {
        match (self, hmac_key) {
            (Self::Blake2b(hmac), HmacKey::Blake2b(hmac_key)) => {
                let mut hmac_ver = SimpleHmac::<blake2::Blake2b512>::new_from_slice(hmac_key.expose_secret().as_slice())
                    .map_err(|_| Error::CryptoBadKey)?;
                hmac_ver.update(data);
                hmac_ver.verify_slice(hmac.deref())
                    .map_err(|_| Error::CryptoHmacVerificationFailed)?;
            }
        }
        Ok(())
    }
}

impl Deref for Hmac {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Hmac::Blake2b(bytes) => &(bytes.deref())[..],
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn hmac_result() {
        let data = String::from("PARDON ME GOOD SIR DO YOU HAVE ANY goats FOR SALE!!!!!!?");
        let hmac_key = HmacKey::new_blake2b_from_bytes([
            0, 1, 2, 3, 4, 5, 6, 7,
            1, 2, 3, 4, 5, 6, 7, 8,
            2, 3, 4, 5, 6, 7, 8, 9,
            3, 4, 5, 6, 7, 8, 9, 9,
            0, 1, 2, 3, 4, 5, 6, 7,
            1, 2, 3, 4, 5, 6, 7, 8,
            2, 3, 4, 5, 6, 7, 8, 9,
            3, 4, 5, 6, 7, 8, 9, 9,
        ]);
        let hmac = Hmac::new_blake2b(&hmac_key, data.as_bytes()).unwrap();
        assert_eq!(hmac, Hmac::Blake2b(Binary::new([169, 157, 71, 138, 100, 209, 231, 66, 235, 62, 177, 211, 221, 201, 245, 204, 239, 118, 150, 175, 115, 56, 152, 95, 79, 66, 212, 183, 167, 44, 158, 101, 19, 142, 242, 171, 29, 96, 22, 119, 47, 175, 45, 124, 33, 197, 171, 116, 119, 221, 17, 79, 108, 250, 31, 237, 169, 130, 47, 43, 222, 73, 104, 5])));
    }

    #[test]
    fn hmac_verify() {
        let data1 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and four children...if it's not too much trouble, maybe you could verify them as we...");
        let data2 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and seven children...if it's not too much trouble, maybe you could verify them as we...");
        let hmac_key1 = HmacKey::new_blake2b().unwrap();
        let hmac_key2 = HmacKey::new_blake2b().unwrap();
        let hmac = Hmac::new_blake2b(&hmac_key1, data1.as_bytes()).unwrap();
        hmac.verify(&hmac_key1, data1.as_bytes()).unwrap();
        let res = hmac.verify(&hmac_key2, data1.as_bytes());
        assert_eq!(res, Err(Error::CryptoHmacVerificationFailed));
        let res = hmac.verify(&hmac_key1, data2.as_bytes());
        assert_eq!(res, Err(Error::CryptoHmacVerificationFailed));
        let res = hmac.verify(&hmac_key2, data2.as_bytes());
        assert_eq!(res, Err(Error::CryptoHmacVerificationFailed));
    }
}

