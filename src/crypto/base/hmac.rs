use crate::{
    error::{Error, Result},
    util::{
        ser::{Binary, BinarySecret},
    },
};
use hmac::{SimpleHmac, Mac};
use rand::{CryptoRng, RngCore};
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// A key for deriving an HMAC.
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum HmacKey {
    /// Blake3 HMAC key
    #[rasn(tag(explicit(0)))]
    Blake3(BinarySecret<32>),
}

impl HmacKey {
    /// Create a new blake3 HMAC key
    pub fn new_blake3<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut randbuf = [0u8; 32];
        rng.fill_bytes(&mut randbuf);
        Ok(Self::Blake3(BinarySecret::new(randbuf)))
    }

    /// Create a new blake3 HMAC key from a byte array
    pub fn new_blake3_from_bytes(keybytes: [u8; 32]) -> Self {
        Self::Blake3(BinarySecret::new(keybytes))
    }
}

/// An HMAC
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Hmac {
    /// Blake3 HMAC
    #[rasn(tag(explicit(0)))]
    Blake3(Binary<32>),
}

impl Hmac {
    /// Create a new HMAC from a key and a set of data.
    pub fn new(hmac_key: &HmacKey, data: &[u8]) -> Result<Self> {
        match hmac_key {
            HmacKey::Blake3(hmac_key) => {
                let mut hmac = SimpleHmac::<blake3::Hasher>::new_from_slice(hmac_key.expose_secret().as_slice())
                    .map_err(|_| Error::CryptoBadKey)?;
                hmac.update(data);
                let result = hmac.finalize();
                let gen_arr = result.into_bytes();
                let arr: &[u8; 32] = gen_arr.as_ref();
                Ok(Hmac::Blake3(Binary::new(arr.clone())))
            }
        }
    }

    /// Verify an HMAC against a set of data.
    pub fn verify(&self, hmac_key: &HmacKey, data: &[u8]) -> Result<()> {
        match (self, hmac_key) {
            (Self::Blake3(hmac), HmacKey::Blake3(hmac_key)) => {
                let mut hmac_ver = SimpleHmac::<blake3::Hasher>::new_from_slice(hmac_key.expose_secret().as_slice())
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
            Hmac::Blake3(bytes) => &(bytes.deref())[..],
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn hmac_result() {
        let data = String::from("PARDON ME GOOD SIR DO YOU HAVE ANY goats FOR SALE!!!!!!?");
        let hmac_key = HmacKey::new_blake3_from_bytes([
            0, 1, 2, 3, 4, 5, 6, 7,
            1, 2, 3, 4, 5, 6, 7, 8,
            2, 3, 4, 5, 6, 7, 8, 9,
            3, 4, 5, 6, 7, 8, 9, 9,
        ]);
        let hmac = Hmac::new(&hmac_key, data.as_bytes()).unwrap();
        assert_eq!(hmac, Hmac::Blake3(Binary::new([64, 13, 214, 251, 117, 123, 250, 89, 128, 228, 226, 211, 142, 212, 238, 115, 50, 230, 69, 202, 84, 248, 52, 139, 28, 86, 138, 202, 63, 142, 2, 29])));
    }

    #[test]
    fn hmac_verify() {
        let mut rng = crate::util::test::rng();
        let data1 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and four children...if it's not too much trouble, maybe you could verify them as we...");
        let data2 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and seven children...if it's not too much trouble, maybe you could verify them as we...");
        let hmac_key1 = HmacKey::new_blake3(&mut rng).unwrap();
        let hmac_key2 = HmacKey::new_blake3(&mut rng).unwrap();
        let hmac = Hmac::new(&hmac_key1, data1.as_bytes()).unwrap();
        hmac.verify(&hmac_key1, data1.as_bytes()).unwrap();
        let res = hmac.verify(&hmac_key2, data1.as_bytes());
        assert_eq!(res, Err(Error::CryptoHmacVerificationFailed));
        let res = hmac.verify(&hmac_key1, data2.as_bytes());
        assert_eq!(res, Err(Error::CryptoHmacVerificationFailed));
        let res = hmac.verify(&hmac_key2, data2.as_bytes());
        assert_eq!(res, Err(Error::CryptoHmacVerificationFailed));
    }
}

