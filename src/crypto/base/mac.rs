use blake2::digest::{FixedOutput, Mac as DigestMac};
use crate::{
    error::{Error, Result},
    util::{
        ser::{Binary, BinarySecret},
    },
};
use rand::{RngCore, rngs::OsRng};
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// A key for deriving a MAC
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum MacKey {
    /// Blake2b MAC key
    #[rasn(tag(0))]
    Blake2b(BinarySecret<64>),
}

impl MacKey {
    /// Create a new blacke2b MAC key
    pub fn new_blake2b() -> Result<Self> {
        let mut randbuf = [0u8; 64];
        OsRng.fill_bytes(&mut randbuf);
        Ok(Self::Blake2b(BinarySecret::new(randbuf)))
    }

    /// Create a new blake2b MAC key from a byte array
    pub fn new_blake2b_from_bytes(keybytes: [u8; 64]) -> Self {
        Self::Blake2b(BinarySecret::new(keybytes))
    }
}

/// A MAC
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Mac {
    /// Blake2b MAC
    #[rasn(tag(0))]
    Blake2b(Binary<64>),
}

impl Deref for Mac {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Mac::Blake2b(bytes) => &(bytes.deref())[..],
        }
    }
}

impl Mac {
    /// Create a new MAC-blake2b from a key and a set of data.
    pub fn new_blake2b(mac_key: &MacKey, data: &[u8]) -> Result<Self> {
        match mac_key {
            MacKey::Blake2b(mac_key) => {
                let mut mac = blake2::Blake2bMac512::new_with_salt_and_personal(mac_key.expose_secret().as_slice(), &[], b"stamp-protocol")
                    .map_err(|_| Error::CryptoBadKey)?;
                mac.update(data);
                let arr: [u8; 64] = mac.finalize_fixed().as_slice().try_into()
                    .map_err(|_| Error::BadLength)?;
                Ok(Mac::Blake2b(Binary::new(arr)))
            }
        }
    }

    /// Verify a MAC against a set of data.
    pub fn verify(&self, mac_key: &MacKey, data: &[u8]) -> Result<()> {
        match (self, mac_key) {
            (Self::Blake2b(mac), MacKey::Blake2b(mac_key)) => {
                let mut mac_ver = blake2::Blake2bMac512::new_with_salt_and_personal(mac_key.expose_secret().as_slice(), &[], b"stamp-protocol")
                    .map_err(|_| Error::CryptoBadKey)?;
                mac_ver.update(data);
                let arr: [u8; 64] = mac_ver.finalize_fixed().as_slice().try_into()
                    .map_err(|_| Error::BadLength)?;
                if mac != &Binary::new(arr) {
                    // the data has been tampered with, my friend.
                    Err(Error::CryptoMacVerificationFailed)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn mac_result() {
        let data = String::from("PARDON ME GOOD SIR DO YOU HAVE ANY goats FOR SALE!!!!!!?");
        let mac_key = MacKey::new_blake2b_from_bytes([
            0, 1, 2, 3, 4, 5, 6, 7,
            1, 2, 3, 4, 5, 6, 7, 8,
            2, 3, 4, 5, 6, 7, 8, 9,
            3, 4, 5, 6, 7, 8, 9, 9,
            0, 1, 2, 3, 4, 5, 6, 7,
            1, 2, 3, 4, 5, 6, 7, 8,
            2, 3, 4, 5, 6, 7, 8, 9,
            3, 4, 5, 6, 7, 8, 9, 9,
        ]);
        let mac = Mac::new_blake2b(&mac_key, data.as_bytes()).unwrap();
        assert_eq!(mac, Mac::Blake2b(Binary::new([180, 48, 36, 120, 45, 212, 97, 54, 140, 236, 63, 242, 120, 88, 177, 237, 196, 173, 110, 201, 8, 226, 18, 152, 29, 146, 33, 174, 39, 63, 156, 136, 82, 242, 221, 143, 179, 198, 47, 69, 223, 118, 96, 49, 42, 73, 86, 138, 147, 204, 67, 201, 217, 32, 145, 204, 138, 128, 101, 84, 115, 69, 173, 180])));
    }

    #[test]
    fn mac_verify() {
        let data1 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and four children...if it's not too much trouble, maybe you could verify them as we...");
        let data2 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and seven children...if it's not too much trouble, maybe you could verify them as we...");
        let mac_key1 = MacKey::new_blake2b().unwrap();
        let mac_key2 = MacKey::new_blake2b().unwrap();
        let mac = Mac::new_blake2b(&mac_key1, data1.as_bytes()).unwrap();
        mac.verify(&mac_key1, data1.as_bytes()).unwrap();
        let res = mac.verify(&mac_key2, data1.as_bytes());
        assert_eq!(res, Err(Error::CryptoMacVerificationFailed));
        let res = mac.verify(&mac_key1, data2.as_bytes());
        assert_eq!(res, Err(Error::CryptoMacVerificationFailed));
        let res = mac.verify(&mac_key2, data2.as_bytes());
        assert_eq!(res, Err(Error::CryptoMacVerificationFailed));
    }
}

