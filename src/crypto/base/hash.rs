use crate::{
    error::{Error, Result},
    util::{
        ser::{self, Binary},
    },
};
#[cfg(test)] use rand::{RngCore, rngs::OsRng};
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// An enum we can pass to various signing functions to tell them which hashing
/// algorithm to use.
pub enum HashAlgo {
    /// Blake3
    Blake3,
}

/// A cryptographic hash. By defining this as an enum, we allow expansion of
/// hash algorithms in the future.
///
/// When stringified, the hash is in the format `base64([<hash bytes>|<u8 tag>])`
/// where the `tag` is the specific hash algorithm we use. This allows the hash
/// to shine on its own without the tag getting in the way. Yes, it's vain.
#[derive(Clone, Debug, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Hash {
    /// Blake3 256bit hash
    #[rasn(tag(explicit(0)))]
    Blake3(Binary<32>),
}

impl Hash {
    /// Create a new blake3 (512 bit) hash from a message
    pub fn new_blake3(message: &[u8]) -> Result<Self> {
        let hash = blake3::hash(message);
        let arr: [u8; 32] = hash.as_bytes().clone();
        Ok(Self::Blake3(Binary::new(arr)))
    }

    #[cfg(test)]
    pub(crate) fn random_blake3() -> Self {
        let mut randbuf = [0u8; 32];
        OsRng.fill_bytes(&mut randbuf);
        Self::Blake3(Binary::new(randbuf))
    }

    /// Return the byte slice representing this hash.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Blake3(bin) => bin.deref(),
        }
    }
}

impl TryFrom<&Hash> for String {
    type Error = Error;

    fn try_from(hash: &Hash) -> std::result::Result<Self, Self::Error> {
        fn bin_with_tag<const N: usize>(bin: &Binary<N>, tag: u8) -> Vec<u8> {
            let mut vec = Vec::from(bin.deref().as_slice());
            vec.push(tag);
            vec
        }
        let enc = match hash {
            Hash::Blake3(bin) => {
                bin_with_tag(bin, 0)
            }
        };
        Ok(ser::base64_encode(&enc[..]))
    }
}

impl TryFrom<&str> for Hash {
    type Error = Error;

    fn try_from(string: &str) -> std::result::Result<Self, Self::Error> {
        let dec = ser::base64_decode(string)?;
        let tag = dec[dec.len() - 1];
        let bytes = &dec[0..dec.len() - 1];
        let hash = match tag {
            0 => {
                let arr: [u8; 32] = bytes.try_into()
                    .map_err(|_| Error::BadLength)?;
                Self::Blake3(Binary::new(arr))
            }
            _ => Err(Error::CryptoAlgoMismatch)?,
        };
        Ok(hash)
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::try_from(self).map_err(|_| std::fmt::Error)?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::util::ser::base64_encode;

    #[test]
    fn hash_blake3_encode_decode_fmt() {
        let msg = b"that kook dropped in on me. we need to send him a (cryptographically hashed) message.";
        let hash = Hash::new_blake3(&msg[..]).unwrap();
        match &hash {
            Hash::Blake3(bin) => {
                assert_eq!(base64_encode(bin.deref()), "WZtRlW37zRXCMzX95hUmVPU0NCrf0U8HonMc-0bb-Pg");
            }
        }
        let bytes = ser::serialize(&hash).unwrap();
        assert_eq!(ser::base64_encode(&bytes[..]), String::from("oCIEIFmbUZVt-80VwjM1_eYVJlT1NDQq39FPB6JzHPtG2_j4"));
        assert_eq!(format!("{}", hash), String::from("WZtRlW37zRXCMzX95hUmVPU0NCrf0U8HonMc-0bb-PgA"));
        let hash2: Hash = ser::deserialize(&bytes).unwrap();
        match &hash2 {
            Hash::Blake3(bin) => {
                assert_eq!(base64_encode(bin.deref()), "WZtRlW37zRXCMzX95hUmVPU0NCrf0U8HonMc-0bb-Pg");
            }
        }

        let hash3 = Hash::try_from("WZtRlW37zRXCMzX95hUmVPU0NCrf0U8HonMc-0bb-PgA").unwrap();
        match &hash3 {
            Hash::Blake3(bin) => {
                assert_eq!(base64_encode(bin.deref()), "WZtRlW37zRXCMzX95hUmVPU0NCrf0U8HonMc-0bb-Pg");
            }
        }
    }
}

