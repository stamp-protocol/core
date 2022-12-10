use blake2::Digest;
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

/// A cryptographic hash. By defining this as an enum, we allow expansion of
/// hash algorithms in the future.
///
/// When stringified, the hash is in the format `base64([<hash bytes>|<u8 tag>])`
/// where the `tag` is the specific hash algorithm we use. This allows the hash
/// to shine on its own without the tag getting inthe way. Yes, it's vain.
#[derive(Clone, Debug, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Hash {
    /// Blake2b hash
    #[rasn(tag(explicit(0)))]
    Blake2b(Binary<64>),
}

impl Hash {
    /// Create a new blake2b hash from a message
    pub fn new_blake2b(message: &[u8]) -> Result<Self> {
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(message);
        let genarr = hasher.finalize();
        let arr: [u8; 64] = genarr.as_slice().try_into()
            .map_err(|_| Error::BadLength)?;
        Ok(Self::Blake2b(Binary::new(arr)))
    }

    #[cfg(test)]
    pub(crate) fn random_blake2b() -> Self {
        let mut randbuf = [0u8; 64];
        OsRng.fill_bytes(&mut randbuf);
        Self::Blake2b(Binary::new(randbuf))
    }

    /// Return the byte slice representing this hash.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Blake2b(bin) => bin.deref(),
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
            Hash::Blake2b(bin) => {
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
                let arr: [u8; 64] = bytes.try_into()
                    .map_err(|_| Error::BadLength)?;
                Self::Blake2b(Binary::new(arr))
            },
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

    #[test]
    fn hash_blake2b_encode_decode_fmt() {
        let msg = b"that kook dropped in on me. we need to send him a (cryptographically hashed) message.";
        let hash = Hash::new_blake2b(&msg[..]).unwrap();
        match &hash {
            Hash::Blake2b(bin) => {
                assert_eq!(bin.deref(), &vec![243, 64, 239, 85, 96, 25, 23, 71, 194, 134, 56, 85, 159, 71, 57, 211, 109, 253, 219, 151, 200, 67, 151, 95, 99, 68, 251, 52, 88, 37, 134, 63, 169, 104, 190, 112, 71, 235, 90, 125, 25, 122, 63, 198, 27, 40, 69, 145, 173, 13, 190, 238, 237, 236, 183, 80, 47, 131, 70, 200, 61, 26, 202, 161][..]);
            }
        }
        let bytes = ser::serialize(&hash).unwrap();
        assert_eq!(ser::base64_encode(&bytes[..]), String::from("oEIEQPNA71VgGRdHwoY4VZ9HOdNt_duXyEOXX2NE-zRYJYY_qWi-cEfrWn0Zej_GGyhFka0Nvu7t7LdQL4NGyD0ayqE"));
        assert_eq!(format!("{}", hash), String::from("80DvVWAZF0fChjhVn0c5023925fIQ5dfY0T7NFglhj-paL5wR-tafRl6P8YbKEWRrQ2-7u3st1Avg0bIPRrKoQA"));
        let hash2: Hash = ser::deserialize(&bytes).unwrap();
        match &hash2 {
            Hash::Blake2b(bin) => {
                assert_eq!(bin.deref(), &vec![243, 64, 239, 85, 96, 25, 23, 71, 194, 134, 56, 85, 159, 71, 57, 211, 109, 253, 219, 151, 200, 67, 151, 95, 99, 68, 251, 52, 88, 37, 134, 63, 169, 104, 190, 112, 71, 235, 90, 125, 25, 122, 63, 198, 27, 40, 69, 145, 173, 13, 190, 238, 237, 236, 183, 80, 47, 131, 70, 200, 61, 26, 202, 161][..]);
            }
        }

        let hash3 = Hash::try_from("80DvVWAZF0fChjhVn0c5023925fIQ5dfY0T7NFglhj-paL5wR-tafRl6P8YbKEWRrQ2-7u3st1Avg0bIPRrKoQA").unwrap();
        match &hash3 {
            Hash::Blake2b(bin) => {
                assert_eq!(bin.deref(), &vec![243, 64, 239, 85, 96, 25, 23, 71, 194, 134, 56, 85, 159, 71, 57, 211, 109, 253, 219, 151, 200, 67, 151, 95, 99, 68, 251, 52, 88, 37, 134, 63, 169, 104, 190, 112, 71, 235, 90, 125, 25, 122, 63, 198, 27, 40, 69, 145, 173, 13, 190, 238, 237, 236, 183, 80, 47, 131, 70, 200, 61, 26, 202, 161][..]);
            }
        }
    }
}

