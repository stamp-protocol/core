use blake2::{
    Digest,
    digest::{FixedOutput, Mac},
};
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
    /// Blake2b 512
    Blake2b512,
    /// Blake2b 256
    Blake2b256,
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
    /// Blake2b 512bit hash
    #[rasn(tag(explicit(0)))]
    Blake2b512(Binary<64>),

    /// Blake2b 512bit hash
    #[rasn(tag(explicit(1)))]
    Blake2b256(Binary<32>),
}

impl Hash {
    /// Create a new blake2b (512 bit) hash from a message
    pub fn new_blake2b_512(message: &[u8]) -> Result<Self> {
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(message);
        let genarr = hasher.finalize();
        let arr: [u8; 64] = genarr.as_slice().try_into()
            .map_err(|_| Error::BadLength)?;
        Ok(Self::Blake2b512(Binary::new(arr)))
    }

    /// Create a blake2b (512 bit) hash derived from a secret key, salt, personal data, and a
    /// message. This can be used for MAC and key stretching.
    pub fn new_blake2b_512_keyed(key_bytes: &[u8], salt: &[u8], personal: &[u8], message: &[u8]) -> Result<Self> {
        let mut hasher = blake2::Blake2bMac512::new_with_salt_and_personal(key_bytes, salt, personal)
            .map_err(|_| Error::CryptoBadKey)?;
        hasher.update(message);
        let arr: [u8; 64] = hasher.finalize_fixed().as_slice().try_into()
            .map_err(|_| Error::BadLength)?;
        Ok(Self::Blake2b512(Binary::new(arr)))
    }

    /// Create a new blake2b (256 bit) hash from a message
    pub fn new_blake2b_256(message: &[u8]) -> Result<Self> {
        let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
        hasher.update(message);
        let genarr = hasher.finalize();
        let arr: [u8; 32] = genarr.as_slice().try_into()
            .map_err(|_| Error::BadLength)?;
        Ok(Self::Blake2b256(Binary::new(arr)))
    }

    #[cfg(test)]
    pub(crate) fn random_blake2b_512() -> Self {
        let mut randbuf = [0u8; 64];
        OsRng.fill_bytes(&mut randbuf);
        Self::Blake2b512(Binary::new(randbuf))
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_blake2b_256() -> Self {
        let mut randbuf = [0u8; 32];
        OsRng.fill_bytes(&mut randbuf);
        Self::Blake2b256(Binary::new(randbuf))
    }

    /// Return the byte slice representing this hash.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Blake2b512(bin) => bin.deref(),
            Self::Blake2b256(bin) => bin.deref(),
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
            Hash::Blake2b512(bin) => {
                bin_with_tag(bin, 0)
            }
            Hash::Blake2b256(bin) => {
                bin_with_tag(bin, 1)
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
                Self::Blake2b512(Binary::new(arr))
            }
            1 => {
                let arr: [u8; 32] = bytes.try_into()
                    .map_err(|_| Error::BadLength)?;
                Self::Blake2b256(Binary::new(arr))
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
    fn hash_blake2b_512_encode_decode_fmt() {
        let msg = b"that kook dropped in on me. we need to send him a (cryptographically hashed) message.";
        let hash = Hash::new_blake2b_512(&msg[..]).unwrap();
        match &hash {
            Hash::Blake2b512(bin) => {
                assert_eq!(base64_encode(bin.deref()), "80DvVWAZF0fChjhVn0c5023925fIQ5dfY0T7NFglhj-paL5wR-tafRl6P8YbKEWRrQ2-7u3st1Avg0bIPRrKoQ");
            }
            _ => panic!("Not possible"),
        }
        let bytes = ser::serialize(&hash).unwrap();
        assert_eq!(ser::base64_encode(&bytes[..]), String::from("oEIEQPNA71VgGRdHwoY4VZ9HOdNt_duXyEOXX2NE-zRYJYY_qWi-cEfrWn0Zej_GGyhFka0Nvu7t7LdQL4NGyD0ayqE"));
        assert_eq!(format!("{}", hash), String::from("80DvVWAZF0fChjhVn0c5023925fIQ5dfY0T7NFglhj-paL5wR-tafRl6P8YbKEWRrQ2-7u3st1Avg0bIPRrKoQA"));
        let hash2: Hash = ser::deserialize(&bytes).unwrap();
        match &hash2 {
            Hash::Blake2b512(bin) => {
                assert_eq!(base64_encode(bin.deref()), "80DvVWAZF0fChjhVn0c5023925fIQ5dfY0T7NFglhj-paL5wR-tafRl6P8YbKEWRrQ2-7u3st1Avg0bIPRrKoQ");
            }
            _ => panic!("Not possible"),
        }

        let hash3 = Hash::try_from("80DvVWAZF0fChjhVn0c5023925fIQ5dfY0T7NFglhj-paL5wR-tafRl6P8YbKEWRrQ2-7u3st1Avg0bIPRrKoQA").unwrap();
        match &hash3 {
            Hash::Blake2b512(bin) => {
                assert_eq!(base64_encode(bin.deref()), "80DvVWAZF0fChjhVn0c5023925fIQ5dfY0T7NFglhj-paL5wR-tafRl6P8YbKEWRrQ2-7u3st1Avg0bIPRrKoQ");
            }
            _ => panic!("Not possible"),
        }
    }

    #[test]
    fn hash_blake2b_512_keyed() {
        let msg = b"that kook dropped in on me. we need to send him a (cryptographically hashed) message.";
        let key = b"mac stuff";
        let salt = b"";
        let personal = b"";
        let hash = Hash::new_blake2b_512_keyed(key, salt, personal, msg).unwrap();
        match &hash {
            Hash::Blake2b512(bin) => {
                assert_eq!(base64_encode(bin.deref()), "Y3ULFER3MO_urLj8YrGayPWBAyVcp0ud78oJjAp8dODaNYsel7siifJpMsAYXNyyHMp1Xs6Hrs3HGXcaEFuzfQ");
            }
            _ => panic!("Not possible"),
        }
    }

    #[test]
    fn hash_blake2b_256_encode_decode_fmt() {
        let msg = b"that kook dropped in on me. we need to send him a (cryptographically hashed) message.";
        let hash = Hash::new_blake2b_256(&msg[..]).unwrap();
        match &hash {
            Hash::Blake2b256(bin) => {
                assert_eq!(base64_encode(bin.deref()), "2qn4qe5V0IOPVYWR7qhTz9RT4aQD3pmA_6HE24A62NI");
            }
            _ => panic!("Not possible"),
        }

        let bytes = ser::serialize(&hash).unwrap();
        assert_eq!(ser::base64_encode(&bytes[..]), String::from("oSIEINqp-KnuVdCDj1WFke6oU8_UU-GkA96ZgP-hxNuAOtjS"));
        assert_eq!(format!("{}", hash), String::from("2qn4qe5V0IOPVYWR7qhTz9RT4aQD3pmA_6HE24A62NIB"));
        let hash2: Hash = ser::deserialize(&bytes).unwrap();
        match &hash2 {
            Hash::Blake2b256(bin) => {
                assert_eq!(base64_encode(bin.deref()), "2qn4qe5V0IOPVYWR7qhTz9RT4aQD3pmA_6HE24A62NI");
            }
            _ => panic!("Not possible"),
        }

        let hash3 = Hash::try_from("2qn4qe5V0IOPVYWR7qhTz9RT4aQD3pmA_6HE24A62NIB").unwrap();
        match &hash3 {
            Hash::Blake2b256(bin) => {
                assert_eq!(base64_encode(bin.deref()), "2qn4qe5V0IOPVYWR7qhTz9RT4aQD3pmA_6HE24A62NI");
            }
            _ => panic!("Not possible"),
        }
    }
}

