//! Utilities. OBVIOUSLY.

use chrono::{DateTime, NaiveDateTime, Utc, Local};
use crate::error::{Error, Result};
use serde_derive::{Serialize, Deserialize};
use sodiumoxide::{
    crypto::generichash,
};
use std::ops::Deref;
use std::str::FromStr;

#[macro_use]
pub(crate) mod ser;
pub(crate) mod sign;

pub use sodiumoxide::utils::{mlock, munlock};

macro_rules! object_id {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        #[derive(Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
        pub struct $name(crate::crypto::key::SignKeypairSignature);

        #[cfg(test)]
        #[allow(dead_code)]
        impl $name {
            pub(crate) fn blank() -> Self {
                let sigbytes = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                let sig = crate::crypto::key::SignKeypairSignature::Ed25519(sodiumoxide::crypto::sign::ed25519::Signature::from_slice(sigbytes.as_slice()).unwrap());
                $name(sig)
            }

            #[cfg(test)]
            pub(crate) fn random() -> Self {
                let sigbytes = sodiumoxide::randombytes::randombytes(64);
                let sig = crate::crypto::key::SignKeypairSignature::Ed25519(sodiumoxide::crypto::sign::ed25519::Signature::from_slice(sigbytes.as_slice()).unwrap());
                $name(sig)
            }
        }

        impl Deref for $name {
            type Target = crate::crypto::key::SignKeypairSignature;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::convert::TryFrom<&$name> for String {
            type Error = crate::error::Error;
            fn try_from(id: &$name) -> std::result::Result<String, Self::Error> {
                let ser_val: u8 = match &id.0 {
                    crate::crypto::key::SignKeypairSignature::Ed25519(_) => 0,
                };
                let mut bytes = Vec::from(id.as_ref());
                bytes.push(ser_val);
                Ok(crate::util::ser::base64_encode(&bytes))
            }
        }

        impl std::convert::TryFrom<&str> for $name {
            type Error = crate::error::Error;
            fn try_from(id_str: &str) -> std::result::Result<Self, Self::Error> {
                let mut bytes = crate::util::ser::base64_decode(id_str.as_bytes())?;
                let ser_val = bytes.pop().ok_or(crate::error::Error::SignatureMissing)?;
                let id_sig = match ser_val {
                    _ => {
                        let sig = sodiumoxide::crypto::sign::ed25519::Signature::from_slice(bytes.as_slice())
                            .ok_or(crate::error::Error::SignatureMissing)?;
                        crate::crypto::key::SignKeypairSignature::Ed25519(sig)
                    }
                };
                Ok(Self(id_sig))
            }
        }
    }
}

pub trait Lockable {
    fn mem_lock(&mut self) -> Result<()>;
    fn mem_unlock(&mut self) -> Result<()>;
}

impl Lockable for String {
    fn mem_lock(&mut self) -> Result<()> {
        unsafe {
            sodiumoxide::utils::mlock(self.as_bytes_mut())
                .map_err(|_| Error::CryptoMemLockFailed)
        }
    }

    fn mem_unlock(&mut self) -> Result<()> {
        unsafe {
            sodiumoxide::utils::munlock(self.as_bytes_mut())
                .map_err(|_| Error::CryptoMemUnlockFailed)
        }
    }
}

/// Hash arbitrary data using blake2b
pub fn hash(data: &[u8]) -> Result<generichash::Digest> {
    let mut state = generichash::State::new(generichash::DIGEST_MAX, None)
        .map_err(|_| Error::CryptoHashStateInitError)?;
    state.update(data)
        .map_err(|_| Error::CryptoHashStateUpdateError)?;
    state.finalize()
        .map_err(|_| Error::CryptoHashStateDigestError)
}

/// A library-local representation of a time. I can hear you groaning already:
/// "Oh my god, why make a custom date/time object?!" Yes, I was once just like
/// you...young, and foolish. But hear me out:
///
/// - We want to the the Right Thing when serializing, and this is often much
/// easier with a wrapper type.
/// - If the underlying datetime object needs to change, we can do it in one
/// place instead of fifty places now. You'd think this wouldn't be an issue,
/// but some places where Stamp might want to run use their own serializers
/// instead of serde, so we might need to do some tricky things with features.
/// - Any place that takes a `Timestamp` will receive any value that can be
/// converted into a `Timestamp` via `From/Into` which we have implemented for
/// [DateTime<Utc>](chrono::DateTime) and [NaiveDateTime](chrono::NaiveDateTime),
/// and you can always get the underlying type via a `&timestamp` deref.
///
/// So put down the pitchfork.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Timestamp(#[serde(with = "crate::util::ser::timestamp")] DateTime<Utc>);

impl Timestamp {
    /// Create a new Timestamp from the current date/time.
    pub fn now() -> Self {
        Self(Utc::now())
    }

    pub fn local(&self) -> DateTime<Local> {
        DateTime::from(self.0)
    }
}

impl Deref for Timestamp {
    type Target = DateTime<Utc>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<NaiveDateTime> for Timestamp {
    fn from(naive: NaiveDateTime) -> Self {
        Self(DateTime::<Utc>::from_utc(naive, Utc))
    }
}

impl From<DateTime<Utc>> for Timestamp {
    fn from(date: DateTime<Utc>) -> Self {
        Self(date)
    }
}

impl FromStr for Timestamp {
    type Err = chrono::format::ParseError;
    fn from_str(s: &str) -> std::result::Result<Timestamp, Self::Err> {
        let datetime: DateTime<Utc> = s.parse()?;
        Ok(Timestamp(datetime))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::key::{SignKeypairSignature},
    };
    use std::convert::TryFrom;
    use std::ops::Deref;

    #[test]
    fn object_id_deref_to_from_string() {
        object_id! {
            TestID
        }

        let sigbytes = vec![61, 47, 37, 255, 130, 49, 42, 60, 55, 247, 221, 146, 149, 13, 27, 227, 23, 228, 6, 170, 103, 177, 184, 3, 124, 102, 180, 148, 228, 67, 30, 140, 172, 59, 90, 94, 220, 123, 143, 239, 97, 164, 186, 213, 141, 217, 174, 43, 186, 16, 184, 236, 166, 130, 38, 5, 176, 33, 22, 5, 111, 171, 57, 2];
        let sig = SignKeypairSignature::Ed25519(sodiumoxide::crypto::sign::ed25519::Signature::from_slice(sigbytes.as_slice()).unwrap());

        let id = TestID(sig);

        let string_id = String::try_from(&id).unwrap();
        assert_eq!(&string_id, "PS8l_4IxKjw3992SlQ0b4xfkBqpnsbgDfGa0lORDHoysO1pe3HuP72GkutWN2a4ruhC47KaCJgWwIRYFb6s5AgA");

        let id2 = TestID::try_from(string_id.as_str()).unwrap();
        assert_eq!(id, id2);

        match &id {
            TestID(sig) => {
                assert_eq!(sig, id.deref());
            }
        }
    }
}

