use chrono::{DateTime, NaiveDateTime, Utc};
use crate::error::{Error, Result};
use serde_derive::{Serialize, Deserialize};
use sodiumoxide::{
    crypto::generichash,
};
use std::ops::Deref;

#[macro_use]
pub mod ser;
pub(crate) mod sign;

/// Hash arbitrary data using blake2b
pub fn hash(data: &[u8]) -> Result<generichash::Digest> {
    let mut state = generichash::State::new(generichash::DIGEST_MAX, None)
        .map_err(|_| Error::CryptoHashStateInitError)?;
    state.update(data)
        .map_err(|_| Error::CryptoHashStateUpdateError)?;
    state.finalize()
        .map_err(|_| Error::CryptoHashStateDigestError)
}

/// A library-local representation of a time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Timestamp(#[serde(with = "crate::util::ser::timestamp")] DateTime<Utc>);

impl Timestamp {
    /// Create a new Timestamp from the current date/time.
    pub fn now() -> Self {
        Self(Utc::now())
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

