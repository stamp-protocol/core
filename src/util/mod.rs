//! Utilities. OBVIOUSLY.

use chrono::{DateTime, NaiveDateTime, Utc};
use crate::error::{Error, Result};
use serde_derive::{Serialize, Deserialize};
use sodiumoxide::{
    crypto::generichash,
};
use std::ops::Deref;

#[macro_use]
pub(crate) mod ser;
pub(crate) mod sign;

/// Hash arbitrary data using blake2b
#[allow(dead_code)]
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

