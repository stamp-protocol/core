//! Includes some utilities helpful for generating signatures.

use crate::{
    error::Result,
    key::{SecretKey, SignKeypairSignature, SignKeypair},
    util::{
        Timestamp,
        ser,
    },
};
use getset;
use serde_derive::{Serialize, Deserialize};

/// Attaches a serializable object to a date for signing.
///
/// This is a one-way object used for comparing signatures, so never needs to be
/// deserialized.
#[derive(Debug, Clone, Serialize, getset::Getters, getset::MutGetters, getset::Setters)]
pub struct DateSigner<'a, 'b, T> {
    /// The date we signed this value.
    date: &'a Timestamp,
    /// The value being signed.
    value: &'b T,
}

impl<'a, 'b, T: serde::Serialize> DateSigner<'a, 'b, T> {
    /// Construct a new DateSigner
    pub fn new(date: &'a Timestamp, value: &'b T) -> Self {
        Self {
            date,
            value,
        }
    }
}

/// A struct that wraps any type and requires it to be signed in order to be
/// created or modified.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct SignedValue<T: serde::Serialize> {
    /// The value we wish to sign.
    value: T,
    /// The signature for our value.
    signature: SignKeypairSignature,
}

impl<T: serde::Serialize> SignedValue<T> {
    /// Create a new signed value. Requires our signing keypair and our root key
    /// (used to unlock the secret signing key).
    pub fn new(master_key: &SecretKey, sign_keypair: &SignKeypair, value: T) -> Result<Self> {
        let serialized = ser::serialize(&value)?;
        let signature = sign_keypair.sign(master_key, &serialized)?;
        Ok(Self {
            value,
            signature,
        })
    }
}


