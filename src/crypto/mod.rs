//! The crypto module contains all of our cryptographic primitives for key
//! generation, signing, messaging, and encrypting private data.

pub mod key;
pub mod message;
pub mod sign;
pub mod secret;

use crate::{
    crypto::key::KeyID,
    identity::{
        IdentityID,
    },
};
use serde_derive::{Serialize, Deserialize};

/// A signature or object containing a signatur that lists the identity and key
/// that created the signature.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct SignedObject<T> {
    /// The ID of the signing identity
    signed_by_identity: IdentityID,
    /// The ID of the key that signed the message
    signed_by_key: KeyID,
    /// The signature or message
    body: T,
}

impl<T: serde::ser::Serialize + serde::de::DeserializeOwned> SignedObject<T> {
    fn new(identity_id: IdentityID, key_id: KeyID, body: T) -> Self {
        Self {
            signed_by_identity: identity_id,
            signed_by_key: key_id,
            body,
        }
    }
}

