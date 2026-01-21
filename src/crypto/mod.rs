//! The crypto module contains all of our cryptographic primitives for key
//! generation, signing, messaging, and encrypting private data.

pub mod base;
pub mod message;
pub mod private;
pub mod seal;
pub mod sign;

use crate::{crypto::base::KeyID, identity::IdentityID};
use rasn::{AsnType, Decode, Decoder, Encode, Encoder};
use serde::{Deserialize, Serialize};

/// A signature or object containing a signature that lists the identity and key
/// that created the signature.
// TODO: remove this useless type.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct SignedObject<T> {
    /// The ID of the signing identity
    #[rasn(tag(explicit(0)))]
    signed_by_identity: IdentityID,
    /// The ID of the key that signed the message
    #[rasn(tag(explicit(1)))]
    signed_by_key: KeyID,
    /// The signature or message
    #[rasn(tag(explicit(2)))]
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
