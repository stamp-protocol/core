//! The identity module defines the data types and operations that define a
//! Stamp identity.
//!
//! An identity is essentially a set of keys (signing and encryption), a set of
//! claims made by the identity owner (including the identity itself), any
//! number of signatures that verify those claims, and a set of "forwards" that
//! can point to other locations (for instance, your canonical email address,
//! your personal domain, etc).
//!
//! This system relies heavily on the [key](crate::key) module, which provides
//! all the mechanisms necessary for encryption, decryption, signing, and
//! verification of data.


pub mod keychain;
pub mod recovery;
pub mod claim;
pub mod stamp;
pub mod identity;

pub use keychain::*;
pub use recovery::*;
pub use claim::*;
pub use stamp::*;
pub use identity::*;

use crate::{
    error::Result,
    key::{SecretKey, SignKeypairSignature},
    util::{
        Timestamp,
        ser,
        sign::DateSigner,
    },
};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

pub(crate) trait Public: Clone {
    /// Strip the private data from a object, returning only public data.
    fn strip_private(&self) -> Self;
}

pub(crate) trait PublicMaybe: Clone {
    /// Strip the private data from a object, unless the object is entirely
    /// private in which case return None.
    fn strip_private_maybe(&self) -> Option<Self>;
}

/// Allows identity formats to be versioned so as to not break compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VersionedIdentity {
    V1(identity::Identity),
}

impl VersionedIdentity {
    /// Serialize this versioned identity into a byte vector.
    pub fn serialize_binary(&self) -> Result<Vec<u8>> {
        ser::serialize(self)
    }

    /// Deserialize this versioned identity from a byte vector.
    pub fn deserialize_binary(slice: &[u8]) -> Result<Self> {
        ser::deserialize(slice)
    }

    /// Re-encrypt this identity's keychain and private claims.
    pub fn reencrypt(self, current_key: &SecretKey, new_key: &SecretKey) -> Result<Self> {
        match self {
            Self::V1(id) => Ok(Self::V1(id.reencrypt(current_key, new_key)?)),
        }
    }

    /// Regenerate the root signature on this identity.
    ///
    /// This is mainly used for development to save an identity that's corrupt
    /// due to buggy code. This should not be used as a regular feature, because
    /// its entire need is based on a buggy stamp protocol implementation.
    pub fn root_sign(self, master_key: &SecretKey) -> Result<Self> {
        match self {
            Self::V1(id) => Ok(Self::V1(id.root_sign(master_key)?)),
        }
    }

    /// Create a new claim from the given data, sign it, and attach it to this
    /// identity.
    pub fn make_claim<T: Into<Timestamp>>(self, master_key: &SecretKey, now: T, claim: ClaimSpec) -> Result<Self> {
        match self {
            Self::V1(id) => Ok(Self::V1(id.make_claim(master_key, now, claim)?)),
        }
    }

    /// Strip all private data from this identity.
    fn strip_private(&self) -> Self {
        match self {
            Self::V1(identity) => Self::V1(identity.strip_private()),
        }
    }
}

// this makes it so we don't have to manually create a bunch of interfaces we
// can otherwise pass through.
impl Deref for VersionedIdentity {
    type Target = Identity;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::V1(ref identity) => identity,
        }
    }
}

impl Public for VersionedIdentity {
    fn strip_private(&self) -> Self {
        match self {
            Self::V1(id) => Self::V1(id.strip_private()),
        }
    }
}

/// The container that is used to publish an identity. This is what otherswill
/// import when they verify an identity, stamp the claim for an identity, send
/// the identity a value for signing (for instance for logging in to an online
/// service), etc.
///
/// The published identity must be signed by our publish keypair, which in turn
/// is signed by our alpha keypair.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct PublishedIdentity {
    /// The signature of this published identity, generated using our publish
    /// keypair.
    publish_signature: SignKeypairSignature,
    /// The date we published on.
    publish_date: Timestamp,
    /// The versioned identity we're publishing.
    identity: VersionedIdentity,
}

impl PublishedIdentity {
    /// Takes an identity and creates a signed published identity object from
    /// it.
    pub fn publish<T: Into<VersionedIdentity>>(master_key: &SecretKey, now: Timestamp, identity: T) -> Result<Self> {
        let versioned_identity: VersionedIdentity = identity.into();
        let public_identity = versioned_identity.strip_private();
        let datesigner = DateSigner::new(&now, &versioned_identity);
        let serialized = ser::serialize(&datesigner)?;
        let signature = match &versioned_identity {
            VersionedIdentity::V1(id) => id.keychain().publish().sign(master_key, &serialized),
        }?;
        Ok(Self {
            publish_signature: signature,
            publish_date: now,
            identity: public_identity,
        })
    }

    /// Serialize this versioned identity into a human readable format
    pub fn serialize(&self) -> Result<String> {
        ser::serialize_human(self)
    }

    /// Deserialize this versioned identity from a byte vector.
    pub fn deserialize(slice: &[u8]) -> Result<Self> {
        ser::deserialize_human(slice)
    }
}

impl Public for PublishedIdentity {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_identity(self.identity().strip_private());
        clone
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::keychain,
        key::CryptoKeypair,
        util::Timestamp,
    };

    #[test]
    fn published() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let now = Timestamp::now();
        let identity = identity::Identity::new(&master_key, now).unwrap()
            .add_subkey(&master_key, keychain::Key::Crypto(CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap()), "Email", "Use this to send me emails.").unwrap();
        let now2 = Timestamp::now();
        let published = PublishedIdentity::publish(&master_key, now2, identity).unwrap();
        let _human = published.serialize().unwrap();
        // TODO: gen with deterministict params, serialize and deserialize
    }
}

