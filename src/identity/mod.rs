//! The identity module defines the data types and operations that define a
//! Stamp identity.
//!
//! An identity is essentially a set of keys (signing and encryption), a set of
//! claims made by the identity owner (including the identity itself), any
//! number of signatures that verify those claims, and a set of "forwards" that
//! can point to other locations (for instance, your canonical email address,
//! your personal domain, etc).
//!
//! This system relies heavily on the [key](crate::crypto::key) module, which
//! provides all the mechanisms necessary for encryption, decryption, signing,
//! and verification of data.


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
    crypto::key::SecretKey,
    dag::Transactions,
    identity::{
        ExtendKeypair,
    },
    util::{
        Public,
        Timestamp,
        ser,
        sign::DateSigner,
    },
};
use serde_derive::{Serialize, Deserialize};

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
    publish_signature: PublishKeypairSignature,
    /// The date we published on.
    publish_date: Timestamp,
    /// The versioned identity we're publishing.
    identity: Transactions,
}

impl PublishedIdentity {
    /// Takes an identity and creates a signed published identity object from
    /// it.
    pub fn publish(master_key: &SecretKey, now: Timestamp, transactions: Transactions) -> Result<Self> {
        let identity = transactions.build_identity()?;
        let public_identity = transactions.strip_private();
        let datesigner = DateSigner::new(&now, &public_identity);
        let serialized = ser::serialize(&datesigner)?;
        let signature = identity.keychain().publish().sign(master_key, &serialized)?;
        Ok(Self {
            publish_signature: signature,
            publish_date: now,
            identity: public_identity,
        })
    }

    /// Confirm that this published identity has indeed been signed by the
    /// publish contained in the identity, and that the identity itself is
    /// valid.
    pub fn verify(&self) -> Result<()> {
        let identity = self.identity().build_identity()?;

        // now that we know the identity is valid, we can validate the publish
        // signature against its publish key
        let datesigner = DateSigner::new(self.publish_date(), self.identity());
        let serialized = ser::serialize(&datesigner)?;
        identity.keychain().publish().verify(self.publish_signature(), &serialized)
    }

    /// Serialize this published identity into a human readable format
    pub fn serialize(&self) -> Result<String> {
        ser::serialize_human(self)
    }

    /// Deserialize this published identity from a byte vector.
    pub fn deserialize(slice: &[u8]) -> Result<Self> {
        let published: Self = ser::deserialize_human(slice)?;
        published.verify()?;
        Ok(published)
    }
}

impl Public for PublishedIdentity {
    fn strip_private(&self) -> Self {
        self.clone()
    }

    fn has_private(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn published_publish() {
        unimplemented!();
    }

    #[test]
    fn published_verify() {
        unimplemented!();
    }

    #[test]
    fn published_serde() {
        unimplemented!();
    }

    #[test]
    fn published_strip_private() {
        unimplemented!();
    }
}

