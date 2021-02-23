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
    use super::*;
    use crate::{
        dag::{TransactionID, TransactionBody, TransactionVersioned},
        error::Error,
        identity::{
            claim::ClaimSpec,
        },
        private::MaybePrivate,
    };
    use std::ops::Deref;
    use std::str::FromStr;

    fn get_transactions(seed: Option<&[u8; 32]>, ts_maybe: Option<Timestamp>) -> (SecretKey, Transactions) {
        let now = ts_maybe.unwrap_or(Timestamp::now());
        let master_key = SecretKey::new_xsalsa20poly1305();
        let (alpha_keypair, policy_keypair, publish_keypair, root_keypair) = match seed {
            Some(seed) => {
                let alpha_keypair = AlphaKeypair::new_ed25519_from_seed(&master_key, seed).unwrap();
                let policy_keypair = PolicyKeypair::new_ed25519_from_seed(&master_key, seed).unwrap();
                let publish_keypair = PublishKeypair::new_ed25519_from_seed(&master_key, seed).unwrap();
                let root_keypair = RootKeypair::new_ed25519_from_seed(&master_key, seed).unwrap();
                (alpha_keypair, policy_keypair, publish_keypair, root_keypair)
            }
            None => {
                let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
                let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
                let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
                let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
                (alpha_keypair, policy_keypair, publish_keypair, root_keypair)
            }
        };
        let transactions = Transactions::new()
            .create_identity(&master_key, now.clone(), alpha_keypair, policy_keypair, publish_keypair, root_keypair).unwrap();
        let identity_id = IdentityID(transactions.transactions()[0].id().deref().clone());
        let transactions = transactions
            .make_claim(&master_key, now.clone(), ClaimSpec::Identity(identity_id.clone())).unwrap()
            .make_claim(&master_key, now.clone(), ClaimSpec::Name(MaybePrivate::new_public("Von Jonie Himself".to_string()))).unwrap()
            .make_claim(&master_key, now.clone(), ClaimSpec::HomeAddress(MaybePrivate::new_private(&master_key, "6969 Uhhhhuhuhuhuh Thtreet".to_string()).unwrap())).unwrap();
        (master_key, transactions)
    }

    #[test]
    fn published_publish_verify() {
        let (master_key, transactions) = get_transactions(None, None);
        let published = PublishedIdentity::publish(&master_key, Timestamp::now(), transactions.clone()).unwrap();

        published.verify().unwrap();

        // modify the publish date and watch it fail
        let mut published_mod = published.clone();
        published_mod.set_publish_date(Timestamp::from_str("1968-03-07T13:45:59Z").unwrap());
        let res = published_mod.verify();
        assert_eq!(res.err(), Some(Error::CryptoSignatureVerificationFailed));

        // modify each transaction and watch it fail
        let mut idx = 0;
        macro_rules! mod_trans {
            ($published:expr, $trans:expr, $inner:ident, $op:expr, $err:expr) => {{
                let mut trans_copy = $trans.clone();
                match trans_copy {
                    TransactionVersioned::V1(ref mut $inner) => {
                        $op;
                        let mut pubclone = $published.clone();
                        pubclone.identity_mut().transactions_mut()[idx] = trans_copy;
                        // should always faily after modificationy
                        let res = pubclone.verify();
                        assert_eq!(res.err(), Some($err));
                    }
                }
            }}
        }
        for trans in published.identity().transactions() {
            published.verify().unwrap();

            mod_trans!( published, trans, inner, {
                inner.set_id(TransactionID::random_alpha());
            }, Error::CryptoSignatureVerificationFailed);

            mod_trans!( published, trans, inner, {
                inner.entry_mut().set_created(Timestamp::from_str("1719-09-12T13:44:58Z").unwrap());
            }, Error::CryptoSignatureVerificationFailed);

            mod_trans!( published, trans, inner, {
                inner.entry_mut().previous_transactions_mut().push(TransactionID::random_alpha());
            }, if idx == 0 { Error::DagNoGenesis } else { Error::CryptoSignatureVerificationFailed });

            mod_trans!( published, trans, inner, {
                let body = match inner.entry().body().clone() {
                    TransactionBody::CreateIdentityV1(alpha, policy, publish, root) => {
                        let master_key = SecretKey::new_xsalsa20poly1305();
                        let new_alpha = AlphaKeypair::new_ed25519(&master_key).unwrap();
                        assert!(new_alpha != alpha);
                        TransactionBody::CreateIdentityV1(new_alpha, policy, publish, root)
                    }
                    TransactionBody::Private => {
                        TransactionBody::MakeClaimV1(ClaimSpec::Name(MaybePrivate::new_public(String::from("BAT MAN"))))
                    }
                    _ => TransactionBody::Private,
                };
                inner.entry_mut().set_body(body);
            }, Error::CryptoSignatureVerificationFailed);
            idx += 1;
        }
    }

    #[test]
    fn published_serde() {
        let (master_key, transactions) = get_transactions(Some(&[33, 90, 159, 88, 22, 24, 84, 4, 237, 121, 198, 195, 71, 238, 107, 91, 235, 93, 9, 129, 252, 221, 2, 149, 250, 142, 49, 36, 161, 184, 44, 156]), Some(Timestamp::from_str("1977-06-06T05:55:05Z").unwrap()));
        let published = PublishedIdentity::publish(&master_key, Timestamp::now(), transactions.clone()).unwrap();
        let ser = published.serialize().unwrap();
        drop(ser);
        unimplemented!();
    }
}

