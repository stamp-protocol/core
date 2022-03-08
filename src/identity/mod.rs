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
        // this verifies each transaction
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

    fn get_transactions() -> (SecretKey, Transactions) {
        let now = Timestamp::now();
        let master_key = SecretKey::new_xsalsa20poly1305().unwrap();
        let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
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
        let (master_key, transactions) = get_transactions();
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
                        let master_key = SecretKey::new_xsalsa20poly1305().unwrap();
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
        let master_key = SecretKey::new_xsalsa20poly1305().unwrap();
        let now = Timestamp::from_str("1977-06-07T04:32:06Z").unwrap();
        let seeds = [
            &[33, 90, 159, 88, 22, 24, 84, 4, 237, 121, 198, 195, 71, 238, 107, 91, 235, 93, 9, 129, 252, 221, 2, 149, 250, 142, 49, 36, 161, 184, 44, 156],
            &[170, 39, 114, 32, 79, 238, 151, 138, 85, 59, 44, 153, 147, 105, 161, 127, 180, 225, 13, 119, 143, 46, 119, 153, 203, 41, 129, 240, 180, 88, 201, 37],
            &[67, 150, 243, 61, 128, 149, 195, 141, 16, 154, 144, 63, 21, 245, 243, 226, 244, 55, 168, 59, 66, 45, 15, 61, 152, 5, 101, 219, 43, 137, 197, 90],
            &[179, 112, 207, 116, 174, 196, 118, 123, 235, 202, 236, 69, 169, 209, 65, 238, 204, 235, 194, 187, 37, 246, 180, 124, 8, 116, 207, 175, 95, 87, 159, 137],
        ];
        let alpha_keypair = AlphaKeypair::new_ed25519_from_seed(&master_key, seeds[0]).unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519_from_seed(&master_key, seeds[1]).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519_from_seed(&master_key, seeds[2]).unwrap();
        let root_keypair = RootKeypair::new_ed25519_from_seed(&master_key, seeds[3]).unwrap();
        let transactions = Transactions::new()
            .create_identity(&master_key, now.clone(), alpha_keypair, policy_keypair, publish_keypair, root_keypair).unwrap();
        let identity_id = transactions.build_identity().unwrap().id().clone();
        let transactions = transactions
            .make_claim(&master_key, now.clone(), ClaimSpec::Identity(identity_id.clone())).unwrap()
            .make_claim(&master_key, now.clone(), ClaimSpec::Name(MaybePrivate::new_public("Von Jonie Himself".to_string()))).unwrap();
        let identity = transactions.build_identity().unwrap();

        let published = PublishedIdentity::publish(&master_key, now.clone(), transactions.clone()).unwrap();
        let ser = published.serialize().unwrap();
        assert_eq!(ser, r#"---
publish_signature:
  Ed25519: ouwBiHEHk6aludnxRhFJ5-eT2_hsnDNtV0DhWYn-BiS6M-L1fFlo3HlG4Q-D7B77GXLjN9c1D783KC2w5e99AA
publish_date: "1977-06-07T04:32:06Z"
identity:
  transactions:
    - V1:
        id:
          Alpha:
            Ed25519: rdjnll1H48XN4WSaqXrCn_kwxv_cWF2tPl8lCa_KKtTNhbb2Qg2GaNHXQ01ScHW8KZNnsQckeorMy-MZpemgAA
        entry:
          created: "1977-06-07T04:32:06Z"
          previous_transactions: []
          body:
            CreateIdentityV1:
              - Ed25519:
                  - dHNopBN3YZrNa52xiVxB1IoY9NsrCz1c9cL8lLTu69U
                  - ~
              - Ed25519:
                  - s5YuvOaxr4y1qQBzZyJJ0SduYXf8toYfLa2izUgcT2I
                  - ~
              - Ed25519:
                  - B1NXKqP26jGll8tT12CCLbGxo09Do2M-A6VvRJoW87M
                  - ~
              - Ed25519:
                  - 75w-F9acRAKDCDdeAiOYTAz9BUoky98lO5rHNSeodQg
                  - ~
    - V1:
        id:
          Root:
            Ed25519: 27C2RwGYtsZnFVrkv4QDIVWoJkb6g04BuBQY6mJo07IgCnxj7Q1Lta_ZMTtv3MOm1bRZnPvMLE1tvlj2AkqBAQ
        entry:
          created: "1977-06-07T04:32:06Z"
          previous_transactions:
            - Alpha:
                Ed25519: rdjnll1H48XN4WSaqXrCn_kwxv_cWF2tPl8lCa_KKtTNhbb2Qg2GaNHXQ01ScHW8KZNnsQckeorMy-MZpemgAA
          body:
            MakeClaimV1:
              Identity:
                Ed25519: rdjnll1H48XN4WSaqXrCn_kwxv_cWF2tPl8lCa_KKtTNhbb2Qg2GaNHXQ01ScHW8KZNnsQckeorMy-MZpemgAA
    - V1:
        id:
          Root:
            Ed25519: tu_FxF5tjcqxnSOE-au34-plcGcG9ljTLwJLgezoIVGrfZqPbomf21UY3TT3euYaRehXnIZFCGx_IOMLbI1yDw
        entry:
          created: "1977-06-07T04:32:06Z"
          previous_transactions:
            - Root:
                Ed25519: 27C2RwGYtsZnFVrkv4QDIVWoJkb6g04BuBQY6mJo07IgCnxj7Q1Lta_ZMTtv3MOm1bRZnPvMLE1tvlj2AkqBAQ
          body:
            MakeClaimV1:
              Name:
                Public: Von Jonie Himself"#);
        let published_des = PublishedIdentity::deserialize(ser.as_bytes()).unwrap();
        let identity_des = published_des.identity().build_identity().unwrap();
        assert_eq!(identity.claims().len(), 2);
        assert_eq!(identity.claims().len(), identity_des.claims().len());
        for i in 0..identity.claims().len() {
            let claim1 = &identity.claims()[i];
            let claim2 = &identity_des.claims()[i];
            assert_eq!(claim1.claim().id(), claim2.claim().id());
        }

        // modify one of our stinkin' claims. this should fail to even build
        // the identity, since seach transaction's signature is checked before
        // we can even access the publish key to check the publish sig.
        let modified_claim = r#"---
publish_signature:
  Ed25519: sa63FcjCTJvb9m04xuUJrzo63Jn7oNAkfcw1V-SIpoiufFNQzBp65oI9QWDdq7aKym97JFw7cQ9-pyOY1wyUAw
publish_date: "1977-06-07T04:32:06Z"
identity:
  transactions:
    - V1:
        id:
          Alpha:
            Ed25519: gtFQEM2do4bIW0gkre1qahPsQZgny9rM1j9nWHuSWc0Ay492K8ydRljKCrCB-_G7aCsxMAMiBhuz9lyWwok5Aw
        entry:
          created: "1977-06-07T04:32:06Z"
          previous_transactions: []
          body:
            CreateIdentityV1:
              - Ed25519:
                  - rcxBT4vC93i4PZzwflbKUzTbvgf96wr4kArteWqwzxA
                  - ~
              - Ed25519:
                  - _iO_wIyxzlWS0OvOKJYR67L80nQoNTCE_JYDcxs1lRk
                  - ~
              - Ed25519:
                  - PRtrFNJJpYsNNYIZEgspwxVtgLqrMx1-3nXuLnTtWlc
                  - ~
              - Ed25519:
                  - Yl7xQtHuYPpQQwBfppPROI0jYqetVxvChC2EofFrNhU
                  - ~
    - V1:
        id:
          Root:
            Ed25519: 6MrVBIEVXNRxnLAQZIuY41I9g5ximL0FkyNqh7AI5uRHgRtabThEyuQA9N5A4_6jKg9ClDr9Yb1YWbfzz_K1Dg
        entry:
          created: "1977-06-07T04:32:06Z"
          previous_transactions:
            - Alpha:
                Ed25519: gtFQEM2do4bIW0gkre1qahPsQZgny9rM1j9nWHuSWc0Ay492K8ydRljKCrCB-_G7aCsxMAMiBhuz9lyWwok5Aw
          body:
            MakeClaimV1:
              Identity:
                Ed25519: gtFQEM2do4bIW0gkre1qahPsQZgny9rM1j9nWHuSWc0Ay492K8ydRljKCrCB-_G7aCsxMAMiBhuz9lyWwok5Aw
    - V1:
        id:
          Root:
            Ed25519: k1pFH_SBskA4aj-AFgDB1oKZFsyHch2W3Lrqw5nO-A4gV7XOVp4_uyYztMpkF-P1NzuhJyNotAgCkfei8FflAA
        entry:
          created: "1977-06-07T04:32:06Z"
          previous_transactions:
            - Root:
                Ed25519: 6MrVBIEVXNRxnLAQZIuY41I9g5ximL0FkyNqh7AI5uRHgRtabThEyuQA9N5A4_6jKg9ClDr9Yb1YWbfzz_K1Dg
          body:
            MakeClaimV1:
              Name:
                Public: Mr. Bovine Jonie"#;

        let res = PublishedIdentity::deserialize(modified_claim.as_bytes());
        assert_eq!(res.err(), Some(Error::CryptoSignatureVerificationFailed));

        // modify the chain itself. this should pass the build_identity()
        // validation, but fail the publish signature check
        let modified_chain = r#"---
publish_signature:
  Ed25519: sa63FcjCTJvb9m04xuUJrzo63Jn7oNAkfcw1V-SIpoiufFNQzBp65oI9QWDdq7aKym97JFw7cQ9-pyOY1wyUAw
publish_date: "1977-06-07T04:32:06Z"
identity:
  transactions:
    - V1:
        id:
          Alpha:
            Ed25519: gtFQEM2do4bIW0gkre1qahPsQZgny9rM1j9nWHuSWc0Ay492K8ydRljKCrCB-_G7aCsxMAMiBhuz9lyWwok5Aw
        entry:
          created: "1977-06-07T04:32:06Z"
          previous_transactions: []
          body:
            CreateIdentityV1:
              - Ed25519:
                  - rcxBT4vC93i4PZzwflbKUzTbvgf96wr4kArteWqwzxA
                  - ~
              - Ed25519:
                  - _iO_wIyxzlWS0OvOKJYR67L80nQoNTCE_JYDcxs1lRk
                  - ~
              - Ed25519:
                  - PRtrFNJJpYsNNYIZEgspwxVtgLqrMx1-3nXuLnTtWlc
                  - ~
              - Ed25519:
                  - Yl7xQtHuYPpQQwBfppPROI0jYqetVxvChC2EofFrNhU
                  - ~
    - V1:
        id:
          Root:
            Ed25519: 6MrVBIEVXNRxnLAQZIuY41I9g5ximL0FkyNqh7AI5uRHgRtabThEyuQA9N5A4_6jKg9ClDr9Yb1YWbfzz_K1Dg
        entry:
          created: "1977-06-07T04:32:06Z"
          previous_transactions:
            - Alpha:
                Ed25519: gtFQEM2do4bIW0gkre1qahPsQZgny9rM1j9nWHuSWc0Ay492K8ydRljKCrCB-_G7aCsxMAMiBhuz9lyWwok5Aw
          body:
            MakeClaimV1:
              Identity:
                Ed25519: gtFQEM2do4bIW0gkre1qahPsQZgny9rM1j9nWHuSWc0Ay492K8ydRljKCrCB-_G7aCsxMAMiBhuz9lyWwok5Aw"#;
        let res = PublishedIdentity::deserialize(modified_chain.as_bytes());
        assert_eq!(res.err(), Some(Error::CryptoSignatureVerificationFailed));
    }
}

