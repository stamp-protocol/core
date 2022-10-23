//! A `Transaction` models a single change against an identity, and is one node
//! inside of the identity DAG.
//!
//! Transactions have a [TransactionBody], an ID (sha512 of the transaction's body,
//! timestamp, and previously-referenced transactions), and a collection of one or
//! more signatures on the transaction's ID that validate that transaction.

use crate::{
    error::{Error, Result},
    crypto::{
        key::{KeyID, SecretKey, Sha512},
    },
    dag::Transactions,
    identity::{
        claim::{
            ClaimID,
            ClaimSpec,
        },
        identity::{
            IdentityID,
            Identity,
        },
        keychain::{
            AdminKey,
            ExtendKeypair,
            Key,
            RevocationReason,
        },
        stamp::{
            StampID,
            StampEntry,
            StampRevocationEntry,
        },
    },
    policy::{CapabilityPolicy, Context, PolicySignature},
    util::{
        Public,
        Timestamp,
        ser::{self},
    },
};
use getset;
use rasn::{Encode, Decode, AsnType};
use serde_derive::{Serialize, Deserialize};
use std::hash::{Hash, Hasher};
use std::ops::Deref;

/// This is all of the possible transactions that can be performed on an
/// identity, including the data they require.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum TransactionBody {
    /// Create a new identity. The [ID][TranscationID] of this transaction will
    /// be the identity's public ID forever after.
    #[rasn(tag(explicit(0)))]
    CreateIdentityV1 {
        #[rasn(tag(explicit(0)))]
        admin_keys: Vec<AdminKey>,
        #[rasn(tag(explicit(1)))]
        capabilities: Vec<CapabilityPolicy>,
    },
    /// Replace optionally both the [admin keys][AdminKey] in the [Keychain] and the
    /// [capabilities][CapabilityPolicy] attached to the identity.
    ///
    /// This is more or less a hailmary recovery option that allows gaining
    /// access to identity after some kind of catastrophic event.
    #[rasn(tag(explicit(1)))]
    ResetIdentityV1 {
        #[rasn(tag(explicit(0)))]
        admin_keys: Option<Vec<AdminKey>>,
        #[rasn(tag(explicit(1)))]
        capabilities: Option<Vec<CapabilityPolicy>>,
    },
    /// Add a new [admin key][AdminKey] to the [Keychain].
    #[rasn(tag(explicit(2)))]
    AddAdminKeyV1 {
        #[rasn(tag(explicit(0)))]
        admin_key: AdminKey,
    },
    /// Edit an admin key
    #[rasn(tag(explicit(3)))]
    EditAdminKeyV1 {
        #[rasn(tag(explicit(0)))]
        id: KeyID,
        #[rasn(tag(explicit(1)))]
        name: Option<String>,
        #[rasn(tag(explicit(2)))]
        description: Option<Option<String>>,
    },
    /// Revokes an [AdminKey] key and moves it into the subkeys, optionally
    /// renaming it.
    #[rasn(tag(explicit(4)))]
    RevokeAdminKeyV1 {
        #[rasn(tag(explicit(0)))]
        id: KeyID,
        #[rasn(tag(explicit(1)))]
        reason: RevocationReason,
        #[rasn(tag(explicit(2)))]
        new_name: Option<String>,
    },
    /// Add a new [capability policy][CapabilityPolicy] to the identity.
    #[rasn(tag(explicit(5)))]
    AddCapabilityPolicyV1 {
        #[rasn(tag(explicit(0)))]
        capability: CapabilityPolicy,
    },
    /// Delete (by name) a capability policy from the identity.
    #[rasn(tag(explicit(6)))]
    DeleteCapabilityPolicyV1 {
        #[rasn(tag(explicit(0)))]
        name: String,
    },
    /// Make a new claim on this identity. The [ID][TransactionID] of this
    /// transaction will be the claim's ID.
    #[rasn(tag(explicit(7)))]
    MakeClaimV1 {
        #[rasn(tag(explicit(0)))]
        spec: ClaimSpec,
        #[rasn(tag(explicit(1)))]
        name: Option<String>,
    },
    /// Edit a claim's name
    #[rasn(tag(explicit(8)))]
    EditClaimV1 {
        #[rasn(tag(explicit(0)))]
        claim_id: ClaimID,
        #[rasn(tag(explicit(1)))]
        name: Option<String>,
    },
    /// Delete/remove a claim by ID.
    #[rasn(tag(explicit(9)))]
    DeleteClaimV1 {
        #[rasn(tag(explicit(0)))]
        claim_id: ClaimID,
    },
    /// Make a stamp that is saved and advertised with this identity.
    #[rasn(tag(explicit(10)))]
    MakeStampV1 {
        #[rasn(tag(explicit(0)))]
        stamp: StampEntry,
    },
    /// Revoke a stamp we previously created and store this revocation with the
    /// identity.
    #[rasn(tag(explicit(11)))]
    RevokeStampV1 {
        #[rasn(tag(explicit(0)))]
        revocation: StampRevocationEntry,
    },
    /// Accept a stamp on one of our claims into our identity. This allows those
    /// who have our identity to see the trust others have put into us.
    #[rasn(tag(explicit(12)))]
    AcceptStampV1 {
        #[rasn(tag(explicit(0)))]
        stamp_transaction: Box<Transaction>,
    },
    /// Delete a stamp on one of our claims.
    #[rasn(tag(explicit(13)))]
    DeleteStampV1 {
        #[rasn(tag(explicit(0)))]
        stamp_id: StampID,
    },
    /// Add a new subkey to our keychain.
    #[rasn(tag(explicit(14)))]
    AddSubkeyV1 { 
        #[rasn(tag(explicit(0)))]
        key: Key,
        #[rasn(tag(explicit(1)))]
        name: String,
        #[rasn(tag(explicit(2)))]
        desc: Option<String>,
    },
    /// Edit the name/description of a subkey by its unique name.
    #[rasn(tag(explicit(15)))]
    EditSubkeyV1 {
        #[rasn(tag(explicit(0)))]
        id: KeyID,
        #[rasn(tag(explicit(1)))]
        new_name: Option<String>,
        #[rasn(tag(explicit(2)))]
        new_desc: Option<Option<String>>,
    },
    /// Mark a subkey as revoked, allowing old signatures to be validated but
    /// without permitting new signatures to be created.
    #[rasn(tag(explicit(16)))]
    RevokeSubkeyV1 {
        #[rasn(tag(explicit(0)))]
        id: KeyID,
        #[rasn(tag(explicit(1)))]
        reason: RevocationReason,
        #[rasn(tag(explicit(2)))]
        new_name: Option<String>,
    },
    /// Delete a subkey entirely from the identity.
    #[rasn(tag(explicit(17)))]
    DeleteSubkeyV1 {
        #[rasn(tag(explicit(0)))]
        id: KeyID,
    },
    /// Set this identity's nickname.
    #[rasn(tag(explicit(18)))]
    SetNicknameV1 {
        #[rasn(tag(explicit(0)))]
        nickname: Option<String>,
    },
    /// Publish this identity. This transaction cannot be saved with the identity, but
    /// rather should be published to a public medium (like StampNet!!!!1)
    #[rasn(tag(explicit(19)))]
    PublishV1 {
        #[rasn(tag(explicit(0)))]
        transactions: Box<Transactions>,
    }
}

impl TransactionBody {
    /// Reencrypt this transaction body
    fn reencrypt(self, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let new_self = match self {
            Self::CreateIdentityV1 { admin_keys, capabilities } => {
                let admin_reenc = admin_keys.into_iter()
                    .map(|x| x.reencrypt(old_master_key, new_master_key))
                    .collect::<Result<Vec<_>>>()?;
                Self::CreateIdentityV1 {
                    admin_keys: admin_reenc,
                    capabilities,
                }
            }
            Self::ResetIdentityV1 { admin_keys, capabilities } => {
                let admin_keys_reenc = admin_keys
                    .map(|keyvec| {
                        keyvec.into_iter()
                            .map(|k| k.reencrypt(old_master_key, new_master_key))
                            .collect::<Result<Vec<_>>>()
                    })
                    .transpose()?;
                Self::ResetIdentityV1 {
                    admin_keys: admin_keys_reenc,
                    capabilities,
                }
            }
            Self::AddAdminKeyV1 { admin_key } => Self::AddAdminKeyV1 {
                admin_key: admin_key.reencrypt(old_master_key, new_master_key)?,
            },
            Self::EditAdminKeyV1 { id, name, description } => Self::EditAdminKeyV1 { id, name, description },
            Self::RevokeAdminKeyV1 { id, reason, new_name } => Self::RevokeAdminKeyV1 { id, reason, new_name },
            Self::AddCapabilityPolicyV1 { capability } => Self::AddCapabilityPolicyV1 { capability },
            Self::DeleteCapabilityPolicyV1 { name } => Self::DeleteCapabilityPolicyV1 { name },
            Self::MakeClaimV1 { spec, name } => Self::MakeClaimV1 {
                spec: spec.reencrypt(old_master_key, new_master_key)?,
                name,
            },
            Self::EditClaimV1 { claim_id, name} => Self::EditClaimV1 { claim_id, name },
            Self::DeleteClaimV1 { claim_id } => Self::DeleteClaimV1 { claim_id },
            Self::MakeStampV1 { stamp } => Self::MakeStampV1 { stamp },
            Self::RevokeStampV1 { revocation } => Self::RevokeStampV1 { revocation },
            Self::AcceptStampV1 { stamp_transaction } => Self::AcceptStampV1 { stamp_transaction },
            Self::DeleteStampV1 { stamp_id } => Self::DeleteStampV1 { stamp_id },
            Self::AddSubkeyV1 { key, name, desc } => {
                let new_subkey = key.reencrypt(old_master_key, new_master_key)?;
                Self::AddSubkeyV1 { key: new_subkey, name, desc }
            }
            Self::EditSubkeyV1 { id, new_name, new_desc } => Self::EditSubkeyV1 { id, new_name, new_desc },
            Self::RevokeSubkeyV1 { id, reason, new_name } => Self::RevokeSubkeyV1 { id, reason, new_name },
            Self::DeleteSubkeyV1 { id } => Self::DeleteSubkeyV1 { id },
            Self::SetNicknameV1 { nickname } => Self::SetNicknameV1 { nickname },
            Self::PublishV1 { transactions } => Self::PublishV1 {
                transactions: Box::new(transactions.reencrypt(old_master_key, new_master_key)?),
            },
        };
        Ok(new_self)
    }
}

impl Public for TransactionBody {
    fn strip_private(&self) -> Self {
        match self.clone() {
            Self::CreateIdentityV1 { admin_keys, capabilities } => {
                let admin_stripped = admin_keys.into_iter()
                    .map(|k| k.strip_private())
                    .collect::<Vec<_>>();
                Self::CreateIdentityV1 { admin_keys: admin_stripped, capabilities}
            }
            Self::ResetIdentityV1 { admin_keys, capabilities } => {
                let stripped_admin = admin_keys
                    .map(|keys| {
                        keys.into_iter()
                            .map(|k| k.strip_private())
                            .collect::<Vec<_>>()
                    });
                Self::ResetIdentityV1 { admin_keys: stripped_admin, capabilities }
            }
            Self::AddAdminKeyV1 { admin_key } => Self::AddAdminKeyV1 { admin_key: admin_key.strip_private() },
            Self::EditAdminKeyV1 { id, name, description } => Self::EditAdminKeyV1 { id, name, description },
            Self::RevokeAdminKeyV1 { id, reason, new_name } => Self::RevokeAdminKeyV1 { id, reason, new_name },
            Self::AddCapabilityPolicyV1 { capability } => Self::AddCapabilityPolicyV1 { capability },
            Self::DeleteCapabilityPolicyV1 { name } => Self::DeleteCapabilityPolicyV1 { name },
            Self::MakeClaimV1 { spec, name } => Self::MakeClaimV1 { spec: spec.strip_private(), name },
            Self::EditClaimV1 { claim_id, name } => Self::EditClaimV1 { claim_id, name },
            Self::DeleteClaimV1 { claim_id } => Self::DeleteClaimV1 { claim_id },
            Self::MakeStampV1 { stamp } => Self::MakeStampV1 { stamp },
            Self::RevokeStampV1 { revocation } => Self::RevokeStampV1 { revocation },
            Self::AcceptStampV1 { stamp_transaction } => Self::AcceptStampV1 { stamp_transaction: Box::new(stamp_transaction.strip_private()) },
            Self::DeleteStampV1 { stamp_id } => Self::DeleteStampV1 { stamp_id },
            Self::AddSubkeyV1 { key, name, desc } => Self::AddSubkeyV1 { key: key.strip_private(), name, desc },
            Self::EditSubkeyV1 { id, new_name, new_desc } => Self::EditSubkeyV1 { id, new_name, new_desc },
            Self::RevokeSubkeyV1 { id, reason, new_name } => Self::RevokeSubkeyV1 { id, reason, new_name },
            Self::DeleteSubkeyV1 { id } => Self::DeleteSubkeyV1 { id },
            Self::SetNicknameV1 { nickname } => Self::SetNicknameV1 { nickname },
            Self::PublishV1 { transactions } => Self::PublishV1 { transactions: Box::new(transactions.strip_private()) },
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::CreateIdentityV1 { admin_keys, .. } => admin_keys.iter().find(|k| k.has_private()).is_some(),
            Self::ResetIdentityV1 { admin_keys, .. } => {
                admin_keys
                    .as_ref()
                    .map(|keys| keys.iter().find(|x| x.key().has_private()).is_some())
                    .unwrap_or(false)
            }
            Self::AddAdminKeyV1 { admin_key } => admin_key.has_private(),
            Self::EditAdminKeyV1 { .. } => false,
            Self::RevokeAdminKeyV1 { .. } => false,
            Self::AddCapabilityPolicyV1 { .. } => false,
            Self::DeleteCapabilityPolicyV1 { .. } => false,
            Self::MakeClaimV1 { spec, .. } => spec.has_private(),
            Self::EditClaimV1 { .. } => false,
            Self::DeleteClaimV1 { .. } => false,
            Self::MakeStampV1 { .. } => false,
            Self::RevokeStampV1 { .. } => false,
            Self::AcceptStampV1 { .. } => false,
            Self::DeleteStampV1 { .. } => false,
            Self::AddSubkeyV1 { key, .. } => key.has_private(),
            Self::EditSubkeyV1 { .. } => false,
            Self::RevokeSubkeyV1 { .. } => false,
            Self::DeleteSubkeyV1 { .. } => false,
            Self::SetNicknameV1 { .. } => false,
            Self::PublishV1 { transactions } => transactions.has_private(),
        }
    }
}

/// The TransactionID is a SHA512 hash of the transaction body
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
pub struct TransactionID(Sha512);

impl From<Sha512> for TransactionID {
    fn from(sha: Sha512) -> Self {
        Self(sha)
    }
}

impl Deref for TransactionID {
    type Target = Sha512;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<TransactionID> for String {
    fn from(id: TransactionID) -> Self {
        ser::base64_encode(&id.deref().deref())
    }
}

impl From<&TransactionID> for String {
    fn from(id: &TransactionID) -> Self {
        ser::base64_encode(&id.deref().deref())
    }
}

impl Hash for TransactionID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.deref().hash(state);
    }
}

impl Eq for TransactionID {}

impl std::fmt::Display for TransactionID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", ser::base64_encode(self.deref().deref()))
    }
}

#[cfg(test)]
impl TransactionID {
    pub(crate) fn random() -> Self {
        Self(Sha512::random())
    }
}

/// The body of an identity transaction. Holds the transaction's references to
/// its previous transactions and the transaction type/data itself.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct TransactionEntry {
    /// When this transaction was created.
    #[rasn(tag(explicit(0)))]
    created: Timestamp,
    /// This is a list of previous transactions that are not already listed by
    /// another transaction.
    ///
    /// In general, this will only list the last transaction, but it's possible
    /// that you might make two separate changes on two separate devices and
    /// when they sync, you will have two leading transactions. The next change
    /// you make to your identity would sign both of those transactions, and
    /// merge the "tree" back into a single trunk.
    ///
    /// Note that when listing previous transactions, their `created` times must
    /// be *less than* this transaction's created time. Future transactions
    /// cannot be signed into a past one.
    #[rasn(tag(explicit(1)))]
    previous_transactions: Vec<TransactionID>,
    /// This holds the actual transaction data.
    #[rasn(tag(explicit(2)))]
    body: TransactionBody,
}

impl TransactionEntry {
    /// Create a new entry.
    pub(crate) fn new<T: Into<Timestamp>>(created: T, previous_transactions: Vec<TransactionID>, body: TransactionBody) -> Self {
        Self {
            created: created.into(),
            previous_transactions,
            body,
        }
    }
}

impl Public for TransactionEntry {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_body(self.body().strip_private());
        clone
    }

    fn has_private(&self) -> bool {
        self.body().has_private()
    }
}

/// A transaction represents a single change on an identity object. In order to
/// build an identity, all transactions are played in order from start to finish.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Transaction {
    /// This is a SHA512 hash of the transaction's `entry`
    #[rasn(tag(explicit(0)))]
    id: TransactionID,
    /// This holds our transaction body: any references to previous
    /// transactions as well as the transaction type/data.
    #[rasn(tag(explicit(1)))]
    entry: TransactionEntry,
    /// The signatures on this transaction's ID.
    #[rasn(tag(explicit(2)))]
    signatures: Vec<PolicySignature>,
}

impl Transaction {
    /// Create a new Transaction from a [TransactionEntry].
    pub(crate) fn new(entry: TransactionEntry) -> Result<Self> {
        let serialized = ser::serialize(&entry.strip_private())?;
        let id = TransactionID::from(Sha512::hash(&serialized)?);
        Ok(Self {
            id,
            entry,
            signatures: Vec::new(),
        })
    }

    /// Sign this transaction. This consumes the transaction, adds the signature
    /// to the `signatures` list, then returns the new transaction.
    pub(crate) fn sign(mut self, master_key: &SecretKey, admin_key: &AdminKey) -> Result<Self> {
        let sig = admin_key.key().sign(master_key, self.id().deref().deref())?;
        let policy_sig = PolicySignature::Key {
            key: admin_key.key().clone().into(),
            signature: sig,
        };
        self.signatures_mut().push(policy_sig);
        Ok(self)
    }

    /// Verify that the signatures on this transaction match the transaction.
    pub(crate) fn verify_signatures(&self) -> Result<()> {
        if self.signatures().len() == 0 {
            Err(Error::TransactionNoSignatures)?;
        }
        for sig in self.signatures() {
            match sig {
                PolicySignature::Key { key, signature } => {
                    match key.verify(signature, self.id().deref().deref()) {
                        Err(_) => Err(Error::TransactionSignatureInvalid(key.clone()))?,
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    /// Verify this transaction's validity. We have to make sure its ID matches
    /// the hash of its public contents, and we have to make sure the signatures
    /// satisfy a policy which has the capabilities the transaction requires.
    pub(crate) fn verify(&self, identity_maybe: Option<&Identity>) -> Result<()> {
        let serialized = ser::serialize(&self.entry().strip_private())?;
        // first verify the transaction's hash.
        let transaction_hash = Sha512::hash(&serialized[..])?;
        if &transaction_hash != self.id().deref() {
            Err(Error::TransactionIDMismatch(self.id().clone()))?;
        }

        // now verify the signatures on the stinkin transaction
        self.verify_signatures()?;

        macro_rules! search_capabilities {
            ($identity:expr) => {
                let mut found_match = false;
                let contexts = Context::contexts_from_transaction(self, $identity);
                for capability in $identity.capabilities() {
                    if capability.validate_transaction(self, &contexts).is_ok() {
                        found_match = true;
                        break;
                    }
                }
                if !found_match {
                    Err(Error::PolicyNotFound)?;
                }
            }
        }

        // if we got here, the transaction, and all the signatures on it, are
        // valid. now we need to figure out if the transaction/signatures match
        // any policy within the identity (if it exists).
        match identity_maybe.as_ref() {
            // if we have an identity, we can verify this transaction using the
            // public keys contained in the identity
            Some(identity) => {
                search_capabilities! { identity }
                Ok(())
            }
            // we don't have an identity, so this is necessarily the genesis
            // transaction that creates it.
            None => {
                match self.entry().body() {
                    TransactionBody::CreateIdentityV1 { admin_keys, capabilities } => {
                        // create an identity with the given keys/capabilities
                        // and see if it will validate its own genesis transaction
                        let identity = Identity::create(IdentityID::from(self.id().clone()), admin_keys.clone(), capabilities.clone(), self.entry().created().clone());
                        search_capabilities! { &identity }
                        Ok(())
                    }
                    _ => Err(Error::DagNoGenesis)?,
                }
            }
        }
    }

    /// Reencrypt this transaction.
    pub(crate) fn reencrypt(mut self, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let new_body = self.entry().body().clone().reencrypt(old_master_key, new_master_key)?;
        self.entry_mut().set_body(new_body);
        Ok(self)
    }
}

impl Public for Transaction {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_entry(self.entry().strip_private());
        clone
    }

    fn has_private(&self) -> bool {
        self.entry().has_private()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::key::{SignKeypair, CryptoKeypair},
        identity::{
            claim::{Relationship, RelationshipType},
            keychain::AdminKeypair,
            stamp::Confidence,
        },
        policy::Policy,
        private::{Private, MaybePrivate},
        util::{Date, Url, ser::BinaryVec, test},
    };
    use std::str::FromStr;

    macro_rules! assert_signkey {
        ($trans:expr, $keyty:ident) => {
            match $trans.id() {
                TransactionID::$keyty(..) => {}
                _ => panic!("Expected sign key type {}, found {:?}", stringify!($keyty), $trans.id()),
            }
        }
    }

    #[test]
    fn trans_body_strip_has_private() {
        fn test_privates(body: &TransactionBody) {
            match body {
                TransactionBody::CreateIdentityV1 { admin_keys, capabilities } => {
                    assert!(body.has_private());
                    assert!(!body.strip_private().has_private());
                    let body2 = TransactionBody::CreateIdentityV1 {
                        admin_keys: admin_keys.clone().into_iter().map(|x| x.strip_private()).collect::<Vec<_>>(),
                        capabilities: capabilities.clone(),
                    };
                    assert!(!body2.has_private());
                }
                TransactionBody::ResetIdentityV1 { admin_keys, capabilities } => {
                    assert!(body.has_private());
                    assert!(!body.strip_private().has_private());
                    let body2 = TransactionBody::ResetIdentityV1 {
                        admin_keys: admin_keys.clone().map(|x| x.into_iter().map(|y| y.strip_private()).collect::<Vec<_>>()),
                        capabilities: capabilities.clone(),
                    };
                    assert!(!body2.has_private());
                }
                TransactionBody::AddAdminKeyV1 { admin_key } => {
                    assert!(body.has_private());
                    let body2 = TransactionBody::AddAdminKeyV1 { admin_key: admin_key.strip_private() };
                    assert!(!body2.has_private());
                }
                TransactionBody::EditAdminKeyV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::RevokeAdminKeyV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::AddCapabilityPolicyV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::DeleteCapabilityPolicyV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::MakeClaimV1 { spec, name } => {
                    assert_eq!(body.has_private(), spec.has_private());
                    let body2 = TransactionBody::MakeClaimV1 { spec: spec.strip_private(), name: name.clone() };
                    assert!(!body2.has_private());
                    let body3 = body.strip_private();
                    assert!(!body3.has_private());
                    let body4 = body3.strip_private();
                    assert!(!body4.has_private());
                }
                TransactionBody::EditClaimV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::DeleteClaimV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::MakeStampV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::RevokeStampV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::AcceptStampV1 { stamp_transaction } => {
                    assert!(!body.has_private());
                    assert!(!stamp_transaction.has_private());
                }
                TransactionBody::DeleteStampV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::AddSubkeyV1 { key, name, desc } => {
                    assert!(body.has_private());
                    let body2 = TransactionBody::AddSubkeyV1 {
                        key: key.strip_private(),
                        name: name.clone(),
                        desc: desc.clone(),
                    };
                    assert!(!body2.has_private());
                    let body3 = body.strip_private();
                    assert!(!body3.has_private());
                }
                TransactionBody::EditSubkeyV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::RevokeSubkeyV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::DeleteSubkeyV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::SetNicknameV1 { .. } => {
                    assert!(!body.has_private());
                }
                // blehhhh...
                TransactionBody::PublishV1 { .. } => { }
            }
        }

        let (master_key, transactions, admin_key) = test::create_fake_identity(Timestamp::now());

        test_privates(&TransactionBody::CreateIdentityV1 { admin_keys: vec![admin_key.clone()], capabilities: Vec::new() });
        test_privates(&TransactionBody::ResetIdentityV1 { admin_keys: Some(vec![admin_key.clone()]), capabilities: None });
        test_privates(&TransactionBody::AddAdminKeyV1 { admin_key: admin_key.clone() });
        test_privates(&TransactionBody::EditAdminKeyV1 { id: admin_key.key().key_id(), name: Some("poopy".into()), description: None });
        test_privates(&TransactionBody::RevokeAdminKeyV1 { id: admin_key.key().key_id(), reason: RevocationReason::Compromised, new_name: Some("old key".into()) });

        let policy = CapabilityPolicy::new("omg".into(), vec![], Policy::MOfN { must_have: 0, participants: vec![] });
        test_privates(&TransactionBody::AddCapabilityPolicyV1 { capability: policy });
        test_privates(&TransactionBody::DeleteCapabilityPolicyV1 { name: "omg".into() });
        test_privates(&TransactionBody::MakeClaimV1 { spec: ClaimSpec::Name(MaybePrivate::new_public(String::from("Negative Nancy"))), name: None });
        test_privates(&TransactionBody::MakeClaimV1 { spec: ClaimSpec::Name(MaybePrivate::new_private(&master_key, String::from("Positive Pyotr")).unwrap()), name: Some("Grover".into()) });
        test_privates(&TransactionBody::DeleteClaimV1 { claim_id: ClaimID::random() });

        let entry = StampEntry::new::<Timestamp>(IdentityID::random(), IdentityID::random(), ClaimID::random(), Confidence::Low, None);
        test_privates(&TransactionBody::MakeStampV1 { stamp: entry.clone() });
        let revocation = StampRevocationEntry::new(IdentityID::random(), IdentityID::random(), StampID::random());
        test_privates(&TransactionBody::RevokeStampV1 { revocation });
        let stamp_transaction = transactions.make_stamp(Timestamp::now(), entry.clone()).unwrap();
        test_privates(&TransactionBody::AcceptStampV1 { stamp_transaction: Box::new(stamp_transaction) });
        test_privates(&TransactionBody::DeleteStampV1 { stamp_id: StampID::random() });

        let key = Key::new_sign(admin_key.key().deref().clone());
        let key_id = key.key_id();
        test_privates(&TransactionBody::AddSubkeyV1 {
            key,
            name: "MY DOGECOIN KEY".into(),
            desc: Some("plz send doge".into()),
        });
        test_privates(&TransactionBody::EditSubkeyV1 {
            id: key_id.clone(),
            new_name: Some("MAI DOGE KEY".into()),
            new_desc: Some(None),
        });
        test_privates(&TransactionBody::RevokeSubkeyV1 {
            id: key_id.clone(),
            reason: RevocationReason::Compromised,
            new_name: Some("REVOKED DOGE KEY".into()),
        });
        test_privates(&TransactionBody::DeleteSubkeyV1 { id: key_id.clone() });
        test_privates(&TransactionBody::SetNicknameV1 { nickname: Some("wreck-dum".into()) });
    }

    #[test]
    fn trans_entry_strip_has_private() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let body = TransactionBody::MakeClaimV1 {
            spec: ClaimSpec::Name(MaybePrivate::new_private(&master_key, "Jackie Chrome".into()).unwrap()),
            name: None,
        };
        let entry = TransactionEntry::new(Timestamp::now(), vec![TransactionID::from(Sha512::random())], body);
        assert!(entry.has_private());
        assert!(entry.body().has_private());
        let entry2 = entry.strip_private();
        assert!(!entry2.has_private());
        assert!(!entry2.body().has_private());
    }

    #[test]
    fn trans_new_verify() {
        todo!();
        /*
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = AdminKeypair::new_ed25519(&master_key).unwrap();
        let identity = Identity::create(IdentityID::random(), alpha_keypair.clone(), policy_keypair.clone(), publish_keypair.clone(), root_keypair.clone(), Timestamp::now());

        let body = TransactionBody::CreateIdentityV1 {
            alpha: alpha_keypair.clone(),
            policy: policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair.clone(),
        };
        let now = Timestamp::now();
        let entry = TransactionEntry::new(now.clone(), vec![], body);
        let trans = Transaction::new(&master_key, &None, SignWith::Alpha, entry.clone()).unwrap();
        trans.verify(None).unwrap();

        let res = Transaction::new(&master_key, &None, SignWith::Policy, entry.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));

        let res = Transaction::new(&master_key, &None, SignWith::Root, entry.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));

        let body2 = TransactionBody::DeleteForwardV1 { name: "blassssstodon".into() };
        let entry2 = TransactionEntry::new(Timestamp::now(), vec![], body2);
        let res = Transaction::new(&master_key, &None, SignWith::Alpha, entry2.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));

        let res = Transaction::new(&master_key, &Some(identity.clone()), SignWith::Root, entry.clone());
        assert_eq!(res.err(), Some(Error::DagCreateIdentityOnExistingChain));

        let new_policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        assert!(new_policy_keypair != policy_keypair);
        let action = PolicyRequestAction::ReplaceKeys {
            policy: new_policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair.clone(),
        };
        let entry = PolicyRequestEntry::new(IdentityID::random(), PolicyID::random(), action);
        let req = PolicyRequest::new(&master_key, &new_policy_keypair, entry).unwrap();
        let body_recover = TransactionBody::ExecuteRecoveryPolicyV1 { request: req };
        let entry_recover = TransactionEntry::new(Timestamp::now(), vec![], body_recover);
        let trans_recover = Transaction::new(&master_key, &Some(identity.clone()), SignWith::Policy, entry_recover.clone()).unwrap();
        trans_recover.verify(Some(&identity)).unwrap();
        let res = Transaction::new(&master_key, &None, SignWith::Alpha, entry_recover.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));
        let res = Transaction::new(&master_key, &Some(identity.clone()), SignWith::Alpha, entry_recover.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));
        let res = Transaction::new(&master_key, &Some(identity.clone()), SignWith::Root, entry_recover.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));

        let mut trans2 = trans.clone();
        trans2.set_id(TransactionID::random_alpha());
        assert_eq!(trans2.verify(None).err(), Some(Error::CryptoSignatureVerificationFailed));

        let mut trans3 = trans.clone();
        let then = Timestamp::from(now.deref().clone() - chrono::Duration::seconds(2));
        trans3.entry_mut().set_created(then);
        assert_eq!(trans3.verify(None).err(), Some(Error::CryptoSignatureVerificationFailed));

        let mut trans4 = trans.clone();
        trans4.entry_mut().set_previous_transactions(vec![TransactionID::random_alpha()]);
        assert_eq!(trans4.verify(None).err(), Some(Error::CryptoSignatureVerificationFailed));

        let mut trans5 = trans.clone();
        let root_keypair2 = AdminKeypair::new_ed25519(&master_key).unwrap();
        assert!(root_keypair != root_keypair2);
        let body = TransactionBody::CreateIdentityV1 {
            alpha: alpha_keypair.clone(),
            policy: policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair2.clone(),
        };
        trans5.entry_mut().set_body(body);
        assert_eq!(trans5.verify(None).err(), Some(Error::CryptoSignatureVerificationFailed));
        */
    }

    #[test]
    fn trans_strip_has_private() {
        todo!();
        /*
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = AdminKeypair::new_ed25519(&master_key).unwrap();

        let body = TransactionBody::CreateIdentityV1 {
            alpha: alpha_keypair.clone(),
            policy: policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair.clone(),
        };
        let entry = TransactionEntry::new(Timestamp::now(), vec![], body);
        let trans = Transaction::new(&master_key, &None, SignWith::Alpha, entry.clone()).unwrap();

        assert!(trans.has_private());
        assert!(trans.entry().has_private());
        assert!(trans.entry().body().has_private());
        let trans2 = trans.strip_private();
        assert!(!trans2.has_private());
        assert!(!trans2.entry().has_private());
        assert!(!trans2.entry().body().has_private());
        */
    }
}

