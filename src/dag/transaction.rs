//! A `Transaction` models a single change against an identity, and is one node
//! inside of the identity DAG.
//!
//! Transactions have a [TransactionBody], an ID ([Hash][crate::crypto::base::Hash]
//! of the transaction's body, timestamp, and previously-referenced transactions),
//! and a collection of one or more signatures on the transaction's ID that validate
//! that transaction.

use crate::{
    error::{Error, Result},
    crypto::base::{KeyID, SecretKey, Hash, HashAlgo},
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
            AdminKeyID,
            AdminKeypair,
            AdminKeypairPublic,
            ExtendKeypair,
            Key,
            RevocationReason,
        },
        stamp::{
            RevocationReason as StampRevocationReason,
            StampID,
            StampEntry,
        },
    },
    policy::{Context, MultisigPolicySignature, Policy, PolicyContainer, PolicyID},
    util::{
        Public,
        Timestamp,
        ser::{self, BinaryVec, KeyValEntry, SerdeBinary, SerText},
    },
};
use getset;
use rasn::{Encode, Decode, AsnType};
use serde_derive::{Serialize, Deserialize};
use std::hash::{Hash as StdHash, Hasher};
use std::ops::Deref;

/// This is all of the possible transactions that can be performed on an
/// identity, including the data they require.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum TransactionBody {
    /// Create a new identity. The [ID][TransactionID] of this transaction will
    /// be the identity's public ID forever after.
    #[rasn(tag(explicit(0)))]
    CreateIdentityV1 {
        #[rasn(tag(explicit(0)))]
        admin_keys: Vec<AdminKey>,
        #[rasn(tag(explicit(1)))]
        policies: Vec<Policy>,
    },
    /// Replace optionally both the [admin keys][AdminKey] in the [Keychain][crate::identity::keychain::Keychain]
    /// and the [policies][Policy] attached to the identity.
    ///
    /// This is more or less a hailmary recovery option that allows gaining
    /// access to identity after some kind of catastrophic event.
    #[rasn(tag(explicit(1)))]
    ResetIdentityV1 {
        #[rasn(tag(explicit(0)))]
        admin_keys: Option<Vec<AdminKey>>,
        #[rasn(tag(explicit(1)))]
        policies: Option<Vec<Policy>>,
    },
    /// Add a new [admin key][AdminKey] to the [Keychain][crate::identity::keychain::Keychain].
    #[rasn(tag(explicit(2)))]
    AddAdminKeyV1 {
        #[rasn(tag(explicit(0)))]
        admin_key: AdminKey,
    },
    /// Edit an admin key
    #[rasn(tag(explicit(3)))]
    EditAdminKeyV1 {
        #[rasn(tag(explicit(0)))]
        id: AdminKeyID,
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
        id: AdminKeyID,
        #[rasn(tag(explicit(1)))]
        reason: RevocationReason,
        #[rasn(tag(explicit(2)))]
        new_name: Option<String>,
    },
    /// Add a new [Policy] to the identity.
    #[rasn(tag(explicit(5)))]
    AddPolicyV1 {
        #[rasn(tag(explicit(0)))]
        policy: Policy,
    },
    /// Delete (by name) a capability policy from the identity.
    #[rasn(tag(explicit(6)))]
    DeletePolicyV1 {
        #[rasn(tag(explicit(0)))]
        id: PolicyID,
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
        stamp_id: StampID,
        #[rasn(tag(explicit(1)))]
        reason: StampRevocationReason,
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
    /// Publish this identity. This transaction cannot be saved with the identity, but
    /// rather should be published to a public medium (like StampNet!!!!1)
    #[rasn(tag(explicit(18)))]
    PublishV1 {
        #[rasn(tag(explicit(0)))]
        transactions: Box<Transactions>,
    },
    /// Sign a message. The usual Stamp policy process applies here, so an official
    /// identity signing transaction must match an existing policy to be valid. This
    /// allows creating group signatures that are policy-validated.
    ///
    /// To create detached signatures, set `body` to None after signing.
    ///
    /// `Sign` transactions cannot be applied to the identity!
    #[rasn(tag(explicit(19)))]
    SignV1 {
        #[rasn(tag(explicit(0)))]
        creator: IdentityID,
        #[rasn(tag(explicit(1)))]
        body: Option<BinaryVec>,
    },
    /// Create a transaction for use in an external network. This allows Stamp to act
    /// as a transactional medium for other networks. If the members of that network
    /// can speak Stamp, they can use it to create and sign custom transactions.
    /// `Ext` transactions can also benefit not just from signatures and formatting,
    /// but from the `previous_transactions` field which allows DAG-based causal
    /// ordering.
    ///
    /// `Ext` allows specifying an optional transaction type and optional set of
    /// binary contexts, which can be used for matching in the policy system. This
    /// makes it so a policy can determine which [admin keys][AdminKey] can create
    /// valid external transactions.
    ///
    /// Note that `Ext` transactions cannot be applied to the identity...Stamp allows
    /// their creation but provides no methods for executing them.
    #[rasn(tag(explicit(20)))]
    ExtV1 {
        #[rasn(tag(explicit(0)))]
        creator: IdentityID,
        #[rasn(tag(explicit(1)))]
        ty: Option<BinaryVec>,
        #[rasn(tag(explicit(2)))]
        context: Option<Vec<KeyValEntry>>,
        #[rasn(tag(explicit(3)))]
        payload: BinaryVec,
    },
}

impl TransactionBody {
    /// Reencrypt this transaction body
    fn reencrypt(self, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let new_self = match self {
            Self::CreateIdentityV1 { admin_keys, policies } => {
                let admin_reenc = admin_keys.into_iter()
                    .map(|x| x.reencrypt(old_master_key, new_master_key))
                    .collect::<Result<Vec<_>>>()?;
                Self::CreateIdentityV1 {
                    admin_keys: admin_reenc,
                    policies,
                }
            }
            Self::ResetIdentityV1 { admin_keys, policies } => {
                let admin_keys_reenc = admin_keys
                    .map(|keyvec| {
                        keyvec.into_iter()
                            .map(|k| k.reencrypt(old_master_key, new_master_key))
                            .collect::<Result<Vec<_>>>()
                    })
                    .transpose()?;
                Self::ResetIdentityV1 {
                    admin_keys: admin_keys_reenc,
                    policies,
                }
            }
            Self::AddAdminKeyV1 { admin_key } => Self::AddAdminKeyV1 {
                admin_key: admin_key.reencrypt(old_master_key, new_master_key)?,
            },
            Self::EditAdminKeyV1 { id, name, description } => Self::EditAdminKeyV1 { id, name, description },
            Self::RevokeAdminKeyV1 { id, reason, new_name } => Self::RevokeAdminKeyV1 { id, reason, new_name },
            Self::AddPolicyV1 { policy } => Self::AddPolicyV1 { policy },
            Self::DeletePolicyV1 { id } => Self::DeletePolicyV1 { id },
            Self::MakeClaimV1 { spec, name } => Self::MakeClaimV1 {
                spec: spec.reencrypt(old_master_key, new_master_key)?,
                name,
            },
            Self::EditClaimV1 { claim_id, name} => Self::EditClaimV1 { claim_id, name },
            Self::DeleteClaimV1 { claim_id } => Self::DeleteClaimV1 { claim_id },
            Self::MakeStampV1 { stamp } => Self::MakeStampV1 { stamp },
            Self::RevokeStampV1 { stamp_id, reason } => Self::RevokeStampV1 { stamp_id, reason },
            Self::AcceptStampV1 { stamp_transaction } => Self::AcceptStampV1 { stamp_transaction },
            Self::DeleteStampV1 { stamp_id } => Self::DeleteStampV1 { stamp_id },
            Self::AddSubkeyV1 { key, name, desc } => {
                let new_subkey = key.reencrypt(old_master_key, new_master_key)?;
                Self::AddSubkeyV1 { key: new_subkey, name, desc }
            }
            Self::EditSubkeyV1 { id, new_name, new_desc } => Self::EditSubkeyV1 { id, new_name, new_desc },
            Self::RevokeSubkeyV1 { id, reason, new_name } => Self::RevokeSubkeyV1 { id, reason, new_name },
            Self::DeleteSubkeyV1 { id } => Self::DeleteSubkeyV1 { id },
            Self::PublishV1 { transactions } => Self::PublishV1 {
                transactions: Box::new(transactions.reencrypt(old_master_key, new_master_key)?),
            },
            Self::SignV1 { creator, body } => Self::SignV1 { creator, body },
            Self::ExtV1 { creator, ty, context, payload } => Self::ExtV1 { creator, ty, context, payload },
        };
        Ok(new_self)
    }
}

impl Public for TransactionBody {
    fn strip_private(&self) -> Self {
        match self.clone() {
            Self::CreateIdentityV1 { admin_keys, policies } => {
                let admin_stripped = admin_keys.into_iter()
                    .map(|k| k.strip_private())
                    .collect::<Vec<_>>();
                Self::CreateIdentityV1 { admin_keys: admin_stripped, policies }
            }
            Self::ResetIdentityV1 { admin_keys, policies } => {
                let stripped_admin = admin_keys
                    .map(|keys| {
                        keys.into_iter()
                            .map(|k| k.strip_private())
                            .collect::<Vec<_>>()
                    });
                Self::ResetIdentityV1 { admin_keys: stripped_admin, policies }
            }
            Self::AddAdminKeyV1 { admin_key } => Self::AddAdminKeyV1 { admin_key: admin_key.strip_private() },
            Self::EditAdminKeyV1 { id, name, description } => Self::EditAdminKeyV1 { id, name, description },
            Self::RevokeAdminKeyV1 { id, reason, new_name } => Self::RevokeAdminKeyV1 { id, reason, new_name },
            Self::AddPolicyV1 { policy } => Self::AddPolicyV1 { policy },
            Self::DeletePolicyV1 { id } => Self::DeletePolicyV1 { id },
            Self::MakeClaimV1 { spec, name } => Self::MakeClaimV1 { spec: spec.strip_private(), name },
            Self::EditClaimV1 { claim_id, name } => Self::EditClaimV1 { claim_id, name },
            Self::DeleteClaimV1 { claim_id } => Self::DeleteClaimV1 { claim_id },
            Self::MakeStampV1 { stamp } => Self::MakeStampV1 { stamp },
            Self::RevokeStampV1 { stamp_id, reason } => Self::RevokeStampV1 { stamp_id, reason },
            Self::AcceptStampV1 { stamp_transaction } => Self::AcceptStampV1 { stamp_transaction: Box::new(stamp_transaction.strip_private()) },
            Self::DeleteStampV1 { stamp_id } => Self::DeleteStampV1 { stamp_id },
            Self::AddSubkeyV1 { key, name, desc } => Self::AddSubkeyV1 { key: key.strip_private(), name, desc },
            Self::EditSubkeyV1 { id, new_name, new_desc } => Self::EditSubkeyV1 { id, new_name, new_desc },
            Self::RevokeSubkeyV1 { id, reason, new_name } => Self::RevokeSubkeyV1 { id, reason, new_name },
            Self::DeleteSubkeyV1 { id } => Self::DeleteSubkeyV1 { id },
            Self::PublishV1 { transactions } => Self::PublishV1 { transactions: Box::new(transactions.strip_private()) },
            Self::SignV1 { creator, body } => Self::SignV1 { creator, body },
            Self::ExtV1 { creator, ty, context, payload } => Self::ExtV1 { creator, ty, context, payload },
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
            Self::AddPolicyV1 { .. } => false,
            Self::DeletePolicyV1 { .. } => false,
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
            Self::PublishV1 { transactions } => transactions.has_private(),
            Self::SignV1 { .. } => false,
            Self::ExtV1 { .. } => false,
        }
    }
}

/// The TransactionID is a [Hash][crate::crypto::base::Hash] of the transaction body
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
pub struct TransactionID(Hash);

impl TransactionID {
    pub(crate) fn as_string(&self) -> String {
        format!("{}", self.deref())
    }
}

impl From<Hash> for TransactionID {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl Deref for TransactionID {
    type Target = Hash;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&TransactionID> for String {
    type Error = Error;

    fn try_from(tid: &TransactionID) -> std::result::Result<Self, Self::Error> {
        String::try_from(tid.deref())
    }
}

impl TryFrom<&str> for TransactionID {
    type Error = Error;

    fn try_from(string: &str) -> std::result::Result<Self, Self::Error> {
        Ok(TransactionID::from(Hash::try_from(string)?))
    }
}

impl StdHash for TransactionID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.deref().as_bytes().hash(state);
    }
}

impl Eq for TransactionID {}

impl std::fmt::Display for TransactionID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.deref())
    }
}

#[cfg(test)]
impl TransactionID {
    pub(crate) fn random() -> Self {
        Self(Hash::random_blake2b_512())
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
    /// This is a hash of the transaction's `entry`
    #[rasn(tag(explicit(0)))]
    id: TransactionID,
    /// This holds our transaction body: any references to previous
    /// transactions as well as the transaction type/data.
    #[rasn(tag(explicit(1)))]
    entry: TransactionEntry,
    /// The signatures on this transaction's ID.
    #[rasn(tag(explicit(2)))]
    signatures: Vec<MultisigPolicySignature>,
}

impl Transaction {
    /// Create a new Transaction from a [TransactionEntry].
    pub(crate) fn new(entry: TransactionEntry, hash_with: &HashAlgo) -> Result<Self> {
        let serialized = ser::serialize(&entry.strip_private())?;
        let hash = match hash_with {
            HashAlgo::Blake2b512 => Hash::new_blake2b_512(&serialized)?,
            HashAlgo::Blake2b256 => Hash::new_blake2b_256(&serialized)?,
        };
        let id = TransactionID::from(hash);
        Ok(Self {
            id,
            entry,
            signatures: Vec::new(),
        })
    }

    /// Sign this transaction. This consumes the transaction, adds the signature
    /// to the `signatures` list, then returns the new transaction.
    pub fn sign<K>(mut self, master_key: &SecretKey, admin_key: &K) -> Result<Self>
        where K: Deref<Target = AdminKeypair>
    {
        let admin_key = admin_key.deref();
        let admin_key_pub: AdminKeypairPublic = admin_key.clone().into();
        let sig_exists = self.signatures().iter()
            .find(|sig| {
                match sig {
                    MultisigPolicySignature::Key { key, .. } => key == &admin_key_pub,
                }
            });
        if sig_exists.is_some() {
            Err(Error::DuplicateSignature)?;
        }
        let serialized = ser::serialize(self.id().deref())?;
        let sig = admin_key.sign(master_key, &serialized[..])?;
        let policy_sig = MultisigPolicySignature::Key {
            key: admin_key.clone().into(),
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
        let ver_sig = ser::serialize(self.id().deref())?;
        for sig in self.signatures() {
            match sig {
                MultisigPolicySignature::Key { key, signature } => {
                    match key.verify(signature, &ver_sig[..]) {
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
    pub fn verify(&self, identity_maybe: Option<&Identity>) -> Result<()> {
        let serialized = ser::serialize(&self.entry().strip_private())?;
        // first verify the transaction's hash.
        let transaction_hash = match self.id().deref() {
            Hash::Blake2b512(..) => Hash::new_blake2b_512(&serialized[..])?,
            Hash::Blake2b256(..) => Hash::new_blake2b_256(&serialized[..])?,
        };
        if &transaction_hash != self.id().deref() {
            Err(Error::TransactionIDMismatch(self.id().clone()))?;
        }

        // now verify the signatures on the stinkin transaction
        self.verify_signatures()?;

        macro_rules! search_capabilities {
            ($identity:expr) => {
                let mut found_match = false;
                let contexts = Context::contexts_from_transaction(self, $identity);
                for policy in $identity.policies() {
                    if policy.validate_transaction(self, &contexts).is_ok() {
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
                    TransactionBody::CreateIdentityV1 { admin_keys, policies } => {
                        // create an identity with the given keys/capabilities
                        // and see if it will validate its own genesis transaction
                        let policies_con = policies
                            .iter()
                            .map(|x| PolicyContainer::try_from(x.clone()))
                            .collect::<Result<Vec<PolicyContainer>>>()?;
                        let identity = Identity::create(IdentityID::from(self.id().clone()), admin_keys.clone(), policies_con, self.entry().created().clone());
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

impl SerdeBinary for Transaction {}
impl SerText for Transaction {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::{
            stamp::Confidence,
        },
        policy::{MultisigPolicy, Policy},
        private::{MaybePrivate},
        util::test,
    };

    #[test]
    fn trans_body_strip_has_private() {
        fn test_privates(body: &TransactionBody) {
            match body {
                TransactionBody::CreateIdentityV1 { admin_keys, policies } => {
                    assert!(body.has_private());
                    assert!(!body.strip_private().has_private());
                    let body2 = TransactionBody::CreateIdentityV1 {
                        admin_keys: admin_keys.clone().into_iter().map(|x| x.strip_private()).collect::<Vec<_>>(),
                        policies: policies.clone(),
                    };
                    assert!(!body2.has_private());
                }
                TransactionBody::ResetIdentityV1 { admin_keys, policies } => {
                    assert!(body.has_private());
                    assert!(!body.strip_private().has_private());
                    let body2 = TransactionBody::ResetIdentityV1 {
                        admin_keys: admin_keys.clone().map(|x| x.into_iter().map(|y| y.strip_private()).collect::<Vec<_>>()),
                        policies: policies.clone(),
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
                TransactionBody::AddPolicyV1 { .. } => {
                    assert!(!body.has_private());
                }
                TransactionBody::DeletePolicyV1 { .. } => {
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
                // blehhhh...
                TransactionBody::PublishV1 { .. } => { }
                // blehhhh...
                TransactionBody::SignV1 { .. } => { }
                // blehhhh...
                TransactionBody::ExtV1 { .. } => { }
            }
        }

        let (master_key, transactions, admin_key) = test::create_fake_identity(Timestamp::now());

        test_privates(&TransactionBody::CreateIdentityV1 { admin_keys: vec![admin_key.clone()], policies: Vec::new() });
        test_privates(&TransactionBody::ResetIdentityV1 { admin_keys: Some(vec![admin_key.clone()]), policies: None });
        test_privates(&TransactionBody::AddAdminKeyV1 { admin_key: admin_key.clone() });
        test_privates(&TransactionBody::EditAdminKeyV1 { id: admin_key.key_id(), name: Some("poopy".into()), description: None });
        test_privates(&TransactionBody::RevokeAdminKeyV1 { id: admin_key.key_id(), reason: RevocationReason::Compromised, new_name: Some("old key".into()) });

        let policy = Policy::new(vec![], MultisigPolicy::MOfN { must_have: 0, participants: vec![] });
        test_privates(&TransactionBody::AddPolicyV1 { policy });
        test_privates(&TransactionBody::DeletePolicyV1 { id: PolicyID::random() });
        test_privates(&TransactionBody::MakeClaimV1 { spec: ClaimSpec::Name(MaybePrivate::new_public(String::from("Negative Nancy"))), name: None });
        test_privates(&TransactionBody::MakeClaimV1 { spec: ClaimSpec::Name(MaybePrivate::new_private(&master_key, String::from("Positive Pyotr")).unwrap()), name: Some("Grover".into()) });
        test_privates(&TransactionBody::DeleteClaimV1 { claim_id: ClaimID::random() });

        let entry = StampEntry::new::<Timestamp>(IdentityID::random(), IdentityID::random(), ClaimID::random(), Confidence::Low, None);
        test_privates(&TransactionBody::MakeStampV1 { stamp: entry.clone() });
        test_privates(&TransactionBody::RevokeStampV1 { stamp_id: StampID::random(), reason: StampRevocationReason::Unspecified });
        let stamp_transaction = transactions.make_stamp(&HashAlgo::Blake2b512, Timestamp::now(), entry.clone()).unwrap();
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
    }

    #[test]
    fn trans_entry_strip_has_private() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let body = TransactionBody::MakeClaimV1 {
            spec: ClaimSpec::Name(MaybePrivate::new_private(&master_key, "Jackie Chrome".into()).unwrap()),
            name: None,
        };
        let entry = TransactionEntry::new(Timestamp::now(), vec![TransactionID::from(Hash::random_blake2b_512())], body);
        assert!(entry.has_private());
        assert!(entry.body().has_private());
        let entry2 = entry.strip_private();
        assert!(!entry2.has_private());
        assert!(!entry2.body().has_private());
    }

    #[test]
    fn trans_new_verify() {
        let now = Timestamp::now();
        let (_master_key, transactions, admin_key) = test::create_fake_identity(now.clone());
        transactions.transactions()[0].verify(None).unwrap();

        let (_, transactions_new, _) = test::create_fake_identity(now.clone());

        let create2 = transactions_new.transactions()[0].clone();

        let res = transactions.clone().push_transaction(create2);
        assert_eq!(res.err(), Some(Error::DagCreateIdentityOnExistingChain));

        let mut trans2 = transactions.transactions()[0].clone();
        trans2.set_id(TransactionID::random());
        assert!(matches!(trans2.verify(None).err(), Some(Error::TransactionIDMismatch(..))));

        let mut trans3 = transactions.transactions()[0].clone();
        let then = Timestamp::from(now.deref().clone() - chrono::Duration::seconds(2));
        trans3.entry_mut().set_created(then);
        assert!(matches!(trans3.verify(None).err(), Some(Error::TransactionIDMismatch(..))));

        let mut trans4 = transactions.transactions()[0].clone();
        trans4.entry_mut().set_previous_transactions(vec![TransactionID::random()]);
        assert!(matches!(trans4.verify(None).err(), Some(Error::TransactionIDMismatch(..))));

        let mut trans5 = transactions.transactions()[0].clone();
        trans5.entry_mut().set_body(TransactionBody::CreateIdentityV1 {
            admin_keys: vec![admin_key.clone()],
            policies: vec![],
        });
        assert!(matches!(trans5.verify(None).err(), Some(Error::TransactionIDMismatch(..))));
    }

    #[test]
    fn trans_strip_has_private() {
        let now = Timestamp::now();
        let (_master_key, transactions, _admin_key) = test::create_fake_identity(now.clone());
        let trans = transactions.transactions()[0].clone();

        assert!(trans.has_private());
        assert!(trans.entry().has_private());
        assert!(trans.entry().body().has_private());
        let trans2 = trans.strip_private();
        assert!(!trans2.has_private());
        assert!(!trans2.entry().has_private());
        assert!(!trans2.entry().body().has_private());
    }

    #[test]
    fn trans_serde_binary() {
        let now = Timestamp::now();
        let (_master_key, transactions, _admin_key) = test::create_fake_identity(now.clone());
        let trans = transactions.transactions()[0].clone();

        let ser = trans.serialize_binary().unwrap();
        let des = Transaction::deserialize_binary(ser.as_slice()).unwrap();

        assert_eq!(trans.id(), des.id());
    }
}

