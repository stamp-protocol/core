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
        ser::{self, BinaryVec, HashMapAsn1, SerdeBinary, SerText},
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
    /// access to the identity after some kind of catastrophic event.
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
    /// `Ext` transactions use the policy system, allowing an identity to manage which
    /// keys can issue which transactions.
    ///
    /// `Ext` allows specifying an optional transaction type and optional set of
    /// binary contexts, which can be used for attaching arbitrary key-value data
    /// to the transaction (like tags). Both the type and the contexts can be matched
    /// in the policy system, making it so a policy can determine which [admin keys][AdminKey]
    /// can create valid external transactions.
    ///
    /// Note that `Ext` transactions cannot be applied to the identity...Stamp allows
    /// their creation but provides no methods for executing them.
    #[rasn(tag(explicit(20)))]
    ExtV1 {
        /// The identity that created this transaction
        #[rasn(tag(explicit(0)))]
        creator: IdentityID,
        /// The optional transaction type. Can be used to segment different transactions
        /// from each other in mixed networks.
        #[rasn(tag(explicit(1)))]
        ty: Option<BinaryVec>,
        /// Tells us which *external* transaction(s) came before. This is distinct from
        /// [`TransactionEntry.previous_transactions`][TransactionEntry], which for external
        /// transactions stores the previous transaction IDs *of the identity that issued the
        /// external transaction*, whereas this field allows listing previous transactions
        /// for the external transactions.
        ///
        /// The distinction is important: keeping `TransactionEntry.previous_transactions`
        /// scoped to the identity means that external transactions can be verified against
        /// an identity at a point-in-time.
        #[rasn(tag(explicit(2)))]
        previous_transactions: Vec<TransactionID>,
        /// The context allows setting arbitrary, binary key-value pairs in this transaction
        /// which can be used for policy matching, routing in p2p networks, etc.
        #[rasn(tag(explicit(3)))]
        context: Option<HashMapAsn1<BinaryVec, BinaryVec>>,
        /// The actual transaction body, serialized however you like.
        #[rasn(tag(explicit(4)))]
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
            Self::ExtV1 { creator, ty, previous_transactions, context, payload } => Self::ExtV1 { creator, ty, previous_transactions, context, payload },
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
            Self::ExtV1 { creator, ty, previous_transactions, context, payload } => Self::ExtV1 { creator, ty, previous_transactions, context, payload },
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::CreateIdentityV1 { admin_keys, .. } => admin_keys.iter().any(|k| k.has_private()),
            Self::ResetIdentityV1 { admin_keys, .. } => {
                admin_keys
                    .as_ref()
                    .map(|keys| keys.iter().any(|x| x.key().has_private()))
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

#[cfg(test)]
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

impl std::cmp::PartialOrd for TransactionID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.deref().as_bytes().cmp(other.deref().as_bytes()))
    }
}

impl std::cmp::Ord for TransactionID {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deref().as_bytes().cmp(other.deref().as_bytes())
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
        if self.signatures().is_empty() {
            Err(Error::TransactionNoSignatures)?;
        }
        let ver_sig = ser::serialize(self.id().deref())?;
        for sig in self.signatures() {
            match sig {
                MultisigPolicySignature::Key { key, signature } => {
                    if key.verify(signature, &ver_sig[..]).is_err() {
                        Err(Error::TransactionSignatureInvalid(key.clone()))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Verify the hash on this transaction matches the transaction entry's hash, and also verify
    /// the signatures of that hash.
    ///
    /// This is useful if you need to validate a transaction is "valid" up until the point where
    /// you need a copy of the full identity (so that the policies can be checked). In other words,
    /// if you need a verify a transaction but don't have all the information you need to run
    /// `Transaction.verify()` then you can run this as a self-contained way of verification, as
    /// long as you keep in mind that the transaction ultimately needs to be checked against a
    /// built identity.
    pub fn verify_hash_and_signatures(&self) -> Result<()> {
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
        Ok(())
    }

    /// Verify this transaction's validity. We have to make sure its ID matches
    /// the hash of its public contents, and we have to make sure the signatures
    /// satisfy a policy which has the capabilities the transaction requires.
    pub fn verify(&self, identity_maybe: Option<&Identity>) -> Result<()> {
        self.verify_hash_and_signatures()?;

        macro_rules! search_capabilities {
            ($identity:expr) => {
                let mut found_match = false;
                let contexts = Context::contexts_from_transaction_body(self.entry().body(), $identity);
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
                            .enumerate()
                            .map(|(idx, x)| PolicyContainer::from_policy_transaction(self.id(), idx, x.clone()))
                            .collect::<Result<Vec<PolicyContainer>>>()?;
                        let identity = Identity::create(IdentityID::from(self.id().clone()), admin_keys.clone(), policies_con, self.entry().created().clone());
                        search_capabilities! { &identity }
                        Ok(())
                    }
                    _ => Err(Error::DagGenesisError)?,
                }
            }
        }
    }

    /// Determines if this transaction has been signed by a given key.
    pub fn is_signed_by(&self, admin_key: &AdminKeypairPublic) -> bool {
        self.signatures().iter()
            .find(|sig| {
                match sig {
                    MultisigPolicySignature::Key { key, .. } => key == admin_key,
                }
            })
            .is_some()
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
        crypto::base::SignKeypair,
        identity::{
            keychain::RevocationReason,
            stamp::Confidence,
        },
        policy::{Capability, Context, ContextClaimType, MultisigPolicy, Policy, TransactionBodyType},
        private::{MaybePrivate},
        util::{ser, test},
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
    fn trans_verify_hash_and_signatures() {
        let now = Timestamp::now();
        let (_master_key1, transactions1, _admin_key1) = test::create_fake_identity(now.clone());
        let (_master_key2, mut transactions2, _admin_key2) = test::create_fake_identity(now.clone());
        transactions1.transactions()[0].verify_hash_and_signatures().unwrap();
        *transactions2.transactions_mut()[0].signatures_mut() = transactions1.transactions()[0].signatures().clone();
        assert!(matches!(transactions2.transactions()[0].verify_hash_and_signatures(), Err(Error::TransactionSignatureInvalid(_))));
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
    fn trans_is_signed_by() {
        let now = Timestamp::now();
        let (master_key, transactions, admin_key) = test::create_fake_identity(now.clone());
        let admin_key2 = AdminKeypair::new_ed25519(&master_key).unwrap();
        assert!(transactions.transactions()[0].is_signed_by(&admin_key.key().clone().into()));
        assert!(!transactions.transactions()[0].is_signed_by(&admin_key2.clone().into()));
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

    // -------------------------------------------------------------------------
    // a series of tests that make sure our serialization format doesn't change.
    // -------------------------------------------------------------------------

    macro_rules! assert_sign_keys_eq {
        ($master:expr, $key1:expr, $key2:expr) => {
            match ($key1, $key2) {
                (SignKeypair::Ed25519 { public: public1, secret: Some(secret1)}, SignKeypair::Ed25519 { public: public2, secret: Some(secret2)}) => {
                    assert_eq!(public1, public2);
                    let revealed1 = secret1.open($master).unwrap();
                    let revealed2 = secret2.open($master).unwrap();
                    assert_eq!(revealed1.expose_secret(), revealed2.expose_secret());
                }
                _ => panic!("assert_keys_eq -- invalid pattern encountered"),
            }
        }
    }

    #[test]
    fn trans_deser_create_identity_v1() {
        let master_key = SecretKey::new_xchacha20poly1305_from_slice(&[0; 32]).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519_from_seed(&master_key, &[1; 32]).unwrap()),
            "alpha",
            Some("hello there")
        );
        let admin_key2 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519_from_seed(&master_key, &[2; 32]).unwrap()),
            "name-claim",
            None
        );
        let policy1 = Policy::new(
            vec![Capability::Permissive],
            MultisigPolicy::MOfN { must_have: 1, participants: vec![admin_key1.key().clone().into()] }
        );
        let policy2 = Policy::new(
            vec![
                Capability::Transaction {
                    body_type: TransactionBodyType::MakeClaimV1,
                    context: Context::All(vec![Context::ClaimType(ContextClaimType::Name)]),
                },
            ],
            MultisigPolicy::MOfN { must_have: 1, participants: vec![admin_key2.key().clone().into()] }
        );
        let trans = TransactionBody::CreateIdentityV1 {
            admin_keys: vec![admin_key1.clone(), admin_key2.clone()],
            policies: vec![policy1, policy2],
        };
        let ser = [160, 130, 1, 226, 48, 130, 1, 222, 160, 130, 1, 60, 48, 130, 1, 56, 48, 129, 158, 160, 129, 131, 160, 129, 128, 48, 126, 160, 34, 4, 32, 77, 75, 24, 6, 47, 133, 2, 89, 141, 224, 69, 202, 123, 105, 240, 103, 245, 159, 147, 177, 110, 58, 248, 115, 58, 152, 138, 220, 35, 65, 245, 200, 161, 88, 48, 86, 160, 84, 160, 28, 160, 26, 4, 24, 52, 91, 131, 196, 94, 206, 247, 246, 234, 187, 1, 17, 143, 130, 214, 69, 34, 35, 89, 7, 194, 4, 126, 66, 161, 52, 4, 50, 159, 166, 85, 242, 21, 236, 41, 128, 9, 108, 48, 173, 252, 29, 121, 36, 216, 195, 78, 127, 7, 0, 192, 74, 102, 35, 48, 46, 196, 80, 187, 47, 9, 219, 219, 150, 62, 173, 55, 225, 136, 36, 240, 233, 204, 242, 208, 94, 109, 149, 161, 7, 12, 5, 97, 108, 112, 104, 97, 162, 13, 12, 11, 104, 101, 108, 108, 111, 32, 116, 104, 101, 114, 101, 48, 129, 148, 160, 129, 131, 160, 129, 128, 48, 126, 160, 34, 4, 32, 125, 23, 127, 30, 113, 180, 144, 173, 12, 227, 128, 249, 87, 138, 177, 43, 176, 252, 0, 169, 141, 232, 246, 165, 85, 200, 29, 72, 194, 3, 146, 73, 161, 88, 48, 86, 160, 84, 160, 28, 160, 26, 4, 24, 148, 34, 105, 99, 167, 187, 233, 96, 221, 201, 98, 140, 99, 217, 108, 67, 187, 129, 55, 59, 46, 83, 139, 194, 161, 52, 4, 50, 247, 253, 123, 253, 8, 207, 12, 152, 47, 37, 145, 147, 71, 146, 222, 206, 96, 37, 47, 161, 118, 141, 142, 255, 89, 50, 5, 165, 4, 240, 68, 30, 246, 102, 20, 85, 108, 54, 215, 212, 108, 242, 4, 204, 161, 216, 178, 62, 99, 156, 161, 12, 12, 10, 110, 97, 109, 101, 45, 99, 108, 97, 105, 109, 161, 129, 155, 48, 129, 152, 48, 65, 160, 6, 48, 4, 160, 2, 5, 0, 161, 55, 162, 53, 48, 51, 160, 3, 2, 1, 1, 161, 44, 48, 42, 160, 40, 48, 38, 161, 36, 160, 34, 4, 32, 77, 75, 24, 6, 47, 133, 2, 89, 141, 224, 69, 202, 123, 105, 240, 103, 245, 159, 147, 177, 110, 58, 248, 115, 58, 152, 138, 220, 35, 65, 245, 200, 48, 83, 160, 24, 48, 22, 161, 20, 48, 18, 160, 4, 167, 2, 5, 0, 161, 10, 160, 8, 48, 6, 168, 4, 161, 2, 5, 0, 161, 55, 162, 53, 48, 51, 160, 3, 2, 1, 1, 161, 44, 48, 42, 160, 40, 48, 38, 161, 36, 160, 34, 4, 32, 125, 23, 127, 30, 113, 180, 144, 173, 12, 227, 128, 249, 87, 138, 177, 43, 176, 252, 0, 169, 141, 232, 246, 165, 85, 200, 29, 72, 194, 3, 146, 73];
        let trans_deser: TransactionBody = ser::deserialize(&ser).unwrap();

        match (trans, trans_deser) {
            (TransactionBody::CreateIdentityV1 { admin_keys: admin_keys1, policies: policies1 }, TransactionBody::CreateIdentityV1 { admin_keys: admin_keys2, policies: policies2 }) => {
                assert_eq!(admin_keys1.len(), 2);
                assert_eq!(admin_keys2.len(), 2);
                assert_sign_keys_eq!(&master_key, admin_keys1[0].key().deref(), admin_keys2[0].key().deref());
                assert_sign_keys_eq!(&master_key, admin_keys1[1].key().deref(), admin_keys2[1].key().deref());
                assert_eq!(policies1.len(), 2);
                assert_eq!(policies1, policies2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_deser_reset_identity_v1() {
        let master_key = SecretKey::new_xchacha20poly1305_from_slice(&[0; 32]).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519_from_seed(&master_key, &[1; 32]).unwrap()),
            "alpha",
            Some("hello there")
        );
        let admin_key2 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519_from_seed(&master_key, &[2; 32]).unwrap()),
            "name-claim",
            None
        );
        let policy1 = Policy::new(
            vec![Capability::Permissive],
            MultisigPolicy::MOfN { must_have: 1, participants: vec![admin_key1.key().clone().into()] }
        );
        let policy2 = Policy::new(
            vec![
                Capability::Transaction {
                    body_type: TransactionBodyType::MakeClaimV1,
                    context: Context::All(vec![Context::ClaimType(ContextClaimType::Name)]),
                },
            ],
            MultisigPolicy::MOfN { must_have: 1, participants: vec![admin_key2.key().clone().into()] }
        );
        let trans1 = TransactionBody::ResetIdentityV1 {
            admin_keys: Some(vec![admin_key1.clone(), admin_key2.clone()]),
            policies: Some(vec![policy1, policy2]),
        };
        let trans2 = TransactionBody::ResetIdentityV1 {
            admin_keys: None,
            policies: None,
        };
        let ser1 = [161, 130, 1, 226, 48, 130, 1, 222, 160, 130, 1, 60, 48, 130, 1, 56, 48, 129, 158, 160, 129, 131, 160, 129, 128, 48, 126, 160, 34, 4, 32, 77, 75, 24, 6, 47, 133, 2, 89, 141, 224, 69, 202, 123, 105, 240, 103, 245, 159, 147, 177, 110, 58, 248, 115, 58, 152, 138, 220, 35, 65, 245, 200, 161, 88, 48, 86, 160, 84, 160, 28, 160, 26, 4, 24, 59, 157, 16, 187, 125, 102, 38, 178, 42, 221, 198, 41, 202, 74, 99, 86, 37, 223, 79, 158, 184, 100, 28, 225, 161, 52, 4, 50, 214, 69, 210, 9, 116, 25, 59, 244, 101, 180, 177, 25, 187, 124, 241, 9, 46, 180, 192, 69, 185, 202, 32, 55, 227, 168, 207, 84, 37, 252, 155, 31, 171, 92, 11, 11, 98, 117, 221, 152, 19, 107, 41, 104, 238, 26, 37, 236, 101, 74, 161, 7, 12, 5, 97, 108, 112, 104, 97, 162, 13, 12, 11, 104, 101, 108, 108, 111, 32, 116, 104, 101, 114, 101, 48, 129, 148, 160, 129, 131, 160, 129, 128, 48, 126, 160, 34, 4, 32, 125, 23, 127, 30, 113, 180, 144, 173, 12, 227, 128, 249, 87, 138, 177, 43, 176, 252, 0, 169, 141, 232, 246, 165, 85, 200, 29, 72, 194, 3, 146, 73, 161, 88, 48, 86, 160, 84, 160, 28, 160, 26, 4, 24, 20, 191, 11, 205, 229, 5, 208, 26, 137, 35, 22, 94, 241, 251, 122, 91, 202, 1, 5, 232, 69, 215, 42, 215, 161, 52, 4, 50, 232, 51, 240, 227, 248, 73, 144, 230, 132, 196, 37, 100, 141, 99, 104, 239, 130, 61, 39, 163, 131, 18, 55, 42, 247, 25, 108, 77, 201, 75, 246, 180, 152, 167, 183, 88, 15, 180, 236, 95, 31, 33, 248, 224, 254, 133, 247, 48, 213, 163, 161, 12, 12, 10, 110, 97, 109, 101, 45, 99, 108, 97, 105, 109, 161, 129, 155, 48, 129, 152, 48, 65, 160, 6, 48, 4, 160, 2, 5, 0, 161, 55, 162, 53, 48, 51, 160, 3, 2, 1, 1, 161, 44, 48, 42, 160, 40, 48, 38, 161, 36, 160, 34, 4, 32, 77, 75, 24, 6, 47, 133, 2, 89, 141, 224, 69, 202, 123, 105, 240, 103, 245, 159, 147, 177, 110, 58, 248, 115, 58, 152, 138, 220, 35, 65, 245, 200, 48, 83, 160, 24, 48, 22, 161, 20, 48, 18, 160, 4, 167, 2, 5, 0, 161, 10, 160, 8, 48, 6, 168, 4, 161, 2, 5, 0, 161, 55, 162, 53, 48, 51, 160, 3, 2, 1, 1, 161, 44, 48, 42, 160, 40, 48, 38, 161, 36, 160, 34, 4, 32, 125, 23, 127, 30, 113, 180, 144, 173, 12, 227, 128, 249, 87, 138, 177, 43, 176, 252, 0, 169, 141, 232, 246, 165, 85, 200, 29, 72, 194, 3, 146, 73];
        let ser2 = [161, 2, 48, 0];
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();
        let trans_deser2: TransactionBody = ser::deserialize(&ser2).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::ResetIdentityV1 { admin_keys: Some(admin_keys1), policies: policies1 }, TransactionBody::ResetIdentityV1 { admin_keys: Some(admin_keys2), policies: policies2 }) => {
                assert_eq!(admin_keys1.len(), 2);
                assert_eq!(admin_keys2.len(), 2);
                assert_sign_keys_eq!(&master_key, admin_keys1[0].key().deref(), admin_keys2[0].key().deref());
                assert_sign_keys_eq!(&master_key, admin_keys1[1].key().deref(), admin_keys2[1].key().deref());
                assert_eq!(policies1, policies2);
            }
            _ => panic!("Unmatched serialization"),
        }
        match (trans2, trans_deser2) {
            (TransactionBody::ResetIdentityV1 { admin_keys: admin_keys1, policies: policies1 }, TransactionBody::ResetIdentityV1 { admin_keys: admin_keys2, policies: policies2 }) => {
                assert!(admin_keys1.is_none());
                assert!(admin_keys2.is_none());
                assert!(policies1.is_none());
                assert!(policies2.is_none());
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_deser_add_admin_key_v1() {
        let master_key = SecretKey::new_xchacha20poly1305_from_slice(&[0; 32]).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519_from_seed(&master_key, &[3; 32]).unwrap()),
            "alpha",
            Some("been watching you for quite a while now")
        );
        let trans1 = TransactionBody::AddAdminKeyV1 {
            admin_key: admin_key1,
        };
        let ser1 = [162, 129, 195, 48, 129, 192, 160, 129, 189, 48, 129, 186, 160, 129, 131, 160, 129, 128, 48, 126, 160, 34, 4, 32, 91, 4, 106, 214, 52, 192, 140, 163, 195, 39, 181, 159, 112, 135, 253, 242, 62, 47, 86, 225, 164, 231, 164, 207, 169, 14, 185, 87, 230, 177, 29, 250, 161, 88, 48, 86, 160, 84, 160, 28, 160, 26, 4, 24, 134, 243, 201, 153, 106, 228, 220, 47, 211, 214, 235, 2, 236, 85, 39, 179, 84, 157, 211, 69, 187, 144, 64, 117, 161, 52, 4, 50, 237, 14, 55, 198, 27, 15, 7, 33, 92, 210, 204, 186, 200, 3, 106, 10, 143, 165, 116, 143, 95, 76, 37, 6, 78, 64, 233, 253, 171, 34, 161, 48, 35, 81, 240, 193, 17, 110, 222, 38, 236, 251, 28, 191, 137, 0, 110, 216, 155, 220, 161, 7, 12, 5, 97, 108, 112, 104, 97, 162, 41, 12, 39, 98, 101, 101, 110, 32, 119, 97, 116, 99, 104, 105, 110, 103, 32, 121, 111, 117, 32, 102, 111, 114, 32, 113, 117, 105, 116, 101, 32, 97, 32, 119, 104, 105, 108, 101, 32, 110, 111, 119];
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::AddAdminKeyV1 { admin_key: admin_key1 }, TransactionBody::AddAdminKeyV1 { admin_key: admin_key2 }) => {
                assert_sign_keys_eq!(&master_key, admin_key1.key().deref(), admin_key2.key().deref());
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_deser_edit_admin_key_v1() {
        let master_key = SecretKey::new_xchacha20poly1305_from_slice(&[22; 32]).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519_from_seed(&master_key, &[8; 32]).unwrap()),
            "admin/edit",
            Some("i like your hat")
        );
        let trans1 = TransactionBody::EditAdminKeyV1 {
            id: admin_key1.key_id(),
            name: Some("admin/all".to_string()),
            description: Some(None),
        };
        let trans2 = TransactionBody::EditAdminKeyV1 {
            id: admin_key1.key_id(),
            name: Some("admin/all".to_string()),
            description: Some(Some("fun times".to_string())),
        };
        let ser1 = [163, 57, 48, 55, 160, 38, 160, 36, 160, 34, 4, 32, 196, 139, 104, 122, 29, 216, 38, 81, 1, 179, 61, 246, 174, 11, 104, 37, 35, 78, 63, 40, 223, 158, 203, 56, 251, 40, 108, 247, 109, 174, 145, 157, 161, 11, 12, 9, 97, 100, 109, 105, 110, 47, 97, 108, 108, 162, 0];
        let ser2 = [163, 68, 48, 66, 160, 38, 160, 36, 160, 34, 4, 32, 196, 139, 104, 122, 29, 216, 38, 81, 1, 179, 61, 246, 174, 11, 104, 37, 35, 78, 63, 40, 223, 158, 203, 56, 251, 40, 108, 247, 109, 174, 145, 157, 161, 11, 12, 9, 97, 100, 109, 105, 110, 47, 97, 108, 108, 162, 11, 12, 9, 102, 117, 110, 32, 116, 105, 109, 101, 115];
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();
        let trans_deser2: TransactionBody = ser::deserialize(&ser2).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::EditAdminKeyV1 { id: id1, name: name1, description: desc1 }, TransactionBody::EditAdminKeyV1 { id: id2, name: name2, description: desc2 }) => {
                assert_eq!(id1, id2);
                assert_eq!(name1, name2);
                assert_eq!(desc1, desc2);
            }
            _ => panic!("Unmatched serialization"),
        }
        match (trans2, trans_deser2) {
            (TransactionBody::EditAdminKeyV1 { id: id1, name: name1, description: desc1 }, TransactionBody::EditAdminKeyV1 { id: id2, name: name2, description: desc2 }) => {
                assert_eq!(id1, id2);
                assert_eq!(name1, name2);
                assert_eq!(desc1, desc2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_deser_revoke_admin_key_v1() {
        let master_key = SecretKey::new_xchacha20poly1305_from_slice(&[22; 32]).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519_from_seed(&master_key, &[8; 32]).unwrap()),
            "admin/edit",
            Some("i like your hat")
        );
        let trans1 = TransactionBody::RevokeAdminKeyV1 {
            id: admin_key1.key_id(),
            reason: RevocationReason::Compromised,
            new_name: Some("admin/no-more".to_string()),
        };
        let ser1 = [164, 65, 48, 63, 160, 38, 160, 36, 160, 34, 4, 32, 196, 139, 104, 122, 29, 216, 38, 81, 1, 179, 61, 246, 174, 11, 104, 37, 35, 78, 63, 40, 223, 158, 203, 56, 251, 40, 108, 247, 109, 174, 145, 157, 161, 4, 162, 2, 5, 0, 162, 15, 12, 13, 97, 100, 109, 105, 110, 47, 110, 111, 45, 109, 111, 114, 101];
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::RevokeAdminKeyV1 { id: id1, reason: reason1, new_name: name1 }, TransactionBody::RevokeAdminKeyV1 { id: id2, reason: reason2, new_name: name2 }) => {
                assert_eq!(id1, id2);
                assert_eq!(reason1, reason2);
                assert_eq!(name1, name2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_deser_add_policy_v1() {
        let master_key = SecretKey::new_xchacha20poly1305_from_slice(&[22; 32]).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519_from_seed(&master_key, &[8; 32]).unwrap()),
            "admin/edit",
            Some("i like your hat")
        );
        let policy1 = Policy::new(
            vec![
                Capability::Transaction {
                    body_type: TransactionBodyType::MakeClaimV1,
                    context: Context::All(vec![Context::ClaimType(ContextClaimType::Name)]),
                },
            ],
            MultisigPolicy::MOfN { must_have: 1, participants: vec![admin_key1.key().clone().into()] }
        );
        let trans1 = TransactionBody::AddPolicyV1 {
            policy: policy1,
        };
        let ser1 = [165, 89, 48, 87, 160, 85, 48, 83, 160, 24, 48, 22, 161, 20, 48, 18, 160, 4, 167, 2, 5, 0, 161, 10, 160, 8, 48, 6, 168, 4, 161, 2, 5, 0, 161, 55, 162, 53, 48, 51, 160, 3, 2, 1, 1, 161, 44, 48, 42, 160, 40, 48, 38, 161, 36, 160, 34, 4, 32, 196, 139, 104, 122, 29, 216, 38, 81, 1, 179, 61, 246, 174, 11, 104, 37, 35, 78, 63, 40, 223, 158, 203, 56, 251, 40, 108, 247, 109, 174, 145, 157];
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::AddPolicyV1 { policy: policy1 }, TransactionBody::AddPolicyV1 { policy: policy2 }) => {
                assert_eq!(policy1, policy2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_deser_delete_policy_v1() {
        let policy_id1 = PolicyID::from(TransactionID::from(Hash::new_blake2b_256(&[55, 66, 42, 17, 0, 9]).unwrap()));
        let trans1 = TransactionBody::DeletePolicyV1 {
            id: policy_id1,
        };
        let ser1 = [166, 42, 48, 40, 160, 38, 48, 36, 161, 34, 4, 32, 234, 7, 225, 147, 113, 146, 63, 122, 46, 234, 139, 233, 225, 119, 117, 152, 248, 84, 207, 241, 51, 163, 11, 85, 51, 68, 7, 130, 40, 38, 4, 228];
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::DeletePolicyV1 { id: id1 }, TransactionBody::DeletePolicyV1 { id: id2 }) => {
                assert_eq!(id1, id2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_deser_make_claim_v1() {
        let master_key = SecretKey::new_xchacha20poly1305_from_slice(&[22; 32]).unwrap();
        let claim1 = ClaimSpec::Identity(MaybePrivate::new_public(IdentityID::from(TransactionID::from(Hash::new_blake2b_256(&[1, 2, 3, 4, 5]).unwrap()))));
        let claim2 = ClaimSpec::Extension {
            key: BinaryVec::from(vec![2, 4, 6, 8]),
            value: MaybePrivate::new_private(&master_key, BinaryVec::from(vec![9, 9, 9])).unwrap(),
        };
        let trans1 = TransactionBody::MakeClaimV1 {
            spec: claim1,
            name: Some("my-old-id".to_string()),
        };
        let trans2 = TransactionBody::MakeClaimV1 {
            spec: claim2,
            name: None,
        };
        let ser1 = [167, 59, 48, 57, 160, 42, 160, 40, 160, 38, 48, 36, 161, 34, 4, 32, 2, 184, 57, 74, 2, 9, 205, 216, 210, 77, 230, 58, 45, 139, 80, 30, 92, 141, 137, 51, 230, 188, 18, 199, 110, 191, 194, 202, 152, 32, 121, 202, 161, 11, 12, 9, 109, 121, 45, 111, 108, 100, 45, 105, 100];
        let ser2 = [167, 129, 237, 48, 129, 234, 160, 129, 231, 171, 129, 228, 48, 129, 225, 160, 6, 4, 4, 2, 4, 6, 8, 161, 129, 214, 161, 129, 211, 48, 129, 208, 160, 68, 160, 66, 4, 64, 119, 249, 37, 233, 249, 41, 126, 192, 130, 174, 249, 214, 25, 238, 96, 41, 134, 177, 61, 93, 231, 220, 146, 159, 54, 3, 254, 67, 22, 189, 177, 177, 170, 118, 103, 129, 79, 157, 40, 241, 56, 172, 68, 104, 137, 194, 194, 58, 81, 150, 160, 43, 100, 122, 73, 124, 199, 138, 203, 141, 205, 240, 150, 171, 161, 129, 135, 48, 129, 132, 160, 129, 129, 160, 28, 160, 26, 4, 24, 34, 41, 154, 149, 54, 35, 146, 15, 173, 244, 166, 49, 240, 239, 127, 92, 42, 149, 212, 205, 94, 166, 231, 195, 161, 97, 4, 95, 248, 230, 162, 110, 59, 33, 11, 236, 61, 105, 238, 140, 31, 173, 90, 138, 143, 186, 156, 215, 157, 7, 126, 192, 81, 170, 134, 154, 198, 255, 226, 238, 165, 164, 138, 143, 142, 234, 235, 13, 68, 28, 157, 203, 33, 141, 209, 108, 240, 91, 170, 93, 218, 115, 58, 203, 152, 190, 60, 144, 9, 40, 228, 92, 241, 53, 195, 36, 171, 131, 57, 62, 89, 100, 64, 54, 216, 10, 165, 27, 144, 221, 181, 29, 44, 52, 190, 155, 214, 183, 250, 81, 50, 209, 92];
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();
        let trans_deser2: TransactionBody = ser::deserialize(&ser2).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::MakeClaimV1 { spec: spec1, name: name1 }, TransactionBody::MakeClaimV1 { spec: spec2, name: name2 }) => {
                match (spec1, spec2) {
                    (ClaimSpec::Identity(MaybePrivate::Public(pub1)), ClaimSpec::Identity(MaybePrivate::Public(pub2))) => {
                        assert_eq!(pub1, pub2);
                    }
                    _ => panic!("Unmatched spec"),
                }
                assert_eq!(name1, name2);
            }
            _ => panic!("Unmatched serialization"),
        }
        match (trans2, trans_deser2) {
            (TransactionBody::MakeClaimV1 { spec: spec1, name: name1 }, TransactionBody::MakeClaimV1 { spec: spec2, name: name2 }) => {
                match (spec1, spec2) {
                    (ClaimSpec::Extension { key: key1, value: priv1 }, ClaimSpec::Extension { key: key2, value: priv2 }) => {
                        assert_eq!(key1, key2);
                        let unsealed1 = priv1.open(&master_key).unwrap();
                        let unsealed2 = priv2.open(&master_key).unwrap();
                        assert_eq!(unsealed1, unsealed2);
                    }
                    _ => panic!("Unmatched spec"),
                }
                assert_eq!(name1, name2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[ignore] #[test] fn trans_deser_edit_claim_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_delete_claim_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_make_stamp_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_revoke_stamp_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_accept_stamp_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_delete_stamp_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_add_subkey_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_edit_subkey_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_revoke_subkey_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_delete_subkey_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_publish_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_sign_v1() { todo!(); }
    #[ignore] #[test] fn trans_deser_ext_v1() { todo!(); }
}

