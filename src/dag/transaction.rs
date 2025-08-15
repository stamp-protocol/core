//! A `Transaction` models a single change against an identity, and is one node
//! inside of the identity DAG.
//!
//! Transactions have a [TransactionBody], an ID ([Hash][crate::crypto::base::Hash]
//! of the transaction's body, timestamp, and previously-referenced transactions),
//! and a collection of one or more signatures on the transaction's ID that validate
//! that transaction.

use crate::{
    crypto::base::{Hash, HashAlgo, KeyID, SecretKey},
    dag::{DagNode, Transactions},
    error::{Error, Result},
    identity::{
        claim::{ClaimID, ClaimSpec},
        identity::{Identity, IdentityID},
        keychain::{AdminKey, AdminKeyID, AdminKeypair, AdminKeypairPublic, ExtendKeypair, Key, RevocationReason},
        stamp::{RevocationReason as StampRevocationReason, StampEntry, StampID},
    },
    policy::{Context, MultisigPolicySignature, Policy, PolicyContainer, PolicyID},
    util::{
        ser::{self, BinaryVec, DeText, HashMapAsn1, SerText, SerdeBinary},
        Public, Timestamp,
    },
};
use getset;
use rand::{CryptoRng, RngCore};
use rasn::{AsnType, Decode, Decoder, Encode, Encoder};
use serde_derive::{Deserialize, Serialize};
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
    /// Revoke an identity. Makes any future transactions not apply, and makes anything signed by
    /// the identity after the revocation invalid.
    ///
    /// The only valid action after revocation is publishing.
    #[rasn(tag(explicit(2)))]
    RevokeIdentityV1,
    /// Add a new [admin key][AdminKey] to the [Keychain][crate::identity::keychain::Keychain].
    #[rasn(tag(explicit(3)))]
    AddAdminKeyV1 {
        #[rasn(tag(explicit(0)))]
        admin_key: AdminKey,
    },
    /// Edit an admin key
    #[rasn(tag(explicit(4)))]
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
    #[rasn(tag(explicit(5)))]
    RevokeAdminKeyV1 {
        #[rasn(tag(explicit(0)))]
        id: AdminKeyID,
        #[rasn(tag(explicit(1)))]
        reason: RevocationReason,
        #[rasn(tag(explicit(2)))]
        new_name: Option<String>,
    },
    /// Add a new [Policy] to the identity.
    #[rasn(tag(explicit(6)))]
    AddPolicyV1 {
        #[rasn(tag(explicit(0)))]
        policy: Policy,
    },
    /// Delete (by name) a capability policy from the identity.
    #[rasn(tag(explicit(7)))]
    DeletePolicyV1 {
        #[rasn(tag(explicit(0)))]
        id: PolicyID,
    },
    /// Make a new claim on this identity. The [ID][TransactionID] of this
    /// transaction will be the claim's ID.
    #[rasn(tag(explicit(8)))]
    MakeClaimV1 {
        #[rasn(tag(explicit(0)))]
        spec: ClaimSpec,
        #[rasn(tag(explicit(1)))]
        name: Option<String>,
    },
    /// Edit a claim's name
    #[rasn(tag(explicit(9)))]
    EditClaimV1 {
        #[rasn(tag(explicit(0)))]
        claim_id: ClaimID,
        #[rasn(tag(explicit(1)))]
        name: Option<String>,
    },
    /// Delete/remove a claim by ID.
    #[rasn(tag(explicit(10)))]
    DeleteClaimV1 {
        #[rasn(tag(explicit(0)))]
        claim_id: ClaimID,
    },
    /// Make a stamp that is saved and advertised with this identity.
    #[rasn(tag(explicit(11)))]
    MakeStampV1 {
        #[rasn(tag(explicit(0)))]
        stamp: StampEntry,
    },
    /// Revoke a stamp we previously created and store this revocation with the
    /// identity.
    #[rasn(tag(explicit(12)))]
    RevokeStampV1 {
        #[rasn(tag(explicit(0)))]
        stamp_id: StampID,
        #[rasn(tag(explicit(1)))]
        reason: StampRevocationReason,
    },
    /// Accept a stamp on one of our claims into our identity. This allows those
    /// who have our identity to see the trust others have put into us.
    #[rasn(tag(explicit(13)))]
    AcceptStampV1 {
        #[rasn(tag(explicit(0)))]
        stamp_transaction: Box<Transaction>,
    },
    /// Delete a stamp on one of our claims.
    #[rasn(tag(explicit(14)))]
    DeleteStampV1 {
        #[rasn(tag(explicit(0)))]
        stamp_id: StampID,
    },
    /// Add a new subkey to our keychain.
    #[rasn(tag(explicit(15)))]
    AddSubkeyV1 {
        #[rasn(tag(explicit(0)))]
        key: Key,
        #[rasn(tag(explicit(1)))]
        name: String,
        #[rasn(tag(explicit(2)))]
        desc: Option<String>,
    },
    /// Edit the name/description of a subkey by its unique name.
    #[rasn(tag(explicit(16)))]
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
    #[rasn(tag(explicit(17)))]
    RevokeSubkeyV1 {
        #[rasn(tag(explicit(0)))]
        id: KeyID,
        #[rasn(tag(explicit(1)))]
        reason: RevocationReason,
        #[rasn(tag(explicit(2)))]
        new_name: Option<String>,
    },
    /// Delete a subkey entirely from the identity.
    #[rasn(tag(explicit(18)))]
    DeleteSubkeyV1 {
        #[rasn(tag(explicit(0)))]
        id: KeyID,
    },
    /// Publish this identity. This transaction cannot be saved with the identity, but
    /// rather should be published to a public medium (like StampNet!!!!1)
    #[rasn(tag(explicit(19)))]
    PublishV1 {
        #[rasn(tag(explicit(0)))]
        transactions: Box<Transactions>,
    },
    /// Sign a message. The usual Stamp policy process applies here, so an official
    /// identity signing transaction must match an existing policy to be valid. This
    /// allows creating group signatures that are policy-validated.
    ///
    /// Note that we don't actually sign the body, but the body's hash. This makes the
    /// transaction fairly lightweight while still being reasonably secure.
    ///
    /// `Sign` transactions cannot be applied to the identity!
    #[rasn(tag(explicit(20)))]
    SignV1 {
        #[rasn(tag(explicit(0)))]
        creator: IdentityID,
        #[rasn(tag(explicit(1)))]
        body_hash: Hash,
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
    #[rasn(tag(explicit(21)))]
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
    fn reencrypt<R: RngCore + CryptoRng>(self, rng: &mut R, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let new_self = match self {
            Self::CreateIdentityV1 { admin_keys, policies } => {
                let admin_reenc = admin_keys
                    .into_iter()
                    .map(|x| x.reencrypt(rng, old_master_key, new_master_key))
                    .collect::<Result<Vec<_>>>()?;
                Self::CreateIdentityV1 {
                    admin_keys: admin_reenc,
                    policies,
                }
            }
            Self::ResetIdentityV1 { admin_keys, policies } => {
                let admin_keys_reenc = admin_keys
                    .map(|keyvec| {
                        keyvec
                            .into_iter()
                            .map(|k| k.reencrypt(rng, old_master_key, new_master_key))
                            .collect::<Result<Vec<_>>>()
                    })
                    .transpose()?;
                Self::ResetIdentityV1 {
                    admin_keys: admin_keys_reenc,
                    policies,
                }
            }
            Self::RevokeIdentityV1 => Self::RevokeIdentityV1,
            Self::AddAdminKeyV1 { admin_key } => Self::AddAdminKeyV1 {
                admin_key: admin_key.reencrypt(rng, old_master_key, new_master_key)?,
            },
            Self::EditAdminKeyV1 { id, name, description } => Self::EditAdminKeyV1 { id, name, description },
            Self::RevokeAdminKeyV1 { id, reason, new_name } => Self::RevokeAdminKeyV1 { id, reason, new_name },
            Self::AddPolicyV1 { policy } => Self::AddPolicyV1 { policy },
            Self::DeletePolicyV1 { id } => Self::DeletePolicyV1 { id },
            Self::MakeClaimV1 { spec, name } => Self::MakeClaimV1 {
                spec: spec.reencrypt(rng, old_master_key, new_master_key)?,
                name,
            },
            Self::EditClaimV1 { claim_id, name } => Self::EditClaimV1 { claim_id, name },
            Self::DeleteClaimV1 { claim_id } => Self::DeleteClaimV1 { claim_id },
            Self::MakeStampV1 { stamp } => Self::MakeStampV1 { stamp },
            Self::RevokeStampV1 { stamp_id, reason } => Self::RevokeStampV1 { stamp_id, reason },
            Self::AcceptStampV1 { stamp_transaction } => Self::AcceptStampV1 { stamp_transaction },
            Self::DeleteStampV1 { stamp_id } => Self::DeleteStampV1 { stamp_id },
            Self::AddSubkeyV1 { key, name, desc } => {
                let new_subkey = key.reencrypt(rng, old_master_key, new_master_key)?;
                Self::AddSubkeyV1 {
                    key: new_subkey,
                    name,
                    desc,
                }
            }
            Self::EditSubkeyV1 { id, new_name, new_desc } => Self::EditSubkeyV1 { id, new_name, new_desc },
            Self::RevokeSubkeyV1 { id, reason, new_name } => Self::RevokeSubkeyV1 { id, reason, new_name },
            Self::DeleteSubkeyV1 { id } => Self::DeleteSubkeyV1 { id },
            Self::PublishV1 { transactions } => Self::PublishV1 {
                transactions: Box::new(transactions.reencrypt(rng, old_master_key, new_master_key)?),
            },
            Self::SignV1 { creator, body_hash } => Self::SignV1 { creator, body_hash },
            Self::ExtV1 {
                creator,
                ty,
                previous_transactions,
                context,
                payload,
            } => Self::ExtV1 {
                creator,
                ty,
                previous_transactions,
                context,
                payload,
            },
        };
        Ok(new_self)
    }
}

impl Public for TransactionBody {
    fn strip_private(&self) -> Self {
        match self.clone() {
            Self::CreateIdentityV1 { admin_keys, policies } => {
                let admin_stripped = admin_keys.into_iter().map(|k| k.strip_private()).collect::<Vec<_>>();
                Self::CreateIdentityV1 {
                    admin_keys: admin_stripped,
                    policies,
                }
            }
            Self::ResetIdentityV1 { admin_keys, policies } => {
                let stripped_admin = admin_keys.map(|keys| keys.into_iter().map(|k| k.strip_private()).collect::<Vec<_>>());
                Self::ResetIdentityV1 {
                    admin_keys: stripped_admin,
                    policies,
                }
            }
            Self::RevokeIdentityV1 => Self::RevokeIdentityV1,
            Self::AddAdminKeyV1 { admin_key } => Self::AddAdminKeyV1 {
                admin_key: admin_key.strip_private(),
            },
            Self::EditAdminKeyV1 { id, name, description } => Self::EditAdminKeyV1 { id, name, description },
            Self::RevokeAdminKeyV1 { id, reason, new_name } => Self::RevokeAdminKeyV1 { id, reason, new_name },
            Self::AddPolicyV1 { policy } => Self::AddPolicyV1 { policy },
            Self::DeletePolicyV1 { id } => Self::DeletePolicyV1 { id },
            Self::MakeClaimV1 { spec, name } => Self::MakeClaimV1 {
                spec: spec.strip_private(),
                name,
            },
            Self::EditClaimV1 { claim_id, name } => Self::EditClaimV1 { claim_id, name },
            Self::DeleteClaimV1 { claim_id } => Self::DeleteClaimV1 { claim_id },
            Self::MakeStampV1 { stamp } => Self::MakeStampV1 { stamp },
            Self::RevokeStampV1 { stamp_id, reason } => Self::RevokeStampV1 { stamp_id, reason },
            Self::AcceptStampV1 { stamp_transaction } => Self::AcceptStampV1 {
                stamp_transaction: Box::new(stamp_transaction.strip_private()),
            },
            Self::DeleteStampV1 { stamp_id } => Self::DeleteStampV1 { stamp_id },
            Self::AddSubkeyV1 { key, name, desc } => Self::AddSubkeyV1 {
                key: key.strip_private(),
                name,
                desc,
            },
            Self::EditSubkeyV1 { id, new_name, new_desc } => Self::EditSubkeyV1 { id, new_name, new_desc },
            Self::RevokeSubkeyV1 { id, reason, new_name } => Self::RevokeSubkeyV1 { id, reason, new_name },
            Self::DeleteSubkeyV1 { id } => Self::DeleteSubkeyV1 { id },
            Self::PublishV1 { transactions } => Self::PublishV1 {
                transactions: Box::new(transactions.strip_private()),
            },
            Self::SignV1 { creator, body_hash } => Self::SignV1 { creator, body_hash },
            Self::ExtV1 {
                creator,
                ty,
                previous_transactions,
                context,
                payload,
            } => Self::ExtV1 {
                creator,
                ty,
                previous_transactions,
                context,
                payload,
            },
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::CreateIdentityV1 { admin_keys, .. } => admin_keys.iter().any(|k| k.has_private()),
            Self::ResetIdentityV1 { admin_keys, .. } => admin_keys
                .as_ref()
                .map(|keys| keys.iter().any(|x| x.key().has_private()))
                .unwrap_or(false),
            Self::RevokeIdentityV1 => false,
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

/// The TransactionID is a [Hash][enum@crate::crypto::base::Hash] of the transaction body
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

impl SerdeBinary for TransactionID {}

#[cfg(test)]
impl TransactionID {
    pub(crate) fn random() -> Self {
        Self(Hash::random_blake3())
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
            HashAlgo::Blake3 => Hash::new_blake3(&serialized)?,
        };
        let id = TransactionID::from(hash);
        Ok(Self {
            id,
            entry,
            signatures: Vec::new(),
        })
    }

    /// A very unsafe function that is sometimes required in situations where a DAG needs to be
    /// hand-created (forged) and we don't have all the information to do it ze proper way.
    ///
    /// For instance, if removing nodes from a DAG and then later re-creating them with fake
    /// entries (that would never verify BTW so it's not some workaround to break integrity) we
    /// might want to recreate the removed DAG nodes given just an ID and timestamp.
    pub fn create_raw_with_id<T: Into<Timestamp>>(
        id: TransactionID,
        created: T,
        previous_transactions: Vec<TransactionID>,
        body: TransactionBody,
    ) -> Self {
        let entry = TransactionEntry::new(created, previous_transactions, body);
        Self {
            id,
            entry,
            signatures: Vec::new(),
        }
    }

    /// Create a new transaction with hand-supplied values for the create time, previous
    /// transactions, and body.
    ///
    /// You almost never want this! Use the dag::Transactions::<create_identity|add_subkey|...>
    /// functions instead. This function's main utility is raw DAG manipulation.
    pub fn create_raw<T: Into<Timestamp>>(
        hash_with: &HashAlgo,
        created: T,
        previous_transactions: Vec<TransactionID>,
        body: TransactionBody,
    ) -> Result<Self> {
        let entry = TransactionEntry::new(created, previous_transactions, body);
        Transaction::new(entry, hash_with)
    }

    /// Allows modification of the `previous_transactions` field of an ExtV1 body. This is useful
    /// in situations where an application needs to do some DAG manipulation but can't do it
    /// directly because the official functions don't allow modifications of the `Transaction` or
    /// inner fields.
    ///
    /// We can do the same by cloning a bunch of garbage and using [`Transaction::create_raw`] but this
    /// allows the same without copy.
    pub fn try_mod_ext_previous_transaction(&mut self, new_ext_previous_transactions: Vec<TransactionID>) -> Result<()> {
        match self.entry_mut().body_mut() {
            TransactionBody::ExtV1 {
                ref mut previous_transactions,
                ..
            } => {
                *previous_transactions = new_ext_previous_transactions;
                Ok(())
            }
            _ => Err(Error::TransactionMismatch),
        }
    }

    /// Sign this transaction. This consumes the transaction, adds the signature
    /// to the `signatures` list, then returns the new transaction.
    pub fn sign<K>(mut self, master_key: &SecretKey, admin_key: &K) -> Result<Self>
    where
        K: Deref<Target = AdminKeypair>,
    {
        let admin_key = admin_key.deref();
        let admin_key_pub: AdminKeypairPublic = admin_key.clone().into();
        let sig_exists = self.signatures().iter().find(|sig| match sig {
            MultisigPolicySignature::Key { key, .. } => key == &admin_key_pub,
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
            Hash::Blake3(..) => Hash::new_blake3(&serialized[..])?,
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
            };
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
                        let identity = Identity::create(
                            IdentityID::from(self.id().clone()),
                            admin_keys.clone(),
                            policies_con,
                            self.entry().created().clone(),
                        );
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
        self.signatures()
            .iter()
            .find(|sig| match sig {
                MultisigPolicySignature::Key { key, .. } => key == admin_key,
            })
            .is_some()
    }

    /// Reencrypt this transaction.
    pub fn reencrypt<R: RngCore + CryptoRng>(
        mut self,
        rng: &mut R,
        old_master_key: &SecretKey,
        new_master_key: &SecretKey,
    ) -> Result<Self> {
        let new_body = self.entry().body().clone().reencrypt(rng, old_master_key, new_master_key)?;
        self.entry_mut().set_body(new_body);
        Ok(self)
    }

    /// Ensures that this transaction is a publish transaction, verifies it *fully* (as in, runs
    /// [`Transaction::verify`], and returns the contained [`crate::dag::Transactions`] and
    /// [`crate::identity::Identity`].
    pub fn validate_publish_transaction(self) -> Result<(Transactions, Identity)> {
        // first, do a borrowed verification of the full published identity. this lets us verify
        // without cloning.
        let identity = match self.entry().body() {
            TransactionBody::PublishV1 { transactions } => {
                let identity = transactions.build_identity()?;
                self.verify(Some(&identity))?;
                identity
            }
            _ => Err(Error::TransactionMismatch)?,
        };

        // now we can fully deconstuct the transaction, get the inner identity, and return it
        match self {
            Transaction {
                entry:
                    TransactionEntry {
                        body: TransactionBody::PublishV1 { transactions },
                        ..
                    },
                ..
            } => Ok((*transactions, identity)),
            _ => Err(Error::TransactionMismatch),
        }
    }
}

impl std::cmp::PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id() && self.signatures() == other.signatures()
    }
}

impl std::cmp::Eq for Transaction {}

impl std::cmp::Ord for Transaction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let cmp = self.entry().created().cmp(other.entry().created());
        let ord = if cmp == std::cmp::Ordering::Equal {
            self.id().cmp(other.id())
        } else {
            cmp
        };
        ord
    }
}

impl std::cmp::PartialOrd for Transaction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> From<&'a Transaction> for DagNode<'a, TransactionID, Transaction> {
    fn from(t: &'a Transaction) -> Self {
        DagNode::new(t.id(), t, t.entry().previous_transactions().iter().collect::<Vec<_>>(), t.entry().created())
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
impl DeText for Transaction {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{base::SignKeypair, private::MaybePrivate},
        identity::{keychain::RevocationReason, stamp::Confidence},
        policy::{Capability, Context, ContextClaimType, MultisigPolicy, Policy, TransactionBodyType},
        util::{ser, test},
    };
    use std::str::FromStr;

    #[test]
    fn trans_create_raw() {
        let body = TransactionBody::ExtV1 {
            creator: IdentityID::from(TransactionID::from(Hash::new_blake3(b"owwww my head").unwrap())),
            ty: Some(Vec::from(b"/stamp/test/raw").into()),
            previous_transactions: vec![TransactionID::from(Hash::new_blake3(b"i like your hat").unwrap())],
            context: Some([("create", "raw")].into()),
            payload: Vec::from(b"who's this...Steve?").into(),
        };
        let trans1 = Transaction::create_raw(
            &HashAlgo::Blake3,
            crate::util::Timestamp::from_str("2028-09-30T06:34:22Z").unwrap(),
            vec![TransactionID::from(Hash::new_blake3(b"toot").unwrap())],
            body.clone(),
        )
        .unwrap();
        let trans2 = Transaction::create_raw(
            &HashAlgo::Blake3,
            crate::util::Timestamp::from_str("3028-09-30T06:34:22Z").unwrap(),
            vec![TransactionID::from(Hash::new_blake3(b"toot").unwrap())],
            body.clone(),
        )
        .unwrap();
        let trans3 = Transaction::create_raw(
            &HashAlgo::Blake3,
            crate::util::Timestamp::from_str("3028-09-30T06:34:22Z").unwrap(),
            vec![TransactionID::from(Hash::new_blake3(b"zing").unwrap())],
            body.clone(),
        )
        .unwrap();
        assert_eq!(format!("{}", trans1.id()), "VvM-YerBlAZZBSHQQDTVMRDh87dZw5sbr-3GlzySeiMA");
        assert_eq!(format!("{}", trans2.id()), "nibq1lpMmDE57hdvL3__K-IjHTmURCelR3YVXGVNSkQA");
        assert_eq!(format!("{}", trans3.id()), "pXmIbpDkH9c_jnKtbsGTMmyfq4p5PldYRYAhP8kl60EA");
    }

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
                        admin_keys: admin_keys
                            .clone()
                            .map(|x| x.into_iter().map(|y| y.strip_private()).collect::<Vec<_>>()),
                        policies: policies.clone(),
                    };
                    assert!(!body2.has_private());
                }
                TransactionBody::RevokeIdentityV1 => {
                    assert!(!body.has_private());
                }
                TransactionBody::AddAdminKeyV1 { admin_key } => {
                    assert!(body.has_private());
                    let body2 = TransactionBody::AddAdminKeyV1 {
                        admin_key: admin_key.strip_private(),
                    };
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
                    let body2 = TransactionBody::MakeClaimV1 {
                        spec: spec.strip_private(),
                        name: name.clone(),
                    };
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
                TransactionBody::PublishV1 { .. } => {}
                // blehhhh...
                TransactionBody::SignV1 { .. } => {}
                // blehhhh...
                TransactionBody::ExtV1 { .. } => {}
            }
        }

        let mut rng = crate::util::test::rng();
        let (master_key, transactions, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());

        test_privates(&TransactionBody::CreateIdentityV1 {
            admin_keys: vec![admin_key.clone()],
            policies: Vec::new(),
        });
        test_privates(&TransactionBody::ResetIdentityV1 {
            admin_keys: Some(vec![admin_key.clone()]),
            policies: None,
        });
        test_privates(&TransactionBody::AddAdminKeyV1 {
            admin_key: admin_key.clone(),
        });
        test_privates(&TransactionBody::EditAdminKeyV1 {
            id: admin_key.key_id(),
            name: Some("poopy".into()),
            description: None,
        });
        test_privates(&TransactionBody::RevokeAdminKeyV1 {
            id: admin_key.key_id(),
            reason: RevocationReason::Compromised,
            new_name: Some("old key".into()),
        });

        let policy = Policy::new(
            vec![],
            MultisigPolicy::MOfN {
                must_have: 0,
                participants: vec![],
            },
        );
        test_privates(&TransactionBody::AddPolicyV1 { policy });
        test_privates(&TransactionBody::DeletePolicyV1 { id: PolicyID::random() });
        test_privates(&TransactionBody::MakeClaimV1 {
            spec: ClaimSpec::Name(MaybePrivate::new_public(String::from("Negative Nancy"))),
            name: None,
        });
        test_privates(&TransactionBody::MakeClaimV1 {
            spec: ClaimSpec::Name(MaybePrivate::new_private(&mut rng, &master_key, String::from("Positive Pyotr")).unwrap()),
            name: Some("Grover".into()),
        });
        test_privates(&TransactionBody::DeleteClaimV1 {
            claim_id: ClaimID::random(),
        });

        let entry = StampEntry::new::<Timestamp>(IdentityID::random(), IdentityID::random(), ClaimID::random(), Confidence::Low, None);
        test_privates(&TransactionBody::MakeStampV1 { stamp: entry.clone() });
        test_privates(&TransactionBody::RevokeStampV1 {
            stamp_id: StampID::random(),
            reason: StampRevocationReason::Unspecified,
        });
        let stamp_transaction = transactions.make_stamp(&HashAlgo::Blake3, Timestamp::now(), entry.clone()).unwrap();
        test_privates(&TransactionBody::AcceptStampV1 {
            stamp_transaction: Box::new(stamp_transaction),
        });
        test_privates(&TransactionBody::DeleteStampV1 {
            stamp_id: StampID::random(),
        });

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
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let body = TransactionBody::MakeClaimV1 {
            spec: ClaimSpec::Name(MaybePrivate::new_private(&mut rng, &master_key, "Jackie Chrome".into()).unwrap()),
            name: None,
        };
        let entry = TransactionEntry::new(Timestamp::now(), vec![TransactionID::from(Hash::random_blake3())], body);
        assert!(entry.has_private());
        assert!(entry.body().has_private());
        let entry2 = entry.strip_private();
        assert!(!entry2.has_private());
        assert!(!entry2.body().has_private());
    }

    #[test]
    fn trans_verify_hash_and_signatures() {
        let mut rng = crate::util::test::rng();
        let now = Timestamp::now();
        let (_master_key1, transactions1, _admin_key1) = test::create_fake_identity(&mut rng, now.clone());
        let (_master_key2, mut transactions2, _admin_key2) = test::create_fake_identity(&mut rng, now.clone());
        transactions1.transactions()[0].verify_hash_and_signatures().unwrap();
        *transactions2.transactions_mut()[0].signatures_mut() = transactions1.transactions()[0].signatures().clone();
        assert!(matches!(
            transactions2.transactions()[0].verify_hash_and_signatures(),
            Err(Error::TransactionSignatureInvalid(_))
        ));
    }

    #[test]
    fn trans_new_verify() {
        let mut rng = crate::util::test::rng();
        let now = Timestamp::now();
        let (_master_key, transactions, admin_key) = test::create_fake_identity(&mut rng, now.clone());
        transactions.transactions()[0].verify(None).unwrap();

        let (_, transactions_new, _) = test::create_fake_identity(&mut rng, now.clone());

        let create2 = transactions_new.transactions()[0].clone();

        let res = transactions.clone().push_transaction(create2);
        assert_eq!(res.err(), Some(Error::DagCreateIdentityOnExistingChain));

        let mut trans2 = transactions.transactions()[0].clone();
        trans2.set_id(TransactionID::random());
        assert!(matches!(trans2.verify(None).err(), Some(Error::TransactionIDMismatch(..))));

        let mut trans3 = transactions.transactions()[0].clone();
        let then = Timestamp::from(*now.deref() - chrono::Duration::seconds(2));
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
        let mut rng = crate::util::test::rng();
        let now = Timestamp::now();
        let (master_key, transactions, admin_key) = test::create_fake_identity(&mut rng, now.clone());
        let admin_key2 = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        assert!(transactions.transactions()[0].is_signed_by(&admin_key.key().clone().into()));
        assert!(!transactions.transactions()[0].is_signed_by(&admin_key2.clone().into()));
    }

    #[ignore]
    #[test]
    fn trans_validate_publish_transaction() {
        todo!();
    }

    #[test]
    fn trans_strip_has_private() {
        let mut rng = crate::util::test::rng();
        let now = Timestamp::now();
        let (_master_key, transactions, _admin_key) = test::create_fake_identity(&mut rng, now.clone());
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
        let mut rng = crate::util::test::rng();
        let now = Timestamp::now();
        let (_master_key, transactions, _admin_key) = test::create_fake_identity(&mut rng, now.clone());
        let trans = transactions.transactions()[0].clone();

        let ser = trans.serialize_binary().unwrap();
        let des = Transaction::deserialize_binary(ser.as_slice()).unwrap();

        assert_eq!(trans.id(), des.id());
    }

    #[test]
    #[ignore]
    fn trans_ord() {
        todo!("make sure transaction orders by created asc then id asc");
    }

    // -------------------------------------------------------------------------
    // a series of tests that make sure our serialization format doesn't change.
    // -------------------------------------------------------------------------

    macro_rules! assert_sign_keys_eq {
        ($master:expr, $key1:expr, $key2:expr) => {
            match ($key1, $key2) {
                (
                    SignKeypair::Ed25519 {
                        public: public1,
                        secret: Some(secret1),
                    },
                    SignKeypair::Ed25519 {
                        public: public2,
                        secret: Some(secret2),
                    },
                ) => {
                    assert_eq!(public1, public2);
                    let revealed1 = secret1.open($master).unwrap();
                    let revealed2 = secret2.open($master).unwrap();
                    assert_eq!(revealed1.expose_secret(), revealed2.expose_secret());
                }
                _ => panic!("assert_keys_eq -- invalid pattern encountered"),
            }
        };
    }

    #[test]
    fn trans_serde_create_identity_v1() {
        let mut rng = crate::util::test::rng_seeded(b"jimmy don't");
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap()),
            "alpha",
            Some("hello there"),
        );
        let admin_key2 = AdminKey::new(AdminKeypair::from(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap()), "name-claim", None);
        let policy1 = Policy::new(
            vec![Capability::Permissive],
            MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![admin_key1.key().clone().into()],
            },
        );
        let policy2 = Policy::new(
            vec![Capability::Transaction {
                body_type: vec![TransactionBodyType::MakeClaimV1],
                context: Context::All(vec![Context::ClaimType(ContextClaimType::Name)]),
            }],
            MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![admin_key2.key().clone().into()],
            },
        );
        let trans = TransactionBody::CreateIdentityV1 {
            admin_keys: vec![admin_key1.clone(), admin_key2.clone()],
            policies: vec![policy1, policy2],
        };
        let ser_check = ser::serialize(&trans).unwrap();
        let ser = [
            160, 130, 1, 228, 48, 130, 1, 224, 160, 130, 1, 60, 48, 130, 1, 56, 48, 129, 158, 160, 129, 131, 160, 129, 128, 48, 126, 160,
            34, 4, 32, 226, 90, 17, 113, 54, 95, 229, 226, 244, 99, 234, 123, 135, 232, 99, 214, 213, 227, 33, 127, 24, 249, 137, 242, 46,
            150, 172, 28, 121, 47, 92, 109, 161, 88, 48, 86, 160, 84, 160, 28, 160, 26, 4, 24, 133, 132, 245, 13, 7, 219, 153, 61, 55, 17,
            36, 116, 170, 185, 198, 21, 38, 252, 51, 68, 194, 65, 16, 228, 161, 52, 4, 50, 250, 141, 166, 56, 151, 29, 190, 25, 139, 203,
            142, 148, 84, 206, 16, 28, 167, 165, 178, 93, 37, 83, 12, 30, 126, 220, 32, 101, 123, 52, 1, 223, 140, 177, 176, 226, 6, 191,
            181, 136, 133, 189, 166, 11, 77, 114, 160, 239, 240, 182, 161, 7, 12, 5, 97, 108, 112, 104, 97, 162, 13, 12, 11, 104, 101, 108,
            108, 111, 32, 116, 104, 101, 114, 101, 48, 129, 148, 160, 129, 131, 160, 129, 128, 48, 126, 160, 34, 4, 32, 151, 40, 118, 117,
            50, 148, 213, 26, 80, 129, 252, 213, 116, 94, 198, 68, 34, 171, 19, 44, 99, 185, 232, 137, 144, 209, 82, 131, 11, 177, 81, 88,
            161, 88, 48, 86, 160, 84, 160, 28, 160, 26, 4, 24, 126, 211, 248, 125, 247, 70, 44, 106, 7, 197, 177, 121, 25, 118, 5, 100, 96,
            210, 7, 49, 214, 133, 140, 43, 161, 52, 4, 50, 50, 61, 176, 253, 193, 203, 151, 105, 21, 18, 9, 43, 235, 225, 118, 44, 149,
            110, 145, 115, 98, 235, 65, 219, 156, 13, 170, 216, 244, 198, 121, 156, 250, 36, 176, 190, 92, 116, 212, 140, 193, 73, 68, 13,
            184, 103, 233, 185, 71, 138, 161, 12, 12, 10, 110, 97, 109, 101, 45, 99, 108, 97, 105, 109, 161, 129, 157, 48, 129, 154, 48,
            65, 160, 6, 48, 4, 160, 2, 5, 0, 161, 55, 162, 53, 48, 51, 160, 3, 2, 1, 1, 161, 44, 48, 42, 160, 40, 48, 38, 161, 36, 160, 34,
            4, 32, 226, 90, 17, 113, 54, 95, 229, 226, 244, 99, 234, 123, 135, 232, 99, 214, 213, 227, 33, 127, 24, 249, 137, 242, 46, 150,
            172, 28, 121, 47, 92, 109, 48, 85, 160, 26, 48, 24, 161, 22, 48, 20, 160, 6, 48, 4, 167, 2, 5, 0, 161, 10, 160, 8, 48, 6, 169,
            4, 161, 2, 5, 0, 161, 55, 162, 53, 48, 51, 160, 3, 2, 1, 1, 161, 44, 48, 42, 160, 40, 48, 38, 161, 36, 160, 34, 4, 32, 151, 40,
            118, 117, 50, 148, 213, 26, 80, 129, 252, 213, 116, 94, 198, 68, 34, 171, 19, 44, 99, 185, 232, 137, 144, 209, 82, 131, 11,
            177, 81, 88,
        ];
        assert_eq!(ser_check, ser);
        let trans_deser: TransactionBody = ser::deserialize(&ser).unwrap();

        match (trans, trans_deser) {
            (
                TransactionBody::CreateIdentityV1 {
                    admin_keys: admin_keys1,
                    policies: policies1,
                },
                TransactionBody::CreateIdentityV1 {
                    admin_keys: admin_keys2,
                    policies: policies2,
                },
            ) => {
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
    fn trans_serde_reset_identity_v1() {
        let mut rng = crate::util::test::rng_seeded(b"jimmy don't");
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap()),
            "alpha",
            Some("hello there"),
        );
        let admin_key2 = AdminKey::new(AdminKeypair::from(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap()), "name-claim", None);
        let policy1 = Policy::new(
            vec![Capability::Permissive],
            MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![admin_key1.key().clone().into()],
            },
        );
        let policy2 = Policy::new(
            vec![Capability::Transaction {
                body_type: vec![TransactionBodyType::MakeClaimV1],
                context: Context::All(vec![Context::ClaimType(ContextClaimType::Name)]),
            }],
            MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![admin_key2.key().clone().into()],
            },
        );
        let trans1 = TransactionBody::ResetIdentityV1 {
            admin_keys: Some(vec![admin_key1.clone(), admin_key2.clone()]),
            policies: Some(vec![policy1, policy2]),
        };
        let trans2 = TransactionBody::ResetIdentityV1 {
            admin_keys: None,
            policies: None,
        };
        let ser1_check = ser::serialize(&trans1).unwrap();
        let ser2_check = ser::serialize(&trans2).unwrap();
        let ser1 = [
            161, 130, 1, 228, 48, 130, 1, 224, 160, 130, 1, 60, 48, 130, 1, 56, 48, 129, 158, 160, 129, 131, 160, 129, 128, 48, 126, 160,
            34, 4, 32, 226, 90, 17, 113, 54, 95, 229, 226, 244, 99, 234, 123, 135, 232, 99, 214, 213, 227, 33, 127, 24, 249, 137, 242, 46,
            150, 172, 28, 121, 47, 92, 109, 161, 88, 48, 86, 160, 84, 160, 28, 160, 26, 4, 24, 133, 132, 245, 13, 7, 219, 153, 61, 55, 17,
            36, 116, 170, 185, 198, 21, 38, 252, 51, 68, 194, 65, 16, 228, 161, 52, 4, 50, 250, 141, 166, 56, 151, 29, 190, 25, 139, 203,
            142, 148, 84, 206, 16, 28, 167, 165, 178, 93, 37, 83, 12, 30, 126, 220, 32, 101, 123, 52, 1, 223, 140, 177, 176, 226, 6, 191,
            181, 136, 133, 189, 166, 11, 77, 114, 160, 239, 240, 182, 161, 7, 12, 5, 97, 108, 112, 104, 97, 162, 13, 12, 11, 104, 101, 108,
            108, 111, 32, 116, 104, 101, 114, 101, 48, 129, 148, 160, 129, 131, 160, 129, 128, 48, 126, 160, 34, 4, 32, 151, 40, 118, 117,
            50, 148, 213, 26, 80, 129, 252, 213, 116, 94, 198, 68, 34, 171, 19, 44, 99, 185, 232, 137, 144, 209, 82, 131, 11, 177, 81, 88,
            161, 88, 48, 86, 160, 84, 160, 28, 160, 26, 4, 24, 126, 211, 248, 125, 247, 70, 44, 106, 7, 197, 177, 121, 25, 118, 5, 100, 96,
            210, 7, 49, 214, 133, 140, 43, 161, 52, 4, 50, 50, 61, 176, 253, 193, 203, 151, 105, 21, 18, 9, 43, 235, 225, 118, 44, 149,
            110, 145, 115, 98, 235, 65, 219, 156, 13, 170, 216, 244, 198, 121, 156, 250, 36, 176, 190, 92, 116, 212, 140, 193, 73, 68, 13,
            184, 103, 233, 185, 71, 138, 161, 12, 12, 10, 110, 97, 109, 101, 45, 99, 108, 97, 105, 109, 161, 129, 157, 48, 129, 154, 48,
            65, 160, 6, 48, 4, 160, 2, 5, 0, 161, 55, 162, 53, 48, 51, 160, 3, 2, 1, 1, 161, 44, 48, 42, 160, 40, 48, 38, 161, 36, 160, 34,
            4, 32, 226, 90, 17, 113, 54, 95, 229, 226, 244, 99, 234, 123, 135, 232, 99, 214, 213, 227, 33, 127, 24, 249, 137, 242, 46, 150,
            172, 28, 121, 47, 92, 109, 48, 85, 160, 26, 48, 24, 161, 22, 48, 20, 160, 6, 48, 4, 167, 2, 5, 0, 161, 10, 160, 8, 48, 6, 169,
            4, 161, 2, 5, 0, 161, 55, 162, 53, 48, 51, 160, 3, 2, 1, 1, 161, 44, 48, 42, 160, 40, 48, 38, 161, 36, 160, 34, 4, 32, 151, 40,
            118, 117, 50, 148, 213, 26, 80, 129, 252, 213, 116, 94, 198, 68, 34, 171, 19, 44, 99, 185, 232, 137, 144, 209, 82, 131, 11,
            177, 81, 88,
        ];
        let ser2 = [161, 2, 48, 0];
        assert_eq!(ser1_check, ser1);
        assert_eq!(ser2_check, ser2);
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();
        let trans_deser2: TransactionBody = ser::deserialize(&ser2).unwrap();

        match (trans1, trans_deser1) {
            (
                TransactionBody::ResetIdentityV1 {
                    admin_keys: Some(admin_keys1),
                    policies: policies1,
                },
                TransactionBody::ResetIdentityV1 {
                    admin_keys: Some(admin_keys2),
                    policies: policies2,
                },
            ) => {
                assert_eq!(admin_keys1.len(), 2);
                assert_eq!(admin_keys2.len(), 2);
                assert_sign_keys_eq!(&master_key, admin_keys1[0].key().deref(), admin_keys2[0].key().deref());
                assert_sign_keys_eq!(&master_key, admin_keys1[1].key().deref(), admin_keys2[1].key().deref());
                assert_eq!(policies1, policies2);
            }
            _ => panic!("Unmatched serialization"),
        }
        match (trans2, trans_deser2) {
            (
                TransactionBody::ResetIdentityV1 {
                    admin_keys: admin_keys1,
                    policies: policies1,
                },
                TransactionBody::ResetIdentityV1 {
                    admin_keys: admin_keys2,
                    policies: policies2,
                },
            ) => {
                assert!(admin_keys1.is_none());
                assert!(admin_keys2.is_none());
                assert!(policies1.is_none());
                assert!(policies2.is_none());
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_serde_add_admin_key_v1() {
        let mut rng = crate::util::test::rng_seeded(b"jimmy don't");
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap()),
            "alpha",
            Some("been watching you for quite a while now"),
        );
        let trans1 = TransactionBody::AddAdminKeyV1 { admin_key: admin_key1 };
        let ser1_check = ser::serialize(&trans1).unwrap();
        let ser1 = [
            162, 129, 195, 48, 129, 192, 160, 129, 189, 48, 129, 186, 160, 129, 131, 160, 129, 128, 48, 126, 160, 34, 4, 32, 226, 90, 17,
            113, 54, 95, 229, 226, 244, 99, 234, 123, 135, 232, 99, 214, 213, 227, 33, 127, 24, 249, 137, 242, 46, 150, 172, 28, 121, 47,
            92, 109, 161, 88, 48, 86, 160, 84, 160, 28, 160, 26, 4, 24, 133, 132, 245, 13, 7, 219, 153, 61, 55, 17, 36, 116, 170, 185, 198,
            21, 38, 252, 51, 68, 194, 65, 16, 228, 161, 52, 4, 50, 250, 141, 166, 56, 151, 29, 190, 25, 139, 203, 142, 148, 84, 206, 16,
            28, 167, 165, 178, 93, 37, 83, 12, 30, 126, 220, 32, 101, 123, 52, 1, 223, 140, 177, 176, 226, 6, 191, 181, 136, 133, 189, 166,
            11, 77, 114, 160, 239, 240, 182, 161, 7, 12, 5, 97, 108, 112, 104, 97, 162, 41, 12, 39, 98, 101, 101, 110, 32, 119, 97, 116,
            99, 104, 105, 110, 103, 32, 121, 111, 117, 32, 102, 111, 114, 32, 113, 117, 105, 116, 101, 32, 97, 32, 119, 104, 105, 108, 101,
            32, 110, 111, 119,
        ];
        assert_eq!(ser1_check, ser1);
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::AddAdminKeyV1 { admin_key: admin_key1 }, TransactionBody::AddAdminKeyV1 { admin_key: admin_key2 }) => {
                assert_sign_keys_eq!(&master_key, admin_key1.key().deref(), admin_key2.key().deref());
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_serde_edit_admin_key_v1() {
        let mut rng = crate::util::test::rng_seeded(b"jimmy don't");
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap()),
            "admin/edit",
            Some("i like your hat"),
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
        let ser1 = [
            163, 57, 48, 55, 160, 38, 160, 36, 160, 34, 4, 32, 226, 90, 17, 113, 54, 95, 229, 226, 244, 99, 234, 123, 135, 232, 99, 214,
            213, 227, 33, 127, 24, 249, 137, 242, 46, 150, 172, 28, 121, 47, 92, 109, 161, 11, 12, 9, 97, 100, 109, 105, 110, 47, 97, 108,
            108, 162, 0,
        ];
        let ser2 = [
            163, 68, 48, 66, 160, 38, 160, 36, 160, 34, 4, 32, 226, 90, 17, 113, 54, 95, 229, 226, 244, 99, 234, 123, 135, 232, 99, 214,
            213, 227, 33, 127, 24, 249, 137, 242, 46, 150, 172, 28, 121, 47, 92, 109, 161, 11, 12, 9, 97, 100, 109, 105, 110, 47, 97, 108,
            108, 162, 11, 12, 9, 102, 117, 110, 32, 116, 105, 109, 101, 115,
        ];
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();
        let trans_deser2: TransactionBody = ser::deserialize(&ser2).unwrap();

        match (trans1, trans_deser1) {
            (
                TransactionBody::EditAdminKeyV1 {
                    id: id1,
                    name: name1,
                    description: desc1,
                },
                TransactionBody::EditAdminKeyV1 {
                    id: id2,
                    name: name2,
                    description: desc2,
                },
            ) => {
                assert_eq!(id1, id2);
                assert_eq!(name1, name2);
                assert_eq!(desc1, desc2);
            }
            _ => panic!("Unmatched serialization"),
        }
        match (trans2, trans_deser2) {
            (
                TransactionBody::EditAdminKeyV1 {
                    id: id1,
                    name: name1,
                    description: desc1,
                },
                TransactionBody::EditAdminKeyV1 {
                    id: id2,
                    name: name2,
                    description: desc2,
                },
            ) => {
                assert_eq!(id1, id2);
                assert_eq!(name1, name2);
                assert_eq!(desc1, desc2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_serde_revoke_admin_key_v1() {
        let mut rng = crate::util::test::rng_seeded(b"jimmy don't");
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap()),
            "admin/edit",
            Some("i like your hat"),
        );
        let trans1 = TransactionBody::RevokeAdminKeyV1 {
            id: admin_key1.key_id(),
            reason: RevocationReason::Compromised,
            new_name: Some("admin/no-more".to_string()),
        };
        let ser1 = [
            164, 65, 48, 63, 160, 38, 160, 36, 160, 34, 4, 32, 226, 90, 17, 113, 54, 95, 229, 226, 244, 99, 234, 123, 135, 232, 99, 214,
            213, 227, 33, 127, 24, 249, 137, 242, 46, 150, 172, 28, 121, 47, 92, 109, 161, 4, 162, 2, 5, 0, 162, 15, 12, 13, 97, 100, 109,
            105, 110, 47, 110, 111, 45, 109, 111, 114, 101,
        ];
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();

        match (trans1, trans_deser1) {
            (
                TransactionBody::RevokeAdminKeyV1 {
                    id: id1,
                    reason: reason1,
                    new_name: name1,
                },
                TransactionBody::RevokeAdminKeyV1 {
                    id: id2,
                    reason: reason2,
                    new_name: name2,
                },
            ) => {
                assert_eq!(id1, id2);
                assert_eq!(reason1, reason2);
                assert_eq!(name1, name2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_serde_add_policy_v1() {
        let mut rng = crate::util::test::rng_seeded(b"jimmy don't");
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let admin_key1 = AdminKey::new(
            AdminKeypair::from(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap()),
            "admin/edit",
            Some("i like your hat"),
        );
        let policy1 = Policy::new(
            vec![Capability::Transaction {
                body_type: vec![TransactionBodyType::MakeClaimV1],
                context: Context::All(vec![Context::ClaimType(ContextClaimType::Name)]),
            }],
            MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![admin_key1.key().clone().into()],
            },
        );
        let trans1 = TransactionBody::AddPolicyV1 { policy: policy1 };
        let ser1 = [
            165, 93, 48, 91, 160, 89, 48, 87, 160, 26, 48, 24, 161, 22, 48, 20, 160, 6, 48, 4, 167, 2, 5, 0, 161, 10, 160, 8, 48, 6, 169,
            4, 161, 2, 5, 0, 161, 57, 162, 55, 48, 53, 160, 3, 2, 1, 1, 161, 46, 48, 44, 160, 42, 48, 40, 160, 0, 161, 36, 160, 34, 4, 32,
            226, 90, 17, 113, 54, 95, 229, 226, 244, 99, 234, 123, 135, 232, 99, 214, 213, 227, 33, 127, 24, 249, 137, 242, 46, 150, 172,
            28, 121, 47, 92, 109,
        ];
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::AddPolicyV1 { policy: policy1 }, TransactionBody::AddPolicyV1 { policy: policy2 }) => {
                assert_eq!(policy1, policy2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_serde_delete_policy_v1() {
        let policy_id1 = PolicyID::from(TransactionID::from(Hash::new_blake3(&[55, 66, 42, 17, 0, 9]).unwrap()));
        let trans1 = TransactionBody::DeletePolicyV1 { id: policy_id1 };
        let ser1 = [
            166, 42, 48, 40, 160, 38, 48, 36, 160, 34, 4, 32, 2, 52, 247, 192, 86, 41, 53, 236, 142, 72, 7, 209, 104, 10, 19, 55, 211, 110,
            35, 148, 193, 106, 201, 79, 182, 100, 227, 110, 29, 175, 128, 162,
        ];
        let trans_deser1: TransactionBody = ser::deserialize(&ser1).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::DeletePolicyV1 { id: id1 }, TransactionBody::DeletePolicyV1 { id: id2 }) => {
                assert_eq!(id1, id2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_serde_make_claim_v1() {
        let mut rng = crate::util::test::rng_seeded(b"jimmy don't");
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let claim1 = ClaimSpec::Identity(MaybePrivate::new_public(IdentityID::from(TransactionID::from(
            Hash::new_blake3(&[1, 2, 3, 4, 5]).unwrap(),
        ))));
        let claim2 = ClaimSpec::Extension {
            key: BinaryVec::from(vec![2, 4, 6, 8]),
            value: MaybePrivate::new_private(&mut rng, &master_key, BinaryVec::from(vec![9, 9, 9])).unwrap(),
        };
        let trans1 = TransactionBody::MakeClaimV1 {
            spec: claim1,
            name: Some("my-old-id".to_string()),
        };
        let trans2 = TransactionBody::MakeClaimV1 { spec: claim2, name: None };
        let ser1 = [
            167, 59, 48, 57, 160, 42, 160, 40, 160, 38, 48, 36, 160, 34, 4, 32, 2, 79, 103, 192, 66, 90, 61, 192, 47, 186, 245, 140, 185,
            61, 229, 19, 46, 61, 117, 197, 25, 250, 160, 186, 218, 33, 73, 29, 136, 201, 112, 87, 161, 11, 12, 9, 109, 121, 45, 111, 108,
            100, 45, 105, 100,
        ];
        let ser2 = [
            167, 129, 172, 48, 129, 169, 160, 129, 164, 172, 129, 161, 48, 129, 158, 160, 6, 4, 4, 2, 4, 6, 8, 161, 129, 147, 161, 129,
            144, 48, 129, 141, 160, 36, 160, 34, 4, 32, 216, 38, 14, 63, 6, 105, 24, 215, 247, 128, 138, 208, 100, 48, 185, 147, 137, 79,
            58, 139, 216, 1, 48, 218, 42, 87, 252, 65, 221, 233, 175, 90, 161, 101, 48, 99, 160, 97, 160, 28, 160, 26, 4, 24, 133, 132,
            245, 13, 7, 219, 153, 61, 55, 17, 36, 116, 170, 185, 198, 21, 38, 252, 51, 68, 194, 65, 16, 228, 161, 65, 4, 63, 206, 128, 94,
            229, 26, 112, 231, 200, 143, 126, 32, 50, 101, 242, 222, 26, 26, 215, 52, 27, 134, 11, 135, 88, 200, 251, 159, 208, 240, 39,
            213, 110, 16, 84, 172, 181, 199, 215, 19, 103, 85, 216, 234, 141, 75, 132, 214, 7, 6, 83, 29, 38, 23, 15, 183, 78, 239, 100,
            217, 4, 176, 122, 149, 161, 0,
        ];
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

    #[ignore]
    #[test]
    fn trans_serde_edit_claim_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_delete_claim_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_make_stamp_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_revoke_stamp_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_accept_stamp_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_delete_stamp_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_add_subkey_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_edit_subkey_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_revoke_subkey_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_delete_subkey_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_publish_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_sign_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn trans_serde_ext_v1() {
        todo!();
    }

    #[test]
    fn trans_deser_publish_yaml() {
        let published_identity = r#"
---
id:
  Blake3: pJbf3PvEF2swcX-QRMcHF2YPn7_ome5o30IhFaYuKM0
entry:
  created: "2024-07-26T00:24:15.361Z"
  previous_transactions:
    - Blake3: o9eaGWb0Xgkrg5Oqf-tehNdur7pUUC4UmSV00r_hR6s
  body:
    PublishV1:
      transactions:
        transactions:
          - id:
              Blake3: zef-iKEplM5PtaQTP3l0_Yb2vYK_cVuTZg8rwejfjzw
            entry:
              created: "2024-07-26T00:19:03.796Z"
              previous_transactions: []
              body:
                CreateIdentityV1:
                  admin_keys:
                    - key:
                        Ed25519:
                          public: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
                          secret: ~
                      name: alpha
                      description: Your main admin key
                      revocation: ~
                  policies:
                    - capabilities:
                        - Permissive
                      multisig_policy:
                        MOfN:
                          must_have: 1
                          participants:
                            - Key:
                                name: ~
                                key:
                                  Ed25519: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
            signatures:
              - Key:
                  key:
                    Ed25519: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
                  signature:
                    Ed25519: H1Vbg47FW01JJhdk2_ASIFNB4xUbOIxpcUJJlm6PyT-kJcrS3uTPUGyl7yWq4mZ8OlENNGihuJgfFIqdS14RAA
          - id:
              Blake3: 9CpMShDnJCkm7xfYnzhlXLTVz_4ooR9lOggYG2E2Qxo
            entry:
              created: "2024-07-26T00:19:36.383Z"
              previous_transactions:
                - Blake3: zef-iKEplM5PtaQTP3l0_Yb2vYK_cVuTZg8rwejfjzw
              body:
                MakeClaimV1:
                  spec:
                    Identity:
                      Public:
                        Blake3: zef-iKEplM5PtaQTP3l0_Yb2vYK_cVuTZg8rwejfjzw
                  name: ~
            signatures:
              - Key:
                  key:
                    Ed25519: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
                  signature:
                    Ed25519: eUsfBpWGePyR98OUV4WQkJuSeW_7KrzpPKI-9lN9OG_YqpRHeadYXUp_ZXO1NHGYU4HwoBNEhfBDnbk--v27AQ
          - id:
              Blake3: FJLh0dArIgR10WyPyDCuYHEBxTeGvLhUetN5vmtB7aU
            entry:
              created: "2024-07-26T00:19:36.384Z"
              previous_transactions:
                - Blake3: 9CpMShDnJCkm7xfYnzhlXLTVz_4ooR9lOggYG2E2Qxo
              body:
                MakeClaimV1:
                  spec:
                    Name:
                      Public: Zefram Cochrane
                  name: ~
            signatures:
              - Key:
                  key:
                    Ed25519: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
                  signature:
                    Ed25519: n0c1QeglXFA4Ih96pqdVTb7orjofHgKVCaaGFOYTOHsxHXf5l9eG5F4a3foxH8-7GOcwV2JFFvAtfDPs1HQ6Aw
          - id:
              Blake3: gOpIJMGGUsRdLSI8EqnkHDfroXUzmA3zEK_alKlqPs4
            entry:
              created: "2024-07-26T00:19:36.384Z"
              previous_transactions:
                - Blake3: FJLh0dArIgR10WyPyDCuYHEBxTeGvLhUetN5vmtB7aU
              body:
                MakeClaimV1:
                  spec:
                    Email:
                      Public: zef@starfleet.org
                  name: ~
            signatures:
              - Key:
                  key:
                    Ed25519: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
                  signature:
                    Ed25519: "-hUkX6qOsU3YRfA-Rhx-TLjnBcTMzWBT3wsVyAJF6VauYWcc9LdxPyllannYs7vaVjzhL2mOjLnqMhJ7h4kuDw"
          - id:
              Blake3: CME1vP1HrTOf44TLvQ08zZJ2vgNJ2Ao1IIgwW1LWDuw
            entry:
              created: "2024-07-26T00:19:36.385Z"
              previous_transactions:
                - Blake3: gOpIJMGGUsRdLSI8EqnkHDfroXUzmA3zEK_alKlqPs4
              body:
                AddSubkeyV1:
                  key:
                    Sign:
                      Ed25519:
                        public: hmGYRn5eH6lAhTEoYTkJWi27eNwLU0G2XgILwyiO0Lo
                        secret: ~
                  name: default/sign
                  desc: A default key for signing documents or messages.
            signatures:
              - Key:
                  key:
                    Ed25519: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
                  signature:
                    Ed25519: taLWH361m-uYkrpvWFKyYQCHm8eMbBeBFvJgvU03DSVe5XNh45SoA5ayureIAJjSSfay5lj3oLIfnY0uJv3FCw
          - id:
              Blake3: YxCab7-VEgAhqKF9HuD6wRDz2sn6w_SEAi0Jl_C5-EI
            entry:
              created: "2024-07-26T00:19:36.386Z"
              previous_transactions:
                - Blake3: CME1vP1HrTOf44TLvQ08zZJ2vgNJ2Ao1IIgwW1LWDuw
              body:
                AddSubkeyV1:
                  key:
                    Crypto:
                      Curve25519XChaCha20Poly1305:
                        public: gwxr0F2ylNd98u6_2G3FZ38dfeY-bnMTQrADEJMVIlE
                        secret: ~
                  name: default/crypto
                  desc: A default key for receiving private messages.
            signatures:
              - Key:
                  key:
                    Ed25519: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
                  signature:
                    Ed25519: "-7QYIod0Gf25U8dZorfqMzfBGmlITgEMsMQP0CZPHqfT6wWVHwE2_eydlBsAmQhV-rBkBg7IXwohPcuhaeKqDg"
          - id:
              Blake3: 2FokIj1zj4EQg24Z1MCWZ-1cnc_EodzgpTVMAiBFVIE
            entry:
              created: "2024-07-26T00:19:36.387Z"
              previous_transactions:
                - Blake3: YxCab7-VEgAhqKF9HuD6wRDz2sn6w_SEAi0Jl_C5-EI
              body:
                AddSubkeyV1:
                  key:
                    Secret:
                      hmac:
                        Blake3: tv-7T7GEqR36xuwzcdhxr66t6iDacLdZ2raoAppgyRw
                      data: ~
                  name: default/secret
                  desc: A default key allowing encryption/decryption of personal data.
            signatures:
              - Key:
                  key:
                    Ed25519: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
                  signature:
                    Ed25519: TIBcinDKy3Mh7fGZ6Hhr7StUlyLrZXHq44wHpKUg8EBw_KzWrFUYUcbVEm_GYs8uTIlLgMpH5AzZY9U2dDyoAA
          - id:
              Blake3: Z-qg1FexHYIrLsqm9HrYC_E7vJ1Pl-XQNKwh5AtVADo
            entry:
              created: "2024-07-26T00:20:39.788Z"
              previous_transactions:
                - Blake3: 2FokIj1zj4EQg24Z1MCWZ-1cnc_EodzgpTVMAiBFVIE
              body:
                MakeClaimV1:
                  spec:
                    Photo:
                      Public: _9j_4AAQSkZJRgABAQEASABIAAD_2wBDABQODxIPDRQSEBIXFRQYHjIhHhwcHj0sLiQySUBMS0dARkVQWnNiUFVtVkVGZIhlbXd7gYKBTmCNl4x9lnN-gXz_2wBDARUXFx4aHjshITt8U0ZTfHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHz_wgARCACZAJkDAREAAhEBAxEB_8QAGQAAAgMBAAAAAAAAAAAAAAAAAgMAAQQF_8QAFwEBAQEBAAAAAAAAAAAAAAAAAAECA__aAAwDAQACEAMQAAABz8qy6kCKsFKQiFAlllC9BqqhRB_Kto1Wg1aFLdXJKkoooql6BVkIQ0c7ZCqlhlhSyIXYVXGSkaQhCEHYtw2w6qqBi4gwOjoIztZdZohCENmUiWssIXTIRDShupsOdNKms1zVkIQhsxYQZqDYNIlqNMtDlfWRAlz0u5shCG3mtZZWlEWSsmnqQ0ZQGdOcym5lQhDbzsSUJbWlqgJSDCM9aIZbzdYzMVUIQ140UhkoGnqIgFdMq0uzeoHLuUXEqEIbMaKSy7q2mSIFVQ-XfQDlSnJ1hVzCEIa8bJkoixsrCQCpSXbaBcVXNvNGoCRLWG3G7mZVwy6FSFxQ-0yKmNIjWMaIspKqzbnbEKRqsM6iqoolMa2IAwBLQKFMlzmOhnQoCvIARVqci7WroWg7nnw-R1pIVlJnjGhrqIudGW3NAUFK-1qKucDMl3roFkTKykYrhRms0rc1agMlfRIihuMSas72DgTnM2LHiDNqOV0tKUWNURlxlFJsmiXQEc2ZlsSCLFgmuqmhlOV1p3I3GaKHS75oBVZ5m1uxYqwQKGtEuuAVo-zKmaCFHSmnLDCzUUq7EWWVQVS7syx1azAZoaIOlNaFSf_EACYQAAIBBAEEAgMBAQAAAAAAAAABAgMQERIhIDAxMhNBIzNCBEP_2gAIAQEAAQUCVsmw-b4NTXpz1oyZM9evaybWwY62sk447Goo9KMGuoqcmlTkPKJ9fCMn2yMHIjzKcVinhikTqZdGpKBFtE6jk5D7O-pKo5OKYpSGJpGNnFSRiriSw5D7P9SaclsaYEkKKFeSFTiift2MZEkhDtsbHyRN2RbyVPbsJWRJjkblLEiUNZ_HmSisS8y9u19MaMEPZx3SWojzL77UbOyRH1nJCdpL8j7OrFwO2RelN4KkN1TbtOnlyg10owYFgb48t9H2Y5tJ20jIqUtbKPDmIVpGdkOyyao9TIqgnlReSQuT44EvWZC3lzZT_WOyEnaZOOpF8wawNYMsfmSI8L6fmb5pv8ZgwIR9VfEuacfK4IPk0RIflH8ytSlrKS1FIyhCJsr_AK8kuCKUjDg88Wxylxnh-LQqZWjsjOFTjsT5_wA78y9KUhPhxNrP2fgm8ivGZsS0z8URRXyT5g_L9Fw4O2R3dkO8fEPaA_Nb1P8AmQv_AP_EABoRAAIDAQEAAAAAAAAAAAAAAAERADBAIGD_2gAIAQMBAT8B9corlFFF0ahUchpGQVGH3QsHBxOPb__EABQRAQAAAAAAAAAAAAAAAAAAAID_2gAIAQIBAT8BSH__xAApEAABAwIFBAICAwAAAAAAAAABABEhAhAgMDFRYRIiQHEyQQOBUtHx_9oACAEBAAY_AvPjxZ8GQycCFomOYdhqmVRoEBFyy4W6MIN8ul-lfFesrlkenRa9xTOW2t2kokvK7QU0ts6-6Su4TvlUnqH9ItuiHg65DmRsjnBAqVCmxz-kri0Wq9-AMB8AKb1eBK5TGxqBU5XOTomtonGmJ04waLZTOAv_AIuVxbTEcht1xYb4Xw-sf46sX3b2E1jtadCuMIp3Q4KKBtuLzYxh6al2rm0pzqi_8rftNaFrlTSCodTU6cFgqjb95wsVSqvdxg__xAAmEAEAAgIBBAEEAwEAAAAAAAABABEhMUEQUWFxgSAwobGRwfDx_9oACAEBAAE_IasWnEHzFX0joJntFcTUvotRi5cuX01qJ3FVGMIM4geelvM3xG-f4TI5ixfquFY2mWecIYOJh6kA4Szhx9gTANyokuLFcbaGKpYqvMQ3Bnca12wr0Lv6gh4QyL6L9XcQGfRy-J7yP-5dI0LLjmS3wLgXZw5gA1DNs0g8Rs8MsWOeOY7Kze1zb6q6VG0ouy7lEURSLuKwV_FAD5y24bVCULed4rMbzSrwTbH3AGD0kexOBeo32b-w10OOI6YUgu2e8tDpEDa5eqAdRcEGoMBEQRitiOoFAGvquX0fmjHSalzLL1EUPpiB-kHa_aKoJZVd8T5_MfqOirslUzSYOnZaIMjuMlnjAA8dpSUqCqEz-0KOITvLdwrMYK17IipqK-ZajMtu7jv7N04i4iHRUrivxQECmIblQQ0_Z1WMNt9FxpFQ7svdk0-moTFAxBzh2mSH8RM_SLShuMupiPnUU0kYEqJLzDAzBlG3QS21jmpU4ONxM5B-IirGLyeirLcIoPxFcTP0io70KLM3BRL7KFuaEFBTFWxqJC3REXbXaVzLkeYr0bQVmKCkK6HKFn9QsCpeHiYLf9hoPe44juXWpZhoZMxlWhWJmMZ7Stf9QzbW-IvwnqgteZfYlQm1_cVIHcRpxLn3cuvXQ5TGPMULMK8RmcTGvxFb3ARfEoAPE8EWqzZPJ_VMw0Bi3bgiLy8I5th-kMZ-f4lHki0TFLDkdfE3uzU2EGHCqeYnL7YHocjwjodmYBdlBrvdw1IYjA2kbOZ2l7HEbyrMElkWCWXuVmHwJqgrt2jekoVz8T_VQwl_mYYajsdpdTD8TIidON-GZHzLKcIHszNak4uUzNId4eyqMxk4wqWYJ81Pc6HicvSzn0cw1Pwpun7Cf4-5-InPxGOfof_aAAwDAQACAAMAAAAQ9-Q77rbigk_TnwZTrEAA20gMSA_AAAGJgTr0IAAAPgSSbvkgAAACZ0SQtFAA6IYE0Yk_AAXe6SfUMrAAnT_FC9FWAALzCQiJBNAAgZ1pEgpZtAivFG8sfvXggadhxhptmKJp_cYIhjDGbxyMkwZfDzvxvXgQ4NSyrFdANef3Vi4IOZTQd6yQ6sL0yGqQvKPUNYrQWgvI_8QAHBEAAwEBAQEBAQAAAAAAAAAAAAERECAwQCEx_9oACAEDAQE_EEJlL8VKX7p8aJ8LELH7Qm8EPylEEFlNaJh-KEIJlJlF50hfh_dRdXgmoNU_m0XDGPl6xeILILRopdeITxatsKMY0QmvYIXK4eNEGiDZcuXlYxsuseUuvE-FrKJ9TXiFtG8Y16ITLlJl_fc2IQ49Qu2LYXSj1C7fouP_xAAaEQACAwEBAAAAAAAAAAAAAAABEQAQIDBA_9oACAECAQE_EMriIPCIKG3ByG1FFBFFRtRdALIiioUeQMFmGOgY8DYgMcceHTggh7OOnBBD1WR3eR5BQ8Qp8HhcHYjp-U2MvChFDAhsaWhsWaMejT0KGhBZ4CO1agEVCjzOxRv_xAAmEAEAAgMAAgICAgMBAQAAAAABABEhMUFRYXGBIKEQkbHB8NHx_9oACAEBAAE_EEQILEo1qWaGJcXn3Cpf1AlxLLqDWB9y7sj6IfKH4wy1UiPuFsQrstRm5g2xxlpaW-YKrTcpiW_EMWq8xG7uFVb9QXRuUYeZ5MPEQ40zwCpYabnueQPlj-o2AInE_mn8UepYvxNUIHKh6Q8trGHJVc5EHz4hFkvEuzjCq8wZUyzZ332PuFryRfyMuDc4VETFZgKwQAuYzJNSvjxFVqHwSmMKDo5AaBt0FXqDghbF9PP7leS_XIsUj9zd-WQrMW0CpiF2JGwsuqi40C0ao39_UZqs4S06YhPVRswsB0MLR1EhrRitAAbUKq_u5fgWVZVZGjLA2xbAL_7Nf3KMaaZ3Z1EJ6QBSPSCvyPllgJyWsTLcFx0FF2uMHkLlIHCAUxnzUUwymEAe2ISy4KmXfMtWBetss5kJ1DP3GUMvHlmOGraIbW7Xydg7D1AYq8bJrJqXGy9ltnz2Ds3-NT9JQIy4ZlQMU0rFKFvct4OSvAICthz1MLY_EGEYcRcZJjObjFhWaQmou_PYCAlX5hNmqmVp5lyj8-IaUCqnNR_EwjYjdzGpAddSsH9wAYKNQMrihs2Zg2NjKu-JrE3i77l0ys6yTL0LwNKlmQ11wxuLcNDhBHUJt-Jlhzcor3EQBRbbFAlAtQIYJRxAKAx5gIOncAcbLHHzHyyxZYkmzmhuABP9IY3VZE23ImP4jCpdmYVkfqKDolfcYldhUKvrPLXyolaMESC4rSQoxxY8YAtV0hLg9RRs1-5aFsin3-UFMDTCrqOyCBDdVVRW1p-5Qt36gOEya3EC17l-HKplbgP-IRVZ6gpp5uAXgu58ozc1_IWymBWY5-4Dgh1WyCghXVRYs5EuoQvsRmEs51Bc2lMOxhbbyeGIKhGgeSixllLZhb1EVdVvIiDA-nEqV8_xYUaxEyDEFNxfEqQS82-ooBFyyjpARzkye55FXd0TIXzMHoomK5CpajsDUpyaCCbN-JSAcYsr5wsG9ZhctKY733M5LGitiVoFVGKr4l5Zsb4TEsLAjbyFZNFV_kxnd3XfENZeUorkulWUdcsAMCLtK-oYjvfqVh38QLPUzRY-oEXyXljEVfMKFc-XqIbkLa5Eos7oNMJVle5Rqn_UK0oNvfUtZtOmmOlDKtZ_1IEgyqFnP_ImIUGEdhhXughUUx7iFKIpb57jUXoaG9vMHpJPyMBkVXmWQ0RqrAhcAUM7jltU6pupgAtqVBIBuvEfJRw9GPYLEPqpyFNZ0NjfGBAs1o6-oCbbfxLANNBBwkrhREAfENHlT6ioCrTB0xS9K2hqtkcJwbBhjDLUOjApFFt4iaxj3G-BG4mouBqL3oC4kCgR-WEvywxfmHO64RFLwe9iK7RRfTVTGFp1P_oxWYnG7zNqsMFm3iDI-Q4S4tezGE8fMG9hNd01LpGxXPYL4M_PcxvKqVD0F-zUIvT7ljDdQ80ZqAQ8A51BWCUh4Kg711RyGOhpIJG3RORUr8BNfMZZboMkx5IrQKtIdjVwUANRBsGr_wA_MuIA401j-4hKBZgXO5tZzyCllFcChfEG9rI5SxpNUlRJYHGKloq81M5CnQDo9PuJ2xUPaxXzE4dOKZl3AlBh0tiBba_cV2ivmfH8AFdYtRRhWh3yV5btzEyN8hJhnCuSmHkqfUtHGH1GKeq9NRBVSacv3BVDM6fqNpiCPB9NQ4KVaxTKVGXoGmqV1Xmo6KyAEtTxaOVqwqI1eRByJBKz5-Zv8iP7Zo_M6-X-DSMbPmftp-hNf-WZ-7_BLr8Ju-SH7p_rHT8fx__Z
                  name: ~
            signatures:
              - Key:
                  key:
                    Ed25519: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
                  signature:
                    Ed25519: D8Xy0Qo6JqRrb7sUJC_B2NkCl7D9e8uFk8Jf8DYVL0L2CnDNw0NJLrTGjUkP-VhSVkwrizkHhS4yL0m3HcXfCQ
          - id:
              Blake3: o9eaGWb0Xgkrg5Oqf-tehNdur7pUUC4UmSV00r_hR6s
            entry:
              created: "2024-07-26T00:21:11.657Z"
              previous_transactions:
                - Blake3: Z-qg1FexHYIrLsqm9HrYC_E7vJ1Pl-XQNKwh5AtVADo
              body:
                MakeClaimV1:
                  spec:
                    Url:
                      Public: "https://news.ycombinator.com/user?id=xX_zefram420_Xx"
                  name: ~
            signatures:
              - Key:
                  key:
                    Ed25519: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
                  signature:
                    Ed25519: JlDAP8rs64KmR0VxWeLPGUYAbhLWInvuy-XuSYhX5N7oGBT6f2ZraGGGuRErQs6DHWRBL5wH6J2NmVAKlmRUAA
signatures:
  - Key:
      key:
        Ed25519: qgye4VRJgGnvxVcfqlB7hIyy6f5SZxJnqmOIJYfGmdA
      signature:
        Ed25519: JjVFZPID7ITsX13xJLk_ht-a-JDVpQ7mun_yG7WE6V2SdZsHFeQoWjXQHxoD6HNAi4qEHtqlwVoW3u_CpwGdAg
        "#;
        let transaction = Transaction::deserialize_text(published_identity).unwrap();
        match transaction.entry().body() {
            TransactionBody::PublishV1 { transactions } => {
                let identity = transactions.build_identity().unwrap();
                assert_eq!(format!("{}", identity.id()), "zef-iKEplM5PtaQTP3l0_Yb2vYK_cVuTZg8rwejfjzwA");
                let ids = transactions
                    .transactions()
                    .iter()
                    .map(|x| format!("{}", x.id()))
                    .collect::<Vec<_>>();
                assert_eq!(
                    ids,
                    vec![
                        "zef-iKEplM5PtaQTP3l0_Yb2vYK_cVuTZg8rwejfjzwA",
                        "9CpMShDnJCkm7xfYnzhlXLTVz_4ooR9lOggYG2E2QxoA",
                        "FJLh0dArIgR10WyPyDCuYHEBxTeGvLhUetN5vmtB7aUA",
                        "gOpIJMGGUsRdLSI8EqnkHDfroXUzmA3zEK_alKlqPs4A",
                        "CME1vP1HrTOf44TLvQ08zZJ2vgNJ2Ao1IIgwW1LWDuwA",
                        "YxCab7-VEgAhqKF9HuD6wRDz2sn6w_SEAi0Jl_C5-EIA",
                        "2FokIj1zj4EQg24Z1MCWZ-1cnc_EodzgpTVMAiBFVIEA",
                        "Z-qg1FexHYIrLsqm9HrYC_E7vJ1Pl-XQNKwh5AtVADoA",
                        "o9eaGWb0Xgkrg5Oqf-tehNdur7pUUC4UmSV00r_hR6sA",
                    ]
                );
            }
            _ => panic!("bad dates"),
        }
    }

    #[test]
    fn trans_deser_stamp_base64() {
        let stamp_base = r#"
            MIIBYqAmMCSgIgQgilik2Qll91ayj_YAeMs8yXanIVWJ9OOdOjMuD1Lm2
            bqhgcMwgcCgCAIGAYzTp4-joSgwJjAkoCIEILSu2LuV0C-YEOhrYA5Be_
            e7ZEccnNwMOv_6MC56MDytooGJqoGGMIGDoIGAMH6gJjAkoCIEILNH__0
            7TcYlKzSfMoteL1ULXnnD-8UGEM3KIYT6jnbfoSYwJKAiBCBl5_5mmZ1b
            UKwD7PGpTMdM_awpnBSqd9XehDsOLaAvcKImMCSgIgQgDr4qJ88VNLMra
            CqXBGoNO8ILbtizognoTwOvR3o7OtajBKECBQCicjBwoG4wbKAkoCIEIK
            DmNHCSnibCj7sBu0xHMW2r39lMo20o-SFpHsFUJgK5oUSgQgRAXeuErZt
            9bu65JmIK51-HfTi9p6Q38Wf1QTMI3Bx8GO1vWVuZGsk9QHormGe5cPkj
            50LNI8wm8yBCAdp6zkBvCw
        "#;
        let trans = Transaction::deserialize_binary(&ser::base64_decode(stamp_base).unwrap()).unwrap();
        assert_eq!(format!("{}", trans.id()), "ilik2Qll91ayj_YAeMs8yXanIVWJ9OOdOjMuD1Lm2boA");
    }
}
