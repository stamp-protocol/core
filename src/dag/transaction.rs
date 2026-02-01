//! A `Transaction` models a single change against an identity, and is one node
//! inside of the identity DAG.
//!
//! Transactions have a [TransactionBody], an ID ([Hash][crate::crypto::base::Hash]
//! of the transaction's body, timestamp, and previously-referenced transactions),
//! and a collection of one or more signatures on the transaction's ID that validate
//! that transaction.

use crate::{
    crypto::{
        base::{Hash, HashAlgo, KeyID, SecretKey},
        private::{PrivateContainer, ReEncrypt},
    },
    dag::{DagNode, DagTamperUtil, Identity},
    error::{Error, Result},
    identity::{
        claim::{ClaimID, ClaimSpec},
        instance::{IdentityID, IdentityInstance},
        keychain::{AdminKey, AdminKeyID, AdminKeypair, Key, RevocationReason},
        stamp::{Confidence, RevocationReason as StampRevocationReason, StampEntry, StampID},
    },
    policy::{Context, MultisigPolicySignature, Policy, PolicyContainer, PolicyID},
    util::{
        ser::{self, BinaryVec, DeText, HashMapAsn1, SerText, SerdeBinary},
        Timestamp,
    },
};
use getset;
use private_parts::{Full, PrivacyMode, PrivateParts, Public};
use rand::{CryptoRng, RngCore};
use rasn::{
    types::{
        fields::{Field, Fields},
        Constructed, Tag,
    },
    AsnType, Decode, Decoder, Encode, Encoder,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::convert::TryFrom;
use std::hash::{Hash as StdHash, Hasher};
use std::ops::{Deref, DerefMut};

/// A type that exists just for serializing [`Ext`] efficiently
#[derive(Debug, Clone, Encode, Decode)]
struct ExtSer<'a> {
    #[rasn(tag(explicit(0)))]
    creator: Cow<'a, IdentityID>,
    #[rasn(tag(explicit(1)))]
    ty: Option<Cow<'a, BinaryVec>>,
    #[rasn(tag(explicit(2)))]
    previous_transactions: Option<Cow<'a, Vec<TransactionID>>>,
    #[rasn(tag(explicit(3)))]
    context: Option<Cow<'a, HashMapAsn1<BinaryVec, BinaryVec>>>,
    #[rasn(tag(explicit(4)))]
    payload: Option<Cow<'a, BinaryVec>>,
}

impl<'a> AsnType for ExtSer<'a> {
    const TAG: Tag = Tag::SEQUENCE;
}

impl<'a> Constructed<5, 0> for ExtSer<'a> {
    const FIELDS: Fields<5> = Fields::from_static([
        Field::new_required_type::<Cow<'a, IdentityID>>(0, "creator"),
        Field::new_optional_type::<Cow<'a, BinaryVec>>(1, "ty"),
        Field::new_optional_type::<Cow<'a, Vec<TransactionID>>>(2, "previous_transaction"),
        Field::new_optional_type::<Cow<'a, HashMapAsn1<BinaryVec, BinaryVec>>>(3, "context"),
        Field::new_optional_type::<Cow<'a, BinaryVec>>(4, "payload"),
    ]);
}

/// A type that holds the fields for "external" transactions, ie custom transactions that can be
/// used in other systems but still adhere to the rules of the Stamp protocol. For more into, see
/// [`TransactionBody::ExtV1`].
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Ext {
    /// The identity that created this transaction
    creator: IdentityID,
    /// The optional transaction type. Can be used to segment different transactions
    /// from each other in mixed networks.
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
    previous_transactions: Vec<TransactionID>,
    /// The context allows setting arbitrary, binary key-value pairs in this transaction
    /// which can be used for policy matching, routing in p2p networks, etc.
    context: HashMapAsn1<BinaryVec, BinaryVec>,
    /// The actual transaction body, serialized however you like.
    payload: BinaryVec,
}

impl Ext {
    /// Create a new `Ext` from *scratch* (!!) using basic household items!!1
    pub fn new(
        creator: IdentityID,
        ty: Option<BinaryVec>,
        previous_transactions: Vec<TransactionID>,
        context: HashMapAsn1<BinaryVec, BinaryVec>,
        payload: BinaryVec,
    ) -> Self {
        Self {
            creator,
            ty,
            previous_transactions,
            context,
            payload,
        }
    }
}

impl<'a> From<ExtSer<'a>> for Ext {
    fn from(value: ExtSer<'a>) -> Self {
        let ExtSer {
            creator,
            ty,
            previous_transactions,
            context,
            payload,
        } = value;
        let previous_transactions = previous_transactions.map(|x| x.into_owned()).unwrap_or_else(|| Vec::new());
        let context = context.map(|x| x.into_owned()).unwrap_or_else(|| HashMapAsn1::default());
        let payload = payload.map(|x| x.into_owned()).unwrap_or_else(|| BinaryVec::from(Vec::new()));
        Self {
            creator: creator.into_owned(),
            ty: ty.map(|x| x.into_owned()),
            previous_transactions,
            context,
            payload,
        }
    }
}

impl<'a> From<&'a Ext> for ExtSer<'a> {
    fn from(value: &'a Ext) -> Self {
        let ty = value.ty().as_ref().map(Cow::Borrowed);
        let previous_transactions = if value.previous_transactions().is_empty() {
            None
        } else {
            Some(Cow::Borrowed(value.previous_transactions()))
        };
        let context = if value.context().is_empty() {
            None
        } else {
            Some(Cow::Borrowed(value.context()))
        };
        let payload = if value.payload().is_empty() {
            None
        } else {
            Some(Cow::Borrowed(value.payload()))
        };
        Self {
            creator: Cow::Borrowed(value.creator()),
            ty,
            previous_transactions,
            context,
            payload,
        }
    }
}

impl AsnType for Ext {
    const TAG: Tag = ExtSer::TAG;
}

impl Encode for Ext {
    fn encode_with_tag_and_constraints<'encoder, E: Encoder<'encoder>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
        identifier: rasn::types::Identifier,
    ) -> std::result::Result<(), E::Error> {
        let ser = ExtSer::from(self);
        ser.encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

impl Decode for Ext {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
    ) -> std::result::Result<Self, D::Error> {
        let ser = ExtSer::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self::from(ser))
    }
}

/// This is all of the possible transactions that can be performed on an
/// identity, including the data they require.
#[derive(Debug, Clone, PrivateParts, AsnType, Encode, Decode, Serialize, Deserialize)]
#[parts(private_data = "PrivateContainer")]
#[rasn(choice)]
pub enum TransactionBody<M: PrivacyMode> {
    /// Create a new identity. The [ID][TransactionID] of this transaction will
    /// be the identity's public ID forever after.
    #[rasn(tag(explicit(0)))]
    CreateIdentityV1 {
        #[rasn(tag(explicit(0)))]
        admin_keys: Vec<AdminKey<M>>,
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
        admin_keys: Option<Vec<AdminKey<M>>>,
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
        admin_key: AdminKey<M>,
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
        spec: ClaimSpec<M>,
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
        stamp_transaction: Box<StampTransaction>,
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
        key: Key<M>,
        #[rasn(tag(explicit(1)))]
        name: String,
        #[rasn(tag(explicit(2)))]
        description: Option<String>,
    },
    /// Edit the name/description of a subkey by its unique name.
    #[rasn(tag(explicit(16)))]
    EditSubkeyV1 {
        #[rasn(tag(explicit(0)))]
        id: KeyID,
        #[rasn(tag(explicit(1)))]
        name: Option<String>,
        #[rasn(tag(explicit(2)))]
        description: Option<Option<String>>,
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
        identity: Identity<Public>,
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
    ExtV1(Ext),
}

impl ReEncrypt for TransactionBody<Full> {
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
            Self::AddSubkeyV1 { key, name, description } => {
                let new_subkey = key.reencrypt(rng, old_master_key, new_master_key)?;
                Self::AddSubkeyV1 {
                    key: new_subkey,
                    name,
                    description,
                }
            }
            Self::EditSubkeyV1 { id, name, description } => Self::EditSubkeyV1 { id, name, description },
            Self::RevokeSubkeyV1 { id, reason, new_name } => Self::RevokeSubkeyV1 { id, reason, new_name },
            Self::DeleteSubkeyV1 { id } => Self::DeleteSubkeyV1 { id },
            Self::PublishV1 { identity } => Self::PublishV1 { identity },
            Self::SignV1 { creator, body_hash } => Self::SignV1 { creator, body_hash },
            Self::ExtV1(ext) => Self::ExtV1(ext),
        };
        Ok(new_self)
    }
}

/// The TransactionID is a [Hash][enum@crate::crypto::base::Hash] of the transaction body
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(delegate)]
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
#[derive(
    Debug, Clone, PrivateParts, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters,
)]
#[parts(private_data = "PrivateContainer")]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct TransactionEntry<M: PrivacyMode> {
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
    body: TransactionBody<M>,
}

impl<M: PrivacyMode> TransactionEntry<M> {
    /// Create a new entry.
    // NOTE: we don't usually do `new()` for generic `<M: PrivacyMode>` or `<Public>` types but
    // this is in service to some DAG rewiring stuff
    pub(crate) fn new<T: Into<Timestamp>>(created: T, previous_transactions: Vec<TransactionID>, body: TransactionBody<M>) -> Self {
        Self {
            created: created.into(),
            previous_transactions,
            body,
        }
    }
}

/// A transaction represents a single change on an identity object. In order to
/// build an identity, all transactions are played in order from start to finish.
///
/// Note that `Transaction` itself *cannot be binary (de)serialized*. Instead, it has to be
/// converted to a [`TransactionContainer`] which can then be saved/sent. We *can* serialize it in
/// plaintext format for display/debug purposes.
#[derive(
    Debug, Clone, PrivateParts, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters,
)]
#[parts(private_data = "PrivateContainer")]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Transaction<M: PrivacyMode> {
    /// This is a hash of the transaction's `entry`
    #[rasn(tag(explicit(0)))]
    id: TransactionID,
    /// This holds our serialized [`TransactionEntry`]
    #[rasn(tag(explicit(1)))]
    entry: TransactionEntry<M>,
    /// The signatures on this transaction's ID.
    #[rasn(tag(explicit(2)))]
    signatures: Vec<MultisigPolicySignature>,
}

impl<M: PrivacyMode> Transaction<M> {
    /// Test if an admin key has signed a set of signatures
    pub(crate) fn is_signed_by_impl(signatures: &[MultisigPolicySignature], admin_key: &AdminKeypair<Public>) -> bool {
        signatures
            .iter()
            .find(|sig| match sig {
                MultisigPolicySignature::Key { key, .. } => key == admin_key,
            })
            .is_some()
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
                        Err(Error::TransactionSignatureInvalid(key.clone(), signature.clone().into()))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Sign this transaction in-place.
    pub fn sign_mut(&mut self, master_key: &SecretKey, admin_key: &AdminKeypair<Full>) -> Result<()> {
        let admin_key_pub: AdminKeypair<Public> = admin_key.clone().into();
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
        Ok(())
    }

    /// Sign this transaction. This consumes the transaction, adds the signature
    /// to the `signatures` list, then returns the new transaction.
    pub fn sign(mut self, master_key: &SecretKey, admin_key: &AdminKeypair<Full>) -> Result<Self> {
        self.sign_mut(master_key, admin_key)?;
        Ok(self)
    }

    /// Determines if this transaction has been signed by a given key.
    pub fn is_signed_by(&self, admin_key: &AdminKeypair<Public>) -> bool {
        Self::is_signed_by_impl(self.signatures(), admin_key)
    }
}

impl<M> Transaction<M>
where
    M: PrivacyMode,
    TransactionEntry<M>: Into<TransactionEntry<Public>>,
{
    // NOTE: my hope was to only implement this for Transaction<Full>, but some of the DAG util
    // stuff needs to be able to create raw entries for public tx as well. oh well.
    /// Create a new Transaction from a [TransactionEntry].
    pub(crate) fn new(entry: TransactionEntry<M>, hash_with: &HashAlgo) -> Result<Self> {
        let serialized = {
            let public: TransactionEntry<Public> = entry.clone().into();
            ser::serialize(&public)?
        };
        // recalculate our tx id based on the actual bytes that will be represented.
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

    /// Verify that the hash on this transaction matches its serialized body.
    pub(crate) fn verify_hash(&self) -> Result<()> {
        let public: TransactionEntry<Public> = self.entry().clone().into();
        let serialized = ser::serialize(&public)?;
        // first verify the transaction's hash.
        let transaction_hash = match self.id().deref() {
            Hash::Blake3(..) => Hash::new_blake3(&serialized[..])?,
        };
        if &transaction_hash != self.id().deref() {
            Err(Error::TransactionIDMismatch(self.id().clone()))?;
        }
        Ok(())
    }

    /// Verify the hash on this transaction matches the transaction entry's hash, and also verify
    /// the signatures of that hash.
    ///
    /// This is useful if you need to validate a transaction is "valid" up until the point where
    /// you need a copy of the full identity (so that the policies can be checked). In other words,
    /// if you need to verify a transaction but don't have all the information you need to run
    /// `Transaction.authorize()` then you can run this as a self-contained way of verification, as
    /// long as you keep in mind that the transaction ultimately needs to be checked against a
    /// built identity (and its contained policies).
    pub fn verify_hash_and_signatures(&self) -> Result<()> {
        self.verify_hash()?;
        self.verify_signatures()?;
        Ok(())
    }

    /// Authorize that this transaction has the signatures needed to match a policy that grants the
    /// actions contained within the transaction.
    ///
    /// By the time we get here, the transaction hash/signatures must have been validated, so we
    /// focus on the policy-based validation.
    pub fn authorize(&self, identity_maybe: Option<&IdentityInstance<M>>) -> Result<()> {
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
                        let identity = IdentityInstance::create(
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
}

impl<M: PrivacyMode + Encode + Decode> SerdeBinary for Transaction<M> {}

impl ReEncrypt for Transaction<Full> {
    /// Reencrypt this transaction.
    fn reencrypt<R: RngCore + CryptoRng>(mut self, rng: &mut R, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let new_body = self.entry().body().clone().reencrypt(rng, old_master_key, new_master_key)?;
        self.entry_mut().set_body(new_body);
        Ok(self)
    }
}

impl<M> DagTamperUtil for Transaction<M>
where
    M: PrivacyMode,
    TransactionEntry<M>: Into<TransactionEntry<Public>>,
{
    type ID = TransactionID;
    type Body = TransactionBody<M>;

    fn create_raw_with_id<T: Into<Timestamp>>(id: Self::ID, created: T, previous_transactions: Vec<Self::ID>, body: Self::Body) -> Self {
        let entry = TransactionEntry::new(created, previous_transactions, body);
        Self {
            id,
            entry,
            signatures: Vec::new(),
        }
    }

    fn create_raw<T: Into<Timestamp>>(
        hash_with: &HashAlgo,
        created: T,
        previous_transactions: Vec<Self::ID>,
        body: Self::Body,
    ) -> Result<Self> {
        let entry = TransactionEntry::new(created, previous_transactions, body);
        Self::new(entry, hash_with)
    }

    fn try_mod_ext_previous_transaction(&mut self, new_ext_previous_transactions: Vec<Self::ID>) -> Result<()> {
        match self.entry_mut().body_mut() {
            TransactionBody::ExtV1(ref mut ext) => {
                ext.set_previous_transactions(new_ext_previous_transactions);
                Ok(())
            }
            _ => Err(Error::TransactionMismatch),
        }
    }
}

impl<M: PrivacyMode> std::cmp::PartialEq for Transaction<M> {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id() && self.signatures() == other.signatures()
    }
}

impl<M: PrivacyMode> std::cmp::Eq for Transaction<M> {}

impl<M: PrivacyMode> std::cmp::PartialOrd for Transaction<M> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<M: PrivacyMode> std::cmp::Ord for Transaction<M> {
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

impl<'a, M: PrivacyMode> From<&'a Transaction<M>> for DagNode<'a, TransactionID, Transaction<M>> {
    fn from(t: &'a Transaction<M>) -> Self {
        DagNode::new(t.id(), t, t.entry().previous_transactions().iter().collect::<Vec<_>>(), t.entry().created())
    }
}

impl SerText for Transaction<Public> {
    fn serialize_text(&self) -> Result<String> {
        // make sure at least the tx id matches before we serialize.
        self.verify_hash()?;
        ser::serialize_text(self)
    }
}

impl DeText for Transaction<Public> {
    fn deserialize_text(ser: &str) -> Result<Self> {
        let des: Self = ser::deserialize_text(ser)?;
        // make sure at least the tx id matches before we deserialize.
        des.verify_hash()?;
        Ok(des)
    }
}

/// Makes it easy to define wrapper transactions
macro_rules! define_wrapper_tx {
    ( $name:ident, $body_type:path ) => {
        impl $name {
            /// Convert this into a [`Transaction`]
            pub fn into_inner(self) -> Transaction<Public> {
                let Self(tx) = self;
                tx
            }
        }

        impl TryFrom<Transaction<Full>> for $name {
            type Error = Error;
            fn try_from(val: Transaction<Full>) -> std::result::Result<Self, Self::Error> {
                if matches!(val.entry().body(), $body_type { .. }) {
                    Ok(Self(val.strip().0))
                } else {
                    Err(Error::TransactionMismatch)
                }
            }
        }

        impl TryFrom<Transaction<Public>> for $name {
            type Error = Error;
            fn try_from(val: Transaction<Public>) -> std::result::Result<Self, Self::Error> {
                if matches!(val.entry().body(), $body_type { .. }) {
                    Ok(Self(val))
                } else {
                    Err(Error::TransactionMismatch)
                }
            }
        }

        impl Deref for $name {
            type Target = Transaction<Public>;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl Encode for $name {
            fn encode_with_tag_and_constraints<'encoder, E: Encoder<'encoder>>(
                &self,
                encoder: &mut E,
                tag: rasn::types::Tag,
                constraints: rasn::types::constraints::Constraints,
                identifier: rasn::types::Identifier,
            ) -> std::result::Result<(), E::Error> {
                self.0.encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
            }
        }

        impl Decode for $name {
            fn decode_with_tag_and_constraints<D: Decoder>(
                decoder: &mut D,
                tag: rasn::types::Tag,
                constraints: rasn::types::constraints::Constraints,
            ) -> std::result::Result<Self, D::Error> {
                let tx = Transaction::<Public>::decode_with_tag_and_constraints(decoder, tag, constraints)?;
                Self::try_from(tx).map_err(|_| rasn::de::Error::no_valid_choice("unexpected TransactionBody variant", rasn::Codec::Der))
            }
        }

        impl SerdeBinary for $name {}
    };
}

/// A wrapper around `MakeStampV1` transactions
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, AsnType, Serialize, Deserialize)]
#[rasn(delegate)]
pub struct StampTransaction(Transaction<Public>);

define_wrapper_tx!(StampTransaction, TransactionBody::MakeStampV1);

impl StampTransaction {
    /// IF (and this is a BIG if...) this is a `MakeStamp` transaction, grab the stamper's
    /// identity ID
    pub fn get_stamper(&self) -> Result<&IdentityID> {
        match self.entry().body() {
            TransactionBody::MakeStampV1 { stamp } => Ok(stamp.stamper()),
            _ => Err(Error::TransactionMismatch),
        }
    }

    /// IF (and this is a BIG if...) this is a `MakeStamp` transaction, grab the stampee's
    /// identity ID
    pub fn get_stampee(&self) -> Result<&IdentityID> {
        match self.entry().body() {
            TransactionBody::MakeStampV1 { stamp } => Ok(stamp.stampee()),
            _ => Err(Error::TransactionMismatch),
        }
    }

    /// Get the claim ID from this stamp
    pub fn get_claim_id(&self) -> Result<&ClaimID> {
        match self.entry().body() {
            TransactionBody::MakeStampV1 { stamp } => Ok(stamp.claim_id()),
            _ => Err(Error::TransactionMismatch),
        }
    }

    /// Get the confidence from this stamp
    pub fn get_confidence(&self) -> Result<&Confidence> {
        match self.entry().body() {
            TransactionBody::MakeStampV1 { stamp } => Ok(stamp.confidence()),
            _ => Err(Error::TransactionMismatch),
        }
    }

    /// Get this stamp's expiration date
    pub fn get_expires(&self) -> Result<&Option<Timestamp>> {
        match self.entry().body() {
            TransactionBody::MakeStampV1 { stamp } => Ok(stamp.expires()),
            _ => Err(Error::TransactionMismatch),
        }
    }
}

/// A wrapper around `Publish` transactions
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, AsnType, Serialize, Deserialize)]
#[rasn(delegate)]
pub struct PublishTransaction(Transaction<Public>);

define_wrapper_tx!(PublishTransaction, TransactionBody::PublishV1);

impl PublishTransaction {
    /// Ensures that this transaction is a publish transaction, verifies it *fully* (as in, runs
    /// [`Transaction::authorize`], and returns the contained [`crate::dag::Transactions`] and
    /// [`crate::identity::Identity`].
    pub fn validate_publish_transaction(&self) -> Result<(Identity<Public>, IdentityInstance<Public>)> {
        // do a verification of the full published identity.
        match self.entry().body() {
            TransactionBody::PublishV1 { identity } => {
                let identity_pub = Identity::<Public>::from(identity.clone());
                let identity = identity_pub.build_identity_instance()?;
                self.authorize(Some(&identity))?;
                Ok((identity_pub, identity))
            }
            _ => Err(Error::TransactionMismatch)?,
        }
    }
}

/// A wrapper around `Sign` transactions
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, AsnType, Serialize, Deserialize)]
#[rasn(delegate)]
pub struct SignTransaction(Transaction<Public>);

define_wrapper_tx!(SignTransaction, TransactionBody::SignV1);

impl SignTransaction {
    /// If this is an Sign transaction, grab the `creator` field.
    pub fn get_creator(&self) -> Result<&IdentityID> {
        match self.entry().body() {
            TransactionBody::SignV1 { ref creator, .. } => Ok(creator),
            _ => Err(Error::TransactionMismatch),
        }
    }

    /// If this is a Sign transaction, grab the `body_hash` field
    pub fn get_body_hash(&self) -> Result<&Hash> {
        match self.entry().body() {
            TransactionBody::SignV1 { ref body_hash, .. } => Ok(body_hash),
            _ => Err(Error::TransactionMismatch),
        }
    }
}

/// A wrapper around `Ext` transactions
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, AsnType, Serialize, Deserialize)]
#[rasn(delegate)]
pub struct ExtTransaction(Transaction<Public>);

define_wrapper_tx!(ExtTransaction, TransactionBody::ExtV1);

impl ExtTransaction {
    pub fn get_ext(&self) -> Result<&Ext> {
        match self.entry().body() {
            TransactionBody::ExtV1(ref ext) => Ok(ext),
            _ => Err(Error::TransactionMismatch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{base::SignKeypair, private::MaybePrivate},
        identity::keychain::RevocationReason,
        policy::{Capability, Context, ContextClaimType, MultisigPolicy, Policy, TransactionBodyType},
        util::{
            ser,
            test::{self, sign_and_push},
        },
    };
    use std::str::FromStr;

    #[test]
    fn trans_create_raw() {
        let body = TransactionBody::<Full>::ExtV1(Ext::new(
            IdentityID::from(TransactionID::from(Hash::new_blake3(b"owwww my head").unwrap())),
            Some(Vec::from(b"/stamp/test/raw").into()),
            vec![TransactionID::from(Hash::new_blake3(b"i like your hat").unwrap())],
            [("create", "raw")].into(),
            Vec::from(b"who's this...Steve?").into(),
        ));
        let trans1 = Transaction::<Full>::create_raw(
            &HashAlgo::Blake3,
            crate::util::Timestamp::from_str("2028-09-30T06:34:22Z").unwrap(),
            vec![TransactionID::from(Hash::new_blake3(b"toot").unwrap())],
            body.clone(),
        )
        .unwrap();
        let trans2 = Transaction::<Full>::create_raw(
            &HashAlgo::Blake3,
            crate::util::Timestamp::from_str("3028-09-30T06:34:22Z").unwrap(),
            vec![TransactionID::from(Hash::new_blake3(b"toot").unwrap())],
            body.clone(),
        )
        .unwrap();
        let trans3 = Transaction::<Full>::create_raw(
            &HashAlgo::Blake3,
            crate::util::Timestamp::from_str("3028-09-30T06:34:22Z").unwrap(),
            vec![TransactionID::from(Hash::new_blake3(b"zing").unwrap())],
            body.clone(),
        )
        .unwrap();
        assert_eq!(format!("{}", trans1.id()), "QV8clS17HVt_Wo4NzHFLWJfbHg86sKHydSZySK2WrCkA");
        assert_eq!(format!("{}", trans2.id()), "2Kxq6FKEO2o1OVM7FYx8JFoGuJwm5UOqOz4mIZzOlRsA");
        assert_eq!(format!("{}", trans3.id()), "mxxmsc1m2hvyQlukGCNliF1MDqME-FGOBr4DYV1fz-MA");
    }

    #[test]
    fn trans_verify_hash_and_signatures() {
        let mut rng = crate::util::test::rng();
        let now = Timestamp::now();
        let (_master_key1, identity1, _admin_key1) = test::create_fake_identity(&mut rng, now.clone());
        let (_master_key2, mut identity2, _admin_key2) = test::create_fake_identity(&mut rng, now.clone());
        identity1.transactions()[0].verify_hash_and_signatures().unwrap();
        *identity2.transactions_mut()[0].signatures_mut() = identity1.transactions()[0].signatures().clone();
        assert!(matches!(
            identity2.transactions()[0].verify_hash_and_signatures(),
            Err(Error::TransactionSignatureInvalid(_, _))
        ));
    }

    #[test]
    fn trans_new_verify() {
        let mut rng = crate::util::test::rng();
        let now = Timestamp::now();
        let (_master_key, identity, admin_key) = test::create_fake_identity(&mut rng, now.clone());
        identity.transactions()[0].authorize(None).unwrap();

        let (_, identity_new, _) = test::create_fake_identity(&mut rng, now.clone());

        let create2 = identity_new.transactions()[0].clone();

        let res = identity.clone().push_transaction(create2);
        assert_eq!(res.err(), Some(Error::DagCreateIdentityOnExistingChain));

        let mut trans2 = identity.transactions()[0].clone();
        trans2.set_id(TransactionID::random());
        assert!(matches!(trans2.authorize(None).err(), Some(Error::TransactionIDMismatch(..))));

        let mut trans3 = identity.transactions()[0].clone();
        let then = Timestamp::from(*now.deref() - chrono::Duration::seconds(2));
        trans3.entry_mut().set_created(then);
        assert!(matches!(trans3.authorize(None).err(), Some(Error::TransactionIDMismatch(..))));

        let mut trans4 = identity.transactions()[0].clone();
        trans4.entry_mut().set_previous_transactions(vec![TransactionID::random()]);
        assert!(matches!(trans4.authorize(None).err(), Some(Error::TransactionIDMismatch(..))));

        let mut trans5 = identity.transactions()[0].clone();
        trans5.entry_mut().set_body(TransactionBody::CreateIdentityV1 {
            admin_keys: vec![admin_key.clone()],
            policies: vec![],
        });
        assert!(matches!(trans5.authorize(None).err(), Some(Error::TransactionIDMismatch(..))));
    }

    #[test]
    fn trans_is_signed_by() {
        let mut rng = crate::util::test::rng();
        let now = Timestamp::now();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, now.clone());
        let admin_key2 = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        assert!(identity.transactions()[0].is_signed_by(&admin_key.key().clone().into()));
        assert!(!identity.transactions()[0].is_signed_by(&admin_key2.clone().into()));
    }

    #[ignore]
    #[test]
    fn trans_validate_publish_transaction() {
        todo!();
    }

    #[ignore]
    #[test]
    fn trans_validate_and_open_publish_transaction() {
        todo!();
    }

    #[test]
    fn trans_serde_binary() {
        let mut rng = crate::util::test::rng();
        let now = Timestamp::now();
        let (_master_key, identity, _admin_key) = test::create_fake_identity(&mut rng, now.clone());
        let trans = identity.transactions()[0].clone();

        let ser = trans.serialize_binary().unwrap();
        let des = Transaction::<Full>::deserialize_binary(ser.as_slice()).unwrap();

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
                    SignKeypair::<Full>::Ed25519 {
                        public: public1,
                        secret: secret1,
                    },
                    SignKeypair::<Full>::Ed25519 {
                        public: public2,
                        secret: secret2,
                    },
                ) => {
                    assert_eq!(public1, public2);
                    let revealed1 = secret1.open($master).unwrap();
                    let revealed2 = secret2.open($master).unwrap();
                    assert_eq!(revealed1.expose_secret(), revealed2.expose_secret());
                }
            }
        };
    }

    #[test]
    fn trans_serde_create_identity_v1() {
        let mut rng = crate::util::test::rng_seeded(b"jimmy don't");
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let admin_key1 = AdminKey::<Full>::new(
            AdminKeypair::from(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap()),
            "alpha",
            Some("hello there"),
        );
        let admin_key2 = AdminKey::<Full>::new(
            AdminKeypair::from(SignKeypair::<Full>::new_ed25519(&mut rng, &master_key).unwrap()),
            "name-claim",
            None,
        );
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
        let trans = TransactionBody::<Full>::CreateIdentityV1 {
            admin_keys: vec![admin_key1.clone(), admin_key2.clone()],
            policies: vec![policy1, policy2],
        };
        let ser_check = ser::base64_encode(&ser::serialize(&trans).unwrap());
        let ser_expected = "oIIB6jCCAeagggE2MIIBMjCBm6CBgKB-MHygIgQg4loRcTZf5eL0Y-p7h-hj1tXjIX8Y-YnyLpasHHkvXG2hVjBUoBygGgQYhYT1DQfbmT03ESR0qrnGFSb8M0TCQRDkoTQEMvqNpjiXHb4Zi8uOlFTOEBynpbJdJVMMHn7cIGV7NAHfjLGw4ga_tYiFvaYLTXKg7_C2oQcMBWFscGhhog0MC2hlbGxvIHRoZXJlMIGRoIGAoH4wfKAiBCCXKHZ1MpTVGlCB_NV0XsZEIqsTLGO56ImQ0VKDC7FRWKFWMFSgHKAaBBh-0_h990YsagfFsXkZdgVkYNIHMdaFjCuhNAQyMj2w_cHLl2kVEgkr6-F2LJVukXNi60HbnA2q2PTGeZz6JLC-XHTUjMFJRA24Z-m5R4qhDAwKbmFtZS1jbGFpbaGBqTCBpjBHoAYwBKACBQChPaI7MDmgAwIBAaEyMDCgLjAsoSqgKDAmoCIEIOJaEXE2X-Xi9GPqe4foY9bV4yF_GPmJ8i6WrBx5L1xtoQAwW6AaMBihFjAUoAYwBKgCBQChCqAIMAapBKECBQChPaI7MDmgAwIBAaEyMDCgLjAsoSqgKDAmoCIEIJcodnUylNUaUIH81XRexkQiqxMsY7noiZDRUoMLsVFYoQA";
        assert_eq!(ser_check, ser_expected);
        let trans_deser: TransactionBody<Full> = ser::deserialize(&ser::base64_decode(&ser_expected).unwrap()).unwrap();

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
        let admin_key1 = AdminKey::<Full>::new(
            AdminKeypair::from(SignKeypair::<Full>::new_ed25519(&mut rng, &master_key).unwrap()),
            "alpha",
            Some("hello there"),
        );
        let admin_key2 = AdminKey::<Full>::new(
            AdminKeypair::from(SignKeypair::<Full>::new_ed25519(&mut rng, &master_key).unwrap()),
            "name-claim",
            None,
        );
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
        let trans1 = TransactionBody::<Full>::ResetIdentityV1 {
            admin_keys: Some(vec![admin_key1.clone(), admin_key2.clone()]),
            policies: Some(vec![policy1, policy2]),
        };
        let trans2 = TransactionBody::<Full>::ResetIdentityV1 {
            admin_keys: None,
            policies: None,
        };
        let ser1_check = ser::base64_encode(&ser::serialize(&trans1).unwrap());
        let ser2_check = ser::base64_encode(&ser::serialize(&trans2).unwrap());
        let ser1_expected = "oYIB6jCCAeagggE2MIIBMjCBm6CBgKB-MHygIgQg4loRcTZf5eL0Y-p7h-hj1tXjIX8Y-YnyLpasHHkvXG2hVjBUoBygGgQYhYT1DQfbmT03ESR0qrnGFSb8M0TCQRDkoTQEMvqNpjiXHb4Zi8uOlFTOEBynpbJdJVMMHn7cIGV7NAHfjLGw4ga_tYiFvaYLTXKg7_C2oQcMBWFscGhhog0MC2hlbGxvIHRoZXJlMIGRoIGAoH4wfKAiBCCXKHZ1MpTVGlCB_NV0XsZEIqsTLGO56ImQ0VKDC7FRWKFWMFSgHKAaBBh-0_h990YsagfFsXkZdgVkYNIHMdaFjCuhNAQyMj2w_cHLl2kVEgkr6-F2LJVukXNi60HbnA2q2PTGeZz6JLC-XHTUjMFJRA24Z-m5R4qhDAwKbmFtZS1jbGFpbaGBqTCBpjBHoAYwBKACBQChPaI7MDmgAwIBAaEyMDCgLjAsoSqgKDAmoCIEIOJaEXE2X-Xi9GPqe4foY9bV4yF_GPmJ8i6WrBx5L1xtoQAwW6AaMBihFjAUoAYwBKgCBQChCqAIMAapBKECBQChPaI7MDmgAwIBAaEyMDCgLjAsoSqgKDAmoCIEIJcodnUylNUaUIH81XRexkQiqxMsY7noiZDRUoMLsVFYoQA";
        let ser2_expected = "oQIwAA";
        assert_eq!(ser1_check, ser1_expected);
        assert_eq!(ser2_check, ser2_expected);
        let trans_deser1: TransactionBody<Full> = ser::deserialize(&ser::base64_decode(&ser1_expected).unwrap()).unwrap();
        let trans_deser2: TransactionBody<Full> = ser::deserialize(&ser::base64_decode(&ser2_expected).unwrap()).unwrap();

        match (trans1, trans_deser1) {
            (
                TransactionBody::<Full>::ResetIdentityV1 {
                    admin_keys: Some(admin_keys1),
                    policies: policies1,
                },
                TransactionBody::<Full>::ResetIdentityV1 {
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
                TransactionBody::<Full>::ResetIdentityV1 {
                    admin_keys: admin_keys1,
                    policies: policies1,
                },
                TransactionBody::<Full>::ResetIdentityV1 {
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
        let admin_key1 = AdminKey::<Full>::new(
            AdminKeypair::from(SignKeypair::<Full>::new_ed25519(&mut rng, &master_key).unwrap()),
            "alpha",
            Some("been watching you for quite a while now"),
        );
        let trans1 = TransactionBody::<Full>::AddAdminKeyV1 { admin_key: admin_key1 };
        let ser1_check = ser::serialize(&trans1).unwrap();
        let ser1 = [
            163, 129, 192, 48, 129, 189, 160, 129, 186, 48, 129, 183, 160, 129, 128, 160, 126, 48, 124, 160, 34, 4, 32, 226, 90, 17, 113,
            54, 95, 229, 226, 244, 99, 234, 123, 135, 232, 99, 214, 213, 227, 33, 127, 24, 249, 137, 242, 46, 150, 172, 28, 121, 47, 92,
            109, 161, 86, 48, 84, 160, 28, 160, 26, 4, 24, 133, 132, 245, 13, 7, 219, 153, 61, 55, 17, 36, 116, 170, 185, 198, 21, 38, 252,
            51, 68, 194, 65, 16, 228, 161, 52, 4, 50, 250, 141, 166, 56, 151, 29, 190, 25, 139, 203, 142, 148, 84, 206, 16, 28, 167, 165,
            178, 93, 37, 83, 12, 30, 126, 220, 32, 101, 123, 52, 1, 223, 140, 177, 176, 226, 6, 191, 181, 136, 133, 189, 166, 11, 77, 114,
            160, 239, 240, 182, 161, 7, 12, 5, 97, 108, 112, 104, 97, 162, 41, 12, 39, 98, 101, 101, 110, 32, 119, 97, 116, 99, 104, 105,
            110, 103, 32, 121, 111, 117, 32, 102, 111, 114, 32, 113, 117, 105, 116, 101, 32, 97, 32, 119, 104, 105, 108, 101, 32, 110, 111,
            119,
        ];
        assert_eq!(ser1_check, ser1);
        let trans_deser1: TransactionBody<Full> = ser::deserialize(&ser1).unwrap();

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
        let admin_key1 = AdminKey::<Full>::new(
            AdminKeypair::from(SignKeypair::<Full>::new_ed25519(&mut rng, &master_key).unwrap()),
            "admin/edit",
            Some("i like your hat"),
        );
        let trans1 = TransactionBody::<Full>::EditAdminKeyV1 {
            id: admin_key1.key_id(),
            name: Some("admin/all".to_string()),
            description: Some(None),
        };
        let trans2 = TransactionBody::<Full>::EditAdminKeyV1 {
            id: admin_key1.key_id(),
            name: Some("admin/all".to_string()),
            description: Some(Some("good times".to_string())), // great trucks
        };
        let ser1 = ser::base64_encode(ser::serialize(&trans1).unwrap());
        let ser2 = ser::base64_encode(ser::serialize(&trans2).unwrap());
        let ser1_expected = "pD8wPaAsoCqgKDAmoCIEIOJaEXE2X-Xi9GPqe4foY9bV4yF_GPmJ8i6WrBx5L1xtoQChCwwJYWRtaW4vYWxsogA";
        let ser2_expected = "pEswSaAsoCqgKDAmoCIEIOJaEXE2X-Xi9GPqe4foY9bV4yF_GPmJ8i6WrBx5L1xtoQChCwwJYWRtaW4vYWxsogwMCmdvb2QgdGltZXM";
        assert_eq!(ser1, ser1_expected);
        assert_eq!(ser2, ser2_expected);
        let trans_deser1: TransactionBody<Full> = ser::deserialize(&ser::base64_decode(&ser1_expected).unwrap()).unwrap();
        let trans_deser2: TransactionBody<Full> = ser::deserialize(&ser::base64_decode(&ser2_expected).unwrap()).unwrap();

        match (trans1, trans_deser1) {
            (
                TransactionBody::<Full>::EditAdminKeyV1 {
                    id: id1,
                    name: name1,
                    description: desc1,
                },
                TransactionBody::<Full>::EditAdminKeyV1 {
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
                TransactionBody::<Full>::EditAdminKeyV1 {
                    id: id1,
                    name: name1,
                    description: desc1,
                },
                TransactionBody::<Full>::EditAdminKeyV1 {
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
        let admin_key1 = AdminKey::<Full>::new(
            AdminKeypair::from(SignKeypair::<Full>::new_ed25519(&mut rng, &master_key).unwrap()),
            "admin/edit",
            Some("i like your hat"),
        );
        let trans1 = TransactionBody::<Full>::RevokeAdminKeyV1 {
            id: admin_key1.key_id(),
            reason: RevocationReason::Compromised,
            new_name: Some("admin/no-more".to_string()),
        };
        let ser1 = ser::base64_encode(&ser::serialize(&trans1).unwrap());
        let ser1_expected = "pUcwRaAsoCqgKDAmoCIEIOJaEXE2X-Xi9GPqe4foY9bV4yF_GPmJ8i6WrBx5L1xtoQChBKICBQCiDwwNYWRtaW4vbm8tbW9yZQ";
        assert_eq!(ser1, ser1_expected);
        let trans_deser1: TransactionBody<Full> = ser::deserialize(&ser::base64_decode(&ser1_expected).unwrap()).unwrap();

        match (trans1, trans_deser1) {
            (
                TransactionBody::<Full>::RevokeAdminKeyV1 {
                    id: id1,
                    reason: reason1,
                    new_name: name1,
                },
                TransactionBody::<Full>::RevokeAdminKeyV1 {
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
        let admin_key1 = AdminKey::<Full>::new(
            AdminKeypair::from(SignKeypair::<Full>::new_ed25519(&mut rng, &master_key).unwrap()),
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
        let trans1 = TransactionBody::<Full>::AddPolicyV1 { policy: policy1 };
        let ser1 = [
            166, 97, 48, 95, 160, 93, 48, 91, 160, 26, 48, 24, 161, 22, 48, 20, 160, 6, 48, 4, 168, 2, 5, 0, 161, 10, 160, 8, 48, 6, 169,
            4, 161, 2, 5, 0, 161, 61, 162, 59, 48, 57, 160, 3, 2, 1, 1, 161, 50, 48, 48, 160, 46, 48, 44, 161, 42, 160, 40, 48, 38, 160,
            34, 4, 32, 226, 90, 17, 113, 54, 95, 229, 226, 244, 99, 234, 123, 135, 232, 99, 214, 213, 227, 33, 127, 24, 249, 137, 242, 46,
            150, 172, 28, 121, 47, 92, 109, 161, 0,
        ];
        let trans_deser1: TransactionBody<Full> = ser::deserialize(&ser1).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::<Full>::AddPolicyV1 { policy: policy1 }, TransactionBody::<Full>::AddPolicyV1 { policy: policy2 }) => {
                assert_eq!(policy1, policy2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_serde_delete_policy_v1() {
        let policy_id1 = PolicyID::from(TransactionID::from(Hash::new_blake3(&[55, 66, 42, 17, 0, 9]).unwrap()));
        let trans1 = TransactionBody::<Full>::DeletePolicyV1 { id: policy_id1 };
        let ser1 = ser::base64_encode(&ser::serialize(&trans1).unwrap());
        let ser1_expected = "pygwJqAkoCIEIAI098BWKTXsjkgH0WgKEzfTbiOUwWrJT7Zk424dr4Ci";
        assert_eq!(ser1, ser1_expected);
        let trans_deser1: TransactionBody<Full> = ser::deserialize(&ser::base64_decode(&ser1).unwrap()).unwrap();

        match (trans1, trans_deser1) {
            (TransactionBody::<Full>::DeletePolicyV1 { id: id1 }, TransactionBody::<Full>::DeletePolicyV1 { id: id2 }) => {
                assert_eq!(id1, id2);
            }
            _ => panic!("Unmatched serialization"),
        }
    }

    #[test]
    fn trans_serde_make_claim_v1() {
        let mut rng = crate::util::test::rng_seeded(b"jimmy don't");
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let claim1 = ClaimSpec::<Full>::Identity(MaybePrivate::<Full, _>::new_public(IdentityID::from(TransactionID::from(
            Hash::new_blake3(&[1, 2, 3, 4, 5]).unwrap(),
        ))));
        let claim2 = ClaimSpec::<Full>::Extension {
            key: BinaryVec::from(vec![2, 4, 6, 8]),
            value: MaybePrivate::<Full, _>::new_private_verifiable(&mut rng, &master_key, BinaryVec::from(vec![9, 9, 9])).unwrap(),
        };
        let trans1 = TransactionBody::<Full>::MakeClaimV1 {
            spec: claim1,
            name: Some("my-old-id".to_string()),
        };
        let trans2 = TransactionBody::<Full>::MakeClaimV1 { spec: claim2, name: None };
        let ser1 = ser::base64_encode(ser::serialize(&trans1).unwrap());
        let ser2 = ser::base64_encode(ser::serialize(&trans2).unwrap());
        let ser1_expected = "qDkwN6AooCagJKAiBCACT2fAQlo9wC-69Yy5PeUTLj11xRn6oLraIUkdiMlwV6ELDAlteS1vbGQtaWQ";
        let ser2_expected = "qIGoMIGloIGirIGfMIGcoAYEBAIEBgihgZGhgY4wgYugJKAiBCDYJg4_BmkY1_eAitBkMLmTiU86i9gBMNoqV_xB3emvWqFjMGGgHKAaBBiFhPUNB9uZPTcRJHSqucYVJvwzRMJBEOShQQQ_zoBe5Rpw58iPfiAyZfLeGhrXNBuGC4dYyPuf0PAn1W4QVKy1x9cTZ1XY6o1LhNYHBlMdJhcPt07vZNkEsHqV";
        assert_eq!(ser1, ser1_expected);
        assert_eq!(ser2, ser2_expected);
        let trans_deser1: TransactionBody<Full> = ser::deserialize(&ser::base64_decode(&ser1).unwrap()).unwrap();
        let trans_deser2: TransactionBody<Full> = ser::deserialize(&ser::base64_decode(&ser2).unwrap()).unwrap();

        match (trans1, trans_deser1) {
            (
                TransactionBody::<Full>::MakeClaimV1 { spec: spec1, name: name1 },
                TransactionBody::<Full>::MakeClaimV1 { spec: spec2, name: name2 },
            ) => {
                match (spec1, spec2) {
                    (
                        ClaimSpec::<Full>::Identity(MaybePrivate::<Full, _>::Public(pub1)),
                        ClaimSpec::<Full>::Identity(MaybePrivate::<Full, _>::Public(pub2)),
                    ) => {
                        assert_eq!(pub1, pub2);
                    }
                    _ => panic!("Unmatched spec"),
                }
                assert_eq!(name1, name2);
            }
            _ => panic!("Unmatched serialization"),
        }
        match (trans2, trans_deser2) {
            (
                TransactionBody::<Full>::MakeClaimV1 { spec: spec1, name: name1 },
                TransactionBody::<Full>::MakeClaimV1 { spec: spec2, name: name2 },
            ) => {
                match (spec1, spec2) {
                    (
                        ClaimSpec::<Full>::Extension { key: key1, value: priv1 },
                        ClaimSpec::<Full>::Extension { key: key2, value: priv2 },
                    ) => {
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

    #[test]
    fn trans_serde_ext_v1() {
        let mut rng = test::rng_seeded(b"no thank you");
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::from_str("2024-01-01T00:00:06Z").unwrap());
        {
            let ext = TransactionBody::<Full>::ExtV1(Ext::new(
                IdentityID::from(TransactionID::from(Hash::new_blake3(b"yo").unwrap())),
                Some(Vec::from(b"/stamp/net/test").into()),
                vec![TransactionID::from(Hash::new_blake3(b"hi").unwrap())],
                [("name", "barry")].into(),
                BinaryVec::from(Vec::from(b"test")),
            ));
            assert_eq!(
                ser::base64_encode(&ser::serialize(&ext).unwrap()),
                "tYGDMIGAoCSgIgQgwWb4dQqCoZN_Y1MljXNCIBRURkp0EogBhinDzKy8rVuhEQQPL3N0YW1wL25ldC90ZXN0oiYwJKAiBCCFBS6aqxtntmItlKCEQbCf1besph7jYEFtcN5dpn2GyqMVMBMwEaAGBARuYW1loQcEBWJhcnJ5pAYEBHRlc3Q",
            );
        }
        {
            let ext = TransactionBody::<Full>::ExtV1(Ext::new(
                IdentityID::from(TransactionID::from(Hash::new_blake3(b"yo").unwrap())),
                Some(Vec::from(b"/stamp/net/test").into()),
                vec![TransactionID::from(Hash::new_blake3(b"hi").unwrap())],
                [(b"name", b"barry")].into(),
                BinaryVec::from(Vec::from(b"test")),
            ));
            assert_eq!(
                ser::base64_encode(&ser::serialize(&ext).unwrap()),
                "tYGDMIGAoCSgIgQgwWb4dQqCoZN_Y1MljXNCIBRURkp0EogBhinDzKy8rVuhEQQPL3N0YW1wL25ldC90ZXN0oiYwJKAiBCCFBS6aqxtntmItlKCEQbCf1besph7jYEFtcN5dpn2GyqMVMBMwEaAGBARuYW1loQcEBWJhcnJ5pAYEBHRlc3Q",
            );
        }
        {
            let ext = TransactionBody::<Full>::ExtV1(Ext::new(
                IdentityID::from(TransactionID::from(Hash::new_blake3(b"yo").unwrap())),
                None,
                vec![TransactionID::from(Hash::new_blake3(b"hi").unwrap())],
                [("", ""); 0].into(),
                BinaryVec::from(Vec::from(b"test")),
            ));
            assert_eq!(
                ser::base64_encode(&ser::serialize(&ext).unwrap()),
                "tVgwVqAkoCIEIMFm-HUKgqGTf2NTJY1zQiAUVEZKdBKIAYYpw8ysvK1boiYwJKAiBCCFBS6aqxtntmItlKCEQbCf1besph7jYEFtcN5dpn2GyqQGBAR0ZXN0",
            );
        }
        {
            let ext = TransactionBody::<Full>::ExtV1(Ext::new(
                IdentityID::from(TransactionID::from(Hash::new_blake3(b"yo").unwrap())),
                None,
                vec![],
                [("name", "barry"); 0].into(),
                BinaryVec::from(Vec::new()),
            ));
            assert_eq!(
                ser::base64_encode(&ser::serialize(&ext).unwrap()),
                "tSgwJqAkoCIEIMFm-HUKgqGTf2NTJY1zQiAUVEZKdBKIAYYpw8ysvK1b"
            );
        }
        {
            let mut ext = identity
                .ext(
                    &HashAlgo::Blake3,
                    Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
                    vec![TransactionID::from(Hash::new_blake3(b"gffft").unwrap())],
                    Some(Vec::from(b"/stamp/net/packet/v1").into()),
                    Some([(b"topic_id", &[12u8; 32])]),
                    Vec::from(b"hi everyone how's it going?").into(),
                )
                .unwrap();
            ext.sign_mut(&master_key, &admin_key).unwrap();
            let ser = ser::base64_encode(&ser::serialize(&ext).unwrap());
            let ser_expected = "MIIBnKAkoCIEID_MQFeHDzdOBmrsaS8u3I3NZxNo4YOjW2b9xMnXHlPUoYH5MIH2oAgCBgGbdtqoAKEmMCSgIgQgbz8J8TzquNt-_7axKHqQnM43rY2UFNOpg4Lw80TO4oSigcG1gb4wgbugJKAiBCBvPwnxPOq4237_trEoepCczjetjZQU06mDgvDzRM7ihKEWBBQvc3RhbXAvbmV0L3BhY2tldC92MaImMCSgIgQgBoUxL_1rgBdcG8K_FqvgQHRuSRhBM6yEFdXE5q6kh76jNDAyMDCgCgQIdG9waWNfaWShIgQgDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAykHQQbaGkgZXZlcnlvbmUgaG93J3MgaXQgZ29pbmc_ongwdqB0MHKgKqAoMCagIgQgb-Hl_fWltlU1yhhQHc_miEqrDQ09Vi414wjHr_rhlkOhAKFEoEIEQBk6cOzAZyTa2pMc6bs6lIAMseQpNxmMDN1xRARhrZHPxXSEZAP5v7F1zbjqqyjjT9tUFXk7s96TFxL1mplKfAU";
            assert_eq!(ser, ser_expected);
            {
                let ext_des: ExtTransaction = ser::deserialize(&ser::base64_decode(&ser_expected).unwrap()).unwrap();
                ext_des.verify_hash_and_signatures().unwrap();
                assert_eq!(ext.id(), ext_des.id());
            }
        }
        {
            let mut ext = identity
                .ext(
                    &HashAlgo::Blake3,
                    Timestamp::from_str("2026-01-01T00:00:00Z").unwrap(),
                    vec![],
                    None,
                    None::<HashMapAsn1<_, _>>,
                    Vec::from(b"").into(),
                )
                .unwrap();
            ext.sign_mut(&master_key, &admin_key).unwrap();
            let ser = ser::base64_encode(&ser::serialize(&ext).unwrap());
            let ser_expected = "MIIBAqAkoCIEIKDQJSMFcGMRK-U13wdlXyb3eGbpv4snbtP9dx9VfASDoWAwXqAIAgYBm3baqAChJjAkoCIEIG8_CfE86rjbfv-2sSh6kJzON62NlBTTqYOC8PNEzuKEoiq1KDAmoCSgIgQgbz8J8TzquNt-_7axKHqQnM43rY2UFNOpg4Lw80TO4oSieDB2oHQwcqAqoCgwJqAiBCBv4eX99aW2VTXKGFAdz-aISqsNDT1WLjXjCMev-uGWQ6EAoUSgQgRA3HnvFcFpcdGhxkLl3tYFVNTbd-a5l0Equf_hRUlwWFUgQ7u_k7hwItSLCuWEJD554Smx_Tvz35TPULYimVtjAQ";
            assert_eq!(ser, ser_expected);
            {
                let ext_des: ExtTransaction = ser::deserialize(&ser::base64_decode(&ser_expected).unwrap()).unwrap();
                ext_des.verify_hash_and_signatures().unwrap();
                assert_eq!(ext.id(), ext_des.id());
            }
        }
    }

    #[test]
    fn trans_deser_publish_yaml() {
        let mut rng = test::rng_seeded(b"hi there!");
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::from_str("2024-01-01T00:00:06Z").unwrap());
        let now = Timestamp::from_str("2068-12-31T23:59:59.999Z").unwrap();
        let identity = sign_and_push! { &master_key, &admin_key, identity.clone(),
            [ make_claim, now.clone(), ClaimSpec::Name(MaybePrivate::new_public("Butch".into())), None::<String> ]
            [ make_claim, now.clone(), ClaimSpec::Address(MaybePrivate::new_private_verifiable(&mut rng, &master_key, "1234 Cat Pooop Enjoyer Blvd, Giardiaville, CA".to_string()).unwrap()), None::<String> ]
        };

        let publish_tx = identity.publish(&HashAlgo::Blake3, now.clone()).unwrap();
        let publish_tx_pub: Transaction<Public> = publish_tx.into();
        let publish_tx_sertxt = publish_tx_pub.serialize_text().unwrap();
        let publish_tx_expected = r#"---
id:
  Blake3: D9m-Yf-23dykPCmur2GoCt8SrGNnMuYyvFJPExwHYME
entry:
  created: "2068-12-31T23:59:59.999Z"
  previous_transactions:
    - Blake3: SnH9F9D03XhwlsxyPvTibOFVc86aNGepSieUh7D7lh8
  body:
    PublishV1:
      identity:
        transactions:
          - id:
              Blake3: NFTxOYhpoN0_ZVD6E54hZXsZJ5yZAZEy3N2HB1aXeMI
            entry:
              created: "2024-01-01T00:00:06Z"
              previous_transactions: []
              body:
                CreateIdentityV1:
                  admin_keys:
                    - key:
                        Ed25519:
                          public: BdMMToyKyC_o3mTwqMCjabfw3DgzAiiggD51bKLZBBU
                          secret:
                            sealed: ~
                      name: Alpha
                      description: ~
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
                                  Ed25519:
                                    public: BdMMToyKyC_o3mTwqMCjabfw3DgzAiiggD51bKLZBBU
                                    secret:
                                      sealed: ~
            signatures:
              - Key:
                  key:
                    Ed25519:
                      public: BdMMToyKyC_o3mTwqMCjabfw3DgzAiiggD51bKLZBBU
                      secret:
                        sealed: ~
                  signature:
                    Ed25519: VEpfVwC-NmmGr9HpTyjOW4SYxbBpJmXPAq8_t47YmmIa5RsamIlCQ9qbFlIAT1YcD1IIEf-OKL7tLCHf3qWFCA
          - id:
              Blake3: dHGUIK_qUwnqA0g_jr7GXdNM8xchCEnF3icR7yrWKMA
            entry:
              created: "2068-12-31T23:59:59.999Z"
              previous_transactions:
                - Blake3: NFTxOYhpoN0_ZVD6E54hZXsZJ5yZAZEy3N2HB1aXeMI
              body:
                MakeClaimV1:
                  spec:
                    Name:
                      Public: Butch
                  name: ~
            signatures:
              - Key:
                  key:
                    Ed25519:
                      public: BdMMToyKyC_o3mTwqMCjabfw3DgzAiiggD51bKLZBBU
                      secret:
                        sealed: ~
                  signature:
                    Ed25519: fF9mKpMRqQgwclPdsf9I0r8Uu2k6oBGSxL5ppAKjehQM0gilhtjPa9Fc-7ebZfWVt2RA-yGMKiZWmbSzXqA8Dg
          - id:
              Blake3: SnH9F9D03XhwlsxyPvTibOFVc86aNGepSieUh7D7lh8
            entry:
              created: "2068-12-31T23:59:59.999Z"
              previous_transactions:
                - Blake3: dHGUIK_qUwnqA0g_jr7GXdNM8xchCEnF3icR7yrWKMA
              body:
                MakeClaimV1:
                  spec:
                    Address:
                      PrivateVerifiable:
                        hmac:
                          Blake3: 3e_KLNBgoDpsne6q1SH9dgwRhXDv9PMG4oLBy2KVlus
                        data:
                          sealed: ~
                  name: ~
            signatures:
              - Key:
                  key:
                    Ed25519:
                      public: BdMMToyKyC_o3mTwqMCjabfw3DgzAiiggD51bKLZBBU
                      secret:
                        sealed: ~
                  signature:
                    Ed25519: aPyx0OUdOSKRauuVToC-46JO9FWvvzXtxnur0kYtMZiaqM1-UHjUFnc4v9kVWfM0NgxjhDfcJnvKTnOQBqhyAg
signatures: []
"#;
        assert_eq!(publish_tx_sertxt, publish_tx_expected);

        let transaction = Transaction::deserialize_text(&publish_tx_sertxt).unwrap();
        match transaction.entry().body() {
            TransactionBody::PublishV1 {
                identity: identity_serialized,
            } => {
                let identity_des: Identity<Public> = identity_serialized.clone().try_into().unwrap();
                let identity_instance_des = identity_des.build_identity_instance().unwrap();
                let expected_identity_id = identity.identity_id().unwrap();
                assert_eq!(format!("{}", identity_instance_des.id()), format!("{}", expected_identity_id));
                let ids = identity_des
                    .transactions()
                    .iter()
                    .map(|x| format!("{}", x.id()))
                    .collect::<Vec<_>>();
                let ids_expected = identity.transactions().iter().map(|x| format!("{}", x.id())).collect::<Vec<_>>();
                assert_eq!(ids, ids_expected);
            }
            _ => panic!("bad dates"),
        }

        let publish_tx_tampered = r#"---
id:
  Blake3: D9m-Yf-23dykPCmur2GoCt8SrGNnMuYyvFJPExwHYME
entry:
  created: "2068-12-31T23:59:59.999Z"
  previous_transactions:
    - Blake3: SnH9F9D03XhwlsxyPvTibOFVc86aNGepSieUh7D7lh8
  body:
    PublishV1:
      identity:
        transactions:
          - id:
              Blake3: NFTxOYhpoN0_ZVD6E54hZXsZJ5yZAZEy3N2HB1aXeMI
            entry:
              created: "2024-01-01T00:00:06Z"
              previous_transactions: []
              body:
                CreateIdentityV1:
                  admin_keys:
                    - key:
                        Ed25519:
                          public: BdMMToyKyC_o3mTwqMCjabfw3DgzAiiggD51bKLZBBU
                          secret:
                            sealed: ~
                      name: Alpha
                      description: ~
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
                                  Ed25519:
                                    public: BdMMToyKyC_o3mTwqMCjabfw3DgzAiiggD51bKLZBBU
                                    secret:
                                      sealed: ~
            signatures:
              - Key:
                  key:
                    Ed25519:
                      public: BdMMToyKyC_o3mTwqMCjabfw3DgzAiiggD51bKLZBBU
                      secret:
                        sealed: ~
                  signature:
                    Ed25519: VEpfVwC-NmmGr9HpTyjOW4SYxbBpJmXPAq8_t47YmmIa5RsamIlCQ9qbFlIAT1YcD1IIEf-OKL7tLCHf3qWFCA
          - id:
              Blake3: dHGUIK_qUwnqA0g_jr7GXdNM8xchCEnF3icR7yrWKMA
            entry:
              created: "2068-12-31T23:59:59.999Z"
              previous_transactions:
                - Blake3: NFTxOYhpoN0_ZVD6E54hZXsZJ5yZAZEy3N2HB1aXeMI
              body:
                MakeClaimV1:
                  spec:
                    Name:
                      Public: Dotty
                  name: ~
            signatures:
              - Key:
                  key:
                    Ed25519:
                      public: BdMMToyKyC_o3mTwqMCjabfw3DgzAiiggD51bKLZBBU
                      secret:
                        sealed: ~
                  signature:
                    Ed25519: fF9mKpMRqQgwclPdsf9I0r8Uu2k6oBGSxL5ppAKjehQM0gilhtjPa9Fc-7ebZfWVt2RA-yGMKiZWmbSzXqA8Dg
          - id:
              Blake3: SnH9F9D03XhwlsxyPvTibOFVc86aNGepSieUh7D7lh8
            entry:
              created: "2068-12-31T23:59:59.999Z"
              previous_transactions:
                - Blake3: dHGUIK_qUwnqA0g_jr7GXdNM8xchCEnF3icR7yrWKMA
              body:
                MakeClaimV1:
                  spec:
                    Address:
                      PrivateVerifiable:
                        hmac:
                          Blake3: 3e_KLNBgoDpsne6q1SH9dgwRhXDv9PMG4oLBy2KVlus
                        data:
                          sealed: ~
                  name: ~
            signatures:
              - Key:
                  key:
                    Ed25519:
                      public: BdMMToyKyC_o3mTwqMCjabfw3DgzAiiggD51bKLZBBU
                      secret:
                        sealed: ~
                  signature:
                    Ed25519: aPyx0OUdOSKRauuVToC-46JO9FWvvzXtxnur0kYtMZiaqM1-UHjUFnc4v9kVWfM0NgxjhDfcJnvKTnOQBqhyAg
signatures: []
"#;
        assert!(matches!(Transaction::deserialize_text(publish_tx_tampered), Err(Error::TransactionIDMismatch(_))));
    }

    #[test]
    fn trans_deser_stamp_base64() {
        let mut rng = test::rng_seeded(b"no thank you");
        let (master_key_claimer, identity_claimer, admin_key_claimer) =
            test::create_fake_identity(&mut rng, Timestamp::from_str("2026-01-01T00:00:06Z").unwrap());
        let (_master_key_stamper, identity_stamper, _admin_key_stamper) =
            test::create_fake_identity(&mut rng, Timestamp::from_str("2025-01-01T00:00:06Z").unwrap());
        let now = Timestamp::from_str("2068-12-31T23:59:59.999Z").unwrap();
        let identity_claimer = sign_and_push! { &master_key_claimer, &admin_key_claimer, identity_claimer.clone(),
            [ make_claim, now.clone(), ClaimSpec::Name(MaybePrivate::new_public("Butch".into())), None::<String> ]
            [ make_claim, now.clone(), ClaimSpec::Address(MaybePrivate::new_private_verifiable(&mut rng, &master_key_claimer, "1234 Cat Pooop Enjoyer Blvd, Giardiaville, CA".to_string()).unwrap()), None::<String> ]
        };
        let identity_claimer_instance = identity_claimer.build_identity_instance().unwrap();

        let stamp_entry = StampEntry::new(
            identity_stamper.identity_id().unwrap(),
            identity_claimer.identity_id().unwrap(),
            identity_claimer_instance.claims().last().unwrap().id().clone(),
            Confidence::High,
            None::<Timestamp>,
        );

        let stamp_tx: StampTransaction = identity_stamper
            .make_stamp(&HashAlgo::Blake3, now.clone(), stamp_entry.clone())
            .unwrap()
            .try_into()
            .unwrap();

        let stamp_tx_ser = ser::base64_encode(&stamp_tx.serialize_binary().unwrap());
        let stamp_tx_ser_expected = r#"MIHloCSgIgQgQEMevTKpkYArXNBLW7VryEtb1sINSdSGQVKkEHG7i3ShgbgwgbWgCAIGAtdqQv__oSYwJKAiBCC3QcBZVj3YTSdYn2AXhQVmkXYX2MI4m5xDhP_M297g06KBgKt-MHygejB4oCSgIgQgt0HAWVY92E0nWJ9gF4UFZpF2F9jCOJucQ4T_zNve4NOhJKAiBCD8WDdcfSmSW1aFZdogHQMofjaN5eM2rXyy0itR1J4vEKIkoCIEIGnU-WaP2k9nsAXXuGorD3QyizZviKDgFRccCB70Kp9mowSjAgUAogIwAA"#;
        assert_eq!(stamp_tx_ser, stamp_tx_ser_expected);

        let stamp_tx_des = StampTransaction::deserialize_binary(&ser::base64_decode(stamp_tx_ser).unwrap()).unwrap();
        match stamp_tx_des.entry().body() {
            TransactionBody::MakeStampV1 { stamp: stamp_entry_des } => {
                assert_eq!(&stamp_entry, stamp_entry_des);
            }
            _ => panic!("bad dates"),
        }
    }
}
