//! The policy system provides a method for assigning [capabilities][Capability] (permissions) to
//! combinations of [admin keys][AdminKey] ([multisig][MultisigPolicy]). This extends beyond simple M-of-N and allows
//! arbitrary combinations of signatures to satisfy the requirements for a particular transaction.
//!
//! In combination with capabilties, this allows an identity to be managed
//! not just by keys it owns, but by trusted third parties as well.
//!
//! Capabilities assigned to keys via a policy can be restricted using ["contexts"][Context] which are pieces
//! of information from the given transaction, such as a particular ID, string name, etc. For
//! instance, it's possible to allow the ability to edit *a particular key by id*, or to manage
//! *any resource with a certain name*. This allows additively creating fine-grained permissions
//! and assigning them to groups of admin keys.

use crate::{
    crypto::base::{Hash, KeyID},
    dag::{Transaction, TransactionBody, TransactionID},
    error::{Error, Result},
    identity::{
        claim::ClaimSpec,
        identity::{Identity, IdentityID},
        keychain::{AdminKey, AdminKeyID, AdminKeypair, AdminKeypairPublic, AdminKeypairSignature},
    },
    util::ser::{self, BinaryVec},
};
use getset;
use glob::Pattern;
use rasn::{AsnType, Decode, Encode};
use serde_derive::{Deserialize, Serialize};
use std::ops::Deref;

object_id! {
    /// A unique identifier for capability policies.
    PolicyID
}

/// Defines a context specifier specific to various claim types
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum TransactionBodyType {
    #[rasn(tag(explicit(0)))]
    CreateIdentityV1,
    #[rasn(tag(explicit(1)))]
    ResetIdentityV1,
    #[rasn(tag(explicit(2)))]
    AddAdminKeyV1,
    #[rasn(tag(explicit(3)))]
    EditAdminKeyV1,
    #[rasn(tag(explicit(4)))]
    RevokeAdminKeyV1,
    #[rasn(tag(explicit(5)))]
    AddPolicyV1,
    #[rasn(tag(explicit(6)))]
    DeletePolicyV1,
    #[rasn(tag(explicit(7)))]
    MakeClaimV1,
    #[rasn(tag(explicit(8)))]
    EditClaimV1,
    #[rasn(tag(explicit(9)))]
    DeleteClaimV1,
    #[rasn(tag(explicit(10)))]
    MakeStampV1,
    #[rasn(tag(explicit(11)))]
    RevokeStampV1,
    #[rasn(tag(explicit(12)))]
    AcceptStampV1,
    #[rasn(tag(explicit(13)))]
    DeleteStampV1,
    #[rasn(tag(explicit(14)))]
    AddSubkeyV1,
    #[rasn(tag(explicit(15)))]
    EditSubkeyV1,
    #[rasn(tag(explicit(16)))]
    RevokeSubkeyV1,
    #[rasn(tag(explicit(17)))]
    DeleteSubkeyV1,
    #[rasn(tag(explicit(18)))]
    PublishV1,
    #[rasn(tag(explicit(19)))]
    SignV1,
    #[rasn(tag(explicit(20)))]
    ExtV1,
}

impl From<&TransactionBody> for TransactionBodyType {
    // Not sure if this is actually useful as much as it keeps ContextClaimType
    // in sync with ClaimSpec
    fn from(body: &TransactionBody) -> Self {
        match *body {
            TransactionBody::CreateIdentityV1 { .. } => Self::CreateIdentityV1,
            TransactionBody::ResetIdentityV1 { .. } => Self::ResetIdentityV1,
            TransactionBody::AddAdminKeyV1 { .. } => Self::AddAdminKeyV1,
            TransactionBody::EditAdminKeyV1 { .. } => Self::EditAdminKeyV1,
            TransactionBody::RevokeAdminKeyV1 { .. } => Self::RevokeAdminKeyV1,
            TransactionBody::AddPolicyV1 { .. } => Self::AddPolicyV1,
            TransactionBody::DeletePolicyV1 { .. } => Self::DeletePolicyV1,
            TransactionBody::MakeClaimV1 { .. } => Self::MakeClaimV1,
            TransactionBody::EditClaimV1 { .. } => Self::EditClaimV1,
            TransactionBody::DeleteClaimV1 { .. } => Self::DeleteClaimV1,
            TransactionBody::MakeStampV1 { .. } => Self::MakeStampV1,
            TransactionBody::RevokeStampV1 { .. } => Self::RevokeStampV1,
            TransactionBody::AcceptStampV1 { .. } => Self::AcceptStampV1,
            TransactionBody::DeleteStampV1 { .. } => Self::DeleteStampV1,
            TransactionBody::AddSubkeyV1 { .. } => Self::AddSubkeyV1,
            TransactionBody::EditSubkeyV1 { .. } => Self::EditSubkeyV1,
            TransactionBody::RevokeSubkeyV1 { .. } => Self::RevokeSubkeyV1,
            TransactionBody::DeleteSubkeyV1 { .. } => Self::DeleteSubkeyV1,
            TransactionBody::PublishV1 { .. } => Self::PublishV1,
            TransactionBody::SignV1 { .. } => Self::SignV1,
            TransactionBody::ExtV1 { .. } => Self::ExtV1,
        }
    }
}

/// Defines a context specifier specific to various claim types
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum ContextClaimType {
    #[rasn(tag(explicit(0)))]
    Identity,
    #[rasn(tag(explicit(1)))]
    Name,
    #[rasn(tag(explicit(2)))]
    Birthday,
    #[rasn(tag(explicit(3)))]
    Email,
    #[rasn(tag(explicit(4)))]
    Photo,
    #[rasn(tag(explicit(5)))]
    Pgp,
    #[rasn(tag(explicit(6)))]
    Domain,
    #[rasn(tag(explicit(7)))]
    Url,
    #[rasn(tag(explicit(8)))]
    Address,
    #[rasn(tag(explicit(9)))]
    PhoneNumber,
    #[rasn(tag(explicit(10)))]
    Relation,
    #[rasn(tag(explicit(11)))]
    RelationExtension,
    #[rasn(tag(explicit(12)))]
    Extension,
}

impl From<&ClaimSpec> for ContextClaimType {
    // Not sure if this is actually useful as much as it keeps ContextClaimType
    // in sync with ClaimSpec
    fn from(spec: &ClaimSpec) -> Self {
        match *spec {
            ClaimSpec::Identity(..) => Self::Identity,
            ClaimSpec::Name(..) => Self::Name,
            ClaimSpec::Birthday(..) => Self::Birthday,
            ClaimSpec::Email(..) => Self::Email,
            ClaimSpec::Photo(..) => Self::Photo,
            ClaimSpec::Pgp(..) => Self::Pgp,
            ClaimSpec::Domain(..) => Self::Domain,
            ClaimSpec::Url(..) => Self::Url,
            ClaimSpec::Address(..) => Self::Address,
            ClaimSpec::PhoneNumber(..) => Self::PhoneNumber,
            ClaimSpec::Relation(..) => Self::Relation,
            ClaimSpec::RelationExtension(..) => Self::RelationExtension,
            ClaimSpec::Extension { .. } => Self::Extension,
        }
    }
}

/// Defines a context under which a transaction can be performed.
///
/// This is a recursive structure which allows defining arbitrary combinations
/// of contexts.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Context {
    /// Represents a context in which ALL given contexts must match (an AND gate)
    #[rasn(tag(explicit(0)))]
    All(Vec<Context>),
    /// Represents a context in which one or more of the given contexts must
    /// match (an OR gate).
    #[rasn(tag(explicit(1)))]
    Any(Vec<Context>),
    /// Represents a context in which the sub-contexts *must not match* (a NOT gate).
    #[rasn(tag(explicit(2)))]
    Not(Box<Context>),
    /// Allows an action in any context (ie, context is irrelevant).
    #[rasn(tag(explicit(3)))]
    Permissive,
    /// Allows an action in the context of an identity that has this exact ID.
    #[rasn(tag(explicit(4)))]
    IdentityID(IdentityID),
    /// Allows an action in the context of items with an exact ID match (for
    /// instance, a claim that was created by transaction 0x03fd913)
    #[rasn(tag(explicit(5)))]
    ObjectID(TransactionID),
    /// Allows an action on an admin key with the given ID.
    AdminKeyID(AdminKeyID),
    /// Allows an action on a key with the given ID. This can match Admin keys, although
    /// using the `AdminKeyID` variant might be more useful.
    #[rasn(tag(explicit(6)))]
    KeyID(KeyID),
    /// Allows an action in the context of items with an exact name match. This
    /// can be an admin key, subkey, claim, or capability policy generally.
    #[rasn(tag(explicit(7)))]
    Name(String),
    /// Allows an action in the context of items with name matching a glob pattern.
    /// For instance `email-keys/*`
    #[rasn(tag(explicit(8)))]
    NameGlob(String),
    /// Allows actions on claims where the claim is of a particular type
    #[rasn(tag(explicit(9)))]
    ClaimType(ContextClaimType),
    /// Allows actions on external transactions of a certain type
    #[rasn(tag(explicit(10)))]
    ExtType(BinaryVec),
    /// Allows actions on external transactions of a certain type by prefix.
    ///
    /// So if we have a type of `turtl/op/v2` and a `Context::ExtTypePrefix("turtl/op/")`
    /// that would match.
    ///
    /// ```
    /// use stamp_core::policy::Context;
    /// let context = Context::ExtTypePrefix(b"turtl/".to_vec().into());
    ///
    /// // The dude abides.
    /// context.test(&Context::ExtType(b"turtl/op/v1".to_vec().into())).unwrap();
    /// context.test(&Context::ExtType(b"turtl/checkpoint/v1".to_vec().into())).unwrap();
    /// // This will not stand, man.
    /// context.test(&Context::ExtType(b"/turtl/op/v1".to_vec().into())).unwrap_err();
    /// ```
    #[rasn(tag(explicit(11)))]
    ExtTypePrefix(BinaryVec),
    /// Allows actions on external transactions containing a key/value pair
    #[rasn(tag(explicit(12)))]
    ExtContext {
        #[rasn(tag(explicit(0)))]
        key: BinaryVec,
        #[rasn(tag(explicit(1)))]
        val: BinaryVec,
    },
    /// Allows actions on external transactions matching a key and *prefix* of a value.
    ///
    /// For instance:
    ///
    /// ```
    /// use stamp_core::policy::Context;
    /// use stamp_core::util::{BinaryVec};
    /// let context = Context::ExtContextPrefix {
    ///     key: BinaryVec::from(vec![1, 2, 3]),
    ///     val: BinaryVec::from(vec![4, 5, 6]),
    /// };
    ///
    /// // The dude abides.
    /// context.test(
    ///     &Context::ExtContext {
    ///         key: BinaryVec::from(vec![1, 2, 3]),
    ///         val: BinaryVec::from(vec![4, 5, 6, 42, 83, 129])
    ///     }
    /// ).unwrap();
    ///
    /// // This will not stand, man.
    /// context.test(
    ///     &Context::ExtContext {
    ///         key: BinaryVec::from(vec![3, 2, 1]),
    ///         val: BinaryVec::from(vec![4, 5, 6, 42, 83, 129])
    ///     }
    /// ).unwrap_err();
    /// context.test(
    ///     &Context::ExtContext {
    ///         key: BinaryVec::from(vec![1, 2, 3, 4]),
    ///         val: BinaryVec::from(vec![4, 5, 6])
    ///     }
    /// ).unwrap_err();
    /// context.test(
    ///     &Context::ExtContext {
    ///         key: BinaryVec::from(vec![1, 2, 3]),
    ///         val: BinaryVec::from(vec![4, 5, 7])
    ///     }
    /// ).unwrap_err();
    /// ```
    ///
    /// As you can see, the *value* is matched via prefix, but the key must be an
    /// exact match. Or else.
    #[rasn(tag(explicit(13)))]
    ExtContextPrefix {
        #[rasn(tag(explicit(0)))]
        key: BinaryVec,
        #[rasn(tag(explicit(1)))]
        val: BinaryVec,
    },
}

impl Context {
    /// Takes a transaction and returns all the contexts it covers.
    pub(crate) fn contexts_from_transaction_body(transaction_body: &TransactionBody, identity: &Identity) -> Vec<Self> {
        let mut contexts = Vec::new();
        match transaction_body {
            TransactionBody::CreateIdentityV1 { .. } => {}
            TransactionBody::ResetIdentityV1 { .. } => {}
            TransactionBody::AddAdminKeyV1 { admin_key } => {
                contexts.push(Self::AdminKeyID(admin_key.key_id()));
                contexts.push(Self::KeyID(admin_key.key_id().into()));
                contexts.push(Self::Name(admin_key.name().clone()));
            }
            TransactionBody::EditAdminKeyV1 { id, .. } => {
                if let Some(admin_key) = identity.keychain().admin_key_by_keyid(id) {
                    contexts.push(Self::Name(admin_key.name().clone()));
                }
                contexts.push(Self::AdminKeyID(id.clone()));
                contexts.push(Self::KeyID(id.clone().into()));
            }
            TransactionBody::RevokeAdminKeyV1 { id, .. } => {
                if let Some(admin_key) = identity.keychain().admin_key_by_keyid(id) {
                    contexts.push(Self::Name(admin_key.name().clone()));
                }
                contexts.push(Self::AdminKeyID(id.clone()));
                contexts.push(Self::KeyID(id.clone().into()));
            }
            TransactionBody::AddPolicyV1 { .. } => {}
            TransactionBody::DeletePolicyV1 { id } => {
                contexts.push(Self::ObjectID(id.deref().clone()));
            }
            TransactionBody::MakeClaimV1 { spec, name } => {
                contexts.push(Self::ClaimType(ContextClaimType::from(spec)));
                if let Some(name) = name {
                    contexts.push(Self::Name(name.clone()));
                }
            }
            TransactionBody::EditClaimV1 { claim_id, .. } => {
                contexts.push(Self::ObjectID(claim_id.deref().clone()));
                // TODO: look up the claim and grab its name (#38)
            }
            TransactionBody::DeleteClaimV1 { claim_id } => {
                contexts.push(Self::ObjectID(claim_id.deref().clone()));
                // TODO: look up the claim and grab its name (#38)
            }
            TransactionBody::MakeStampV1 { stamp } => {
                contexts.push(Self::ObjectID(stamp.claim_id().deref().clone()));
                contexts.push(Self::IdentityID(stamp.stampee().clone()));
            }
            TransactionBody::RevokeStampV1 { stamp_id, .. } => {
                contexts.push(Self::ObjectID(stamp_id.deref().clone()));

                let stamp_maybe = identity.find_claim_stamp_by_id(stamp_id);
                if let Some(stamp) = stamp_maybe {
                    contexts.push(Self::IdentityID(stamp.entry().stampee().clone()));
                    contexts.push(Self::ObjectID(stamp.entry().claim_id().deref().clone()));
                }
            }
            TransactionBody::AcceptStampV1 { stamp_transaction } => {
                if let TransactionBody::MakeStampV1 { stamp } = stamp_transaction.entry().body() {
                    contexts.push(Self::ObjectID(stamp.claim_id().deref().clone()));
                    contexts.push(Self::IdentityID(stamp.stamper().clone()));
                }
            }
            TransactionBody::DeleteStampV1 { stamp_id } => {
                let stamp_maybe = identity.find_claim_stamp_by_id(stamp_id);
                if let Some(stamp) = stamp_maybe {
                    contexts.push(Self::ObjectID(stamp.id().deref().clone()));
                    contexts.push(Self::ObjectID(stamp.entry().claim_id().deref().clone()));
                    contexts.push(Self::IdentityID(stamp.entry().stamper().clone()));
                }
            }
            TransactionBody::AddSubkeyV1 { key, name, .. } => {
                contexts.push(Self::Name(name.clone()));
                contexts.push(Self::KeyID(key.key_id()));
            }
            TransactionBody::EditSubkeyV1 { id, .. } => {
                contexts.push(Self::KeyID(id.clone()));
                if let Some(subkey) = identity.keychain().subkey_by_keyid(id) {
                    contexts.push(Self::Name(subkey.name().clone()));
                }
            }
            TransactionBody::RevokeSubkeyV1 { id, .. } => {
                contexts.push(Self::KeyID(id.clone()));
                if let Some(subkey) = identity.keychain().subkey_by_keyid(id) {
                    contexts.push(Self::Name(subkey.name().clone()));
                }
            }
            TransactionBody::DeleteSubkeyV1 { id } => {
                contexts.push(Self::KeyID(id.clone()));
                if let Some(subkey) = identity.keychain().subkey_by_keyid(id) {
                    contexts.push(Self::Name(subkey.name().clone()));
                }
            }
            TransactionBody::PublishV1 { .. } => {}
            TransactionBody::SignV1 { .. } => {}
            TransactionBody::ExtV1 { ty, context, .. } => {
                if let Some(t) = ty.as_ref() {
                    contexts.push(Self::ExtType(t.clone()));
                }
                if let Some(exists) = context.as_ref() {
                    for (k, v) in exists.iter() {
                        contexts.push(Self::ExtContext {
                            key: k.clone(),
                            val: v.clone(),
                        });
                    }
                }
            }
        }
        contexts
    }

    /// Make sure the given context matches the current one
    pub fn test(&self, against: &Context) -> Result<()> {
        macro_rules! search_context {
            ($matches:ident, $context1:expr, $contexts2:expr, $against:expr) => {
                for context2 in $contexts2 {
                    let mut to_match = context2;
                    // cannot recurse on the `against` context
                    if matches!(context2, Context::Any(..) | Context::All(..) | Context::Not(..)) {
                        break;
                    }
                    // allows recursion
                    if matches!($context1, Context::Any(..) | Context::All(..) | Context::Not(..)) {
                        to_match = $against;
                    }
                    if $context1.test(to_match).is_ok() {
                        $matches = true;
                        break;
                    }
                }
            };
        }
        let test = match (self, against) {
            (Self::All(contexts1), Self::Any(contexts2)) => {
                let mut retval = true;
                for context1 in contexts1 {
                    let mut matches = false;
                    search_context! { matches, context1, contexts2, against }
                    if !matches {
                        retval = false;
                        break;
                    }
                }
                retval
            }
            (Self::Any(contexts1), Self::Any(contexts2)) => {
                let mut retval = false;
                for context1 in contexts1 {
                    let mut matches = false;
                    search_context! { matches, context1, contexts2, against }
                    if matches {
                        retval = true;
                        break;
                    }
                }
                retval
            }
            (Self::Not(context1), Self::Any(contexts2)) => {
                let mut matches = false;
                search_context! { matches, context1.as_ref(), contexts2, against }
                !matches
            }
            (Self::Permissive, _) => true,
            (_, Self::Any(contexts)) => {
                let mut retval = false;
                for context in contexts {
                    if self.test(context).is_ok() {
                        retval = true;
                        break;
                    }
                }
                retval
            }
            (Self::IdentityID(id1), Self::IdentityID(id2)) => id1 == id2,
            (Self::ObjectID(id1), Self::ObjectID(id2)) => id1 == id2,
            (Self::AdminKeyID(id1), Self::AdminKeyID(id2)) => id1 == id2,
            (Self::KeyID(id1), Self::KeyID(id2)) => id1 == id2,
            (Self::Name(name1), Self::Name(name2)) => name1 == name2,
            (Self::NameGlob(glob1), Self::Name(name2)) => {
                let glob = Pattern::new(glob1)?;
                glob.matches(name2)
            }
            (Self::ClaimType(ty1), Self::ClaimType(ty2)) => ty1 == ty2,
            (Self::ExtType(ty1), Self::ExtType(ty2)) => ty1 == ty2,
            (Self::ExtTypePrefix(p1), Self::ExtType(ty2)) => ty2.starts_with(p1),
            (Self::ExtContext { key: c1k, val: c1v }, Self::ExtContext { key: c2k, val: c2v }) => c1k == c2k && c1v == c2v,
            (
                Self::ExtContextPrefix {
                    key: prefix_key,
                    val: prefix_val,
                },
                Self::ExtContext {
                    key: context_key,
                    val: context_val,
                },
            ) => context_key == prefix_key && context_val.starts_with(prefix_val.deref()),
            _ => false,
        };
        if test {
            Ok(())
        } else {
            Err(Error::PolicyContextMismatch)
        }
    }
}

/// Defines an action that can be taken on an identity. Effectively, this is the
/// ability to group transactions (as defined by [`TransactionBody`]) within
/// certain contexts (such as "manage subkeys if the name matches the glob
/// pattern 'dogecoin/*'").
///
/// Capabilities do not control read access to data as this can only realistically
/// be done through key management.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Capability {
    /// A capability that allows all actions
    #[rasn(tag(explicit(0)))]
    Permissive,
    /// The ability to perform a transaction in a given context. Allows specifying
    /// multiple transaction body types, of which *ANY* can match (an OR gate).
    #[rasn(tag(explicit(1)))]
    Transaction {
        #[rasn(tag(explicit(0)))]
        body_type: Vec<TransactionBodyType>,
        #[rasn(tag(explicit(1)))]
        context: Context,
    },
}

impl Capability {
    pub(crate) fn test(&self, against: &Capability) -> Result<()> {
        match self {
            // allow anything
            Self::Permissive => Ok(()),
            // check transactions and their stupid context
            Self::Transaction { body_type, context } => match against {
                Self::Transaction {
                    body_type: against_body_type,
                    context: against_context,
                } => {
                    if against_body_type.len() != 1 {
                        Err(Error::PolicyCapabilityMismatch)?;
                    }
                    if body_type.contains(&against_body_type[0]) {
                        context.test(against_context)
                    } else {
                        Err(Error::PolicyCapabilityMismatch)
                    }
                }
                _ => Err(Error::PolicyCapabilityMismatch),
            },
        }
    }
}

/// A policy participant. Currently this is just an [Admin][AdminKeypair] public key
/// but could be expanded later on to allow other participant types.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Participant {
    /// This participant is a specific key, and policy signatures must come from
    /// this exact key.
    #[rasn(tag(explicit(0)))]
    Key {
        /// Lets us know who this key belongs to, ie "Rick"
        #[rasn(tag(explicit(0)))]
        name: Option<String>,
        /// The public key
        #[rasn(tag(explicit(1)))]
        key: AdminKeypairPublic,
    },
}

impl From<AdminKeypairPublic> for Participant {
    fn from(admin_pubkey: AdminKeypairPublic) -> Self {
        Participant::Key {
            name: None,
            key: admin_pubkey,
        }
    }
}

impl From<AdminKeypair> for Participant {
    fn from(admin_keypair: AdminKeypair) -> Self {
        Participant::Key {
            name: None,
            key: admin_keypair.into(),
        }
    }
}

impl From<AdminKey> for Participant {
    fn from(admin_key: AdminKey) -> Self {
        let AdminKey { key: admin_keypair, .. } = admin_key;
        admin_keypair.into()
    }
}

/// A signature on a policy transaction. Currently only supports direct signatures
/// from admin keys, but could allow expanding to other signature methods.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum MultisigPolicySignature {
    /// A signature on a transaction from a specific key, generally one that's
    /// listed as a [Participant::Key] in the policy.
    #[rasn(tag(explicit(0)))]
    Key {
        /// The key the signature came from
        #[rasn(tag(explicit(0)))]
        key: AdminKeypairPublic,
        /// The signature
        #[rasn(tag(explicit(1)))]
        signature: AdminKeypairSignature,
    },
}

/// A recursive structure that defines the conditions under which a multisig
/// policy can be satisfied. Allows expressing arbitrary combinations of
/// signatures.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum MultisigPolicy {
    /// All of the given conditions must be met.
    #[rasn(tag(explicit(0)))]
    All(Vec<MultisigPolicy>),
    /// Any of the given conditions can be met.
    #[rasn(tag(explicit(1)))]
    Any(Vec<MultisigPolicy>),
    /// Of the given public keys, N many must produce a valid signature in order
    /// for the policy to be ratified.
    #[rasn(tag(explicit(2)))]
    MOfN {
        /// Must have at least this many signatures.
        #[rasn(tag(explicit(0)))]
        must_have: u16,
        /// The keys we're listing as identity recovery keys.
        #[rasn(tag(explicit(1)))]
        participants: Vec<Participant>,
    },
}

impl MultisigPolicy {
    /// Tests whether the given signatures match the current policy. KEEP IN MIND
    /// that the signatures *must* be validated before we get here. We're simply
    /// testing that the signatures are from keys that satisfy the policy: WE DO
    /// NOT VALIDATE THE SIGNATURES.
    pub(crate) fn test(&self, signatures: &[MultisigPolicySignature]) -> Result<()> {
        match self {
            Self::All(policies) => {
                policies.iter().map(|p| p.test(signatures)).collect::<Result<Vec<_>>>()?;
            }
            Self::Any(policies) => {
                policies
                    .iter()
                    .find(|p| p.test(signatures).is_ok())
                    .ok_or(Error::MultisigPolicyConditionMismatch)?;
            }
            Self::MOfN { must_have, participants } => {
                let has = participants
                    .iter()
                    .filter_map(|participant| {
                        for sig in signatures {
                            match (participant, sig) {
                                (Participant::Key { key: ref pubkey, .. }, MultisigPolicySignature::Key { key, .. }) => {
                                    // NOTE: all signatures have already been validated
                                    // upstreeaaaaam so all we need to do is verify that
                                    // the participant's key matches the signing key.
                                    if pubkey == key {
                                        return Some(());
                                    }
                                }
                            }
                        }
                        None
                    })
                    .count();
                if &(has as u16) < must_have {
                    Err(Error::MultisigPolicyConditionMismatch)?;
                }
            }
        }
        Ok(())
    }
}

/// Matches a set of [Capabilities][Capability] to a [multisig policy][MultisigPolicy],
/// making it so the policy must be fulfilled in order to perform those capabilities.
#[derive(
    Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters,
)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Policy {
    /// The capabilities (or actions) this policy can access. These are permissive,
    /// and combined via OR.
    #[rasn(tag(explicit(0)))]
    capabilities: Vec<Capability>,
    /// The signature policy defining which keys are required to perform the
    /// specified capabilities
    #[rasn(tag(explicit(1)))]
    multisig_policy: MultisigPolicy,
}

impl Policy {
    /// Create a new `Policy`
    pub fn new(capabilities: Vec<Capability>, multisig_policy: MultisigPolicy) -> Self {
        Self {
            capabilities,
            multisig_policy,
        }
    }

    /// Determine if this particular `Policy` allows performing the
    /// action `capability`.
    pub fn can(&self, capability: &Capability) -> bool {
        self.capabilities().iter().any(|c| c.test(capability).is_ok())
    }

    /// Determine if this particular `Policy` allows performing the
    /// action `capability`, and also checks the transaction's signatures against the policy
    /// to make sure we have the signatures we need to perform this action (although
    /// this function does not validate transactions, that needs to happen higher up).
    pub(crate) fn validate_transaction(&self, transaction: &Transaction, contexts: &[Context]) -> Result<()> {
        // don't check the signature validity here. just check that we have the signatures
        // needed to satisfy the policy. signature checks happen higher level.
        self.multisig_policy().test(transaction.signatures())?;
        let transaction_capability = Capability::Transaction {
            body_type: vec![transaction.entry().body().into()],
            context: Context::Any(Vec::from(contexts)),
        };
        if !self.can(&transaction_capability) {
            Err(Error::PolicyCapabilityMismatch)?;
        }
        Ok(())
    }
}

/// A container that assigns a unique ID to a capability policy.
#[derive(
    Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters,
)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct PolicyContainer {
    /// The ID of this capability policy.
    #[rasn(tag(explicit(0)))]
    id: PolicyID,
    /// The actual capability policy
    #[rasn(tag(explicit(1)))]
    policy: Policy,
}

impl PolicyContainer {
    /// Create a new container
    pub fn new(id: PolicyID, policy: Policy) -> Self {
        Self { id, policy }
    }

    /// Generates a `PolicyID` given a transaction id and the policy's position (index) in that
    /// transaction.
    pub fn gen_id(transaction_id: &TransactionID, idx: usize) -> Result<PolicyID> {
        #[derive(AsnType, Encode)]
        struct PolicyContainerSer<'a> {
            #[rasn(tag(explicit(0)))]
            transaction_id: &'a TransactionID,
            #[rasn(tag(explicit(1)))]
            idx: usize,
        }

        let ser_struct = PolicyContainerSer { transaction_id, idx };
        let serialized = ser::serialize(&ser_struct)?;
        let hashed = Hash::new_blake3(&serialized[..])?;
        Ok(PolicyID(TransactionID::from(hashed)))
    }

    /// Creates a `PolicyContainer` from a `Policy` and its index in the transaction
    pub fn from_policy_transaction(transaction_id: &TransactionID, idx: usize, policy: Policy) -> Result<Self> {
        let id = Self::gen_id(transaction_id, idx)?;
        Ok(PolicyContainer { id, policy })
    }
}

impl Deref for PolicyContainer {
    type Target = Policy;
    fn deref(&self) -> &Self::Target {
        self.policy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{
            base::{HashAlgo, SecretKey},
            private::MaybePrivate,
        },
        identity::keychain::{AdminKey, AdminKeypair, ExtendKeypair},
        util::{self, test::sign_and_push, Timestamp, Url},
    };

    #[test]
    fn context_test() {
        let combos = vec![
            Context::IdentityID(IdentityID::random()),
            Context::ObjectID(TransactionID::random()),
            Context::AdminKeyID(KeyID::random_sign().into()),
            Context::KeyID(KeyID::random_sign()),
            Context::Name("frothy".into()),
            Context::NameGlob("GANDALFFFF-*".into()),
            Context::ClaimType(ContextClaimType::Email),
            Context::ExtType(BinaryVec::from(Vec::from("order-create".as_bytes()))),
            Context::ExtContext {
                key: BinaryVec::from(Vec::from("department".as_bytes())),
                val: BinaryVec::from(Vec::from("inventory/receiving".as_bytes())),
            },
        ];

        for round1 in combos.iter() {
            // FIGHT
            for round2 in combos.iter() {
                if matches!((round1, round2), (Context::NameGlob(_), Context::Name(_))) {
                    continue;
                } else if round1 == round2 && !matches!(round1, Context::NameGlob(_)) {
                    match round1.test(round2) {
                        Ok(_) => {}
                        Err(e) => {
                            panic!("Test failed comparing {:?} to {:?}: {:?}", round1, round2, e)
                        }
                    }
                } else {
                    assert_eq!(round1.test(round2), Err(Error::PolicyContextMismatch));
                }
            }
        }

        let con1 = Context::Permissive;
        con1.test(&Context::All(vec![])).unwrap();
        con1.test(&Context::Any(vec![])).unwrap();
        con1.test(&Context::Permissive).unwrap();
        for round1 in combos.iter() {
            con1.test(round1).unwrap();
        }

        let conglob1 = Context::NameGlob("policies/purchasing/*".into());
        conglob1.test(&Context::Name("policies/purchasing/inventory".into())).unwrap();
        conglob1.test(&Context::Name("policies/purchasing/shipping".into())).unwrap();
        assert_eq!(
            conglob1.test(&Context::Name("policies/marketing/inventory".into())),
            Err(Error::PolicyContextMismatch)
        );

        let conglob2 = Context::NameGlob("*/purchasing/*".into());
        conglob2.test(&Context::Name("policies/purchasing/inventory".into())).unwrap();
        conglob2.test(&Context::Name("actions/purchasing/shipping".into())).unwrap();
        assert_eq!(
            conglob2.test(&Context::NameGlob("policies/purchasing/inventory".into())),
            Err(Error::PolicyContextMismatch)
        );
        assert_eq!(
            conglob2.test(&Context::Name("policies/marketing/inventory".into())),
            Err(Error::PolicyContextMismatch)
        );

        let typeprefix = Context::ExtTypePrefix(b"turtl/op/".to_vec().into());
        typeprefix.test(&Context::ExtType(b"turtl/op/".to_vec().into())).unwrap();
        typeprefix.test(&Context::ExtType(b"turtl/op/v1".to_vec().into())).unwrap();
        assert_eq!(
            typeprefix.test(&Context::ExtType(b"turtl/checkpoint/v1".to_vec().into())),
            Err(Error::PolicyContextMismatch),
        );
        assert_eq!(
            typeprefix.test(&Context::ExtType(b"/turtl/op/v1".to_vec().into())),
            Err(Error::PolicyContextMismatch),
        );
        assert_eq!(
            typeprefix.test(&Context::ExtTypePrefix(b"turtl/op/v1".to_vec().into())),
            Err(Error::PolicyContextMismatch),
        );

        let conextprefix = Context::ExtContextPrefix {
            key: Vec::from("department".as_bytes()).into(),
            val: Vec::from("inventory/".as_bytes()).into(),
        };
        conextprefix
            .test(&Context::ExtContext {
                key: Vec::from("department".as_bytes()).into(),
                val: Vec::from("inventory/".as_bytes()).into(),
            })
            .unwrap();
        conextprefix
            .test(&Context::ExtContext {
                key: Vec::from("department".as_bytes()).into(),
                val: Vec::from("inventory/orders".as_bytes()).into(),
            })
            .unwrap();
        conextprefix
            .test(&Context::ExtContext {
                key: Vec::from("department".as_bytes()).into(),
                val: Vec::from("inventory/widgets/incoming".as_bytes()).into(),
            })
            .unwrap();
        assert_eq!(
            conextprefix.test(&Context::ExtContextPrefix {
                key: Vec::from("department".as_bytes()).into(),
                val: Vec::from("inventory/".as_bytes()).into(),
            }),
            Err(Error::PolicyContextMismatch)
        );
        assert_eq!(
            conextprefix.test(&Context::ExtContext {
                key: Vec::from("repartment".as_bytes()).into(),
                val: Vec::from("inventory/".as_bytes()).into(),
            }),
            Err(Error::PolicyContextMismatch)
        );
        assert_eq!(
            conextprefix.test(&Context::ExtContext {
                key: Vec::from("department".as_bytes()).into(),
                val: Vec::from("zing/".as_bytes()).into(),
            }),
            Err(Error::PolicyContextMismatch)
        );

        let con2 = Context::All(vec![Context::Name("timmy".into())]);
        for round1 in combos.iter() {
            assert_eq!(con2.test(round1), Err(Error::PolicyContextMismatch));
        }

        let con3 = Context::Any(vec![Context::Name("timmy".into())]);
        for round1 in combos.iter() {
            assert_eq!(con3.test(round1), Err(Error::PolicyContextMismatch));
        }

        let tid1 = TransactionID::random();
        let tid2 = TransactionID::random();

        let con4 = Context::All(vec![
            Context::Any(vec![Context::ObjectID(tid1.clone()), Context::ObjectID(tid2.clone())]),
            Context::Any(vec![Context::Name("jerry".into()), Context::Name("larry".into())]),
        ]);
        assert_eq!(con4.test(&con4), Err(Error::PolicyContextMismatch));
        assert_eq!(con4.test(&Context::Any(combos.clone())), Err(Error::PolicyContextMismatch));
        con4.test(&Context::Any(vec![Context::Name("jerry".into()), Context::ObjectID(tid1.clone())]))
            .unwrap();
        con4.test(&Context::Any(vec![Context::Name("larry".into()), Context::ObjectID(tid2.clone())]))
            .unwrap();
        assert_eq!(
            con4.test(&Context::Any(vec![Context::Name("larry".into()), Context::ObjectID(TransactionID::random()),])),
            Err(Error::PolicyContextMismatch)
        );
        assert_eq!(
            con4.test(&Context::Any(vec![Context::Name("larry".into()), Context::Name("jerry".into()),])),
            Err(Error::PolicyContextMismatch)
        );

        let con5 = Context::Any(vec![
            Context::All(vec![Context::ObjectID(tid1.clone()), Context::ObjectID(tid2.clone())]),
            Context::All(vec![Context::Name("jerry".into()), Context::Name("larry".into())]),
        ]);
        assert_eq!(con4.test(&Context::Any(combos.clone())), Err(Error::PolicyContextMismatch));
        con5.test(&Context::Any(vec![
            Context::Name("larry".into()),
            Context::Name("jerry".into()),
            Context::ObjectID(TransactionID::random()),
        ]))
        .unwrap();
        con5.test(&Context::Any(vec![
            Context::ObjectID(tid1.clone()),
            Context::ObjectID(tid2.clone()),
            Context::Name("sandra".into()),
        ]))
        .unwrap();
        assert_eq!(
            con5.test(&Context::Any(vec![
                Context::Name("larry".into()),
                Context::Name("sandra".into()),
                Context::ObjectID(tid1.clone()),
                Context::ObjectID(TransactionID::random()),
            ])),
            Err(Error::PolicyContextMismatch)
        );
        assert_eq!(
            con5.test(&Context::Any(vec![
                Context::Name("larry".into()),
                Context::Name("sandra".into()),
                Context::ObjectID(tid2.clone()),
                Context::ObjectID(TransactionID::random()),
            ])),
            Err(Error::PolicyContextMismatch)
        );

        let con6 = Context::Name("Frodo".into());
        assert_eq!(
            con6.test(&Context::Any(vec![Context::Name("Sam".into()), Context::Name("Gandalf".into()),])),
            Err(Error::PolicyContextMismatch)
        );
        con6.test(&Context::Any(vec![
            Context::Name("Gandalf".into()),
            Context::Name("Sam".into()),
            Context::Name("Frodo".into()),
        ]))
        .unwrap();
        con6.test(&Context::Any(vec![Context::Name("Frodo".into()), Context::Name("Gandalf".into())]))
            .unwrap();
        con6.test(&Context::Any(vec![Context::Name("Frodo".into()), Context::Name("Aragorn".into())]))
            .unwrap();

        let con7 = Context::Not(Box::new(Context::Name("Gandalf".into()))); // sry gandalf
        con7.test(&Context::Any(vec![
            Context::Name("larry".into()),
            Context::Name("barry".into()),
            Context::Name("jerry".into()),
            Context::Name("darry".into()),
        ]))
        .unwrap();
        assert_eq!(
            con7.test(&Context::Any(vec![
                Context::Name("larry".into()),
                Context::Name("barry".into()),
                Context::Name("jerry".into()),
                Context::Name("darry".into()),
                Context::Name("Gandalf".into()),
            ])),
            Err(Error::PolicyContextMismatch)
        );

        let con8 = Context::All(vec![
            Context::ObjectID(tid1.clone()),
            Context::Not(Box::new(Context::ObjectID(tid2.clone()))),
        ]);
        con8.test(&Context::Any(vec![Context::ObjectID(tid1.clone()), Context::ObjectID(TransactionID::random())]))
            .unwrap();
        con8.test(&Context::Any(vec![Context::ObjectID(tid1.clone())])).unwrap();
        assert_eq!(
            con8.test(&Context::Any(vec![Context::ObjectID(tid1.clone()), Context::ObjectID(tid2.clone()),])),
            Err(Error::PolicyContextMismatch)
        );

        let con9 = Context::All(vec![Context::Not(Box::new(Context::Permissive))]);
        assert_eq!(con9.test(&Context::Any(vec![Context::ObjectID(tid1.clone()),])), Err(Error::PolicyContextMismatch));
        assert_eq!(con9.test(&Context::Any(vec![Context::Name("Frodo".into()),])), Err(Error::PolicyContextMismatch));
        assert_eq!(
            con9.test(&Context::Any(vec![Context::Name("Gandalf".into()), Context::ObjectID(tid2.clone()),])),
            Err(Error::PolicyContextMismatch)
        );
    }

    #[test]
    fn capability_test() {
        let cap1 = Capability::Permissive;
        cap1.test(&Capability::Permissive).unwrap();
        cap1.test(&Capability::Transaction {
            body_type: vec![TransactionBodyType::CreateIdentityV1],
            context: Context::Any(vec![]),
        })
        .unwrap();

        // alright, now the tricky stuff
        let cap3 = Capability::Transaction {
            body_type: vec![TransactionBodyType::CreateIdentityV1],
            context: Context::Any(vec![Context::Name("omglol".into())]),
        };
        assert_eq!(cap3.test(&cap1).err(), Some(Error::PolicyCapabilityMismatch));
        let res3_1 = cap3.test(&Capability::Transaction {
            body_type: vec![TransactionBodyType::SignV1],
            context: Context::Any(vec![]),
        });
        assert_eq!(res3_1.err(), Some(Error::PolicyCapabilityMismatch));

        let res3_2 = cap3.test(&Capability::Transaction {
            body_type: vec![TransactionBodyType::CreateIdentityV1],
            context: Context::Any(vec![]),
        });
        assert_eq!(res3_2.err(), Some(Error::PolicyContextMismatch));

        cap3.test(&Capability::Transaction {
            body_type: vec![TransactionBodyType::CreateIdentityV1],
            context: Context::Any(vec![Context::Name("omglol".into())]),
        })
        .unwrap();

        let cap4 = Capability::Transaction {
            body_type: vec![
                TransactionBodyType::MakeClaimV1,
                TransactionBodyType::EditClaimV1,
                TransactionBodyType::DeleteClaimV1,
            ],
            context: Context::Any(vec![Context::NameGlob("email/*".into())]),
        };
        cap4.test(&Capability::Transaction {
            body_type: vec![TransactionBodyType::MakeClaimV1],
            context: Context::Any(vec![Context::Name("email/default".into())]),
        })
        .unwrap();
        cap4.test(&Capability::Transaction {
            body_type: vec![TransactionBodyType::EditClaimV1],
            context: Context::Any(vec![Context::Name("email/omg".into())]),
        })
        .unwrap();
        cap4.test(&Capability::Transaction {
            body_type: vec![TransactionBodyType::DeleteClaimV1],
            context: Context::Any(vec![Context::Name("email/suckerrr".into())]),
        })
        .unwrap();
        let res4_1 = cap4.test(&Capability::Transaction {
            body_type: vec![TransactionBodyType::AddSubkeyV1],
            context: Context::Any(vec![Context::Name("email/suckerrr".into())]),
        });
        assert_eq!(res4_1.err(), Some(Error::PolicyCapabilityMismatch));
        let res4_2 = cap4.test(&Capability::Transaction {
            // can only specify EXACTLY ONE body_type in the testee capability
            body_type: vec![TransactionBodyType::MakeClaimV1, TransactionBodyType::EditClaimV1],
            context: Context::Any(vec![Context::Name("email/suckerrr".into())]),
        });
        assert_eq!(res4_2.err(), Some(Error::PolicyCapabilityMismatch));
        let res4_3 = cap4.test(&Capability::Transaction {
            body_type: vec![],
            context: Context::Any(vec![Context::Name("email/suckerrr".into())]),
        });
        assert_eq!(res4_3.err(), Some(Error::PolicyCapabilityMismatch));
    }

    #[test]
    fn multisig_policy_test() {
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();

        let gus = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let marty = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let jackie = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let rosarita = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let dirk = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let twinkee = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let syd = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let scurvy = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let kitty = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();

        let conditions = MultisigPolicy::Any(vec![
            MultisigPolicy::All(vec![
                MultisigPolicy::MOfN {
                    must_have: 1,
                    participants: vec![dirk.clone().into(), jackie.clone().into()],
                },
                MultisigPolicy::MOfN {
                    must_have: 1,
                    participants: vec![syd.clone().into(), twinkee.clone().into()],
                },
            ]),
            MultisigPolicy::MOfN {
                must_have: 3,
                participants: vec![gus.clone().into(), marty.clone().into(), jackie.clone().into(), dirk.clone().into()],
            },
        ]);

        let people = vec![&gus, &marty, &jackie, &rosarita, &dirk, &twinkee, &syd, &scurvy, &kitty];
        let combinations =
            util::test::generate_combinations(&vec!["gus", "marty", "jackie", "rosarita", "dirk", "twinkee", "syd", "scurvy", "kitty"]);
        let obj = "Pretend entry";
        let possible_signatures = people
            .into_iter()
            .map(|key| (key, key.sign(&master_key, obj.as_bytes()).unwrap()))
            .collect::<Vec<_>>();

        let kn = |name| match name {
            "gus" => &gus,
            "marty" => &marty,
            "jackie" => &jackie,
            "rosarita" => &rosarita,
            "dirk" => &dirk,
            "twinkee" => &twinkee,
            "syd" => &syd,
            "scurvy" => &scurvy,
            "kitty" => &kitty,
            _ => panic!("bad key name"),
        };
        let fs = |key| {
            possible_signatures
                .iter()
                .find(|ent| ent.0 == key)
                .map(|x| MultisigPolicySignature::Key {
                    key: x.0.clone().into(),
                    signature: x.1.clone(),
                })
                .unwrap()
        };
        let passing_combinations = vec![
            vec!["dirk", "syd"],
            vec!["dirk", "twinkee"],
            vec!["jackie", "syd"],
            vec!["jackie", "twinkee"],
            vec!["gus", "marty", "jackie"],
            vec!["marty", "jackie", "dirk"],
            vec!["gus", "jackie", "dirk"],
            vec!["gus", "marty", "dirk"],
        ];
        let should_pass = |names: &[&str]| -> bool {
            if names.len() == 0 {
                return false;
            }
            for entry in &passing_combinations {
                let mut has_all_names = true;
                for must_have in entry {
                    if !names.contains(must_have) {
                        has_all_names = false;
                        break;
                    }
                }
                if has_all_names {
                    return true;
                }
            }
            false
        };
        for combo in combinations {
            let combo_sigs = combo.iter().map(|name| fs(kn(name))).collect::<Vec<_>>();
            let res = conditions.test(&combo_sigs);
            match res {
                Ok(_) => {
                    if !should_pass(&combo) {
                        panic!("Combination passed but should not have: {:?}", combo);
                    }
                }
                Err(_) => {
                    if should_pass(&combo) {
                        panic!("Combination errored but should have passed: {:?}", combo);
                    }
                }
            }
        }
    }

    #[test]
    fn policy_can() {
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let admin_keypair = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let tid = TransactionID::random();
        let testcap = Capability::Transaction {
            body_type: vec![TransactionBodyType::MakeStampV1],
            context: Context::Any(vec![Context::ObjectID(tid.clone()), Context::Name("keys/publish".into())]),
        };

        let capabilities1 = vec![Capability::Permissive];
        let multisig1 = MultisigPolicy::MOfN {
            must_have: 1,
            participants: vec![admin_keypair.clone().into()],
        };
        let policy1 = Policy::new(capabilities1, multisig1.clone());
        assert!(policy1.can(&testcap));
        assert!(policy1.can(&Capability::Permissive));

        let capabilities2 = vec![Capability::Transaction {
            body_type: vec![TransactionBodyType::CreateIdentityV1],
            context: Context::Any(vec![Context::Name("shooter mcgavin".into())]),
        }];
        let policy2 = Policy::new(capabilities2.clone(), multisig1.clone());
        assert!(!policy2.can(&testcap));

        let mut capabilities3 = capabilities2.clone();
        capabilities3.push(Capability::Transaction {
            body_type: vec![TransactionBodyType::MakeStampV1],
            context: Context::Any(vec![Context::ObjectID(tid.clone())]),
        });
        let policy3 = Policy::new(capabilities3.clone(), multisig1.clone());
        assert!(policy3.can(&testcap));

        let testcap2 = Capability::Transaction {
            body_type: vec![TransactionBodyType::ExtV1],
            context: Context::Any(vec![
                Context::ExtType(Vec::from("orders-create".as_bytes()).into()),
                Context::ExtContext {
                    key: Vec::from("department".as_bytes()).into(),
                    val: Vec::from("inventory".as_bytes()).into(),
                },
                Context::ExtContext {
                    key: Vec::from("budget".as_bytes()).into(),
                    val: Vec::from("production/inventory/widgets".as_bytes()).into(),
                },
            ]),
        };
        let testcap3 = Capability::Transaction {
            body_type: vec![TransactionBodyType::ExtV1],
            context: Context::Any(vec![
                Context::ExtType(Vec::from("orders-create".as_bytes()).into()),
                Context::ExtContext {
                    key: Vec::from("department".as_bytes()).into(),
                    val: Vec::from("inventory".as_bytes()).into(),
                },
                Context::ExtContext {
                    key: Vec::from("budget".as_bytes()).into(),
                    val: Vec::from("current/not-the-capital-account".as_bytes()).into(), // thank you, we do our best
                },
            ]),
        };
        let capabilities4 = vec![Capability::Transaction {
            body_type: vec![TransactionBodyType::ExtV1],
            context: Context::All(vec![
                Context::ExtType(Vec::from("orders-create".as_bytes()).into()),
                Context::ExtContext {
                    key: Vec::from("department".as_bytes()).into(),
                    val: Vec::from("inventory".as_bytes()).into(),
                },
                Context::ExtContextPrefix {
                    key: Vec::from("budget".as_bytes()).into(),
                    val: Vec::from("production/inventory/".as_bytes()).into(),
                },
            ]),
        }];
        let policy4 = Policy::new(capabilities4.clone(), multisig1.clone());
        assert!(!policy4.can(&testcap));
        assert!(policy4.can(&testcap2));
        assert!(!policy4.can(&testcap3));
    }

    #[test]
    fn policy_validate_transaction() {
        let mut rng = crate::util::test::rng();
        let (master_key, transactions, admin_key) = util::test::create_fake_identity(&mut rng, Timestamp::now());
        let admin_key2 = AdminKey::new(AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap(), "Jack's", None);
        let identity = transactions.build_identity().unwrap();

        let capabilities = vec![Capability::Transaction {
            body_type: vec![TransactionBodyType::MakeClaimV1],
            context: Context::Any(vec![Context::ClaimType(ContextClaimType::Url)]),
        }];
        let multisig = MultisigPolicy::MOfN {
            must_have: 2,
            participants: vec![admin_key.key().clone().into(), admin_key2.key().clone().into()],
        };
        let policy = Policy::new(capabilities.clone(), multisig.clone());

        let transaction1 = transactions
            .make_claim(
                &HashAlgo::Blake3,
                Timestamp::now(),
                ClaimSpec::Url(MaybePrivate::new_public(Url::parse("http://timmy.com").unwrap())),
                Some("primary-url"),
            )
            .unwrap();
        let contexts = Context::contexts_from_transaction_body(transaction1.entry().body(), &identity);

        assert_eq!(policy.validate_transaction(&transaction1, &contexts), Err(Error::MultisigPolicyConditionMismatch));

        let transaction2 = transaction1.clone().sign(&master_key, &admin_key).unwrap();
        assert_eq!(policy.validate_transaction(&transaction2, &contexts), Err(Error::MultisigPolicyConditionMismatch));

        let transaction3 = transaction2.clone().sign(&master_key, &admin_key2).unwrap();
        policy.validate_transaction(&transaction3, &contexts).unwrap();

        let capabilities2 = vec![Capability::Transaction {
            body_type: vec![TransactionBodyType::EditClaimV1],
            context: Context::Any(vec![Context::ClaimType(ContextClaimType::Url)]),
        }];
        let mut policy2 = policy.clone();
        policy2.set_capabilities(capabilities2.clone());
        assert_eq!(policy2.validate_transaction(&transaction3, &contexts), Err(Error::PolicyCapabilityMismatch));
    }

    #[test]
    fn contexts_from_transaction_body_create_identity_v1() {
        let mut rng = crate::util::test::rng();
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity(&mut rng, Timestamp::now());
        let identity = transactions.build_identity().unwrap();
        assert_eq!(
            Context::contexts_from_transaction_body(transactions.transactions()[0].entry().body(), &identity,),
            vec![],
        );
    }

    #[test]
    fn contexts_from_transaction_body_reset_identity_v1() {
        let mut rng = crate::util::test::rng();
        let (master_key, transactions, admin_key) = crate::util::test::create_fake_identity(&mut rng, Timestamp::now());
        let policies = match transactions.transactions()[0].entry().body() {
            TransactionBody::CreateIdentityV1 { policies, .. } => policies.clone(),
            _ => panic!("how strange"),
        };
        let transactions = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ reset_identity, Timestamp::now(), Some(vec![admin_key.clone()]), Some(policies.clone()) ]
        };
        let identity = transactions.build_identity().unwrap();
        assert_eq!(
            Context::contexts_from_transaction_body(transactions.transactions()[1].entry().body(), &identity,),
            vec![],
        );
    }

    #[test]
    fn contexts_from_transaction_body_add_admin_key_v1() {
        let mut rng = crate::util::test::rng();
        let (master_key, transactions, admin_key) = crate::util::test::create_fake_identity(&mut rng, Timestamp::now());
        let admin_keypair2 = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let admin_key2 = AdminKey::new(admin_keypair2, "Alpha", None);
        let transactions = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ add_admin_key, Timestamp::now(), admin_key2.clone() ]
        };
        let identity = transactions.build_identity().unwrap();
        assert_eq!(
            Context::contexts_from_transaction_body(transactions.transactions()[1].entry().body(), &identity,),
            vec![
                Context::AdminKeyID(admin_key2.key_id()),
                Context::KeyID(admin_key2.key_id().into()),
                Context::Name(admin_key2.name().clone()),
            ],
        );
    }

    #[test]
    fn contexts_from_transaction_body_edit_admin_key_v1() {
        let mut rng = crate::util::test::rng();
        let (master_key, transactions, admin_key) = crate::util::test::create_fake_identity(&mut rng, Timestamp::now());
        let admin_keypair2 = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let admin_key2 = AdminKey::new(admin_keypair2, "turtl/manager", None);
        let transactions = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ add_admin_key, Timestamp::now(), admin_key2.clone() ]
        };
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ edit_admin_key, Timestamp::now(), admin_key2.key_id(), Some("turtl/manage".to_string()), None ]
        };
        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ edit_admin_key, Timestamp::now(), admin_key2.key_id(), None, Some(Some("management key".to_string())) ]
        };
        let identity2 = transactions2.build_identity().unwrap();
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(
            Context::contexts_from_transaction_body(transactions2.transactions()[2].entry().body(), &identity2,),
            vec![
                Context::Name("turtl/manage".to_string()),
                Context::AdminKeyID(admin_key2.key_id()),
                Context::KeyID(admin_key2.key_id().into()),
            ],
        );
        assert_eq!(
            Context::contexts_from_transaction_body(transactions3.transactions()[2].entry().body(), &identity3,),
            vec![
                Context::Name("turtl/manager".to_string()),
                Context::AdminKeyID(admin_key2.key_id()),
                Context::KeyID(admin_key2.key_id().into()),
            ],
        );
    }

    #[ignore]
    #[test]
    fn contexts_from_transaction_body_revoke_admin_key_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_add_policy_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_delete_policy_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_make_claim_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_edit_claim_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_delete_claim_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_make_stamp_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_revoke_stamp_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_accept_stamp_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_delete_stamp_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_add_subkey_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_edit_subkey_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_revoke_subkey_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_delete_subkey_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_publish_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_sign_v1() {
        todo!();
    }
    #[ignore]
    #[test]
    fn contexts_from_transaction_body_ext_v1() {
        todo!();
    }
}
