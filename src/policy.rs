//! The policy system provides a method for validating transactions using a
//! pre-determined combination of cryptographic signatures (effectively
//! multisig).
//!
//! Policies are general constructions that do not force M-of-N or any other
//! rigid arrangement, but rather allow expressions of completely arbitrary
//! combinations of keys.
//!
//! In combination with capabilties, this allows an identity to be managed
//! not just by keys it owns, but by trusted third parties as well.

use crate::{
    crypto::key::{KeyID},
    dag::{TransactionBody, TransactionID, Transaction},
    error::{Error, Result},
    identity::{
        claim::ClaimSpec,
        identity::{Identity, IdentityID},
        keychain::{ExtendKeypair, AdminKeypair, AdminKeypairPublic, AdminKeypairSignature},
    },
    util::{ser::BinaryVec},
};
use getset;
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

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
    AddCapabilityPolicyV1,
    #[rasn(tag(explicit(6)))]
    DeleteCapabilityPolicyV1,
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
    SetNicknameV1,
    #[rasn(tag(explicit(19)))]
    PublishV1,
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
            TransactionBody::AddCapabilityPolicyV1 { .. } => Self::AddCapabilityPolicyV1,
            TransactionBody::DeleteCapabilityPolicyV1 { .. } => Self::DeleteCapabilityPolicyV1,
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
            TransactionBody::SetNicknameV1 { .. } => Self::SetNicknameV1,
            TransactionBody::PublishV1 { .. } => Self::PublishV1,
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
    Relation,
    #[rasn(tag(explicit(10)))]
    RelationExtension,
    #[rasn(tag(explicit(11)))]
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
    /// Allows an action in any context (ie, context is irrelevant).
    #[rasn(tag(explicit(2)))]
    Permissive,
    /// Allows an action in the context of an identity that has this exact ID.
    #[rasn(tag(explicit(3)))]
    IdentityID(IdentityID),
    /// Allows an action in the context of items with an exact ID match (for
    /// instance, a claim that was created by transaction 0x03fd913)
    #[rasn(tag(explicit(4)))]
    ObjectID(TransactionID),
    /// Allows an action on a keypair that has a public key matching the given
    /// ID.
    #[rasn(tag(explicit(5)))]
    KeyID(KeyID),
    /// Allows an action in the context of items with an exact name match. This
    /// can be an admin key, subkey, or capability policy generally.
    #[rasn(tag(explicit(6)))]
    Name(String),
    /// Allows an action in the context of items with name matching a glob pattern.
    /// For instance `email-keys/*`
    #[rasn(tag(explicit(7)))]
    NameGlob(String),
    /// Allows actions on claims where the claim is of a particular type
    #[rasn(tag(explicit(8)))]
    ClaimType(ContextClaimType),
}

impl Context {
    /// Takes a transaction and returns all the contexts it covers.
    pub(crate) fn contexts_from_transaction(transaction: &Transaction, identity: &Identity) -> Vec<Self> {
        let mut contexts = Vec::new();
        match transaction.entry().body() {
            TransactionBody::CreateIdentityV1 { .. } => {}
            TransactionBody::ResetIdentityV1 { .. } => {}
            TransactionBody::AddAdminKeyV1 { admin_key } => {
                contexts.push(Self::KeyID(admin_key.key().key_id()));
                contexts.push(Self::Name(admin_key.name().clone()));
            }
            TransactionBody::EditAdminKeyV1 { id, .. } => {
                identity.keychain().admin_key_by_keyid(id)
                    .map(|admin_key| contexts.push(Self::Name(admin_key.name().clone())));
                contexts.push(Self::KeyID(id.clone()));
            }
            TransactionBody::RevokeAdminKeyV1 { id, .. } => {
                identity.keychain().admin_key_by_keyid(id)
                    .map(|admin_key| contexts.push(Self::Name(admin_key.name().clone())));
                contexts.push(Self::KeyID(id.clone()));
            }
            TransactionBody::AddCapabilityPolicyV1 { capability } => {
                contexts.push(Self::Name(capability.name().clone()));
            }
            TransactionBody::DeleteCapabilityPolicyV1 { name } => {
                contexts.push(Self::Name(name.clone()));
            }
            TransactionBody::MakeClaimV1 { spec, name } => {
                contexts.push(Self::ClaimType(ContextClaimType::from(spec)));
                if let Some(name) = name {
                    contexts.push(Self::Name(name.clone()));
                }
            }
            TransactionBody::EditClaimV1 { claim_id, .. } => {
                contexts.push(Self::ObjectID(claim_id.deref().clone()));
            }
            TransactionBody::DeleteClaimV1 { claim_id } => {
                contexts.push(Self::ObjectID(claim_id.deref().clone()));
            }
            TransactionBody::MakeStampV1 { stamp } => {
                contexts.push(Self::ObjectID(stamp.claim_id().deref().clone()));
                contexts.push(Self::IdentityID(stamp.stampee().clone()));
            }
            TransactionBody::RevokeStampV1 { revocation } => {
                contexts.push(Self::ObjectID(revocation.stamp_id().deref().clone()));
                contexts.push(Self::IdentityID(revocation.stampee().clone()));

                let stamp_maybe = identity.find_claim_stamp_by_id(revocation.stamp_id());
                if let Some(stamp) = stamp_maybe {
                    contexts.push(Self::ObjectID(stamp.entry().claim_id().deref().clone()));
                }
            }
            TransactionBody::AcceptStampV1 { stamp_transaction } => {
                match stamp_transaction.entry().body() {
                    TransactionBody::MakeStampV1 { stamp } => {
                        contexts.push(Self::ObjectID(stamp.claim_id().deref().clone()));
                        contexts.push(Self::IdentityID(stamp.stamper().clone()));
                    }
                    _ => {}
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
                contexts.push(Self::KeyID(key.key_id().clone()));
            }
            TransactionBody::EditSubkeyV1 { id, .. } => {
                contexts.push(Self::KeyID(id.clone()));
                identity.keychain().subkey_by_keyid(id)
                    .map(|subkey| contexts.push(Self::Name(subkey.name().clone())));
            }
            TransactionBody::RevokeSubkeyV1 { id, .. } => {
                contexts.push(Self::KeyID(id.clone()));
                identity.keychain().subkey_by_keyid(id)
                    .map(|subkey| contexts.push(Self::Name(subkey.name().clone())));
            }
            TransactionBody::DeleteSubkeyV1 { id } => {
                contexts.push(Self::KeyID(id.clone()));
                identity.keychain().subkey_by_keyid(id)
                    .map(|subkey| contexts.push(Self::Name(subkey.name().clone())));
            }
            TransactionBody::SetNicknameV1 { .. } => {}
            TransactionBody::PublishV1 { .. } => {}
        }
        contexts
    }
}

/// Defines an action that can be taken on an identity. Effectively, this is the
/// ability to group transactions (as defined by `[TransactionBody]`) within
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
    /// The ability to perform a transaction in a given context
    #[rasn(tag(explicit(1)))]
    Transaction {
        #[rasn(tag(explicit(0)))]
        body_type: TransactionBodyType,
        #[rasn(tag(explicit(1)))]
        context: Context,
    },
    /// Allows creating any kind of custom actions/contexts outside the scope of
    /// the Stamp protocol.
    ///
    /// For instance, an identity might have the ability to publish transactions
    /// in other protocols, and the `Extension` capability allows that protocol
    /// to define its own action types and contexts in serialized binary form.
    ///
    /// This allows harnessing the identity and its policy system for participating
    /// in protocols outside of Stamp.
    #[rasn(tag(explicit(2)))]
    Extension {
        #[rasn(tag(explicit(0)))]
        ty: BinaryVec,
        #[rasn(tag(explicit(1)))]
        context: BinaryVec,
    }
}

impl Capability {
    pub(crate) fn test(&self, test: &Capability) -> Result<()> {
        match self {
            // allow anything
            Self::Permissive => Ok(()),
            // tricky...
            Self::Transaction { body_type, context } => {
                todo!();
            }
            // don't validate extensions. you need to do that yourself.
            Self::Extension { .. } => Ok(()),
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
    Key(AdminKeypairPublic),
}

impl From<AdminKeypairPublic> for Participant {
    fn from(admin_pubkey: AdminKeypairPublic) -> Self {
        Participant::Key(admin_pubkey)
    }
}

impl From<AdminKeypair> for Participant {
    fn from(admin_pubkey: AdminKeypair) -> Self {
        Participant::Key(admin_pubkey.into())
    }
}

/// A signature on a policy transaction. Currently only supports direct signatures
/// from admin keys, but could allow expanding to other signature methods.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum PolicySignature {
    /// A signature on a transaction from a specific key, generally one that's
    /// listed as a [Participant::Key] in the policy.
    #[rasn(tag(explicit(0)))]
    Key {
        key: AdminKeypairPublic,
        signature: AdminKeypairSignature,
    },
}

/// A recursive structure that defines the conditions under which a multisig
/// policy can be satisfied. Allows expressing arbitrary combinations of
/// signatures.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Policy {
    /// All of the given conditions must be met.
    #[rasn(tag(explicit(0)))]
    All(Vec<Policy>),
    /// Any of the given conditions can be met.
    #[rasn(tag(explicit(1)))]
    Any(Vec<Policy>),
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

impl Policy {
    /// Tests whether the given signatures match the current policy. KEEP IN MIND
    /// that the signatures *must* be validated before we get here. We're simply
    /// testing that the signatures are from keys that satisfy the policy: WE DO
    /// NOT VALIDATE THE SIGNATURES.
    pub(crate) fn test(&self, signatures: &Vec<PolicySignature>) -> Result<()> {
        match self {
            Self::All(policies) => {
                policies.iter()
                    .map(|p| p.test(signatures))
                    .collect::<Result<Vec<_>>>()?;
            }
            Self::Any(policies) => {
                policies.iter()
                    .find(|p| p.test(signatures).is_ok())
                    .ok_or(Error::PolicyConditionMismatch)?;
            }
            Self::MOfN { must_have, participants } => {
                let has = participants.iter()
                    .filter_map(|participant| {
                        for sig in signatures {
                            match (participant, sig) {
                                (Participant::Key(ref pubkey), PolicySignature::Key { key, .. }) => {
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
                    Err(Error::PolicyConditionMismatch)?;
                }
            }
        }
        Ok(())
    }
}

/// Matches a set of [Capabilities][Capability] to a multisig [Policy], making
/// it so the policy must be fulfilled in order to perform those capabilities.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct CapabilityPolicy {
    /// The *unique* name of this capability policy.
    #[rasn(tag(explicit(0)))]
    name: String,
    /// The capabilities (or actions) this policy can access. These are permissive,
    /// and combined via OR.
    #[rasn(tag(explicit(1)))]
    capabilities: Vec<Capability>,
    /// The signature policy defining which keys are required to perform the
    /// specified capabilities
    #[rasn(tag(explicit(2)))]
    policy: Policy,
}

impl CapabilityPolicy {
    /// Create a new `CapabilityPolicy`
    pub fn new(name: String, capabilities: Vec<Capability>, policy: Policy) -> Self {
        Self { name, capabilities, policy }
    }

    /// Determine if this particular `CapabilityPolicy` allows performing the
    /// action `capability` in the given `context`.
    pub fn can(&self, capability: &Capability) -> bool {
        self.capabilities().iter().find(|c| c.test(capability).is_ok()).is_some()
    }

    /// Determine if this particular `CapabilityPolicy` allows performing the
    /// action `capability`, and also checks the `signatures` against the policy
    /// to make sure we have the signatures we need to perform this action.
    pub(crate) fn validate_transaction(&self, transaction: &Transaction, contexts: &Vec<Context>) -> Result<()> {
        // don't check the signature validity here. just check that we have the signatures
        // needed to satisfy the policy. signature checks happen higher level.
        self.policy().test(transaction.signatures())?;
        let transaction_capability = Capability::Transaction {
            body_type: transaction.entry().body().into(),
            context: Context::Any(contexts.clone()),
        };
        if !self.can(&transaction_capability) {
            Err(Error::PolicyCapabilityMismatch)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::key::{SecretKey},
        identity::keychain::{AdminKeypair},
        util,
    };

    #[test]
    fn capability_test() {
        todo!();
    }

    #[test]
    fn policy_test() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();

        let gus = AdminKeypair::new_ed25519(&master_key).unwrap();
        let marty = AdminKeypair::new_ed25519(&master_key).unwrap();
        let jackie = AdminKeypair::new_ed25519(&master_key).unwrap();
        let rosarita = AdminKeypair::new_ed25519(&master_key).unwrap();
        let dirk = AdminKeypair::new_ed25519(&master_key).unwrap();
        let twinkee = AdminKeypair::new_ed25519(&master_key).unwrap();
        let syd = AdminKeypair::new_ed25519(&master_key).unwrap();
        let scurvy = AdminKeypair::new_ed25519(&master_key).unwrap();
        let kitty = AdminKeypair::new_ed25519(&master_key).unwrap();

        let conditions = Policy::Any(vec![
            Policy::All(vec![
                Policy::MOfN {
                    must_have: 1, 
                    participants: vec![
                        dirk.clone().into(),
                        jackie.clone().into(),
                    ],
                },
                Policy::MOfN {
                    must_have: 1, 
                    participants: vec![
                        syd.clone().into(),
                        twinkee.clone().into(),
                    ],
                },
            ]),
            Policy::MOfN {
                must_have: 3, 
                participants: vec![
                    gus.clone().into(),
                    marty.clone().into(),
                    jackie.clone().into(),
                    dirk.clone().into(),
                ],
            }
        ]);

        let people = vec![
            &gus, &marty, &jackie,
            &rosarita, &dirk, &twinkee,
            &syd, &scurvy, &kitty,
        ];
        let combinations = util::test::generate_combinations(&vec![
            "gus", "marty", "jackie",
            "rosarita", "dirk", "twinkee",
            "syd", "scurvy", "kitty",
        ]);
        let obj = "Pretend entry";
        let possible_signatures = people.into_iter()
            .map(|key| (key, key.sign(&master_key, obj.as_bytes()).unwrap()))
            .collect::<Vec<_>>();

        let kn = |name| {
            match name {
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
            }
        };
        let fs = |key| {
            possible_signatures.iter()
                .find(|ent| ent.0 == key)
                .map(|x| PolicySignature::Key {
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
        let should_pass = |names: &Vec<&str>| -> bool {
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
    fn capability_policy_can() {
        todo!();
    }

    #[test]
    fn capability_policy_validate_transaction() {
        todo!();
    }
}

