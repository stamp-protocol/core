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
    crypto::key::{SecretKey, SignKeypair, SignKeypairPublic, SignKeypairSignature},
    dag::{TransactionBody, TransactionID},
    error::{Error, Result},
    identity::{
        Public,
        identity::{IdentityID, ForwardType},
        keychain::{ExtendKeypair, AdminKeypairPublic, AdminKeypairSignature},
    },
    util::ser::{self, BinaryVec},
};
use getset;
#[cfg(test)] use rand::RngCore;
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::convert::TryInto;
use std::ops::Deref;

/// Defines a context specifier specific to various claim types
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum TransactionBodyType {
    #[rasn(tag(explicit(0)))]
    CreateIdentityV1,
    #[rasn(tag(explicit(1)))]
    MakeClaimV1,
    #[rasn(tag(explicit(2)))]
    DeleteClaimV1,
    #[rasn(tag(explicit(3)))]
    MakeStampV1,
    #[rasn(tag(explicit(4)))]
    RevokeStampV1,
    #[rasn(tag(explicit(5)))]
    AcceptStampV1,
    #[rasn(tag(explicit(6)))]
    DeleteStampV1,
    #[rasn(tag(explicit(7)))]
    AddSubkeyV1,
    #[rasn(tag(explicit(8)))]
    EditSubkeyV1,
    #[rasn(tag(explicit(9)))]
    RevokeSubkeyV1,
    #[rasn(tag(explicit(10)))]
    DeleteSubkeyV1,
    #[rasn(tag(explicit(11)))]
    SetNicknameV1,
    #[rasn(tag(explicit(12)))]
    AddForwrdV1,
    #[rasn(tag(explicit(13)))]
    DeleteForwardV1,
}

impl From<TransactionBody> for TransactionBodyType {
    // Not sure if this is actually useful as much as it keeps ContextClaimType
    // in sync with ClaimSpec
    fn from(body: TransactionBody) -> Self {
        match body {
            TransactionBody::CreateIdentityV1 { .. } => Self::CreateIdentityV1,
            TransactionBody::MakeClaimV1 { .. } => Self::MakeClaimV1,
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
            TransactionBody::AddForwrdV1 { .. } => Self::AddForwrdV1,
            TransactionBody::DeleteForwardV1 { .. } => Self::DeleteForwardV1,
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

impl From<ClaimSpec> for ContextClaimType {
    // Not sure if this is actually useful as much as it keeps ContextClaimType
    // in sync with ClaimSpec
    fn from(spec: ClaimSpec) -> Self {
        match spec {
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

/// Defines a context specifier specific to various forward types
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum ContextForwardType {
    #[rasn(tag(explicit(0)))]
    Email,
    #[rasn(tag(explicit(1)))]
    Social,
    #[rasn(tag(explicit(2)))]
    Pgp,
    #[rasn(tag(explicit(3)))]
    Url,
    #[rasn(tag(explicit(4)))]
    Extension,
}

impl From<ForwardType> for ContextForwardType {
    // Not sure if this is actually useful as much as it keeps ContextClaimType
    // in sync with ClaimSpec
    fn from(spec: ForwardType) -> Self {
        match spec {
            ForwardType::Email(..) => Self::Email,
            ForwardType::Social { .. } => Self::Social,
            ForwardType::Pgp(..) => Self::Pgp,
            ForwardType::Url(..) => Self::Url,
            ForwardType::Extension { .. } => Self::Extension,
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
    /// Represents a context in which ALL given contexts must match.
    #[rasn(tag(explicit(0)))]
    All(Vec<Context>),
    /// Represents a context in which one or more of the given contexts must
    /// match.
    #[rasn(tag(explicit(1)))]
    Any(Vec<Context>),
    /// Allows an action in the context of items with an exact ID match (for
    /// instance, a claim that was created by transaction 0x03fd913)
    #[rasn(tag(explicit(2)))]
    ID(TransactionID),
    /// Allows an action in the context of items with an exact name match. This
    /// can be a forward or a subkey generally.
    #[rasn(tag(explicit(3)))]
    Name(String),
    /// Allows an action in the context of items with name matching a glob pattern.
    /// This can be a forward or a subkey generally.
    #[rasn(tag(explicit(4)))]
    NameGlob(String),
    /// Allows actions on claims where the claim is of a particular type
    #[rasn(tag(explicit(5)))]
    ClaimType(ContextClaimType),
    /// Allows actions on forwards where the claim is of a particular type
    #[rasn(tag(explicit(6)))]
    ForwardType(ContextForwardType),
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
    /// The ability to perform a transaction in a given context
    #[rasn(tag(explicit(0)))]
    Transaction {
        #[rasn(tag(explicit(0)))]
        transaction: TransactionBodyType,
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
    #[rasn(tag(explicit(1)))]
    Extension {
        #[rasn(tag(explicit(0)))]
        #[serde(rename = "type")]
        ty: BinaryVec,
        #[rasn(tag(explicit(1)))]
        context: BinaryVec,
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

/// A signature on a policy transaction. Currently only supports direct signatures
/// from admin keys, but could allow expanding to other signature methods.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum PolicySignature {
    /// A signature on a transaction from a specific key, generally one that's
    /// listed as a [Participant::Key] in the policy.
    #[rasn(tag(explicit(0)))]
    Key(AdminKeypairSignature),
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
    /// Tests whether the given signatures match the policy condition
    pub(crate) fn test<F>(&self, signatures: &Vec<PolicySignature>, serialized_transaction: &[u8]) -> Result<()>
        where F: Fn(&Participant, &PolicySignature) -> Result<()>,
    {
        match self {
            Self::All(conditions) => {
                conditions.iter()
                    .map(|c| c.test(signatures, sigtest))
                    .collect::<Result<Vec<_>>>()?;
            }
            Self::Any(conditions) => {
                conditions.iter()
                    .find(|c| c.test(signatures, sigtest).is_ok())
                    .ok_or(Error::PolicyConditionMismatch)?;
            }
            Self::OfN { must_have, participants } => {
                let has = participants.iter()
                    .filter_map(|participant| {
                        for sig in signatures {
                            match (participant, sig) {
                                (Participant::Key(pubkey), PolicySignature::Key(sig)) => {
                                    if pubkey.verify(sig, &serialized_transaction).is_ok() {
                                        return Some(());
                                    }
                                }
                                _ => {}
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
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct CapabilityPolicy {
    /// The capabilities (or actions) this policy can access
    #[rasn(tag(explicit(0)))]
    capabilities: Vec<Capability>,
    /// The signature policy defining which keys are required to perform the
    /// specified capabilities
    #[rasn(tag(explicit(1)))]
    policy: Policy,
}

impl CapabilityPolicy {
    /// Create a new `CapabilityPolicy`
    pub fn new(capabilities: Vec<Capability>, policy: Policy) -> Self {
        Self { capabilities, policy }
    }

    /// Determine if this particular `CapabilityPolicy` allows performing the
    /// action `capability`.
    pub fn can(&self, capability: Capability) -> bool {
        todo!();
    }

    /// Determine if this particular `CapabilityPolicy` allows performing the
    /// action `capability`, and also checks the `signatures` against the policy
    /// to make sure we have the signatures we need to perform this action.
    pub fn validate(&self, capability: Capability, signatures: &Vec<PolicySignature>) -> bool {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::key::{SignKeypair},
        error::Error,
        util,
    };

    #[test]
    fn policy_condition_test() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();

        let gus = SignKeypair::new_ed25519(&master_key).unwrap();
        let marty = SignKeypair::new_ed25519(&master_key).unwrap();
        let jackie = SignKeypair::new_ed25519(&master_key).unwrap();
        let rosarita = SignKeypair::new_ed25519(&master_key).unwrap();
        let dirk = SignKeypair::new_ed25519(&master_key).unwrap();
        let twinkee = SignKeypair::new_ed25519(&master_key).unwrap();
        let syd = SignKeypair::new_ed25519(&master_key).unwrap();
        let scurvy = SignKeypair::new_ed25519(&master_key).unwrap();
        let kitty = SignKeypair::new_ed25519(&master_key).unwrap();

        let conditions = PolicyCondition::Any(vec![
            PolicyCondition::All(vec![
                PolicyCondition::OfN {
                    must_have: 1, 
                    pubkeys: vec![
                        dirk.clone().into(),
                        jackie.clone().into(),
                    ],
                },
                PolicyCondition::OfN {
                    must_have: 1, 
                    pubkeys: vec![
                        syd.clone().into(),
                        twinkee.clone().into(),
                    ],
                },
            ]),
            PolicyCondition::OfN {
                must_have: 3, 
                pubkeys: vec![
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
                .map(|x| x.1.clone())
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
        let sigtest = |pubkey: &SignKeypairPublic, sig: &SignKeypairSignature| {
            pubkey.verify(sig, obj.as_bytes())
        };
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
            let res = conditions.test(&combo_sigs, &sigtest);
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
    fn policy_sign_request_validate_request() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let gus = SignKeypair::new_ed25519(&master_key).unwrap();
        let marty = SignKeypair::new_ed25519(&master_key).unwrap();
        let jackie = SignKeypair::new_ed25519(&master_key).unwrap();
        let rosarita = SignKeypair::new_ed25519(&master_key).unwrap();
        let dirk = SignKeypair::new_ed25519(&master_key).unwrap();

        let identity_id = IdentityID::random();
        let policy_id = PolicyID::random();

        let policy = RecoveryPolicy::new(policy_id.clone(), PolicyCondition::OfN {
            must_have: 3,
            pubkeys: vec![
                gus.clone().into(),
                marty.clone().into(),
                jackie.clone().into(),
                rosarita.clone().into(),
                dirk.clone().into(),
            ],
        });

        let new_policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let new_publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let new_root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let action = PolicyRequestAction::ReplaceKeys {
            policy: new_policy_keypair.clone(),
            publish: new_publish_keypair.clone(),
            root: new_root_keypair.clone(),
        };
        let entry = PolicyRequestEntry::new(identity_id.clone(), policy_id.clone(), action.clone());
        let req = PolicyRequest::new(&master_key, &new_policy_keypair, entry).unwrap();

        let entry2 = PolicyRequestEntry::new(identity_id.clone(), PolicyID::random(), action.clone());
        let req_random_policy = PolicyRequest::new(&master_key, &new_policy_keypair, entry2).unwrap();

        macro_rules! sig_failed {
            ($req_mod:ident, $setter:expr) => {
                let mut $req_mod = req.clone();
                $setter;
                let res = policy.validate_request(&identity_id, &$req_mod);
                assert_eq!(res.err(), Some(Error::CryptoSignatureVerificationFailed));
            }
        }

        sig_failed! { req_mod, req_mod.set_id(RequestID::random()) }
        sig_failed! { req_mod, req_mod.entry_mut().set_identity_id(IdentityID::random()) }
        sig_failed! { req_mod, req_mod.entry_mut().set_policy_id(PolicyID::random()) }
        match req.entry().action().clone() {
            PolicyRequestAction::ReplaceKeys { publish, root, .. } => {
                let new_policy = PolicyKeypair::new_ed25519(&master_key).unwrap();
                let new_action = PolicyRequestAction::ReplaceKeys {
                    policy: new_policy,
                    publish,
                    root,
                };
                sig_failed! { req_mod, req_mod.entry_mut().set_action(new_action) }
            }
        }

        let res = policy.validate_request(&IdentityID::random(), &req);
        assert_eq!(res.err(), Some(Error::RecoveryPolicyRequestIdentityMismatch));

        let res = policy.validate_request(&identity_id, &req_random_policy);
        assert_eq!(res.err(), Some(Error::RecoveryPolicyRequestPolicyMismatch));

        let res = policy.validate_request(&identity_id, &req);
        assert_eq!(res.err(), Some(Error::PolicyConditionMismatch));

        // ok, let's get some sigs
        let req_signed = req
            .sign(&master_key, &gus).unwrap()
            .sign(&master_key, &marty).unwrap();
        // almost there...
        let res = policy.validate_request(&identity_id, &req_signed);
        assert_eq!(res.err(), Some(Error::PolicyConditionMismatch));

        // marty signs again...shouldn't count
        let req_signed_2 = req_signed.clone()
            .sign(&master_key, &marty).unwrap();
        assert_eq!(req_signed_2.signatures().len(), 3);
        // nice try
        let res = policy.validate_request(&identity_id, &req_signed_2);
        assert_eq!(res.err(), Some(Error::PolicyConditionMismatch));

        // rosarita to the rescue
        let req_signed_3 = req_signed.clone()
            .sign(&master_key, &rosarita).unwrap();
        // this shoudl get it
        let res = policy.validate_request(&identity_id, &req_signed_3);
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn policy_request_new_verify() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let new_policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let new_publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let new_root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let identity_id = IdentityID::random();
        let policy_id = PolicyID::random();
        let action = PolicyRequestAction::ReplaceKeys {
            policy: new_policy_keypair.clone(),
            publish: new_publish_keypair.clone(),
            root: new_root_keypair.clone(),
        };
        let entry = PolicyRequestEntry::new(identity_id.clone(), policy_id.clone(), action);
        let req = PolicyRequest::new(&master_key, &new_policy_keypair, entry).unwrap();

        assert_eq!(req.entry().identity_id(), &identity_id);
        assert_eq!(req.entry().policy_id(), &policy_id);
        match req.entry().action() {
            PolicyRequestAction::ReplaceKeys { policy, publish, root } => {
                assert_eq!(policy, &new_policy_keypair);
                assert_eq!(publish, &new_publish_keypair);
                assert_eq!(root, &new_root_keypair);
            }
        }

        req.verify(&new_policy_keypair).unwrap();

        // wrong key won't verify
        let res = req.verify(&PolicyKeypair::from(new_root_keypair.deref().clone()));
        assert_eq!(res.err(), Some(Error::CryptoSignatureVerificationFailed));

        // modified request won't verify
        let mut req2 = req.clone();
        let identity_id2 = IdentityID::random();
        assert!(identity_id != identity_id2);
        req2.entry_mut().set_identity_id(identity_id2);
        let res = req2.verify(&new_policy_keypair);
        assert_eq!(res.err(), Some(Error::CryptoSignatureVerificationFailed));
    }

    #[test]
    fn policy_request_reencrypt() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let new_policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let new_publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let new_root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let identity_id = IdentityID::random();
        let policy_id = PolicyID::random();
        let action = PolicyRequestAction::ReplaceKeys {
            policy: new_policy_keypair.clone(),
            publish: new_publish_keypair.clone(),
            root: new_root_keypair.clone(),
        };
        let entry = PolicyRequestEntry::new(identity_id.clone(), policy_id.clone(), action);
        let req = PolicyRequest::new(&master_key, &new_policy_keypair, entry).unwrap();

        // i'm detective john kimble
        let obj = "yeah sure you are.";

        let sig = match req.entry().action() {
            PolicyRequestAction::ReplaceKeys { policy, .. } => {
                policy.sign(&master_key, obj.as_bytes()).unwrap()
            }
        };

        let new_master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let req2 = req.reencrypt(&master_key, &new_master_key).unwrap();

        match req2.entry().action() {
            PolicyRequestAction::ReplaceKeys { policy, .. } => {
                let sig2 = policy.sign(&new_master_key, obj.as_bytes()).unwrap();
                assert_eq!(sig, sig2);
                let res = policy.sign(&master_key, obj.as_bytes());
                assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
            }
        }
    }

    #[test]
    fn policy_request_strip_private_has_private() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let new_policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let new_publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let new_root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let identity_id = IdentityID::random();
        let policy_id = PolicyID::random();
        let action = PolicyRequestAction::ReplaceKeys {
            policy: new_policy_keypair.clone(),
            publish: new_publish_keypair.clone(),
            root: new_root_keypair.clone(),
        };
        let entry = PolicyRequestEntry::new(identity_id.clone(), policy_id.clone(), action);
        let req = PolicyRequest::new(&master_key, &new_policy_keypair, entry).unwrap();

        assert!(req.has_private());
        match req.entry().action() {
            PolicyRequestAction::ReplaceKeys{ policy, publish, root } => {
                assert!(policy.has_private());
                assert!(publish.has_private());
                assert!(root.has_private());
            }
        }
        let req2 = req.strip_private();
        assert!(!req2.has_private());
        match req2.entry().action() {
            PolicyRequestAction::ReplaceKeys { policy, publish, root } => {
                assert!(!policy.has_private());
                assert!(!publish.has_private());
                assert!(!root.has_private());
            }
        }
    }

    #[test]
    fn capability_policy_can() {
        todo!();
    }

    #[test]
    fn capability_policy_validate() {
        todo!();
    }
}

