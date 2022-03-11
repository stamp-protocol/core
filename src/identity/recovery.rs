//! The recovery system provides a method for replacing the recovery key (which
//! has ultimate control over the keychain) in the event it is lost or stolen.
//!
//! The idea here is that using our policy keypair, we can create and sign a
//! recovery policy that allows us to generate new policy, publish, and root
//! keypairs for our identity, provided that it is ratified by some combination
//! of signatures from other keys. So let's say you create a recovery policy
//! that requires you to have at least three signatures of the five public
//! keys that you list (which might belong to family members, identity
//! companies, or other trusted third parties). If you lose any non-alpha key,
//! you can create a recovery request, sign it with the policy key you hope
//! to replace the lost one, and try to get three or more signatures on that
//! request from your trusted circle. If you get the signatures you need, the
//! protocol will "honor" the replacement request and grant you your new
//! keys.
//!
//! The recovery request currently only has one action available to it, which is
//! to replace the policy, publis and root keys. In essence, this allows you to
//! manage most aspects of your identity even without having ready access to the
//! alpha or policy keypair, which allows them to be safely locked away (only to
//! be used during emergencies).
//!
//! The policy itself can require any arbitrary combination of signatures, so
//! it's really up to the identity holder to choose a policy they feel gives
//! them the most benefit.
//!
//! It's important to weigh accessibilty and security here. You can say *all ten
//! of the following identities must sign* in order to recover, but if one of
//! those ten people dies, then you're SOL. If your policy is too difficult to
//! actually satisfy, then you'll likely keep your higher-powered keys laying
//! around more often, increasing your attack surface.
//!
//! Another note: the recovery keys we list must be exact matches: signatures
//! from a subkey of one of those keys won't work. A person must sign a recovery
//! request with whatever key is listed in the policy. The reason is that a
//! recovery request must be able to be processed locally, so subkeys won't be
//! available at the time of verification.

use crate::{
    error::{Error, Result},
    crypto::key::{SecretKey, SignKeypair, SignKeypairPublic, SignKeypairSignature},
    identity::{
        Public,
        identity::IdentityID,
        keychain::{ExtendKeypair, PolicyKeypair, PolicyKeypairSignature, PublishKeypair, RootKeypair},
    },
    util::ser,
};
use getset;
#[cfg(test)] use rand::RngCore;
use serde_derive::{Serialize, Deserialize};
use std::convert::TryInto;
use std::ops::Deref;

object_id! {
    /// A unique identifier for recovery policies.
    PolicyID
}

object_id! {
    /// A unique identifier for recovery requests.
    RequestID
}

/// A condition that goes into a recovery policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyCondition {
    /// All of the given conditions must be met.
    All(Vec<PolicyCondition>),
    /// Any of the given conditions can be met.
    Any(Vec<PolicyCondition>),
    /// Of the given public keys, N many must produce a valid signature in order
    /// for the policy to be ratified.
    OfN {
        /// Must have at least this many signatures.
        must_have: u16,
        /// The keys we're listing as identity recovery keys.
        pubkeys: Vec<SignKeypairPublic>,
    },
    /// A special condition that can never be satisfied. Useful for creating
    /// policies that cannot be fulfilled.
    Deny,
}

impl PolicyCondition {
    /// Tests whether the given signatures match the policy condition
    pub(crate) fn test<F>(&self, signatures: &Vec<SignKeypairSignature>, sigtest: &F) -> Result<()>
        where F: Fn(&SignKeypairPublic, &SignKeypairSignature) -> Result<()>,
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
            Self::OfN { must_have, pubkeys } => {
                let has = pubkeys.iter()
                    .filter_map(|pubkey| {
                        for sig in signatures {
                            if sigtest(pubkey, sig).is_ok() {
                                return Some(());
                            }
                        }
                        None
                    })
                    .count();
                if &(has as u16) < must_have {
                    Err(Error::PolicyConditionMismatch)?;
                }
            }
            Self::Deny => {
                Err(Error::PolicyConditionMismatch)?;
            }
        }
        Ok(())
    }
}

/// A recovery policy.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct RecoveryPolicy {
    id: PolicyID,
    conditions: PolicyCondition,
}

impl RecoveryPolicy {
    /// Create a new recovery policy
    pub(crate) fn new(id: PolicyID, conditions: PolicyCondition) -> Self {
        Self {
            id,
            conditions,
        }
    }

    pub(crate) fn validate_request(&self, identity_id: &IdentityID, request: &PolicyRequest) -> Result<()> {
        // make sure the request signature is valid
        match request.entry().action() {
            PolicyRequestAction::ReplaceKeys(policy, ..) => request.verify(&policy)?,
        }

        // check the identity matches the request
        if identity_id != request.entry().identity_id() {
            Err(Error::RecoveryPolicyRequestIdentityMismatch)?;
        }

        // check the polocy matches the request
        if self.id() != request.entry().policy_id() {
            Err(Error::RecoveryPolicyRequestPolicyMismatch)?;
        }

        // check the signatures match the policy conditions
        let serialized = ser::serialize(request.entry())?;
        self.conditions().test(
            request.signatures(),
            &|pubkey, sig| pubkey.verify(sig, &serialized),
        )?;

        Ok(())
    }
}

/// The actions we can take on a recovery request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRequestAction {
    /// Replace the current policy-controlled keys.
    ReplaceKeys(PolicyKeypair, PublishKeypair, RootKeypair),
}

impl PolicyRequestAction {
    fn reencrypt(self, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        match self {
            Self::ReplaceKeys(policy, publish, root) => {
                let new_policy = policy.reencrypt(old_master_key, new_master_key)?;
                let new_publish = publish.reencrypt(old_master_key, new_master_key)?;
                let new_root = root.reencrypt(old_master_key, new_master_key)?;
                Ok(Self::ReplaceKeys(new_policy, new_publish, new_root))
            }
        }
    }
}

impl Public for PolicyRequestAction {
    fn strip_private(&self) -> Self {
        match self {
            Self::ReplaceKeys(policy, publish, root) => {
                Self::ReplaceKeys(policy.strip_private(), publish.strip_private(), root.strip_private())
            }
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::ReplaceKeys(policy, publish, root) => {
                policy.has_private() || publish.has_private() || root.has_private()
            }
        }
    }
}

/// The inner data of a recovery request. This object is what our recovery
/// compadres sign when they help us execute a recovery request.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct PolicyRequestEntry {
    /// "The ID of the identity we're trying to recover," he said with a boyish
    /// grin.
    identity_id: IdentityID,
    /// The ID of the policy we're trying to satisfy.
    policy_id: PolicyID,
    /// What exactly is it we're trying to do.
    action: PolicyRequestAction,
}

impl PolicyRequestEntry {
    /// Create a new request entry.
    pub(crate) fn new(identity_id: IdentityID, policy_id: PolicyID, action: PolicyRequestAction) -> Self {
        Self {
            identity_id,
            policy_id,
            action,
        }
    }
}

/// A recovery request. Must be signed and validated according to the identity's
/// current [recovery policy](RecoveryPolicy) to be
/// considered valid.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct PolicyRequest {
    /// The ID of this request. This is a signature (using the new policy
    /// keypair) of our `PolicyRequestEntry`.
    id: RequestID,
    /// The actual policy request data: this contains the new policy and the new
    /// recovery key we'll use in the event the request satisfies the current
    /// policy.
    entry: PolicyRequestEntry,
    /// Here, we collect the signaturs needed to fulfill the policy. The request
    /// can only be executed if the signatures match the conditions of the
    /// policy.
    ///
    /// Each signature must sign the `entry` field (the [PolicyRequestEntry]
    /// object).
    signatures: Vec<SignKeypairSignature>,
}

impl PolicyRequest {
    /// Create a new recovery policy request.
    pub(crate) fn new(master_key: &SecretKey, sign_keypair: &PolicyKeypair, entry: PolicyRequestEntry) -> Result<Self> {
        let serialized = ser::serialize(&entry)?;
        let sig = sign_keypair.sign(master_key, &serialized)?;
        let id = RequestID(sig.deref().clone());
        Ok(Self {
            id,
            entry,
            signatures: Vec::new(),
        })
    }

    /// Make sure this policy request is properly signed.
    pub(crate) fn verify(&self, sign_keypair: &PolicyKeypair) -> Result<()> {
        let serialized = ser::serialize(self.entry())?;
        sign_keypair.verify(&PolicyKeypairSignature::from(self.id().deref().clone()), &serialized)
    }

    /// Sign this policy request and add the signature to the `signatures` list.
    /// Generally, this is done by someone in the policy's condition lists,
    /// although that's not enforced in any way.
    pub(crate) fn sign(mut self, master_key: &SecretKey, sign_keypair: &SignKeypair) -> Result<Self> {
        let serialized = ser::serialize(self.entry())?;
        let sig = sign_keypair.sign(master_key, &serialized)?;
        self.signatures_mut().push(sig);
        Ok(self)
    }

    /// Reencrypt this policy request.
    pub(crate) fn reencrypt(mut self, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let new_action = self.entry().action().clone().reencrypt(old_master_key, new_master_key)?;
        self.entry_mut().set_action(new_action);
        Ok(self)
    }
}

impl Public for PolicyRequest {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.entry_mut().set_action(self.entry().action().strip_private());
        clone
    }

    fn has_private(&self) -> bool {
        self.entry().action().has_private()
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
        let conditions = PolicyCondition::Deny;
        let res = conditions.test(&vec![], &|_, _| Ok(()));
        assert_eq!(res.err(), Some(Error::PolicyConditionMismatch));

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
        let action = PolicyRequestAction::ReplaceKeys(new_policy_keypair.clone(), new_publish_keypair.clone(), new_root_keypair.clone());
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
            PolicyRequestAction::ReplaceKeys(_, publish, root) => {
                let new_policy = PolicyKeypair::new_ed25519(&master_key).unwrap();
                let new_action = PolicyRequestAction::ReplaceKeys(new_policy, publish, root);
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
        let action = PolicyRequestAction::ReplaceKeys(new_policy_keypair.clone(), new_publish_keypair.clone(), new_root_keypair.clone());
        let entry = PolicyRequestEntry::new(identity_id.clone(), policy_id.clone(), action);
        let req = PolicyRequest::new(&master_key, &new_policy_keypair, entry).unwrap();

        assert_eq!(req.entry().identity_id(), &identity_id);
        assert_eq!(req.entry().policy_id(), &policy_id);
        match req.entry().action() {
            PolicyRequestAction::ReplaceKeys(policy, publish, root) => {
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
        let action = PolicyRequestAction::ReplaceKeys(new_policy_keypair.clone(), new_publish_keypair.clone(), new_root_keypair.clone());
        let entry = PolicyRequestEntry::new(identity_id.clone(), policy_id.clone(), action);
        let req = PolicyRequest::new(&master_key, &new_policy_keypair, entry).unwrap();

        // i'm detective john kimble
        let obj = "yeah sure you are.";

        let sig = match req.entry().action() {
            PolicyRequestAction::ReplaceKeys(policy, ..) => {
                policy.sign(&master_key, obj.as_bytes()).unwrap()
            }
        };

        let new_master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let req2 = req.reencrypt(&master_key, &new_master_key).unwrap();

        match req2.entry().action() {
            PolicyRequestAction::ReplaceKeys(policy, ..) => {
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
        let action = PolicyRequestAction::ReplaceKeys(new_policy_keypair.clone(), new_publish_keypair.clone(), new_root_keypair.clone());
        let entry = PolicyRequestEntry::new(identity_id.clone(), policy_id.clone(), action);
        let req = PolicyRequest::new(&master_key, &new_policy_keypair, entry).unwrap();

        assert!(req.has_private());
        match req.entry().action() {
            PolicyRequestAction::ReplaceKeys(policy, publish, root) => {
                assert!(policy.has_private());
                assert!(publish.has_private());
                assert!(root.has_private());
            }
        }
        let req2 = req.strip_private();
        assert!(!req2.has_private());
        match req2.entry().action() {
            PolicyRequestAction::ReplaceKeys(policy, publish, root) => {
                assert!(!policy.has_private());
                assert!(!publish.has_private());
                assert!(!root.has_private());
            }
        }
    }
}

