//! The recovery system provides a method for replacing the recovery key (which
//! has ultimate control over the keychain) in the event it is lost or stolen.
//!
//! The idea here is that using our policy keypair, we can create and sign a
//! recovery policy that allows us to generate a new recovery keypair and
//! assign it to our identity, provided that it is ratified by some combination
//! of signatures from other keys. So let's say you create a recovery policy
//! that requires you to have at least three signatures of the five public
//! keys that you list (which might belong to family members, identity
//! companies, or other trusted third parties). If you lose your recovery key,
//! you can create a recovery request, sign it with the recovery key you hope
//! to replace the lost one, and try to get three or more signatures on that
//! request from your trusted circle. If you get the signatures you need, the
//! protocol will "honor" the replacement request and grant you your new
//! recovery key, which can be used to then rotate the keys in your keychain.
//!
//! The recovery request can do two things: replace the recovery key, and also
//! set a new policy to replace the old one. In essence, this allows you to
//! manage most aspects of your identity even without having ready access to the
//! recovery keypair or policy keypair, which allows them to be safely locked
//! away (only to be used during emergencies).
//!
//! The policy itself can require any arbitrary combination of signatures, so
//! it's really up to the identity holder to choose a policy they feel gives
//! them the most benefit.
//!
//! It's important to weigh accessibilty and security here. You can say *all ten
//! of the following identities must sign* in order to recover, but if one of
//! those ten people dies, then you're SOL. If your policy is too difficult to
//! actually satisfy, then you'll likely keep your recovery key or policy key
//! hanging around, which might increase your attack surface.
//!
//! Another note: the recovery keys we list must be exact matches: signatures
//! from a subkey of one of those keys won't work. A person must sign a recovery
//! request with whatever key is listed in the policy. The reason is that a
//! recovery request must be able to be processed locally, so subkeys won't be
//! available at the time of verification.

use crate::{
    error::Result,
    crypto::key::{SecretKey, SignKeypairPublic, SignKeypairSignature},
    identity::{
        Public,
        identity::IdentityID,
        keychain::{ExtendKeypair, PolicyKeypair, PolicyKeypairSignature, PublishKeypair, RootKeypair},
    },
    util::ser,
};
use getset;
use serde_derive::{Serialize, Deserialize};
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
        match request.entry().action() {
            PolicyRequestAction::ReplaceKeys(policy, ..) => request.verify(&policy)?,
        }
        drop(identity_id);
        // TODO: make sure the request entry identity_id matches the current
        //       identity id
        // TODO: make sure the request entry policy matches the current policy
        // TODO: make sure each request signature actually matches the entry
        // TODO: make sure the given signatures match the conditions in the
        //       policy itself
        unimplemented!();
    }
}

/// The actions we can take on a recovery request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRequestAction {
    /// Replace the current policy-controlled keys.
    ReplaceKeys(PolicyKeypair, PublishKeypair, RootKeypair),
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
    //use super::*;

    #[test]
    fn policy_validate_request() {
        unimplemented!();
    }

    #[test]
    fn policy_request_action_strip_private() {
        unimplemented!();
    }

    #[test]
    fn policy_request_action_has_private() {
        unimplemented!();
    }

    #[test]
    fn policy_request_new() {
        unimplemented!();
    }

    #[test]
    fn policy_request_verify() {
        unimplemented!();
    }

    #[test]
    fn policy_request_strip_private() {
        unimplemented!();
    }

    #[test]
    fn policy_request_has_private() {
        unimplemented!();
    }
}

