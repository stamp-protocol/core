//! The recovery module provides methods for recovering an identity if it is
//! "lost" or stolen (ie, the recovery keys are compromised in some way).
//!
//! The idea here is that while the recovery key has ultimate control over the
//! identity, the management of the recovery key(s) require meeting predefined
//! conditions (a recovery policy) that's *signed* by the current recovery key.
//! In other words, if your recovery key is stolen, the thief might be able to
//! masquerade as you for a while, but they will not be able to change the
//! recovery key *without first completing the policy outlined in the recovery
//! section of the identity*.
//!
//! This could be something like getting the new recovery key signed by two or
//! more (pre-selected) trusted parties. Changes to the recovery policy itself
//! require meeting the policy guidelines itself, otherwise the compromised
//! recovery keypair could be used to just erase the policy.
//!
//! This acts as a safeguard against "identity theft."
//! 
//! As an example, you might create a policy that must be signed by two of three
//! identities that you list as trusted. Or you could create a policy where
//! either identity A must sign, OR identity B, C *and* D must sign.
//!
//! It's important to weigh accessibilty and security here. You can say *all ten
//! of the following identities must sign* in order to recover, but if one of
//! those ten people dies, then you're SOL.
//!
//! Another note: the recovery keys we list must be exact matches: signatures
//! from a subkey of one of those keys won't work. A person must sign a recovery
//! request with whatever key is listed in the policy. The reason is that a
//! recovery request must be able to be processed locally, so subkeys won't be
//! available at the time of verification.

use crate::{
    error::Result,
    identity::{
        identity::IdentityID,
    },
    key::{SignKeypair, SignKeypairPublic, SignKeypairSignature},
    //util::sign::SignedValue,
};
use getset;
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// A unique identifier for recovery policies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyID(SignKeypairSignature);

impl Deref for PolicyID {
    type Target = SignKeypairSignature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A unique identifier for recovery requests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestID(SignKeypairSignature);

impl Deref for RequestID {
    type Target = SignKeypairSignature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A condition that goes into a recovery policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        pubkeys: Vec<SignKeypair>,
    },
}

/// A recovery policy. Creates a set of conditions where in order for the policy
/// to validate, we must get signatures from third-party identities.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct RecoveryPolicy {
    /// Our policy ID, which is a signature of the policy itself.
    id: PolicyID,
    /// The conditions under which this policy is satisfied.
    conditions: PolicyCondition,
}

/// The inner data of a recovery request. This object is what our recovery
/// compadres sign when they help us execute a recovery request.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct PolicyRequestEntry {
    /// The ID of the identity we're trying to recover.
    identity_id: IdentityID,
    /// The ID of the policy we're trying to satisfy.
    policy_id: PolicyID,
    /// The new recovery policy that will replace the curent one (if this
    /// recovery request satisfies the policy).
    new_policy: RecoveryPolicy,
    /// The public key of the new recovery key we're hoping to use to replace
    /// the old key (if the recovery request satisfies the policy).
    new_recovery_key: SignKeypairPublic,
}

/// A recovery request. Must be signed and validated according to the identity's
/// current [recovery policy](crate::identity::recovery::RecoveryPolicy) to be
/// considered valid.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct PolicyRequest {
    /// The ID of this request. This is a signature (using the new recovery
    /// keypair) of our `PolicyRequestEntry`.
    request_id: RequestID,
    /// The actual policy request data: this contains the new policy and the new
    /// recovery key we'll use in the event the request satisfies the current
    /// policy.
    entry: PolicyRequestEntry,
    /// The signatures on this recovery request's `new_recovery_pubkey` field.
    /// These must satisfy the conditions of the current recovery policy before
    /// this request can be considered valid.
    signatures: Vec<SignKeypairSignature>,
}

/// A collection of recovery requests and recovery policies.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Recovery {
}

impl Recovery {
    pub fn new() -> Result<Self> {
        Ok(Self {
        })
    }
}

