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
    error::{Error, Result},
    identity::{
        identity::IdentityID,
    },
    crypto::key::{SignKeypair, SignKeypairPublic, SignKeypairSignature},
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
    /// A special condition that can never be satisfied. Useful for creating
    /// policies that cannot be fulfilled.
    Deny,
}

/// The actions we can take on a recovery request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRequestAction {
    /// Replace the current recovery policy.
    ReplacePolicy(PolicyCondition),
    /// Replace the current recovery key.
    ReplaceRootKey(SignKeypairPublic),
    /// Replace both the current policy *and* key.
    ReplacePolicyAndRootKey(PolicyCondition, SignKeypairPublic),
}

/// A recovery policy.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct RecoveryPolicy {
    id: PolicyID,
    conditions: PolicyCondition,
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

/// A self-signed signature object. This doesn't need to satisfy the current
/// recovery policy, because policy key signatures override policies. It does
/// need to be verifiable even in the event that the policy keypair has been
/// rotated, so we store the current alpha key's signature of the current policy
/// key here so we can verify into the past.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct SelfSigned {

}

/// The object we use to sign our request. It can be a set of signatures that
/// satisfy the conditions of the linked policy, or it can be self-signed by our
/// policy keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRequestSignatures {
    /// A set of signatures needed to satisfy a recovery policy, generally from
    /// pre-selected trusted peer identity holders (like your grandparents).
    Peer(Vec<SignKeypairSignature>),
    /// A self-signed policy request (using our policy key, and the current
    /// alpha keypair signature chain).
    SelfSigned(SelfSigned),
}

/// A recovery request. Must be signed and validated according to the identity's
/// current [recovery policy](RecoveryPolicy) to be
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
    signatures: PolicyRequestSignatures,
}

/// An executed policy. Effectively, this is a [policy](RecoveryPolicy) matched
/// with a [policy request](PolicyRequest). This must be signed with our new
/// recovery keypair when stored.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct ExecutedPolicy {
    policy: RecoveryPolicy,
    request: PolicyRequest,
}

/// A collection of recovery requests and recovery policies.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Recovery {
    /// The recoveries we've performed, each one signed by the replacement
    /// recovery key instated by the policy request.
    executed: Vec<ExecutedPolicy>,
}

impl Recovery {
    pub fn new() -> Result<Self> {
        Ok(Self {
            executed: vec![],
        })
    }

    pub(crate) fn verify_publish(&self, _publish_keypair: &SignKeypair) -> Result<()> {
        Err(Error::PolicyVerificationFailure)
    }

    pub(crate) fn verify_root(&self, _root_keypair: &SignKeypair) -> Result<()> {
        Err(Error::PolicyVerificationFailure)
    }
}

