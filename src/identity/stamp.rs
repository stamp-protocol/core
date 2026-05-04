//! A stamp is a signed seal of approval on a [claim](crate::identity::claim::Claim).
//!
//! Stamps form the underlying trust network of the Stamp protocol. They are
//! seals of approval, and depending on who you trust, allow you to determine if
//! a particular identity is "real" or trusted.

use crate::{
    identity::{claim::ClaimID, instance::IdentityID},
    util::{ser::SerText, Timestamp},
};
use getset;
use rasn::{AsnType, Decode, Decoder, Encode, Encoder};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

object_id! {
    /// A unique identifier for stamps.
    StampID
}

/// Why we are revoking a stamp.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum RevocationReason {
    /// No reason. Feeling cute today, might revoke a stamp, IDK.
    #[rasn(tag(explicit(0)))]
    Unspecified,
    /// Replacing this stamp with another.
    #[rasn(tag(explicit(2)))]
    Superseded,
    /// The stamped identity has been compromised
    #[rasn(tag(explicit(3)))]
    Compromised,
    /// This stamp was signed by a compromised key and cannot be trusted
    #[rasn(tag(explicit(4)))]
    Invalid,
}

/// The confidence of a stamp being made.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Confidence {
    /// You are certain the claim is false. This might be issued if you determine someone
    /// is impersonating a valid identity. Obviously, the stampee will likely not add
    /// this stamp to their identity, but it can serve as a warning to those who trust
    /// you.
    #[rasn(tag(explicit(0)))]
    Negative,
    /// Some verification of the claim happened, but it was quick and
    /// dirty.
    #[rasn(tag(explicit(1)))]
    Low,
    /// We verified the claim using a decent amount of diligence. This could be
    /// like checking someone's state-issued ID.
    #[rasn(tag(explicit(2)))]
    Medium,
    /// The claim was extensively investigated: birth certificates, background
    /// checks, photo verification.
    #[rasn(tag(explicit(3)))]
    High,
    /// We climbed mountains, pulled teeth, interrogated family members, and are
    /// absolutely positive that this claim is true in every way.
    ///
    /// This should really only be used between people who have known each other
    /// for years (like family).
    #[rasn(tag(explicit(4)))]
    Ultimate,
}

/// An inner struct type created when making a stamp. This is what is wrapped in a
/// [transaction][crate::dag::Transaction] for signing (and possibly
/// publishing).
#[derive(
    Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters,
)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampEntry {
    /// The ID of the identity that is stamping.
    #[rasn(tag(explicit(0)))]
    stamper: IdentityID,
    /// The ID of the identity being stamped.
    #[rasn(tag(explicit(1)))]
    stampee: IdentityID,
    /// The ID of the claim we're stamping.
    #[rasn(tag(explicit(2)))]
    claim_id: ClaimID,
    /// How much confidence the stamper has that the claim being stamped is
    /// valid.
    #[rasn(tag(explicit(3)))]
    confidence: Confidence,
    /// The date this stamp expires (if at all). The stamper can choose to set
    /// this expiration date if they feel their stamp is only good for a set
    /// period of time.
    #[rasn(tag(explicit(4)))]
    expires: Option<Timestamp>,
}

impl StampEntry {
    /// Create a new stamp entry.
    pub fn new<T: Into<Timestamp>>(
        stamper: IdentityID,
        stampee: IdentityID,
        claim_id: ClaimID,
        confidence: Confidence,
        expires: Option<T>,
    ) -> Self {
        Self {
            stamper,
            stampee,
            claim_id,
            confidence,
            expires: expires.map(|x| x.into()),
        }
    }
}

/// A stamp of approval on a claim.
///
/// Effectively, this is a signature and a collection of stamp data.
///
/// This is created by the stamper, and it is up to the claim owner to save the
/// stamp to their identity.
#[derive(
    Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters,
)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Stamp {
    /// The [transaction id][crate::dag::TransactionID] of the transaction that created
    /// this stamp.
    #[rasn(tag(explicit(0)))]
    id: StampID,
    /// The stamp entry, containing all the actual stamp data.
    #[rasn(tag(explicit(1)))]
    entry: StampEntry,
    /// The date this stamp was created
    #[rasn(tag(explicit(2)))]
    created: Timestamp,
    /// An optional revocation for this stamp
    #[rasn(tag(explicit(3)))]
    revocation: Option<RevocationReason>,
}

impl Stamp {
    pub(crate) fn new(id: StampID, entry: StampEntry, created: Timestamp) -> Self {
        Self {
            id,
            entry,
            created,
            revocation: None,
        }
    }
}

impl SerText for Stamp {}
