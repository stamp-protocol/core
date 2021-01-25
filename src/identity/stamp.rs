//! A stamp is a signed seal of approval on a [claim](crate::identity::Claim).

use crate::{
    error::Result,
    identity::{
        {Claim, ClaimID},
        IdentityID,
    },
    key::{SecretKey, SignKeypairSignature, SignKeypair},
    util::{
        Timestamp,
        sign::DateSigner,
        ser,
    },
};
use getset;
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

object_id! {
    /// A unique identifier for stamps.
    ///
    /// A stamp is a signature on a claim, and this ID is that signature.
    StampID
}

/// The confidence of a stamp being made.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Confidence {
    /// The stamp is being made with absolutely no verification whatsoever.
    None,
    /// Some verification of the claim happened, but it was quick and dirty.
    Low,
    /// We verified the claim using a decent amount of diligence. This could be
    /// like checking someone's state-issued ID.
    Medium,
    /// The claim was extensively investigated: birth certificates, background
    /// checks, photo verification.
    High,
    /// We climbed mountains, pulled teeth, interrogated family members, and are
    /// absolutely positive that this claim is true in every way.
    ///
    /// This should really only be used between people who have known each other
    /// for years (like family).
    Extreme,
}

/// A set of data that is signed when a stamp is created that is stored
/// alongside the signature itself.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampEntry {
    /// The ID of the identity that is stamping.
    stamper: IdentityID,
    /// The ID of the identity being stamped.
    stampee: IdentityID,
    /// The ID of the claim we're stamping.
    claim_id: ClaimID,
    /// How much confidence the stamper has that the claim being stamped is
    /// valid. This is a value between 0 and 255, and is ultimately a ratio
    /// via `c / 255`, where 0.0 is "lowest confidence" and 1.0 is "ultimate
    /// confidence." Keep in mind that 0 here is not "absolutely zero
    /// confidence" as otherwise the stamp wouldn't be occurring in the first
    /// place.
    confidence: Confidence,
    /// Filled in by the stamper, the date the claim was stamped.
    date_signed: Timestamp,
    /// The date this stamp expires (if at all). The stamper can choose to set
    /// this expiration date if they feel their stamp is only good for a set
    /// period of time.
    expires: Option<Timestamp>,
}

impl StampEntry {
    /// Create a new stamp entry.
    fn new<T: Into<Timestamp>>(stamper: IdentityID, stampee: IdentityID, claim_id: ClaimID, confidence: Confidence, date_signed: T, expires: Option<T>) -> Self {
        Self {
            stamper,
            stampee,
            claim_id,
            confidence,
            date_signed: date_signed.into(),
            expires: expires.map(|x| x.into()),
        }
    }
}

/// A somewhat ephemeral container used specifically for signing a stamp entry
/// along with the claim being stamped. This container is not stored anywhere,
/// but rather we just store the resulting signature.
///
/// Note that in the case of a claim with private data being signed, the
/// signature applies to the encrypted entry, not the decrypted entry, allowing
/// anyone to verify that X stamped Y's claim without *knowing* Y's claim.
#[derive(Debug, Clone, Serialize, getset::Getters, getset::MutGetters, getset::Setters)]
pub struct StampSignatureContainer<'a, 'b> {
    /// The stamp entry we're signing with this signature.
    entry: &'a StampEntry,
    /// The claim we're signing.
    claim: &'b Claim,
}

impl<'a, 'b> StampSignatureContainer<'a, 'b> {
    /// Create a new sig container
    fn new(entry: &'a StampEntry, claim: &'b Claim) -> Self {
        Self {
            entry,
            claim,
        }
    }
}

/// A stamp of approval on a claim.
///
/// Effectively, this is a signature and a collection of stamp data.
///
/// This is created by the stamper, and it is up to the claim owner to save the
/// stamp to their identity (using the `AcceptedStamp` object).
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Stamp {
    /// This stamp's signature, and by remarkable coincidence, also its unique
    /// identifier.
    id: StampID,
    /// The stamp entry, containing all the actual stamp data.
    entry: StampEntry,
}

impl Stamp {
    /// Stamp a claim.
    ///
    /// This must be created by the identity validating the claim, using their
    /// private signing key.
    pub fn stamp<T: Into<Timestamp>>(master_key: &SecretKey, sign_keypair: &SignKeypair, stamper: &IdentityID, stampee: &IdentityID, confidence: Confidence, now: T, claim: &Claim, expires: Option<T>) -> Result<Self> {
        let entry = StampEntry::new(stamper.clone(), stampee.clone(), claim.id().clone(), confidence, now, expires);
        let container = StampSignatureContainer::new(&entry, claim);
        let ser = ser::serialize(&container)?;
        let signature = sign_keypair.sign(master_key, &ser)?;
        Ok(Self {
            id: StampID(signature),
            entry: entry,
        })
    }

    /// Verify a stamp.
    ///
    /// Must have the stamper's public key, which can be obtained by querying
    /// whatever networks means are accessible for the `IdentityID` in the
    /// `entry.stamper` field.
    pub fn verify(&self, sign_keypair: &SignKeypair, claim: &Claim) -> Result<()> {
        let container = StampSignatureContainer::new(self.entry(), claim);
        let ser = ser::serialize(&container)?;
        sign_keypair.verify(&self.id, &ser)
    }
}

/// A stamp that has been counter-signed by our signing private key and accepted
/// into our identity. Ie, a stamped stamp.
///
/// This is created by the identity owner after receiving a signed stamp. The
/// idea here is that a stamp is not full valid until it has been accepted by us
/// for inclusion into the identity.
///
/// Any schmuck can stamp any of our claims, but those stamps are not included
/// in our identity (and should be disregarded by others) until we accept them.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct AcceptedStamp {
    /// The stamp itself.
    stamp: Stamp,
    /// The date this stamp was saved (from the claim owner's point of view)
    recorded: Timestamp,
    /// The signature of the stamp we're accepting, created by signing the stamp
    /// in a `DateSigner` with our current signing keypair.
    signature: SignKeypairSignature,
}

impl AcceptedStamp {
    /// Accept a stamp.
    pub fn accept(master_key: &SecretKey, sign_keypair: &SignKeypair, stamp: Stamp, now: Timestamp) -> Result<Self> {
        let datesigner = DateSigner::new(&now, &stamp);
        let serialized = ser::serialize(&datesigner)?;
        let signature = sign_keypair.sign(&master_key, &serialized)?;
        Ok(Self {
            stamp,
            recorded: now,
            signature,
        })
    }

    /// Verify the accepted stamp. Note that we cannot verify the stamp itself
    /// without the signing identity being known, so for now we just verify the
    /// acceptance.
    pub fn verify(&self, sign_keypair: &SignKeypair) -> Result<()> {
        let datesigner = DateSigner::new(self.recorded(), self.stamp());
        let serialized = ser::serialize(&datesigner)?;
        sign_keypair.verify(self.signature(), &serialized)
    }
}

object_id! {
    /// A unique identifier for a stamp revocation.
    ///
    /// A stamp is a signature on a claim, and this ID is that signature.
    StampRevocationID
}

/// An object that contains a stamp revocation's inner data. Its signature is
/// what gives the revocation its ID.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampRevocationEntry {
    /// The identity ID of the original stamper (which must match the identity
    /// ID of the revoker).
    stamper: IdentityID,
    /// The identity ID of the recipient of the original stamp.
    stampee: IdentityID,
    /// The ID of the stamp we're revoking.
    stamp_id: StampID,
    /// Date revoked
    date_revoked: Timestamp,
}

impl StampRevocationEntry {
    /// Create a new stamp revocaiton entry.
    fn new(stamper: IdentityID, stampee: IdentityID, stamp_id: StampID, date_revoked: Timestamp) -> Self {
        Self {
            stamper,
            stampee,
            stamp_id,
            date_revoked,
        }
    }
}

/// An object published when a stamper wishes to revoke their stamp.
///
/// If this is not signed by the same identity that made the original stamp, it
/// must be ignored. Note, however, that the original stamper's signing key may
/// have changed since then, so we must look through their revoked keys when
/// checking if this revocation is valid. If any of their signing keys match the
/// original stamp, then it's a valid revocation.
///
/// Effectively, if the same identity can verify both the original stamp and the
/// revocation, then the revocation is valid.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampRevocation {
    /// The unique ID of this recovation, which also happens to be the signature
    /// of the revocation.
    id: StampRevocationID,
    /// Holds the revocations inner data.
    entry: StampRevocationEntry,
}

impl StampRevocation {
    /// Create a new stamp revocation
    pub fn new<T: Into<Timestamp>>(master_key: &SecretKey, sign_keypair: &SignKeypair, stamper: IdentityID, stampee: IdentityID, stamp_id: StampID, date_revoked: T) -> Result<Self> {
        let entry = StampRevocationEntry::new(stamper, stampee, stamp_id, date_revoked.into());
        let serialized = ser::serialize(&entry)?;
        let sig = sign_keypair.sign(master_key, &serialized)?;
        Ok(Self {
            id: StampRevocationID(sig),
            entry,
        })
    }
}

