//! Is it stamped?

use crate::{
    error::Result,
    identity::{
        Claim,
        IdentityID,
    },
    key::{SecretKey, SignKeypairSignature, SignKeypair},
    ser,
    util::{
        Timestamp,
        sign::DateSigner,
    },
};
use getset;
use serde_derive::{Serialize, Deserialize};

/// A set of metadata that is signed when a stamp is created that is stored
/// alongside the signature itself.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampSignatureMetadata {
    /// The ID of the identity that is stamping.
    stamper: IdentityID,
    /// How much confidence the stamper has that the claim being stamped is
    /// valid. This is a value between 0 and 255, and is ultimately a ratio
    /// via `c / 255`, where 0.0 is "lowest confidence" and 1.0 is "ultimate
    /// confidence." Keep in mind that 0 here is not "absolutely zero
    /// confidence" as otherwise the stamp wouldn't be occuring in the first
    /// place.
    confidence: u8,
    /// Filled in by the stamper, the date the claim was stamped
    date_signed: Timestamp,
}

impl StampSignatureMetadata {
    /// Create a new stamp signature metadata object.
    pub fn new(stamper: IdentityID, confidence: u8, date_signed: Timestamp) -> Self {
        Self {
            stamper,
            confidence,
            date_signed,
        }
    }
}

/// A somewhat ephemeral container used to serialize a set of data and sign it.
/// Includes metadata about the signature (`SignatureEntry`)
/// A struct used to sign a claim, only used for signing and verification (but
/// not storage).
///
/// Note that in the case of a *private* claim being signed, the signature
/// applies to the encrypted entry, not the decrypted entry, allowing peers to
/// verify that X stamped Y's claim without *knowing* Y's claim.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampSignatureContainer {
    /// The metadata we're signing with this signature.
    meta: StampSignatureMetadata,
    /// The claim we're signing.
    claim: Claim,
}

impl StampSignatureContainer {
    /// Create a new sig container
    fn new(meta: StampSignatureMetadata, claim: Claim) -> Self {
        Self {
            meta,
            claim,
        }
    }
}

/// A stamp of approval on a claim.
///
/// This is created by the stamper, and it is up to the claim owner to save the
/// stamp to their identity (as well as to fill in the `recorded` date).
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Stamp {
    /// The signature metadata.
    signature_meta: StampSignatureMetadata,
    /// Signature of the attached `signature_entry` data.
    signature: SignKeypairSignature,
}

impl Stamp {
    /// Stamp a claim.
    ///
    /// This must be created by the identity validating the claim, using their
    /// private signing key.
    pub fn stamp(master_key: &SecretKey, sign_keypair: &SignKeypair, stamper: &IdentityID, confidence: u8, now: &Timestamp, claim: &Claim) -> Result<Self> {
        let meta = StampSignatureMetadata::new(stamper.clone(), confidence, now.clone());
        let container = StampSignatureContainer::new(meta.clone(), claim.clone());
        let ser = ser::serialize(&container)?;
        let signature = sign_keypair.sign(master_key, &ser)?;
        Ok(Self {
            signature_meta: meta,
            signature,
        })
    }

    /// Verify a stamp.
    ///
    /// Must have the stamper's public key, which can be obtained by querying
    /// whatever networks means are accessible for the `IdentityID` in the
    /// `signature_meta.stamper` field.
    pub fn verify(&self, sign_keypair: &SignKeypair, claim: &Claim) -> Result<()> {
        let container = StampSignatureContainer::new(self.signature_meta.clone(), claim.clone());
        let ser = ser::serialize(&container)?;
        sign_keypair.verify(&self.signature, &ser)
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
}


