use crate::{
    error::Result,
    identity::{
        AcceptedStamp,
        IdentityID,
    },
    key::{SecretKey, SignKeypairSignature, SignKeypair},
    private::MaybePrivate,
    util::{
        Timestamp,
        sign::DateSigner,
        ser,
    },
};
use getset;
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// A unique identifier for claims.
///
/// We generate this by signing the claim's data in a `DateSigner` with our
/// current private signing key.
///
/// `IdentityID`s are permanent and are not regenerated when the keysets are
/// rotated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimID(SignKeypairSignature);

impl Deref for ClaimID {
    type Target = SignKeypairSignature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Various types of codified relationships, used in relationship claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Relationship {
    /// A familial relationship.
    Family,
    /// A friendship.
    Friend,
    /// An organizational or group membership.
    ///
    /// Note that this doesn't have to be a company or any predefined notion of
    /// an organization, but can really mean "a member of any group" including
    /// but not limited to a book club, a state citizenship, and anything
    /// in-between or beyond.
    OrganizationMember,
    /// Any custom relationship.
    Extension(Vec<u8>),
}

/// A collection of known claims one can make about their identity.
///
/// Note that the claim type itself will always be public, but the data attached
/// to a claim can be either public or private ("private" as in encrypted with
/// our `secret` key in our keyset). This allows others to see that I have made
/// a particular claim (and that others have stamped it) without revealing the
/// private data in that claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClaimSpec {
    /// A claim that this identity is mine (always public).
    ///
    /// This claim should be made any time a new identity is created.
    Identity(IdentityID),
    /// A claim that the name attached to this identity is mine.
    Name(MaybePrivate<String>),
    /// A claim that I own an email address
    Email(MaybePrivate<String>),
    /// A claim that I own a PGP keypair
    PGP(MaybePrivate<String>),
    /// A claim that I reside at a physical address
    HomeAddress(MaybePrivate<String>),
    /// A claim that I am in a relationship with another identity, hopefully
    /// stamped by that identity ='[
    Relation(Relationship, MaybePrivate<IdentityID>),
    /// A claim that I am in a relationship with another entity with some form
    /// of serializable identification (such as a signed certificate, a name,
    /// etc). Can be used to assert relationships to entities outside of the
    /// Stamp protocol (although stamps on these relationships must be provided
    /// by Stamp protocol identities).
    RelationExtension(Relationship, MaybePrivate<Vec<u8>>),
    /// Any kind of claim of identity ownership or possession outside the
    /// defined types.
    ///
    /// This can be something like a state-issued identification, ownership over
    /// an internet domain name, a social networking screen name, etc.
    ///
    /// Effectively, this exists as a catch-all and allows for many more types
    /// of claims than can be thought of here. This could be a JSON string with
    /// a pre-defined schema stored somewhere. It could be an XML document. It
    /// could be binary-encoded data.
    ///
    /// Anything you can dream up that you wish to claim in any format can exist
    /// here.
    Extension(Vec<u8>, MaybePrivate<Vec<u8>>),
}

/// A type used when signing a claim. Contains all data about the claim except
/// the stamps.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Claim {
    /// The unique ID of this claim, created by signing the claim's data in a
    /// `DateSigner` with our current signing keypair.
    id: ClaimID,
    /// The date we created the claim.
    created: Timestamp,
    /// The data we're claiming.
    spec: ClaimSpec,
}

impl Claim {
    /// Create a new claim.
    fn new(id: ClaimID, now: Timestamp, spec: ClaimSpec) -> Self {
        Self {
            id,
            created: now,
            spec,
        }
    }
}

/// A wrapper around a `Claim` that stores its stamps.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct ClaimContainer {
    /// The actual claim data
    claim: Claim,
    /// Stamps that have been made on our claim.
    stamps: Vec<AcceptedStamp>,
}

impl ClaimContainer {
    /// Create a new claim, sign it with our signing key, and return a container
    /// that holds the claim (with an empty set of stamps).
    pub fn new(master_key: &SecretKey, sign_keypair: &SignKeypair, now: Timestamp, spec: ClaimSpec) -> Result<Self> {
        let datesigner = DateSigner::new(&now, &spec);
        let serialized = ser::serialize(&datesigner)?;
        let signature = sign_keypair.sign(master_key, &serialized)?;
        let claim = Claim::new(ClaimID(signature), now, spec);
        Ok(Self {
            claim,
            stamps: Vec::new(),
        })
    }
}

