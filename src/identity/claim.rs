//! A claim is any information we can provide to distinguish our identity. This
//! can be as simple as "this identity is mine" (which is the default claim and
//! always exists in any identity) or "this email is mine" to something like "I
//! have blonde hair, blue eyes, and a cute little button nose."
//!
//! However, a claim by itself is not meaningful or useful unless it is
//! [stamped](crate::identity::stamp) by someone withing your trust network.

use crate::{
    error::Result,
    identity::{
        AcceptedStamp,
        IdentityID,
    },
    key::{SecretKey, SignKeypair},
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

object_id! {
    /// A unique identifier for claims.
    ///
    /// We generate this by signing the claim's data in a `DateSigner` with our
    /// current private signing key.
    ///
    /// `IdentityID`s are permanent and are not regenerated when the keysets are
    /// rotated.
    ClaimID
}

/// Various types of codified relationships, used in relationship claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelationshipType {
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

/// Defines a relationship.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Relationship<T> {
    /// The type of relationship we have.
    relation: RelationshipType,
    /// Who the relationship is with.
    who: T,
}

impl<T> Relationship<T> {
    /// Create a new relationship.
    pub fn new(relation: RelationshipType, who: T) -> Self {
        Self {
            relation,
            who,
        }
    }
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
    ///
    /// NOTE: we *could* reimplement *all* of PGP and allow people to verify
    /// this themselves via cross-signing, but seems more appropriate to keep
    /// the spec lean and instead require third-parties to verify the claim.
    PGP(MaybePrivate<String>),
    /// A claim that I reside at a physical address
    HomeAddress(MaybePrivate<String>),
    /// A claim that I am in a relationship with another identity, hopefully
    /// stamped by that identity ='[
    Relation(MaybePrivate<Relationship<IdentityID>>),
    /// A claim that I am in a relationship with another entity with some form
    /// of serializable identification (such as a signed certificate, a name,
    /// etc). Can be used to assert relationships to entities outside of the
    /// Stamp protocol (although stamps on these relationships must be provided
    /// by Stamp protocol identities).
    RelationExtension(MaybePrivate<Relationship<Vec<u8>>>),
    /// Any kind of claim of identity ownership or possession outside the
    /// defined types. This includes a public field (which could be used as a
    /// key) and a maybe-private field which would be a value (or a key and
    /// value if the public field is empty).
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

impl ClaimSpec {
    fn strip_private(&self) -> Self {
        match self {
            Self::Identity(id) => Self::Identity(id.clone()),
            Self::Name(val) => Self::Name(val.strip_private()),
            Self::Email(val) => Self::Email(val.strip_private()),
            Self::PGP(val) => Self::PGP(val.strip_private()),
            Self::HomeAddress(val) => Self::HomeAddress(val.strip_private()),
            Self::Relation(val) => Self::Relation(val.strip_private()),
            Self::RelationExtension(val) => Self::RelationExtension(val.strip_private()),
            Self::Extension(key, val) => Self::Extension(key.clone(), val.strip_private()),
        }
    }

    /// Re-encrypt this claim spec's private data, if it has any
    pub(crate) fn reencrypt(self, current_key: &SecretKey, new_key: &SecretKey) -> Result<Self> {
        let spec = match self.clone() {
            Self::Name(MaybePrivate::Private(tag, Some(val))) => Self::Name(MaybePrivate::Private(tag, Some(val.reencrypt(current_key, new_key)?))),
            Self::Email(MaybePrivate::Private(tag, Some(val))) => Self::Email(MaybePrivate::Private(tag, Some(val.reencrypt(current_key, new_key)?))),
            Self::PGP(MaybePrivate::Private(tag, Some(val))) => Self::PGP(MaybePrivate::Private(tag, Some(val.reencrypt(current_key, new_key)?))),
            Self::HomeAddress(MaybePrivate::Private(tag, Some(val))) => Self::HomeAddress(MaybePrivate::Private(tag, Some(val.reencrypt(current_key, new_key)?))),
            Self::Relation(MaybePrivate::Private(tag, Some(val))) => Self::Relation(MaybePrivate::Private(tag, Some(val.reencrypt(current_key, new_key)?))),
            Self::RelationExtension(MaybePrivate::Private(tag, Some(val))) => Self::RelationExtension(MaybePrivate::Private(tag, Some(val.reencrypt(current_key, new_key)?))),
            Self::Extension(key, MaybePrivate::Private(tag, Some(val))) => Self::Extension(key, MaybePrivate::Private(tag, Some(val.reencrypt(current_key, new_key)?))),
            _ => self,
        };
        Ok(spec)
    }
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
    pub fn new<T: Into<Timestamp>>(master_key: &SecretKey, sign_keypair: &SignKeypair, now: T, spec: ClaimSpec) -> Result<Self> {
        let now: Timestamp = now.into();
        // stripping returns either the public data or the HMAC of the private
        // data, giving us an unchanging item we van verify.
        let stripped_spec = spec.strip_private();
        let datesigner = DateSigner::new(&now, &stripped_spec);
        let serialized = ser::serialize(&datesigner)?;
        let signature = sign_keypair.sign(master_key, &serialized)?;
        let claim = Claim::new(ClaimID(signature), now, spec);
        Ok(Self {
            claim,
            stamps: Vec::new(),
        })
    }
}

