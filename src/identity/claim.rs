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
        Public,
    },
    crypto::key::{SecretKey, SignKeypair},
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
    ClaimID
}

/// Various types of codified relationships, used in relationship claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RelationshipType {
    /// An organizational or group membership.
    ///
    /// Note that this doesn't have to be a company or any predefined notion of
    /// an organization, but can really mean "a member of any group" including
    /// but not limited to a book club, a state citizenship, a murder of crows,
    /// and anything in-between or beyond.
    OrganizationMember,
    /// Any custom relationship.
    Extension(Vec<u8>),
}

/// Defines a relationship.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Relationship<T> {
    /// The type of relationship we have.
    ty: RelationshipType,
    /// Who the relationship is with.
    subject: T,
}

impl<T> Relationship<T> {
    /// Create a new relationship.
    pub fn new(ty: RelationshipType, subject: T) -> Self {
        Self {
            ty,
            subject,
        }
    }
}

/// A thin wrapper around binary data in claims. Obnoxious, but useful for
/// (de)serialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimBin(#[serde(with = "crate::util::ser::human_bytes")] Vec<u8>);

impl From<ClaimBin> for Vec<u8> {
    fn from(val: ClaimBin) -> Self {
        let ClaimBin(vec) = val;
        vec
    }
}

impl From<Vec<u8>> for ClaimBin {
    fn from(val: Vec<u8>) -> Self {
        Self(val)
    }
}

impl Deref for ClaimBin {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
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
    /// A claim that I own an email address.
    Email(MaybePrivate<String>),
    /// A claim that the attached photo is a photo of me.
    Photo(MaybePrivate<ClaimBin>),
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
    RelationExtension(MaybePrivate<Relationship<ClaimBin>>),
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
    Extension(String, MaybePrivate<ClaimBin>),
}

impl ClaimSpec {
    /// Re-encrypt this claim spec's private data, if it has any
    pub(crate) fn reencrypt(self, current_key: &SecretKey, new_key: &SecretKey) -> Result<Self> {
        let spec = match self.clone() {
            Self::Name(maybe) => Self::Name(maybe.reencrypt(current_key, new_key)?),
            Self::Email(maybe) => Self::Email(maybe.reencrypt(current_key, new_key)?),
            Self::PGP(maybe) => Self::PGP(maybe.reencrypt(current_key, new_key)?),
            Self::HomeAddress(maybe) => Self::HomeAddress(maybe.reencrypt(current_key, new_key)?),
            Self::Relation(maybe) => Self::Relation(maybe.reencrypt(current_key, new_key)?),
            Self::RelationExtension(maybe) => Self::RelationExtension(maybe.reencrypt(current_key, new_key)?),
            Self::Extension(key, maybe) => Self::Extension(key, maybe.reencrypt(current_key, new_key)?),
            _ => self,
        };
        Ok(spec)
    }

    /// Determines if this claim has private data associated with it. Note that
    /// this doesn't care if we have a MaybePrivate:Private, but rather if there
    /// is actually private data present within that MaybePrivate.
    ///
    /// See [MaybePrivate::has_private](crate::private::MaybePrivate::has_private)
    pub(crate) fn has_private(&self) -> bool {
        match self {
            Self::Name(val) => val.has_private(),
            Self::Email(val) => val.has_private(),
            Self::PGP(val) => val.has_private(),
            Self::HomeAddress(val) => val.has_private(),
            Self::Relation(val) => val.has_private(),
            Self::RelationExtension(val) => val.has_private(),
            Self::Extension(_, val) => val.has_private(),
            _ => false,
        }
    }
}

impl Public for ClaimSpec {
    fn strip_private(&self) -> Self {
        match self {
            Self::Name(val) => Self::Name(val.strip_private()),
            Self::Email(val) => Self::Email(val.strip_private()),
            Self::PGP(val) => Self::PGP(val.strip_private()),
            Self::HomeAddress(val) => Self::HomeAddress(val.strip_private()),
            Self::Relation(val) => Self::Relation(val.strip_private()),
            Self::RelationExtension(val) => Self::RelationExtension(val.strip_private()),
            Self::Extension(key, val) => Self::Extension(key.clone(), val.strip_private()),
            _ => self.clone(),
        }
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

impl Public for Claim {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_spec(clone.spec().strip_private());
        clone
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

    /// Determines if this claim has private data associated with it.
    pub fn has_private(&self) -> bool {
        self.claim().spec().has_private()
    }
}

impl Public for ClaimContainer {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_claim(clone.claim().strip_private());
        clone
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::Error,
        identity::IdentityID,
        util::Timestamp,
    };

    #[test]
    fn claimspec_reencrypt() {
        macro_rules! claim_reenc {
            ($claimtype:ident, $val:expr, $createfn:expr, $getmaybe:expr) => {
                let val = $val;
                let master_key = SecretKey::new_xsalsa20poly1305();
                let private = MaybePrivate::new_private(&master_key, val.clone()).unwrap();
                let spec = $createfn(private);
                assert_eq!($getmaybe(spec.clone()).open(&master_key).unwrap(), val);

                let master_key2 = SecretKey::new_xsalsa20poly1305();
                assert!(master_key != master_key2);
                let spec2 = spec.reencrypt(&master_key, &master_key2).unwrap();
                let maybe2 = $getmaybe(spec2);
                assert_eq!(maybe2.open(&master_key), Err(Error::CryptoOpenFailed));
                assert_eq!(maybe2.open(&master_key2).unwrap(), val);

                let public = MaybePrivate::new_public(val.clone());
                let spec = $createfn(public);
                let spec2 = spec.clone().reencrypt(&master_key, &master_key2).unwrap();
                match ($getmaybe(spec), $getmaybe(spec2)) {
                    (MaybePrivate::Public(val), MaybePrivate::Public(val2)) => {
                        assert_eq!(val, val2);
                    }
                    _ => panic!("Bad claim type {}", stringify!($claimtype)),
                }
            };
            ($claimtype:ident, $val:expr) => {
                claim_reenc!{
                    $claimtype,
                    $val,
                    |maybe| { ClaimSpec::$claimtype(maybe) },
                    |spec: ClaimSpec| if let ClaimSpec::$claimtype(maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
                }
            };
        }

        // first test Identity claims, which our dumb macro above doesn't handle
        let master_key = SecretKey::new_xsalsa20poly1305();
        let master_key2 = SecretKey::new_xsalsa20poly1305();
        let spec = ClaimSpec::Identity(IdentityID::blank());
        let spec2 = spec.clone().reencrypt(&master_key, &master_key2).unwrap();
        match (spec, spec2) {
            (ClaimSpec::Identity(id), ClaimSpec::Identity(id2)) => assert_eq!(id, id2),
            _ => panic!("Bad claim type: Identity"),
        }
        claim_reenc!{ Name, String::from("Marty Malt") }
        claim_reenc!{ Email, String::from("marty@sids.com") }
        claim_reenc!{ PGP, String::from("12345") }
        claim_reenc!{ HomeAddress, String::from("111 blumps ln") }
        claim_reenc!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::blank()) }
        claim_reenc!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![1, 2, 3, 4, 5])) }
        claim_reenc!{
            Extension,
            ClaimBin(vec![7, 3, 2, 90]),
            |maybe| { ClaimSpec::Extension(String::from("id:state:ca"), maybe) },
            |spec: ClaimSpec| {
                match spec {
                    ClaimSpec::Extension(_, maybe) => maybe,
                    _ => panic!("bad claim type: {}", stringify!($claimtype)),
                }
            }
        }
    }

    #[test]
    fn claimcontainer_claimspec_has_private() {
        macro_rules! claim_pub_priv {
            ($claimtype:ident, $val:expr, $createfn:expr, $getmaybe:expr) => {
                let val = $val;
                let master_key = SecretKey::new_xsalsa20poly1305();
                let private = MaybePrivate::new_private(&master_key, val.clone()).unwrap();
                let spec = $createfn(private);
                assert_eq!(spec.has_private(), true);
                match $getmaybe(spec.clone()) {
                    MaybePrivate::Private(_, Some(_)) => {},
                    _ => panic!("bad maybe val: {}", stringify!($claimtype)),
                }
                let now = Timestamp::now();
                let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
                let claim = ClaimContainer::new(&master_key, &sign_keypair, now, spec).unwrap();
                assert_eq!(claim.has_private(), true);

                let public = MaybePrivate::new_public(val.clone());
                let spec2 = $createfn(public);
                assert_eq!(spec2.has_private(), false);
                let now2 = Timestamp::now();
                let sign_keypair2 = SignKeypair::new_ed25519(&master_key).unwrap();
                let claim2 = ClaimContainer::new(&master_key, &sign_keypair2, now2, spec2).unwrap();
                assert_eq!(claim2.has_private(), false);
            };
            ($claimtype:ident, $val:expr) => {
                claim_pub_priv!{
                    $claimtype,
                    $val,
                    |maybe| { ClaimSpec::$claimtype(maybe) },
                    |spec: ClaimSpec| if let ClaimSpec::$claimtype(maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
                }
            };
        }

        // as usual, Identity is special
        let spec = ClaimSpec::Identity(IdentityID::blank());
        assert_eq!(spec.has_private(), false);

        claim_pub_priv!{ Name, String::from("I LIKE FOOTBALL") }
        claim_pub_priv!{ Email, String::from("IT@IS.FUN") }
        claim_pub_priv!{ PGP, String::from("I LIKE FOOTBALL") }
        claim_pub_priv!{ HomeAddress, String::from("I LIKE TO RUN") }
        claim_pub_priv!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::blank()) }
        claim_pub_priv!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![69,69,69])) }
        claim_pub_priv!{
            Extension,
            ClaimBin(vec![42, 22]),
            |maybe| ClaimSpec::Extension(String::from("SOCIAL NETWORK WEB2.0"), maybe),
            |spec| {
                match spec {
                    ClaimSpec::Extension(_, maybe) => maybe,
                    _ => panic!("bad claim type: Extension"),
                }
            }
        }
    }

    #[test]
    fn claimcontainer_claimspec_strip() {
        macro_rules! thtrip {
            (next, $val:expr, $createfn:expr) => {
                let val = $val;
                let master_key = SecretKey::new_xsalsa20poly1305();
                let private = MaybePrivate::new_private(&master_key, val.clone()).unwrap();
                let claimspec = $createfn(private);
                let claimspec2 = claimspec.clone().strip_private();
                assert_eq!(claimspec.has_private(), true);
                assert_eq!(claimspec2.has_private(), false);
            };
            ($claimtype:ident, $val:expr) => {
                thtrip!{
                    next,
                    $val,
                    |maybe| { ClaimSpec::$claimtype(maybe) }
                }
            };
        }

        thtrip!{ Name, String::from("I LIKE FOOTBALL") }
        thtrip!{ Email, String::from("IT.MAKES@ME.GLAD") }
        thtrip!{ PGP, String::from("I PLAY FOOTBALL") }
        thtrip!{ HomeAddress, String::from("WITH MY DAD") }
        thtrip!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::blank()) }
        thtrip!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![69,69,69])) }
        thtrip!{
            next,
            ClaimBin(vec![42, 17, 86]),
            |maybe| { ClaimSpec::Extension(String::from("best poet ever"), maybe) }
        }

        // for Identity, nothing will fundamentally change.
        let claimspec = ClaimSpec::Identity(IdentityID::blank());
        let claimspec2 = claimspec.clone().strip_private();
        match (&claimspec, &claimspec2) {
            (ClaimSpec::Identity(id), ClaimSpec::Identity(id2)) => {
                assert_eq!(id, id2);
            }
            _ => panic!("Bad claim type: Identity"),
        }
    }
}

