//! A claim is any information we can provide to distinguish our identity. This
//! can be as simple as "this identity is mine" (which is the default claim and
//! always exists in any identity) or "this email is mine" to something like "I
//! have blonde hair, blue eyes, and a cute little button nose."
//!
//! However, a claim by itself is not meaningful or useful unless it is
//! [stamped](crate::identity::stamp) by someone withing your trust network.

use crate::{
    error::{Error, Result},
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
use std::convert::TryFrom;
use std::ops::Deref;
use url::Url;

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
    ///
    /// This can also be used to claim ownership of another identity, hopefully
    /// stamped by that identity.
    Identity(IdentityID),
    /// A claim that the name attached to this identity is mine.
    Name(MaybePrivate<String>),
    /// A claim that I own an email address.
    Email(MaybePrivate<String>),
    /// A claim that the attached photo is a photo of me.
    Photo(MaybePrivate<ClaimBin>),
    /// A claim that I own a PGP keypair (using the key's ID as the value).
    ///
    /// In general, you would create this claim, sign the claim's ID with your
    /// PGP keypair, then publish the signature somewhere it can be validated
    /// by others.
    ///
    /// NOTE: we *could* reimplement *all* of PGP and allow people to verify
    /// this themselves via cross-signing, but seems more appropriate to keep
    /// the spec lean and instead require third-parties to verify the claim.
    Pgp(MaybePrivate<String>),
    /// A claim that I own or have write access to an internet domain.
    ///
    /// This claim should be accompanied by a DNS TXT record on the domain that
    /// has the full URL of the identity/claim. This takes the format
    ///   stamp://<identityID>/claim/<claimID>
    ///
    /// For instance, if you want to claim ownership of killtheradio.net then
    /// you could create a Domain claim with a value of "killtheradio.net". If
    /// you have the identity ID:
    ///
    ///   o8AL10aawwthQIURV5RND2fo1RM-GU6x6H_ZtwRxv-rVeFnh4Eaa2ps9Xq5Pzbn27_CPQHm2sObYu22bxaWDDwA
    ///
    /// and the domain claim has an ID of:
    ///
    ///   cZVhuW0Of5aqaFa1aCf6J_1vS2XtNV94r1LxfgIgkK8tpZmzlVnA_Xb04LJrRWno--cVj5P8P9zOMMXmZe75AQA
    ///
    /// Then you would create a DNS TXT record on the killtheradio.net domain as
    /// follows:
    ///
    ///   stamp://o8AL10aawwthQIURV5RND2fo1RM-GU6x6H_ZtwRxv-rVeFnh4Eaa2ps9Xq5Pzbn27_CPQHm2sObYu22bxaWDDwA/claim/cZVhuW0Of5aqaFa1aCf6J_1vS2XtNV94r1LxfgIgkK8tpZmzlVnA_Xb04LJrRWno--cVj5P8P9zOMMXmZe75AQA
    ///
    /// It's a mouthfull, I know. But now anybody who can read the domain DNS
    /// can look up your identity and verify your claim. If you really want to,
    /// you can use the short form URL:
    ///
    ///   stamp://o8AL10aawwthQIUR/claim/cZVhuW0Of5aqaFa1
    Domain(MaybePrivate<String>),
    /// A claim that I own or have write access to a specific URL.
    ///
    /// This claim can generally be validated by implementations themselves.
    /// After creation of the claim, the ID of the claim should be published to
    /// that URL and prepended with "stamp:" (a 16-character shortened ID can be
    /// used if space is limited).
    ///
    /// For instance, if you want to claim ownership of https://killtheradio.net/
    /// then you would create a Url claim with that URL as the value. Let's say
    /// the resulting claim ID is:
    ///
    ///   0SgfsdQ2YNk6Nlre9ENLrcRVuFffm81OcAPxYWFNXG9-XMfEI2LtW9LW_yIWiMUX6oOjszqaLlxrGy1vufc8AAA
    ///
    /// You would then publish on https://killtheradio.net/ a string somewhere
    /// on the homepage
    ///
    ///   stamp:0SgfsdQ2YNk6Nlre9ENLrcRVuFffm81OcAPxYWFNXG9-XMfEI2LtW9LW_yIWiMUX6oOjszqaLlxrGy1vufc8AAA
    ///
    /// or for stupid, useless, idiotic platforms like twitter, abbreviated:
    ///
    ///   stamp:0SgfsdQ2YNk6Nlre
    ///
    /// Long-form is preferred for security, but obviously not as hip.
    ///
    /// It's also possible, although very unstylish, to use the full URL of the
    /// claim itself, in the format
    ///   stamp://<identityID>/claim/<claimID>
    ///
    /// This can be specified either with long-form IDs or short-form, 16-char
    /// abbreviated IDs:
    ///
    ///   stamp://o8AL10aawwthQIURV5RND2fo1RM-GU6x6H_ZtwRxv-rVeFnh4Eaa2ps9Xq5Pzbn27_CPQHm2sObYu22bxaWDDwA/claim/0SgfsdQ2YNk6Nlre9ENLrcRVuFffm81OcAPxYWFNXG9-XMfEI2LtW9LW_yIWiMUX6oOjszqaLlxrGy1vufc8AAA
    ///   stamp://o8AL10aawwthQIUR/claim/0SgfsdQ2YNk6Nlre
    ///
    /// If whatever system you're using doesn't have the concept of a "profile"
    /// with editable text you can update, and doesn't provide a predictable URL
    /// format for new posts, and doesn't have editable posts, you will need a
    /// third-party to stamp this claim.
    Url(MaybePrivate<Url>),
    /// A claim that I reside at a physical address.
    ///
    /// Must be stamped in-person. At the DMV. The one that's further away.
    /// Sorry, that's the protocol.
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
    /// This can be something like a state-issued identification.
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
            Self::Identity(val) => Self::Identity(val),
            Self::Name(maybe) => Self::Name(maybe.reencrypt(current_key, new_key)?),
            Self::Email(maybe) => Self::Email(maybe.reencrypt(current_key, new_key)?),
            Self::Photo(maybe) => Self::Photo(maybe.reencrypt(current_key, new_key)?),
            Self::Pgp(maybe) => Self::Pgp(maybe.reencrypt(current_key, new_key)?),
            Self::Domain(maybe) => Self::Domain(maybe.reencrypt(current_key, new_key)?),
            Self::Url(maybe) => Self::Url(maybe.reencrypt(current_key, new_key)?),
            Self::HomeAddress(maybe) => Self::HomeAddress(maybe.reencrypt(current_key, new_key)?),
            Self::Relation(maybe) => Self::Relation(maybe.reencrypt(current_key, new_key)?),
            Self::RelationExtension(maybe) => Self::RelationExtension(maybe.reencrypt(current_key, new_key)?),
            Self::Extension(key, maybe) => Self::Extension(key, maybe.reencrypt(current_key, new_key)?),
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
            Self::Identity(..) => false,
            Self::Name(val) => val.has_private(),
            Self::Email(val) => val.has_private(),
            Self::Photo(val) => val.has_private(),
            Self::Pgp(val) => val.has_private(),
            Self::Domain(val) => val.has_private(),
            Self::Url(val) => val.has_private(),
            Self::HomeAddress(val) => val.has_private(),
            Self::Relation(val) => val.has_private(),
            Self::RelationExtension(val) => val.has_private(),
            Self::Extension(_, val) => val.has_private(),
        }
    }
}

impl Public for ClaimSpec {
    fn strip_private(&self) -> Self {
        match self {
            Self::Identity(val) => Self::Identity(val.clone()),
            Self::Name(val) => Self::Name(val.strip_private()),
            Self::Email(val) => Self::Email(val.strip_private()),
            Self::Photo(val) => Self::Photo(val.strip_private()),
            Self::Pgp(val) => Self::Pgp(val.strip_private()),
            Self::Domain(val) => Self::Domain(val.strip_private()),
            Self::Url(val) => Self::Url(val.strip_private()),
            Self::HomeAddress(val) => Self::HomeAddress(val.strip_private()),
            Self::Relation(val) => Self::Relation(val.strip_private()),
            Self::RelationExtension(val) => Self::RelationExtension(val.strip_private()),
            Self::Extension(key, val) => Self::Extension(key.clone(), val.strip_private()),
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

    /// Given a claim we want to "instant verify" (ie, any claim type that can
    /// be verified automatically), return the possible values for that claim's
    /// automatic validation. If one of these values is present in the body of
    /// the resource being checked, then the claim is valid and verified.
    ///
    /// Some claims, such as your name, date of birth, email, etc will need
    /// external verification. However, some claims will not, and we can verify
    /// them automatically!
    ///
    /// For instance, if you claim you own a URL, we can immediately verify that
    /// claim by reading that URL (provided it's a protocol we understand, like
    /// HTTP[S]) and checking if the claim is included in the response.
    ///
    /// The following claim types can currently be automated:
    ///
    /// - `Url`
    /// - `Domain`
    pub fn instant_verify_allowed_values(&self, identity_id: &IdentityID) -> Result<Vec<String>> {
        match self.spec() {
            ClaimSpec::Domain(_) => {
                let identity_id_str = String::try_from(identity_id)?;
                let claim_id_str = String::try_from(self.id())?;
                Ok(vec![
                    format!("stamp://{}/claim/{}", identity_id_str, claim_id_str),
                    format!("stamp://{}/claim/{}", IdentityID::short(&identity_id_str), ClaimID::short(&claim_id_str)),
                ])
            }
            ClaimSpec::Url(_) => {
                let identity_id_str = String::try_from(identity_id)?;
                let claim_id_str = String::try_from(self.id())?;
                Ok(vec![
                    format!("stamp:{}", claim_id_str),
                    format!("stamp:{}", ClaimID::short(&claim_id_str)),
                    format!("stamp://{}/claim/{}", identity_id_str, claim_id_str),
                    format!("stamp://{}/claim/{}", IdentityID::short(&identity_id_str), ClaimID::short(&claim_id_str)),
                ])
            }
            _ => Err(Error::IdentityClaimVerificationNotAllowed),
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
                // really just here to make tests fail if we add more claims
                match &spec {
                    ClaimSpec::Identity(..) => {}
                    ClaimSpec::Name(..) => {}
                    ClaimSpec::Email(..) => {}
                    ClaimSpec::Photo(..) => {}
                    ClaimSpec::Pgp(..) => {}
                    ClaimSpec::Domain(..) => {}
                    ClaimSpec::Url(..) => {}
                    ClaimSpec::HomeAddress(..) => {}
                    ClaimSpec::Relation(..) => {}
                    ClaimSpec::RelationExtension(..) => {}
                    ClaimSpec::Extension(..) => {}
                }

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
        claim_reenc!{ Photo, ClaimBin(vec![1, 2, 3]) }
        claim_reenc!{ Pgp, String::from("12345") }
        claim_reenc!{ Domain, String::from("slappy.com") }
        claim_reenc!{ Url, Url::parse("https://killtheradio.net/").unwrap() }
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
                // really just here to make tests fail if we add more claims
                match &spec {
                    ClaimSpec::Identity(..) => {}
                    ClaimSpec::Name(..) => {}
                    ClaimSpec::Email(..) => {}
                    ClaimSpec::Photo(..) => {}
                    ClaimSpec::Pgp(..) => {}
                    ClaimSpec::Domain(..) => {}
                    ClaimSpec::Url(..) => {}
                    ClaimSpec::HomeAddress(..) => {}
                    ClaimSpec::Relation(..) => {}
                    ClaimSpec::RelationExtension(..) => {}
                    ClaimSpec::Extension(..) => {}
                }
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
        claim_pub_priv!{ Photo, ClaimBin(vec![1, 2, 3]) }
        claim_pub_priv!{ Pgp, String::from("I LIKE FOOTBALL") }
        claim_pub_priv!{ Domain, String::from("I-LIKE.TO.RUN") }
        claim_pub_priv!{ Url, Url::parse("https://www.imdb.com/title/tt0101660/").unwrap() }
        claim_pub_priv!{ HomeAddress, String::from("22334 FOOTBALL LANE, FOOTBALLSVILLE, CA 00001") }
        claim_pub_priv!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::blank()) }
        claim_pub_priv!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![69,69,69])) }
        claim_pub_priv!{
            Extension,
            ClaimBin(vec![42, 22]),
            |maybe| ClaimSpec::Extension(String::from("I HERETOFORE NOTWITHSTANDING FORTHWITH CLAIM THIS POEM IS GREAT"), maybe),
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
                // really just here to make tests fail if we add more claims
                match &claimspec {
                    ClaimSpec::Identity(..) => {}
                    ClaimSpec::Name(..) => {}
                    ClaimSpec::Email(..) => {}
                    ClaimSpec::Photo(..) => {}
                    ClaimSpec::Pgp(..) => {}
                    ClaimSpec::Domain(..) => {}
                    ClaimSpec::Url(..) => {}
                    ClaimSpec::HomeAddress(..) => {}
                    ClaimSpec::Relation(..) => {}
                    ClaimSpec::RelationExtension(..) => {}
                    ClaimSpec::Extension(..) => {}
                }
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
        thtrip!{ Photo, ClaimBin(vec![1, 2, 3]) }
        thtrip!{ Pgp, String::from("I PLAY FOOTBALL") }
        thtrip!{ Domain, String::from("WITH.MY.DAD") }
        thtrip!{ Url, Url::parse("https://facebookdomainplus03371kz.free-vidsnet.com/best.football.videos.touchdowns.sports.team.extreme.NORTON-SCAN-RESULT-VIRUS-FREE.avi.mp4.zip.rar.exe").unwrap() }
        thtrip!{ HomeAddress, String::from("445 Elite Football Sports Street, Football, KY 44666") }
        thtrip!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::blank()) }
        thtrip!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![69,69,69])) }
        thtrip!{
            next,
            ClaimBin(vec![42, 17, 86]),
            |maybe| { ClaimSpec::Extension(String::from("best poem ever"), maybe) }
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

