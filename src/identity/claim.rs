//! A claim is any information we can provide to distinguish our identity. This
//! can be as simple as "this identity is mine" (which is the default claim and
//! always exists in any identity) or "this email is mine" to something like "I
//! have blonde hair, blue eyes, and a cute little button nose."
//!
//! However, a claim by itself is not meaningful or useful unless it is
//! [stamped](crate::identity::stamp) by someone within your trust network.

use crate::{
    error::{Error, Result},
    identity::{
        Public,
        stamp::Stamp,
        identity::IdentityID,
    },
    crypto::key::SecretKey,
    private::MaybePrivate,
    util::{Timestamp, Date},
};
use getset;
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;
use url::Url;

object_id! {
    /// A unique identifier for claims.
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
pub struct ClaimBin(#[serde(with = "crate::util::ser::human_bytes")] pub Vec<u8>);

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
    /// A claim I was born on a certain day.
    Birthday(MaybePrivate<Date>),
    /// A claim that I own an email address.
    Email(MaybePrivate<String>),
    /// A claim that the attached photo is a photo of me (ie, not an anime
    /// avatar).
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
            Self::Birthday(maybe) => Self::Birthday(maybe.reencrypt(current_key, new_key)?),
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

    /// Convert this spec into a public one, assuming we have the correct
    /// decrypt key.
    fn into_public(self, open_key: &SecretKey) -> Result<Self> {
        let spec = match self.clone() {
            Self::Identity(val) => Self::Identity(val),
            Self::Name(maybe) => Self::Name(maybe.into_public(open_key)?),
            Self::Birthday(maybe) => Self::Birthday(maybe.into_public(open_key)?),
            Self::Email(maybe) => Self::Email(maybe.into_public(open_key)?),
            Self::Photo(maybe) => Self::Photo(maybe.into_public(open_key)?),
            Self::Pgp(maybe) => Self::Pgp(maybe.into_public(open_key)?),
            Self::Domain(maybe) => Self::Domain(maybe.into_public(open_key)?),
            Self::Url(maybe) => Self::Url(maybe.into_public(open_key)?),
            Self::HomeAddress(maybe) => Self::HomeAddress(maybe.into_public(open_key)?),
            Self::Relation(maybe) => Self::Relation(maybe.into_public(open_key)?),
            Self::RelationExtension(maybe) => Self::RelationExtension(maybe.into_public(open_key)?),
            Self::Extension(key, maybe) => Self::Extension(key, maybe.into_public(open_key)?),
        };
        Ok(spec)
    }
}

impl Public for ClaimSpec {
    fn strip_private(&self) -> Self {
        match self {
            Self::Identity(val) => Self::Identity(val.clone()),
            Self::Name(val) => Self::Name(val.strip_private()),
            Self::Birthday(val) => Self::Birthday(val.strip_private()),
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

    fn has_private(&self) -> bool {
        match self {
            Self::Identity(..) => false,
            Self::Name(val) => val.has_private(),
            Self::Birthday(val) => val.has_private(),
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

/// A type used when signing a claim. Contains all data about the claim except
/// the stamps.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Claim {
    /// The unique ID of this claim.
    id: ClaimID,
    /// The data we're claiming.
    spec: ClaimSpec,
    /// The date we created this claim.
    created: Timestamp,
}

impl Claim {
    /// Create a new claim.
    fn new(id: ClaimID, spec: ClaimSpec, created: Timestamp) -> Self {
        Self {
            id,
            spec,
            created,
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
    /// HTTP\[S\]) and checking if the claim is included in the response.
    ///
    /// The following claim types can currently be automated:
    ///
    /// - `Url`
    /// - `Domain`
    pub fn instant_verify_allowed_values(&self, identity_id: &IdentityID) -> Result<Vec<String>> {
        match self.spec() {
            ClaimSpec::Domain(_) => {
                let identity_id_str = String::from(identity_id);
                let claim_id_str = String::from(self.id());
                Ok(vec![
                    format!("stamp://{}/claim/{}", identity_id_str, claim_id_str),
                    format!("stamp://{}/claim/{}", IdentityID::short(&identity_id_str), ClaimID::short(&claim_id_str)),
                ])
            }
            ClaimSpec::Url(_) => {
                let identity_id_str = String::from(identity_id);
                let claim_id_str = String::from(self.id());
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

    /// Whether this is a public claim or a private claim, return a public claim
    /// (assuming we have the correct decrypting key).
    pub fn as_public(&self, open_key: &SecretKey) -> Result<Self> {
        let mut claim = self.clone();
        claim.set_spec(claim.spec().clone().into_public(open_key)?);
        Ok(claim)
    }
}

impl Public for Claim {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_spec(clone.spec().strip_private());
        clone
    }

    fn has_private(&self) -> bool {
        self.spec().has_private()
    }
}

/// A wrapper around a `Claim` that stores its stamps.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct ClaimContainer {
    /// The actual claim data
    claim: Claim,
    /// Stamps that have been made on our claim.
    stamps: Vec<Stamp>,
}

impl ClaimContainer {
    /// Create a new claim, sign it with our signing key, and return a container
    /// that holds the claim (with an empty set of stamps).
    pub fn new(claim_id: ClaimID, spec: ClaimSpec, created: Timestamp) -> Self {
        let claim = Claim::new(claim_id, spec, created);
        Self {
            claim,
            stamps: Vec::new(),
        }
    }
}

impl Public for ClaimContainer {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_claim(clone.claim().strip_private());
        clone
    }

    fn has_private(&self) -> bool {
        self.claim().spec().has_private()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        error::Error,
        identity::{IdentityID},
    };
    use std::convert::TryFrom;
    use std::str::FromStr;

    macro_rules! make_specs {
        ($claimmaker:expr, $val:expr) => {{
            let master_key = SecretKey::new_xsalsa20poly1305().unwrap();
            let val = $val;
            let maybe_private = MaybePrivate::new_private(&master_key, val.clone()).unwrap();
            let maybe_public = MaybePrivate::new_public(val.clone());
            let spec_private = $claimmaker(maybe_private, val.clone());
            let spec_public = $claimmaker(maybe_public, val.clone());
            (master_key, spec_private, spec_public)
        }}
    }

    #[test]
    fn claimspec_reencrypt() {
        macro_rules! claim_reenc {
            (raw, $claimmaker:expr, $val:expr, $get_maybe:expr) => {
                let val = $val;
                let (master_key, spec_private, spec_public) = make_specs!($claimmaker, val.clone());
                assert_eq!($get_maybe(spec_private.clone()).open(&master_key).unwrap(), val);
                let master_key2 = SecretKey::new_xsalsa20poly1305().unwrap();
                assert!(master_key != master_key2);
                let spec_private2 = spec_private.reencrypt(&master_key, &master_key2).unwrap();
                let maybe_private2 = $get_maybe(spec_private2);
                assert_eq!(maybe_private2.open(&master_key), Err(Error::CryptoOpenFailed));
                assert_eq!(maybe_private2.open(&master_key2).unwrap(), val);

                let spec_public2 = spec_public.clone().reencrypt(&master_key, &master_key2).unwrap();
                match ($get_maybe(spec_public), $get_maybe(spec_public2)) {
                    (MaybePrivate::Public(val), MaybePrivate::Public(val2)) => {
                        assert_eq!(val, val2);
                    }
                    _ => panic!("Bad claim type {}", stringify!($claimtype)),
                }
            };

            ($claimty:ident, $val:expr) => {
                claim_reenc! {
                    raw,
                    |maybe, _| ClaimSpec::$claimty(maybe),
                    $val,
                    |spec: ClaimSpec| if let ClaimSpec::$claimty(maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
                }
            };
        }

        let (master_key, _, spec) = make_specs!(|_, val| ClaimSpec::Identity(val), IdentityID::random());
        let master_key2 = SecretKey::new_xsalsa20poly1305().unwrap();
        let spec2 = spec.clone().reencrypt(&master_key, &master_key2).unwrap();
        match (spec, spec2) {
            (ClaimSpec::Identity(id), ClaimSpec::Identity(id2)) => assert_eq!(id, id2),
            _ => panic!("Bad claim type: Identity"),
        }

        claim_reenc!{ Name, String::from("Marty Malt") }
        claim_reenc!{ Birthday, Date::from_str("2010-01-03").unwrap() }
        claim_reenc!{ Email, String::from("marty@sids.com") }
        claim_reenc!{ Photo, ClaimBin(vec![1, 2, 3]) }
        claim_reenc!{ Pgp, String::from("12345") }
        claim_reenc!{ Domain, String::from("slappy.com") }
        claim_reenc!{ Url, Url::parse("https://killtheradio.net/").unwrap() }
        claim_reenc!{ HomeAddress, String::from("111 blumps ln") }
        claim_reenc!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        claim_reenc!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![1, 2, 3, 4, 5])) }
        claim_reenc!{
            raw,
            |maybe, _| ClaimSpec::Extension(String::from("id:state:ca"), maybe),
            ClaimBin(vec![7, 3, 2, 90]),
            |spec: ClaimSpec| if let ClaimSpec::Extension(_, maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
        }
    }

    #[test]
    fn claimcontainer_claimspec_has_private() {
        macro_rules! claim_pub_priv {
            (raw, $claimmaker:expr, $val:expr, $getmaybe:expr) => {
                let (_master_key, spec, spec2) = make_specs!($claimmaker, $val);
                assert_eq!(spec.has_private(), true);
                match $getmaybe(spec.clone()) {
                    MaybePrivate::Private(_, Some(_)) => {},
                    _ => panic!("bad maybe val: {}", stringify!($claimtype)),
                }
                let claim = ClaimContainer::new(ClaimID::random(), spec, Timestamp::now());
                assert_eq!(claim.has_private(), true);

                assert_eq!(spec2.has_private(), false);
                let claim2 = ClaimContainer::new(ClaimID::random(), spec2, Timestamp::now());
                assert_eq!(claim2.has_private(), false);
            };
            ($claimty:ident, $val:expr) => {
                claim_pub_priv!{
                    raw,
                    |maybe, _| ClaimSpec::$claimty(maybe),
                    $val,
                    |spec: ClaimSpec| if let ClaimSpec::$claimty(maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
                }
            };
        }

        // as usual, Identity is special
        let spec = ClaimSpec::Identity(IdentityID::random());
        assert_eq!(spec.has_private(), false);

        claim_pub_priv!{ Name, String::from("I LIKE FOOTBALL") }
        claim_pub_priv!{ Birthday, Date::from_str("1990-03-04").unwrap() }
        claim_pub_priv!{ Email, String::from("IT@IS.FUN") }
        claim_pub_priv!{ Photo, ClaimBin(vec![1, 2, 3]) }
        claim_pub_priv!{ Pgp, String::from("I LIKE FOOTBALL") }
        claim_pub_priv!{ Domain, String::from("I-LIKE.TO.RUN") }
        claim_pub_priv!{ Url, Url::parse("https://www.imdb.com/title/tt0101660/").unwrap() }
        claim_pub_priv!{ HomeAddress, String::from("22334 FOOTBALL LANE, FOOTBALLSVILLE, CA 00001") }
        claim_pub_priv!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        claim_pub_priv!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![69,69,69])) }
        claim_pub_priv!{
            raw,
            |maybe, _| ClaimSpec::Extension(String::from("I HERETOFORE NOTWITHSTANDING FORTHWITH CLAIM THIS POEM IS GREAT"), maybe),
            ClaimBin(vec![42, 22]),
            |spec| {
                match spec {
                    ClaimSpec::Extension(_, maybe) => maybe,
                    _ => panic!("bad claim type: Extension"),
                }
            }
        }
    }

    #[test]
    fn claimspec_strip() {
        macro_rules! thtrip {
            (next, $val:expr, $createfn:expr) => {
                let val = $val;
                let master_key = SecretKey::new_xsalsa20poly1305().unwrap();
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
        thtrip!{ Birthday, Date::from_str("1967-12-03").unwrap() }
        thtrip!{ Email, String::from("IT.MAKES@ME.GLAD") }
        thtrip!{ Photo, ClaimBin(vec![1, 2, 3]) }
        thtrip!{ Pgp, String::from("I PLAY FOOTBALL") }
        thtrip!{ Domain, String::from("WITH.MY.DAD") }
        thtrip!{ Url, Url::parse("https://facebookdomainplus03371kz.free-vidsnet.com/best.football.videos.touchdowns.sports.team.extreme.NORTON-SCAN-RESULT-VIRUS-FREE.avi.mp4.zip.rar.exe").unwrap() }
        thtrip!{ HomeAddress, String::from("445 Elite Football Sports Street, Football, KY 44666") }
        thtrip!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        thtrip!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![69,69,69])) }
        thtrip!{
            next,
            ClaimBin(vec![42, 17, 86]),
            |maybe| { ClaimSpec::Extension(String::from("best poem ever"), maybe) }
        }

        // for Identity, nothing will fundamentally change.
        let claimspec = ClaimSpec::Identity(IdentityID::random());
        let claimspec2 = claimspec.clone().strip_private();
        match (&claimspec, &claimspec2) {
            (ClaimSpec::Identity(id), ClaimSpec::Identity(id2)) => {
                assert_eq!(id, id2);
            }
            _ => panic!("Bad claim type: Identity"),
        }
    }

    #[test]
    fn claim_instant_verify() {
        macro_rules! match_container {
            ($container:expr, $expected:expr) => {
                let identity_id = IdentityID::random();
                let identity_id_str = String::try_from(&identity_id).unwrap();
                let identity_id_str_short = IdentityID::short(&identity_id_str);
                let claim_id_str = String::try_from($container.claim().id()).unwrap();
                let claim_id_str_short = ClaimID::short(&claim_id_str);
                match $container.claim().spec() {
                    ClaimSpec::Domain(..) | ClaimSpec::Url(..) => {
                        let instant_vals = $container.claim().instant_verify_allowed_values(&identity_id).unwrap();
                        let compare: Vec<String> = $expected.into_iter()
                            .map(|x: String| {
                                x
                                    .replace("{{identity_id}}", &identity_id_str)
                                    .replace("{{claim_id}}", &claim_id_str)
                                    .replace("{{identity_id_short}}", &identity_id_str_short)
                                    .replace("{{claim_id_short}}", &claim_id_str_short)
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(instant_vals, compare);
                    }
                    _ => {
                        let res = $container.claim().instant_verify_allowed_values(&identity_id);
                        assert_eq!(res, Err(Error::IdentityClaimVerificationNotAllowed));
                    }
                }
            }
        }
        macro_rules! assert_instant {
            (raw, $claimmaker:expr, $val:expr, $expected:expr) => {
                let (_master_key, spec_private, spec_public) = make_specs!($claimmaker, $val);
                let container_private = ClaimContainer::new(ClaimID::random(), spec_private, Timestamp::now());
                let container_public = ClaimContainer::new(ClaimID::random(), spec_public, Timestamp::now());

                match_container! { container_public, $expected }
                match_container! { container_private, $expected }
            };
            ($claimty:ident, $val:expr, $expected:expr) => {
                assert_instant!{ raw, |maybe, _| ClaimSpec::$claimty(maybe), $val, $expected }
            };
        }
        assert_instant!{ raw, |_, val| ClaimSpec::Identity(val), IdentityID::random(), vec![] }
        assert_instant!{ Name, String::from("I LIKE FOOTBALL"), vec![] }
        assert_instant!{ Birthday, Date::from_str("1967-12-03").unwrap(), vec![] }
        assert_instant!{ Email, String::from("IT.MAKES@ME.GLAD"), vec![] }
        assert_instant!{ Photo, ClaimBin(vec![1, 2, 3]), vec![] }
        assert_instant!{ Pgp, String::from("I PLAY FOOTBALL"), vec![] }
        assert_instant!{ Domain, String::from("WITH.MY.DAD"), vec![
            "stamp://{{identity_id}}/claim/{{claim_id}}".into(),
            "stamp://{{identity_id_short}}/claim/{{claim_id_short}}".into(),
        ] }
        assert_instant!{ Url, Url::parse("https://facebookdomainplus03371kz.free-vidsnet.com/best.football.videos.touchdowns.sports.team.extreme.NORTON-SCAN-RESULT-VIRUS-FREE.avi.mp4.zip.rar.exe").unwrap(), vec![
            "stamp:{{claim_id}}".into(),
            "stamp:{{claim_id_short}}".into(),
            "stamp://{{identity_id}}/claim/{{claim_id}}".into(),
            "stamp://{{identity_id_short}}/claim/{{claim_id_short}}".into(),
        ] }
        assert_instant!{ HomeAddress, String::from("445 Elite Football Sports Street, Football, KY 44666"), vec![] }
        assert_instant!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()), vec![] }
        assert_instant!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![69,69,69])), vec![] }
        assert_instant!{
            raw,
            |maybe, _| { ClaimSpec::Extension(String::from("shaka gnar gnar"), maybe) },
            ClaimBin(vec![66, 6]),
            vec![]
        }
    }

    #[test]
    fn claim_as_public() {
        macro_rules! as_pub {
            (raw, $claimmaker:expr, $val:expr, $getmaybe:expr) => {
                let (master_key, spec_private, spec_public) = make_specs!($claimmaker, $val);
                let fake_master_key = SecretKey::new_xsalsa20poly1305().unwrap();
                let container_private = ClaimContainer::new(ClaimID::random(), spec_private, Timestamp::now());
                let container_public = ClaimContainer::new(ClaimID::random(), spec_public, Timestamp::now());
                let opened_claim = container_private.claim().as_public(&master_key).unwrap();
                assert_eq!(container_private.has_private(), true);
                assert_eq!(container_public.has_private(), false);
                assert_eq!(opened_claim.spec().has_private(), false);
                assert_eq!($getmaybe(opened_claim.spec().clone()), $getmaybe(container_public.claim().spec().clone()));
                assert_eq!(container_private.claim().as_public(&fake_master_key).err(), Some(Error::CryptoOpenFailed));
            };
            ($claimty:ident, $val:expr) => {
                as_pub!{
                    raw,
                    |maybe, _| ClaimSpec::$claimty(maybe),
                    $val,
                    |spec: ClaimSpec| if let ClaimSpec::$claimty(maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
                }
            };
        }

        let (master_key, spec_private, _) = make_specs!(|_, val| ClaimSpec::Identity(val), IdentityID::random());
        let container_private = ClaimContainer::new(ClaimID::random(), spec_private, Timestamp::now());
        match (container_private.claim().spec(), container_private.claim().as_public(&master_key).unwrap().spec()) {
            (ClaimSpec::Identity(val1), ClaimSpec::Identity(val2)) => {
                assert_eq!(val1, val2);
            }
            _ => panic!("weird"),
        }

        as_pub!{ Name, String::from("Sassafrass Stevens") }
        as_pub!{ Birthday, Date::from_str("1990-03-04").unwrap() }
        as_pub!{ Email, String::from("MEGATRON@nojerrystopjerry.net") }
        as_pub!{ Photo, ClaimBin(vec![1, 2, 3]) }
        as_pub!{ Pgp, String::from("0x00000000000") }
        as_pub!{ Domain, String::from("decolonizing-decolonization.decolonize.org") }
        as_pub!{ Url, Url::parse("https://i.gifer.com/RL4.gif").unwrap() }
        as_pub!{ HomeAddress, String::from("22334 MECHA SHIVA LANE, GAINESVILLE, FL 00001") }
        as_pub!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        as_pub!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![69,69,69])) }
        as_pub!{
            raw,
            |maybe, _| ClaimSpec::Extension(String::from("I HERETOFORE NOTWITHSTANDING FORTHWITH CLAIM THAT I AM NOT A CAT YOUR HONOR"), maybe),
            ClaimBin(vec![42, 22]),
            |spec: ClaimSpec| if let ClaimSpec::Extension(_, maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
        }
    }

    #[test]
    fn claimcontainer_has_private_strip() {
        macro_rules! has_priv {
            (raw, $claimmaker:expr, $val:expr, $haspriv:expr) => {
                let (_master_key, spec_private, spec_public) = make_specs!($claimmaker, $val);
                let container_private = ClaimContainer::new(ClaimID::random(), spec_private, Timestamp::now());
                let container_public = ClaimContainer::new(ClaimID::random(), spec_public, Timestamp::now());
                assert_eq!(container_private.has_private(), $haspriv);
                assert_eq!(container_public.has_private(), false);

                let container_private_stripped = container_private.strip_private();
                let container_public_stripped = container_public.strip_private();
                assert_eq!(container_private_stripped.has_private(), false);
                assert_eq!(container_public_stripped.has_private(), false);
            };

            ($claimty:ident, $val:expr, $haspriv:expr) => {
                has_priv! { raw, |maybe, _| ClaimSpec::$claimty(maybe), $val, $haspriv }
            };
        }
        has_priv! { raw, |_, val| ClaimSpec::Identity(val), IdentityID::random(), false }
        has_priv! { Name, String::from("Goleen Jundersun"), true }
        has_priv! { Birthday, Date::from_str("1969-12-03").unwrap(), true }
        has_priv! { Email, String::from("jerry@karate.com"), true }
        has_priv! { Photo, ClaimBin(vec![1, 2, 3]), true }
        has_priv! { Pgp, String::from("45de280a"), true }
        has_priv! { Domain, String::from("good-times.great-trucks.nsf"), true }
        has_priv! { Url, Url::parse("https://you-might.be/wrong").unwrap(), true }
        has_priv! { HomeAddress, String::from("Mojave Desert"), true }
        has_priv! { Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()), true }
        has_priv! { RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![69,69,69])), true }
        has_priv! { raw, |maybe, _| ClaimSpec::Extension(String::from("tuna-melt-tuna-melt-TUNA-MELT-TUNA-MELT"), maybe), ClaimBin(vec![123, 122, 100]), true }
    }
}

