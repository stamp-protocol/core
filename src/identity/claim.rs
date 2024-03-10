//! A claim is any information we can provide to distinguish our identity. This
//! can be as simple as "this identity is mine" (which is the default claim and
//! always exists in any identity) or "this email is mine" to something like "I
//! have blonde hair, blue eyes, and a cute little button nose."
//!
//! However, a claim by itself is not meaningful or useful unless it is
//! [stamped](crate::identity::stamp) by someone within your trust network.

use crate::{
    crypto::{base::SecretKey, private::MaybePrivate},
    error::{Error, Result},
    identity::{identity::IdentityID, stamp::Stamp},
    util::{BinaryVec, Date, Public, SerText, Url},
};
use getset;
use rand::{CryptoRng, RngCore};
use rasn::{AsnType, Decode, Encode};
use serde_derive::{Deserialize, Serialize};
use std::ops::Deref;

object_id! {
    /// A unique identifier for claims.
    ClaimID
}

/// Various types of codified relationships, used in relationship claims.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum RelationshipType {
    /// An organizational or group membership.
    ///
    /// Note that this doesn't have to be a company or any predefined notion of
    /// an organization, but can really mean "a member of any group" including
    /// but not limited to a book club, a state citizenship, a murder of crows,
    /// and anything in-between or beyond.
    #[rasn(tag(explicit(0)))]
    OrganizationMember,
    /// Any custom relationship.
    #[rasn(tag(explicit(1)))]
    Extension(BinaryVec),
}

/// Defines a relationship.
#[derive(
    Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters,
)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Relationship<T> {
    /// The type of relationship we have.
    #[rasn(tag(explicit(0)))]
    #[serde(rename = "type")]
    ty: RelationshipType,
    /// Who the relationship is with.
    ///
    /// Eg: "your mom"
    #[rasn(tag(explicit(1)))]
    subject: T,
}

impl<T> Relationship<T> {
    /// Create a new relationship.
    pub fn new(ty: RelationshipType, subject: T) -> Self {
        Self { ty, subject }
    }
}

/// A collection of known claims one can make about their identity.
///
/// Note that the claim type itself will always be public, but the data attached
/// to a claim can be either public or private ("private" as in encrypted with
/// our `secret` key in our keyset). This allows others to see that I have made
/// a particular claim (and that others have stamped it) without revealing the
/// private data in that claim.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum ClaimSpec {
    /// A claim that this identity is mine.
    ///
    /// This claim should be made *publicly* any time a new identity is created.
    ///
    /// This can also be used to claim ownership of another identity, for instance
    /// if you lost your keys and need to move to a new identity.
    #[rasn(tag(explicit(0)))]
    Identity(MaybePrivate<IdentityID>),
    /// A claim that the name attached to this identity is mine.
    #[rasn(tag(explicit(1)))]
    Name(MaybePrivate<String>),
    /// A claim I was born on a certain day.
    #[rasn(tag(explicit(2)))]
    Birthday(MaybePrivate<Date>),
    /// A claim that I own an email address.
    #[rasn(tag(explicit(3)))]
    Email(MaybePrivate<String>),
    /// A claim that the attached photo is a photo of me (ie, not an anime
    /// avatar).
    #[rasn(tag(explicit(4)))]
    Photo(MaybePrivate<BinaryVec>),
    /// A claim that I own a PGP keypair (using the key's ID as the value).
    ///
    /// In general, you would create this claim, sign the claim's ID with your
    /// PGP keypair, then publish the signature somewhere it can be validated
    /// by others.
    ///
    /// NOTE: we *could* reimplement *all* of PGP and allow people to verify
    /// this themselves via cross-signing, but seems more appropriate to keep
    /// the spec lean and instead require third-parties to verify the claim.
    #[rasn(tag(explicit(5)))]
    Pgp(MaybePrivate<String>),
    /// A claim that I own or have write access to an internet domain.
    ///
    /// This claim should be accompanied by a DNS TXT record on the domain that
    /// has the full URL of the identity/claim. This takes the format
    ///
    /// ```txt
    /// stamp://<identityID>/claim/<claimID>
    /// ```
    ///
    /// For instance, if you want to claim ownership of killtheradio.net then
    /// you could create a Domain claim with a value of "killtheradio.net". If
    /// you have the identity ID:
    ///
    /// ```txt
    /// s0f__TtNxiUrNJ8yi14vVQteecP7xQYQzcohhPqOdt8A
    /// ```
    ///
    /// and the domain claim has an ID of:
    ///
    /// ```txt
    /// zYY3Z_P_MappC5sdHumcZ7goXMAlHuNQ9uCG9NEi02IA
    /// ```
    ///
    /// Then you would create a DNS TXT record on the killtheradio.net domain as
    /// follows:
    ///
    /// ```txt
    /// stamp://s0f__TtNxiUrNJ8yi14vVQteecP7xQYQzcohhPqOdt8A/claim/zYY3Z_P_MappC5sdHumcZ7goXMAlHuNQ9uCG9NEi02IA
    /// ```
    ///
    /// It's a mouthfull, I know. But now anybody who can read the domain DNS
    /// can look up your identity and verify your claim. If you really want to,
    /// you can use the short form URL:
    ///
    /// ```txt
    /// stamp://s0f__TtNxiUrNJ8y/claim/zYY3Z_P_MappC5sd
    /// ```
    #[rasn(tag(explicit(6)))]
    Domain(MaybePrivate<String>),
    /// A claim that I own or have write access to a specific URL.
    ///
    /// This claim can generally be validated by implementations themselves.
    /// After creation of the claim, the url should be updated with one of the following
    /// formats:
    ///
    /// ```txt
    /// stamp://<identityID>/claim/<claimID>
    /// stamp:<identityID>:<claimID>
    /// ```
    ///
    /// For instance, if you want to claim ownership of <https://killtheradio.net/>
    /// then you would create a Url claim with that URL as the value. Let's say (hypothetically!!1)
    /// that your identity ID is:
    ///
    /// ```txt
    /// s0f__TtNxiUrNJ8yi14vVQteecP7xQYQzcohhPqOdt8A
    /// ```
    ///
    /// and your URL claim has the ID:
    ///
    /// ```txt
    /// gsIXBbspigIQ-34m2TCxxRA_1V-fiefRa60WfXbR408A
    /// ```
    ///
    /// You would then publish on <https://killtheradio.net/> a string somewhere
    /// on the homepage one of the following values:
    ///
    /// ```txt
    /// stamp://s0f__TtNxiUrNJ8yi14vVQteecP7xQYQzcohhPqOdt8A/claim/gsIXBbspigIQ-34m2TCxxRA_1V-fiefRa60WfXbR408A
    /// stamp:s0f__TtNxiUrNJ8yi14vVQteecP7xQYQzcohhPqOdt8A:gsIXBbspigIQ-34m2TCxxRA_1V-fiefRa60WfXbR408A
    /// ```
    ///
    /// or if you are tryping to impress your crush with your baller website and don't want to clutter
    /// your page with enourmous amounts of base64 you can use the short-hand:
    ///
    /// ```txt
    /// stamp://s0f__TtNxiUrNJ8y/claim/gsIXBbspigIQ-34m
    /// stamp:s0f__TtNxiUrNJ8y:gsIXBbspigIQ-34m
    /// ```
    ///
    /// Long-form is preferred for security, but obviously not as hip.
    ///
    /// If whatever system you're using doesn't have the concept of a "profile"
    /// with editable text you can update, and doesn't provide a predictable URL
    /// format for new posts, and doesn't have editable posts, you will need a
    /// third-party to stamp this claim.
    #[rasn(tag(explicit(7)))]
    Url(MaybePrivate<Url>),
    /// A claim that I reside at a physical address.
    ///
    /// Must be stamped in-person. At the DMV. The one that's further away.
    /// Sorry, that's the protocol.
    #[rasn(tag(explicit(8)))]
    Address(MaybePrivate<String>),
    /// A claim that I own a phone number.
    #[rasn(tag(explicit(9)))]
    PhoneNumber(MaybePrivate<String>),
    /// A claim that I am in a relationship with another identity, hopefully
    /// stamped by that identity ='[
    #[rasn(tag(explicit(10)))]
    Relation(MaybePrivate<Relationship<IdentityID>>),
    /// A claim that I am in a relationship with another entity with some form
    /// of serializable identification (such as a signed certificate, a name,
    /// etc). Can be used to assert relationships to entities outside of the
    /// Stamp protocol (although stamps on these relationships must be provided
    /// by Stamp protocol identities).
    #[rasn(tag(explicit(11)))]
    RelationExtension(MaybePrivate<Relationship<BinaryVec>>),
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
    #[rasn(tag(explicit(12)))]
    Extension {
        #[rasn(tag(explicit(0)))]
        key: BinaryVec,
        #[rasn(tag(explicit(1)))]
        value: MaybePrivate<BinaryVec>,
    },
}

impl ClaimSpec {
    /// Re-encrypt this claim spec's private data, if it has any
    pub(crate) fn reencrypt<R: RngCore + CryptoRng>(self, rng: &mut R, current_key: &SecretKey, new_key: &SecretKey) -> Result<Self> {
        let spec = match self {
            Self::Identity(maybe) => Self::Identity(maybe.reencrypt(rng, current_key, new_key)?),
            Self::Name(maybe) => Self::Name(maybe.reencrypt(rng, current_key, new_key)?),
            Self::Birthday(maybe) => Self::Birthday(maybe.reencrypt(rng, current_key, new_key)?),
            Self::Email(maybe) => Self::Email(maybe.reencrypt(rng, current_key, new_key)?),
            Self::Photo(maybe) => Self::Photo(maybe.reencrypt(rng, current_key, new_key)?),
            Self::Pgp(maybe) => Self::Pgp(maybe.reencrypt(rng, current_key, new_key)?),
            Self::Domain(maybe) => Self::Domain(maybe.reencrypt(rng, current_key, new_key)?),
            Self::Url(maybe) => Self::Url(maybe.reencrypt(rng, current_key, new_key)?),
            Self::Address(maybe) => Self::Address(maybe.reencrypt(rng, current_key, new_key)?),
            Self::PhoneNumber(maybe) => Self::PhoneNumber(maybe.reencrypt(rng, current_key, new_key)?),
            Self::Relation(maybe) => Self::Relation(maybe.reencrypt(rng, current_key, new_key)?),
            Self::RelationExtension(maybe) => Self::RelationExtension(maybe.reencrypt(rng, current_key, new_key)?),
            Self::Extension { key, value } => Self::Extension {
                key,
                value: value.reencrypt(rng, current_key, new_key)?,
            },
        };
        Ok(spec)
    }

    /// Convert this spec into a public one, assuming we have the correct
    /// decrypt key.
    fn into_public(self, open_key: &SecretKey) -> Result<Self> {
        let spec = match self {
            Self::Identity(maybe) => Self::Identity(maybe.into_public(open_key)?),
            Self::Name(maybe) => Self::Name(maybe.into_public(open_key)?),
            Self::Birthday(maybe) => Self::Birthday(maybe.into_public(open_key)?),
            Self::Email(maybe) => Self::Email(maybe.into_public(open_key)?),
            Self::Photo(maybe) => Self::Photo(maybe.into_public(open_key)?),
            Self::Pgp(maybe) => Self::Pgp(maybe.into_public(open_key)?),
            Self::Domain(maybe) => Self::Domain(maybe.into_public(open_key)?),
            Self::Url(maybe) => Self::Url(maybe.into_public(open_key)?),
            Self::Address(maybe) => Self::Address(maybe.into_public(open_key)?),
            Self::PhoneNumber(maybe) => Self::PhoneNumber(maybe.into_public(open_key)?),
            Self::Relation(maybe) => Self::Relation(maybe.into_public(open_key)?),
            Self::RelationExtension(maybe) => Self::RelationExtension(maybe.into_public(open_key)?),
            Self::Extension { key, value } => Self::Extension {
                key,
                value: value.into_public(open_key)?,
            },
        };
        Ok(spec)
    }
}

impl Public for ClaimSpec {
    fn strip_private(&self) -> Self {
        match self {
            Self::Identity(val) => Self::Identity(val.strip_private()),
            Self::Name(val) => Self::Name(val.strip_private()),
            Self::Birthday(val) => Self::Birthday(val.strip_private()),
            Self::Email(val) => Self::Email(val.strip_private()),
            Self::Photo(val) => Self::Photo(val.strip_private()),
            Self::Pgp(val) => Self::Pgp(val.strip_private()),
            Self::Domain(val) => Self::Domain(val.strip_private()),
            Self::Url(val) => Self::Url(val.strip_private()),
            Self::Address(val) => Self::Address(val.strip_private()),
            Self::PhoneNumber(val) => Self::PhoneNumber(val.strip_private()),
            Self::Relation(val) => Self::Relation(val.strip_private()),
            Self::RelationExtension(val) => Self::RelationExtension(val.strip_private()),
            Self::Extension { key, value } => Self::Extension {
                key: key.clone(),
                value: value.strip_private(),
            },
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::Identity(val) => val.has_private(),
            Self::Name(val) => val.has_private(),
            Self::Birthday(val) => val.has_private(),
            Self::Email(val) => val.has_private(),
            Self::Photo(val) => val.has_private(),
            Self::Pgp(val) => val.has_private(),
            Self::Domain(val) => val.has_private(),
            Self::Url(val) => val.has_private(),
            Self::Address(val) => val.has_private(),
            Self::PhoneNumber(val) => val.has_private(),
            Self::Relation(val) => val.has_private(),
            Self::RelationExtension(val) => val.has_private(),
            Self::Extension { value, .. } => value.has_private(),
        }
    }
}

/// A claim on an identity, along with its ID, name, and any [stamps][Stamp] we've received.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Claim {
    /// The ID of this claim (the [transaction id][crate::dag::TransactionID] that created it).
    #[rasn(tag(explicit(0)))]
    id: ClaimID,
    /// The data we're claiming.
    #[rasn(tag(explicit(1)))]
    spec: ClaimSpec,
    /// Stamps that have been made on our claim.
    #[rasn(tag(explicit(2)))]
    stamps: Vec<Stamp>,
    /// This claim's name, can be used for forwarding/redirection.
    #[rasn(tag(explicit(3)))]
    name: Option<String>,
}

impl Claim {
    /// Create a new claim.
    pub(crate) fn new(id: ClaimID, spec: ClaimSpec, name: Option<String>) -> Self {
        Self {
            id,
            spec,
            stamps: Vec::new(),
            name,
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
                    format!("stamp://{}/claim/{}", identity_id_str, claim_id_str),
                    format!("stamp://{}/claim/{}", IdentityID::short(&identity_id_str), ClaimID::short(&claim_id_str)),
                    format!("stamp:{}:{}", identity_id_str, claim_id_str),
                    format!("stamp:{}:{}", IdentityID::short(&identity_id_str), ClaimID::short(&claim_id_str)),
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

impl SerText for Claim {}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{crypto::private::PrivateWithHmac, error::Error, identity::IdentityID};
    use std::convert::TryFrom;
    use std::str::FromStr;

    macro_rules! make_specs {
        ($rng:expr, $claimmaker:expr, $val:expr) => {{
            let master_key = SecretKey::new_xchacha20poly1305($rng).unwrap();
            let val = $val;
            let maybe_private = MaybePrivate::new_private($rng, &master_key, val.clone()).unwrap();
            let maybe_public = MaybePrivate::new_public(val.clone());
            let spec_private = $claimmaker(maybe_private, val.clone());
            let spec_public = $claimmaker(maybe_public, val.clone());
            (master_key, spec_private, spec_public)
        }};
    }

    #[test]
    fn claimspec_reencrypt() {
        macro_rules! claim_reenc {
            (raw, $claimmaker:expr, $val:expr, $get_maybe:expr) => {
                let mut rng = crate::util::test::rng();
                let val = $val;
                let (master_key, spec_private, spec_public) = make_specs!(&mut rng, $claimmaker, val.clone());
                assert_eq!($get_maybe(spec_private.clone()).open(&master_key).unwrap(), val);
                let master_key2 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
                assert!(master_key != master_key2);
                let spec_private2 = spec_private.reencrypt(&mut rng, &master_key, &master_key2).unwrap();
                let maybe_private2 = $get_maybe(spec_private2);
                assert_eq!(maybe_private2.open(&master_key), Err(Error::CryptoOpenFailed));
                assert_eq!(maybe_private2.open(&master_key2).unwrap(), val);

                let spec_public2 = spec_public.clone().reencrypt(&mut rng, &master_key, &master_key2).unwrap();
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

        claim_reenc! { Identity, IdentityID::random() }
        claim_reenc! { Name, String::from("Marty Malt") }
        claim_reenc! { Birthday, Date::from_str("2010-01-03").unwrap() }
        claim_reenc! { Email, String::from("marty@sids.com") }
        claim_reenc! { Photo, BinaryVec::from(vec![1, 2, 3]) }
        claim_reenc! { Pgp, String::from("12345") }
        claim_reenc! { Domain, String::from("slappy.com") }
        claim_reenc! { Url, Url::parse("https://killtheradio.net/").unwrap() }
        claim_reenc! { Address, String::from("111 blumps ln") }
        claim_reenc! { PhoneNumber, String::from("+1 831-555-1237") }
        claim_reenc! { Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        claim_reenc! { RelationExtension, Relationship::new(RelationshipType::OrganizationMember, BinaryVec::from(vec![1, 2, 3, 4, 5])) }
        claim_reenc! {
            raw,
            |maybe, _| ClaimSpec::Extension { key: Vec::from("id:state:ca".as_bytes()).into(), value: maybe },
            BinaryVec::from(vec![7, 3, 2, 90]),
            |spec: ClaimSpec| if let ClaimSpec::Extension { value: maybe, .. } = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
        }
    }

    #[test]
    fn claimcontainer_claimspec_has_private() {
        macro_rules! claim_pub_priv {
            (raw, $claimmaker:expr, $val:expr, $getmaybe:expr) => {
                let mut rng = crate::util::test::rng();
                let (_master_key, spec, spec2) = make_specs!(&mut rng, $claimmaker, $val);
                assert_eq!(spec.has_private(), true);
                match $getmaybe(spec.clone()) {
                    MaybePrivate::Private(PrivateWithHmac { data: Some(_), .. }) => {}
                    _ => panic!("bad maybe val: {}", stringify!($claimtype)),
                }
                let claim = Claim::new(ClaimID::random(), spec, None);
                assert_eq!(claim.has_private(), true);

                assert_eq!(spec2.has_private(), false);
                let claim2 = Claim::new(ClaimID::random(), spec2, None);
                assert_eq!(claim2.has_private(), false);
            };
            ($claimty:ident, $val:expr) => {
                claim_pub_priv! {
                    raw,
                    |maybe, _| ClaimSpec::$claimty(maybe),
                    $val,
                    |spec: ClaimSpec| if let ClaimSpec::$claimty(maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
                }
            };
        }

        claim_pub_priv! { Identity, IdentityID::random() }
        claim_pub_priv! { Name, String::from("I LIKE FOOTBALL") }
        claim_pub_priv! { Birthday, Date::from_str("1990-03-04").unwrap() }
        claim_pub_priv! { Email, String::from("IT@IS.FUN") }
        claim_pub_priv! { Photo, BinaryVec::from(vec![1, 2, 3]) }
        claim_pub_priv! { Pgp, String::from("I LIKE FOOTBALL") }
        claim_pub_priv! { Domain, String::from("I-LIKE.TO.RUN") }
        claim_pub_priv! { Url, Url::parse("https://www.imdb.com/title/tt0101660/").unwrap() }
        claim_pub_priv! { Address, String::from("22334 FOOTBALL LANE, FOOTBALLSVILLE, CA 00001") }
        claim_pub_priv! { PhoneNumber, String::from("415-888-0001") }
        claim_pub_priv! { Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        claim_pub_priv! { RelationExtension, Relationship::new(RelationshipType::OrganizationMember, BinaryVec::from(vec![69,69,69])) }
        claim_pub_priv! {
            raw,
            |maybe, _| ClaimSpec::Extension { key: Vec::from("I HERETOFORE NOTWITHSTANDING FORTHWITH CLAIM THIS POEM IS GREAT".as_bytes()).into(), value: maybe },
            BinaryVec::from(vec![42, 22]),
            |spec| {
                match spec {
                    ClaimSpec::Extension { value: maybe, .. } => maybe,
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
                let mut rng = crate::util::test::rng();
                let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
                let private = MaybePrivate::new_private(&mut rng, &master_key, val.clone()).unwrap();
                let claimspec = $createfn(private);
                let claimspec2 = claimspec.clone().strip_private();
                assert_eq!(claimspec.has_private(), true);
                assert_eq!(claimspec2.has_private(), false);
            };
            ($claimtype:ident, $val:expr) => {
                thtrip! {
                    next,
                    $val,
                    |maybe| { ClaimSpec::$claimtype(maybe) }
                }
            };
        }

        thtrip! { Identity, IdentityID::random() }
        thtrip! { Name, String::from("I LIKE FOOTBALL") }
        thtrip! { Birthday, Date::from_str("1967-12-03").unwrap() }
        thtrip! { Email, String::from("IT.MAKES@ME.GLAD") }
        thtrip! { Photo, BinaryVec::from(vec![1, 2, 3]) }
        thtrip! { Pgp, String::from("I PLAY FOOTBALL") }
        thtrip! { Domain, String::from("WITH.MY.DAD") }
        thtrip! { Url, Url::parse("https://facebookdomainplus03371kz.free-vidsnet.com/best.football.videos.touchdowns.sports.team.extreme.NORTON-SCAN-RESULT-VIRUS-FREE.avi.mp4.zip.rar.exe").unwrap() }
        thtrip! { Address, String::from("445 Elite Football Sports Street, Football, KY 44666") }
        thtrip! { PhoneNumber, String::from("+22 222 4444 22") }
        thtrip! { Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        thtrip! { RelationExtension, Relationship::new(RelationshipType::OrganizationMember, BinaryVec::from(vec![69,69,69])) }
        thtrip! {
            next,
            BinaryVec::from(vec![42, 17, 86]),
            |maybe| { ClaimSpec::Extension { key: Vec::from("best poem ever".as_bytes()).into(), value: maybe } }
        }
    }

    #[test]
    fn claim_instant_verify() {
        macro_rules! match_container {
            ($container:expr, $expected:expr) => {
                let identity_id = IdentityID::random();
                let identity_id_str = String::try_from(&identity_id).unwrap();
                let identity_id_str_short = IdentityID::short(&identity_id_str);
                let claim_id_str = String::try_from($container.id()).unwrap();
                let claim_id_str_short = ClaimID::short(&claim_id_str);
                match $container.spec() {
                    ClaimSpec::Domain(..) | ClaimSpec::Url(..) => {
                        let instant_vals = $container.instant_verify_allowed_values(&identity_id).unwrap();
                        let compare: Vec<String> = $expected
                            .into_iter()
                            .map(|x: String| {
                                x.replace("{{identity_id}}", &identity_id_str)
                                    .replace("{{claim_id}}", &claim_id_str)
                                    .replace("{{identity_id_short}}", &identity_id_str_short)
                                    .replace("{{claim_id_short}}", &claim_id_str_short)
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(instant_vals, compare);
                    }
                    _ => {
                        let res = $container.instant_verify_allowed_values(&identity_id);
                        assert_eq!(res, Err(Error::IdentityClaimVerificationNotAllowed));
                    }
                }
            };
        }
        macro_rules! assert_instant {
            (raw, $claimmaker:expr, $val:expr, $expected:expr) => {
                let mut rng = crate::util::test::rng();
                let (_master_key, spec_private, spec_public) = make_specs!(&mut rng, $claimmaker, $val);
                let container_private = Claim::new(ClaimID::random(), spec_private, None);
                let container_public = Claim::new(ClaimID::random(), spec_public, None);

                match_container! { container_public, $expected }
                match_container! { container_private, $expected }
            };
            ($claimty:ident, $val:expr, $expected:expr) => {
                assert_instant! { raw, |maybe, _| ClaimSpec::$claimty(maybe), $val, $expected }
            };
        }
        assert_instant! { Identity, IdentityID::random(), vec![] }
        assert_instant! { Name, String::from("I LIKE FOOTBALL"), vec![] }
        assert_instant! { Birthday, Date::from_str("1967-12-03").unwrap(), vec![] }
        assert_instant! { Email, String::from("IT.MAKES@ME.GLAD"), vec![] }
        assert_instant! { Photo, BinaryVec::from(vec![1, 2, 3]), vec![] }
        assert_instant! { Pgp, String::from("I PLAY FOOTBALL"), vec![] }
        assert_instant! { Domain, String::from("WITH.MY.DAD"), vec![
            "stamp://{{identity_id}}/claim/{{claim_id}}".into(),
            "stamp://{{identity_id_short}}/claim/{{claim_id_short}}".into(),
        ] }
        assert_instant! { Url, Url::parse("https://facebookdomainplus03371kz.free-vidsnet.com/best.football.videos.touchdowns.sports.team.extreme.NORTON-SCAN-RESULT-VIRUS-FREE.avi.mp4.zip.rar.exe").unwrap(), vec![
            "stamp://{{identity_id}}/claim/{{claim_id}}".into(),
            "stamp://{{identity_id_short}}/claim/{{claim_id_short}}".into(),
            "stamp:{{identity_id}}:{{claim_id}}".into(),
            "stamp:{{identity_id_short}}:{{claim_id_short}}".into(),
        ] }
        assert_instant! { Address, String::from("445 Elite Football Sports Street, Football, KY 44666"), vec![] }
        assert_instant! { PhoneNumber, String::from("231234123"), vec![] }
        assert_instant! { Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()), vec![] }
        assert_instant! { RelationExtension, Relationship::new(RelationshipType::OrganizationMember, BinaryVec::from(vec![69,69,69])), vec![] }
        assert_instant! {
            raw,
            |maybe, _| { ClaimSpec::Extension { key: Vec::from("shaka gnar gnar".as_bytes()).into(), value: maybe } },
            BinaryVec::from(vec![66, 6]),
            vec![]
        }
    }

    #[test]
    fn claim_as_public() {
        macro_rules! as_pub {
            (raw, $claimmaker:expr, $val:expr, $getmaybe:expr) => {
                let mut rng = crate::util::test::rng();
                let (master_key, spec_private, spec_public) = make_specs!(&mut rng, $claimmaker, $val);
                let fake_master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
                let container_private = Claim::new(ClaimID::random(), spec_private, None);
                let container_public = Claim::new(ClaimID::random(), spec_public, None);
                let opened_claim = container_private.as_public(&master_key).unwrap();
                assert_eq!(container_private.has_private(), true);
                assert_eq!(container_public.has_private(), false);
                assert_eq!(opened_claim.spec().has_private(), false);
                assert_eq!($getmaybe(opened_claim.spec().clone()), $getmaybe(container_public.spec().clone()));
                assert_eq!(container_private.as_public(&fake_master_key).err(), Some(Error::CryptoOpenFailed));
            };
            ($claimty:ident, $val:expr) => {
                as_pub! {
                    raw,
                    |maybe, _| ClaimSpec::$claimty(maybe),
                    $val,
                    |spec: ClaimSpec| if let ClaimSpec::$claimty(maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
                }
            };
        }

        as_pub! { Identity, IdentityID::random() }
        as_pub! { Name, String::from("Sassafrass Stevens") }
        as_pub! { Birthday, Date::from_str("1990-03-04").unwrap() }
        as_pub! { Email, String::from("MEGATRON@nojerrystopjerry.net") }
        as_pub! { Photo, BinaryVec::from(vec![1, 2, 3]) }
        as_pub! { Pgp, String::from("0x00000000000") }
        as_pub! { Domain, String::from("decolonizing-decolonization.decolonize.org") }
        as_pub! { Url, Url::parse("https://i.gifer.com/RL4.gif").unwrap() }
        as_pub! { Address, String::from("22334 MECHA SHIVA LANE, GAINESVILLE, FL 00001") }
        as_pub! { PhoneNumber, String::from("121212") }
        as_pub! { Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        as_pub! { RelationExtension, Relationship::new(RelationshipType::OrganizationMember, BinaryVec::from(vec![69,69,69])) }
        as_pub! {
            raw,
            |maybe, _| ClaimSpec::Extension { key: Vec::from("I HERETOFORE NOTWITHSTANDING FORTHWITH CLAIM THAT I AM NOT A CAT YOUR HONOR".as_bytes()).into(), value: maybe },
            BinaryVec::from(vec![42, 22]),
            |spec: ClaimSpec| if let ClaimSpec::Extension { value: maybe, .. } = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
        }
    }

    #[test]
    fn claimcontainer_has_private_strip() {
        macro_rules! has_priv {
            (raw, $claimmaker:expr, $val:expr, $haspriv:expr) => {
                let mut rng = crate::util::test::rng();
                let (_master_key, spec_private, spec_public) = make_specs!(&mut rng, $claimmaker, $val);
                let container_private = Claim::new(ClaimID::random(), spec_private, None);
                let container_public = Claim::new(ClaimID::random(), spec_public, None);
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
        has_priv! { Identity, IdentityID::random(), true }
        has_priv! { Name, String::from("Goleen Jundersun"), true }
        has_priv! { Birthday, Date::from_str("1969-12-03").unwrap(), true }
        has_priv! { Email, String::from("jerry@karate.com"), true }
        has_priv! { Photo, BinaryVec::from(vec![1, 2, 3]), true }
        has_priv! { Pgp, String::from("45de280a"), true }
        has_priv! { Domain, String::from("good-times.great-trucks.nsf"), true }
        has_priv! { Url, Url::parse("https://you-might.be/wrong").unwrap(), true }
        has_priv! { Address, String::from("Mojave Desert"), true }
        has_priv! { PhoneNumber, String::from("555-6969"), true }
        has_priv! { Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()), true }
        has_priv! { RelationExtension, Relationship::new(RelationshipType::OrganizationMember, BinaryVec::from(vec![69,69,69])), true }
        has_priv! { raw, |maybe, _| ClaimSpec::Extension { key: Vec::from("tuna-melt-tuna-melt-TUNA-MELT-TUNA-MELT".as_bytes()).into(), value: maybe }, BinaryVec::from(vec![123, 122, 100]), true }
    }
}
