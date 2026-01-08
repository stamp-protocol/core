//! A stamp is a signed seal of approval on a [claim](crate::identity::claim::Claim).
//!
//! Stamps form the underlying trust network of the Stamp protocol. They are
//! seals of approval, and depending on who you trust, allow you to determine if
//! a particular identity is "real" or trusted.

use crate::{
    crypto::{
        base::SecretKey,
        message::{self, Message},
        private::ReEncrypt,
    },
    error::Result,
    identity::{
        claim::{Claim, ClaimID},
        instance::IdentityID,
        keychain::Subkey,
    },
    util::{
        ser::{self, SerText},
        Timestamp,
    },
};
use getset;
use private_parts::{Full, Public};
use rand::{CryptoRng, RngCore};
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

/// A request for a claim to be stamped (basically a CSR, in the parlance of our
/// times).
///
/// Generally this only needs to be created for *private* claims where you wish
/// to decrypt the private data then immediately encrypt it with a private key
/// from the stamper's keychain, thus giving the stamper and only the stamper
/// access to the claim's private data.
///
/// In the case of public claims, a simple "hey, can you stamp claim X" would
/// suffice because the data is public.
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampRequest {
    /// The claim we wish to have stamped
    #[rasn(tag(explicit(0)))]
    claim: Claim<Full>,
    /// The one-time key that can be used to decrypt and verify this claim.
    #[rasn(tag(explicit(1)))]
    decrypt_key: SecretKey,
}

impl StampRequest {
    /// Create a new stamp request, given the appropriate key setup.
    ///
    /// This re-encryptes the claim with a new key, then creates a signed
    /// message to the recipient (stamper) using one of their keys.
    pub fn new_message<R: RngCore + CryptoRng>(
        rng: &mut R,
        sender_master_key: &SecretKey,
        sender_identity_id: &IdentityID,
        sender_key: &Subkey<Full>,
        recipient_key: &Subkey<Public>,
        claim: &Claim<Full>,
        one_time_key: SecretKey,
    ) -> Result<Message> {
        let claim_reencrypted_spec = claim.spec().clone().reencrypt(rng, sender_master_key, &one_time_key)?;
        let mut claim_reencrypted = claim.clone();
        claim_reencrypted.set_spec(claim_reencrypted_spec);
        let req = Self {
            claim: claim_reencrypted,
            decrypt_key: one_time_key,
        };
        let serialized = ser::serialize(&req)?;
        message::seal(rng, sender_master_key, sender_identity_id, sender_key, recipient_key, serialized.as_slice())
    }

    /// Opens a message with a StampRequest in it, and if all goes well, returns
    /// the *decrypted* claim (as a public claim).
    ///
    /// Note that if the claim is public already, this is where we stop. If the
    /// claim is private, then we check the MAC against the embedded key in the
    /// private claim data and make sure it validates. If the MAC does not
    /// represent the data ("this doesn't represent me!") then hard pass on
    /// allowing this data to be stamped.
    pub fn open(
        recipient_master_key: &SecretKey,
        recipient_key: &Subkey<Full>,
        sender_key: &Subkey<Public>,
        req: &Message,
    ) -> Result<Claim<Full>> {
        let serialized = message::open(recipient_master_key, recipient_key, sender_key, req)?;
        let stamp_req: Self = ser::deserialize(&serialized)?;
        stamp_req.claim().as_public(stamp_req.decrypt_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{
            base::{CryptoKeypair, SecretKey, SignKeypair},
            private::MaybePrivate,
        },
        error::Error,
        identity::{
            claim::{Claim, ClaimSpec, Relationship, RelationshipType},
            instance::IdentityID,
            keychain::{AdminKey, AdminKeypair, Key, Keychain},
        },
        util::{ser::BinaryVec, Date, Url},
    };
    use std::str::FromStr;

    #[test]
    fn stamp_request_new_open() {
        // stolen/copied from claim tests. oh well. not going to dedicate a bunch
        // of infrastructure to not duplicating a 7 line macro.
        macro_rules! make_specs {
            ($rng:expr, $claimmaker:expr, $val:expr) => {{
                let val = $val;
                let master_key = SecretKey::new_xchacha20poly1305($rng).unwrap();
                let root_keypair = SignKeypair::new_ed25519($rng, &master_key).unwrap();
                let maybe_private = MaybePrivate::new_private_verifiable($rng, &master_key, val.clone()).unwrap();
                let maybe_public = MaybePrivate::new_public(val.clone());
                let spec_private = $claimmaker(maybe_private, val.clone());
                let spec_public = $claimmaker(maybe_public, val.clone());
                (master_key, root_keypair, spec_private, spec_public)
            }};
        }

        macro_rules! req_open {
            (raw, $claimmaker:expr, $val:expr) => {{
                let mut rng = crate::util::test::rng();
                let val = $val;
                let (sender_master_key, _root_keypair, spec_private, spec_public) = make_specs!(&mut rng, $claimmaker, val.clone());
                let sender_identity_id = IdentityID::random();
                let subkey_key = Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &sender_master_key).unwrap());
                let admin = AdminKeypair::new_ed25519(&mut rng, &sender_master_key).unwrap();
                let admin_key = AdminKey::new(admin, "MAIN LOL", None);
                let sender_keychain = Keychain::new(vec![admin_key])
                    .add_subkey(subkey_key, "default:crypto", None)
                    .unwrap();
                let container_private = Claim::new(ClaimID::random(), spec_private, None);
                let container_public = Claim::new(ClaimID::random(), spec_public, None);
                let sender_subkey = sender_keychain.subkey_by_name("default:crypto").unwrap();

                let recipient_master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
                let subkey_key = Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &recipient_master_key).unwrap());
                let admin = AdminKeypair::new_ed25519(&mut rng, &sender_master_key).unwrap();
                let admin_key = AdminKey::new(admin, "ALPHA MALE BIG HANDS", None);
                let recipient_keychain = Keychain::new(vec![admin_key])
                    .add_subkey(subkey_key, "default:crypto", None)
                    .unwrap();
                let recipient_subkey = recipient_keychain.subkey_by_name("default:crypto").unwrap();

                let sk_tmp1 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
                let sk_tmp2 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
                let req_msg_priv = StampRequest::new_message(
                    &mut rng,
                    &sender_master_key,
                    &sender_identity_id,
                    sender_subkey,
                    &recipient_subkey.clone().into(),
                    &container_private,
                    sk_tmp1,
                )
                .unwrap();
                let req_msg_pub = StampRequest::new_message(
                    &mut rng,
                    &sender_master_key,
                    &sender_identity_id,
                    sender_subkey,
                    &recipient_subkey.clone().into(),
                    &container_public,
                    sk_tmp2,
                )
                .unwrap();

                let res1 = StampRequest::open(&sender_master_key, recipient_subkey, &sender_subkey.clone().into(), &req_msg_priv);
                let res2 = StampRequest::open(&sender_master_key, recipient_subkey, &sender_subkey.clone().into(), &req_msg_pub);

                assert_eq!(res1.err(), Some(Error::CryptoOpenFailed));
                assert_eq!(res2.err(), Some(Error::CryptoOpenFailed));

                let opened_priv =
                    StampRequest::open(&recipient_master_key, recipient_subkey, &sender_subkey.clone().into(), &req_msg_priv).unwrap();
                let opened_pub =
                    StampRequest::open(&recipient_master_key, recipient_subkey, &sender_subkey.clone().into(), &req_msg_pub).unwrap();

                (opened_priv, opened_pub)
            }};

            ($claimty:ident, $val:expr) => {
                let val = $val;
                let (opened_priv, opened_pub) = req_open! {
                    raw,
                    |maybe, _| ClaimSpec::<Full>::$claimty(maybe),
                    val.clone()
                };
                let getmaybe = |spec: ClaimSpec<Full>| {
                    if let ClaimSpec::<Full>::$claimty(maybe) = spec {
                        maybe
                    } else {
                        panic!("bad claim type: {}", stringify!($claimtype))
                    }
                };
                match (getmaybe(opened_priv.spec().clone()), getmaybe(opened_pub.spec().clone())) {
                    (MaybePrivate::Public(val1), MaybePrivate::Public(val2)) => {
                        assert_eq!(val1, val);
                        assert_eq!(val2, val);
                        assert_eq!(val1, val2); // probably not needed but w/e
                    }
                    _ => panic!("Invalid combination when opening StampRequest"),
                }
            };
        }

        req_open! { Identity, IdentityID::random() }
        req_open! { Name, String::from("Hippie Steve") }
        req_open! { Birthday, Date::from_str("1957-12-03").unwrap() }
        req_open! { Email, String::from("decolonizing.decolonialism@decolonize.dclnze") }
        req_open! { Photo, BinaryVec::from(vec![5,6,7]) }
        req_open! { Pgp, String::from("8989898989") }
        req_open! { Domain, String::from("get.a.job") }
        req_open! { Url, Url::parse("http://mrwgifs.com/wp-content/uploads/2014/05/Beavis-Typing-Random-Characters-On-The-Computer-On-Mike-Judges-Beavis-and-Butt-Head.gif").unwrap() }
        req_open! { Address, String::from("123 DOINK ln., Bork, KY 44666") }
        req_open! { Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        req_open! { RelationExtension, Relationship::new(RelationshipType::OrganizationMember, BinaryVec::from(vec![69,69,69])) }

        let val = BinaryVec::from(vec![89, 89, 89]);
        let (opened_priv, opened_pub) = req_open! { raw, |maybe, _| ClaimSpec::<Full>::Extension { key: Vec::from("a-new-kind-of-claimspec".as_bytes()).into(), value: maybe }, val.clone() };
        match (opened_priv.spec().clone(), opened_pub.spec().clone()) {
            (
                ClaimSpec::<Full>::Extension {
                    key: key1,
                    value: MaybePrivate::Public(val1),
                },
                ClaimSpec::<Full>::Extension {
                    key: key2,
                    value: MaybePrivate::Public(val2),
                },
            ) => {
                // the doctor said it was
                assert_eq!(key1, Vec::from("a-new-kind-of-claimspec".as_bytes()).into());
                assert_eq!(key2, Vec::from("a-new-kind-of-claimspec".as_bytes()).into());
                assert_eq!(val1, val);
                assert_eq!(val2, val);
                assert_eq!(val1, val2); // probably not needed but w/e
            }
            _ => panic!("Invalid claim type"),
        }
    }
}
