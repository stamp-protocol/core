//! A stamp is a signed seal of approval on a [claim](crate::identity::Claim).
//!
//! Stamps form the underlying trust network of the Stamp protocol. They are
//! seals of approval, and depending on who you trust, allow you to determine if
//! a particular identity is "real" or trusted.

use crate::{
    error::Result,
    identity::{
        claim::{Claim, ClaimID},
        identity::IdentityID,
        keychain::{Subkey},
    },
    crypto::{
        base::SecretKey,
        message::{self, Message},
    },
    util::{
        Public,
        Timestamp,
        ser,
    },
};
use getset;
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

object_id! {
    /// A unique identifier for stamps.
    StampID
}

object_id! {
    /// A unique identifier for a stamp revocation.
    StampRevocationID
}

/// An inner container for creating a stamp revocation.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampRevocationEntry {
    /// The identity ID of the original stamper (which must match the identity
    /// ID of the revoker).
    #[rasn(tag(explicit(0)))]
    stamper: IdentityID,
    /// The identity ID of the recipient of the original stamp.
    #[rasn(tag(explicit(1)))]
    stampee: IdentityID,
    /// The ID of the stamp we're revoking.
    #[rasn(tag(explicit(2)))]
    stamp_id: StampID,
}

impl StampRevocationEntry {
    /// Create a new stamp revocation
    pub fn new(stamper: IdentityID, stampee: IdentityID, stamp_id: StampID) -> Self {
        Self {
            stamper,
            stampee,
            stamp_id,
        }
    }
}

/// An object published when a stamper wishes to revoke their stamp.
///
/// Note that like [`Stamp` objects][Stamp], this must be wrapped in an outer transaction
/// which is what determines its validity (through signatures). A stamp revocation on
/// its own is fairly useless.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampRevocation {
    /// The unique ID of this recovation, which also happens to be the signature
    /// of the revocation.
    #[rasn(tag(explicit(0)))]
    id: StampRevocationID,
    /// Holds the revocations inner data.
    #[rasn(tag(explicit(1)))]
    entry: StampRevocationEntry,
}

impl StampRevocation {
    pub(crate) fn new(id: StampRevocationID, entry: StampRevocationEntry) -> Self {
        Self { id, entry }
    }
}

impl Public for StampRevocation {
    fn strip_private(&self) -> Self {
        self.clone()
    }

    fn has_private(&self) -> bool {
        false
    }
}

/// The confidence of a stamp being made.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Confidence {
    /// The stamp is being made with absolutely no verification whatsoever.
    #[rasn(tag(explicit(0)))]
    None,
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
    Extreme,
}

/// An inner struct type created when making a stamp. This is what is wrapped in a
/// [transaction][crate::dag::Transaction] for signing (and possibly
/// publishing).
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
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
    /// valid. This is a value between 0 and 255, and is ultimately a ratio
    /// via `c / 255`, where 0.0 is "lowest confidence" and 1.0 is "ultimate
    /// confidence." Keep in mind that 0 here is not "absolutely zero
    /// confidence" as otherwise the stamp wouldn't be occurring in the first
    /// place.
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
    pub fn new<T: Into<Timestamp>>(stamper: IdentityID, stampee: IdentityID, claim_id: ClaimID, confidence: Confidence, expires: Option<T>) -> Self {
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
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Stamp {
    /// The [transaction id][crate::dag::TransactionID] of the transaction that created
    /// this stamp.
    #[rasn(tag(explicit(0)))]
    id: StampID,
    /// The stamp entry, containing all the actual stamp data.
    #[rasn(tag(explicit(1)))]
    entry: StampEntry,
}

impl Stamp {
    pub(crate) fn new(id: StampID, entry: StampEntry) -> Self {
        Self { id, entry }
    }
}

impl Public for Stamp {
    fn strip_private(&self) -> Self {
        self.clone()
    }

    fn has_private(&self) -> bool {
        false
    }
}

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
    claim: Claim,
    /// The one-time key that can be used to decrypt and verify this claim.
    #[rasn(tag(explicit(1)))]
    decrypt_key: SecretKey,
}

impl StampRequest {
    /// Create a new stamp request, given the appropriate key setup.
    ///
    /// This re-encryptes the claim with a new key, then creates a signed
    /// message to the recipient (stamper) using one of their keys.
    pub fn new(sender_master_key: &SecretKey, sender_identity_id: &IdentityID, sender_key: &Subkey, recipient_key: &Subkey, claim: &Claim) -> Result<Message> {
        let one_time_key = SecretKey::new_xchacha20poly1305()?;
        let claim_reencrypted_spec = claim.spec().clone().reencrypt(sender_master_key, &one_time_key)?;
        let mut claim_reencrypted = claim.clone();
        claim_reencrypted.set_spec(claim_reencrypted_spec);
        let req = Self {
            claim: claim_reencrypted,
            decrypt_key: one_time_key,
        };
        let serialized = ser::serialize(&req)?;
        message::send(sender_master_key, sender_identity_id, sender_key, recipient_key, serialized.as_slice())
    }

    /// Opens a message with a StampRequest in it, and if all goes well, returns
    /// the *decrypted* claim (as a public claim).
    ///
    /// Note that if the claim is public already, this is where we stop. If the
    /// claim is private, then we check the MAC against the embedded key in the
    /// private claim data and make sure it validates. If the MAC does not
    /// represent the data ("this doesn't represent me!") then hard pass on
    /// allowing this data to be stamped.
    pub fn open(recipient_master_key: &SecretKey, recipient_key: &Subkey, sender_key: &Subkey, req: &Message) -> Result<Claim> {
        let serialized = message::open(recipient_master_key, recipient_key, sender_key, req)?;
        let stamp_req: Self = ser::deserialize(&serialized)?;
        stamp_req.claim().as_public(stamp_req.decrypt_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::Error,
        identity::{
            claim::{Relationship, RelationshipType, ClaimSpec, Claim},
            identity::IdentityID,
            keychain::{ExtendKeypair, AdminKey, AdminKeypair, Key, Keychain},
            stamp::Confidence,
        },
        crypto::base::{SecretKey, SignKeypair, CryptoKeypair},
        private::MaybePrivate,
        util::{Timestamp, Date, Url, ser::BinaryVec},
    };
    use std::str::FromStr;

    #[test]
    fn stamp_strip() {
        let entry = StampEntry::new::<Timestamp>(IdentityID::random(), IdentityID::random(), ClaimID::random(), Confidence::None, None);
        let stamp = Stamp::new(StampID::random(), entry);
        let stamp2 = stamp.strip_private();
        // we only really need strip_private() so we can serialized_human, but
        // stamps don't hold ANY private data at all, so a stripped stamp should
        // equal an unstripped stamp.
        assert_eq!(stamp, stamp2);
    }

    #[test]
    fn stamp_request_new_open() {
        // stolen/copied from claim tests. oh well. not going to dedicate a bunch
        // of infrastructure to not duplicating a 7 line macro.
        macro_rules! make_specs {
            ($claimmaker:expr, $val:expr) => {{
                let val = $val;
                let master_key = SecretKey::new_xchacha20poly1305().unwrap();
                let root_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
                let maybe_private = MaybePrivate::new_private(&master_key, val.clone()).unwrap();
                let maybe_public = MaybePrivate::new_public(val.clone());
                let spec_private = $claimmaker(maybe_private, val.clone());
                let spec_public = $claimmaker(maybe_public, val.clone());
                (master_key, root_keypair, spec_private, spec_public)
            }}
        }

        macro_rules! req_open {
            (raw, $claimmaker:expr, $val:expr) =>  {{
                let val = $val;
                let (sender_master_key, _root_keypair, spec_private, spec_public) = make_specs!($claimmaker, val.clone());
                let sender_identity_id = IdentityID::random();
                let subkey_key = Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(&sender_master_key).unwrap());
                let admin = AdminKeypair::new_ed25519(&sender_master_key).unwrap();
                let admin_key = AdminKey::new(admin, "MAIN LOL", None);
                let sender_keychain = Keychain::new(vec![admin_key])
                    .add_subkey(subkey_key, "default:crypto", None).unwrap();
                let container_private = Claim::new(ClaimID::random(), spec_private, None);
                let container_public = Claim::new(ClaimID::random(), spec_public, None);
                let sender_subkey = sender_keychain.subkey_by_name("default:crypto").unwrap();

                let recipient_master_key = SecretKey::new_xchacha20poly1305().unwrap();
                let subkey_key = Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(&recipient_master_key).unwrap());
                let admin = AdminKeypair::new_ed25519(&sender_master_key).unwrap();
                let admin_key = AdminKey::new(admin, "ALPHA MALE BIG HANDS", None);
                let recipient_keychain = Keychain::new(vec![admin_key])
                    .add_subkey(subkey_key, "default:crypto", None).unwrap();
                let recipient_subkey = recipient_keychain.subkey_by_name("default:crypto").unwrap();

                let req_msg_priv = StampRequest::new(&sender_master_key, &sender_identity_id, sender_subkey, recipient_subkey, &container_private).unwrap();
                let req_msg_pub = StampRequest::new(&sender_master_key, &sender_identity_id, sender_subkey, recipient_subkey, &container_public).unwrap();

                let res1 = StampRequest::open(&sender_master_key, recipient_subkey, sender_subkey, &req_msg_priv);
                let res2 = StampRequest::open(&sender_master_key, recipient_subkey, sender_subkey, &req_msg_pub);

                assert_eq!(res1.err(), Some(Error::CryptoOpenFailed));
                assert_eq!(res2.err(), Some(Error::CryptoOpenFailed));

                let opened_priv = StampRequest::open(&recipient_master_key, recipient_subkey, sender_subkey, &req_msg_priv).unwrap();
                let opened_pub = StampRequest::open(&recipient_master_key, recipient_subkey, sender_subkey, &req_msg_pub).unwrap();

                (opened_priv, opened_pub)
            }};

            ($claimty:ident, $val:expr) => {
                let val = $val;
                let (opened_priv, opened_pub) = req_open!{
                    raw,
                    |maybe, _| ClaimSpec::$claimty(maybe),
                    val.clone()
                };
                let getmaybe = |spec: ClaimSpec| if let ClaimSpec::$claimty(maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) };
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

        req_open!{ Identity, IdentityID::random() }
        req_open!{ Name, String::from("Hippie Steve") }
        req_open!{ Birthday, Date::from_str("1957-12-03").unwrap() }
        req_open!{ Email, String::from("decolonizing.decolonialism@decolonize.dclnze") }
        req_open!{ Photo, BinaryVec::from(vec![5,6,7]) }
        req_open!{ Pgp, String::from("8989898989") }
        req_open!{ Domain, String::from("get.a.job") }
        req_open!{ Url, Url::parse("http://mrwgifs.com/wp-content/uploads/2014/05/Beavis-Typing-Random-Characters-On-The-Computer-On-Mike-Judges-Beavis-and-Butt-Head.gif").unwrap() }
        req_open!{ Address, String::from("123 DOINK ln., Bork, KY 44666") }
        req_open!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        req_open!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, BinaryVec::from(vec![69,69,69])) }

        let val = BinaryVec::from(vec![89, 89, 89]);
        let (opened_priv, opened_pub) = req_open!{ raw, |maybe, _| ClaimSpec::Extension { key: Vec::from("a-new-kind-of-claimspec".as_bytes()).into(), value: maybe }, val.clone() };
        match (opened_priv.spec().clone(), opened_pub.spec().clone()) {
            (ClaimSpec::Extension { key: key1, value: MaybePrivate::Public(val1) }, ClaimSpec::Extension{ key: key2, value: MaybePrivate::Public(val2) }) => {
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

