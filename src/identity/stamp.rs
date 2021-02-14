//! A stamp is a signed seal of approval on a [claim](crate::identity::Claim).
//!
//! Stamps form the underlying trust network of the Stamp protocol. They are
//! seals of approval, and depending on who you trust, allow you to determine if
//! a particular identity is "real" or trusted.

use crate::{
    error::Result,
    identity::{
        Public,
        Subkey,
        Claim,
        ClaimID,
        IdentityID,
        VersionedIdentity,
    },
    crypto::{
        key::{SecretKey, SignKeypairSignature, SignKeypair},
        message::{self, Message},
    },
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
    fn from_stamp(stamp: &Stamp, date_revoked: Timestamp) -> Self {
        let stamp_id = stamp.id().clone();
        let stamper = stamp.entry().stamper().clone();
        let stampee = stamp.entry().stampee().clone();
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
    fn new(id: StampRevocationID, entry: StampRevocationEntry) -> Self {
        Self { id, entry }
    }

    /// Verify this stamp revocation's integrity.
    pub fn verify(&self, sign_keypair: &SignKeypair) -> Result<()> {
        let serialized = ser::serialize(self.entry())?;
        sign_keypair.verify(self.id(), &serialized)
    }
}

/// The confidence of a stamp being made.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Confidence {
    /// The stamp is being made with absolutely no verification whatsoever.
    None,
    /// Some verification of the claim happened, but it was quick and
    /// dirty.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
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

/// A stamp of approval on a claim.
///
/// Effectively, this is a signature and a collection of stamp data.
///
/// This is created by the stamper, and it is up to the claim owner to save the
/// stamp to their identity (using the `AcceptedStamp` object).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
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
        let ser = ser::serialize(&entry)?;
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
    pub fn verify(&self, sign_keypair: &SignKeypair) -> Result<()> {
        let ser = ser::serialize(self.entry())?;
        sign_keypair.verify(&self.id, &ser)
    }

    /// Create a new stamp revocation
    pub fn revoke<T: Into<Timestamp>>(&self, master_key: &SecretKey, sign_keypair: &SignKeypair, date_revoked: T) -> Result<StampRevocation> {
        let entry = StampRevocationEntry::from_stamp(self, date_revoked.into());
        let serialized = ser::serialize(&entry)?;
        let sig = sign_keypair.sign(master_key, &serialized)?;
        Ok(StampRevocation::new(StampRevocationID(sig), entry))
    }

    /// Serialize this stamp in human-readable form.
    pub fn serialize(&self) -> Result<String> {
        ser::serialize_human(self)
    }

    /// Deserialize this stamp from a byte vector.
    pub fn deserialize(slice: &[u8]) -> Result<Self> {
        ser::deserialize_human(slice)
    }
}

impl Public for Stamp {
    fn strip_private(&self) -> Self {
        self.clone()
    }
}

/// A request for a claim to be stamped (basically a CRT, in the parlance of our
/// times).
///
/// Generally this only needs to be created for *private* claims where you wish
/// to decrypt the private data then immediately encrypt it with a private key
/// from the stamper's keychain, thus giving the stamper and only the stamper
/// access to the claim's private data.
///
/// In the case of public claims, a simple "hey, can you stamp claim X" would
/// suffice because the data is public.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampRequest {
    /// The claim we wish to have stamped
    claim: Claim,
    /// The one-time key that can be used to decrypt and verify this claim.
    decrypt_key: SecretKey,
}

impl StampRequest {
    /// Create a new stamp request, given the appropriate key setup.
    ///
    /// This re-encryptes the claim with a new key, then creates a signed
    /// message to the recipient (stamper) using one of their keys.
    pub fn new(sender_master_key: &SecretKey, sender_identity_id: &IdentityID, sender_key: &Subkey, recipient_key: &Subkey, claim: &Claim) -> Result<Message> {
        let one_time_key = SecretKey::new_xsalsa20poly1305();
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
    /// claim is private, then we check the HMAC against the embedded key in the
    /// private claim data and make sure it validates. If the HMAC does not
    /// represent the data ("this doesn't represent me!") then hard pass on
    /// allowing this data to be stamped.
    pub fn open(recipient_master_key: &SecretKey, recipient_key: &Subkey, sender_key: &Subkey, req: &Message) -> Result<Claim> {
        let serialized = message::open(recipient_master_key, recipient_key, sender_key, req)?;
        let stamp_req: Self = ser::deserialize(&serialized)?;
        stamp_req.claim().as_public(stamp_req.decrypt_key())
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
    pub fn accept(master_key: &SecretKey, sign_keypair: &SignKeypair, stamping_identity: &VersionedIdentity, stamp: Stamp, now: Timestamp) -> Result<Self> {
        stamping_identity.verify_stamp(&stamp)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::Error,
        identity::{
            ClaimBin,
            Relationship,
            RelationshipType,
            ClaimSpec,
            ClaimContainer,
            Confidence,
            Key,
            Keychain,
            IdentityID,
            Identity,
            VersionedIdentity,
        },
        crypto::key::{SecretKey, SignKeypair, CryptoKeypair},
        private::{Private, MaybePrivate},
        util::{Timestamp, Date},
    };
    use std::convert::TryFrom;
    use std::str::FromStr;
    use url::Url;

    fn make_stamp(master_key: &SecretKey, sign_keypair: &SignKeypair, stamper: &IdentityID, stampee: &IdentityID, ts: Option<Timestamp>) -> Stamp {
        assert!(stamper != stampee);
        let maybe = MaybePrivate::new_public(String::from("andrew"));
        let ts = ts.unwrap_or(Timestamp::now());
        // kind of stupid to sign the claim with the same key creating the stamp
        // but it's also not incorrect.
        let claim = ClaimContainer::new(&master_key, &sign_keypair, ts.clone(), ClaimSpec::Name(maybe)).unwrap();
        Stamp::stamp(&master_key, &sign_keypair, &stamper, &stampee, Confidence::Medium, ts, claim.claim(), None).unwrap()
    }

    #[test]
    fn stamp_verify() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let mut stamp = make_stamp(&master_key, &sign_keypair, &IdentityID::random(), &IdentityID::random(), None);
        stamp.verify(&sign_keypair).unwrap();

        // let's modify the stamp. and set the confidence a bit higher. why not?
        // OH BECAUSE NOW IT DOESN'T FUCKING VERIFY YOU DINGLEBERRY
        stamp.entry_mut().set_confidence(Confidence::Extreme);
        assert_eq!(stamp.verify(&sign_keypair), Err(Error::CryptoSignatureVerificationFailed));
    }

    #[test]
    fn stamp_serde() {
        let master_bytes = vec![58, 30, 74, 149, 49, 101, 115, 190, 250, 4, 99, 141, 245, 201, 209, 83, 46, 121, 28, 174, 1, 150, 149, 118, 181, 228, 215, 78, 226, 248, 53, 152];
        let pub_bytes = vec![26, 106, 94, 179, 115, 143, 20, 33, 69, 141, 83, 70, 153, 34, 32, 255, 16, 247, 128, 73, 151, 32, 100, 94, 237, 70, 81, 136, 90, 207, 56, 198];
        let priv_bytes = vec![83, 139, 41, 104, 20, 105, 245, 17, 35, 207, 94, 108, 93, 46, 156, 41, 62, 193, 147, 102, 144, 125, 4, 83, 21, 106, 181, 144, 243, 164, 48, 24, 26, 106, 94, 179, 115, 143, 20, 33, 69, 141, 83, 70, 153, 34, 32, 255, 16, 247, 128, 73, 151, 32, 100, 94, 237, 70, 81, 136, 90, 207, 56, 198];
        let id1 = IdentityID::try_from("Q8LwXx3nZvCn13Y49OydJ0OioG8_2idvEZGlmYeiBd2VHr5GOa5C3vxE_l-zWzhc5KcMiV_enu8LxpP4TIpUqwA").unwrap();
        let id2 = IdentityID::try_from("c1lZ31CxrYGk4D3jXWrbhtetQ93kigNtJmOm09cptryHhOfeX3PMltqZet6Gql-7A0CkELbaqu_u1qXW95DkgAA").unwrap();
        let master_key = SecretKey::Xsalsa20Poly1305(sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key::from_slice(master_bytes.as_ref()).unwrap());
        let sign_keypair = SignKeypair::Ed25519(
            sodiumoxide::crypto::sign::ed25519::PublicKey::from_slice(pub_bytes.as_slice()).unwrap(),
            Some(Private::seal(&master_key, &sodiumoxide::crypto::sign::ed25519::SecretKey::from_slice(priv_bytes.as_slice()).unwrap()).unwrap())
        );

        let ts = Timestamp::from_str("2021-06-06T00:00:00-06:00").unwrap();
        let stamp = make_stamp(&master_key, &sign_keypair, &id1, &id2, Some(ts));
        let ser = stamp.serialize().unwrap();
        assert_eq!(ser, r#"---
id:
  Ed25519: zA2wZGLUIRQUcNPcZfS5lllhL8TjorFSKZ5GpdE5Ss6Qhej4w-hpQFdgnc7q_lArYtXuTisszuonCdpIFR4xBg
entry:
  stamper:
    Ed25519: Q8LwXx3nZvCn13Y49OydJ0OioG8_2idvEZGlmYeiBd2VHr5GOa5C3vxE_l-zWzhc5KcMiV_enu8LxpP4TIpUqw
  stampee:
    Ed25519: c1lZ31CxrYGk4D3jXWrbhtetQ93kigNtJmOm09cptryHhOfeX3PMltqZet6Gql-7A0CkELbaqu_u1qXW95DkgA
  claim_id:
    Ed25519: g-1Wm3zCfyHo-54MKAD6y69Ue5n6qH1XsCz9GDP0XVU_m3EBrhxFqXt9hjIOtTRxdarWrOR4An4HYdTxJZvCDw
  confidence: Medium
  date_signed: "2021-06-06T06:00:00Z"
  expires: ~"#);
        let des = Stamp::deserialize(ser.as_bytes()).unwrap();
        assert_eq!(stamp, des);
    }

    #[test]
    fn stamp_strip() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let stamp = make_stamp(&master_key, &sign_keypair, &IdentityID::random(), &IdentityID::random(), None);
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
                let master_key = SecretKey::new_xsalsa20poly1305();
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
                let (sender_master_key, root_keypair, spec_private, spec_public) = make_specs!($claimmaker, val.clone());
                let sender_identity_id = IdentityID::random();
                let subkey_key = Key::new_crypto(CryptoKeypair::new_curve25519xsalsa20poly1305(&sender_master_key).unwrap());
                let keypair = SignKeypair::new_ed25519(&sender_master_key).unwrap();
                let sender_keychain = Keychain::new(&sender_master_key, keypair.clone(), keypair.clone(), keypair.clone(), keypair.clone()).unwrap()
                    .add_subkey(&sender_master_key, subkey_key, "default:crypto", None).unwrap();
                let container_private = ClaimContainer::new(&sender_master_key, &root_keypair, Timestamp::now(), spec_private).unwrap();
                let container_public = ClaimContainer::new(&sender_master_key, &root_keypair, Timestamp::now(), spec_public).unwrap();
                let sender_subkey = sender_keychain.subkey_by_name("default:crypto").unwrap();

                let recipient_master_key = SecretKey::new_xsalsa20poly1305();
                let subkey_key = Key::new_crypto(CryptoKeypair::new_curve25519xsalsa20poly1305(&recipient_master_key).unwrap());
                let keypair = SignKeypair::new_ed25519(&recipient_master_key).unwrap();
                let recipient_keychain = Keychain::new(&recipient_master_key, keypair.clone(), keypair.clone(), keypair.clone(), keypair.clone()).unwrap()
                    .add_subkey(&recipient_master_key, subkey_key, "default:crypto", None).unwrap();
                let recipient_subkey = recipient_keychain.subkey_by_name("default:crypto").unwrap();

                let req_msg_priv = StampRequest::new(&sender_master_key, &sender_identity_id, sender_subkey, recipient_subkey, container_private.claim()).unwrap();
                let req_msg_pub = StampRequest::new(&sender_master_key, &sender_identity_id, sender_subkey, recipient_subkey, container_public.claim()).unwrap();

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

        let val = IdentityID::random();
        let (opened_priv, opened_pub) = req_open!{ raw, |_, val| ClaimSpec::Identity(val), val.clone() };
        match (opened_priv.spec().clone(), opened_pub.spec().clone()) {
            (ClaimSpec::Identity(val1), ClaimSpec::Identity(val2)) => {
                assert_eq!(val1, val);
                assert_eq!(val2, val);
                assert_eq!(val1, val2); // probably not needed but w/e
            }
            _ => panic!("Invalid claim type"),
        }

        req_open!{ Name, String::from("Hippie Steve") }
        req_open!{ Birthday, Date::from_str("1957-12-03").unwrap() }
        req_open!{ Email, String::from("decolonizing.decolonialist@decolonize.dclnze") }
        req_open!{ Photo, ClaimBin(vec![5,6,7]) }
        req_open!{ Pgp, String::from("8989898989") }
        req_open!{ Domain, String::from("get.a.job") }
        req_open!{ Url, Url::parse("http://mrwgifs.com/wp-content/uploads/2014/05/Beavis-Typing-Random-Characters-On-The-Computer-On-Mike-Judges-Beavis-and-Butt-Head.gif").unwrap() }
        req_open!{ HomeAddress, String::from("123 DOINK ln., Bork, KY 44666") }
        req_open!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        req_open!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![69,69,69])) }

        let val = ClaimBin(vec![89, 89, 89]);
        let (opened_priv, opened_pub) = req_open!{ raw, |maybe, _| ClaimSpec::Extension(String::from("a-new-kind-of-claimspec"), maybe), val.clone() };
        match (opened_priv.spec().clone(), opened_pub.spec().clone()) {
            (ClaimSpec::Extension(key1, MaybePrivate::Public(val1)), ClaimSpec::Extension(key2, MaybePrivate::Public(val2))) => {
                // the doctor said it was
                assert_eq!(key1, String::from("a-new-kind-of-claimspec"));
                assert_eq!(key2, String::from("a-new-kind-of-claimspec"));
                assert_eq!(val1, val);
                assert_eq!(val2, val);
                assert_eq!(val1, val2); // probably not needed but w/e
            }
            _ => panic!("Invalid claim type"),
        }
    }

    #[test]
    fn accepted_accept_verify() {
        let master_key_stamper = SecretKey::new_xsalsa20poly1305();
        let master_key_accepter = SecretKey::new_xsalsa20poly1305();

        let identity_stamper: VersionedIdentity = Identity::new(&master_key_stamper, Timestamp::now()).unwrap().into();

        let sign_keypair_accepter = SignKeypair::new_ed25519(&master_key_accepter).unwrap();
        let maybe = MaybePrivate::new_public(String::from("andrew"));
        let claim = ClaimContainer::new(&master_key_accepter, &sign_keypair_accepter, Timestamp::now(), ClaimSpec::Name(maybe)).unwrap();
        let stamp = Stamp::stamp(&master_key_stamper, identity_stamper.keychain().root(), &IdentityID::random(), &IdentityID::random(), Confidence::Medium, Timestamp::now(), claim.claim(), None).unwrap();

        let accepted = AcceptedStamp::accept(&master_key_accepter, &sign_keypair_accepter, &identity_stamper, stamp, Timestamp::now()).unwrap();
        accepted.verify(&sign_keypair_accepter.strip_private()).unwrap();

        let mut accepted2 = accepted.clone();
        let then = Timestamp::from_str("1999-01-01T00:00:00-06:00").unwrap();
        accepted2.set_recorded(then);
        assert_eq!(accepted2.verify(&sign_keypair_accepter.strip_private()), Err(Error::CryptoSignatureVerificationFailed));
    }

    #[test]
    fn stamp_revocation_create_verify() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let stamp = make_stamp(&master_key, &sign_keypair, &IdentityID::random(), &IdentityID::random(), None);

        // oh no i stamped superman but meant to stamp batman gee willickers

        // revocation should verify
        let rev = stamp.revoke(&master_key, &sign_keypair, Timestamp::now()).unwrap();
        rev.verify(&sign_keypair).unwrap();

        // let's modify the revocation. this should invalidate the sig.
        let mut rev2 = rev.clone();
        let then = Timestamp::from_str("1999-01-01T00:00:00-06:00").unwrap();
        rev2.entry_mut().set_date_revoked(then);
        assert_eq!(rev2.verify(&sign_keypair), Err(Error::CryptoSignatureVerificationFailed));
    }
}

