//! The identity module defines the data types and operations that define a
//! Stamp identity.
//!
//! An identity is essentially a master set of keys (signing and encryption),
//! a set of claims made by the identity owner (including the identity itself),
//! any number of signatures that verify those claims, and a set of "forwards"
//! that can point to other locations (for instance, your canonical email
//! address, your personal domain, etc).
//!
//! This system relies heavily on the [key](crate::key) module, which provides
//! all the mechanisms necessary for encryption, decryption, signing, and
//! verification of data.

use chrono::{DateTime, Utc};
use crate::{
    error::{Error, Result},
    key::{SecretKey, SignKeypairSignature, SignKeypair, CryptoKeypair},
    private::{Private, MaybePrivate},
    ser,
};
use getset;
use serde_derive::{Serialize, Deserialize};

/// A unique identifier for identities.
///
/// We generate this by signing the string "This is my stamp." using our initial
/// private signing key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ID(SignKeypairSignature);

/// A struct used to sign a claim, only used for signing and verification (but
/// not storage).
///
/// This is used to construct a [SignatureEntry](crate::identity::SignatureEntry)
/// object, which is ultimately what is stored with an identity.
///
/// Ths purpose of splitting these two objects apart is to make it easy to
/// provide a standard way of signing a claim without having to duplicate the
/// claim's data.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct SignatureEntryForSigning {
    /// How much confidence the stamper has that the claim being stamped is
    /// valid. This is a value between 0 and 255, and is ultimately a ratio
    /// via `c / 255`, where 0.0 is "lowest confidence" and 1.0 is "ultimate
    /// confidence." Keep in mind that 0 here is not "absolutely zero
    /// confidence" as otherwise the stamp wouldn't be occuring in the first
    /// place.
    confidence: u8,
    /// Filled in by the stamper, the date the claim was stamped
    date_signed: DateTime<Utc>,
    /// The claim data being signed.
    claimdata: ClaimSpec,
}

impl SignatureEntryForSigning {
    /// Create a new signature entry for signing.
    pub fn new(confidence: u8, date_signed: DateTime<Utc>, claimdata: ClaimSpec) -> Self {
        Self {
            confidence,
            date_signed,
            claimdata,
        }
    }
}

/// An entry used to describe a signature on a claim.
///
/// This includes the date it was signed, the confidence of the stamp, and
/// optionally the claim data itself (present for the signature, but absent when
/// stored).
///
/// Note that in the case of a *private* claim being signed, the signature
/// applies to the encrypted entry, not the decrypted entry, allowing peers to
/// verify that X stamped Y's claim without *knowing* Y's claim.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct SignatureEntry {
    /// How much confidence the stamper has that the claim being stamped is
    /// valid. This is a value between 0 and 255, and is ultimately a ratio
    /// via `c / 255`, where 0.0 is "lowest confidence" and 1.0 is "ultimate
    /// confidence." Keep in mind that 0 here is not "absolutely zero
    /// confidence" as otherwise the stamp wouldn't be occuring in the first
    /// place.
    confidence: u8,
    /// Filled in by the stamper, the date the claim was stamped
    date_signed: DateTime<Utc>,
}

impl SignatureEntry {
    /// Take a `SignatureEntryForSigning`, sign it, and return a
    /// `SignatureEntry` and the signature.
    pub fn generate_signed_entry(master_key: &SecretKey, sign_keypair: &SignKeypair, entry_to_sign: SignatureEntryForSigning) -> Result<(Self, SignKeypairSignature)> {
        let ser = ser::serialize(&entry_to_sign)?;
        let sig = sign_keypair.sign(master_key, &ser)?;
        let SignatureEntryForSigning { confidence, date_signed, .. } = entry_to_sign;
        let entry = SignatureEntry {
            confidence,
            date_signed,
        };
        Ok((entry, sig))
    }
}

/// A draft of stamp of approval on a claim.
///
/// The draft is created by the stamper, and is then converted to a `Stamp` by
/// the owner of the claim when they wish to record it.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampDraft {
    /// Who stamped it
    from: ID,
    /// Signature of the attached `signature_entry` data.
    signature: SignKeypairSignature,
    /// Their signature
    signature_entry: SignatureEntry,
}

impl StampDraft {
    /// Create a new stamp on a claim.
    pub fn stamp(our_id: &ID, master_key: &SecretKey, sign_keypair: &SignKeypair, claim_data: &ClaimSpec, confidence: u8, now: DateTime<Utc>) -> Result<Self> {
        let signature_entry_for_signing = SignatureEntryForSigning::new(confidence, now, claim_data.clone());
        let (signature_entry, signature) = SignatureEntry::generate_signed_entry(master_key, sign_keypair, signature_entry_for_signing)?;
        Ok(Self {
            from: our_id.clone(),
            signature,
            signature_entry,
        })
    }
}

/// A stamp of approval on a claim.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Stamp {
    /// Who stamped it
    from: ID,
    /// Signature of the attached `signature_entry` data.
    signature: SignKeypairSignature,
    /// Their signature
    signature_entry: SignatureEntry,
    /// The date this stamp was saved (from the claim owner's point of view)
    date_recorded: DateTime<Utc>,
}

impl Stamp {
    /// Create a new stamp from a stamp draft
    pub fn new(stamp_draft: StampDraft, now: DateTime<Utc>) -> Self {
        let StampDraft { from, signature, signature_entry } = stamp_draft;
        Self {
            from,
            signature,
            signature_entry,
            date_recorded: now,
        }
    }
}

/// Various types of codified relationships.
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
    Identity(ID),
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
    Relation(Relationship, MaybePrivate<ID>),
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

/// A claim made by an identity.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Claim {
    /// The unique ID of this claim, created by signing the claim itself with
    /// our current signing keypair.
    ///
    /// IDs are not updated if the keyset is rotated.
    id: ID,
    /// The data we're claiming.
    data: ClaimSpec,
    /// Stamps that have been made on our claim.
    stamps: Vec<Stamp>,
}

impl Claim {
    /// Create a new claim and sign it with our signing key.
    pub fn new(master_key: &SecretKey, sign_keypair: &SignKeypair, data: ClaimSpec) -> Result<Self> {
        let serialized = ser::serialize(&data)?;
        let signature = sign_keypair.sign(master_key, &serialized)?;
        Ok(Self {
            id: ID(signature),
            data: data,
            stamps: Vec::new(),
        })
    }
}

/// A Keyset is a set of keys.
///
/// One key to encrypt messages.
/// One key to hide them.
/// One key to verify claims, and in the darkness sign them.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Keyset {
    /// Signs our claims and others' claims
    sign: SignKeypair,
    /// Lets others send us encrypted messages, and us them.
    crypto: CryptoKeypair,
    /// Hides our private claim data
    secret: Private<SecretKey>,
}

impl Keyset {
    pub fn new(master_key: &SecretKey) -> Result<Self> {
        Ok(Self {
            sign: SignKeypair::new_ed25519(master_key)?,
            crypto: CryptoKeypair::new_curve25519xsalsa20poly1305(master_key)?,
            secret: Private::seal(master_key, &SecretKey::new_xsalsa20poly1305())?,
        })
    }
}

/// Describes te various versions our for our identity format, allowing upgrades
/// and downgrades.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IdentityVersion {
    V1,
}

impl Default for IdentityVersion {
    fn default() -> Self {
        Self::V1
    }
}

/// A set of forward types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForwardType {
    /// An email address
    Email(String),
    /// A social identity. This is two strings to represent type and handle/url.
    Social(String, String),
    /// A PGP keypair ID or URL to a published public key
    PGP(String),
    /// A raw url.
    Url(String),
    /// An extension type, can be used to implement any kind of forward you can
    /// think of.
    Extension(Vec<u8>),
}

/// A pointer to somewhere else.
///
/// This can be useful for pointing either people or machines to a known
/// location. For instance, if you switch Mastodon servers, you could add a new
/// "Mastodon" forward pointing to your new handle and mark it as the default
/// for that forward type. Or you could forward to your personal domain, or
/// your email address.
///
/// Each forward is signed with your signing secret key. This is a bit different
/// from a claim in that claims help verify your identity, and forwards are
/// assertions you can make that don't require external verification. If people
/// trust that this is *your* identity via the signed claims, then they can
/// trust the forwards you assert and sign.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Forward {
    /// The forward type we're creating
    val: ForwardType,
    /// Whether or not this forward is a default. For instance, you could have
    /// ten emails listed, but only one used as the default. If multiple
    /// defaults are given for a particular forward type, then the one with the
    /// most recent `Signature::date_signed` date in the `SignedForward::sig`
    /// field should be used.
    is_default: bool,
}

/// A struct that wraps any type and requires it to be signed in order to be
/// created or modified.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct SignedValue<T: serde::Serialize> {
    /// The value we wish to sign.
    value: T,
    /// The signature for our value.
    signature: SignKeypairSignature,
}

impl<T: serde::Serialize> SignedValue<T> {
    /// Create a new signed value. Requires our signing keypair and our master
    /// key (used to unlock the secret signing key).
    pub fn new(master_key: &SecretKey, sign_keypair: &SignKeypair, value: T) -> Result<Self> {
        let serialized = ser::serialize(&value)?;
        let signature = sign_keypair.sign(master_key, &serialized)?;
        Ok(Self {
            value,
            signature,
        })
    }
}

/// Extra public data that is attached to our identity.
///
/// Each entry in this struct is signed by our secret signing key. In the case
/// that our identity is re-keyed, the entries in this struct must be re-signed.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct IdentityExtraData {
    /// An always-public nickname that can be used to look up this identity
    /// in various indexed locations. This will always have `stamp://` prepended
    /// to it, so don't include it here.
    ///
    /// For instance, I might set my nickname as "zefram-cochrane" and
    /// from thereafter people will be able to find me via the nickname
    /// `stamp://zefram-cochrane`.
    ///
    /// Note that this necessarily cannot be unique, so services that index the
    /// nickname will need to list *all* known identities using that shortname.
    /// Note that it will be possible to specify a hex ID in long or short-form,
    /// such as `stamp://zefram-cochrane/b07f4429c5`.
    ///
    /// It's up to users of the protocol to pick names that are unique enough to
    /// avoid accidental collisions, and any malicious immitations must be
    /// weeded out by inclusion of an ID (prefix or full), stamp verification
    /// and trust levels.
    nickname: Option<SignedValue<String>>,
    /// A canonical list of places this identity forwards to.
    forwards: Vec<SignedValue<Forward>>,
    /// A field for storing any signed data we wish to store alongside our
    /// identity.
    extension: Option<SignedValue<Vec<u8>>>,
}

impl IdentityExtraData {
    /// Create a blank identity data container
    pub fn new() -> Self {
        Self {
            nickname: None,
            forwards: Vec::new(),
            extension: None,
        }
    }
}

/// An identity.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Identity {
    /// The version of this identity.
    version: IdentityVersion,
    /// The unique identifier for this identity.
    id: ID,
    /// The identity's current and default master key set.
    keyset: Keyset,
    /// The claims this identity makes.
    claims: Vec<Claim>,
    /// Expired or deprecated or compromised keysets. We keep these in order to
    /// allow others to verify past claims we have stamped, and also to decrypt
    /// messages encrypted to us with the old keys, in case someone has an old
    /// version of the identity.
    ///
    /// New information must not be signed or encrypted with the old keys.
    ///
    /// The old keysets must be appended to, that is, new entries must be added
    /// to the end of the list.
    old_keysets: Vec<Keyset>,
    /// Extra data that can be attached to our identity.
    extra_data: IdentityExtraData,
}

impl Identity {
    /// Create a new identity
    pub fn new(master_key: &SecretKey) -> Result<Self> {
        let keyset = Keyset::new(master_key)?;
        let sig = keyset.sign().sign(master_key, "This is my stamp.".as_bytes())?;
        let id = ID(sig);
        let extra_data = IdentityExtraData::new();
        let identity_claim = Claim::new(master_key, keyset.sign(), ClaimSpec::Identity(id.clone()))?;
        Ok(Self {
            version: IdentityVersion::default(),
            id,
            keyset,
            claims: vec![identity_claim],
            old_keysets: Vec::new(),
            extra_data,
        })
    }

    /// Verify that the portions of this identity that can be verified, mainly
    /// by using the identity's public signing key.
    ///
    /// Specifically, we verify our identity's ID, the signatures we've made on
    /// our claims (stored in each claim's ID), and the identity's extra data
    /// entries.
    ///
    /// The idea here is that we can't verify the stamps on our claims inside
    /// the identity (we need the public keys of all the signers for that, which
    /// must not be stored alongside the signatures).
    pub fn verify(&self) -> Result<()> {
        let verify_multi = |sig: &SignKeypairSignature, bytes_to_verify: &[u8]| -> std::result::Result<(), ()> {
            match self.keyset().sign().verify(sig, bytes_to_verify) {
                Ok(_) => Ok(()),
                _ => {
                    for keyset in self.old_keysets() {
                        if keyset.sign().verify(sig, bytes_to_verify).is_ok() {
                            return Ok(());
                        }
                    }
                    Err(())
                }
            }
        };

        verify_multi(&self.id().0, "This is my stamp.".as_bytes())
            .map_err(|_| Error::IdentityVerificationFailed(String::from("identity.id")))?;

        // now check that our claims are signed with our
        for claim in self.claims() {
            let ser = ser::serialize(claim.data())?;
            verify_multi(&claim.id().0, &ser)
                .map_err(|_| {
                    Error::IdentityVerificationFailed(format!("identity.claims[{}].id", claim.id().0.to_hex()))
                })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_master_key() -> SecretKey {
        SecretKey::new_xsalsa20poly1305()
    }

    #[test]
    fn init() {
        let master_key = gen_master_key();
        let identity = Identity::new(&master_key).unwrap();

        assert_eq!(identity.version(), &IdentityVersion::default());
        assert_eq!(identity.old_keysets().len(), 0);
        assert_eq!(identity.claims().len(), 1);
        assert!(identity.extra_data().nickname().is_none());
        assert_eq!(identity.extra_data().forwards().len(), 0);
        assert!(identity.extra_data().extension().is_none());
    }

    #[test]
    fn verify() {
        let master_key = gen_master_key();
        let identity = Identity::new(&master_key).unwrap();
        assert_eq!(identity.verify(), Ok(()));
    }
}

