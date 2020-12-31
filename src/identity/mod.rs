//! The identity module defines the data types and operations that define a
//! Stamp identity.
//!
//! An identity is essentially a set of keys (signing and encryption), a set of
//! claims made by the identity owner (including the identity itself), any
//! number of signatures that verify those claims, and a set of "forwards" that
//! can point to other locations (for instance, your canonical email address,
//! your personal domain, etc).
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
///
/// `IdentityID`s are permanent and are not regenerated when the keysets are
/// rotated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityID(SignKeypairSignature);

/// A unique identifier for claims.
///
/// We generate this by signing the claim's data with our current private
/// signing key.
///
/// `IdentityID`s are permanent and are not regenerated when the keysets are
/// rotated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimID(SignKeypairSignature);

/// A set of metadata that is signed when a stamp is created that is stored
/// alongside the signature itself.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampSignatureMetadata {
    /// The ID of the identity that is stamping.
    stamper: IdentityID,
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

impl StampSignatureMetadata {
    /// Create a new stamp signature metadata object.
    pub fn new(stamper: IdentityID, confidence: u8, date_signed: DateTime<Utc>) -> Self {
        Self {
            stamper,
            confidence,
            date_signed,
        }
    }
}

/// A somewhat ephemeral container used to serialize a set of data and sign it.
/// Includes metadata about the signature (`SignatureEntry`)
/// A struct used to sign a claim, only used for signing and verification (but
/// not storage).
///
/// Note that in the case of a *private* claim being signed, the signature
/// applies to the encrypted entry, not the decrypted entry, allowing peers to
/// verify that X stamped Y's claim without *knowing* Y's claim.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct StampSignatureContainer {
    /// The metadata we're signing with this signature.
    meta: StampSignatureMetadata,
    /// The claim we're signing.
    claim: Claim,
}

impl StampSignatureContainer {
    /// Create a new sig container
    fn new(meta: StampSignatureMetadata, claim: Claim) -> Self {
        Self {
            meta,
            claim,
        }
    }
}

/// A stamp of approval on a claim.
///
/// This is created by the stamper, and it is up to the claim owner to save the
/// stamp to their identity (as well as to fill in the `recorded` date).
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Stamp {
    /// The signature metadata.
    signature_meta: StampSignatureMetadata,
    /// Signature of the attached `signature_entry` data.
    signature: SignKeypairSignature,
    /// The date this stamp was saved (from the claim owner's point of view)
    recorded: Option<DateTime<Utc>>,
}

impl Stamp {
    /// Stamp a claim.
    ///
    /// This must be created by the identity validating the claim, using their
    /// private signing key.
    pub fn stamp(master_key: &SecretKey, sign_keypair: &SignKeypair, stamper: &IdentityID, confidence: u8, now: &DateTime<Utc>, claim: &Claim) -> Result<Self> {
        let meta = StampSignatureMetadata::new(stamper.clone(), confidence, now.clone());
        let container = StampSignatureContainer::new(meta.clone(), claim.clone());
        let ser = ser::serialize(&container)?;
        let signature = sign_keypair.sign(master_key, &ser)?;
        Ok(Self {
            signature_meta: meta,
            signature,
            recorded: None,
        })
    }

    /// Verify a stamp.
    ///
    /// Must have the stamper's public key, which can be obtained by querying
    /// whatever networks means are accessible for the `IdentityID` in the
    /// `signature_meta.stamper` field.
    pub fn verify(&self, sign_keypair: &SignKeypair, claim: &Claim) -> Result<()> {
        let container = StampSignatureContainer::new(self.signature_meta.clone(), claim.clone());
        let ser = ser::serialize(&container)?;
        sign_keypair.verify(&self.signature, &ser)
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
    /// The unique ID of this claim, created by signing the claim's data with
    /// our current signing keypair.
    id: ClaimID,
    /// The data we're claiming.
    spec: ClaimSpec,
}

impl Claim {
    /// Create a new claim.
    fn new(id: ClaimID, spec: ClaimSpec) -> Self {
        Self {
            id,
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
    stamps: Vec<Stamp>,
}

impl ClaimContainer {
    /// Create a new claim, sign it with our signing key, and return a container
    /// that holds the claim (with an empty set of stamps).
    pub fn new(master_key: &SecretKey, sign_keypair: &SignKeypair, spec: ClaimSpec) -> Result<Self> {
        let serialized = ser::serialize(&spec)?;
        let signature = sign_keypair.sign(master_key, &serialized)?;
        let claim = Claim::new(ClaimID(signature), spec);
        Ok(Self {
            claim,
            stamps: Vec::new(),
        })
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
    /// Create a new signed value. Requires our signing keypair and our root key
    /// (used to unlock the secret signing key).
    pub fn new(master_key: &SecretKey, sign_keypair: &SignKeypair, value: T) -> Result<Self> {
        let serialized = ser::serialize(&value)?;
        let signature = sign_keypair.sign(master_key, &serialized)?;
        Ok(Self {
            value,
            signature,
        })
    }
}

/// Why we are deprecating a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeprecationReason {
    /// No reason.
    Unspecified,
    /// Replacing this key with another.
    Superseded,
    /// This key has been compromised.
    Compromised,
}

/// Marks a key as deprecated, signed with our root key. In the case that the
/// root key is being deprecated, the deprecation must be signed with the new
/// root key.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Deprecation {
    /// Deprecation signature.
    signature: SignKeypairSignature,
    /// The reason we're deprecating this key.
    reason: DeprecationReason,
}

/// An enum that holds any type of key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Key {
    /// A signing key.
    Sign(SignKeypair),
    /// An asymmetric crypto key.
    Crypto(CryptoKeypair),
    /// Hides our private claim data
    Secret(Private<SecretKey>),
}

impl Key {
    /// Returns the `SignKeypair` if this is a signing key.
    pub fn sign(&self) -> Option<SignKeypair> {
        match self {
            Self::Sign(ref x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Returns the `SignKeypair` if this is a signing key.
    pub fn crypto(&self) -> Option<CryptoKeypair> {
        match self {
            Self::Crypto(ref x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Returns the `SignKeypair` if this is a signing key.
    pub fn secret(&self) -> Option<Private<SecretKey>> {
        match self {
            Self::Secret(ref x) => Some(x.clone()),
            _ => None,
        }
    }
}

/// Holds a subkey, signed by the identity's root key. It also stores whether or
/// not the key has been deprecated.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Subkey {
    /// The signature of this subkey's public key (unless this is a secret key,
    /// in which case we sign the encrypted secret key).
    signature: SignKeypairSignature,
    /// The key itself.
    key: Key,
    /// Allows deprecation of a key.
    deprecated: Option<Deprecation>,
}

/// Holds the keys for our identity.
///
/// This includes an always-present root signing key, and any number of other
/// keys. There's no restriction on how many keys we can have or what kind of
/// keys (signing, enryption, etc).
///
/// The keys stored here can also be deprecated. They can remain stored here for
/// the purposes of verifying old signatures or decrypting old messages, but
/// deprecated keys should not be used to sign or encrypt new data. Even the
/// root key can be deprecated in the case that it's compromised.
///
/// In the event a root key is deprecated, the subkeys must be re-signed with
/// the new root key.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Keychain {
    /// The account's root signing key.
    root: SignKeypair,
    /// Holds our subkeys, signed with our root keypair.
    subkeys: Vec<Subkey>,
}

impl Keychain {
    /// Create a new identity key collection
    pub fn new(root_keypair: SignKeypair) -> Self {
        Self {
            root: root_keypair,
            subkeys: Vec::new(),
        }
    }

    /// Grab all signing subkeys.
    pub fn subkeys_sign(&self) -> Vec<SignKeypair> {
        self.subkeys.iter()
            .map(|x| x.key().sign())
            .filter(|x| x.is_some())
            .map(|x| x.unwrap())
            .collect::<Vec<_>>()
    }

    /// Grab all crypto subkeys.
    pub fn subkeys_crypto(&self) -> Vec<CryptoKeypair> {
        self.subkeys.iter()
            .map(|x| x.key().crypto())
            .filter(|x| x.is_some())
            .map(|x| x.unwrap())
            .collect::<Vec<_>>()
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
    /// The unique identifier for this identity.
    id: IdentityID,
    /// Holds the keys for our identity.
    keychain: Keychain,
    /// The claims this identity makes.
    claims: Vec<ClaimContainer>,
    /// Extra data that can be attached to our identity.
    extra_data: IdentityExtraData,
}

impl Identity {
    /// Create a new identity
    pub fn new(master_key: &SecretKey) -> Result<Self> {
        let root_keypair = SignKeypair::new_ed25519(master_key)?;
        let sig = root_keypair.sign(master_key, "This is my stamp.".as_bytes())?;
        let id = IdentityID(sig);
        let identity_claim = ClaimContainer::new(master_key, &root_keypair, ClaimSpec::Identity(id.clone()))?;
        let keychain = Keychain::new(root_keypair);
        let extra_data = IdentityExtraData::new();
        Ok(Self {
            id,
            keychain,
            claims: vec![identity_claim],
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
            match self.keychain().root().verify(sig, bytes_to_verify) {
                Ok(_) => Ok(()),
                _ => {
                    for sign_keypair in self.keychain().subkeys_sign() {
                        if sign_keypair.verify(sig, bytes_to_verify).is_ok() {
                            return Ok(());
                        }
                    }
                    Err(())
                }
            }
        };

        verify_multi(&self.id().0, "This is my stamp.".as_bytes())
            .map_err(|_| Error::IdentityVerificationFailed(String::from("identity.id")))?;

        // now check that our claims are signed with one of our sign keys
        for claim in self.claims() {
            let ser = ser::serialize(claim.claim().spec())?;
            verify_multi(&claim.claim().id().0, &ser)
                .map_err(|_| {
                    Error::IdentityVerificationFailed(format!("identity.claims[{}].id", claim.claim().id().0.to_hex()))
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

        assert_eq!(identity.keychain().subkeys().len(), 0);
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

