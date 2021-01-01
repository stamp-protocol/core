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

use crate::{
    error::{Error, Result},
    key::{SecretKey, SignKeypairSignature, SignKeypair},
    keychain::Keychain,
    private::MaybePrivate,
    ser,
    util::Timestamp,
};
use getset;
use serde_derive::{Serialize, Deserialize};

/// A unique identifier for identities.
///
/// We generate this by signing the string "This is my stamp." in a `DateSigner`
/// using our initial private signing key.
///
/// `IdentityID`s are permanent and are not regenerated when the keysets are
/// rotated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityID(SignKeypairSignature);

/// A unique identifier for claims.
///
/// We generate this by signing the claim's data in a `DateSigner` with our
/// current private signing key.
///
/// `IdentityID`s are permanent and are not regenerated when the keysets are
/// rotated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimID(SignKeypairSignature);

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

/// Attaches a serializable object to a date for signing.
///
/// This is a one-way object used for comparing signatures, so never needs to be
/// deserialized.
#[derive(Debug, Clone, Serialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct DateSigner<'a, 'b, T> {
    /// The date we signed this value.
    date: &'a Timestamp,
    /// The value being signed.
    value: &'b T,
}

impl<'a, 'b, T: serde::Serialize> DateSigner<'a, 'b, T> {
    /// Construct a new DateSigner
    pub fn new(date: &'a Timestamp, value: &'b T) -> Self {
        Self {
            date,
            value,
        }
    }
}

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
    date_signed: Timestamp,
}

impl StampSignatureMetadata {
    /// Create a new stamp signature metadata object.
    pub fn new(stamper: IdentityID, confidence: u8, date_signed: Timestamp) -> Self {
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
}

impl Stamp {
    /// Stamp a claim.
    ///
    /// This must be created by the identity validating the claim, using their
    /// private signing key.
    pub fn stamp(master_key: &SecretKey, sign_keypair: &SignKeypair, stamper: &IdentityID, confidence: u8, now: &Timestamp, claim: &Claim) -> Result<Self> {
        let meta = StampSignatureMetadata::new(stamper.clone(), confidence, now.clone());
        let container = StampSignatureContainer::new(meta.clone(), claim.clone());
        let ser = ser::serialize(&container)?;
        let signature = sign_keypair.sign(master_key, &ser)?;
        Ok(Self {
            signature_meta: meta,
            signature,
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
    pub fn accept(master_key: &SecretKey, sign_keypair: &SignKeypair, stamp: Stamp, now: Timestamp) -> Result<Self> {
        let datesigner = DateSigner::new(&now, &stamp);
        let serialized = ser::serialize(&datesigner)?;
        let signature = sign_keypair.sign(&master_key, &serialized)?;
        Ok(Self {
            stamp,
            recorded: now,
            signature,
        })
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
    pub fn new(master_key: &SecretKey, sign_keypair: &SignKeypair, now: Timestamp, spec: ClaimSpec) -> Result<Self> {
        let datesigner = DateSigner::new(&now, &spec);
        let serialized = ser::serialize(&datesigner)?;
        let signature = sign_keypair.sign(master_key, &serialized)?;
        let claim = Claim::new(ClaimID(signature), now, spec);
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

/// Extra public data that is attached to our identity.
///
/// Each entry in this struct is signed by our root signing key. In the case
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
}

impl IdentityExtraData {
    /// Create a blank identity data container
    pub fn new() -> Self {
        Self {
            nickname: None,
            forwards: Vec::new(),
        }
    }
}

/// An identity.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Identity {
    /// The unique identifier for this identity.
    id: IdentityID,
    /// A signature that is created by collecting all signatures contained in
    /// the identity and signing them with the root signing key.
    ///
    /// This gives any identity a verifiable completeness: if any data is added
    /// or removed that is not authorized by the identity owner, the identity
    /// will fail to validate. This can be useful in cases where an identity is
    /// distributed by a third party.
    ///
    /// This obviously doesn't guard against distributing an old (but unedited)
    /// version of an identity.
    root_signature: SignKeypairSignature,
    /// When this identity was created. This value is signed in the IdentityID
    /// via a `DateSigner`.
    created: Timestamp,
    /// Holds the keys for our identity.
    keychain: Keychain,
    /// The claims this identity makes.
    claims: Vec<ClaimContainer>,
    /// Extra data that can be attached to our identity.
    extra_data: IdentityExtraData,
}

impl Identity {
    /// Create a new identity
    pub fn new(master_key: &SecretKey, now: Timestamp) -> Result<Self> {
        let root_keypair = SignKeypair::new_ed25519(master_key)?;
        let id_string = String::from("This is my stamp.");
        let datesigner = DateSigner::new(&now, &id_string);
        let ser = ser::serialize(&datesigner)?;
        let sig = root_keypair.sign(master_key, &ser)?;
        let id = IdentityID(sig);
        let identity_claim = ClaimContainer::new(master_key, &root_keypair, now.clone(), ClaimSpec::Identity(id.clone()))?;
        let keychain = Keychain::new(root_keypair);
        let extra_data = IdentityExtraData::new();
        let temporary_root_signature = keychain.root().sign(master_key, "temporary".as_bytes())?;
        let mut identity = Self {
            id,
            root_signature: temporary_root_signature,
            created: now,
            keychain,
            claims: vec![identity_claim],
            extra_data,
        };
        identity.set_root_signature(identity.generate_root_signature(master_key)?);
        Ok(identity)
    }

    /// Grab a list of all our identity's sub-signatures.
    fn sub_signatures(&self) -> Vec<&SignKeypairSignature> {
        let mut signatures = vec![
            &self.id().0,
        ];

        // sign the signatures of all our subkeys
        for subkey in self.keychain().subkeys() {
            signatures.push(&subkey.signature());
        }

        // sign our claims and their stamps
        for claim in self.claims() {
            // sign each claim's id (which is itself a signature)
            signatures.push(&claim.claim().id().0);
            // now sign each claim's accepted stamps. the accepted stamp's
            // signature signs the entire stamp, so we can stop there.
            for stamp in claim.stamps() {
                signatures.push(&stamp.signature());
            }
        }

        // sign our extra data
        if let Some(nickname) = self.extra_data().nickname().as_ref() {
            signatures.push(nickname.signature());
        }
        for forward in self.extra_data().forwards() {
            signatures.push(forward.signature());
        }
        signatures
    }

    /// Generate a signature that is a result of signing all the identity's
    /// contained signatures *in the order they are stored*.
    ///
    /// This makes each identity completely immutable (even the order of the
    /// contained items) by anyone but the owner of the master key/root signing
    /// key.
    ///
    /// One signature to rule them all.
    fn generate_root_signature(&self, master_key: &SecretKey) -> Result<SignKeypairSignature> {
        let signatures = self.sub_signatures();
        let serialized = ser::serialize(&signatures)?;
        self.keychain().root().sign(master_key, &serialized)
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
        // verify our root signature
        let sub_signatures = self.sub_signatures();
        self.keychain().root().verify(self.root_signature(), &ser::serialize(&sub_signatures)?)?;

        // a helper that tries to verify a signature with all the signing keys
        // in the keychain, even the revoked ones.
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

        let id_string = String::from("This is my stamp.");
        let datesigner = DateSigner::new(self.created(), &id_string);
        let ser = ser::serialize(&datesigner)?;
        verify_multi(&self.id().0, &ser)
            .map_err(|_| Error::IdentityVerificationFailed(String::from("identity.id")))?;

        // now check that our claims are signed with one of our sign keys
        for claim in self.claims() {
            let datesigner = DateSigner::new(claim.claim().created(), claim.claim().spec());
            let ser = ser::serialize(&datesigner)?;
            verify_multi(&claim.claim().id().0, &ser)
                .map_err(|_| {
                    Error::IdentityVerificationFailed(format!("identity.claims[{}].id", claim.claim().id().0.to_hex()))
                })?;
        }

        Ok(())
    }
}

/// Allows identity formats to be versioned so as to not break compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityVersion {
    V1(Identity),
}

pub trait VersionedIdentity {
    /// Converts an identity into a versioned identity.
    fn version(self) -> IdentityVersion;
}

impl VersionedIdentity for Identity {
    fn version(self) -> IdentityVersion {
        IdentityVersion::V1(self)
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
        let now = Timestamp::now();
        let identity = Identity::new(&master_key, now).unwrap();

        assert_eq!(identity.keychain().subkeys().len(), 0);
        assert_eq!(identity.claims().len(), 1);
        assert!(identity.extra_data().nickname().is_none());
        assert_eq!(identity.extra_data().forwards().len(), 0);
    }

    #[test]
    fn verify() {
        let master_key = gen_master_key();
        let now = Timestamp::now();
        let identity = Identity::new(&master_key, now).unwrap();
        assert_eq!(identity.verify(), Ok(()));
    }
}

