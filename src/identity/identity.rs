//! This module holds the identity structures and methods.
//!
//! Here we define what an identity looks like and how all the pieces
//! ([claims](crate::identity::claim), [stamps](crate::identity::stamp), and
//! [forwards](crate::identity::Forward)) all tie together.

use crate::{
    error::{Error, Result},
    identity::{
        claim::{ClaimID, Claim, ClaimSpec, ClaimContainer},
        keychain::{RevocationReason, SignedOrRecoveredKeypair, KeyID, Key, Keychain},
        recovery::{Recovery},
        stamp::{StampID, Stamp, StampRevocation, AcceptedStamp},
        VersionedIdentity,
    },
    key::{SecretKey, SignKeypairSignature, SignKeypair},
    util::{
        Timestamp,
        sign::{DateSigner, SignedValue},
        ser,
    },
};
use getset;
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// A unique identifier for identities.
///
/// We generate this by signing the string "This is my stamp." in a `DateSigner`
/// using our initial private signing key.
///
/// `IdentityID`s are permanent and are not regenerated when the keysets are
/// rotated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityID(SignKeypairSignature);

impl Deref for IdentityID {
    type Target = SignKeypairSignature;
    fn deref(&self) -> &Self::Target {
        &self.0
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
    /// Our identity recovery mechanisms. This allows us to replace our recovery
    /// keypair in the event it's lost or compromised.
    recovery: Recovery,
    /// A signature that is created by collecting all claim, stamp, and keychain
    /// signatures contained in the identity and signing them with the root
    /// signing key.
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
    /// Inner implementation of the identity creator.
    fn new_impl(master_key: &SecretKey, now: Timestamp, alpha_keypair: SignKeypair, id: IdentityID) -> Result<Self> {
        // controls recovery policies (and ultimately the recovery key)
        let policy_keypair = SignKeypair::new_ed25519(master_key)?;
        // control publishing the identity
        let publish_keypair = SignKeypair::new_ed25519(master_key)?;
        // controls claims, stamping, the root signature, and signing subkeys
        let root_keypair = SignKeypair::new_ed25519(master_key)?;

        // create our first claim (the identity claim)
        let identity_claim = ClaimContainer::new(master_key, &root_keypair, now.clone(), ClaimSpec::Identity(id.clone()))?;

        // create a recovery policy that cannot be satisfied.
        let recovery = Recovery::new()?;

        // create a new keychain from our keys above.
        let keychain = Keychain::new(master_key, alpha_keypair, policy_keypair, publish_keypair, root_keypair)?;

        // init our extra data
        let extra_data = IdentityExtraData::new();

        // create the identity
        let blank_root_signature = SignKeypairSignature::blank(keychain.root());
        let mut identity = Self {
            id,
            recovery,
            root_signature: blank_root_signature,
            created: now,
            keychain,
            claims: vec![identity_claim],
            extra_data,
        };
        // ...and sign it with our root keypair
        identity.set_root_signature(identity.generate_root_signature(master_key)?);
        // just making sure
        identity.verify()?;
        Ok(identity)
    }

    /// Create a new random identity.
    pub fn new(master_key: &SecretKey, now: Timestamp) -> Result<Self> {
        // top doge key
        let alpha_keypair = SignKeypair::new_ed25519(master_key)?;

        // create our identity's ID
        let id_string = String::from("This is my stamp.");
        let datesigner = DateSigner::new(&now, &id_string);
        let ser = ser::serialize(&datesigner)?;
        let id = IdentityID(alpha_keypair.sign(master_key, &ser)?);

        Identity::new_impl(master_key, now, alpha_keypair, id)
    }

    /// Create a new identity with a vanity prefixed ID.
    pub fn new_vanity(master_key: &SecretKey, now: Timestamp, prefix: &str) -> Result<Self> {
        let mut alpha_keypair;
        let mut id;
        loop {
            alpha_keypair = SignKeypair::new_ed25519(master_key)?;
            let id_string = String::from("This is my stamp.");
            let datesigner = DateSigner::new(&now, &id_string);
            let ser = ser::serialize(&datesigner)?;
            id = IdentityID(alpha_keypair.sign(master_key, &ser)?);
            let based = ser::base64_encode(id.as_ref());
            println!("- trying {}", based);
            if based.starts_with(prefix) {
                break;
            }
        }
        Identity::new_impl(master_key, now, alpha_keypair, id)
    }

    /// Return a version of this identity without and private data (secret keys,
    /// mainly).
    pub(crate) fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_keychain(self.keychain().clone().strip_private());
        clone
    }

    /// Grab a list of all our identity's sub-signatures.
    fn sub_signatures(&self) -> Vec<&SignKeypairSignature> {
        let mut signatures = vec![
            &self.id().0,
        ];

        // sign the signatures of all our subkeys
        for subkey in self.keychain().subkeys() {
            // only sign keys with a public component, since these will be
            // published and can be verified. secret keys are not published and
            // therefor cannot be verified (so we don't add them to verification
            // chain)..
            match subkey.key().public_only() {
                Some(_) => signatures.push(&subkey.id()),
                None => {}
            }
        }

        // sign our claims and their stamps
        for claim in self.claims() {
            // sign each claim's id (which is itself a signature)
            signatures.push(&claim.claim().id());
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

    /// Verify that a signature and a set of data used to generate that
    /// signature can be verified by at least one of our signing keys.
    fn try_keys<F>(&self, keylist: &Vec<SignKeypair>, sigfn: F) -> Result<()>
        where F: Fn(&SignKeypair) -> Result<()>,
    {
        for sign_keypair in keylist {
            if sigfn(sign_keypair).is_ok() {
                return Ok(());
            }
        }
        Err(Error::CryptoSignatureVerificationFailed)
    }

    /// Verify that the portions of this identity that can be verified, mainly
    /// by using the identity's public signing key (or key*s* if we have revoked
    /// keys).
    ///
    /// Specifically, we verify our identity's ID, our keychain, the signatures
    /// we've made on our claims (stored in each claim's ID), and the identity's
    /// extra data entries.
    ///
    /// The idea here is that we can't verify the stamps on our claims inside
    /// the identity (we need the public keys of all the signers for that, which
    /// must not be stored alongside the signatures).
    pub fn verify(&self) -> Result<()> {
        // verify our identity ID against the alpha key.
        let id_string = String::from("This is my stamp.");
        let datesigner = DateSigner::new(self.created(), &id_string);
        let ser = ser::serialize(&datesigner)?;
        self.keychain().alpha().verify(self.id(), &ser)
            .map_err(|_| Error::IdentityVerificationFailed(String::from("identity.id")))?;

        // verify our policy and root keys against the alpha key and/or the
        // recovery chain
        self.keychain().policy().verify_value(self.keychain().alpha())
            .map_err(|_| Error::IdentityVerificationFailed(String::from("identity.keychain.policy")))?;
        self.keychain().publish().verify_signed(self.keychain().alpha())
            .or_else(|err| {
                if err != Error::SignatureMissing { return Err(err); }
                self.recovery().verify_publish(self.keychain().publish().deref())
            })
            .map_err(|_| Error::IdentityVerificationFailed(String::from("identity.keychain.publish")))?;
        self.keychain().root().verify_signed(self.keychain().alpha())
            .or_else(|err| {
                if err != Error::SignatureMissing { return Err(err); }
                self.recovery().verify_root(self.keychain().root().deref())
            })
            .map_err(|_| Error::IdentityVerificationFailed(String::from("identity.keychain.root")))?;

        // verify our root signature with our root key
        self.keychain().root().verify(self.root_signature(), &ser::serialize(&self.sub_signatures())?)
            .map_err(|_| Error::IdentityVerificationFailed(String::from("identity.root_signature")))?;

        let root_keys = self.keychain().keys_root();

        // now check that our claims are signed with one of our root keys
        for claim in self.claims() {
            let datesigner = DateSigner::new(claim.claim().created(), claim.claim().spec());
            let ser = ser::serialize(&datesigner)?;
            self.try_keys(&root_keys, |sign_keypair| sign_keypair.verify(&claim.claim().id(), &ser))
                .map_err(|_| {
                    let claim_id = base64::encode_config(claim.claim().id().as_ref(), base64::URL_SAFE_NO_PAD);
                    Error::IdentityVerificationFailed(format!("identity.claims[{}].id", claim_id))
                })?;
            for stamp in claim.stamps() {
                self.try_keys(&root_keys, |sign_keypair| stamp.verify(sign_keypair))
                    .map_err(|_| {
                        let claim_id = base64::encode_config(claim.claim().id().as_ref(), base64::URL_SAFE_NO_PAD);
                        let stamp_id = base64::encode_config(stamp.stamp().id().as_ref(), base64::URL_SAFE_NO_PAD);
                        Error::IdentityVerificationFailed(format!("identity.claims[{}].stamps[{}]", claim_id, stamp_id))
                    })?;
            }
        }

        Ok(())
    }

    /// Create a new claim from the given data, sign it, and attach it to this
    /// identity.
    pub fn make_claim<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, claim: ClaimSpec) -> Result<Self> {
        let claim_container = ClaimContainer::new(master_key, self.keychain().root(), now, claim)?;
        self.claims_mut().push(claim_container);
        Ok(self)
    }

    /// Look up a claim by ID
    pub fn find_claim(&self, claim_id: &ClaimID) -> Option<&ClaimContainer> {
        self.claims().iter().find(|x| x.claim().id() == claim_id)
    }

    /// Accept a stamp on one of our claims
    pub fn accept_stamp<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, stamp: Stamp) -> Result<Self> {
        let claim_id = stamp.entry().claim_id();
        let root_key = self.keychain().root().clone();
        let claim = self.claims_mut().iter_mut().find(|x| x.claim().id() == claim_id)
            .ok_or(Error::IdentityClaimNotFound)?;
        let accepted = AcceptedStamp::accept(master_key, &root_key, stamp, now.into())?;
        claim.stamps_mut().push(accepted);
        self.set_root_signature(self.generate_root_signature(master_key)?);
        Ok(self)
    }

    /// Remove a claim from this identity, including any stamps it has received.
    pub fn remove_claim(mut self, master_key: &SecretKey, id: &ClaimID) -> Result<Self> {
        let exists = self.claims().iter().find(|x| x.claim().id() == id);
        if exists.is_none() {
            Err(Error::IdentityClaimNotFound)?;
        }
        self.claims_mut().retain(|x| x.claim().id() != id);
        self.set_root_signature(self.generate_root_signature(master_key)?);
        Ok(self)
    }

    /// Set the policy signing key on this identity.
    pub fn set_policy_key(mut self, master_key: &SecretKey, new_policy_keypair: SignKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        self.set_keychain(self.keychain().clone().set_policy_key(master_key, self.keychain().alpha(), new_policy_keypair, revocation_reason)?);
        Ok(self)
    }

    /// Set the publish signing key on this identity.
    pub fn set_publish_key(mut self, master_key: &SecretKey, new_publish_keypair: SignKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        let signed = SignedValue::new(master_key, self.keychain().alpha(), new_publish_keypair)?;
        let wrapped = SignedOrRecoveredKeypair::Signed(signed);
        self.set_keychain(self.keychain().clone().set_publish_key(master_key, wrapped, revocation_reason)?);
        Ok(self)
    }

    /// Set the root signing key on this identity.
    pub fn set_root_key(mut self, master_key: &SecretKey, new_root_keypair: SignKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        let signed = SignedValue::new(master_key, self.keychain().alpha(), new_root_keypair)?;
        let wrapped = SignedOrRecoveredKeypair::Signed(signed);
        self.set_keychain(self.keychain().clone().set_root_key(master_key, wrapped, revocation_reason)?);
        self.set_root_signature(self.generate_root_signature(master_key)?);
        Ok(self)
    }

    /// Add a new subkey to our identity.
    pub fn add_subkey<T: Into<String>>(mut self, master_key: &SecretKey, key: Key, title: T, description: T) -> Result<Self> {
        self.set_keychain(self.keychain().clone().add_subkey(master_key, key, title, description)?);
        self.set_root_signature(self.generate_root_signature(master_key)?);
        Ok(self)
    }

    /// Revoke one of our subkeys, for instance if it has been compromised.
    pub fn revoke_subkey(mut self, master_key: &SecretKey, key_id: KeyID, reason: RevocationReason) -> Result<Self> {
        self.set_keychain(self.keychain().clone().revoke_subkey(master_key, key_id, reason)?);
        self.set_root_signature(self.generate_root_signature(master_key)?);
        Ok(self)
    }

    /// Remove a subkey from the keychain.
    pub fn delete_subkey(mut self, master_key: &SecretKey, key_id: &KeyID) -> Result<Self> {
        self.set_keychain(self.keychain().clone().delete_subkey(key_id)?);
        self.set_root_signature(self.generate_root_signature(master_key)?);
        Ok(self)
    }

    /// Stamp a claim with our identity.
    pub fn stamp<T: Into<Timestamp>>(&self, master_key: &SecretKey, confidence: u8, now: T, claim: &Claim, expires: Option<T>) -> Result<Stamp> {
        Stamp::stamp(master_key, self.keychain().root(), self.id(), confidence, now, claim, expires)
    }

    /// Revoke a stamp we've made.
    ///
    /// For instance if you've stamped the identity for the Miner 49er but it
    /// turns out it was just Hank the caretaker all along (who was trying to
    /// scare people away from the mines so he could have the oil reserves to
    /// himself), you might wish to revoke your stamp on that identity.
    ///
    /// Note that this doesn't change the claim itself on the identity the claim
    /// belongs to, but instead we must publish this revocation on whatever
    /// medium we see fit, and it is up to people to check for revocations on
    /// that medium before accepting a stamped claim as given.
    pub fn revoke_stamp<T: Into<Timestamp>>(&self, master_key: &SecretKey, stamp_id: StampID, date_revoked: T) -> Result<StampRevocation> {
        StampRevocation::new(master_key, self.keychain().root(), self.id().clone(), stamp_id, date_revoked)
    }
}

impl From<Identity> for VersionedIdentity {
    fn from(identity: Identity) -> Self {
        VersionedIdentity::V1(identity)
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
        let identity = Identity::new(&master_key, Timestamp::now()).unwrap();

        let master_key2 = gen_master_key();
        let identity2 = Identity::new(&master_key2, Timestamp::now()).unwrap();

        let claim = identity.claims()[0].claim();
        let stamp = identity2.stamp(&master_key2, 64, Timestamp::now(), claim, None).unwrap();

        let identity = identity.accept_stamp(&master_key, Timestamp::now(), stamp).unwrap();
        assert_eq!(identity.verify(), Ok(()));
    }

    #[test]
    fn serialize_human() {
        let master_key = gen_master_key();
        let now = Timestamp::now();
        let identity = Identity::new(&master_key, now).unwrap();
        let yaml = ser::serialize_human(&identity).unwrap();
        let msgpk = ser::serialize(&identity).unwrap();

        // TODO: build a nice, complete identity and (de)serialize it

        let identity2: Identity = ser::deserialize_human(yaml.as_bytes()).unwrap();
        let identity3: Identity = ser::deserialize(&msgpk).unwrap();
        assert_eq!(ser::serialize_human(&identity2).unwrap(), ser::serialize_human(&identity3).unwrap());
    }
}

