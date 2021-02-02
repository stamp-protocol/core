//! This module holds the identity structures and methods.
//!
//! Here we define what an identity looks like and how all the pieces
//! ([claims](crate::identity::claim), [stamps](crate::identity::stamp), and
//! [forwards](crate::identity::Forward)) all tie together.

use crate::{
    error::{Error, Result},
    identity::{
        Public,
        PublicMaybe,
        VersionedIdentity,

        claim::{ClaimID, Claim, ClaimSpec, ClaimContainer},
        keychain::{RevocationReason, SignedOrRecoveredKeypair, KeyID, Key, Keychain},
        recovery::{Recovery},
        stamp::{Confidence, Stamp, StampRevocation, AcceptedStamp},
    },
    crypto::key::{SecretKey, SignKeypairSignature, SignKeypair},
    private::MaybePrivate,
    util::{
        Timestamp,
        sign::{DateSigner, Signable, SignedValue},
        ser,
    },
};
use getset;
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

object_id! {
    /// A unique identifier for identities.
    ///
    /// We generate this by signing the string "This is my stamp." in a `DateSigner`
    /// using our initial private signing key.
    ///
    /// `IdentityID`s are permanent and are not regenerated when the keysets are
    /// rotated.
    IdentityID
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
    Extension(String, Vec<u8>),
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

impl Signable for Forward {
    type Item = Forward;
    fn signable(&self) -> Self::Item {
        self.clone()
    }
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
    /// such as `stamp://zefram-cochrane/s0yB0i-4y822` to narrow down the result
    /// by the nickname *and* ID.
    ///
    /// It's up to users of the protocol to pick names that are unique enough to
    /// avoid accidental collisions, and any malicious immitations must be
    /// weeded out by inclusion of an ID (prefix or full), stamp verification,
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

    /// Re-sign the extra data in this identity with a new root key.
    fn resign(mut self, master_key: &SecretKey, root_key: &SignKeypair) -> Result<Self> {
        match self.nickname_mut().as_mut() {
            Some(x) => {
                let val = x.value().clone();
                *x = SignedValue::new(master_key, root_key, val)?;
            }
            None => {},
        }
        for forward in self.forwards_mut() {
            let val = forward.value().clone();
            *forward = SignedValue::new(master_key, root_key, val)?;
        }
        Ok(self)
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
    fn id_gen(now: &Timestamp) -> Result<Vec<u8>> {
        let id_string = String::from("This is my stamp.");
        let datesigner = DateSigner::new(now, &id_string);
        ser::serialize(&datesigner)
    }

    /// Given an alpha key and a timestamp, create a (deterministic) identity ID.
    pub fn create_id(master_key: &SecretKey, alpha_keypair: &SignKeypair, now: &Timestamp) -> Result<IdentityID> {
        // create our identity's ID
        let ser = Self::id_gen(now)?;
        let id = IdentityID(alpha_keypair.sign(master_key, &ser)?);
        Ok(id)
    }

    /// Create a new identity from an existing alpha keypair, timestamp, and
    /// identity ID.
    pub fn new_with_alpha_and_id(master_key: &SecretKey, now: Timestamp, alpha_keypair: SignKeypair, id: IdentityID) -> Result<Self> {
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
        let id = Identity::create_id(master_key, &alpha_keypair, &now)?;
        Identity::new_with_alpha_and_id(master_key, now, alpha_keypair, id)
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
            match subkey.key().strip_private_maybe() {
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

    /// Regenerate the root signature on this identity.
    ///
    /// This is mainly used for development to save an identity that's corrupt
    /// due to buggy code. This should not be used as a regular feature, because
    /// its entire need is based on a buggy stamp protocol implementation.
    pub fn root_sign(mut self, master_key: &SecretKey) -> Result<Self> {
        self.set_root_signature(self.generate_root_signature(master_key)?);
        self.verify()?;
        Ok(self)
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
        let ser = Self::id_gen(self.created())?;
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
        self.keychain().verify_subkeys()
            .map_err(|_| Error::IdentityVerificationFailed(String::from("identity.keychain.subkeys")))?;

        // verify our root signature with our root key
        self.keychain().root().verify(self.root_signature(), &ser::serialize(&self.sub_signatures())?)
            .map_err(|_| Error::IdentityVerificationFailed(String::from("identity.root_signature")))?;

        let root_keys = self.keychain().keys_root();

        // now check that our claims are signed with one of our root keys
        for claim in self.claims() {
            let stripped_spec = claim.claim().spec().strip_private();
            let datesigner = DateSigner::new(claim.claim().created(), &stripped_spec);
            let ser = ser::serialize(&datesigner)?;
            Keychain::try_keys(&root_keys, |sign_keypair| sign_keypair.verify(&claim.claim().id(), &ser))
                .map_err(|_| {
                    let claim_id = base64::encode_config(claim.claim().id().as_ref(), base64::URL_SAFE_NO_PAD);
                    Error::IdentityVerificationFailed(format!("identity.claims[{}].id", claim_id))
                })?;
            for stamp in claim.stamps() {
                Keychain::try_keys(&root_keys, |sign_keypair| stamp.verify(sign_keypair))
                    .map_err(|_| {
                        let claim_id = base64::encode_config(claim.claim().id().as_ref(), base64::URL_SAFE_NO_PAD);
                        let stamp_id = base64::encode_config(stamp.stamp().id().as_ref(), base64::URL_SAFE_NO_PAD);
                        Error::IdentityVerificationFailed(format!("identity.claims[{}].stamps[{}]", claim_id, stamp_id))
                    })?;
            }
        }

        Ok(())
    }

    /// Re-encrypt this identity's keychain and private claims.
    pub fn reencrypt(mut self, current_key: &SecretKey, new_key: &SecretKey) -> Result<Self> {
        self.set_keychain(self.keychain().clone().reencrypt(current_key, new_key)?);
        for claim in self.claims_mut() {
            let new_spec = claim.claim().spec().clone().reencrypt(current_key, new_key)?;
            claim.claim_mut().set_spec(new_spec);
        }
        Ok(self)
    }

    /// Create a new claim from the given data, sign it, and attach it to this
    /// identity.
    pub fn make_claim<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, claim: ClaimSpec) -> Result<Self> {
        let claim_container = ClaimContainer::new(master_key, self.keychain().root(), now, claim)?;
        self.claims_mut().push(claim_container);
        self.set_root_signature(self.generate_root_signature(master_key)?);
        self.verify()?;
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
        self.verify()?;
        Ok(self)
    }

    /// Accept a stamp on one of our claims
    pub fn accept_stamp<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, stamping_identity: &VersionedIdentity, stamp: Stamp) -> Result<Self> {
        let claim_id = stamp.entry().claim_id();
        let root_key = self.keychain().root().clone();
        let claim = self.claims_mut().iter_mut().find(|x| x.claim().id() == claim_id)
            .ok_or(Error::IdentityClaimNotFound)?;
        let accepted = AcceptedStamp::accept(master_key, &root_key, stamping_identity, stamp, now.into())?;
        claim.stamps_mut().push(accepted);
        self.set_root_signature(self.generate_root_signature(master_key)?);
        self.verify()?;
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
        self.set_extra_data(self.extra_data().clone().resign(master_key, self.keychain().root())?);
        self.verify()?;
        Ok(self)
    }

    /// Add a new subkey to our identity.
    pub fn add_subkey<T: Into<String>>(mut self, master_key: &SecretKey, key: Key, name: T, description: Option<T>) -> Result<Self> {
        self.set_keychain(self.keychain().clone().add_subkey(master_key, key, name, description)?);
        self.set_root_signature(self.generate_root_signature(master_key)?);
        self.verify()?;
        Ok(self)
    }

    /// Revoke one of our subkeys, for instance if it has been compromised.
    pub fn revoke_subkey(mut self, master_key: &SecretKey, key_id: &KeyID, reason: RevocationReason) -> Result<Self> {
        self.set_keychain(self.keychain().clone().revoke_subkey(master_key, key_id, reason)?);
        self.set_root_signature(self.generate_root_signature(master_key)?);
        self.verify()?;
        Ok(self)
    }

    /// Remove a subkey from the keychain.
    pub fn delete_subkey(mut self, master_key: &SecretKey, key_id: &KeyID) -> Result<Self> {
        self.set_keychain(self.keychain().clone().delete_subkey(key_id)?);
        self.set_root_signature(self.generate_root_signature(master_key)?);
        self.verify()?;
        Ok(self)
    }

    /// Stamp a claim with our identity.
    pub fn stamp<T: Into<Timestamp>>(&self, master_key: &SecretKey, confidence: Confidence, now: T, stampee: &IdentityID, claim: &Claim, expires: Option<T>) -> Result<Stamp> {
        Stamp::stamp(master_key, self.keychain().root(), self.id(), stampee, confidence, now, claim, expires)
    }

    /// Verify that the given stamp was actually signed by this identity.
    pub fn verify_stamp(&self, stamp: &Stamp) -> Result<()> {
        let root_keys = self.keychain().keys_root();
        Keychain::try_keys(&root_keys, |sign_keypair| stamp.verify(sign_keypair))
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
    pub fn revoke_stamp<T: Into<Timestamp>>(&self, master_key: &SecretKey, stamp: &Stamp, date_revoked: T) -> Result<StampRevocation> {
        if self.id() != stamp.entry().stamper() {
            Err(Error::IdentityIDMismatch)?;
        }
        stamp.revoke(master_key, self.keychain().root(), date_revoked)
    }

    /// Send a message to this identity.
    ///
    /// The message will be signed by a key belonging to the *sender*, allowing
    /// the receiver to verify that the message came from the sender and not
    /// some random troll. Opening will require having the sender's identity.
    pub fn send_message(&self) -> Result<()> {
        Ok(())
    }

    /// Send an anonymous message to this identity.
    ///
    /// Anonymous messages are *not* signed by the sender, and thus do not
    /// require having their identity available to open/verify. However, they
    /// also do not provide any sort of proof as to the origin of the message.
    pub fn send_anonymous_message(&self) -> Result<()> {
        Ok(())
    }

    /// Grab this identity's nickname, if it has one.
    pub fn nickname_maybe(&self) -> Option<String> {
        self.extra_data().nickname().as_ref().map(|x| x.value().clone())
    }

    /// Return all emails associated with this identity.
    pub fn emails(&self) -> Vec<String> {
        let mut forwards = self.extra_data().forwards().iter()
            .filter_map(|x| {
                match x.value().val() {
                    ForwardType::Email(ref email) => Some(email.clone()),
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        let mut claims = self.claims().iter()
            .filter_map(|x| {
                match x.claim().spec() {
                    ClaimSpec::Email(MaybePrivate::Public(ref email)) => Some(email.clone()),
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        forwards.append(&mut claims);
        forwards
    }

    /// Grab this identity's primary email, if it has one.
    pub fn email_maybe(&self) -> Option<String> {
        // first search forwards for a default email. if that fails, check our
        // claims department.
        self.extra_data().forwards().iter()
            .find_map(|x| {
                match (x.value().is_default(), x.value().val()) {
                    (true, ForwardType::Email(ref email)) => Some(email.clone()),
                    _ => None,
                }
            })
            .or_else(|| {
                self.claims().iter()
                    .find_map(|x| {
                        match x.claim().spec() {
                            ClaimSpec::Email(MaybePrivate::Public(ref email)) => Some(email.clone()),
                            _ => None,
                        }
                    })
            })
    }

    /// Return all names associated with this identity.
    pub fn names(&self) -> Vec<String> {
        self.claims().iter()
            .filter_map(|x| {
                match x.claim().spec() {
                    ClaimSpec::Name(MaybePrivate::Public(ref name)) => Some(name.clone()),
                    _ => None,
                }
            })
            .collect::<Vec<_>>()
    }

    /// Grab this identity's primary name, if it has one.
    pub fn name_maybe(&self) -> Option<String> {
        self.claims().iter()
            .find_map(|x| {
                match x.claim().spec() {
                    ClaimSpec::Name(MaybePrivate::Public(ref name)) => Some(name.clone()),
                    _ => None,
                }
            })
    }

    /// Determine if this identity is owned (ie, we have the private keys stored
    /// locally) or it is imported (ie, someone else's identity).
    pub fn is_owned(&self) -> bool {
        self.keychain().alpha().has_private() ||
            self.keychain().policy().has_private() ||
            self.keychain().publish().has_private() ||
            self.keychain().root().has_private()
    }

    /// Test if a master key is correct.
    pub fn test_master_key(&self, master_key: &SecretKey) -> Result<()> {
        if !self.is_owned() {
            Err(Error::IdentityNotOwned)?;
        }

        let test_bytes = sodiumoxide::randombytes::randombytes(32);
        if self.keychain().alpha().has_private() {
            self.keychain().alpha().sign(master_key, test_bytes.as_slice())?;
        } else if self.keychain().policy().has_private() {
            self.keychain().policy().sign(master_key, test_bytes.as_slice())?;
        } else if self.keychain().publish().has_private() {
            self.keychain().publish().sign(master_key, test_bytes.as_slice())?;
        } else if self.keychain().root().has_private() {
            self.keychain().root().sign(master_key, test_bytes.as_slice())?;
        }
        Ok(())
    }
}

impl Public for Identity {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_keychain(self.keychain().clone().strip_private());
        let claims = self.claims().clone().into_iter()
            .map(|mut x| {
                x.set_claim(x.claim().strip_private());
                x
            })
            .collect::<Vec<_>>();
        clone.set_claims(claims);
        clone
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
        let stamp = identity2.stamp(&master_key2, Confidence::Medium, Timestamp::now(), identity.id(), claim, None).unwrap();

        let versioned2 = identity2.into();
        let identity = identity.accept_stamp(&master_key, Timestamp::now(), &versioned2, stamp).unwrap();
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

