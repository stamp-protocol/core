//! This module holds the identity structures and methods.
//!
//! Here we define what an identity looks like and how all the pieces
//! ([claims](crate::identity::claim), [stamps](crate::identity::stamp), and
//! [forwards](crate::identity::Forward)) all tie together.

use crate::{
    error::{Error, Result},
    identity::{
        claim::{ClaimID, Claim, ClaimSpec, ClaimContainer},
        keychain::{ExtendKeypair, AlphaKeypair, PolicyKeypair, PublishKeypair, RootKeypair, RevocationID, RevocationReason, KeyID, Key, Keychain},
        recovery::{Recovery},
        stamp::{Confidence, Stamp, StampRevocation},
    },
    crypto::key::SecretKey,
    private::MaybePrivate,
    util::{
        Timestamp,
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
    /// The identity-unique name of this forward. This lets us reference this
    /// object by name.
    name: String,
    /// The forward type we're creating.
    val: ForwardType,
    /// Whether or not this forward is a default. For instance, you could have
    /// ten emails listed, but only one used as the default. If multiple
    /// defaults are given for a particular forward type, then the one with the
    /// most recent `Signature::date_signed` date in the `SignedForward::sig`
    /// field should be used.
    is_default: bool,
}

impl Forward {
    /// Create a new forward.
    pub fn new(name: String, val: ForwardType, is_default: bool) -> Self {
        Self {
            name,
            val,
            is_default,
        }
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
    nickname: Option<String>,
    /// A canonical list of places this identity forwards to.
    forwards: Vec<Forward>,
}

impl IdentityExtraData {
    /// Create a blank identity data container
    fn new() -> Self {
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
    /// When this identity came into being.
    created: Timestamp,
    /// Our identity recovery mechanisms. This allows us to replace our recovery
    /// keypair in the event it's lost or compromised.
    recovery: Recovery,
    /// Holds the keys for our identity.
    keychain: Keychain,
    /// The claims this identity makes.
    claims: Vec<ClaimContainer>,
    /// Extra data that can be attached to our identity.
    extra_data: IdentityExtraData,
}

impl Identity {
    /// Create a new identity.
    pub fn create(id: IdentityID, alpha_keypair: AlphaKeypair, policy_keypair: PolicyKeypair, publish_keypair: PublishKeypair, root_keypair: RootKeypair, created: Timestamp) -> Self {
        // create a recovery policy that cannot be satisfied.
        let recovery = Recovery::new();

        // create a new keychain from our keys above.
        let keychain = Keychain::new(alpha_keypair, policy_keypair, publish_keypair, root_keypair);

        // init our extra data
        let extra_data = IdentityExtraData::new();

        // create the identity
        Self {
            id,
            created,
            recovery,
            keychain,
            claims: vec![],
            extra_data,
        }
    }

    /// Create a new claim from the given data, sign it, and attach it to this
    /// identity.
    pub fn make_claim(mut self, claim_id: ClaimID, claim: ClaimSpec) -> Self {
        let claim_container = ClaimContainer::new(claim_id, claim);
        self.claims_mut().push(claim_container);
        self
    }

    /// Remove a claim from this identity, including any stamps it has received.
    pub fn remove_claim(mut self, id: &ClaimID) -> Result<Self> {
        let exists = self.claims().iter().find(|x| x.claim().id() == id);
        if exists.is_none() {
            Err(Error::IdentityClaimNotFound)?;
        }
        self.claims_mut().retain(|x| x.claim().id() != id);
        Ok(self)
    }

    /// Accept a stamp on one of our claims
    pub fn accept_stamp(mut self, stamping_identity: &Identity, stamp: Stamp) -> Result<Self> {
        stamping_identity.verify_stamp(&stamp)?;
        let claim_id = stamp.entry().claim_id();
        let claim = self.claims_mut().iter_mut().find(|x| x.claim().id() == claim_id)
            .ok_or(Error::IdentityClaimNotFound)?;
        claim.stamps_mut().push(stamp);
        Ok(self)
    }

    /// Set the policy signing key on this identity.
    pub fn set_policy_key(mut self, new_policy_keypair: PolicyKeypair, subkey_id: KeyID, revocation_id: RevocationID, revocation_reason: RevocationReason) -> Self {
        self.set_keychain(self.keychain().clone().set_policy_key(new_policy_keypair, subkey_id, revocation_id, revocation_reason));
        self
    }

    /// Set the publish signing key on this identity.
    pub fn set_publish_key(mut self, new_publish_keypair: PublishKeypair, subkey_id: KeyID, revocation_id: RevocationID, revocation_reason: RevocationReason) -> Self {
        self.set_keychain(self.keychain().clone().set_publish_key(new_publish_keypair, subkey_id, revocation_id, revocation_reason));
        self
    }

    /// Set the root signing key on this identity.
    pub fn set_root_key(mut self, new_root_keypair: RootKeypair, subkey_id: KeyID, revocation_id: RevocationID, revocation_reason: RevocationReason) -> Self {
        self.set_keychain(self.keychain().clone().set_root_key(new_root_keypair, subkey_id, revocation_id, revocation_reason));
        self
    }

    /// Add a new subkey to our identity.
    pub fn add_subkey<T: Into<String>>(mut self, key_id: KeyID, key: Key, name: T, description: Option<T>) -> Self {
        self.set_keychain(self.keychain().clone().add_subkey(key_id, key, name, description));
        self
    }

    /// Revoke one of our subkeys, for instance if it has been compromised.
    pub fn revoke_subkey(mut self, key_id: &KeyID, revocation_id: RevocationID, reason: RevocationReason) -> Result<Self> {
        self.set_keychain(self.keychain().clone().revoke_subkey(key_id, revocation_id, reason)?);
        Ok(self)
    }

    /// Remove a subkey from the keychain.
    pub fn delete_subkey(mut self, key_id: &KeyID) -> Result<Self> {
        self.set_keychain(self.keychain().clone().delete_subkey(key_id)?);
        Ok(self)
    }

    /// Set the nickname on this identity
    pub fn set_nickname(mut self, nickname: Option<&str>) -> Self {
        self.extra_data_mut().set_nickname(nickname.map(|x| String::from(x)));
        self
    }

    /// Add a forward to this identity
    pub fn add_forward<T: Into<String>>(mut self, name: T, ty: ForwardType, is_default: bool) -> Result<Self> {
        let name: String = name.into();
        if self.extra_data().forwards().iter().find(|x| x.name() == &name).is_some() {
            Err(Error::DuplicateName)?;
        }
        let forward = Forward::new(name, ty, is_default);
        self.extra_data_mut().forwards_mut().push(forward);
        Ok(self)
    }

    /// Stamp a claim with our identity.
    pub fn stamp<T: Into<Timestamp>>(&self, master_key: &SecretKey, confidence: Confidence, now: T, stampee: &IdentityID, claim: &Claim, expires: Option<T>) -> Result<Stamp> {
        Stamp::stamp(master_key, self.keychain().root(), self.id(), stampee, confidence, now, claim, expires)
    }

    /// Verify that the given stamp was actually signed by this identity.
    pub fn verify_stamp(&self, stamp: &Stamp) -> Result<()> {
        let root_keys = self.keychain().keys_root().into_iter()
            .map(|x| x.deref())
            .collect::<Vec<_>>();
        Keychain::try_keys(&root_keys, |sign_keypair| stamp.verify(&sign_keypair.clone().into()))
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

    /// Grab this identity's nickname, if it has one.
    pub fn nickname_maybe(&self) -> Option<String> {
        self.extra_data().nickname().clone()
    }

    /// Return all emails associated with this identity.
    pub fn emails(&self) -> Vec<String> {
        let mut forwards = self.extra_data().forwards().iter()
            .filter_map(|x| {
                match x.val() {
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
                match (x.is_default(), x.val()) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        util,
    };

    fn gen_master_key() -> SecretKey {
        SecretKey::new_xsalsa20poly1305()
    }

    #[test]
    fn identity_create() {
        let master_key = gen_master_key();
        let id = IdentityID::random();
        let alpha = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root = RootKeypair::new_ed25519(&master_key).unwrap();
        let created = Timestamp::now();
        let identity = Identity::create(id.clone(), alpha.clone(), policy.clone(), publish.clone(), root.clone(), created.clone());

        assert_eq!(identity.id(), &id);
        assert_eq!(identity.created(), &created);
        assert_eq!(identity.keychain().alpha(), &alpha);
        assert_eq!(identity.keychain().policy(), &policy);
        assert_eq!(identity.keychain().publish(), &publish);
        assert_eq!(identity.keychain().root(), &root);
    }

    #[test]
    fn identity_reencrypt() {
        unimplemented!();
    }

    #[test]
    fn identity_make_claim() {
        unimplemented!();
    }

    #[test]
    fn identity_remove_claim() {
        unimplemented!();
    }

    #[test]
    fn identity_accept_stamp() {
        unimplemented!();
    }

    #[test]
    fn identity_set_policy_key() {
        unimplemented!();
    }

    #[test]
    fn identity_set_publish_key() {
        unimplemented!();
    }

    #[test]
    fn identity_set_root_key() {
        unimplemented!();
    }

    #[test]
    fn identity_add_subkey() {
        unimplemented!();
    }

    #[test]
    fn identity_revoke_subkey() {
        unimplemented!();
    }

    #[test]
    fn identity_delete_subkey() {
        unimplemented!();
    }

    #[test]
    fn identity_stamp() {
        unimplemented!();
    }

    #[test]
    fn identity_verify_stamp() {
        unimplemented!();
    }

    #[test]
    fn identity_revoke_stamp() {
        unimplemented!();
    }

    #[test]
    fn identity_set_nickname() {
        let (_master_key, identity) = util::test::setup_identity_with_subkeys();
        assert_eq!(identity.extra_data().nickname().is_none(), true);
        let identity = identity.set_nickname(Some("fascistpig"));
        assert_eq!(identity.extra_data().nickname().as_ref().unwrap(), "fascistpig");
        let identity = identity.set_nickname(None);
        assert_eq!(identity.extra_data().nickname(), &None);
    }

    #[test]
    fn identity_nickname_maybe() {
        unimplemented!();
    }

    #[test]
    fn identity_emails() {
        unimplemented!();
    }

    #[test]
    fn identity_email_maybe() {
        unimplemented!();
    }

    #[test]
    fn identity_names() {
        unimplemented!();
    }

    #[test]
    fn identity_name_maybe() {
        unimplemented!();
    }

    #[test]
    fn identity_is_owned() {
        unimplemented!();
    }

    #[test]
    fn identity_strip_private() {
        unimplemented!();
    }
}

