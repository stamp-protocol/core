//! This module holds the identity structures and methods.
//!
//! Here we define what an identity looks like and how all the pieces
//! ([claims](crate::identity::claim), [stamps](crate::identity::stamp), and
//! [forwards](crate::identity::Forward)) all tie together.

use crate::{
    error::{Error, Result},
    crypto::key::{SecretKey, SignKeypair},
    identity::{
        claim::{ClaimID, Claim, ClaimSpec, ClaimContainer},
        keychain::{ExtendKeypair, AlphaKeypair, PolicyKeypair, PublishKeypair, RootKeypair, RevocationReason, Key, Keychain},
        recovery::{PolicyCondition, PolicyID, PolicyRequestAction, PolicyRequestEntry, PolicyRequest, RecoveryPolicy},
        stamp::{Confidence, StampID, Stamp, StampRevocation},
    },
    private::MaybePrivate,
    util::{
        Public,
        Timestamp,
        ser::{self, BinaryVec},
    },
};
use getset;
use rand::{RngCore, rngs::OsRng};
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::convert::TryInto;
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
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum ForwardType {
    /// An email address
    #[rasn(tag(explicit(0)))]
    Email(String),
    /// A social identity. This is two strings to represent type and handle/url.
    #[rasn(tag(explicit(1)))]
    Social {
        #[rasn(tag(explicit(0)))]
        ty: String,
        #[rasn(tag(explicit(1)))]
        handle: String,
    },
    /// A PGP keypair ID or URL to a published public key
    #[rasn(tag(explicit(2)))]
    PGP(String),
    /// A raw url.
    #[rasn(tag(explicit(3)))]
    Url(String),
    /// An extension type, can be used to implement any kind of forward you can
    /// think of.
    #[rasn(tag(explicit(4)))]
    Extension {
        #[rasn(tag(explicit(0)))]
        ty: String,
        #[rasn(tag(explicit(1)))]
        data: BinaryVec,
    },
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
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Forward {
    /// The identity-unique name of this forward. This lets us reference this
    /// object by name.
    #[rasn(tag(explicit(0)))]
    name: String,
    /// The forward type we're creating.
    #[rasn(tag(explicit(1)))]
    val: ForwardType,
    /// Whether or not this forward is a default. For instance, you could have
    /// ten emails listed, but only one used as the default. If multiple
    /// defaults are given for a particular forward type, then the one with the
    /// most recent `Signature::date_signed` date in the `SignedForward::sig`
    /// field should be used.
    #[rasn(tag(explicit(2)))]
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
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
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
    ///
    /// NOTE that the nickname is only useful for discovery of an identity in
    /// the network. It must *not* be included in forwards or claim proofs,
    /// because if the nickname changes then the forward or claim proof will
    /// break. It's really meant as a quick way to allow people to find your
    /// identity, as opposed to a piece of static information used by other
    /// systems.
    #[rasn(tag(explicit(0)))]
    nickname: Option<String>,
    /// A canonical list of places this identity forwards to.
    #[rasn(tag(explicit(1)))]
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
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Identity {
    /// The unique identifier for this identity.
    #[rasn(tag(explicit(0)))]
    id: IdentityID,
    /// When this identity came into being.
    #[rasn(tag(explicit(1)))]
    created: Timestamp,
    /// Our identity recovery mechanism. This allows us to replace various
    /// keypairs in the event they're lost or compromised and we don't have or
    /// don't want to use our alpha key.
    #[rasn(tag(explicit(2)))]
    recovery_policy: Option<RecoveryPolicy>,
    /// Holds the keys for our identity.
    #[rasn(tag(explicit(3)))]
    keychain: Keychain,
    /// The claims this identity makes.
    #[rasn(tag(explicit(4)))]
    claims: Vec<ClaimContainer>,
    /// Extra data that can be attached to our identity.
    #[rasn(tag(explicit(5)))]
    extra_data: IdentityExtraData,
}

impl Identity {
    /// Create a new identity.
    pub(crate) fn create(id: IdentityID, alpha_keypair: AlphaKeypair, policy_keypair: PolicyKeypair, publish_keypair: PublishKeypair, root_keypair: RootKeypair, created: Timestamp) -> Self {
        // create a new keychain from our keys above.
        let keychain = Keychain::new(alpha_keypair, policy_keypair, publish_keypair, root_keypair);

        // init our extra data
        let extra_data = IdentityExtraData::new();

        // create the identity
        Self {
            id,
            created,
            recovery_policy: None,
            keychain,
            claims: vec![],
            extra_data,
        }
    }

    /// Set the current recovery policy.
    pub(crate) fn set_recovery(mut self, policy_id: PolicyID, conditions: Option<PolicyCondition>) -> Self {
        if let Some(conditions) = conditions {
            self.set_recovery_policy(Some(RecoveryPolicy::new(policy_id, conditions)));
        } else {
            self.set_recovery_policy(None);
        }
        self
    }

    /// Execute a recovery against the current policy.
    pub(crate) fn execute_recovery(self, request: PolicyRequest) -> Result<Self> {
        let policy = self.recovery_policy().as_ref().ok_or(Error::IdentityMissingRecoveryPolicy)?;
        policy.validate_request(self.id(), &request)?;
        match request.entry().action() {
            PolicyRequestAction::ReplaceKeys { policy, publish, root } => {
                self.set_policy_key(policy.clone(), RevocationReason::Recovery)?
                    .set_publish_key(publish.clone(), RevocationReason::Recovery)?
                    .set_root_key(root.clone(), RevocationReason::Recovery)
            }
        }
    }

    /// Create a new claim from the given data, sign it, and attach it to this
    /// identity.
    pub(crate) fn make_claim(mut self, claim_id: ClaimID, claim: ClaimSpec, created: Timestamp) -> Self {
        let claim_container = ClaimContainer::new(claim_id, claim, created);
        self.claims_mut().push(claim_container);
        self
    }

    /// Remove a claim from this identity, including any stamps it has received.
    pub(crate) fn delete_claim(mut self, id: &ClaimID) -> Result<Self> {
        let exists = self.claims().iter().find(|x| x.claim().id() == id);
        if exists.is_none() {
            Err(Error::IdentityClaimNotFound)?;
        }
        self.claims_mut().retain(|x| x.claim().id() != id);
        Ok(self)
    }

    /// Accept a stamp on one of our claims.
    pub(crate) fn accept_stamp(mut self, stamp: Stamp) -> Result<Self> {
        let claim_id = stamp.entry().claim_id();
        let claim = self.claims_mut().iter_mut().find(|x| x.claim().id() == claim_id)
            .ok_or(Error::IdentityClaimNotFound)?;
        if claim.stamps().iter().find(|x| x.id() == stamp.id()).is_some() {
            Err(Error::IdentityStampAlreadyExists)?;
        }
        claim.stamps_mut().push(stamp);
        Ok(self)
    }

    /// Remove a stamp from one of our claims.
    pub(crate) fn delete_stamp(mut self, stamp_id: &StampID) -> Result<Self> {
        let mut found = None;
        for claim in self.claims_mut() {
            for stamp in claim.stamps() {
                if stamp.id() == stamp_id {
                    found = Some(claim);
                    break;
                }
            }
            if found.is_some() { break; }
        }

        if let Some(claim) = found {
            claim.stamps_mut().retain(|x| x.id() != stamp_id);
            Ok(self)
        } else {
            Err(Error::IdentityStampNotFound)
        }
    }

    /// Set the policy signing key on this identity.
    pub(crate) fn set_policy_key(mut self, new_policy_keypair: PolicyKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        self.set_keychain(self.keychain().clone().set_policy_key(new_policy_keypair, revocation_reason)?);
        Ok(self)
    }

    /// Set the publish signing key on this identity.
    pub(crate) fn set_publish_key(mut self, new_publish_keypair: PublishKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        self.set_keychain(self.keychain().clone().set_publish_key(new_publish_keypair, revocation_reason)?);
        Ok(self)
    }

    /// Set the root signing key on this identity.
    pub(crate) fn set_root_key(mut self, new_root_keypair: RootKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        self.set_keychain(self.keychain().clone().set_root_key(new_root_keypair, revocation_reason)?);
        Ok(self)
    }

    /// Add a new subkey to our identity.
    pub(crate) fn add_subkey<T: Into<String>>(mut self, key: Key, name: T, description: Option<T>) -> Result<Self> {
        self.set_keychain(self.keychain().clone().add_subkey(key, name, description)?);
        Ok(self)
    }

    /// Update the name/description on a subkey.
    pub(crate) fn edit_subkey<T: Into<String>>(mut self, name: &str, new_name: T, description: Option<T>) -> Result<Self> {
        self.set_keychain(self.keychain().clone().edit_subkey(name, new_name, description)?);
        Ok(self)
    }

    /// Revoke one of our subkeys, for instance if it has been compromised.
    pub(crate) fn revoke_subkey(mut self, name: &str, reason: RevocationReason, new_name: Option<String>) -> Result<Self> {
        self.set_keychain(self.keychain().clone().revoke_subkey(name, reason, new_name)?);
        Ok(self)
    }

    /// Remove a subkey from the keychain.
    pub(crate) fn delete_subkey(mut self, name: &str) -> Result<Self> {
        self.set_keychain(self.keychain().clone().delete_subkey(name)?);
        Ok(self)
    }

    /// Set the nickname on this identity
    pub(crate) fn set_nickname(mut self, nickname: Option<String>) -> Self {
        self.extra_data_mut().set_nickname(nickname);
        self
    }

    /// Add a forward to this identity
    pub(crate) fn add_forward<T: Into<String>>(mut self, name: T, ty: ForwardType, is_default: bool) -> Result<Self> {
        let name: String = name.into();
        if self.extra_data().forwards().iter().find(|x| x.name() == &name).is_some() {
            Err(Error::DuplicateName)?;
        }
        let forward = Forward::new(name, ty, is_default);
        self.extra_data_mut().forwards_mut().push(forward);
        Ok(self)
    }

    /// Add a forward to this identity
    pub(crate) fn delete_forward(mut self, name: &str) -> Result<Self> {
        let forwards = self.extra_data_mut().forwards_mut();
        if forwards.iter().find(|x| x.name() == name).is_none() {
            Err(Error::IdentityForwardNotFound)?;
        }
        forwards.retain(|x| x.name() != name);
        Ok(self)
    }

    /// Create a new recovery request. Once made, we can go out and get all of
    /// our little friends to sign it so we can recovery our identity.
    pub fn create_recovery_request(&self, master_key: &SecretKey, new_policy_key: &PolicyKeypair, action: PolicyRequestAction) -> Result<PolicyRequest> {
        let policy_id = self.recovery_policy().as_ref().ok_or(Error::IdentityMissingRecoveryPolicy)?.id().clone();
        let entry = PolicyRequestEntry::new(self.id().clone(), policy_id, action); 
        PolicyRequest::new(master_key, new_policy_key, entry)
    }

    /// Sign someone else's recovery policy request. This is how signatures are
    /// added to the request, possibly allowing for the recovery of an identity.
    pub fn sign_recovery_request(&self, master_key: &SecretKey, sign_keypair: &SignKeypair, request: PolicyRequest) -> Result<PolicyRequest> {
        request.sign(master_key, sign_keypair)
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
        let mut randbuf = [0u8; 32];
        OsRng.fill_bytes(&mut randbuf);
        let test_bytes = Vec::from(&randbuf[..]);
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

    /// Serialize this identity in human readable format.
    ///
    /// Note that this cannot be undone: an identity cannot be deserialized from
    /// this format. This is for display only.
    pub fn serialize(&self) -> Result<String> {
        ser::serialize_human(self)
    }
}

impl Public for Identity {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_keychain(clone.keychain().strip_private());
        clone.set_claims(clone.claims().iter().map(|c| c.strip_private()).collect::<Vec<_>>());
        clone
    }

    fn has_private(&self) -> bool {
        self.keychain().has_private() || self.claims().iter().find(|c| c.has_private()).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::key::SignKeypair,
        util,
    };
    use std::str::FromStr;

    fn gen_master_key() -> SecretKey {
        SecretKey::new_xchacha20poly1305().unwrap()
    }

    fn create_identity() -> (SecretKey, Identity) {
        let master_key = gen_master_key();
        let id = IdentityID::random();
        let alpha = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root = RootKeypair::new_ed25519(&master_key).unwrap();
        let created = Timestamp::now();
        let identity = Identity::create(id.clone(), alpha.clone(), policy.clone(), publish.clone(), root.clone(), created.clone());
        (master_key, identity)
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
        assert!(identity.recovery_policy().is_none());
        assert_eq!(identity.created(), &created);
        assert_eq!(identity.keychain().alpha(), &alpha);
        assert_eq!(identity.keychain().policy(), &policy);
        assert_eq!(identity.keychain().publish(), &publish);
        assert_eq!(identity.keychain().root(), &root);
    }

    #[test]
    fn identity_set_recovery() {
        let policy_id = PolicyID::random();
        let conditions = PolicyCondition::Any(vec![PolicyCondition::Deny]);
        let (_master_key, identity) = create_identity();
        assert!(identity.recovery_policy().is_none());
        let identity2 = identity.set_recovery(policy_id.clone(), Some(conditions.clone()));
        assert_eq!(identity2.recovery_policy().as_ref().unwrap().id(), &policy_id);
        assert_eq!(identity2.recovery_policy().as_ref().unwrap().conditions(), &conditions);
    }

    #[test]
    fn identity_create_sign_execute_recovery() {
        let (master_key, identity) = create_identity();
        let new_policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let new_publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let new_root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let action = PolicyRequestAction::ReplaceKeys {
            policy: new_policy_keypair.clone(),
            publish: new_publish_keypair.clone(),
            root: new_root_keypair.clone(),
        };

        let res = identity.create_recovery_request(&master_key, &new_policy_keypair, action.clone());
        // you can't triple-stamp a double-stamp
        assert_eq!(res.err(), Some(Error::IdentityMissingRecoveryPolicy));

        let policy_id = PolicyID::random();
        let conditions = PolicyCondition::Deny;
        let identity2 = identity.set_recovery(policy_id.clone(), Some(conditions));

        let req = identity2.create_recovery_request(&master_key, &new_policy_keypair, action.clone()).unwrap();
        let res = identity2.clone().execute_recovery(req);
        assert_eq!(res.err(), Some(Error::PolicyConditionMismatch));

        let (gus_master, gus) = util::test::setup_identity_with_subkeys();
        let (_marty_master, marty) = util::test::setup_identity_with_subkeys();
        let (jackie_master, jackie) = util::test::setup_identity_with_subkeys();
        let gus_sign = gus.keychain().subkey_by_name("sign").unwrap().as_signkey().unwrap().clone();
        let marty_sign = marty.keychain().subkey_by_name("sign").unwrap().as_signkey().unwrap().clone();
        let jackie_sign = jackie.keychain().subkey_by_name("sign").unwrap().as_signkey().unwrap().clone();

        let identity3 = identity2.set_recovery(policy_id.clone(), Some(PolicyCondition::OfN {
            must_have: 2,
            pubkeys: vec![
                gus_sign.clone().into(),
                marty_sign.clone().into(),
                jackie_sign.clone().into(),
            ],
        }));

        let req = identity3.create_recovery_request(&master_key, &new_policy_keypair, action.clone()).unwrap();
        let res = identity3.clone().execute_recovery(req);
        assert_eq!(res.err(), Some(Error::PolicyConditionMismatch));

        let req = identity3.create_recovery_request(&master_key, &new_policy_keypair, action.clone()).unwrap();
        let req_signed_1 = gus.sign_recovery_request(&gus_master, &gus_sign, req.clone()).unwrap();
        let res = identity3.clone().execute_recovery(req_signed_1.clone());
        assert_eq!(res.err(), Some(Error::PolicyConditionMismatch));

        let req_signed_2 = jackie.sign_recovery_request(&jackie_master, &jackie_sign, req_signed_1.clone()).unwrap();
        let identity4 = identity3.clone().execute_recovery(req_signed_2.clone()).unwrap();

        assert!(identity3.keychain().policy() != identity4.keychain().policy());
        assert!(identity3.keychain().publish() != identity4.keychain().publish());
        assert!(identity3.keychain().root() != identity4.keychain().root());
        assert_eq!(identity3.keychain().subkeys().len(), 0);
        assert_eq!(identity4.keychain().policy(), &new_policy_keypair);
        assert_eq!(identity4.keychain().publish(), &new_publish_keypair);
        assert_eq!(identity4.keychain().root(), &new_root_keypair);
        assert_eq!(identity4.keychain().subkeys().len(), 3);
        assert_eq!(identity4.keychain().subkeys()[0].name(), &format!("revoked:policy:{}", identity3.keychain().policy().key_id().as_string()));
        assert_eq!(identity4.keychain().subkeys()[1].name(), &format!("revoked:publish:{}", identity3.keychain().publish().key_id().as_string()));
        assert_eq!(identity4.keychain().subkeys()[2].name(), &format!("revoked:root:{}", identity3.keychain().root().key_id().as_string()));
    }

    #[test]
    fn identity_claim_make_delete() {
        let (_master_key, identity) = create_identity();

        let claim_id = ClaimID::random();
        let spec = ClaimSpec::Identity(IdentityID::random());
        assert_eq!(identity.claims().len(), 0);
        let identity = identity.make_claim(claim_id.clone(), spec.clone(), Timestamp::now());
        assert_eq!(identity.claims().len(), 1);
        assert_eq!(identity.claims()[0].claim().id(), &claim_id);
        match (identity.claims()[0].claim().spec(), &spec) {
            (ClaimSpec::Identity(val), ClaimSpec::Identity(val2)) => assert_eq!(val, val2),
            _ => panic!("bad claim type"),
        }

        let claim_id2 = ClaimID::random();
        let spec2 = ClaimSpec::Name(MaybePrivate::new_public(String::from("BOND. JAMES BOND.")));
        let identity = identity.make_claim(claim_id2.clone(), spec2.clone(), Timestamp::now());
        assert_eq!(identity.claims().len(), 2);
        assert_eq!(identity.claims()[0].claim().id(), &claim_id);
        assert_eq!(identity.claims()[1].claim().id(), &claim_id2);

        let identity = identity.delete_claim(&claim_id).unwrap();
        assert_eq!(identity.claims().len(), 1);
        assert_eq!(identity.claims()[0].claim().id(), &claim_id2);

        let res = identity.clone().delete_claim(&claim_id);
        assert_eq!(res.err(), Some(Error::IdentityClaimNotFound));
    }

    #[test]
    fn identity_stamp_accept_delete_verify_revoke() {
        let (_master_key_stampee, identity_stampee) = create_identity();
        let (master_key_stamper, identity_stamper) = create_identity();

        let claim_id = ClaimID::random();
        let spec = ClaimSpec::Identity(IdentityID::random());
        let identity_stampee = identity_stampee.make_claim(claim_id.clone(), spec.clone(), Timestamp::now());

        let stamp = identity_stamper.stamp(&master_key_stamper, Confidence::High, Timestamp::now(), identity_stampee.id(), identity_stampee.claims()[0].claim(), None).unwrap();
        identity_stamper.verify_stamp(&stamp).unwrap();

        let revocation = identity_stamper.revoke_stamp(&master_key_stamper, &stamp, Timestamp::now()).unwrap();
        revocation.verify(identity_stamper.keychain().root()).unwrap();

        let mut stamp_mod = stamp.clone();
        stamp_mod.entry_mut().set_confidence(Confidence::None); // very very log energy
        let res = identity_stamper.verify_stamp(&stamp_mod);
        assert_eq!(res.err(), Some(Error::CryptoSignatureVerificationFailed));

        let identity_stampee = identity_stampee.clone().accept_stamp(stamp.clone()).unwrap();
        assert_eq!(identity_stampee.claims()[0].stamps().len(), 1);

        let identity_stampee2 = identity_stampee.clone().delete_claim(identity_stampee.claims()[0].claim().id()).unwrap();
        let res = identity_stampee2.clone().accept_stamp(stamp.clone());
        assert_eq!(res.err(), Some(Error::IdentityClaimNotFound));

        let identity_stampee3 = identity_stampee.clone().delete_stamp(stamp.id()).unwrap();
        assert_eq!(identity_stampee3.claims()[0].stamps().len(), 0);
        let res = identity_stampee3.delete_stamp(stamp.id());
        assert_eq!(res.err(), Some(Error::IdentityStampNotFound));
    }

    #[test]
    fn identity_set_keys_brah_whoaaa_shaka_gnargnar_so_pitted_whapow() {
        let (master_key, identity) = create_identity();
        macro_rules! keytest {
            ($keyty:ident, $setter:ident, $getter:ident) => {
                let old_keypair = identity.keychain().$getter().clone();
                let new_keypair = $keyty::new_ed25519(&master_key).unwrap();
                assert!(old_keypair != new_keypair);
                let identity2 = identity.clone().$setter(new_keypair.clone(), RevocationReason::Unspecified).unwrap();
                assert_eq!(identity2.keychain().$getter(), &new_keypair);
                assert!(&old_keypair != identity2.keychain().$getter());
            }
        }
        keytest!{ PolicyKeypair, set_policy_key, policy }
        keytest!{ PublishKeypair, set_publish_key, publish }
        keytest!{ RootKeypair, set_root_key, root }
    }

    #[test]
    fn identity_subkey_add_revoke_edit_delete() {
        let (master_key, identity) = create_identity();

        assert_eq!(identity.keychain().subkeys().len(), 0);
        let signkey = SignKeypair::new_ed25519(&master_key).unwrap();
        let key = Key::Sign(signkey.clone());
        let identity = identity.add_subkey(key.clone(), "default:sign", Some("get a job")).unwrap();
        assert_eq!(identity.keychain().subkeys().len(), 1);
        assert_eq!(identity.keychain().subkeys()[0].name(), "default:sign");
        assert_eq!(identity.keychain().subkeys()[0].description(), &Some("get a job".into()));
        assert_eq!(identity.keychain().subkeys()[0].key().as_signkey(), Some(&signkey));
        assert_eq!(identity.keychain().subkeys()[0].revocation().is_some(), false);

        let res = identity.clone().add_subkey(key, "default:sign", Some("get a job"));
        assert_eq!(res.err(), Some(Error::DuplicateName));
        assert_eq!(identity.keychain().subkeys()[0].revocation().is_some(), false);

        let identity = identity.edit_subkey("default:sign", "sign:shutup-parker-thank-you-shutup", None).unwrap();
        assert_eq!(identity.keychain().subkeys().len(), 1);
        assert_eq!(identity.keychain().subkeys()[0].name(), "sign:shutup-parker-thank-you-shutup");
        assert_eq!(identity.keychain().subkeys()[0].description(), &None);
        assert_eq!(identity.keychain().subkeys()[0].key().as_signkey(), Some(&signkey));
        assert_eq!(identity.keychain().subkeys()[0].revocation().is_some(), false);

        let identity = identity.revoke_subkey("sign:shutup-parker-thank-you-shutup", RevocationReason::Superseded, Some("thank-you".into())).unwrap();
        assert_eq!(identity.keychain().subkeys().len(), 1);
        assert_eq!(identity.keychain().subkeys()[0].name(), "thank-you");
        assert_eq!(identity.keychain().subkeys()[0].description(), &None);
        assert_eq!(identity.keychain().subkeys()[0].key().as_signkey(), Some(&signkey));
        assert_eq!(identity.keychain().subkeys()[0].revocation().is_some(), true);

        let res = identity.clone().revoke_subkey("thank-you", RevocationReason::Superseded, Some("thank-you".into()));
        assert_eq!(res.err(), Some(Error::IdentitySubkeyAlreadyRevoked));

        let identity = identity.delete_subkey("thank-you").unwrap();
        assert_eq!(identity.keychain().subkeys().len(), 0);

        let res = identity.clone().delete_subkey("thank-you");
        assert_eq!(res.err(), Some(Error::IdentitySubkeyNotFound));
    }

    #[test]
    fn identity_nicknames() {
        let (_master_key, identity) = util::test::setup_identity_with_subkeys();
        assert_eq!(identity.extra_data().nickname().is_none(), true);
        let identity = identity.set_nickname(Some("fascistpig".into()));
        assert_eq!(identity.extra_data().nickname().as_ref().unwrap(), "fascistpig");
        assert_eq!(identity.nickname_maybe(), Some("fascistpig".into()));
        let identity = identity.set_nickname(None);
        assert_eq!(identity.extra_data().nickname(), &None);
        assert_eq!(identity.nickname_maybe(), None);
    }

    #[test]
    fn identity_forward_add_delete() {
        let (_master_key, identity) = util::test::setup_identity_with_subkeys();
        assert_eq!(identity.extra_data().forwards().len(), 0);
        let forward = ForwardType::Social {
            ty: "matrix".into(),
            handle: "@jayjay-the-stinky-hippie:matrix.oorg".into(),
        };

        let identity = identity.add_forward("matrix", forward.clone(), true).unwrap();
        assert_eq!(identity.extra_data().forwards().len(), 1);
        assert_eq!(identity.extra_data().forwards()[0].name(), "matrix");
        assert_eq!(identity.extra_data().forwards()[0].val(), &forward);
        assert_eq!(identity.extra_data().forwards()[0].is_default(), &true);

        let identity = identity.delete_forward("matrix").unwrap();
        assert_eq!(identity.extra_data().forwards().len(), 0);

        let res = identity.clone().delete_forward("matrix");
        assert_eq!(res.err(), Some(Error::IdentityForwardNotFound));

    }

    #[test]
    fn identity_emails_maybe() {
        let (_master_key, identity) = create_identity();
        assert_eq!(identity.emails().len(), 0);
        assert_eq!(identity.email_maybe(), None);

        let claim_id = ClaimID::random();
        let spec = ClaimSpec::Email(MaybePrivate::new_public(String::from("poopy@butt.com")));
        let identity = identity.make_claim(claim_id.clone(), spec.clone(), Timestamp::now());
        assert_eq!(identity.emails(), vec!["poopy@butt.com".to_string()]);
        assert_eq!(identity.email_maybe(), Some("poopy@butt.com".to_string()));

        let forward1 = ForwardType::Social {
            ty: "matrix".into(),
            handle: "@jayjay-the-stinky-hippie:matrix.oorg".into(),
        };
        let forward2 = ForwardType::Email("dirk@delta.com".into());
        let forward3 = ForwardType::Email("jabjabjabjab@jabjabjabberjaw.com".into());

        let identity2 = identity.clone().add_forward("matrixlol", forward1.clone(), true).unwrap();
        let identity3 = identity.clone().add_forward("email", forward2.clone(), true).unwrap();
        let identity4 = identity3.clone().add_forward("email2", forward3.clone(), true).unwrap();

        assert_eq!(identity2.email_maybe(), Some("poopy@butt.com".to_string()));
        assert_eq!(identity3.email_maybe(), Some("dirk@delta.com".to_string()));
        assert_eq!(identity4.email_maybe(), Some("dirk@delta.com".to_string()));
        assert_eq!(identity3.emails(), vec![
            "dirk@delta.com".to_string(),
            "poopy@butt.com".to_string(),
        ]);
        assert_eq!(identity4.emails(), vec![
            "dirk@delta.com".to_string(),
            "jabjabjabjab@jabjabjabberjaw.com".to_string(),
            "poopy@butt.com".to_string(),
        ]);

        let identity5 = identity4.delete_forward("email").unwrap();
        assert_eq!(identity5.email_maybe(), Some("jabjabjabjab@jabjabjabberjaw.com".to_string()));
    }

    #[test]
    fn identity_names_maybe() {
        let (_master_key, identity) = create_identity();
        assert_eq!(identity.names().len(), 0);
        assert_eq!(identity.name_maybe(), None);

        let claim_id = ClaimID::random();
        let spec = ClaimSpec::Name(MaybePrivate::new_public(String::from("BOND. JAMES BOND.")));
        let identity = identity.make_claim(claim_id.clone(), spec.clone(), Timestamp::now());
        assert_eq!(identity.names(), vec!["BOND. JAMES BOND.".to_string()]);
        assert_eq!(identity.name_maybe(), Some("BOND. JAMES BOND.".to_string()));

        let claim_id2 = ClaimID::random();
        let spec = ClaimSpec::Name(MaybePrivate::new_public(String::from("Jack Mama")));
        let identity = identity.make_claim(claim_id2.clone(), spec.clone(), Timestamp::now());
        assert_eq!(identity.names(), vec!["BOND. JAMES BOND.".to_string(), "Jack Mama".to_string()]);
        assert_eq!(identity.name_maybe(), Some("BOND. JAMES BOND.".to_string()));

        let identity2 = identity.clone().delete_claim(&claim_id).unwrap();
        assert_eq!(identity2.names().len(), 1);
        assert_eq!(identity2.name_maybe(), Some("Jack Mama".to_string()));
        let identity3 = identity2.clone().delete_claim(&claim_id2).unwrap();
        assert_eq!(identity3.names().len(), 0);
        assert_eq!(identity3.name_maybe(), None);
    }

    #[test]
    fn identity_is_owned() {
        let (_master_key, identity) = create_identity();
        assert!(identity.is_owned());

        let mut identity2 = identity.clone();
        identity2.set_keychain(identity.keychain().strip_private());
        assert!(!identity2.is_owned());
    }

    #[test]
    fn identity_test_master_key() {
        let (master_key, identity) = create_identity();
        let master_key_fake = gen_master_key();
        assert!(master_key.as_ref() != master_key_fake.as_ref());

        identity.test_master_key(&master_key).unwrap();
        let res = identity.test_master_key(&master_key_fake);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
    }

    #[test]
    fn identity_serialize() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let now = Timestamp::from_str("1977-06-07T04:32:06Z").unwrap();
        let seeds = [
            &[33, 90, 159, 88, 22, 24, 84, 4, 237, 121, 198, 195, 71, 238, 107, 91, 235, 93, 9, 129, 252, 221, 2, 149, 250, 142, 49, 36, 161, 184, 44, 156],
            &[170, 39, 114, 32, 79, 238, 151, 138, 85, 59, 44, 153, 147, 105, 161, 127, 180, 225, 13, 119, 143, 46, 119, 153, 203, 41, 129, 240, 180, 88, 201, 37],
            &[67, 150, 243, 61, 128, 149, 195, 141, 16, 154, 144, 63, 21, 245, 243, 226, 244, 55, 168, 59, 66, 45, 15, 61, 152, 5, 101, 219, 43, 137, 197, 90],
            &[179, 112, 207, 116, 174, 196, 118, 123, 235, 202, 236, 69, 169, 209, 65, 238, 204, 235, 194, 187, 37, 246, 180, 124, 8, 116, 207, 175, 95, 87, 159, 137],
        ];
        let alpha = AlphaKeypair::new_ed25519_from_seed(&master_key, seeds[0]).unwrap();
        let policy = PolicyKeypair::new_ed25519_from_seed(&master_key, seeds[1]).unwrap();
        let publish = PublishKeypair::new_ed25519_from_seed(&master_key, seeds[2]).unwrap();
        let root = RootKeypair::new_ed25519_from_seed(&master_key, seeds[3]).unwrap();

        let sig = alpha.sign(&master_key, "get a job".as_bytes()).unwrap();
        let id = IdentityID::from(sig.deref().clone());

        let identity = Identity::create(id.clone(), alpha.clone(), policy.clone(), publish.clone(), root.clone(), now.clone());
        let ser = identity.serialize().unwrap();
        assert_eq!(ser, r#"---
id:
  Ed25519: fCIX7Z3EiXIanC2819hWhF3oNW9gg6ujZKW8D_Y1lfZJJODmkkjVJlOZKCtM6YMa_fSS4i6Witse0k2UlZ-GAQ
created: "1977-06-07T04:32:06Z"
recovery_policy: ~
keychain:
  alpha:
    Ed25519:
      public: dHNopBN3YZrNa52xiVxB1IoY9NsrCz1c9cL8lLTu69U
      secret: ~
  policy:
    Ed25519:
      public: s5YuvOaxr4y1qQBzZyJJ0SduYXf8toYfLa2izUgcT2I
      secret: ~
  publish:
    Ed25519:
      public: B1NXKqP26jGll8tT12CCLbGxo09Do2M-A6VvRJoW87M
      secret: ~
  root:
    Ed25519:
      public: 75w-F9acRAKDCDdeAiOYTAz9BUoky98lO5rHNSeodQg
      secret: ~
  subkeys: []
claims: []
extra_data:
  nickname: ~
  forwards: []"#);
    }

    #[test]
    fn identity_strip_has_private() {
        let (master_key, identity) = create_identity();
        let identity = identity.make_claim(ClaimID::random(), ClaimSpec::Name(MaybePrivate::new_private(&master_key, "Bozotron".to_string()).unwrap()), Timestamp::now());
        assert!(identity.has_private());
        assert!(identity.keychain().has_private());
        assert!(identity.claims().iter().find(|c| c.has_private()).is_some());
        let identity2 = identity.strip_private();
        assert!(!identity2.has_private());
        assert!(!identity2.keychain().has_private());
        assert!(!identity2.claims().iter().find(|c| c.has_private()).is_some());
    }
}

