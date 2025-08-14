//! This module holds the identity structures and methods.
//!
//! The identity object holds claims, public stamps/revoations, a keychain
//! of administrative and third-party keys, and a set of capability policies
//! which dictate what signatures from various key are allowed to create
//! valid transactions against the identity.

use crate::{
    crypto::{
        base::{KeyID, SecretKey},
        private::MaybePrivate,
    },
    error::{Error, Result},
    identity::{
        claim::{Claim, ClaimID, ClaimSpec},
        keychain::{AdminKey, AdminKeyID, ExtendKeypair, Key, Keychain, RevocationReason},
        stamp::{RevocationReason as StampRevocationReason, Stamp, StampID},
    },
    policy::{PolicyContainer, PolicyID},
    util::{Public, SerText, Timestamp, Url},
};
use getset;
use rasn::{AsnType, Decode, Decoder, Encode, Encoder};
use serde_derive::{Deserialize, Serialize};
use std::ops::Deref;

object_id! {
    /// The identity's unique ID. This is the Hash of the
    /// [initial transaction][crate::dag::TransactionBody::CreateIdentityV1].
    IdentityID
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
    /// A collection of policies, each with a key policy attached to it. The
    /// idea here is that we can specify a capability/action such as "add subkey"
    /// and allow that action to be performed if we have the proper signature(s)
    /// as determined by the key policy.
    ///
    /// This allows us to not only run transactions against this identity, but
    /// also allows others to do so as well, given they sign their transactions
    /// according to the given policies.
    ///
    /// Effectively, this allows group/multisig management of identities.
    #[rasn(tag(explicit(2)))]
    policies: Vec<PolicyContainer>,
    /// Holds the keys for our identity.
    #[rasn(tag(explicit(3)))]
    keychain: Keychain,
    /// The claims this identity makes.
    #[rasn(tag(explicit(4)))]
    claims: Vec<Claim>,
    /// The public stamps (and revocations) this identity has made *on other
    /// identities.*
    ///
    /// Note that stamps do NOT have to be publicly saved, but can be transmitted
    /// directly to the recipient without advertisement. However, public storage
    /// of stamps within the stamper's identity allows for quick verification and
    /// for checking of revocation.
    #[rasn(tag(explicit(5)))]
    stamps: Vec<Stamp>,
    /// Whether or not this identity is revoked. Revoked identities cannot accept
    /// or create new transactions.
    #[rasn(tag(explicit(6)))]
    revoked: bool,
}

impl Identity {
    /// Create a new identity.
    pub(crate) fn create(id: IdentityID, admin_keys: Vec<AdminKey>, policies: Vec<PolicyContainer>, created: Timestamp) -> Self {
        // create a new keychain from our keys above.
        let keychain = Keychain::new(admin_keys);

        // create the identity
        Self {
            id,
            created,
            policies,
            keychain,
            claims: vec![],
            stamps: vec![],
            revoked: false,
        }
    }

    /// Reset the admin keys/capabilities in this identity.
    pub(crate) fn reset(mut self, admin_keys_maybe: Option<Vec<AdminKey>>, policies_maybe: Option<Vec<PolicyContainer>>) -> Result<Self> {
        if let Some(admin_keys) = admin_keys_maybe {
            let mut keychain = self.keychain().clone();
            keychain.set_admin_keys(admin_keys);
            self.set_keychain(keychain);
        }
        if let Some(policies) = policies_maybe {
            self.set_policies(policies);
        }
        Ok(self)
    }

    pub(crate) fn revoke(mut self) -> Result<Self> {
        self.set_revoked(true);
        Ok(self)
    }

    pub(crate) fn add_admin_key(mut self, admin_key: AdminKey) -> Result<Self> {
        self.set_keychain(self.keychain().clone().add_admin_key(admin_key)?);
        Ok(self)
    }

    pub(crate) fn edit_admin_key(mut self, id: &AdminKeyID, name: Option<String>, description: Option<Option<String>>) -> Result<Self> {
        self.set_keychain(self.keychain().clone().edit_admin_key(id, name, description)?);
        Ok(self)
    }

    pub(crate) fn revoke_admin_key(mut self, id: &AdminKeyID, reason: RevocationReason, new_name: Option<String>) -> Result<Self> {
        self.set_keychain(self.keychain().clone().revoke_admin_key(id, reason, new_name)?);
        Ok(self)
    }

    /// Add a new capability policy
    pub(crate) fn add_policy(mut self, container: PolicyContainer) -> Result<Self> {
        self.policies_mut().push(container);
        Ok(self)
    }

    /// Delete a capability policy by name
    pub(crate) fn delete_policy(mut self, id: &PolicyID) -> Result<Self> {
        if !self.policies().iter().any(|c| c.id() == id) {
            Err(Error::PolicyNotFound)?;
        }
        self.policies_mut().retain(|c| c.id() != id);
        Ok(self)
    }

    /// Create a new claim from the given data, sign it, and attach it to this
    /// identity.
    pub(crate) fn make_claim(mut self, claim_id: ClaimID, claim: ClaimSpec, name: Option<String>) -> Result<Self> {
        let claim = Claim::new(claim_id, claim, name);
        self.claims_mut().push(claim);
        Ok(self)
    }

    /// Set a new name for a claim
    pub(crate) fn edit_claim(mut self, id: &ClaimID, name: Option<String>) -> Result<Self> {
        let claim_maybe = self.claims_mut().iter_mut().find(|x| x.id() == id);
        if let Some(claim) = claim_maybe {
            claim.set_name(name);
        }
        Ok(self)
    }

    /// Remove a claim from this identity, including any stamps it has received.
    pub(crate) fn delete_claim(mut self, id: &ClaimID) -> Result<Self> {
        self.claims_mut().retain(|x| x.id() != id);
        Ok(self)
    }

    /// Make a public stamp
    pub(crate) fn make_stamp(mut self, stamp: Stamp) -> Result<Self> {
        if !self.stamps().iter().any(|s| s.id() == stamp.id()) {
            self.stamps_mut().push(stamp);
        }
        Ok(self)
    }

    /// Revoke a public stamp.
    pub(crate) fn revoke_stamp(mut self, stamp_id: &StampID, reason: StampRevocationReason) -> Result<Self> {
        let stamp = self
            .stamps_mut()
            .iter_mut()
            .find(|x| x.id() == stamp_id)
            .ok_or(Error::IdentityStampNotFound)?;
        stamp.set_revocation(Some(reason));
        Ok(self)
    }

    /// Accept a stamp on one of our claims.
    pub(crate) fn accept_stamp(mut self, stamp: Stamp) -> Result<Self> {
        let claim_id = stamp.entry().claim_id();
        let claim = self
            .claims_mut()
            .iter_mut()
            .find(|x| x.id() == claim_id)
            .ok_or(Error::IdentityClaimNotFound)?;
        if !claim.stamps().iter().any(|x| x.id() == stamp.id()) {
            claim.stamps_mut().push(stamp);
        }
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
            if found.is_some() {
                break;
            }
        }

        if let Some(claim) = found {
            claim.stamps_mut().retain(|x| x.id() != stamp_id);
            Ok(self)
        } else {
            Err(Error::IdentityStampNotFound)
        }
    }

    /// Add a new subkey to our identity.
    pub(crate) fn add_subkey<T: Into<String>>(mut self, key: Key, name: T, description: Option<T>) -> Result<Self> {
        self.set_keychain(self.keychain().clone().add_subkey(key, name, description)?);
        Ok(self)
    }

    /// Update the name/description on a subkey.
    pub(crate) fn edit_subkey<T: Into<String>>(mut self, id: &KeyID, new_name: Option<T>, new_desc: Option<Option<T>>) -> Result<Self> {
        self.set_keychain(self.keychain().clone().edit_subkey(id, new_name, new_desc)?);
        Ok(self)
    }

    /// Revoke one of our subkeys, for instance if it has been compromised.
    pub(crate) fn revoke_subkey(mut self, id: &KeyID, reason: RevocationReason, new_name: Option<String>) -> Result<Self> {
        self.set_keychain(self.keychain().clone().revoke_subkey(id, reason, new_name)?);
        Ok(self)
    }

    /// Remove a subkey from the keychain.
    pub(crate) fn delete_subkey(mut self, id: &KeyID) -> Result<Self> {
        self.set_keychain(self.keychain().clone().delete_subkey(id)?);
        Ok(self)
    }

    /// Given a name, find the matching claim (if any). This searches in reverse,
    /// meaning the *last* claim to be set with this particular name will be used.
    /// This mirrors how a hash table works (last write wins).
    ///
    /// The alternative here is to have some kind of conflict resolution around
    /// duplicate names, and let's be honest, this protocol is complicated enough
    /// without dealing with name conflicts.
    pub fn find_claim_by_name(&self, name: &str) -> Option<&Claim> {
        self.claims()
            .iter()
            .rev()
            .find(|c| c.name().as_ref().map(|n| n.as_str()) == Some(name))
    }

    /// Try to find a [Stamp] on a [Claim] by id.
    pub fn find_claim_stamp_by_id(&self, stamp_id: &StampID) -> Option<&Stamp> {
        let mut found_stamp = None;
        for claim in self.claims() {
            for stamp in claim.stamps() {
                if stamp.id() == stamp_id {
                    found_stamp = Some(stamp);
                    break;
                }
            }
            if found_stamp.is_some() {
                break;
            }
        }
        found_stamp
    }

    /// Return all emails associated with this identity.
    pub fn emails(&self) -> Vec<String> {
        self.claims()
            .iter()
            .filter_map(|x| match x.spec() {
                ClaimSpec::Email(MaybePrivate::Public(ref email)) => Some(email.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    /// Return all names associated with this identity.
    pub fn names(&self) -> Vec<String> {
        self.claims()
            .iter()
            .filter_map(|x| match x.spec() {
                ClaimSpec::Name(MaybePrivate::Public(ref name)) => Some(name.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    /// Return all domains associated with this identity
    pub fn domains(&self) -> Vec<String> {
        self.claims()
            .iter()
            .filter_map(|x| match x.spec() {
                ClaimSpec::Domain(MaybePrivate::Public(ref val)) => Some(val.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    /// Return all URLs associated with this identity
    pub fn urls(&self) -> Vec<Url> {
        self.claims()
            .iter()
            .filter_map(|x| match x.spec() {
                ClaimSpec::Url(MaybePrivate::Public(ref val)) => Some(val.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    /// Determine if this identity is owned (ie, we have the private keys stored
    /// locally) or it is imported (ie, someone else's identity).
    pub fn is_owned(&self) -> bool {
        self.keychain().admin_keys().iter().any(|k| k.has_private())
    }

    /// Test if a master key is correct.
    pub fn test_master_key(&self, master_key: &SecretKey) -> Result<()> {
        let test_bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        if self.keychain().admin_keys().is_empty() {
            Err(Error::IdentityNotOwned)?;
        }
        for key in self.keychain().admin_keys() {
            key.key().sign(master_key, test_bytes.as_slice())?;
        }
        Ok(())
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
        self.keychain().has_private() || self.claims().iter().any(|c| c.has_private())
    }
}

impl SerText for Identity {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::base::{Hash, SignKeypair},
        dag::TransactionID,
        identity::{
            keychain::AdminKeypair,
            stamp::{Confidence, StampEntry},
        },
        policy::{Capability, MultisigPolicy, Policy},
    };
    use rand::{CryptoRng, RngCore};
    use std::str::FromStr;

    fn create_identity<R: RngCore + CryptoRng>(rng: &mut R) -> (SecretKey, Identity) {
        let master_key = SecretKey::new_xchacha20poly1305(rng).unwrap();
        let id = IdentityID::random();
        let admin_keypair = AdminKeypair::new_ed25519(rng, &master_key).unwrap();
        let admin_key = AdminKey::new(admin_keypair.clone(), "Default", None);
        let capability = Policy::new(
            vec![Capability::Permissive],
            MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![admin_keypair.into()],
            },
        );
        let created = Timestamp::now();
        let policy_trans_id = TransactionID::random();
        let identity = Identity::create(
            id,
            vec![admin_key],
            vec![PolicyContainer::from_policy_transaction(&policy_trans_id, 0, capability).unwrap()],
            created,
        );
        (master_key, identity)
    }

    #[test]
    fn identity_create() {
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let id = IdentityID::random();
        let admin_keypair = AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let admin_key = AdminKey::new(admin_keypair, "Default", None);
        let capability = Policy::new(
            vec![Capability::Permissive],
            MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![admin_key.key().clone().into()],
            },
        );
        let container = PolicyContainer::from_policy_transaction(&TransactionID::random(), 0, capability).unwrap();
        let created = Timestamp::now();
        let identity = Identity::create(id.clone(), vec![admin_key.clone()], vec![container.clone().try_into().unwrap()], created.clone());

        assert_eq!(identity.id(), &id);
        assert_eq!(identity.created(), &created);
        assert_eq!(
            &identity.keychain().admin_keys().iter().map(|x| x.key()).collect::<Vec<_>>(),
            &vec![admin_key.key()]
        );
        assert_eq!(identity.policies(), &vec![container.clone()]);
    }

    #[test]
    fn identity_revoke() {
        todo!("Revoked identities should bar any changes/updates");
    }

    #[test]
    fn identity_claim_make_delete() {
        let mut rng = crate::util::test::rng();
        let (_master_key, identity) = create_identity(&mut rng);

        let claim_id = ClaimID::random();
        let spec = ClaimSpec::Identity(MaybePrivate::new_public(IdentityID::random()));
        assert_eq!(identity.claims().len(), 0);
        let identity = identity.make_claim(claim_id.clone(), spec.clone(), None).unwrap();
        assert_eq!(identity.claims().len(), 1);
        assert_eq!(identity.claims()[0].id(), &claim_id);
        match (identity.claims()[0].spec(), &spec) {
            (ClaimSpec::Identity(val), ClaimSpec::Identity(val2)) => assert_eq!(val, val2),
            _ => panic!("bad claim type"),
        }

        let claim_id2 = ClaimID::random();
        let spec2 = ClaimSpec::Name(MaybePrivate::new_public(String::from("BOND. JAMES BOND.")));
        let identity = identity.make_claim(claim_id2.clone(), spec2.clone(), None).unwrap();
        assert_eq!(identity.claims().len(), 2);
        assert_eq!(identity.claims()[0].id(), &claim_id);
        assert_eq!(identity.claims()[1].id(), &claim_id2);

        let identity = identity.delete_claim(&claim_id).unwrap();
        assert_eq!(identity.claims().len(), 1);
        assert_eq!(identity.claims()[0].id(), &claim_id2);

        let identity2 = identity.clone().delete_claim(&claim_id).unwrap();
        assert_eq!(identity2.claims().len(), 1);
        assert_eq!(identity2.claims()[0].id(), &claim_id2);
    }

    #[test]
    fn identity_stamp_make_revoke() {
        let mut rng = crate::util::test::rng();
        let (_master_key1, identity1) = create_identity(&mut rng);
        let (_master_key2, identity2) = create_identity(&mut rng);

        let identity1 = identity1
            .make_claim(ClaimID::random(), ClaimSpec::Name(MaybePrivate::new_public("Toad".into())), None)
            .unwrap();
        let claim = identity1.claims()[0].clone();

        assert_eq!(identity2.stamps().len(), 0);
        assert_eq!(identity2.stamps().iter().filter(|x| x.revocation().is_some()).count(), 0);
        let entry = StampEntry::new(
            identity2.id().clone(),
            identity1.id().clone(),
            claim.id().clone(),
            Confidence::Low,
            None::<Timestamp>,
        );
        let stamp = Stamp::new(StampID::random(), entry, Timestamp::now());
        let identity2_2 = identity2.make_stamp(stamp.clone()).unwrap();
        assert_eq!(identity2_2.stamps().len(), 1);
        assert_eq!(identity2_2.stamps().iter().filter(|x| x.revocation().is_some()).count(), 0);

        let identity2_3 = identity2_2.make_stamp(stamp.clone()).unwrap();
        assert_eq!(identity2_3.stamps().len(), 1);
        assert_eq!(identity2_3.stamps().iter().filter(|x| x.revocation().is_some()).count(), 0);

        let stamp_id = identity2_3.stamps()[0].id().clone();
        let identity2_4 = identity2_3.revoke_stamp(&stamp_id, StampRevocationReason::Invalid).unwrap();
        assert_eq!(identity2_4.stamps().len(), 1);
        assert_eq!(identity2_4.stamps().iter().filter(|x| x.revocation().is_some()).count(), 1);

        let identity2_5 = identity2_4.revoke_stamp(&stamp_id, StampRevocationReason::Invalid).unwrap();
        assert_eq!(identity2_5.stamps().len(), 1);
        assert_eq!(identity2_5.stamps().iter().filter(|x| x.revocation().is_some()).count(), 1);
    }

    #[test]
    fn identity_stamp_accept_delete() {
        let mut rng = crate::util::test::rng();
        let (_master_key1, identity1) = create_identity(&mut rng);
        let (_master_key2, identity2) = create_identity(&mut rng);

        let identity1 = identity1
            .make_claim(ClaimID::random(), ClaimSpec::Name(MaybePrivate::new_public("Toad".into())), None)
            .unwrap();
        let claim = identity1.claims()[0].clone();
        assert_eq!(identity1.claims()[0].stamps().len(), 0);

        let entry = StampEntry::new(
            identity2.id().clone(),
            identity1.id().clone(),
            claim.id().clone(),
            Confidence::Low,
            None::<Timestamp>,
        );
        let mut entry_wrong = entry.clone();
        entry_wrong.set_claim_id(ClaimID::random());
        let now = Timestamp::now();
        let stamp = Stamp::new(StampID::random(), entry, now.clone());
        let stamp_wrong = Stamp::new(stamp.id().clone(), entry_wrong, now.clone());

        let identity1_2 = identity1.accept_stamp(stamp.clone()).unwrap();
        assert_eq!(identity1_2.claims()[0].stamps().len(), 1);
        assert_eq!(identity1_2.claims()[0].stamps()[0].id(), stamp.id());

        let identity1_3 = identity1_2.accept_stamp(stamp.clone()).unwrap();
        assert_eq!(identity1_3.claims()[0].stamps().len(), 1);
        assert_eq!(identity1_3.claims()[0].stamps()[0].id(), stamp.id());

        let res = identity1_3.clone().accept_stamp(stamp_wrong.clone());
        assert_eq!(res.err(), Some(Error::IdentityClaimNotFound));

        let identity1_4 = identity1_3.delete_stamp(stamp.id()).unwrap();
        assert_eq!(identity1_4.claims()[0].stamps().len(), 0);

        let res = identity1_4.delete_stamp(stamp.id());
        assert_eq!(res.err(), Some(Error::IdentityStampNotFound));
    }

    #[test]
    fn identity_add_remove_admin_keys_brah_whoaaa_shaka_gnargnar_so_pitted_whapow() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity) = create_identity(&mut rng);
        assert_eq!(identity.keychain().subkeys().len(), 0);
        let admin_key = AdminKey::new(AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap(), "alpha", None::<&str>);
        let key_id = admin_key.key_id();
        let identity2 = identity.add_admin_key(admin_key.clone()).unwrap();
        assert_eq!(identity2.keychain().admin_keys().len(), 2);
        assert_eq!(identity2.keychain().admin_keys()[1].key_id(), key_id);
        assert_eq!(identity2.keychain().admin_keys()[1].name(), "alpha");
        assert_eq!(identity2.keychain().admin_keys()[1].description(), &None);
        assert_eq!(identity2.keychain().subkeys().len(), 0);

        let identity3 = identity2.clone().add_admin_key(admin_key.clone()).unwrap();
        assert_eq!(identity3.keychain().admin_keys().len(), 2);
        assert_eq!(identity3.keychain().admin_keys()[1].key_id(), key_id);
        assert_eq!(identity3.keychain().admin_keys()[1].name(), "alpha");
        assert_eq!(identity3.keychain().admin_keys()[1].description(), &None);
        assert_eq!(identity3.keychain().subkeys().len(), 0);

        let identity4 = identity3
            .edit_admin_key(&key_id, Some("admin:shutup-parker-thank-you-shutup".into()), Some(Some("send me messages".into())))
            .unwrap();
        assert_eq!(identity4.keychain().admin_keys().len(), 2);
        assert_eq!(identity4.keychain().admin_keys()[1].key_id(), key_id);
        assert_eq!(identity4.keychain().admin_keys()[1].name(), "admin:shutup-parker-thank-you-shutup");
        assert_eq!(identity4.keychain().admin_keys()[1].description(), &Some("send me messages".into()));
        assert_eq!(identity4.keychain().subkeys().len(), 0);

        let identity5 = identity4
            .revoke_admin_key(&key_id, RevocationReason::Superseded, Some("thank-you-parker".into()))
            .unwrap();
        assert_eq!(identity5.keychain().admin_keys().len(), 2);
        assert_eq!(identity5.keychain().admin_keys()[1].name(), "thank-you-parker");
        assert_eq!(identity5.keychain().admin_keys()[1].description(), &Some("send me messages".into()));
        assert_eq!(identity5.keychain().admin_keys()[1].revocation().is_some(), true);
        assert_eq!(identity5.keychain().subkeys().len(), 0);

        let identity6 = identity5
            .revoke_admin_key(&key_id, RevocationReason::Unspecified, Some("alright-shutup".into()))
            .unwrap();
        assert_eq!(identity6.keychain().admin_keys().len(), 2);
        assert_eq!(identity6.keychain().admin_keys()[1].name(), "alright-shutup");
        assert_eq!(identity6.keychain().admin_keys()[1].description(), &Some("send me messages".into()));
        assert_eq!(identity6.keychain().admin_keys()[1].revocation().is_some(), true);
        assert_eq!(identity6.keychain().subkeys().len(), 0);
    }

    #[test]
    fn identity_subkey_add_revoke_edit_delete() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity) = create_identity(&mut rng);

        assert_eq!(identity.keychain().subkeys().len(), 0);
        let signkey = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let key = Key::Sign(signkey.clone());
        let identity = identity.add_subkey(key.clone(), "default:sign", Some("get a job")).unwrap();
        assert_eq!(identity.keychain().subkeys().len(), 1);
        assert_eq!(identity.keychain().subkeys()[0].name(), "default:sign");
        assert_eq!(identity.keychain().subkeys()[0].description(), &Some("get a job".into()));
        assert_eq!(identity.keychain().subkeys()[0].key().as_signkey(), Some(&signkey));
        assert_eq!(identity.keychain().subkeys()[0].revocation().is_some(), false);

        let key_id = key.key_id();
        let res = identity.clone().add_subkey(key, "default:sign", Some("get a job"));
        assert_eq!(res.err(), None);
        assert_eq!(identity.keychain().subkeys()[0].revocation().is_some(), false);

        let identity = identity
            .edit_subkey(&key_id, Some("sign:shutup-parker-thank-you-shutup"), None)
            .unwrap();
        assert_eq!(identity.keychain().subkeys().len(), 1);
        assert_eq!(identity.keychain().subkeys()[0].name(), "sign:shutup-parker-thank-you-shutup");
        assert_eq!(identity.keychain().subkeys()[0].description(), &Some("get a job".into()));
        assert_eq!(identity.keychain().subkeys()[0].key().as_signkey(), Some(&signkey));
        assert_eq!(identity.keychain().subkeys()[0].revocation().is_some(), false);

        let identity = identity
            .revoke_subkey(&key_id, RevocationReason::Superseded, Some("thank-you".into()))
            .unwrap();
        assert_eq!(identity.keychain().subkeys().len(), 1);
        assert_eq!(identity.keychain().subkeys()[0].name(), "thank-you");
        assert_eq!(identity.keychain().subkeys()[0].description(), &Some("get a job".into()));
        assert_eq!(identity.keychain().subkeys()[0].key().as_signkey(), Some(&signkey));
        assert_eq!(identity.keychain().subkeys()[0].revocation().is_some(), true);

        let identity2 = identity
            .clone()
            .revoke_subkey(&key_id, RevocationReason::Superseded, Some("thank-you".into()))
            .unwrap();
        assert_eq!(identity2.keychain().subkeys().len(), 1);
        assert_eq!(identity2.keychain().subkeys()[0].name(), "thank-you");
        assert_eq!(identity2.keychain().subkeys()[0].description(), &Some("get a job".into()));
        assert_eq!(identity2.keychain().subkeys()[0].key().as_signkey(), Some(&signkey));
        assert_eq!(identity2.keychain().subkeys()[0].revocation().is_some(), true);

        let identity = identity.delete_subkey(&key_id).unwrap();
        assert_eq!(identity.keychain().subkeys().len(), 0);

        let identity3 = identity.clone().delete_subkey(&key_id).unwrap();
        assert_eq!(identity3.keychain().subkeys().len(), 0);
    }

    #[test]
    fn identity_find_claim_by_name() {
        let mut rng = crate::util::test::rng();
        let (_, identity) = create_identity(&mut rng);
        let spec1 = ClaimSpec::Name(MaybePrivate::new_public(String::from("Dirk Delta")));
        let spec2 = ClaimSpec::Name(MaybePrivate::new_public(String::from("Marty Malt")));
        let identity2 = identity
            .make_claim(ClaimID::random(), spec1.clone(), Some("name/primary".into()))
            .unwrap()
            .make_claim(ClaimID::random(), spec2.clone(), Some("name/primary".into()))
            .unwrap();
        match identity2.find_claim_by_name("name/primary").unwrap().spec() {
            ClaimSpec::Name(val) => assert_eq!(val.open_public().unwrap().as_str(), "Marty Malt"),
            _ => panic!("bad dates"),
        }
    }

    #[test]
    fn identity_emails_maybe() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity) = create_identity(&mut rng);
        assert_eq!(identity.emails().len(), 0);

        let spec = ClaimSpec::Email(MaybePrivate::new_public(String::from("poopy@butt.com")));
        let identity = identity
            .make_claim(ClaimID::random(), spec.clone(), Some("Zing".into()))
            .unwrap()
            .make_claim(
                ClaimID::random(),
                ClaimSpec::Email(MaybePrivate::new_private(&mut rng, &master_key, "ace@fairweather.com".into()).unwrap()),
                Some("email2".into()),
            )
            .unwrap()
            .make_claim(
                ClaimID::random(),
                ClaimSpec::Email(MaybePrivate::new_public("zing@radiofree.com".into())),
                Some("email3".into()),
            )
            .unwrap();
        assert_eq!(identity.emails(), vec!["poopy@butt.com".to_string(), "zing@radiofree.com".to_string()]);
    }

    #[test]
    fn identity_names_maybe() {
        let mut rng = crate::util::test::rng();
        let (_master_key, identity) = create_identity(&mut rng);
        assert_eq!(identity.names().len(), 0);

        let claim_id = ClaimID::random();
        let spec = ClaimSpec::Name(MaybePrivate::new_public(String::from("BOND. JAMES BOND.")));
        let identity = identity.make_claim(claim_id.clone(), spec.clone(), Some("hvvvv".into())).unwrap();
        assert_eq!(identity.names(), vec!["BOND. JAMES BOND.".to_string()]);

        let claim_id2 = ClaimID::random();
        let spec = ClaimSpec::Name(MaybePrivate::new_public(String::from("Jack Mama")));
        let identity = identity.make_claim(claim_id2.clone(), spec.clone(), Some("GUHHHH".into())).unwrap();
        assert_eq!(identity.names(), vec!["BOND. JAMES BOND.".to_string(), "Jack Mama".to_string()]);

        let identity2 = identity.clone().delete_claim(&claim_id).unwrap();
        assert_eq!(identity2.names().len(), 1);
        let identity3 = identity2.clone().delete_claim(&claim_id2).unwrap();
        assert_eq!(identity3.names().len(), 0);
    }

    #[test]
    fn identity_is_owned() {
        let mut rng = crate::util::test::rng();
        let (_master_key, identity) = create_identity(&mut rng);
        assert!(identity.is_owned());

        let mut identity2 = identity.clone();
        identity2.set_keychain(identity.keychain().strip_private());
        assert!(!identity2.is_owned());
    }

    #[test]
    fn identity_test_master_key() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity) = create_identity(&mut rng);
        let master_key_fake = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        assert!(master_key.as_ref() != master_key_fake.as_ref());

        identity.test_master_key(&master_key).unwrap();
        let res = identity.test_master_key(&master_key_fake);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
    }

    #[test]
    fn identity_serialize() {
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let now = Timestamp::from_str("1977-06-07T04:32:06Z").unwrap();
        let seed = [
            33, 90, 159, 88, 22, 24, 84, 4, 237, 121, 198, 195, 71, 238, 107, 91, 235, 93, 9, 129, 252, 221, 2, 149, 250, 142, 49, 36, 161,
            184, 44, 156,
        ];
        let admin = AdminKeypair::new_ed25519_from_bytes(&mut rng, &master_key, seed).unwrap();
        let admin_key = AdminKey::new(admin.clone(), "alpha", None);

        let id = IdentityID::from(TransactionID::from(Hash::new_blake3(b"get a job").unwrap()));
        let capability = Policy::new(
            vec![Capability::Permissive],
            MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![admin.into()],
            },
        );
        let container = PolicyContainer::from_policy_transaction(&id.deref(), 0, capability).unwrap();
        let identity = Identity::create(id.clone(), vec![admin_key], vec![container], now);
        let ser = identity.serialize_text().unwrap();
        assert_eq!(
            ser.trim(),
            r#"---
id:
  Blake3: He7UaLB48wVhf85NXb5PlCpYuXdYsWCzJ48-IFikVXw
created: "1977-06-07T04:32:06Z"
policies:
  - id:
      Blake3: 8Zse00lvEkvvNQZT6RavqGPIuf5axUgFjOTxx-okjKQ
    policy:
      capabilities:
        - Permissive
      multisig_policy:
        MOfN:
          must_have: 1
          participants:
            - Key:
                name: ~
                key:
                  Ed25519: rcxBT4vC93i4PZzwflbKUzTbvgf96wr4kArteWqwzxA
keychain:
  admin_keys:
    - key:
        Ed25519:
          public: rcxBT4vC93i4PZzwflbKUzTbvgf96wr4kArteWqwzxA
          secret: ~
      name: alpha
      description: ~
      revocation: ~
  subkeys: []
claims: []
stamps: []"#
        );
    }

    #[test]
    fn identity_strip_has_private() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity) = create_identity(&mut rng);
        let identity = identity
            .make_claim(
                ClaimID::random(),
                ClaimSpec::Name(MaybePrivate::new_private(&mut rng, &master_key, "Bozotron".to_string()).unwrap()),
                None,
            )
            .unwrap();
        assert!(identity.has_private());
        assert!(identity.keychain().has_private());
        assert!(identity.claims().iter().find(|c| c.has_private()).is_some());
        let identity2 = identity.strip_private();
        assert!(!identity2.has_private());
        assert!(!identity2.keychain().has_private());
        assert!(!identity2.claims().iter().find(|c| c.has_private()).is_some());
    }
}
