//! The keychain holds all of the keys, active or revoked, for an idntity. It
//! stores keys not only used for the identity itself, but any kind of
//! cryptographic keys the identity holds wishes to use.
//!
//! For instance, they might store an "email" keypair and request that others
//! encrypt emails to them via that key. They might store their dogecoin wallet
//! private keys in the keychain. They could even store the key to their heart
//! (as long as it can be represented cryptographically).
//!
//! Because the keychain stores even revoked keys, it's possible to verify old
//! signatures made with those keys even if they aren't in active use anymore.
//! This gives identities a longevity that wouldn't be possible if they were
//! tied to just a single keypair.

use crate::{
    error::{Error, Result},
    identity::{Public, PublicMaybe},
    crypto::key::{SecretKey, SignKeypairSignature, SignKeypair, CryptoKeypair},
    private::Private,
    util::{ser, sign::SignedValue},
};
use getset;
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

object_id! {
    /// A unique identifier for a key. This is a signature of the key itself.
    ///
    /// A bit different from other IDs in that it must be regenerated when the root
    /// keypair changes.
    KeyID
}

object_id! {
    /// A unique identifier for a key revocation. This is a signature of the
    /// revocation.
    RevocationID
}

/// Why we are deprecating a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationReason {
    /// No reason. Feeling cute today, might revoke my keys, IDK.
    Unspecified,
    /// Replacing this key with another.
    Superseded,
    /// This key has been compromised.
    Compromised,
    /// This key was signed by a compromised key and should never be used.
    Invalid,
}

/// The inner data stored by a revocation, the signature of which is used as the
/// revocation's ID.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct RevocationEntry {
    /// The permanent ID of the key we are revoking.
    key_id: KeyID,
    /// The reason we're deprecating this key.
    reason: RevocationReason,
}

impl RevocationEntry {
    /// Create a new revocation entry.
    pub fn new(key_id: KeyID, reason: RevocationReason) -> Self {
        Self {
            key_id,
            reason,
        }
    }
}

/// Marks a key as revoked, signed with our root key. In the case that the
/// root key is being revoked, the deprecation must be signed with the new
/// root key.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Revocation {
    /// Revocation signature, and also unique ID for this revocation.
    id: RevocationID,
    /// The inner data for this revocation
    entry: RevocationEntry,
}

impl Revocation {
    /// Create a new revocation. Must be signed by a root keypair.
    pub fn new(master_key: &SecretKey, sign_keypair: &SignKeypair, key_id: KeyID, reason: RevocationReason) -> Result<Self> {
        let entry = RevocationEntry::new(key_id, reason);
        let serialized = ser::serialize(&entry)?;
        let signature = sign_keypair.sign(master_key, &serialized)?;
        Ok(Self {
            id: RevocationID(signature),
            entry,
        })
    }

    /// Verify this revocation against the keypair that signed it.
    pub fn verify(&self, sign_keypair: &SignKeypair) -> Result<()> {
        let serialized = ser::serialize(self.entry())?;
        sign_keypair.verify(self.id(), &serialized)
    }
}

/// An enum that holds any type of key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Key {
    /// A policy key
    Policy(SignKeypair),
    /// A publish key
    ///
    /// NOTE: although the idea of keeping a publish key in the subkeys is kind
    /// of dumb (because a publish key is really only useful in the context of
    /// an instance of a published identity and thus only needs to be validated
    /// against the *current* publish key in all cases), we do want to keep it
    /// around so that the revocation of the publish key can be made available.
    /// this allows implementations to know if a published identity was made
    /// with a revoked key, and under what circumstances the key was revoked,
    /// which they can use to adjust their trust of that identity.
    Publish(SignKeypair),
    /// A root key
    Root(SignKeypair),
    /// A signing key.
    Sign(SignKeypair),
    /// An asymmetric crypto key.
    Crypto(CryptoKeypair),
    /// Hides our private data (including private claims).
    Secret(Private<SecretKey>),
    /// An extension type, can be used to save any kind of public/secret keypair
    /// that isn't covered by the stamp system.
    ExtensionKeypair(Vec<u8>, Option<Private<Vec<u8>>>),
    /// An extension type, can be used to save any kind of key that isn't
    /// covered by the stamp system.
    ExtensionSecret(Private<Vec<u8>>),
}

impl Key {
    /// Create a new signing keypair
    pub fn new_sign(keypair: SignKeypair) -> Self {
        Self::Sign(keypair)
    }

    /// Create a new signing keypair
    pub fn new_crypto(keypair: CryptoKeypair) -> Self {
        Self::Crypto(keypair)
    }

    /// Create a new secret key
    pub fn new_secret(key: Private<SecretKey>) -> Self {
        Self::Secret(key)
    }

    /// Returns the `SignKeypair` if this is a policy key.
    pub fn as_policykey(&self) -> Option<&SignKeypair> {
        match self {
            Self::Policy(ref x) => Some(x),
            _ => None,
        }
    }

    /// Returns the `SignKeypair` if this is a root key.
    pub fn as_rootkey(&self) -> Option<&SignKeypair> {
        match self {
            Self::Root(ref x) => Some(x),
            _ => None,
        }
    }

    /// Returns the `SignKeypair` if this is a signing key.
    pub fn as_signkey(&self) -> Option<&SignKeypair> {
        match self {
            Self::Sign(ref x) => Some(x),
            _ => None,
        }
    }

    /// Returns the `SignKeypair` if this is a signing key.
    pub fn as_cryptokey(&self) -> Option<&CryptoKeypair> {
        match self {
            Self::Crypto(ref x) => Some(x),
            _ => None,
        }
    }

    /// Returns the `SignKeypair` if this is a signing key.
    pub fn as_secretkey(&self) -> Option<&Private<SecretKey>> {
        match self {
            Self::Secret(ref x) => Some(x),
            _ => None,
        }
    }

    /// Consumes the key, and re-encryptes it with a new master key.
    pub fn reencrypt(self, previous_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let key = match self {
            Self::Policy(keypair) => Self::Policy(keypair.reencrypt(previous_master_key, new_master_key)?),
            Self::Publish(keypair) => Self::Publish(keypair.reencrypt(previous_master_key, new_master_key)?),
            Self::Root(keypair) => Self::Root(keypair.reencrypt(previous_master_key, new_master_key)?),
            Self::Sign(keypair) => Self::Sign(keypair.reencrypt(previous_master_key, new_master_key)?),
            Self::Crypto(keypair) => Self::Crypto(keypair.reencrypt(previous_master_key, new_master_key)?),
            Self::Secret(secret) => Self::Secret(secret.reencrypt(previous_master_key, new_master_key)?),
            Self::ExtensionKeypair(public, private_maybe) => {
                if let Some(private) = private_maybe {
                    Self::ExtensionKeypair(public, Some(private.reencrypt(previous_master_key, new_master_key)?))
                } else {
                    return Err(Error::CryptoKeyMissing)?;
                }
            }
            Self::ExtensionSecret(secret) => Self::ExtensionSecret(secret.reencrypt(previous_master_key, new_master_key)?),
        };
        Ok(key)
    }

    pub fn has_private(&self) -> bool {
        match self {
            Self::Policy(keypair) => keypair.has_private(),
            Self::Publish(keypair) => keypair.has_private(),
            Self::Root(keypair) => keypair.has_private(),
            Self::Sign(keypair) => keypair.has_private(),
            Self::Crypto(keypair) => keypair.has_private(),
            Self::Secret(_) => true,
            Self::ExtensionKeypair(_, private_maybe) => private_maybe.is_some(),
            Self::ExtensionSecret(_) => true,
        }
    }
}

impl PublicMaybe for Key {
    fn strip_private_maybe(&self) -> Option<Self> {
        match self {
            Self::Policy(keypair) => Some(Self::Policy(keypair.strip_private())),
            Self::Publish(keypair) => Some(Self::Publish(keypair.strip_private())),
            Self::Root(keypair) => Some(Self::Root(keypair.strip_private())),
            Self::Sign(keypair) => Some(Self::Sign(keypair.strip_private())),
            Self::Crypto(keypair) => Some(Self::Crypto(keypair.strip_private())),
            Self::Secret(_) => None,
            Self::ExtensionKeypair(public, _) => Some(Self::ExtensionKeypair(public.clone(), None)),
            Self::ExtensionSecret(_) => None,
        }
    }
}

/// A key container.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct KeyEntry {
    /// The key itself.
    ///
    /// Alright, Parker, shut up. Thank you, Parker. Shut up. Thank you. Nobody
    /// thinks you're funny.
    key: Key,
    /// The key's human-readable name, for example "email".
    ///
    /// This should likely be unique if it's to be of any use, because people
    /// can use this value to quickly find one of an identity's subkeys, for
    /// instance on the command line.
    name: String,
    /// The key's human-readable description, for example "Please send me
    /// encrypted emails using this key." Or "HAI THIS IS MY DOGECOIN ADDRESSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS!!!1"
    description: Option<String>,
}

impl KeyEntry {
    /// Create a new KeyEntry.
    fn new(key: Key, name: String, description: Option<String>) -> Self {
        Self {
            key,
            name,
            description,
        }
    }
}

impl PublicMaybe for KeyEntry {
    /// Returns a version of this key(entry) without any private data. Useful
    /// for signing.
    fn strip_private_maybe(&self) -> Option<Self> {
        match self.key().strip_private_maybe() {
            Some(x) => {
                let mut clone = self.clone();
                clone.set_key(x);
                Some(clone)
            }
            None => None,
        }
    }
}

impl Deref for KeyEntry {
    type Target = Key;
    fn deref(&self) -> &Self::Target {
        self.key()
    }
}

/// Holds a subkey's id/signature (signed by the root key), its key data, and an
/// optional revocation.
///
/// If the subkey is a keypair, we sign the public key of the keypair (making it
/// verifiable without the private data) and in the case of a secret key, we
/// sign the whole key.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Subkey {
    /// They subkey's unique ID, and signature of the key itself by the
    /// identity's *current* root keypair (and forevermore unchanged).
    id: KeyID,
    /// The signature of the key, always kept up to date with the *latest* root
    /// signing key...this must be regeneroned when the root keypair changes
    /// (I feel.....perfect)
    signature: SignKeypairSignature,
    /// The key itself, along with some metadata. This is what we sign in our id
    /// and signature fields.
    key: KeyEntry,
    /// Allows revocation of a key.
    revocation: Option<Revocation>,
}

impl Subkey {
    /// Create a new subkey, signed by our root key.
    fn new<T: Into<String>>(master_key: &SecretKey, sign_keypair: &SignKeypair, key: Key, name: T, description: Option<T>) -> Result<Self> {
        // create a blank signature we're going to use TEMPORARILY for the id
        // and signature fields.
        //
        // fake signature. Sad!
        let blank_signature = SignKeypairSignature::blank(sign_keypair);
        let entry = KeyEntry::new(key, name.into(), description.map(|x| x.into()));
        let mut subkey = Self {
            id: KeyID(blank_signature.clone()),
            signature: blank_signature,
            key: entry,
            revocation: None,
        };
        // now, sign our key and update our key's id
        subkey.sign(master_key, sign_keypair)?;
        subkey.set_id(KeyID(subkey.signature().clone()));
        Ok(subkey)
    }

    /// Sign this subkey with the given signing key.
    fn sign(&mut self, master_key: &SecretKey, sign_keypair: &SignKeypair) -> Result<()> {
        // if we have a keypair, just sign the public key, otherwise sign the
        // whole key body (which is encrypted via the master key).
        //
        // the idea here is that we still want to sign key integrity for private
        // keys (and give them an id), but because we don't publish them there's
        // really no need to sign any kind of verifiable data (it's only used
        // for our own personal amusement).
        let maybe_public = self.key().strip_private_maybe();
        let key = match maybe_public.as_ref() {
            Some(public) => public,
            None => self.key(),
        };
        let serialized = ser::serialize(key)?;
        let signature = sign_keypair.sign(master_key, &serialized)?;
        self.set_signature(signature);
        Ok(())
    }

    /// Verify the signature on this subkey.
    fn verify(&self, sign_keypair: &SignKeypair) -> Result<()> {
        let maybe_public = self.key().strip_private_maybe();
        let key = match maybe_public.as_ref() {
            Some(public) => public,
            None => self.key(),
        };
        let serialized = ser::serialize(key)?;
        sign_keypair.verify(self.signature(), &serialized)
    }

    /// Verify the signature on this subkey.
    fn verify_id(&self, sign_keypair: &SignKeypair) -> Result<()> {
        let maybe_public = self.key().strip_private_maybe();
        let key = match maybe_public.as_ref() {
            Some(public) => public,
            None => self.key(),
        };
        let serialized = ser::serialize(key)?;
        sign_keypair.verify(self.id(), &serialized)
    }

    /// Revoked this subkey.
    fn revoke(&mut self, master_key: &SecretKey, root_keypair: &SignKeypair, reason: RevocationReason) -> Result<()> {
        let revocation = Revocation::new(master_key, root_keypair, self.id().clone(), reason)?;
        self.revocation = Some(revocation);
        Ok(())
    }
}

/// Holds a key that is either signed by the alpha key or has been recovered via
/// the recovery policy system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignedOrRecoveredKeypair {
    /// This key has been signed by the alpha key.
    Signed(SignedValue<SignKeypair>),
    /// This key is the result of a successful recovery policy execution, and
    /// therefor is not signed by the alpha key. It's validity must be
    /// determined through the identity's policy system.
    Recovered(SignKeypair),
}

impl SignedOrRecoveredKeypair {
    /// Verify the contained keypair with the given signing key. In the even the
    /// key is recovered (nto signed) we return an error.
    pub fn verify_signed(&self, sign_keypair: &SignKeypair) -> Result<()> {
        match self {
            Self::Signed(signed) => signed.verify_value(sign_keypair),
            Self::Recovered(_) => Err(Error::SignatureMissing),
        }
    }

    /// Return a clone of this keypair with all private data stripped.
    pub fn strip_private(&self) -> Self {
        match self {
            Self::Signed(signed) => {
                let mut signed_clone = signed.clone();
                signed_clone.set_value(signed.strip_private());
                Self::Signed(signed_clone)
            }
            Self::Recovered(keypair) => Self::Recovered(keypair.strip_private())
        }
    }
}

impl Deref for SignedOrRecoveredKeypair {
    type Target = SignKeypair;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Signed(signed) => signed.deref(),
            Self::Recovered(ref kp) => kp,
        }
    }
}

/// Holds the keys for our identity.
///
/// This includes an always-present root signing key, and any number of other
/// keys. There's no restriction on how many keys we can have or what kind of
/// keys (signing, enryption, etc).
///
/// The keys stored here can also be revoked. They can remain stored here for
/// the purposes of verifying old signatures or decrypting old messages, but
/// revoked keys should not be used to sign or encrypt new data. Even the
/// root key can be revoked in the case that it's compromised.
///
/// In the event a root key is revoked, the subkeys must be re-signed with
/// the new root key.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Keychain {
    /// The alpha key. One key to rule them all.
    ///
    /// You really should never use this key without a REALLY good reason. This
    /// key effectively controls all other keys in the identity, and should only
    /// be used if a top-level key has been compromised.
    alpha: SignKeypair,
    /// Our policy signing key. Lets us create recovery policies. This is signed
    /// by the alpha key, which prevents tampering.
    policy: SignedValue<SignKeypair>,
    /// The publish key, signed by the alpha key. When we want to publish our
    /// identity anywhere, for instance to our personal website, an identity
    /// network, or anywhere else we might want others to find our identity, we
    /// sign the published identity with our publish key.
    publish: SignedOrRecoveredKeypair,
    /// The identity's root signing key, signed by the alpha key.
    root: SignedOrRecoveredKeypair,
    /// Holds our subkeys, signed with our root keypair.
    subkeys: Vec<Subkey>,
}

impl Keychain {
    /// Create a new keychain
    pub(crate) fn new(master_key: &SecretKey, alpha_keypair: SignKeypair, policy_keypair: SignKeypair, publish_keypair: SignKeypair, root_keypair: SignKeypair) -> Result<Self> {
        let policy = SignedValue::new(master_key, &alpha_keypair, policy_keypair)?;
        let publish = SignedOrRecoveredKeypair::Signed(SignedValue::new(master_key, &alpha_keypair, publish_keypair)?);
        let root = SignedOrRecoveredKeypair::Signed(SignedValue::new(master_key, &alpha_keypair, root_keypair)?);
        Ok(Self {
            alpha: alpha_keypair,
            policy,
            publish,
            root,
            subkeys: Vec::new(),
        })
    }

    /// Verify that a signature and a set of data used to generate that
    /// signature can be verified by at least one of our signing keys.
    pub(crate) fn try_keys<F>(keylist: &Vec<&SignKeypair>, sigfn: F) -> Result<()>
        where F: Fn(&SignKeypair) -> Result<()>,
    {
        for sign_keypair in keylist {
            if sigfn(sign_keypair).is_ok() {
                return Ok(());
            }
        }
        Err(Error::CryptoSignatureVerificationFailed)
    }

    /// Make sure our subkeys are signed properly.
    pub(crate) fn verify_subkeys(&self) -> Result<()> {
        let root_keys = self.keys_root();
        for subkey in self.subkeys() {
            // the subkey should always be signed by the current root key
            subkey.verify(self.root())?;
            // however, the ID of the subkey could be signed by any number of
            // present or past root keys, so try them all
            Keychain::try_keys(&root_keys, |keypair| subkey.verify_id(keypair))?;
        }
        Ok(())
    }

    /// Grab all policy keys (active or retired).
    pub fn keys_policy(&self) -> Vec<&SignKeypair> {
        let mut search_keys = vec![self.policy().deref()];
        search_keys.append(&mut self.subkeys_policy());
        search_keys
    }

    /// Find a subkey by ID. Relieves a bit of tedium.
    pub fn subkey_by_id(&self, id: &KeyID) -> Option<&Subkey> {
        self.subkeys().iter().find(|x| x.id() == id)
    }

    /// Find a subkey by name. Relieves a bit of tedium.
    pub fn subkey_by_name(&self, name: &str) -> Option<&Subkey> {
        self.subkeys().iter().find(|x| x.key().name() == name)
    }

    /// Grab all policy subkeys.
    pub fn subkeys_policy(&self) -> Vec<&SignKeypair> {
        self.subkeys().iter()
            .map(|x| x.key().as_policykey())
            .filter(|x| x.is_some())
            .map(|x| x.unwrap())
            .collect::<Vec<_>>()
    }

    /// Grab all root keys.
    pub fn keys_root(&self) -> Vec<&SignKeypair> {
        let mut search_keys = vec![self.root().deref()];
        search_keys.append(&mut self.subkeys_root());
        search_keys
    }

    fn subkeys_root(&self) -> Vec<&SignKeypair> {
        self.subkeys().iter()
            .map(|x| x.key().as_rootkey())
            .filter(|x| x.is_some())
            .map(|x| x.unwrap())
            .collect::<Vec<_>>()
    }

    /// Grab all signing subkeys.
    pub fn subkeys_sign(&self) -> Vec<&SignKeypair> {
        self.subkeys().iter()
            .map(|x| x.key().as_signkey())
            .filter(|x| x.is_some())
            .map(|x| x.unwrap())
            .collect::<Vec<_>>()
    }

    /// Grab all crypto subkeys.
    pub fn subkeys_crypto(&self) -> Vec<&CryptoKeypair> {
        self.subkeys().iter()
            .map(|x| x.key().as_cryptokey())
            .filter(|x| x.is_some())
            .map(|x| x.unwrap())
            .collect::<Vec<_>>()
    }

    /// Replace our policy signing key.
    ///
    /// This moves the current policy key into the subkeys and revokes it.
    pub(crate) fn set_policy_key(mut self, master_key: &SecretKey, alpha_keypair: &SignKeypair, new_policy_keypair: SignKeypair, reason: RevocationReason) -> Result<Self> {
        let policy = self.policy().deref().clone();
        let mut subkey = Subkey::new(master_key, alpha_keypair, Key::Policy(policy), "policy key", Some("revoked policy key"))?;
        subkey.revoke(master_key, self.root(), reason)?;
        self.subkeys_mut().push(subkey);
        self.set_policy(SignedValue::new(master_key, alpha_keypair, new_policy_keypair)?);
        Ok(self)
    }

    /// Replace our publish signing key.
    ///
    /// This moves the current publish key into the subkeys and revokes it.
    pub(crate) fn set_publish_key(mut self, master_key: &SecretKey, new_publish_keypair: SignedOrRecoveredKeypair, reason: RevocationReason) -> Result<Self> {
        let publish = self.publish().deref().clone();
        let mut subkey = Subkey::new(master_key, self.root(), Key::Publish(publish), "publish key", Some("revoked publish key"))?;
        subkey.revoke(master_key, &new_publish_keypair, reason)?;
        self.subkeys_mut().push(subkey);
        self.set_publish(new_publish_keypair);
        Ok(self)
    }

    /// Replace our root signing key.
    ///
    /// This moves the current root key into the subkeys, revokes it, and
    /// updates the signature on all the subkeys (including the old root key).
    pub(crate) fn set_root_key(mut self, master_key: &SecretKey, new_root_keypair: SignedOrRecoveredKeypair, reason: RevocationReason) -> Result<Self> {
        let root = self.root().deref().clone();
        let mut subkey = Subkey::new(master_key, &new_root_keypair, Key::Root(root), "root key", Some("revoked root key"))?;
        subkey.revoke(master_key, &new_root_keypair, reason)?;
        self.subkeys_mut().push(subkey);
        self.set_root(new_root_keypair);
        self.sign_subkeys(master_key)
    }

    /// Add a new subkey to the keychain (and sign it).
    pub(crate) fn add_subkey<T: Into<String>>(mut self, master_key: &SecretKey, key: Key, name: T, description: Option<T>) -> Result<Self> {
        let subkey = Subkey::new(master_key, self.root(), key, name, description)?;
        self.subkeys_mut().push(subkey);
        Ok(self)
    }

    /// Make sure all our subkeys are signed with our current root keypair.
    pub(crate) fn sign_subkeys(mut self, master_key: &SecretKey) -> Result<Self> {
        let root = self.root().clone();
        for subkey in self.subkeys_mut() {
            subkey.sign(master_key, &root)?;
        }
        Ok(self)
    }

    /// Revoke a subkey.
    pub(crate) fn revoke_subkey(mut self, master_key: &SecretKey, key_id: &KeyID, reason: RevocationReason) -> Result<Self> {
        let root = self.root().clone();
        let key = self.subkeys_mut().iter_mut()
            .find(|x| x.id() == key_id)
            .ok_or(Error::IdentitySubkeyNotFound)?;
        key.revoke(master_key, &root, reason)?;
        Ok(self)
    }

    /// Delete a key from the keychain.
    pub(crate) fn delete_subkey(mut self, key_id: &KeyID) -> Result<Self> {
        let exists = self.subkeys().iter().find(|x| x.id() == key_id);
        if exists.is_none() {
            Err(Error::IdentitySubkeyNotFound)?;
        }
        self.subkeys_mut().retain(|x| x.id() != key_id);
        Ok(self)
    }

    /// REEEEEE-encrypt  the keys in this keychain with a new master key.
    pub(crate) fn reencrypt(mut self, current_key: &SecretKey, new_key: &SecretKey) -> Result<Self> {
        match self.alpha().clone().reencrypt(current_key, new_key) {
            Ok(alpha) => { self.set_alpha(alpha); },
            Err(Error::CryptoKeyMissing) => {}
            Err(err) => Err(err)?,
        }
        match self.policy().value().clone().reencrypt(current_key, new_key) {
            Ok(policy) => { self.policy_mut().set_value(policy); },
            Err(Error::CryptoKeyMissing) => {}
            Err(err) => Err(err)?,
        }
        match self.publish().clone() {
            SignedOrRecoveredKeypair::Signed(mut signed) => {
                match signed.value().clone().reencrypt(current_key, new_key) {
                    Ok(publish) => {
                        signed.set_value(publish);
                        self.set_publish(SignedOrRecoveredKeypair::Signed(signed));
                    },
                    Err(Error::CryptoKeyMissing) => {}
                    Err(err) => Err(err)?,
                }
            }
            SignedOrRecoveredKeypair::Recovered(keypair) => {
                match keypair.clone().reencrypt(current_key, new_key) {
                    Ok(publish) => {
                        self.set_publish(SignedOrRecoveredKeypair::Recovered(publish));
                    },
                    Err(Error::CryptoKeyMissing) => {}
                    Err(err) => Err(err)?,
                }
            }
        }
        match self.root().clone() {
            SignedOrRecoveredKeypair::Signed(mut signed) => {
                match signed.value().clone().reencrypt(current_key, new_key) {
                    Ok(root) => {
                        signed.set_value(root);
                        self.set_root(SignedOrRecoveredKeypair::Signed(signed));
                    },
                    Err(Error::CryptoKeyMissing) => {}
                    Err(err) => Err(err)?,
                }
            }
            SignedOrRecoveredKeypair::Recovered(keypair) => {
                match keypair.clone().reencrypt(current_key, new_key) {
                    Ok(root) => {
                        self.set_root(SignedOrRecoveredKeypair::Recovered(root));
                    },
                    Err(Error::CryptoKeyMissing) => {}
                    Err(err) => Err(err)?,
                }
            }
        }
        for subkey in self.subkeys_mut() {
            let rekeyed = subkey.key().key().clone().reencrypt(current_key, new_key)?;
            subkey.key_mut().set_key(rekeyed);
        }
        Ok(self)
    }
}

impl Public for Keychain {
    fn strip_private(&self) -> Self {
        let mut keychain_clone = self.clone();
        keychain_clone.set_alpha(self.alpha().strip_private());
        keychain_clone.policy_mut().set_value(self.policy().value().strip_private());
        keychain_clone.set_publish(self.publish().strip_private());
        keychain_clone.set_root(self.root().strip_private());
        let subkeys = self.subkeys().clone().into_iter()
            .map(|x| {
                (x.key().strip_private_maybe(), x)
            })
            .filter(|x| x.0.is_some())
            .map(|(key, mut subkey)| {
                subkey.set_key(key.unwrap());
                subkey
            })
            .collect::<Vec<_>>();
        keychain_clone.set_subkeys(subkeys);
        keychain_clone
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_new_verify() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let sign_keypair2 = SignKeypair::new_ed25519(&master_key).unwrap();
        assert!(sign_keypair != sign_keypair2);
        let key_id = KeyID(sign_keypair.sign(&master_key, b"hello there").unwrap());
        let revocation = Revocation::new(&master_key, &sign_keypair, key_id, RevocationReason::Compromised).unwrap();
        revocation.verify(&sign_keypair).unwrap();
        let res = revocation.verify(&sign_keypair2);
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));
    }

    #[test]
    fn key_as_type() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap();
        let secret_key = SecretKey::new_xsalsa20poly1305();
        let key1 = Key::Policy(sign_keypair.clone());
        let key2 = Key::Publish(sign_keypair.clone());
        let key3 = Key::Root(sign_keypair.clone());
        let key4 = Key::Sign(sign_keypair.clone());
        let key5 = Key::Crypto(crypto_keypair.clone());
        let key6 = Key::Secret(Private::seal(&master_key, &secret_key).unwrap());

        let keys = vec![key1, key2, key3, key4, key5, key6];
        macro_rules! keytype {
            ($keys:ident, $fn:ident) => {
                $keys.iter().map(|x| x.$fn().is_some()).collect::<Vec<_>>()
            }
        }
        assert_eq!(keytype!(keys, as_policykey), vec![true, false, false, false, false, false]);
        assert_eq!(keytype!(keys, as_rootkey), vec![false, false, true, false, false, false]);
        assert_eq!(keytype!(keys, as_signkey), vec![false, false, false, true, false, false]);
        assert_eq!(keytype!(keys, as_cryptokey), vec![false, false, false, false, true, false]);
        assert_eq!(keytype!(keys, as_secretkey), vec![false, false, false, false, false, true]);
    }

    #[test]
    fn key_reencrypt() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap();
        let secret_key = SecretKey::new_xsalsa20poly1305();
        let key1 = Key::Root(sign_keypair.clone());
        let key2 = Key::Sign(sign_keypair.clone());
        let key3 = Key::Crypto(crypto_keypair.clone());
        let key4 = Key::Secret(Private::seal(&master_key, &secret_key).unwrap());

        let val1 = key1.as_rootkey().unwrap().sign(&master_key, b"hi i'm jerry").unwrap();
        let val2 = key2.as_signkey().unwrap().sign(&master_key, b"hi i'm butch").unwrap();
        let val3 = key3.as_cryptokey().unwrap().seal_anonymous(b"sufferin succotash").unwrap();
        let val4_key = key4.as_secretkey().unwrap().open(&master_key).unwrap();
        let val4_nonce = val4_key.gen_nonce();
        let val4 = val4_key.seal(b"and your nose like a delicious slope of cream", &val4_nonce).unwrap();

        let master_key2 = SecretKey::new_xsalsa20poly1305();
        assert!(master_key != master_key2);
        let key1_2 = key1.reencrypt(&master_key, &master_key2).unwrap();
        let key2_2 = key2.reencrypt(&master_key, &master_key2).unwrap();
        let key3_2 = key3.reencrypt(&master_key, &master_key2).unwrap();
        let key4_2 = key4.reencrypt(&master_key, &master_key2).unwrap();

        let val1_2 = key1_2.as_rootkey().unwrap().sign(&master_key2, b"hi i'm jerry").unwrap();
        let val2_2 = key2_2.as_signkey().unwrap().sign(&master_key2, b"hi i'm butch").unwrap();
        let val3_2 = key3_2.as_cryptokey().unwrap().open_anonymous(&master_key2, &val3).unwrap();
        let val4_2_key = key4_2.as_secretkey().unwrap().open(&master_key2).unwrap();
        let val4_2 = val4_2_key.open(&val4, &val4_nonce).unwrap();

        assert_eq!(val1, val1_2);
        assert_eq!(val2, val2_2);
        assert_eq!(val3_2, b"sufferin succotash");
        assert_eq!(val4_2, b"and your nose like a delicious slope of cream");

        let res1 = key1_2.as_rootkey().unwrap().sign(&master_key, b"hi i'm jerry");
        let res2 = key2_2.as_signkey().unwrap().sign(&master_key, b"hi i'm butch");
        let res3 = key3_2.as_cryptokey().unwrap().open_anonymous(&master_key, &val3);
        let res4 = key4_2.as_secretkey().unwrap().open(&master_key);

        assert_eq!(res1, Err(Error::CryptoOpenFailed));
        assert_eq!(res2, Err(Error::CryptoOpenFailed));
        assert_eq!(res3, Err(Error::CryptoOpenFailed));
        assert_eq!(res4, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn key_strip_private_has_private() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap();
        let secret_key = SecretKey::new_xsalsa20poly1305();
        let key1 = Key::Policy(sign_keypair.clone());
        let key2 = Key::Publish(sign_keypair.clone());
        let key3 = Key::Root(sign_keypair.clone());
        let key4 = Key::Sign(sign_keypair.clone());
        let key5 = Key::Crypto(crypto_keypair.clone());
        let key6 = Key::Secret(Private::seal(&master_key, &secret_key).unwrap());
        let key7 = Key::ExtensionKeypair(vec![1,2,3], Some(Private::seal(&master_key, &vec![4,5,6]).unwrap()));
        let key8 = Key::ExtensionSecret(Private::seal(&master_key, &vec![6,7,8]).unwrap());

        assert!(key1.has_private());
        assert!(key2.has_private());
        assert!(key3.has_private());
        assert!(key4.has_private());
        assert!(key5.has_private());
        assert!(key6.has_private());
        assert!(key7.has_private());
        assert!(key8.has_private());

        let key1_2 = key1.strip_private_maybe();
        let key2_2 = key2.strip_private_maybe();
        let key3_2 = key3.strip_private_maybe();
        let key4_2 = key4.strip_private_maybe();
        let key5_2 = key5.strip_private_maybe();
        let key6_2 = key6.strip_private_maybe();
        let key7_2 = key7.strip_private_maybe();
        let key8_2 = key8.strip_private_maybe();

        assert!(!key1_2.unwrap().has_private());
        assert!(!key2_2.unwrap().has_private());
        assert!(!key3_2.unwrap().has_private());
        assert!(!key4_2.unwrap().has_private());
        assert!(!key5_2.unwrap().has_private());
        assert!(key6_2.is_none());
        assert!(!key7_2.unwrap().has_private());
        assert!(key8_2.is_none());
    }

    #[test]
    fn signed_recovered_verify() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let alpha_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let signed = SignedValue::new(&master_key, &alpha_keypair, publish_keypair).unwrap();
        let signed_rec1 = SignedOrRecoveredKeypair::Signed(signed);
        let signed_rec2 = SignedOrRecoveredKeypair::Recovered(root_keypair);
        assert_eq!(signed_rec1.verify_signed(&alpha_keypair), Ok(()));
        assert_eq!(signed_rec2.verify_signed(&alpha_keypair), Err(Error::SignatureMissing));
    }

    #[test]
    fn signed_recovered_strip() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let alpha_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let signed = SignedValue::new(&master_key, &alpha_keypair, publish_keypair).unwrap();
        let signed_rec1 = SignedOrRecoveredKeypair::Signed(signed);
        let signed_rec2 = SignedOrRecoveredKeypair::Recovered(root_keypair);

        assert!(signed_rec1.has_private());
        assert!(signed_rec2.has_private());

        let signed_rec1_2 = signed_rec1.strip_private();
        let signed_rec2_2 = signed_rec2.strip_private();

        assert!(!signed_rec1_2.has_private());
        assert!(!signed_rec2_2.has_private());
    }

    fn keychain_new() -> (SecretKey, Keychain) {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let alpha_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let policy_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = SignKeypair::new_ed25519(&master_key).unwrap();

        let keychain = Keychain::new(&master_key, alpha_keypair, policy_keypair, publish_keypair, root_keypair).unwrap();
        (master_key, keychain)
    }

    #[test]
    fn keychain_set_policy_keys() {
        let (master_key, keychain) = keychain_new();
        assert_eq!(keychain.keys_policy().len(), 1);
        assert_eq!(keychain.subkeys_policy().len(), 0);
        let new_policy_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let alpha = keychain.alpha().clone();
        let keychain = keychain.set_policy_key(&master_key, &alpha, new_policy_keypair, RevocationReason::Superseded).unwrap();
        assert_eq!(keychain.keys_policy().len(), 2);
        assert_eq!(keychain.subkeys_policy().len(), 1);
    }

    #[test]
    fn keychain_set_publish() {
        let (master_key, keychain) = keychain_new();
        let new_publish_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let msg = b"happy happy joy joy";
        let sig_old = keychain.publish().sign(&master_key, msg).unwrap();
        let sig_new = new_publish_keypair.sign(&master_key, msg).unwrap();
        let signed = SignedValue::new(&master_key, keychain.alpha(), new_publish_keypair).unwrap();
        let wrapped = SignedOrRecoveredKeypair::Signed(signed);
        let keychain = keychain.set_publish_key(&master_key, wrapped, RevocationReason::Superseded).unwrap();
        assert_eq!(keychain.publish().verify(&sig_new, msg), Ok(()));
        assert_eq!(keychain.publish().verify(&sig_old, msg), Err(Error::CryptoSignatureVerificationFailed));
    }

    #[test]
    fn keychain_set_root_keys() {
        let (master_key, keychain) = keychain_new();
        assert_eq!(keychain.keys_root().len(), 1);
        let new_root_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let signed = SignedValue::new(&master_key, keychain.alpha(), new_root_keypair).unwrap();
        let wrapped = SignedOrRecoveredKeypair::Signed(signed);
        let keychain = keychain.set_root_key(&master_key, wrapped, RevocationReason::Superseded).unwrap();
        assert_eq!(keychain.keys_root().len(), 2);
    }

    #[test]
    fn keychain_subkeys_sign_verify_position() {
        let (master_key, keychain) = keychain_new();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap();
        let secret_key = Private::seal(&master_key, &SecretKey::new_xsalsa20poly1305()).unwrap();
        let sign = Key::new_sign(sign_keypair);
        let crypto = Key::new_crypto(crypto_keypair);
        let secret = Key::new_secret(secret_key);

        // add a bunch of subkeys and verify their position in the keychain and
        // their signatures against the root key
        //
        // we want to make sure new keys are always added to the end of the
        // keychain.
        let keychain = keychain.add_subkey(&master_key, sign, "MY signing key", Some("The key I use to sign things generally LOL")).unwrap();
        let last = keychain.subkeys().iter().last().unwrap();
        assert_eq!(last.key().name(), "MY signing key");
        last.verify(keychain.root()).unwrap();

        let keychain = keychain.add_subkey(&master_key, crypto, "MY crypto key", Some("Send me messages with this key OR ELSE")).unwrap();
        let last = keychain.subkeys().iter().last().unwrap();
        assert_eq!(last.key().name(), "MY crypto key");
        last.verify(keychain.root()).unwrap();

        let keychain = keychain.add_subkey(&master_key, secret, "MY secret key", Some("I use this to encrypt files and shit")).unwrap();
        let last = keychain.subkeys().iter().last().unwrap();
        assert_eq!(last.key().name(), "MY secret key");
        last.verify(keychain.root()).unwrap();

        // make sure finding by name does what we expect (first matching key
        // with that name)
        match (keychain.subkeys().iter().find(|x| x.key().name() == "MY crypto key"), keychain.subkey_by_name("MY crypto key")) {
            (Some(key1), Some(key2)) => {
                assert_eq!(key1 as *const Subkey, key2 as *const Subkey);
            }
            _ => panic!("Bad key search"),
        }

        keychain.verify_subkeys().unwrap();

        // now replace the root key, add another subkey, and do another subkey
        // verification to make sure subkeys with different roots will verify
        let new_root_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let signed = SignedValue::new(&master_key, keychain.alpha(), new_root_keypair).unwrap();
        let wrapped = SignedOrRecoveredKeypair::Signed(signed);
        let keychain = keychain.set_root_key(&master_key, wrapped, RevocationReason::Superseded).unwrap();

        let sign_keypair2 = SignKeypair::new_ed25519(&master_key).unwrap();
        let sign2 = Key::new_sign(sign_keypair2);
        let keychain = keychain.add_subkey(&master_key, sign2, "MY OTHER signing key", Some("The key I use to sign things generally LOL")).unwrap();
        // first is re-signed with new root lol
        let first = keychain.subkeys().iter().next().unwrap();
        assert_eq!(first.key().name(), "MY signing key");
        first.verify(keychain.root()).unwrap();
        let last = keychain.subkeys().iter().last().unwrap();
        assert_eq!(last.key().name(), "MY OTHER signing key");
        last.verify(keychain.root()).unwrap();

        keychain.verify_subkeys().unwrap();
    }

    #[test]
    fn keychain_revoke() {
        let (master_key, keychain) = keychain_new();
        let sign = Key::new_sign(SignKeypair::new_ed25519(&master_key).unwrap());
        let keychain = keychain.add_subkey(&master_key, sign, "sign", None).unwrap();
        // revoke a key, and verify the revocation
        let signkey = keychain.subkey_by_name("sign").unwrap().clone();
        assert!(signkey.revocation.is_none());
        let keychain = keychain.revoke_subkey(&master_key, signkey.id(), RevocationReason::Unspecified).unwrap();
        let signkey2 = keychain.subkey_by_name("sign").unwrap();
        signkey2.revocation.as_ref().unwrap().verify(keychain.root()).unwrap();
    }

    #[test]
    fn keychain_delete() {
        let (master_key, keychain) = keychain_new();
        let crypto = Key::new_crypto(CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap());
        let keychain = keychain.add_subkey(&master_key, crypto, "crypto", None).unwrap();
        // delete a key LOL
        let cryptokey = keychain.subkey_by_name("crypto").unwrap().clone();
        let keychain = keychain.delete_subkey(cryptokey.id()).unwrap();
        let cryptokey2 = keychain.subkey_by_name("crypto");
        // checkmate, liberals
        assert!(cryptokey2.is_none());
    }

    #[test]
    fn keychain_reencrypt() {
        let (master_key, keychain) = keychain_new();
        let sign = Key::new_sign(SignKeypair::new_ed25519(&master_key).unwrap());
        let crypto = Key::new_crypto(CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap());
        let secret = Key::new_secret(Private::seal(&master_key, &SecretKey::new_xsalsa20poly1305()).unwrap());
        let keychain = keychain
            .add_subkey(&master_key, sign, "sign", None).unwrap()
            .add_subkey(&master_key, crypto, "crypto", None).unwrap()
            .add_subkey(&master_key, secret, "secret", None).unwrap();

        // we'll generate a signature and encrypted value and try tomatch them
        // or decrypt them once the keychain is rekeyed
        let msg = b"you really trampled that guy";
        let signed = keychain.subkey_by_name("sign").unwrap().key().as_signkey().unwrap()
            .sign(&master_key, msg).unwrap();
        let encrypted = keychain.subkey_by_name("crypto").unwrap().key().as_cryptokey().unwrap()
            .seal_anonymous(msg).unwrap();
        keychain.subkey_by_name("secret").unwrap().key().as_secretkey().unwrap()
            .open(&master_key).unwrap();

        let master_key2 = SecretKey::new_xsalsa20poly1305();
        assert!(master_key != master_key2);
        let keychain = keychain.reencrypt(&master_key, &master_key2).unwrap();

        let signed2 = keychain.subkey_by_name("sign").unwrap().key().as_signkey().unwrap()
            .sign(&master_key2, msg).unwrap();
        let decrypted = keychain.subkey_by_name("crypto").unwrap().key().as_cryptokey().unwrap()
            .open_anonymous(&master_key2, &encrypted[..]).unwrap();
        assert_eq!(signed, signed2);
        assert_eq!(&decrypted[..], msg);

        let res = keychain.subkey_by_name("sign").unwrap().key().as_signkey().unwrap()
            .sign(&master_key, msg);
        assert_eq!(res, Err(Error::CryptoOpenFailed));
        let res = keychain.subkey_by_name("crypto").unwrap().key().as_cryptokey().unwrap()
            .open_anonymous(&master_key, &encrypted[..]);
        assert_eq!(res, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn keychain_strip_private() {
        let (master_key, keychain) = keychain_new();
        let sign = Key::new_sign(SignKeypair::new_ed25519(&master_key).unwrap());
        let crypto = Key::new_crypto(CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap());
        let secret = Key::new_secret(Private::seal(&master_key, &SecretKey::new_xsalsa20poly1305()).unwrap());
        let keychain = keychain
            .add_subkey(&master_key, sign, "sign", None).unwrap()
            .add_subkey(&master_key, crypto, "crypto", None).unwrap()
            .add_subkey(&master_key, secret, "secret", None).unwrap();
        assert_eq!(keychain.alpha().has_private(), true);
        assert_eq!(keychain.policy().has_private(), true);
        assert_eq!(keychain.publish().has_private(), true);
        assert_eq!(keychain.root().has_private(), true);
        assert_eq!(keychain.subkey_by_name("sign").unwrap().key().has_private(), true);
        assert_eq!(keychain.subkey_by_name("crypto").unwrap().key().has_private(), true);
        assert!(keychain.subkey_by_name("secret").is_some());

        let keychain = keychain.strip_private();

        assert_eq!(keychain.alpha().has_private(), false);
        assert_eq!(keychain.policy().has_private(), false);
        assert_eq!(keychain.publish().has_private(), false);
        assert_eq!(keychain.root().has_private(), false);
        assert_eq!(keychain.subkey_by_name("sign").unwrap().key().has_private(), false);
        assert_eq!(keychain.subkey_by_name("crypto").unwrap().key().has_private(), false);
        assert!(keychain.subkey_by_name("secret").is_none());
    }
}

