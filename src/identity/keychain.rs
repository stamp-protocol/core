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
    key::{SecretKey, SignKeypairSignature, SignKeypair, CryptoKeypair},
    private::Private,
    util::{ser, sign::SignedValue},
};
use getset;
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// A unique identifier for a key. This is a signature of the key itself.
///
/// A bit different from other IDs in that it must be regenerated when the root
/// keypair changes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyID(SignKeypairSignature);

impl Deref for KeyID {
    type Target = SignKeypairSignature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A unique identifier for a key revocation. This is a signature of the
/// revocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RevocationID(SignKeypairSignature);

impl Deref for RevocationID {
    type Target = SignKeypairSignature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
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
}

/// An enum that holds any type of key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Key {
    /// A policy key
    Policy(SignKeypair),
    /// A publish key
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
    /// Returns the `SignKeypair` if this is a policy key.
    pub fn as_policykey(&self) -> Option<SignKeypair> {
        match self {
            Self::Policy(ref x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Returns the `SignKeypair` if this is a root key.
    pub fn as_rootkey(&self) -> Option<SignKeypair> {
        match self {
            Self::Root(ref x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Returns the `SignKeypair` if this is a signing key.
    pub fn as_signkey(&self) -> Option<SignKeypair> {
        match self {
            Self::Sign(ref x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Returns the `SignKeypair` if this is a signing key.
    pub fn as_cryptokey(&self) -> Option<CryptoKeypair> {
        match self {
            Self::Crypto(ref x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Returns the `SignKeypair` if this is a signing key.
    pub fn as_secretkey(&self) -> Option<Private<SecretKey>> {
        match self {
            Self::Secret(ref x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Consumes the key, and re-encryptes it with a new master key.
    pub fn rekey(self, previous_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let key = match self {
            Self::Policy(keypair) => Self::Policy(keypair.rekey(previous_master_key, new_master_key)?),
            Self::Publish(keypair) => Self::Publish(keypair.rekey(previous_master_key, new_master_key)?),
            Self::Root(keypair) => Self::Root(keypair.rekey(previous_master_key, new_master_key)?),
            Self::Sign(keypair) => Self::Sign(keypair.rekey(previous_master_key, new_master_key)?),
            Self::Crypto(keypair) => Self::Crypto(keypair.rekey(previous_master_key, new_master_key)?),
            Self::Secret(secret) => Self::Secret(secret.rekey(previous_master_key, new_master_key)?),
            Self::ExtensionKeypair(public, private_maybe) => {
                if let Some(private) = private_maybe {
                    Self::ExtensionKeypair(public, Some(private.rekey(previous_master_key, new_master_key)?))
                } else {
                    return Err(Error::CryptoKeyMissing)?;
                }
            }
            Self::ExtensionSecret(secret) => Self::ExtensionSecret(secret.rekey(previous_master_key, new_master_key)?),
        };
        Ok(key)
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
    description: String,
}

impl KeyEntry {
    /// Create a new KeyEntry.
    fn new(key: Key, name: String, description: String) -> Self {
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
    fn new<T: Into<String>>(master_key: &SecretKey, sign_keypair: &SignKeypair, key: Key, name: T, description: T) -> Result<Self> {
        // create a blank signature we're going to use TEMPORARILY for the id
        // and signature fields.
        //
        // fake signature. Sad!
        let blank_signature = SignKeypairSignature::blank(sign_keypair);
        let entry = KeyEntry::new(key, name.into(), description.into());
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

    /// Grab all policy subkeys.
    pub fn keys_policy(&self) -> Vec<SignKeypair> {
        let mut search_keys = vec![self.policy().deref().clone()];
        search_keys.append(&mut self.subkeys_policy());
        search_keys
    }

    pub fn subkeys_policy(&self) -> Vec<SignKeypair> {
        self.subkeys().iter()
            .map(|x| x.key().as_policykey())
            .filter(|x| x.is_some())
            .map(|x| x.unwrap())
            .collect::<Vec<_>>()
    }

    /// Grab all root keys.
    pub fn keys_root(&self) -> Vec<SignKeypair> {
        let mut search_keys = vec![self.root().deref().clone()];
        search_keys.append(&mut self.subkeys_root());
        search_keys
    }

    fn subkeys_root(&self) -> Vec<SignKeypair> {
        self.subkeys().iter()
            .map(|x| x.key().as_rootkey())
            .filter(|x| x.is_some())
            .map(|x| x.unwrap())
            .collect::<Vec<_>>()
    }

    /// Grab all signing subkeys.
    pub fn subkeys_sign(&self) -> Vec<SignKeypair> {
        self.subkeys().iter()
            .map(|x| x.key().as_signkey())
            .filter(|x| x.is_some())
            .map(|x| x.unwrap())
            .collect::<Vec<_>>()
    }

    /// Grab all crypto subkeys.
    pub fn subkeys_crypto(&self) -> Vec<CryptoKeypair> {
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
        let mut subkey = Subkey::new(master_key, alpha_keypair, Key::Policy(policy), "policy key", "revoked policy key")?;
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
        let mut subkey = Subkey::new(master_key, self.root(), Key::Publish(publish), "publish key", "revoked publish key")?;
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
        let mut subkey = Subkey::new(master_key, &new_root_keypair, Key::Root(root), "root key", "revoked root key")?;
        subkey.revoke(master_key, &new_root_keypair, reason)?;
        self.subkeys_mut().push(subkey);
        self.set_root(new_root_keypair);
        self.sign_subkeys(master_key)
    }

    /// Add a new subkey to the keychain (and sign it).
    pub(crate) fn add_subkey<T: Into<String>>(mut self, master_key: &SecretKey, key: Key, name: T, description: T) -> Result<Self> {
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
    pub(crate) fn revoke_subkey(mut self, master_key: &SecretKey, key_id: KeyID, reason: RevocationReason) -> Result<Self> {
        let root = self.root().clone();
        let key = self.subkeys_mut().iter_mut()
            .find(|x| x.id() == &key_id)
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

