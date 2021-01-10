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
    /// Create a new revocation.
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

    /// Returns a version of this key without any private data. Useful for signing.
    pub(crate) fn public_only(&self) -> Option<Self> {
        match self {
            Self::Sign(keypair) => Some(Self::Sign(keypair.public_only())),
            Self::Crypto(keypair) => Some(Self::Crypto(keypair.public_only())),
            Self::Secret(_) => None,
            Self::ExtensionKeypair(public, _) => Some(Self::ExtensionKeypair(public.clone(), None)),
            Self::ExtensionSecret(_) => None,
        }
    }
}

/// Holds a subkey's id/signature (signed by the root key), its key data, and an
/// optional revocation.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Subkey {
    /// They subkey's unique ID, and signature of its *public* contents, signed
    /// by the identity's *current* root keypair (and forevermore unchanged).
    id: KeyID,
    /// The signature of the key's *public* contents, always kept up to date
    /// with the *latest* root signing key...this must be regeneroned when the
    /// root keypair changes (I feel.....perfect)
    signature: SignKeypairSignature,
    /// The key itself.
    ///
    /// Alright, Parker, shut up. Thank you, Parker. Shut up. Thank you.
    key: Key,
    /// Allows revocation of a key.
    revocation: Option<Revocation>,
}

impl Subkey {
    /// Create a new subkey, signed by our root key.
    fn new(master_key: &SecretKey, sign_keypair: &SignKeypair, key: Key) -> Result<Self> {
        // create a blank signature we're going to use TEMPORARILY for the id
        // and signature fields.
        //
        // fake signature. Sad!
        let blank_signature = SignKeypairSignature::blank(sign_keypair);
        let mut subkey = Self {
            id: KeyID(blank_signature.clone()),
            signature: blank_signature,
            key,
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
        let maybe_public = self.key().public_only();
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
    /// key controls the policy and recovery keys, which should be all you'd
    /// ever need, even in the case of a compromised identity.
    alpha: SignKeypair,
    /// Our policy signing key. Lets us create recovery policies. This is signed
    /// by the alpha key, which prevents tampering.
    policy: SignedValue<SignKeypair>,
    /// The recovery key. If we have this, we can replace our root signing
    /// keypair. This is signed by the alpha key.
    recovery: SignedValue<SignKeypair>,
    /// The identity's root signing key, signed by the recovery key.
    root: SignedValue<SignKeypair>,
    /// Holds our subkeys, signed with our root keypair.
    subkeys: Vec<Subkey>,
}

impl Keychain {
    /// Create a new keychain
    pub(crate) fn new(master_key: &SecretKey, alpha_keypair: SignKeypair, policy_keypair: SignKeypair, recovery_keypair: SignKeypair, root_keypair: SignKeypair) -> Result<Self> {
        let root = SignedValue::new(master_key, &recovery_keypair, root_keypair)?;
        let policy = SignedValue::new(master_key, &alpha_keypair, policy_keypair)?;
        let recovery = SignedValue::new(master_key, &alpha_keypair, recovery_keypair)?;
        Ok(Self {
            alpha: alpha_keypair,
            policy,
            recovery,
            root,
            subkeys: Vec::new(),
        })
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

    /// Add a new subkey to the keychain (and sign it).
    pub(crate) fn add_subkey(mut self, master_key: &SecretKey, key: Key) -> Result<Self> {
        let root = self.root().clone();
        self.subkeys_mut().push(Subkey::new(master_key, &root, key)?);
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

    /// Replace our root signing key.
    ///
    /// This moves the current root key into the subkeys, revokes it, and
    /// updates the signature on all the subkeys (including the old root key).
    pub(crate) fn set_root_key(mut self, master_key: &SecretKey, recovery_key: &SignKeypair, new_root_keypair: SignKeypair) -> Result<Self> {
        let root = self.root().deref().clone();
        self.subkeys_mut().push(Subkey::new(master_key, &new_root_keypair, Key::Sign(root))?);
        self.set_root(SignedValue::new(master_key, recovery_key, new_root_keypair)?);
        self.sign_subkeys(master_key)
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

    pub(crate) fn strip_private(&self) -> Self {
        let mut keychain_clone = self.clone();
        keychain_clone.set_alpha(self.alpha().public_only());
        keychain_clone.policy_mut().set_value(self.policy().value().public_only());
        keychain_clone.recovery_mut().set_value(self.recovery().value().public_only());
        keychain_clone.root_mut().set_value(self.root().value().public_only());
        let subkeys = self.subkeys().clone().into_iter()
            .map(|x| {
                let res = match x.key.clone() {
                    Key::Sign(keypair) => Some(Key::Sign(keypair.public_only())),
                    Key::Crypto(keypair) => Some(Key::Crypto(keypair.public_only())),
                    Key::ExtensionKeypair(public, _) => Some(Key::ExtensionKeypair(public, None)),
                    _ => None,
                };
                (res, x)
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

