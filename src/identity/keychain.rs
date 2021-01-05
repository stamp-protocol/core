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
    key::{SecretKey, SignKeypairSignature, SignKeypair, CryptoKeypair},
    private::Private,
};
use getset;
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

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

/// Marks a key as revoked, signed with our root key. In the case that the
/// root key is being revoked, the deprecation must be signed with the new
/// root key.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Revocation {
    /// Revocation signature, and also unique ID for this revocation.
    id: RevocationID,
    /// The reason we're deprecating this key.
    reason: RevocationReason,
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

/// A unique identifier for a key. This is a signature of the key itself.
///
/// A bit different from other IDs in that it must be regenerated when the root
/// keypair changes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubkeyID(SignKeypairSignature);

impl Deref for SubkeyID {
    type Target = SignKeypairSignature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Holds a subkey's id/signature (signed by the root key), its key data, and an
/// optional revocation.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Subkey {
    /// They subkey's unique ID, and signature of its *public* contents.
    ///
    /// This must be regeneroned when the root keypair changes. (I feel...
    /// perfect)
    id: SubkeyID,
    /// The key itself.
    ///
    /// Alright, Parker, shut up. Thank you, Parker. Shut up. Thank you.
    key: Key,
    /// Allows revocation of a key.
    revocation: Option<Revocation>,
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
    /// The identity's root signing key. Does not need an id or revocations
    /// because a key signing itself would be ridiculous and the moment it is
    /// revoked it joins the other subkeys, so there's no need to wrap it in
    /// the subkey object.
    root: SignKeypair,
    /// Holds our subkeys, signed with our root keypair.
    subkeys: Vec<Subkey>,
}

impl Keychain {
    /// Create a new keychain
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

