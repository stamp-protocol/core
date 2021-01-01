use crate::{
    key::{SecretKey, SignKeypairSignature, SignKeypair, CryptoKeypair},
    private::Private,
};
use getset;
use serde_derive::{Serialize, Deserialize};

/// Why we are deprecating a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationReason {
    /// No reason.
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
    /// Revocation signature.
    signature: SignKeypairSignature,
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
    /// Hides our private claim data
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

/// Holds a subkey, signed by the identity's root key. It also stores whether or
/// not the key has been revoked.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Subkey {
    /// The signature of this subkey's public key (unless this is a secret key,
    /// in which case we sign the encrypted secret key).
    signature: SignKeypairSignature,
    /// The key itself.
    key: Key,
    /// Allows deprecation of a key.
    revoked: Option<Revocation>,
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
    /// The account's root signing key.
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

