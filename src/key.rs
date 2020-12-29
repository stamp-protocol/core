use crate::{
    error::{Error, Result},
    private::{Private},
};
use serde_derive::{Serialize, Deserialize};
use sodiumoxide::{
    crypto::{
        box_::curve25519xsalsa20poly1305,
        pwhash::argon2id13,
        secretbox::xsalsa20poly1305,
        sign::ed25519,
    },
};

/// A symmetric encryption key nonce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretKeyNonce {
    Xsalsa20Poly1305(xsalsa20poly1305::Nonce),
}

/// A symmetric encryption key
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecretKey {
    Xsalsa20Poly1305(xsalsa20poly1305::Key),
}

impl SecretKey {
    /// Create a new xsalsa20poly1305 key
    pub fn new_xsalsa20poly1305() -> Self {
        Self::Xsalsa20Poly1305(xsalsa20poly1305::gen_key())
    }

    /// Create a nonce for use with this secret key
    pub fn gen_nonce(&self) -> SecretKeyNonce {
        match self {
            SecretKey::Xsalsa20Poly1305(_) => SecretKeyNonce::Xsalsa20Poly1305(xsalsa20poly1305::gen_nonce()),
        }
    }

    /// Encrypt a value with a secret key/nonce
    pub fn seal(&self, data: &[u8], nonce: &SecretKeyNonce) -> Result<Vec<u8>> {
        match (self, nonce) {
            (SecretKey::Xsalsa20Poly1305(ref key), SecretKeyNonce::Xsalsa20Poly1305(ref nonce)) => {
                Ok(xsalsa20poly1305::seal(data, nonce, key))
            },
        }
    }

    /// Decrypt a value with a secret key/nonce
    pub fn open(&self, data: &[u8], nonce: &SecretKeyNonce) -> Result<Vec<u8>> {
        match (self, nonce) {
            (SecretKey::Xsalsa20Poly1305(ref key), SecretKeyNonce::Xsalsa20Poly1305(ref nonce)) => {
                let open_bytes = xsalsa20poly1305::open(data, nonce, key)
                    .map_err(|_| Error::CryptoOpenFailed)?;
                Ok(open_bytes)
            },
        }
    }

    /// Get the raw bytes for this key
    pub fn as_ref(&self) -> &[u8] {
        match self {
            SecretKey::Xsalsa20Poly1305(ref key) => key.as_ref(),
        }
    }
}

/// A signature derived from a signing keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignKeypairSignature {
    Ed25519(ed25519::Signature),
}

/// An asymmetric signing keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignKeypair {
    Ed25519(ed25519::PublicKey, Option<Private<ed25519::SecretKey>>),
}

impl SignKeypair {
    /// Create a new ed25519 keypair
    pub fn new_ed25519(master_key: &SecretKey) -> Result<Self> {
        let (public, secret) = ed25519::gen_keypair();
        Ok(Self::Ed25519(public, Some(Private::seal(master_key, &secret)?)))
    }

    /// Sign a value with our secret signing key.
    ///
    /// Must be unlocked via our master key.
    pub fn sign(&self, master_key: &SecretKey, data: &[u8]) -> Result<SignKeypairSignature> {
        match self {
            SignKeypair::Ed25519(_, ref sec_locked_opt) => {
                let sec_locked = sec_locked_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let seckey = sec_locked.open(master_key)?;
                Ok(SignKeypairSignature::Ed25519(ed25519::sign_detached(data, &seckey)))
            }
        }
    }
}

/// An asymmetric signing keypair nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoKeypairNonce {
    Curve25519Xsalsa20Poly1305(curve25519xsalsa20poly1305::Nonce),
}

/// A message we encrypt with their pubkey that's signed with our seckey. Meant
/// for non-anonymous, authenticated messaging.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct CryptoKeypairMessage {
    /// Our heroic nonce
    nonce: CryptoKeypairNonce,
    /// The message ciphertext
    ciphertext: Vec<u8>,
}

impl CryptoKeypairMessage {
    /// Create a new message
    pub fn new(nonce: CryptoKeypairNonce, ciphertext: Vec<u8>) -> Self {
        Self {
            nonce,
            ciphertext,
        }
    }
}

/// An asymmetric signing keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoKeypair {
    Curve25519Xsalsa20Poly1305(curve25519xsalsa20poly1305::PublicKey, Option<Private<curve25519xsalsa20poly1305::SecretKey>>),
}

impl CryptoKeypair {
    /// Create a new keypair
    pub fn new_curve25519xsalsa20poly1305(master_key: &SecretKey) -> Result<Self> {
        let (public, secret) = curve25519xsalsa20poly1305::gen_keypair();
        Ok(Self::Curve25519Xsalsa20Poly1305(public, Some(Private::seal(master_key, &secret)?)))
    }

    /// Anonymously encrypt a message using the recipient's public key.
    pub fn seal_anonymous(their_pk: &CryptoKeypair, data: &[u8]) -> Result<Vec<u8>> {
        match their_pk {
            CryptoKeypair::Curve25519Xsalsa20Poly1305(ref pubkey, _) => {
                Ok(sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305::seal(data, pubkey))
            }
        }
    }

    /// Encrypt a message to a recipient, and sign it with our secret crypto
    /// key. Needs our master key to unlock our heroic private key.
    pub fn seal(master_key: &SecretKey, our_keypair: &CryptoKeypair, their_keypair: &CryptoKeypair, data: &[u8]) -> Result<CryptoKeypairMessage> {
        match (our_keypair, their_keypair) {
            (CryptoKeypair::Curve25519Xsalsa20Poly1305(_, ref our_seckey_opt), CryptoKeypair::Curve25519Xsalsa20Poly1305(ref their_pubkey, _)) => {
                let our_seckey_sealed = our_seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let our_seckey = our_seckey_sealed.open(master_key)?;
                let nonce_raw = curve25519xsalsa20poly1305::gen_nonce();
                let msg = curve25519xsalsa20poly1305::seal(data, &nonce_raw, &their_pubkey, &our_seckey);
                let nonce = CryptoKeypairNonce::Curve25519Xsalsa20Poly1305(nonce_raw);
                Ok(CryptoKeypairMessage::new(nonce, msg))
            }
        }
    }
}


/// Generate a master key from a passphrase/salt
pub fn derive_master_key(passphrase: &[u8], salt: &[u8; argon2id13::SALTBYTES]) -> Result<SecretKey> {
    let len = xsalsa20poly1305::KEYBYTES;
    let mut key: Vec<u8> = vec![0; len];
    let salt_wrap = match argon2id13::Salt::from_slice(salt) {
        Some(x) => x,
        None => Err(Error::CryptoBadSalt)?,
    };
    match argon2id13::derive_key(key.as_mut_slice(), passphrase, &salt_wrap, argon2id13::OPSLIMIT_MODERATE, argon2id13::MEMLIMIT_MODERATE) {
        Ok(x) => {
            let rawkey = xsalsa20poly1305::Key::from_slice(x).ok_or(Error::CryptoKDFFailed)?;
            let seckey = SecretKey::Xsalsa20Poly1305(rawkey);
            Ok(seckey)
        }
        Err(()) => Err(Error::CryptoKDFFailed)?,
    }
}

