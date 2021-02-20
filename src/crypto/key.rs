//! The key model wraps a set of algorithms for encryption and decryption (both
//! symmetric and asymmetric) as well as cryptographic signing of data.
//!
//! The idea here is that specific algorithms are wrapped in descriptive
//! interfaces that allow high-level use of the encapsulated cryptographic
//! algorithms without needing to know the details of those algorithms.
//!
//! For instance, you have a `SignKeypair` which has a standard interface, but
//! can describe any number of signing algorithms. This allows expansion of the
//! cryptographic primitives used without needing to build new interfaces around
//! them.

use crate::{
    error::{Error, Result},
    private::Private,
    util::{
        Lockable,
        Public,

        ser::{self, TryFromSlice},
        sign::Signable,
    },
};
use serde_derive::{Serialize, Deserialize};
use sodiumoxide::{
    crypto::{
        auth::hmacsha512,
        box_::curve25519xsalsa20poly1305,
        pwhash::argon2id13,
        secretbox::xsalsa20poly1305,
        sign::ed25519,
    },
};
use std::convert::TryInto;

impl_try_from_slice!(ed25519::PublicKey);
impl_try_from_slice!(xsalsa20poly1305::Nonce);
impl_try_from_slice!(xsalsa20poly1305::Key);
impl_try_from_slice!(ed25519::Signature);
impl_try_from_slice!(curve25519xsalsa20poly1305::Nonce);
impl_try_from_slice!(curve25519xsalsa20poly1305::PublicKey);
impl_try_from_slice!(hmacsha512::Tag);
impl_try_from_slice!(hmacsha512::Key);

/// A value that lets us reference asymmetric keypairs by their public key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyID {
    SignKeypair(SignKeypairPublic),
    CryptoKeypair(CryptoKeypairPublic),
}

impl KeyID {
    pub fn as_string(&self) -> String {
        fn get_bytes(ty_prefix: u8, key_prefix: u8, bytes: &[u8]) -> Vec<u8> {
            let mut res = vec![ty_prefix, key_prefix];
            let mut bytes_vec = Vec::from(bytes);
            res.append(&mut bytes_vec);
            res
        }
        let bytes = match self {
            Self::SignKeypair(SignKeypairPublic::Ed25519(pubkey)) => {
                get_bytes(0, 0, pubkey.as_ref())
            }
            Self::CryptoKeypair(CryptoKeypairPublic::Curve25519Xsalsa20Poly1305(pubkey)) => {
                get_bytes(1, 0, pubkey.as_ref())
            }
        };
        ser::base64_encode(&bytes)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_sign() -> Self {
        let master_key = SecretKey::new_xsalsa20poly1305();
        Self::SignKeypair(SignKeypair::new_ed25519(&master_key).unwrap().into())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_crypto() -> Self {
        let master_key = SecretKey::new_xsalsa20poly1305();
        Self::CryptoKeypair(CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap().into())
    }
}

/// A symmetric encryption key nonce
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecretKeyNonce {
    #[serde(with = "crate::util::ser::human_binary_from_slice")]
    Xsalsa20Poly1305(xsalsa20poly1305::Nonce),
}

/// A symmetric encryption key
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecretKey {
    #[serde(with = "crate::util::ser::human_binary_from_slice")]
    Xsalsa20Poly1305(xsalsa20poly1305::Key),
}

impl SecretKey {
    /// Create a new xsalsa20poly1305 key
    pub fn new_xsalsa20poly1305() -> Self {
        Self::Xsalsa20Poly1305(xsalsa20poly1305::gen_key())
    }

    /// Try to create a SecretKey from a byte slice
    pub fn new_xsalsa20poly1305_from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(Self::Xsalsa20Poly1305(xsalsa20poly1305::Key::from_slice(bytes).ok_or(Error::CryptoBadKey)?))
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

impl Lockable for SecretKey {
    fn mem_lock(&mut self) -> Result<()> {
        let res = match self {
            Self::Xsalsa20Poly1305(ref mut inner) => sodiumoxide::utils::mlock(&mut inner.0),
        };
        res.map_err(|_| Error::CryptoMemLockFailed)
    }

    fn mem_unlock(&mut self) -> Result<()> {
        let res = match self {
            Self::Xsalsa20Poly1305(ref mut inner) => sodiumoxide::utils::munlock(&mut inner.0),
        };
        res.map_err(|_| Error::CryptoMemUnlockFailed)
    }
}

/// A signature derived from a signing keypair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SignKeypairSignature {
    #[serde(with = "crate::util::ser::human_binary_from_slice")]
    Ed25519(ed25519::Signature),
}

impl SignKeypairSignature {
    /// Given a signing keypair, return a blank (ie, 0x0000000000...) signature
    /// that matches the key type.
    ///
    /// This is useful when an object NEEDS a signature to be constructed, but
    /// there is a method on that object specifically for signing itself. So, do
    /// we duplicate the signing code in two places? Or do we give the object a
    /// blank signature just to construct it, then call the signature method
    /// once it's constructed? I prefer the latter.
    pub fn blank(sign_keypair: &SignKeypair) -> Self {
        match sign_keypair {
            SignKeypair::Ed25519(..) => Self::Ed25519(ed25519::Signature::from_slice(vec![0; ed25519::SIGNATUREBYTES].as_slice()).unwrap()),
        }
    }
}

impl AsRef<[u8]> for SignKeypairSignature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519(sig) => sig.as_ref(),
        }
    }
}

/// An asymmetric signing keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignKeypair {
    Ed25519(#[serde(with = "crate::util::ser::human_binary_from_slice")] ed25519::PublicKey, Option<Private<ed25519::SecretKey>>),
}

impl SignKeypair {
    /// Create a new ed25519 keypair
    pub fn new_ed25519(master_key: &SecretKey) -> Result<Self> {
        let (public, secret) = ed25519::gen_keypair();
        Ok(Self::Ed25519(public, Some(Private::seal(master_key, &secret)?)))
    }

    /// Create a new ed25519 keypair
    pub fn new_ed25519_from_seed(master_key: &SecretKey, seed_bytes: &[u8; 32]) -> Result<Self> {
        let seed = ed25519::Seed::from_slice(seed_bytes).ok_or(Error::CryptoBadSeed)?;
        let (public, secret) = ed25519::keypair_from_seed(&seed);
        Ok(Self::Ed25519(public, Some(Private::seal(master_key, &secret)?)))
    }

    /// Sign a value with our secret signing key.
    ///
    /// Must be unlocked via our master key.
    pub fn sign(&self, master_key: &SecretKey, data: &[u8]) -> Result<SignKeypairSignature> {
        match self {
            Self::Ed25519(_, ref sec_locked_opt) => {
                let sec_locked = sec_locked_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let seckey = sec_locked.open(master_key)?;
                Ok(SignKeypairSignature::Ed25519(ed25519::sign_detached(data, &seckey)))
            }
        }
    }

    /// Verify a value with a detached signature given the public key of the
    /// signer.
    pub fn verify(&self, signature: &SignKeypairSignature, data: &[u8]) -> Result<()> {
        match (self, signature) {
            (Self::Ed25519(ref pubkey, _), SignKeypairSignature::Ed25519(ref sig)) => {
                if ed25519::verify_detached(sig, data, pubkey) {
                    Ok(())
                } else {
                    Err(Error::CryptoSignatureVerificationFailed)
                }
            }
        }
    }

    /// Re-encrypt this signing keypair with a new master key.
    pub fn reencrypt(self, previous_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        match self {
            Self::Ed25519(public, Some(private)) => {
                Ok(Self::Ed25519(public, Some(private.reencrypt(previous_master_key, new_master_key)?)))
            }
            _ => Err(Error::CryptoKeyMissing),
        }
    }

    /// Create a KeyID from this keypair.
    pub fn key_id(&self) -> KeyID {
        KeyID::SignKeypair(self.clone().into())
    }
}

impl Public for SignKeypair {
    fn strip_private(&self) -> Self {
        match self {
            Self::Ed25519(pubkey, _) => {
                Self::Ed25519(pubkey.clone(), None)
            }
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::Ed25519(_, private_maybe) => private_maybe.is_some(),
        }
    }
}

impl PartialEq for SignKeypair {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ed25519(public1, _), Self::Ed25519(public2, _)) => public1 == public2,
        }
    }
}

impl Signable for SignKeypair {
    type Item = SignKeypairPublic;
    fn signable(&self) -> Self::Item {
        self.clone().into()
    }
}

/// An asymmetric signing public key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SignKeypairPublic {
    Ed25519(#[serde(with = "crate::util::ser::human_binary_from_slice")] ed25519::PublicKey),
}

impl SignKeypairPublic {
    /// Verify a value with a detached signature given the public key of the
    /// signer.
    pub fn verify(&self, signature: &SignKeypairSignature, data: &[u8]) -> Result<()> {
        match (self, signature) {
            (Self::Ed25519(ref pubkey), SignKeypairSignature::Ed25519(ref sig)) => {
                if ed25519::verify_detached(sig, data, pubkey) {
                    Ok(())
                } else {
                    Err(Error::CryptoSignatureVerificationFailed)
                }
            }
        }
    }

    /// Create a KeyID from this keypair.
    pub fn key_id(&self) -> KeyID {
        KeyID::SignKeypair(self.clone())
    }
}

impl From<SignKeypair> for SignKeypairPublic {
    fn from(kp: SignKeypair) -> Self {
        match kp {
            SignKeypair::Ed25519(public, _) => Self::Ed25519(public),
        }
    }
}

/// An asymmetric signing keypair nonce.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CryptoKeypairNonce {
    #[serde(with = "crate::util::ser::human_binary_from_slice")] 
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
    fn new(nonce: CryptoKeypairNonce, ciphertext: Vec<u8>) -> Self {
        Self {
            nonce,
            ciphertext,
        }
    }
}

/// An asymmetric signing keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoKeypair {
    Curve25519Xsalsa20Poly1305(#[serde(with = "crate::util::ser::human_binary_from_slice")] curve25519xsalsa20poly1305::PublicKey, Option<Private<curve25519xsalsa20poly1305::SecretKey>>),
}

impl CryptoKeypair {
    /// Create a new keypair
    pub fn new_curve25519xsalsa20poly1305(master_key: &SecretKey) -> Result<Self> {
        let (public, secret) = curve25519xsalsa20poly1305::gen_keypair();
        Ok(Self::Curve25519Xsalsa20Poly1305(public, Some(Private::seal(master_key, &secret)?)))
    }

    /// Anonymously encrypt a message using the recipient's public key.
    pub fn seal_anonymous(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Curve25519Xsalsa20Poly1305(ref pubkey, _) => {
                Ok(sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305::seal(data, pubkey))
            }
        }
    }

    /// Open an anonymous message encrypted with our public key. Requires our
    /// master key to open.
    pub fn open_anonymous(&self, master_key: &SecretKey, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Curve25519Xsalsa20Poly1305(ref pubkey, ref seckey_opt) => {
                let seckey_sealed = seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let seckey = seckey_sealed.open(master_key)?;
                sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305::open(data, pubkey, &seckey)
                    .map_err(|_| Error::CryptoOpenFailed)
            }
        }
    }

    /// Encrypt a message to a recipient, and sign it with our secret crypto
    /// key. Needs our master key to unlock our heroic private key.
    pub fn seal(&self, sender_master_key: &SecretKey, sender_keypair: &CryptoKeypair, data: &[u8]) -> Result<CryptoKeypairMessage> {
        match (sender_keypair, self) {
            (Self::Curve25519Xsalsa20Poly1305(_, ref sender_seckey_opt), Self::Curve25519Xsalsa20Poly1305(ref recipient_pubkey, _)) => {
                let sender_seckey_sealed = sender_seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let sender_seckey = sender_seckey_sealed.open(sender_master_key)?;
                let nonce_raw = curve25519xsalsa20poly1305::gen_nonce();
                let msg = curve25519xsalsa20poly1305::seal(data, &nonce_raw, &recipient_pubkey, &sender_seckey);
                let nonce = CryptoKeypairNonce::Curve25519Xsalsa20Poly1305(nonce_raw);
                Ok(CryptoKeypairMessage::new(nonce, msg))
            }
        }
    }

    /// Open a message encrypted with our public key and verify the sender of
    /// the message using their public key. Needs our master key to unlock the
    /// private key used to decrypt the message.
    pub fn open(&self, recipient_master_key: &SecretKey, sender_keypair: &CryptoKeypair, message: &CryptoKeypairMessage) -> Result<Vec<u8>> {
        match (self, sender_keypair) {
            (Self::Curve25519Xsalsa20Poly1305(_, ref recipient_seckey_opt), CryptoKeypair::Curve25519Xsalsa20Poly1305(ref sender_pubkey, _)) => {
                let recipient_seckey_sealed = recipient_seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let recipient_seckey = recipient_seckey_sealed.open(recipient_master_key)?;
                let nonce = message.nonce();
                let nonce_raw = match nonce {
                    CryptoKeypairNonce::Curve25519Xsalsa20Poly1305(ref x) => x,
                };
                curve25519xsalsa20poly1305::open(message.ciphertext(), nonce_raw, &sender_pubkey, &recipient_seckey)
                    .map_err(|_| Error::CryptoOpenFailed)
            }
        }
    }

    /// Re-encrypt this signing keypair with a new master key.
    pub fn reencrypt(self, previous_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        match self {
            Self::Curve25519Xsalsa20Poly1305(public, Some(private)) => {
                Ok(Self::Curve25519Xsalsa20Poly1305(public, Some(private.reencrypt(previous_master_key, new_master_key)?)))
            }
            _ => Err(Error::CryptoKeyMissing),
        }
    }

    /// Create a KeyID from this keypair.
    pub fn key_id(&self) -> KeyID {
        KeyID::CryptoKeypair(self.clone().into())
    }
}

impl Public for CryptoKeypair {
    fn strip_private(&self) -> Self {
        match self {
            Self::Curve25519Xsalsa20Poly1305(ref pubkey, _) => {
                Self::Curve25519Xsalsa20Poly1305(pubkey.clone(), None)
            }
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::Curve25519Xsalsa20Poly1305(_, private_maybe) => private_maybe.is_some(),
        }
    }
}

/// An asymmetric signing public key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CryptoKeypairPublic {
    Curve25519Xsalsa20Poly1305(#[serde(with = "crate::util::ser::human_binary_from_slice")] curve25519xsalsa20poly1305::PublicKey),
}

impl CryptoKeypairPublic {
    /// Create a KeyID from this keypair.
    pub fn key_id(&self) -> KeyID {
        KeyID::CryptoKeypair(self.clone())
    }
}

impl From<CryptoKeypair> for CryptoKeypairPublic {
    fn from(kp: CryptoKeypair) -> Self {
        match kp {
            CryptoKeypair::Curve25519Xsalsa20Poly1305(public, _) => Self::Curve25519Xsalsa20Poly1305(public),
        }
    }
}

/// A key for deriving an HMAC
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HmacKey {
    #[serde(with = "crate::util::ser::human_binary_from_slice")]
    HmacSha512(hmacsha512::Key),
}

impl HmacKey {
    /// Create a new sha512 HMAC key
    pub fn new_sha512() -> Self {
        Self::HmacSha512(hmacsha512::gen_key())
    }
}

/// An HMAC hash
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Hmac {
    #[serde(with = "crate::util::ser::human_binary_from_slice")]
    HmacSha512(hmacsha512::Tag),
}

impl Hmac {
    /// Create a new HMACSHA512 from a key and a set of data.
    pub fn new_sha512(hmac_key: &HmacKey, data: &[u8]) -> Result<Self> {
        match hmac_key {
            HmacKey::HmacSha512(hmac_key) => {
                let hmac = hmacsha512::authenticate(data, hmac_key);
                Ok(Hmac::HmacSha512(hmac))
            }
        }
    }

    /// Verify an HMAC against a set of data.
    pub fn verify(&self, hmac_key: &HmacKey, data: &[u8]) -> Result<()> {
        match (self, hmac_key) {
            (Self::HmacSha512(hmac), HmacKey::HmacSha512(hmac_key)) => {
                if !hmacsha512::verify(hmac, data, hmac_key) {
                    // the data has been tampered with, my friend.
                    Err(Error::CryptoHmacVerificationFailed)?;
                }
            }
        }
        Ok(())
    }
}

/// Generate a master key from a passphrase/salt
pub fn derive_master_key(passphrase: &[u8], salt_bytes: &[u8], ops: usize, mem: usize) -> Result<SecretKey> {
    let len = xsalsa20poly1305::KEYBYTES;
    let salt: &[u8; argon2id13::SALTBYTES] = salt_bytes[0..argon2id13::SALTBYTES].try_into()
        .map_err(|_| Error::CryptoBadSalt)?;
    let mut key: Vec<u8> = vec![0; len];
    let salt_wrap = match argon2id13::Salt::from_slice(salt) {
        Some(x) => x,
        None => Err(Error::CryptoBadSalt)?,
    };
    match argon2id13::derive_key(key.as_mut_slice(), passphrase, &salt_wrap, argon2id13::OpsLimit(ops), argon2id13::MemLimit(mem)) {
        Ok(x) => {
            let rawkey = xsalsa20poly1305::Key::from_slice(x).ok_or(Error::CryptoKDFFailed)?;
            let seckey = SecretKey::Xsalsa20Poly1305(rawkey);
            Ok(seckey)
        }
        Err(()) => Err(Error::CryptoKDFFailed)?,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::util;

    pub(crate) fn secret_from_vec(bytes: Vec<u8>) -> SecretKey {
        SecretKey::Xsalsa20Poly1305(sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key::from_slice(bytes.as_ref()).unwrap())
    }

    #[test]
    fn secretkey_xsalsa20poly1305_enc_dec() {
        let key = SecretKey::new_xsalsa20poly1305();
        let val = String::from("get a job");
        let nonce = key.gen_nonce();
        let enc = key.seal(val.as_bytes(), &nonce).unwrap();
        let dec_bytes = key.open(&enc, &nonce).unwrap();
        let dec = String::from_utf8(dec_bytes).unwrap();
        assert_eq!(dec, String::from("get a job"));
    }

    #[test]
    fn secretkey_xsalsa20poly1305_from_slice() {
        let nonce: SecretKeyNonce = util::ser::deserialize(vec![129, 0, 196, 24, 33, 86, 38, 93, 180, 121, 32, 51, 21, 36, 74, 137, 32, 165, 2, 99, 111, 179, 32, 242, 56, 9, 254, 1].as_slice()).unwrap();
        let enc: Vec<u8> = vec![147, 142, 48, 155, 76, 177, 2, 169, 183, 176, 53, 157, 237, 55, 40, 216, 37, 197, 216, 146, 107, 162, 57, 58, 145, 103, 32, 78, 238, 30, 104, 186];
        let key = SecretKey::new_xsalsa20poly1305_from_slice(vec![120, 111, 109, 233, 7, 27, 205, 94, 55, 95, 248, 113, 138, 246, 244, 109, 147, 168, 117, 163, 48, 193, 100, 103, 43, 205, 212, 197, 110, 111, 105, 1].as_slice()).unwrap();
        let dec = key.open(enc.as_slice(), &nonce).unwrap();
        assert_eq!(dec.as_slice(), b"HI HUNGRY IM DAD");
    }

    #[test]
    fn signkeypair_ed25519_sign_verify() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let our_keypair = SignKeypair::new_ed25519(&master_key).unwrap();

        let msg_real = String::from("the old man leaned back in his chair, his face weathered by the ceaseless march of time, pondering his...");
        let msg_fake = String::from("the old man leaned back in his chair, his face weathered by the ceaseless march of NATUREFRESH MILK, pondering his...");
        let sig = our_keypair.sign(&master_key, msg_real.as_bytes()).unwrap();
        let verify_real = our_keypair.verify(&sig, msg_real.as_bytes());
        let verify_fake = our_keypair.verify(&sig, msg_fake.as_bytes());
        assert_eq!(verify_real, Ok(()));
        assert_eq!(verify_fake, Err(Error::CryptoSignatureVerificationFailed));
    }

    #[test]
    fn signkeypair_ed25519_seed_sign_verify() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let seed: [u8; 32] = vec![233, 229, 76, 13, 231, 38, 253, 27, 53, 2, 235, 174, 151, 186, 192, 33, 16, 2, 57, 32, 170, 23, 13, 47, 44, 234, 231, 35, 38, 107, 93, 198].try_into().unwrap();
        let our_keypair = SignKeypair::new_ed25519_from_seed(&master_key, &seed).unwrap();

        let msg_real = String::from("the old man leaned back in his chair, his face weathered by the ceaseless march of time, pondering his...");
        let msg_fake = String::from("the old man leaned back in his chair, his face weathered by the ceaseless march of NATUREFRESH MILK, pondering his...");
        let sig = our_keypair.sign(&master_key, msg_real.as_bytes()).unwrap();
        match sig {
            SignKeypairSignature::Ed25519(sig) => {
                let should_be: Vec<u8> = vec![161, 93, 247, 4, 187, 12, 160, 118, 111, 79, 16, 100, 205, 38, 238, 153, 217, 214, 230, 195, 175, 228, 165, 183, 5, 151, 159, 114, 7, 32, 156, 115, 34, 108, 194, 252, 86, 102, 133, 35, 129, 224, 146, 254, 91, 185, 97, 207, 0, 63, 241, 184, 144, 15, 20, 26, 187, 235, 95, 207, 43, 144, 216, 6];
                assert_eq!(sig.as_ref(), should_be.as_slice());
            }
        }
        let verify_real = our_keypair.verify(&sig, msg_real.as_bytes());
        let verify_fake = our_keypair.verify(&sig, msg_fake.as_bytes());
        assert_eq!(verify_real, Ok(()));
        assert_eq!(verify_fake, Err(Error::CryptoSignatureVerificationFailed));
    }

    #[test]
    fn signkeypair_ed25519_reencrypt() {
        let master_key1 = SecretKey::new_xsalsa20poly1305();
        let master_key2 = SecretKey::new_xsalsa20poly1305();
        assert!(master_key1 != master_key2);    // lazy, but ok
        let keypair = SignKeypair::new_ed25519(&master_key1).unwrap();
        let data = vec![1, 2, 3, 4, 5];
        let sig1 = keypair.sign(&master_key1, data.as_slice()).unwrap();
        let keypair = keypair.reencrypt(&master_key1, &master_key2).unwrap();
        let sig2 = keypair.sign(&master_key2, data.as_slice()).unwrap();
        assert_eq!(sig1, sig2);
        let res = keypair.clone().reencrypt(&master_key1, &master_key2);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
        let res = keypair.sign(&master_key1, data.as_slice());
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
    }

    #[test]
    fn signkeypair_ed25519_blank() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let keypair1 = SignKeypair::new_ed25519(&master_key).unwrap();
        let keypair2 = SignKeypair::new_ed25519(&master_key).unwrap();
        let blank1 = SignKeypairSignature::blank(&keypair1);
        let blank2 = SignKeypairSignature::blank(&keypair2);
        assert_eq!(blank1, blank2);
        assert_eq!(blank1.as_ref(), vec![0; ed25519::SIGNATUREBYTES].as_slice());
    }

    #[test]
    fn signkeypair_ed25519_strip_has_private() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        match &keypair {
            SignKeypair::Ed25519(_, Some(_)) => {
                assert!(keypair.has_private());
            }
            _ => panic!("private mismatch"),
        }
        let keypair_pub = keypair.strip_private();
        match &keypair_pub {
            SignKeypair::Ed25519(_, None) => {
                assert!(!keypair_pub.has_private());
            }
            _ => panic!("private mismatch"),
        }
    }

    #[test]
    fn signkeypair_ed25519_eq() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let keypair1 = SignKeypair::new_ed25519(&master_key).unwrap();
        let keypair2 = keypair1.clone();
        assert_eq!(keypair1, keypair2);
        let keypair3 = SignKeypair::new_ed25519(&master_key).unwrap();
        assert!(keypair1 != keypair3);
    }

    #[test]
    fn cryptokeypair_curve25519xsalsa20poly1305_anonymous_enc_dec() {
        let our_master_key = SecretKey::new_xsalsa20poly1305();
        let our_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&our_master_key).unwrap();
        let fake_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&our_master_key).unwrap();

        let message = String::from("HI JERRY I'M BUTCH");
        let sealed = our_keypair.seal_anonymous(message.as_bytes()).unwrap();
        let opened = our_keypair.open_anonymous(&our_master_key, &sealed).unwrap();

        assert_eq!(&opened[..], message.as_bytes());

        let opened2 = fake_keypair.open_anonymous(&our_master_key, &sealed);
        assert_eq!(opened2, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn cryptokeypair_curve25519xsalsa20poly1305_enc_dec() {
        let sender_master_key = SecretKey::new_xsalsa20poly1305();
        let sender_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&sender_master_key).unwrap();
        let recipient_master_key = SecretKey::new_xsalsa20poly1305();
        let recipient_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&recipient_master_key).unwrap();
        let fake_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&recipient_master_key).unwrap();

        let message = String::from("HI JERRY I'M BUTCH");
        let sealed = recipient_keypair.seal(&sender_master_key, &sender_keypair, message.as_bytes()).unwrap();
        let opened = recipient_keypair.open(&recipient_master_key, &sender_keypair, &sealed).unwrap();

        assert_eq!(&opened[..], message.as_bytes());

        let opened2 = sender_keypair.open(&sender_master_key, &fake_keypair, &sealed);
        assert_eq!(opened2, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn cryptokeypair_curve25519xsalsa20poly1305_reencrypt() {
        let master_key1 = SecretKey::new_xsalsa20poly1305();
        let master_key2 = SecretKey::new_xsalsa20poly1305();
        assert!(master_key1 != master_key2);
        let keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key1).unwrap();
        let message = String::from("get a job");
        let sealed = keypair.seal_anonymous(message.as_bytes()).unwrap();
        let keypair = keypair.reencrypt(&master_key1, &master_key2).unwrap();
        let opened = keypair.open_anonymous(&master_key2, &sealed).unwrap();
        assert_eq!(opened.as_slice(), message.as_bytes());
        let res = keypair.clone().reencrypt(&master_key1, &master_key2);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
        let res = keypair.open_anonymous(&master_key1, &sealed);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
    }

    #[test]
    fn cryptokeypair_curve25519xsalsa20poly1305_strip_has_private() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap();
        match &keypair {
            CryptoKeypair::Curve25519Xsalsa20Poly1305(_, Some(_)) => {
                assert!(keypair.has_private());
            }
            _ => panic!("private mismatch"),
        }
        let keypair_pub = keypair.strip_private();
        match &keypair_pub {
            CryptoKeypair::Curve25519Xsalsa20Poly1305(_, None) => {
                assert!(!keypair_pub.has_private());
            }
            _ => panic!("private mismatch"),
        }
    }

    #[test]
    fn derives_master_key() {
        let id = util::hash("my key".as_bytes()).unwrap();
        let salt = util::hash(id.as_ref()).unwrap();
        let master_key = derive_master_key("ZONING IS COMMUNISM".as_bytes(), &salt.as_ref(), argon2id13::OPSLIMIT_INTERACTIVE.0, argon2id13::MEMLIMIT_INTERACTIVE.0).unwrap();
        assert_eq!(master_key.as_ref(), &[148, 34, 57, 50, 168, 111, 176, 114, 120, 168, 159, 158, 96, 119, 14, 194, 52, 224, 58, 194, 77, 44, 168, 25, 54, 138, 172, 91, 164, 86, 190, 89]);
    }

    #[test]
    fn hmac_verify() {
        let data1 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and four children...if it's not too much trouble, maybe you could verify them as we...");
        let data2 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and seven children...if it's not too much trouble, maybe you could verify them as we...");
        let hmac_key1 = HmacKey::new_sha512();
        let hmac_key2 = HmacKey::new_sha512();
        let hmac = Hmac::new_sha512(&hmac_key1, data1.as_bytes()).unwrap();
        hmac.verify(&hmac_key1, data1.as_bytes()).unwrap();
        let res = hmac.verify(&hmac_key2, data1.as_bytes());
        assert_eq!(res, Err(Error::CryptoHmacVerificationFailed));
        let res = hmac.verify(&hmac_key1, data2.as_bytes());
        assert_eq!(res, Err(Error::CryptoHmacVerificationFailed));
        let res = hmac.verify(&hmac_key2, data2.as_bytes());
        assert_eq!(res, Err(Error::CryptoHmacVerificationFailed));
    }
}

