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
    private::{Private},
    util::{
        ser::TryFromSlice,
        sign::Signable,
    },
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

impl_try_from_slice!(ed25519::PublicKey);
impl_try_from_slice!(xsalsa20poly1305::Nonce);
impl_try_from_slice!(xsalsa20poly1305::Key);
impl_try_from_slice!(ed25519::Signature);
impl_try_from_slice!(curve25519xsalsa20poly1305::Nonce);
impl_try_from_slice!(curve25519xsalsa20poly1305::PublicKey);

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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SignKeypairSignature {
    #[serde(with = "crate::util::ser::human_binary_from_slice")]
    Ed25519(ed25519::Signature),
}

impl SignKeypairSignature {
    /// Convert this signature to hex
    pub fn to_hex(&self) -> String {
        match self {
            Self::Ed25519(ref x) => sodiumoxide::hex::encode(x),
        }
    }

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

    /// Return a copy of this keypair with only the public key attached.
    pub fn public_only(&self) -> Self {
        match self {
            Self::Ed25519(pubkey, _) => {
                Self::Ed25519(pubkey.clone(), None)
            }
        }
    }

    /// Convert this signing keypair into a signing public key.
    pub fn into_public(self) -> SignKeypairPublic {
        From::from(self)
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
    Curve25519Xsalsa20Poly1305(#[serde(with = "crate::util::ser::human_binary_from_slice")] curve25519xsalsa20poly1305::PublicKey, Option<Private<curve25519xsalsa20poly1305::SecretKey>>),
}

impl CryptoKeypair {
    /// Create a new keypair
    pub fn new_curve25519xsalsa20poly1305(master_key: &SecretKey) -> Result<Self> {
        let (public, secret) = curve25519xsalsa20poly1305::gen_keypair();
        Ok(Self::Curve25519Xsalsa20Poly1305(public, Some(Private::seal(master_key, &secret)?)))
    }

    /// Return a copy of this keypair with only the public key attached.
    pub fn public_only(&self) -> Self {
        match self {
            Self::Curve25519Xsalsa20Poly1305(ref pubkey, _) => {
                Self::Curve25519Xsalsa20Poly1305(pubkey.clone(), None)
            }
        }
    }

    /// Anonymously encrypt a message using the recipient's public key.
    pub fn seal_anonymous(their_pk: &CryptoKeypair, data: &[u8]) -> Result<Vec<u8>> {
        match their_pk {
            CryptoKeypair::Curve25519Xsalsa20Poly1305(ref pubkey, _) => {
                Ok(sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305::seal(data, pubkey))
            }
        }
    }

    /// Open an anonymous message encrypted with our public key. Requires our
    /// master key to open.
    pub fn open_anonymous(master_key: &SecretKey, our_keypair: &CryptoKeypair, data: &[u8]) -> Result<Vec<u8>> {
        match our_keypair {
            CryptoKeypair::Curve25519Xsalsa20Poly1305(ref pubkey, ref seckey_opt) => {
                let seckey_sealed = seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let seckey = seckey_sealed.open(master_key)?;
                sodiumoxide::crypto::sealedbox::curve25519blake2bxsalsa20poly1305::open(data, pubkey, &seckey)
                    .map_err(|_| Error::CryptoOpenFailed)
            }
        }
    }

    /// Encrypt a message to a recipient, and sign it with our secret crypto
    /// key. Needs our master key to unlock our heroic private key.
    pub fn seal(our_master_key: &SecretKey, our_keypair: &CryptoKeypair, their_keypair: &CryptoKeypair, data: &[u8]) -> Result<CryptoKeypairMessage> {
        match (our_keypair, their_keypair) {
            (CryptoKeypair::Curve25519Xsalsa20Poly1305(_, ref our_seckey_opt), CryptoKeypair::Curve25519Xsalsa20Poly1305(ref their_pubkey, _)) => {
                let our_seckey_sealed = our_seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let our_seckey = our_seckey_sealed.open(our_master_key)?;
                let nonce_raw = curve25519xsalsa20poly1305::gen_nonce();
                let msg = curve25519xsalsa20poly1305::seal(data, &nonce_raw, &their_pubkey, &our_seckey);
                let nonce = CryptoKeypairNonce::Curve25519Xsalsa20Poly1305(nonce_raw);
                Ok(CryptoKeypairMessage::new(nonce, msg))
            }
        }
    }

    /// Open a message encrypted with our public key and verify the sender of
    /// the message using their public key. Needs our master key to unlock the
    /// private key used to decrypt the message.
    pub fn open(our_master_key: &SecretKey, our_keypair: &CryptoKeypair, their_keypair: &CryptoKeypair, message: &CryptoKeypairMessage) -> Result<Vec<u8>> {
        match (our_keypair, their_keypair) {
            (CryptoKeypair::Curve25519Xsalsa20Poly1305(_, ref our_seckey_opt), CryptoKeypair::Curve25519Xsalsa20Poly1305(ref their_pubkey, _)) => {
                let our_seckey_sealed = our_seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let our_seckey = our_seckey_sealed.open(our_master_key)?;
                let nonce = message.nonce();
                let nonce_raw = match nonce {
                    CryptoKeypairNonce::Curve25519Xsalsa20Poly1305(ref x) => x,
                };
                curve25519xsalsa20poly1305::open(message.ciphertext(), nonce_raw, &their_pubkey, &our_seckey)
                    .map_err(|_| Error::CryptoOpenFailed)
            }
        }
    }
}


/// Generate a master key from a passphrase/salt
pub fn derive_master_key(passphrase: &[u8], salt: &[u8; argon2id13::SALTBYTES], ops: argon2id13::OpsLimit, mem: argon2id13::MemLimit) -> Result<SecretKey> {
    let len = xsalsa20poly1305::KEYBYTES;
    let mut key: Vec<u8> = vec![0; len];
    let salt_wrap = match argon2id13::Salt::from_slice(salt) {
        Some(x) => x,
        None => Err(Error::CryptoBadSalt)?,
    };
    match argon2id13::derive_key(key.as_mut_slice(), passphrase, &salt_wrap, ops, mem) {
        Ok(x) => {
            let rawkey = xsalsa20poly1305::Key::from_slice(x).ok_or(Error::CryptoKDFFailed)?;
            let seckey = SecretKey::Xsalsa20Poly1305(rawkey);
            Ok(seckey)
        }
        Err(()) => Err(Error::CryptoKDFFailed)?,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util;
    use std::convert::TryInto;

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
    fn cryptokeypair_curve25519xsalsa20poly1305_anonymous_enc_dec() {
        let our_master_key = SecretKey::new_xsalsa20poly1305();
        let our_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&our_master_key).unwrap();
        let fake_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&our_master_key).unwrap();

        let message = String::from("HI JERRY I'M BUTCH");
        let sealed = CryptoKeypair::seal_anonymous(&our_keypair, message.as_bytes()).unwrap();
        let opened = CryptoKeypair::open_anonymous(&our_master_key, &our_keypair, &sealed).unwrap();

        assert_eq!(&opened[..], message.as_bytes());

        let opened2 = CryptoKeypair::open_anonymous(&our_master_key, &fake_keypair, &sealed);
        assert_eq!(opened2, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn cryptokeypair_curve25519xsalsa20poly1305_enc_dec() {
        let our_master_key = SecretKey::new_xsalsa20poly1305();
        let our_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&our_master_key).unwrap();
        let their_master_key = SecretKey::new_xsalsa20poly1305();
        let their_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&their_master_key).unwrap();
        let fake_keypair = CryptoKeypair::new_curve25519xsalsa20poly1305(&their_master_key).unwrap();

        let message = String::from("HI JERRY I'M BUTCH");
        let sealed = CryptoKeypair::seal(&our_master_key, &our_keypair, &their_keypair, message.as_bytes()).unwrap();
        let opened = CryptoKeypair::open(&our_master_key, &our_keypair, &their_keypair, &sealed).unwrap();

        assert_eq!(&opened[..], message.as_bytes());

        let opened2 = CryptoKeypair::open(&our_master_key, &our_keypair, &fake_keypair, &sealed);
        assert_eq!(opened2, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn derives_master_key() {
        let id = util::hash("my key".as_bytes()).unwrap();
        let salt = util::hash(id.as_ref()).unwrap();
        let saltbytes: [u8; argon2id13::SALTBYTES] = salt.as_ref()[0..argon2id13::SALTBYTES].try_into().unwrap();
        let master_key = derive_master_key("ZONING IS COMMUNISM".as_bytes(), &saltbytes, argon2id13::OPSLIMIT_INTERACTIVE, argon2id13::MEMLIMIT_INTERACTIVE).unwrap();
        assert_eq!(master_key.as_ref(), &[148, 34, 57, 50, 168, 111, 176, 114, 120, 168, 159, 158, 96, 119, 14, 194, 52, 224, 58, 194, 77, 44, 168, 25, 54, 138, 172, 91, 164, 86, 190, 89]);
    }

    #[test]
    fn blank_signature() {
        let master_key = SecretKey::new_xsalsa20poly1305();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let blank = SignKeypairSignature::blank(&sign_keypair);
        assert_eq!(blank.as_ref(), vec![0; ed25519::SIGNATUREBYTES].as_slice());
    }
}

