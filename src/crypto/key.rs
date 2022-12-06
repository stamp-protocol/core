//! The key model wraps a set of algorithms for encryption and decryption (both.expose_secret()
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

use blake2::{Digest, digest::{FixedOutput, Mac as DigestMac, crypto_common::generic_array::GenericArray}};
use chacha20poly1305::aead::{self, Aead, NewAead};
use crate::{
    error::{Error, Result},
    private::Private,
    util::{
        Public,

        ser::{
            self,
            Binary, BinarySecret, BinaryVec,
        },
        sign::Signable,
    },
};
use ed25519_consensus;
use rand::{RngCore, rngs::OsRng};
use rand_chacha::rand_core::{RngCore as RngCoreChaCha, SeedableRng};
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;

/// A constant that provides a default for CPU difficulty for interactive key derivation
pub const KDF_OPS_INTERACTIVE: u32 = 2;
/// A constant that provides a default for mem difficulty for interactive key derivation
pub const KDF_MEM_INTERACTIVE: u32 = 65536;

/// A constant that provides a default for CPU difficulty for moderate key derivation
pub const KDF_OPS_MODERATE: u32 = 3;
/// A constant that provides a default for mem difficulty for moderate key derivation
pub const KDF_MEM_MODERATE: u32 = 262144;

/// A constant that provides a default for CPU difficulty for sensitive key derivation
pub const KDF_OPS_SENSITIVE: u32 = 4;
/// A constant that provides a default for mem difficulty for sensitive key derivation
pub const KDF_MEM_SENSITIVE: u32 = 1048576;

/// A value that lets us reference keys by a unique identifier (pubkey for asymc keypairs
/// and MAC for secret keys).
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum KeyID {
    #[rasn(tag(explicit(0)))]
    SignKeypair(SignKeypairPublic),
    #[rasn(tag(explicit(1)))]
    CryptoKeypair(CryptoKeypairPublic),
    #[rasn(tag(explicit(2)))]
    SecretKey(Mac),
}

impl KeyID {
    pub fn as_string(&self) -> String {
        match self {
            Self::SignKeypair(SignKeypairPublic::Ed25519(pubkey)) => {
                ser::base64_encode(pubkey.as_ref())
            }
            Self::CryptoKeypair(CryptoKeypairPublic::Curve25519XChaCha20Poly1305(pubkey)) => {
                ser::base64_encode(pubkey.as_ref())
            }
            Self::SecretKey(mac) => {
                ser::base64_encode(mac.deref())
            }
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_sign() -> Self {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        Self::SignKeypair(SignKeypair::new_ed25519(&master_key).unwrap().into())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_crypto() -> Self {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        Self::CryptoKeypair(CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap().into())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn random_secret() -> Self {
        Self::SecretKey(Mac::new_blake2b(&MacKey::new_blake2b().unwrap(), b"get a job").unwrap())
    }
}

impl std::fmt::Display for KeyID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

/// A symmetric encryption key nonce
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum SecretKeyNonce {
    #[rasn(tag(0))]
    XChaCha20Poly1305(Binary<24>),
}

/// A symmetric encryption key
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum SecretKey {
    #[rasn(tag(0))]
    XChaCha20Poly1305(BinarySecret<32>),
}

impl SecretKey {
    /// Create a new xchacha20poly1305 key
    pub fn new_xchacha20poly1305() -> Result<Self> {
        let mut randbuf = [0u8; 32];
        OsRng.fill_bytes(&mut randbuf);
        Ok(Self::XChaCha20Poly1305(BinarySecret::new(randbuf)))
    }

    /// Try to create a SecretKey from a byte slice
    pub fn new_xchacha20poly1305_from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes.try_into()
            .map_err(|_| Error::BadLength)?;
        Ok(Self::XChaCha20Poly1305(BinarySecret::new(arr)))
    }

    /// Create a nonce for use with this secret key
    pub fn gen_nonce(&self) -> Result<SecretKeyNonce> {
        match self {
            SecretKey::XChaCha20Poly1305(_) => {
                let mut randbuf = [0u8; 24];
                OsRng.fill_bytes(&mut randbuf);
                Ok(SecretKeyNonce::XChaCha20Poly1305(Binary::new(randbuf)))
            }
        }
    }

    /// Encrypt a value with a secret key/nonce
    pub fn seal<'a>(&'a self, data: &[u8], nonce: &SecretKeyNonce) -> Result<Vec<u8>> {
        match (self, nonce) {
            (SecretKey::XChaCha20Poly1305(ref key), SecretKeyNonce::XChaCha20Poly1305(ref nonce)) => {
                let secret: &'a [u8; 32] = key.expose_secret();
                //let chachakey: &'a chacha20poly1305::Key = secret.into();
                let cipher = chacha20poly1305::XChaCha20Poly1305::new(secret.into());
                let enc = cipher.encrypt(chacha20poly1305::XNonce::from_slice(nonce.deref().as_slice()), data).map_err(|_| Error::CryptoSealFailed)?;
                Ok(enc)
            }
        }
    }

    /// Decrypt a value with a secret key/nonce
    pub fn open(&self, data: &[u8], nonce: &SecretKeyNonce) -> Result<Vec<u8>> {
        match (self, nonce) {
            (SecretKey::XChaCha20Poly1305(ref key), SecretKeyNonce::XChaCha20Poly1305(ref nonce)) => {
                let cipher = chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.expose_secret().as_slice().clone()));
                let dec = cipher.decrypt(chacha20poly1305::XNonce::from_slice(nonce.as_slice()), data).map_err(|_| Error::CryptoOpenFailed)?;
                Ok(dec)
            }
        }
    }

    /// Get the raw bytes for this key
    pub fn as_ref(&self) -> &[u8] {
        match self {
            SecretKey::XChaCha20Poly1305(ref key) => key.expose_secret().as_ref(),
        }
    }
}

#[cfg(test)]
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SecretKey::XChaCha20Poly1305(inner1), SecretKey::XChaCha20Poly1305(inner2)) => {
                inner1.expose_secret() == inner2.expose_secret()
            }
        }
    }
}

/// A signature derived from a signing keypair.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum SignKeypairSignature {
    #[rasn(tag(explicit(0)))]
    Ed25519(Binary<64>),
}

impl AsRef<[u8]> for SignKeypairSignature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519(sig) => sig.as_ref(),
        }
    }
}

/// An asymmetric signing keypair.
#[derive(Debug, Serialize, Deserialize, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum SignKeypair {
    /// Ed25519 signing keypair
    #[rasn(tag(explicit(0)))]
    Ed25519 {
        #[rasn(tag(explicit(0)))]
        public: Binary<32>,
        #[rasn(tag(explicit(1)))]
        secret: Option<Private<BinarySecret<32>>>,
    }
}

impl Clone for SignKeypair {
    fn clone(&self) -> Self {
        match self {
            SignKeypair::Ed25519 { public, secret: secret_maybe } => {
                SignKeypair::Ed25519 {
                    public: public.clone(),
                    secret: secret_maybe.as_ref().map(|x| x.clone()),
                }
            }
        }
    }
}

impl SignKeypair {
    fn new_ed25519_from_secret(master_key: &SecretKey, secret: ed25519_consensus::SigningKey) -> Result<Self> {
        let public = secret.verification_key();
        Ok(Self::Ed25519 { 
            public: Binary::new(public.to_bytes()),
            secret: Some(Private::seal(master_key, &BinarySecret::new(secret.to_bytes()))?),
        })
    }

    /// Create a new ed25519 keypair
    pub fn new_ed25519(master_key: &SecretKey) -> Result<Self> {
        let mut randbuf = [0u8; 32];
        OsRng.fill_bytes(&mut randbuf);
        let secret = ed25519_consensus::SigningKey::from(randbuf);
        Self::new_ed25519_from_secret(master_key, secret)
    }

    /// Create a new ed25519 keypair from a cryptographic seed
    pub fn new_ed25519_from_seed(master_key: &SecretKey, seed_bytes: &[u8; 32]) -> Result<Self> {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed_bytes);
        let mut randbuf = [0u8; 32];
        rng.fill_bytes(&mut randbuf);
        let secret = ed25519_consensus::SigningKey::from(randbuf);
        Self::new_ed25519_from_secret(master_key, secret)
    }

    /// Hash a value then sign it, returning the hash and the signature. This is
    /// already how signing works, but we basically control the hash process
    /// ourselves so we can return the hash.
    pub fn sign(&self, master_key: &SecretKey, data: &[u8]) -> Result<SignKeypairSignature> {
        match self {
            Self::Ed25519 { secret: ref sec_locked_opt, .. } => {
                let sec_locked = sec_locked_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let sec_bytes: [u8; 32] = sec_locked.open(master_key)?.expose_secret().clone();
                let seckey = ed25519_consensus::SigningKey::from(sec_bytes);
                let sig_obj = seckey.sign(data);
                let sig = SignKeypairSignature::Ed25519(Binary::new(sig_obj.to_bytes()));
                Ok(sig)
            }
        }
    }

    /// Verify a value with a detached signature given the public key of the
    /// signer.
    pub fn verify(&self, signature: &SignKeypairSignature, data: &[u8]) -> Result<()> {
        match (self, signature) {
            (Self::Ed25519 { public: ref pubkey_bytes, .. }, SignKeypairSignature::Ed25519(ref sig_bytes)) => {
                let pubkey = ed25519_consensus::VerificationKey::try_from(pubkey_bytes.deref().clone())
                    .map_err(|_| Error::CryptoSignatureVerificationFailed)?;
                let sig_arr: [u8; 64] = sig_bytes.deref().clone();
                let sig = ed25519_consensus::Signature::from(sig_arr);
                pubkey.verify(&sig, data)
                    .map_err(|_| Error::CryptoSignatureVerificationFailed)?;
                Ok(())
            }
        }
    }

    /// Re-encrypt this signing keypair with a new master key.
    pub fn reencrypt(self, previous_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        match self {
            Self::Ed25519 { public, secret: Some(private) } => {
                Ok(Self::Ed25519 { public, secret: Some(private.reencrypt(previous_master_key, new_master_key)?) })
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
            Self::Ed25519 { public: pubkey, .. } => {
                Self::Ed25519 { public: pubkey.clone(), secret: None }
            }
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::Ed25519 { secret: private_maybe, .. } => private_maybe.is_some(),
        }
    }
}

impl PartialEq for SignKeypair {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ed25519 { public: public1, .. }, Self::Ed25519 { public: public2, .. }) => public1 == public2,
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
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum SignKeypairPublic {
    /// Ed25519 signing public key
    #[rasn(tag(explicit(0)))]
    Ed25519(Binary<32>),
}

impl SignKeypairPublic {
    /// Verify a value with a detached signature given the public key of the
    /// signer.
    pub fn verify(&self, signature: &SignKeypairSignature, data: &[u8]) -> Result<()> {
        // this clone()s, but at least we aren't duplicating code anymore
        let keypair = match self {
            SignKeypairPublic::Ed25519(pubkey) => {
                SignKeypair::Ed25519 { public: pubkey.clone(), secret: None }
            }
        };
        keypair.verify(signature, data)
    }

    /// Create a KeyID from this keypair.
    pub fn key_id(&self) -> KeyID {
        KeyID::SignKeypair(self.clone())
    }

    /// Serialize this public key
    pub fn serialize(&self) -> Result<Vec<u8>> {
        ser::serialize(self)
    }

    /// Deserialize into a public key
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        ser::deserialize(bytes)
    }
}

impl From<SignKeypair> for SignKeypairPublic {
    fn from(kp: SignKeypair) -> Self {
        match kp {
            SignKeypair::Ed25519 { public, .. } => Self::Ed25519(public),
        }
    }
}

/// An asymmetric signing keypair nonce.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum CryptoKeypairNonce {
    /// Nonce for Curve25519XChaCha20Poly1305
    #[rasn(tag(explicit(0)))]
    Curve25519XChaCha20Poly1305(Binary<24>),
}

/// A message we encrypt with their pubkey that's signed with our seckey. Meant
/// for non-anonymous, authenticated messaging.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct CryptoKeypairMessage {
    /// Our heroic nonce
    #[rasn(tag(explicit(0)))]
    nonce: CryptoKeypairNonce,
    /// The message ciphertext
    #[rasn(tag(explicit(1)))]
    ciphertext: BinaryVec,
}

impl CryptoKeypairMessage {
    /// Create a new message
    fn new(nonce: CryptoKeypairNonce, ciphertext: Vec<u8>) -> Self {
        Self {
            nonce,
            ciphertext: BinaryVec::from(ciphertext),
        }
    }
}

/// An asymmetric signing keypair.
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum CryptoKeypair {
    /// Curve25519XChaCha20Poly1305 keypair for encryption/decryption
    #[rasn(tag(explicit(0)))]
    Curve25519XChaCha20Poly1305 {
        #[rasn(tag(explicit(0)))]
        public: Binary<32>,
        #[rasn(tag(explicit(1)))]
        secret: Option<Private<BinarySecret<32>>>,
    },
}

impl Clone for CryptoKeypair {
    fn clone(&self) -> Self {
        match self {
            CryptoKeypair::Curve25519XChaCha20Poly1305 { public, secret: secret_maybe } => {
                CryptoKeypair::Curve25519XChaCha20Poly1305 {
                    public: public.clone(),
                    secret: secret_maybe.as_ref().map(|x| x.clone()),
                }
            }
        }
    }
}

impl CryptoKeypair {
    /// Create a new keypair
    pub fn new_curve25519xchacha20poly1305(master_key: &SecretKey) -> Result<Self> {
        let mut rng = OsRng {};
        let secret = crypto_box::SecretKey::generate(&mut rng);
        let public = secret.public_key();
        Ok(Self::Curve25519XChaCha20Poly1305 {
            public: Binary::new(public.as_bytes().clone()),
            secret: Some(Private::seal(master_key, &BinarySecret::new(secret.as_bytes().clone()))?),
        })
    }

    /// Anonymously encrypt a message using the recipient's public key.
    pub fn seal_anonymous(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Curve25519XChaCha20Poly1305 { public: ref pubkey, .. } => {
                let mut rng = OsRng {};
                let ephemeral_secret = crypto_box::SecretKey::generate(&mut rng);
                let ephemeral_pubkey = ephemeral_secret.public_key();
                let cardboard_box = crypto_box::ChaChaBox::new(&crypto_box::PublicKey::from(pubkey.deref().clone()), &ephemeral_secret);
                let mut blake = blake2::Blake2b512::new();
                blake.update(ephemeral_pubkey.as_ref());
                blake.update(pubkey.as_ref());
                let nonce_vec = Vec::from(blake.finalize().as_slice());
                let nonce_arr: [u8; 24] = nonce_vec[0..24].try_into()
                    .map_err(|_| Error::CryptoSealFailed)?;
                let nonce = nonce_arr.into();
                let mut enc = cardboard_box.encrypt(&nonce, aead::Payload::from(data))
                    .map_err(|_| Error::CryptoSealFailed)?;
                let mut pubvec = Vec::from(ephemeral_pubkey.as_ref());
                pubvec.append(&mut enc);
                Ok(pubvec)
            }
        }
    }

    /// Open an anonymous message encrypted with our public key. Requires our
    /// master key to open.
    pub fn open_anonymous(&self, master_key: &SecretKey, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Curve25519XChaCha20Poly1305 { public: ref pubkey, secret: ref seckey_opt } => {
                let seckey_sealed = seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let seckey = crypto_box::SecretKey::from(seckey_sealed.open(master_key)?.expose_secret().deref().clone());
                let ephemeral_pubkey_slice = &data[0..32];
                let ephemeral_pubkey_arr: [u8; 32] = ephemeral_pubkey_slice.try_into()
                    .map_err(|_| Error::CryptoOpenFailed)?;
                let ephemeral_pubkey = crypto_box::PublicKey::from(ephemeral_pubkey_arr);
                let ciphertext = &data[32..];
                let cardboard_box = crypto_box::ChaChaBox::new(&ephemeral_pubkey, &seckey);
                let mut blake = blake2::Blake2b512::new();
                blake.update(ephemeral_pubkey.as_ref());
                blake.update(pubkey.as_ref());
                let nonce_vec = Vec::from(blake.finalize().as_slice());
                let nonce_arr: [u8; 24] = nonce_vec[0..24].try_into()
                    .map_err(|_| Error::CryptoSealFailed)?;
                let nonce = nonce_arr.into();
                cardboard_box.decrypt(&nonce, aead::Payload::from(ciphertext))
                    .map_err(|_| Error::CryptoOpenFailed)
            }
        }
    }

    /// Encrypt a message to a recipient, and sign it with our secret crypto
    /// key. Needs our master key to unlock our heroic private key.
    pub fn seal(&self, sender_master_key: &SecretKey, sender_keypair: &CryptoKeypair, data: &[u8]) -> Result<CryptoKeypairMessage> {
        match (sender_keypair, self) {
            (Self::Curve25519XChaCha20Poly1305 { secret: ref sender_seckey_opt, .. }, Self::Curve25519XChaCha20Poly1305 { public: ref recipient_pubkey, .. }) => {
                let sender_seckey_sealed = sender_seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let sender_seckey = crypto_box::SecretKey::from(sender_seckey_sealed.open(sender_master_key)?.expose_secret().deref().clone());
                let recipient_chacha_pubkey = crypto_box::PublicKey::from(recipient_pubkey.deref().clone());
                let cardboard_box = crypto_box::ChaChaBox::new(&recipient_chacha_pubkey, &sender_seckey);
                let mut rng = OsRng {};
                let nonce = crypto_box::generate_nonce(&mut rng);
                let msg = cardboard_box.encrypt(&nonce, aead::Payload::from(data))
                    .map_err(|_| Error::CryptoSealFailed)?;
                let nonce_arr = nonce.as_slice().clone().try_into()
                    .map_err(|_| Error::BadLength)?;
                Ok(CryptoKeypairMessage::new(CryptoKeypairNonce::Curve25519XChaCha20Poly1305(Binary::new(nonce_arr)), msg))
            }
        }
    }

    /// Open a message encrypted with our public key and verify the sender of
    /// the message using their public key. Needs our master key to unlock the
    /// private key used to decrypt the message.
    pub fn open(&self, recipient_master_key: &SecretKey, sender_keypair: &CryptoKeypair, message: &CryptoKeypairMessage) -> Result<Vec<u8>> {
        match (self, sender_keypair) {
            (Self::Curve25519XChaCha20Poly1305 { secret: ref recipient_seckey_opt, .. }, CryptoKeypair::Curve25519XChaCha20Poly1305 { public: ref sender_pubkey, .. }) => {
                let recipient_seckey_sealed = recipient_seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let recipient_seckey = crypto_box::SecretKey::from(recipient_seckey_sealed.open(recipient_master_key)?.expose_secret().deref().clone());
                let nonce = match message.nonce() {
                    CryptoKeypairNonce::Curve25519XChaCha20Poly1305(vec) => {
                        GenericArray::from_slice(vec.as_slice())
                    }
                };
                let sender_chacha_pubkey = crypto_box::PublicKey::from(sender_pubkey.deref().clone());
                let cardboard_box = crypto_box::ChaChaBox::new(&sender_chacha_pubkey, &recipient_seckey);
                cardboard_box.decrypt(&nonce, aead::Payload::from(message.ciphertext().as_slice()))
                    .map_err(|_| Error::CryptoOpenFailed)
            }
        }
    }

    /// Re-encrypt this signing keypair with a new master key.
    pub fn reencrypt(self, previous_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        match self {
            Self::Curve25519XChaCha20Poly1305 { public, secret: Some(private) } => {
                Ok(Self::Curve25519XChaCha20Poly1305 { public, secret: Some(private.reencrypt(previous_master_key, new_master_key)?) })
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
            Self::Curve25519XChaCha20Poly1305 { public: ref pubkey, .. } => {
                Self::Curve25519XChaCha20Poly1305 { public: pubkey.clone(), secret: None }
            }
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::Curve25519XChaCha20Poly1305 { secret: private_maybe, .. } => private_maybe.is_some(),
        }
    }
}

/// An asymmetric signing public key.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum CryptoKeypairPublic {
    /// Public key for Curve25519XChaCha20Poly1305
    #[rasn(tag(explicit(0)))]
    Curve25519XChaCha20Poly1305(Binary<32>),
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
            CryptoKeypair::Curve25519XChaCha20Poly1305 { public, .. } => Self::Curve25519XChaCha20Poly1305(public),
        }
    }
}

/// A cryptographic hash. By defining this as an enum, we allow expansion of
/// hash algorithms in the future.
///
/// When stringified, the hash is in the format `base64([<hash bytes>|<u8 tag>])`
/// where the `tag` is the specific hash algorithm we use. This allows the hash
/// to shine on its own without the tag getting inthe way. Yes, it's vain.
#[derive(Clone, Debug, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Hash {
    /// Blake2b hash
    #[rasn(tag(explicit(0)))]
    Blake2b(Binary<64>),
}

impl Hash {
    /// Create a new blake2b hash from a message
    pub fn new_blake2b(message: &[u8]) -> Result<Self> {
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(message);
        let genarr = hasher.finalize();
        let arr: [u8; 64] = genarr.as_slice().try_into()
            .map_err(|_| Error::BadLength)?;
        Ok(Self::Blake2b(Binary::new(arr)))
    }

    #[cfg(test)]
    pub(crate) fn random_blake2b() -> Self {
        let mut randbuf = [0u8; 64];
        OsRng.fill_bytes(&mut randbuf);
        Self::Blake2b(Binary::new(randbuf))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Blake2b(bin) => bin.deref(),
        }
    }
}

impl TryFrom<&Hash> for String {
    type Error = Error;

    fn try_from(hash: &Hash) -> std::result::Result<Self, Self::Error> {
        fn bin_with_tag<const N: usize>(bin: &Binary<N>, tag: u8) -> Vec<u8> {
            let mut vec = Vec::from(bin.deref().as_slice());
            vec.push(tag);
            vec
        }
        let enc = match hash {
            Hash::Blake2b(bin) => {
                bin_with_tag(bin, 0)
            }
        };
        Ok(ser::base64_encode(&enc[..]))
    }
}

impl TryFrom<&str> for Hash {
    type Error = Error;

    fn try_from(string: &str) -> std::result::Result<Self, Self::Error> {
        let dec = ser::base64_decode(string)?;
        let tag = dec[dec.len() - 1];
        let bytes = &dec[0..dec.len() - 1];
        let hash = match tag {
            0 => {
                let arr: [u8; 64] = bytes.try_into()
                    .map_err(|_| Error::BadLength)?;
                Self::Blake2b(Binary::new(arr))
            },
            _ => Err(Error::CryptoAlgoMismatch)?,
        };
        Ok(hash)
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::try_from(self).map_err(|_| std::fmt::Error)?)
    }
}

/// A key for deriving a MAC
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum MacKey {
    /// Blake2b MAC key
    #[rasn(tag(explicit(0)))]
    Blake2b(BinarySecret<64>),
}

impl MacKey {
    /// Create a new blacke2b MAC key
    pub fn new_blake2b() -> Result<Self> {
        let mut randbuf = [0u8; 64];
        OsRng.fill_bytes(&mut randbuf);
        Ok(Self::Blake2b(BinarySecret::new(randbuf)))
    }

    /// Create a new blake2b MAC key from a byte array
    pub fn new_blake2b_from_bytes(keybytes: [u8; 64]) -> Self {
        Self::Blake2b(BinarySecret::new(keybytes))
    }
}

/// A MAC
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Mac {
    /// Blake2b MAC
    #[rasn(tag(explicit(0)))]
    Blake2b(Binary<64>),
}

impl Deref for Mac {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Mac::Blake2b(bytes) => &(bytes.deref())[..],
        }
    }
}

impl Mac {
    /// Create a new MAC-blake2b from a key and a set of data.
    pub fn new_blake2b(mac_key: &MacKey, data: &[u8]) -> Result<Self> {
        match mac_key {
            MacKey::Blake2b(mac_key) => {
                let mut mac = blake2::Blake2bMac512::new_with_salt_and_personal(mac_key.expose_secret().as_slice(), &[], b"stamp-protocol")
                    .map_err(|_| Error::CryptoBadKey)?;
                mac.update(data);
                let arr: [u8; 64] = mac.finalize_fixed().as_slice().try_into()
                    .map_err(|_| Error::BadLength)?;
                Ok(Mac::Blake2b(Binary::new(arr)))
            }
        }
    }

    /// Verify a MAC against a set of data.
    pub fn verify(&self, mac_key: &MacKey, data: &[u8]) -> Result<()> {
        match (self, mac_key) {
            (Self::Blake2b(mac), MacKey::Blake2b(mac_key)) => {
                let mut mac_ver = blake2::Blake2bMac512::new_with_salt_and_personal(mac_key.expose_secret().as_slice(), &[], b"stamp-protocol")
                    .map_err(|_| Error::CryptoBadKey)?;
                mac_ver.update(data);
                let arr: [u8; 64] = mac_ver.finalize_fixed().as_slice().try_into()
                    .map_err(|_| Error::BadLength)?;
                if mac != &Binary::new(arr) {
                    // the data has been tampered with, my friend.
                    Err(Error::CryptoMacVerificationFailed)?;
                }
            }
        }
        Ok(())
    }
}

/// Generate a secret key from a passphrase/salt
pub fn derive_secret_key(passphrase: &[u8], salt_bytes: &[u8], ops: u32, mem: u32) -> Result<SecretKey> {
    const LEN: usize = 32;
    let salt: &[u8; 16] = salt_bytes[0..16].try_into()
        .map_err(|_| Error::CryptoBadSalt)?;
    let mut key = [0u8; 32];
    let argon2_ctx = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(mem, ops, 1, Some(LEN)).map_err(|_| Error::CryptoKDFFailed)?
    );
    argon2_ctx.hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| Error::CryptoKDFFailed)?;
    Ok(SecretKey::XChaCha20Poly1305(BinarySecret::new(key)))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn secretkey_xchacha20poly1305_enc_dec() {
        let key = SecretKey::new_xchacha20poly1305().unwrap();
        let val = String::from("get a job");
        let nonce = key.gen_nonce().unwrap();
        let enc = key.seal(val.as_bytes(), &nonce).unwrap();
        let dec_bytes = key.open(&enc, &nonce).unwrap();
        let dec = String::from_utf8(dec_bytes).unwrap();
        assert_eq!(dec, String::from("get a job"));
    }

    #[test]
    fn secretkey_xchacha20poly1305_from_slice() {
        let nonce = SecretKeyNonce::XChaCha20Poly1305(Binary::new([33, 86, 38, 93, 180, 121, 32, 51, 21, 36, 74, 137, 32, 165, 2, 99, 111, 179, 32, 242, 56, 9, 254, 1]));
        let enc: Vec<u8> = vec![8, 175, 83, 132, 142, 229, 0, 29, 187, 23, 223, 152, 164, 120, 206, 13, 240, 105, 184, 47, 228, 239, 34, 85, 79, 242, 230, 150, 186, 203, 156, 26];
        let key = SecretKey::new_xchacha20poly1305_from_slice(vec![120, 111, 109, 233, 7, 27, 205, 94, 55, 95, 248, 113, 138, 246, 244, 109, 147, 168, 117, 163, 48, 193, 100, 103, 43, 205, 212, 197, 110, 111, 105, 1].as_slice()).unwrap();
        let dec = key.open(enc.as_slice(), &nonce).unwrap();
        assert_eq!(dec.as_slice(), b"HI HUNGRY IM DAD");
    }

    #[test]
    fn signkeypair_ed25519_sign_verify() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
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
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let seed: [u8; 32] = vec![233, 229, 76, 13, 231, 38, 253, 27, 53, 2, 235, 174, 151, 186, 192, 33, 16, 2, 57, 32, 170, 23, 13, 47, 44, 234, 231, 35, 38, 107, 93, 198].try_into().unwrap();
        let our_keypair = SignKeypair::new_ed25519_from_seed(&master_key, &seed).unwrap();

        let msg_real = String::from("the old man leaned back in his chair, his face weathered by the ceaseless march of time, pondering his...");
        let msg_fake = String::from("the old man leaned back in his chair, his face weathered by the ceaseless march of NATUREFRESH MILK, pondering his...");
        let sig = our_keypair.sign(&master_key, msg_real.as_bytes()).unwrap();
        match sig {
            SignKeypairSignature::Ed25519(ref sig) => {
                let should_be: Vec<u8> = vec![81, 54, 50, 92, 69, 78, 205, 207, 10, 242, 222, 154, 70, 18, 242, 16, 67, 142, 59, 63, 41, 129, 98, 223, 161, 173, 210, 23, 78, 208, 43, 79, 130, 225, 189, 179, 88, 103, 74, 71, 116, 212, 6, 207, 194, 212, 25, 107, 56, 91, 185, 214, 146, 78, 185, 212, 90, 22, 99, 77, 193, 231, 239, 5];
                assert_eq!(sig.as_ref(), should_be.as_slice());
            }
        }
        let verify_real = our_keypair.verify(&sig, msg_real.as_bytes());
        let verify_fake = our_keypair.verify(&sig, msg_fake.as_bytes());
        assert_eq!(verify_real, Ok(()));
        assert_eq!(verify_fake, Err(Error::CryptoSignatureVerificationFailed));
    }

    #[test]
    fn signkeypair_ed25519_seckey_sign_verify() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let seed: [u8; 32] = vec![111, 229, 76, 13, 231, 38, 253, 27, 53, 2, 235, 174, 151, 186, 192, 33, 16, 2, 57, 32, 170, 23, 13, 47, 44, 234, 231, 35, 38, 107, 93, 198].try_into().unwrap();
        let seckey = SecretKey::new_xchacha20poly1305_from_slice(&seed[..]).expect("bad seed");
        let bytes: &[u8] = seckey.as_ref();
        let seed: [u8; 32] = bytes[0..32].try_into().unwrap();
        let our_keypair = SignKeypair::new_ed25519_from_seed(&master_key, &seed).unwrap();

        let msg_real = String::from("the old man leaned back in his chair, his face weathered by the ceaseless march of time, pondering his...");
        let msg_fake = String::from("the old man leaned back in his chair, his face weathered by the ceaseless march of NATUREFRESH MILK, pondering his...");
        let sig = our_keypair.sign(&master_key, msg_real.as_bytes()).unwrap();
        match sig {
            SignKeypairSignature::Ed25519(ref sig) => {
                let should_be: Vec<u8> = vec![27, 170, 26, 253, 20, 232, 242, 242, 221, 55, 38, 154, 109, 229, 98, 75, 255, 116, 24, 234, 59, 27, 235, 238, 135, 32, 154, 254, 53, 208, 115, 175, 3, 144, 208, 50, 39, 33, 119, 50, 209, 161, 0, 205, 254, 111, 171, 19, 169, 110, 20, 196, 219, 235, 2, 190, 201, 117, 31, 177, 152, 249, 71, 3];
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
        let master_key1 = SecretKey::new_xchacha20poly1305().unwrap();
        let master_key2 = SecretKey::new_xchacha20poly1305().unwrap();
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
    fn signkeypair_ed25519_strip_has_private() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        match &keypair {
            SignKeypair::Ed25519 { secret: Some(_), .. } => {
                assert!(keypair.has_private());
            }
            _ => panic!("private mismatch"),
        }
        let keypair_pub = keypair.strip_private();
        match &keypair_pub {
            SignKeypair::Ed25519 { secret: None, .. } => {
                assert!(!keypair_pub.has_private());
            }
            _ => panic!("private mismatch"),
        }
    }

    #[test]
    fn signkeypair_ed25519_eq() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let keypair1 = SignKeypair::new_ed25519(&master_key).unwrap();
        let keypair2 = keypair1.clone();
        assert_eq!(keypair1, keypair2);
        let keypair3 = SignKeypair::new_ed25519(&master_key).unwrap();
        assert!(keypair1 != keypair3);
    }

    #[test]
    fn cryptokeypair_curve25519xchacha20poly1305_anonymous_enc_dec() {
        let our_master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let our_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&our_master_key).unwrap();
        let fake_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&our_master_key).unwrap();

        let message = String::from("HI JERRY I'M BUTCH");
        let sealed = our_keypair.seal_anonymous(message.as_bytes()).unwrap();
        let opened = our_keypair.open_anonymous(&our_master_key, &sealed).unwrap();

        assert_eq!(&opened[..], message.as_bytes());

        let opened2 = fake_keypair.open_anonymous(&our_master_key, &sealed);
        assert_eq!(opened2, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn cryptokeypair_curve25519xchacha20poly1305_enc_dec() {
        let sender_master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let sender_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&sender_master_key).unwrap();
        let recipient_master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let recipient_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&recipient_master_key).unwrap();
        let fake_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&recipient_master_key).unwrap();

        let message = String::from("HI JERRY I'M BUTCH");
        let sealed = recipient_keypair.seal(&sender_master_key, &sender_keypair, message.as_bytes()).unwrap();
        let opened = recipient_keypair.open(&recipient_master_key, &sender_keypair, &sealed).unwrap();

        assert_eq!(&opened[..], message.as_bytes());

        let opened2 = sender_keypair.open(&sender_master_key, &fake_keypair, &sealed);
        assert_eq!(opened2, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn cryptokeypair_curve25519xchacha20poly1305_reencrypt() {
        let master_key1 = SecretKey::new_xchacha20poly1305().unwrap();
        let master_key2 = SecretKey::new_xchacha20poly1305().unwrap();
        assert!(master_key1 != master_key2);
        let keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key1).unwrap();
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
    fn cryptokeypair_curve25519xchacha20poly1305_strip_has_private() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        match &keypair {
            CryptoKeypair::Curve25519XChaCha20Poly1305 { secret: Some(_), .. } => {
                assert!(keypair.has_private());
            }
            _ => panic!("private mismatch"),
        }
        let keypair_pub = keypair.strip_private();
        match &keypair_pub {
            CryptoKeypair::Curve25519XChaCha20Poly1305 { secret: None, .. } => {
                assert!(!keypair_pub.has_private());
            }
            _ => panic!("private mismatch"),
        }
    }

    #[test]
    fn hash_blake2b_encode_decode_fmt() {
        let msg = b"that kook dropped in on me. we need to send him a (cryptographically hashed) message.";
        let hash = Hash::new_blake2b(&msg[..]).unwrap();
        match &hash {
            Hash::Blake2b(bin) => {
                assert_eq!(bin.deref(), &vec![243, 64, 239, 85, 96, 25, 23, 71, 194, 134, 56, 85, 159, 71, 57, 211, 109, 253, 219, 151, 200, 67, 151, 95, 99, 68, 251, 52, 88, 37, 134, 63, 169, 104, 190, 112, 71, 235, 90, 125, 25, 122, 63, 198, 27, 40, 69, 145, 173, 13, 190, 238, 237, 236, 183, 80, 47, 131, 70, 200, 61, 26, 202, 161][..]);
            }
        }
        let bytes = ser::serialize(&hash).unwrap();
        assert_eq!(ser::base64_encode(&bytes[..]), String::from("oEIEQPNA71VgGRdHwoY4VZ9HOdNt_duXyEOXX2NE-zRYJYY_qWi-cEfrWn0Zej_GGyhFka0Nvu7t7LdQL4NGyD0ayqE"));
        assert_eq!(format!("{}", hash), String::from("80DvVWAZF0fChjhVn0c5023925fIQ5dfY0T7NFglhj-paL5wR-tafRl6P8YbKEWRrQ2-7u3st1Avg0bIPRrKoQA"));
        let hash2: Hash = ser::deserialize(&bytes).unwrap();
        match &hash2 {
            Hash::Blake2b(bin) => {
                assert_eq!(bin.deref(), &vec![243, 64, 239, 85, 96, 25, 23, 71, 194, 134, 56, 85, 159, 71, 57, 211, 109, 253, 219, 151, 200, 67, 151, 95, 99, 68, 251, 52, 88, 37, 134, 63, 169, 104, 190, 112, 71, 235, 90, 125, 25, 122, 63, 198, 27, 40, 69, 145, 173, 13, 190, 238, 237, 236, 183, 80, 47, 131, 70, 200, 61, 26, 202, 161][..]);
            }
        }

        let hash3 = Hash::try_from("80DvVWAZF0fChjhVn0c5023925fIQ5dfY0T7NFglhj-paL5wR-tafRl6P8YbKEWRrQ2-7u3st1Avg0bIPRrKoQA").unwrap();
        match &hash3 {
            Hash::Blake2b(bin) => {
                assert_eq!(bin.deref(), &vec![243, 64, 239, 85, 96, 25, 23, 71, 194, 134, 56, 85, 159, 71, 57, 211, 109, 253, 219, 151, 200, 67, 151, 95, 99, 68, 251, 52, 88, 37, 134, 63, 169, 104, 190, 112, 71, 235, 90, 125, 25, 122, 63, 198, 27, 40, 69, 145, 173, 13, 190, 238, 237, 236, 183, 80, 47, 131, 70, 200, 61, 26, 202, 161][..]);
            }
        }
    }

    #[test]
    fn derives_secret_key() {
        let id = Hash::new_blake2b("my key".as_bytes()).unwrap();
        let salt = Hash::new_blake2b(id.as_bytes()).unwrap();
        let master_key = derive_secret_key("ZONING IS COMMUNISM".as_bytes(), &salt.as_bytes(), KDF_OPS_INTERACTIVE, KDF_MEM_INTERACTIVE).unwrap();
        assert_eq!(master_key.as_ref(), &[148, 34, 57, 50, 168, 111, 176, 114, 120, 168, 159, 158, 96, 119, 14, 194, 52, 224, 58, 194, 77, 44, 168, 25, 54, 138, 172, 91, 164, 86, 190, 89]);
    }

    #[test]
    fn mac_result() {
        let data = String::from("PARDON ME GOOD SIR DO YOU HAVE ANY goats FOR SALE!!!!!!?");
        let mac_key = MacKey::new_blake2b_from_bytes([
            0, 1, 2, 3, 4, 5, 6, 7,
            1, 2, 3, 4, 5, 6, 7, 8,
            2, 3, 4, 5, 6, 7, 8, 9,
            3, 4, 5, 6, 7, 8, 9, 9,
            0, 1, 2, 3, 4, 5, 6, 7,
            1, 2, 3, 4, 5, 6, 7, 8,
            2, 3, 4, 5, 6, 7, 8, 9,
            3, 4, 5, 6, 7, 8, 9, 9,
        ]);
        let mac = Mac::new_blake2b(&mac_key, data.as_bytes()).unwrap();
        assert_eq!(mac, Mac::Blake2b(Binary::new([180, 48, 36, 120, 45, 212, 97, 54, 140, 236, 63, 242, 120, 88, 177, 237, 196, 173, 110, 201, 8, 226, 18, 152, 29, 146, 33, 174, 39, 63, 156, 136, 82, 242, 221, 143, 179, 198, 47, 69, 223, 118, 96, 49, 42, 73, 86, 138, 147, 204, 67, 201, 217, 32, 145, 204, 138, 128, 101, 84, 115, 69, 173, 180])));
    }

    #[test]
    fn mac_verify() {
        let data1 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and four children...if it's not too much trouble, maybe you could verify them as we...");
        let data2 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and seven children...if it's not too much trouble, maybe you could verify them as we...");
        let mac_key1 = MacKey::new_blake2b().unwrap();
        let mac_key2 = MacKey::new_blake2b().unwrap();
        let mac = Mac::new_blake2b(&mac_key1, data1.as_bytes()).unwrap();
        mac.verify(&mac_key1, data1.as_bytes()).unwrap();
        let res = mac.verify(&mac_key2, data1.as_bytes());
        assert_eq!(res, Err(Error::CryptoMacVerificationFailed));
        let res = mac.verify(&mac_key1, data2.as_bytes());
        assert_eq!(res, Err(Error::CryptoMacVerificationFailed));
        let res = mac.verify(&mac_key2, data2.as_bytes());
        assert_eq!(res, Err(Error::CryptoMacVerificationFailed));
    }
}

