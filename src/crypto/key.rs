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

use blake2::Digest;
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
use ed25519_dalek::{Signer};
use hmac::{
    Mac,
    digest::{
        FixedOutput,
        crypto_common::generic_array::GenericArray,
    },
};
use rand::{RngCore, rngs::OsRng};
use rand_chacha::rand_core::{RngCore as RngCoreChaCha, SeedableRng};
use rasn::{Encode, Decode, AsnType};
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

/// A value that lets us reference asymmetric keypairs by their public key.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum KeyID {
    #[rasn(tag(explicit(0)))]
    SignKeypair(SignKeypairPublic),
    #[rasn(tag(explicit(1)))]
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
            Self::CryptoKeypair(CryptoKeypairPublic::Curve25519XChaCha20Poly1305(pubkey)) => {
                get_bytes(1, 0, pubkey.as_ref())
            }
        };
        ser::base64_encode(&bytes)
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
            SignKeypair::Ed25519 { .. } => Self::Ed25519(Binary::new([0u8; ed25519_dalek::SIGNATURE_LENGTH])),
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
    /// Create a new ed25519 keypair
    pub fn new_ed25519(master_key: &SecretKey) -> Result<Self> {
        let mut randbuf = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        OsRng.fill_bytes(&mut randbuf);
        let secret = ed25519_dalek::SecretKey::from_bytes(&randbuf[..])
            .map_err(|_| Error::KeygenFailed)?;
        let public: ed25519_dalek::PublicKey = (&secret).into();
        Ok(Self::Ed25519 { 
            public: Binary::new(public.to_bytes()),
            secret: Some(Private::seal(master_key, &BinarySecret::new(randbuf))?),
        })
    }

    /// Create a new ed25519 keypair
    pub fn new_ed25519_from_seed(master_key: &SecretKey, seed_bytes: &[u8; 32]) -> Result<Self> {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed_bytes);
        let mut randbuf = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut randbuf);
        let secret = ed25519_dalek::SecretKey::from_bytes(&randbuf[..])
            .map_err(|_| Error::KeygenFailed)?;
        let public: ed25519_dalek::PublicKey = (&secret).into();
        Ok(Self::Ed25519 { 
            public: Binary::new(public.to_bytes()),
            secret: Some(Private::seal(master_key, &BinarySecret::new(secret.to_bytes()))?),
        })
    }

    /// Create a new ed25519 keypair from a [SecretKey]
    pub fn new_ed25519_from_secret_key(master_key: &SecretKey, seckey: &SecretKey) -> Result<Self> {
        let bytes: &[u8] = seckey.as_ref();
        if bytes.len() < 32 {
            Err(Error::BadLength)?;
        }
        let seed: [u8; 32] = bytes[0..32].try_into().map_err(|_| Error::BadLength)?;
        Self::new_ed25519_from_seed(master_key, &seed)
    }

    /// Hash a value then sign it, returning the hash and the signature. This is
    /// already how signing works, but we basically control the hash process
    /// ourselves so we can return the hash.
    pub fn sign_and_hash(&self, master_key: &SecretKey, data: &[u8]) -> Result<(Binary<64>, SignKeypairSignature)> {
        match self {
            Self::Ed25519 { secret: ref sec_locked_opt, .. } => {
                let sec_locked = sec_locked_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let seckey = ed25519_dalek::SecretKey::from_bytes(sec_locked.open(master_key)?.expose_secret().as_ref())
                    .map_err(|_| Error::CryptoSignatureFailed)?;
                let pubkey: ed25519_dalek::PublicKey = (&seckey).into();
                let keypair = ed25519_dalek::Keypair { public: pubkey, secret: seckey };
                let mut prehashed = ed25519_dalek::Sha512::new();
                prehashed.update(data);
                // i don't like this clone but oh well...?
                let sig_obj = keypair.sign_prehashed(prehashed.clone(), Some(b"stamp-protocol"));
                let sig = SignKeypairSignature::Ed25519(Binary::new(sig_obj.to_bytes()));
                let hash_vec = Vec::from(prehashed.finalize().as_slice());
                let hash_arr: [u8; 64] = hash_vec.as_slice().try_into()
                    .map_err(|_| Error::CryptoSignatureFailed)?;
                let hash = Sha512(Binary(hash_arr));
                Ok((hash, sig))
            }
        }
    }

    /// Sign a value with our secret signing key.
    ///
    /// Must be unlocked via our master key.
    pub fn sign(&self, master_key: &SecretKey, data: &[u8]) -> Result<SignKeypairSignature> {
        // sign and hash but throw away the hash
        self.sign_and_hash(master_key, data)
            .map(|x| x.1)
    }

    /// Make sure a set of data has the appropriate hash and also verifies
    /// against its signature.
    pub fn verify_and_hash(&self, hash: Sha512, signature: &SignKeypairSignature, data: &[u8]) -> Result<Sha512> {
        match (self, signature) {
            (Self::Ed25519 { public: ref pubkey_bytes, .. }, SignKeypairSignature::Ed25519(ref sig_bytes)) => {
                let pubkey = ed25519_dalek::PublicKey::from_bytes(&pubkey_bytes[..])
                    .map_err(|_| Error::CryptoSignatureVerificationFailed)?;
                let sig_arr: [u8; 64] = sig_bytes.deref().clone().try_into()
                    .map_err(|_| Error::CryptoSignatureVerificationFailed)?;
                let prehashed = ed25519_dalek::Sha512::default().chain(data);
                let body_hash_vec = Vec::from(prehashed.clone().finalize().as_slice());
                let body_hash_arr: [u8; 64] = hash_vec.as_slice().try_into()
                    .map_err(|_| Error::CryptoSignatureFailed)?;
                let body_hash = Sha512(Binary(body_hash_arr));

                if hash != body_hash {
                    Err(Error::CryptoSignatureVerificationFailed)?;
                }

                let sig = ed25519_dalek::Signature::from(sig_arr);
                pubkey.verify_prehashed_strict(data, &sig)
                    .map_err(|_| Error::CryptoSignatureVerificationFailed)
            }
        }
    }

    /// Verify a value with a detached signature given the public key of the
    /// signer.
    pub fn verify(&self, signature: &SignKeypairSignature, data: &[u8]) -> Result<()> {
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

/// Holds a sha512 signature. We could just use Binary<64> directly but this
/// sets a more clear intention, and these days I'm all about clear intentions
/// and open communication (as long as it's securely encrypted between
/// participants, of course).
#[derive(Debug, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
pub struct Sha512(Binary<64>);

impl Sha512 {
    /// Create a new Sha512 from a byte array
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(Binary::new(bytes))
    }

    #[cfg(test)]
    pub(crate) fn random() -> Self {
        let mut randbuf = [0u8; 64];
        OsRng.fill_bytes(&mut randbuf);
        Self::new(randbuf)
    }
}

impl Deref for Sha512 {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0.deref()
    }
}

/// A key for deriving an HMAC
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum HmacKey {
    /// Sha512 HMAC key
    #[rasn(tag(explicit(0)))]
    Sha512(BinarySecret<32>),
}

impl HmacKey {
    /// Create a new sha512 HMAC key
    pub fn new_sha512() -> Result<Self> {
        let mut randbuf = [0u8; 32];
        OsRng.fill_bytes(&mut randbuf);
        Ok(Self::Sha512(BinarySecret::new(randbuf)))
    }

    /// Create a new sha512 HMAC key from a byte array
    pub fn new_sha512_from_bytes(keybytes: [u8; 32]) -> Self {
        Self::Sha512(BinarySecret::new(keybytes))
    }
}

impl TryFrom<SecretKey> for HmacKey {
    type Error = Error;

    fn try_from(key: SecretKey) -> core::result::Result<Self, Self::Error> {
        match key {
            SecretKey::XChaCha20Poly1305(binsec) => {
                Ok(Self::Sha512(binsec))
            }
        }
    }
}

/// An HMAC hash
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Hmac {
    /// Sha512 HMAC
    #[rasn(tag(explicit(0)))]
    Sha512(Binary<64>),
}

impl Deref for Hmac {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Hmac::Sha512(bytes) => &(bytes.deref())[..],
        }
    }
}

impl Hmac {
    /// Create a new HMACSHA512 from a key and a set of data.
    pub fn new_sha512(hmac_key: &HmacKey, data: &[u8]) -> Result<Self> {
        match hmac_key {
            HmacKey::Sha512(hmac_key) => {
                let mut mac = hmac::SimpleHmac::<sha2::Sha512>::new_from_slice(hmac_key.expose_secret().deref())
                    .map_err(|_| Error::CryptoBadKey)?;
                mac.update(data);
                let arr: [u8; 64] = mac.finalize_fixed().as_slice().try_into()
                    .map_err(|_| Error::BadLength)?;
                Ok(Hmac::Sha512(Binary::new(arr)))
            }
        }
    }

    /// Verify an HMAC against a set of data.
    pub fn verify(&self, hmac_key: &HmacKey, data: &[u8]) -> Result<()> {
        match (self, hmac_key) {
            (Self::Sha512(hmac), HmacKey::Sha512(hmac_key)) => {
                let mut mac_ver = hmac::SimpleHmac::<sha2::Sha512>::new_from_slice(&hmac_key.expose_secret()[..])
                    .map_err(|_| Error::CryptoBadKey)?;
                mac_ver.update(data);
                let ct_out = hmac::digest::CtOutput::new(GenericArray::from_slice(hmac.deref()).clone());
                if ct_out != mac_ver.finalize() {
                    // the data has been tampered with, my friend.
                    Err(Error::CryptoHmacVerificationFailed)?;
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
    use crate::util;

    pub(crate) fn secret_from_vec(bytes: Vec<u8>) -> SecretKey {
        let arr = bytes.try_into().unwrap();
        SecretKey::XChaCha20Poly1305(BinarySecret::new(arr))
    }

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
        let our_keypair = SignKeypair::new_ed25519_from_secret_key(&master_key, &seckey).unwrap();

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
    fn signkeypair_ed25519_blank() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let keypair1 = SignKeypair::new_ed25519(&master_key).unwrap();
        let keypair2 = SignKeypair::new_ed25519(&master_key).unwrap();
        let blank1 = SignKeypairSignature::blank(&keypair1);
        let blank2 = SignKeypairSignature::blank(&keypair2);
        assert_eq!(blank1, blank2);
        assert_eq!(blank1.as_ref(), vec![0; ed25519_dalek::SIGNATURE_LENGTH].as_slice());
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
    fn derives_secret_key() {
        let id = util::hash("my key".as_bytes()).unwrap();
        let salt = util::hash(id.as_ref()).unwrap();
        let master_key = derive_secret_key("ZONING IS COMMUNISM".as_bytes(), &salt.as_ref(), KDF_OPS_INTERACTIVE, KDF_MEM_INTERACTIVE).unwrap();
        assert_eq!(master_key.as_ref(), &[148, 34, 57, 50, 168, 111, 176, 114, 120, 168, 159, 158, 96, 119, 14, 194, 52, 224, 58, 194, 77, 44, 168, 25, 54, 138, 172, 91, 164, 86, 190, 89]);
    }

    #[test]
    fn hmac_result() {
        let data = String::from("PARDON ME GOOD SIR DO YOU HAVE ANY goats FOR SALE!!!!!!?");
        let hmac_key = HmacKey::new_sha512_from_bytes([
            0, 1, 2, 3, 4, 5, 6, 7,
            1, 2, 3, 4, 5, 6, 7, 8,
            2, 3, 4, 5, 6, 7, 8, 9,
            3, 4, 5, 6, 7, 8, 9, 9,
        ]);
        let hmac = Hmac::new_sha512(&hmac_key, data.as_bytes()).unwrap();
        assert_eq!(hmac, Hmac::Sha512(Binary::new([156, 55, 129, 245, 223, 131, 164, 169, 16, 253, 155, 213, 86, 246, 186, 151, 64, 222, 116, 203, 60, 141, 238, 58, 243, 10, 108, 239, 195, 253, 44, 24, 162, 111, 160, 243, 22, 144, 143, 251, 26, 48, 68, 19, 157, 53, 120, 83, 58, 193, 183, 100, 30, 220, 65, 80, 32, 47, 141, 1, 48, 195, 198, 0])));
    }

    #[test]
    fn hmac_verify() {
        let data1 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and four children...if it's not too much trouble, maybe you could verify them as we...");
        let data2 = String::from("hai plz verify me. oh and could you verify my cousin too? he's just over there, with his wife and seven children...if it's not too much trouble, maybe you could verify them as we...");
        let hmac_key1 = HmacKey::new_sha512().unwrap();
        let hmac_key2 = HmacKey::new_sha512().unwrap();
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

