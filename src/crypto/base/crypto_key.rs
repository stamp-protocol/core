use blake2::{Digest, digest::crypto_common::generic_array::GenericArray};
use chacha20poly1305::aead::{self, Aead};
use crate::{
    crypto::base::{KeyID, SecretKey},
    error::{Error, Result},
    private::Private,
    util::{
        Public,
        ser::{Binary, BinarySecret, BinaryVec},
    },
};
use rand::rngs::OsRng;
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// An asymmetric signing keypair nonce.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum CryptoKeypairNonce {
    /// Nonce for Curve25519XChaCha20Poly1305
    #[rasn(tag(0))]
    Curve25519XChaCha20Poly1305(Binary<24>),
}

/// A message we encrypt with their pubkey that's signed with our seckey. Meant
/// for non-anonymous, authenticated messaging.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct CryptoKeypairMessage {
    /// Our heroic nonce
    #[rasn(tag(0))]
    nonce: CryptoKeypairNonce,
    /// The message ciphertext
    #[rasn(tag(1))]
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
    #[rasn(tag(0))]
    Curve25519XChaCha20Poly1305 {
        #[rasn(tag(0))]
        public: Binary<32>,
        #[rasn(tag(1))]
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
    #[rasn(tag(0))]
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

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
}

