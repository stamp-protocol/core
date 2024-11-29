use crate::{
    crypto::{
        base::{KeyID, SecretKey},
        private::Private,
    },
    error::{Error, Result},
    util::{
        ser::{Binary, BinarySecret, BinaryVec},
        Public,
    },
};
use crypto_box::aead::{generic_array::GenericArray, Aead as CryptoboxAead, AeadCore as CryptoboxAeadCore};
use rand::{CryptoRng, RngCore};
use rasn::{AsnType, Decode, Encode};
use serde_derive::{Deserialize, Serialize};
use std::ops::Deref;

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
            CryptoKeypair::Curve25519XChaCha20Poly1305 {
                public,
                secret: secret_maybe,
            } => CryptoKeypair::Curve25519XChaCha20Poly1305 {
                public: public.clone(),
                secret: secret_maybe.as_ref().cloned(),
            },
        }
    }
}

impl CryptoKeypair {
    /// Create a new keypair
    pub fn new_curve25519xchacha20poly1305<R: RngCore + CryptoRng>(rng: &mut R, master_key: &SecretKey) -> Result<Self> {
        let secret = crypto_box::SecretKey::generate(rng);
        let public = secret.public_key();
        Ok(Self::Curve25519XChaCha20Poly1305 {
            public: Binary::new(*public.as_bytes()),
            secret: Some(Private::seal(rng, master_key, &BinarySecret::new(secret.to_bytes()))?),
        })
    }

    /// Anonymously encrypt a message using the recipient's public key.
    pub fn seal_anonymous<R: RngCore + CryptoRng>(&self, rng: &mut R, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Curve25519XChaCha20Poly1305 { public: ref pubkey, .. } => {
                let ephemeral_secret = crypto_box::SecretKey::generate(rng);
                let ephemeral_pubkey = ephemeral_secret.public_key();
                let cardboard_box = crypto_box::ChaChaBox::new(&crypto_box::PublicKey::from(*pubkey.deref()), &ephemeral_secret);
                let mut blake = blake3::Hasher::new();
                blake.update(ephemeral_pubkey.as_ref());
                blake.update(pubkey.as_ref());
                let nonce_vec = Vec::from(blake.finalize().as_bytes());
                let nonce_arr: [u8; 24] = nonce_vec[0..24].try_into().map_err(|_| Error::CryptoSealFailed)?;
                let nonce = nonce_arr.into();
                let mut enc = cardboard_box.encrypt(&nonce, data).map_err(|_| Error::CryptoSealFailed)?;
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
            Self::Curve25519XChaCha20Poly1305 {
                public: ref pubkey,
                secret: ref seckey_opt,
            } => {
                let seckey_sealed = seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let seckey = crypto_box::SecretKey::from(*seckey_sealed.open(master_key)?.expose_secret());
                let ephemeral_pubkey_slice = &data[0..32];
                let ephemeral_pubkey_arr: [u8; 32] = ephemeral_pubkey_slice.try_into().map_err(|_| Error::CryptoOpenFailed)?;
                let ephemeral_pubkey = crypto_box::PublicKey::from(ephemeral_pubkey_arr);
                let ciphertext = &data[32..];
                let cardboard_box = crypto_box::ChaChaBox::new(&ephemeral_pubkey, &seckey);
                let mut blake = blake3::Hasher::new();
                blake.update(ephemeral_pubkey.as_ref());
                blake.update(pubkey.as_ref());
                let nonce_vec = Vec::from(blake.finalize().as_bytes());
                let nonce_arr: [u8; 24] = nonce_vec[0..24].try_into().map_err(|_| Error::CryptoSealFailed)?;
                let nonce = nonce_arr.into();
                cardboard_box.decrypt(&nonce, ciphertext).map_err(|_| Error::CryptoOpenFailed)
            }
        }
    }

    /// Encrypt a message to a recipient, and sign it with our secret crypto
    /// key. Needs our master key to unlock our heroic private key.
    pub fn seal<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        sender_master_key: &SecretKey,
        sender_keypair: &Self,
        data: &[u8],
    ) -> Result<CryptoKeypairMessage> {
        match (sender_keypair, self) {
            (
                Self::Curve25519XChaCha20Poly1305 {
                    secret: ref sender_seckey_opt,
                    ..
                },
                Self::Curve25519XChaCha20Poly1305 {
                    public: ref recipient_pubkey,
                    ..
                },
            ) => {
                let sender_seckey_sealed = sender_seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let sender_seckey = crypto_box::SecretKey::from(*sender_seckey_sealed.open(sender_master_key)?.expose_secret());
                let recipient_chacha_pubkey = crypto_box::PublicKey::from(*recipient_pubkey.deref());
                let cardboard_box = crypto_box::ChaChaBox::new(&recipient_chacha_pubkey, &sender_seckey);
                let nonce = crypto_box::ChaChaBox::generate_nonce(rng);
                let msg = cardboard_box.encrypt(&nonce, data).map_err(|_| Error::CryptoSealFailed)?;
                let nonce_arr = nonce.as_slice().try_into().map_err(|_| Error::BadLength)?;
                Ok(CryptoKeypairMessage::new(
                    CryptoKeypairNonce::Curve25519XChaCha20Poly1305(Binary::new(nonce_arr)),
                    msg,
                ))
            }
        }
    }

    /// Open a message encrypted with our public key and verify the sender of
    /// the message using their public key. Needs our master key to unlock the
    /// private key used to decrypt the message.
    pub fn open(&self, recipient_master_key: &SecretKey, sender_keypair: &Self, message: &CryptoKeypairMessage) -> Result<Vec<u8>> {
        match (self, sender_keypair) {
            (
                Self::Curve25519XChaCha20Poly1305 {
                    secret: ref recipient_seckey_opt,
                    ..
                },
                CryptoKeypair::Curve25519XChaCha20Poly1305 {
                    public: ref sender_pubkey, ..
                },
            ) => {
                let recipient_seckey_sealed = recipient_seckey_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let recipient_seckey = crypto_box::SecretKey::from(*recipient_seckey_sealed.open(recipient_master_key)?.expose_secret());
                let nonce = match message.nonce() {
                    CryptoKeypairNonce::Curve25519XChaCha20Poly1305(vec) => GenericArray::from_slice(vec.as_slice()),
                };
                let sender_chacha_pubkey = crypto_box::PublicKey::from(*sender_pubkey.deref());
                let cardboard_box = crypto_box::ChaChaBox::new(&sender_chacha_pubkey, &recipient_seckey);
                cardboard_box
                    .decrypt(nonce, message.ciphertext().as_slice())
                    .map_err(|_| Error::CryptoOpenFailed)
            }
        }
    }

    /// Re-encrypt this signing keypair with a new master key.
    pub fn reencrypt<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        previous_master_key: &SecretKey,
        new_master_key: &SecretKey,
    ) -> Result<Self> {
        match self {
            Self::Curve25519XChaCha20Poly1305 {
                public,
                secret: Some(private),
            } => Ok(Self::Curve25519XChaCha20Poly1305 {
                public,
                secret: Some(private.reencrypt(rng, previous_master_key, new_master_key)?),
            }),
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
            Self::Curve25519XChaCha20Poly1305 { public: ref pubkey, .. } => Self::Curve25519XChaCha20Poly1305 {
                public: pubkey.clone(),
                secret: None,
            },
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
    /// Encrypt a message to a recipient, and sign it with our secret crypto
    /// key. Needs our master key to unlock our heroic private key.
    pub fn seal<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        sender_master_key: &SecretKey,
        sender_pubkey: &CryptoKeypair,
        data: &[u8],
    ) -> Result<CryptoKeypairMessage> {
        let keypair = match self {
            Self::Curve25519XChaCha20Poly1305(pubkey) => CryptoKeypair::Curve25519XChaCha20Poly1305 {
                public: pubkey.clone(),
                secret: None,
            },
        };
        keypair.seal(rng, sender_master_key, sender_pubkey, data)
    }

    /// Anonymously encrypt a message using the recipient's public key.
    pub fn seal_anonymous<R: RngCore + CryptoRng>(&self, rng: &mut R, data: &[u8]) -> Result<Vec<u8>> {
        let keypair = match self {
            Self::Curve25519XChaCha20Poly1305(pubkey) => CryptoKeypair::Curve25519XChaCha20Poly1305 {
                public: pubkey.clone(),
                secret: None,
            },
        };
        keypair.seal_anonymous(rng, data)
    }

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
        let mut rng = crate::util::test::rng();
        let our_master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let our_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &our_master_key).unwrap();
        let fake_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &our_master_key).unwrap();

        let message = String::from("HI JERRY I'M BUTCH");
        let sealed = our_keypair.seal_anonymous(&mut rng, message.as_bytes()).unwrap();
        let opened = our_keypair.open_anonymous(&our_master_key, &sealed).unwrap();

        assert_eq!(&opened[..], message.as_bytes());

        let opened2 = fake_keypair.open_anonymous(&our_master_key, &sealed);
        assert_eq!(opened2, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn cryptokeypair_curve25519xchacha20poly1305_anonymous_encpub_dec() {
        let mut rng = crate::util::test::rng();
        let our_master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let our_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &our_master_key).unwrap();
        let fake_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &our_master_key).unwrap();
        let our_pubkey = CryptoKeypairPublic::from(our_keypair.clone());

        let message = String::from("HI JERRY I'M BUTCH");
        let sealed1 = our_keypair.seal_anonymous(&mut rng, message.as_bytes()).unwrap();
        let sealed2 = our_pubkey.seal_anonymous(&mut rng, message.as_bytes()).unwrap();
        let opened1 = our_keypair.open_anonymous(&our_master_key, &sealed1).unwrap();
        let opened2 = our_keypair.open_anonymous(&our_master_key, &sealed2).unwrap();

        assert_eq!(&opened1[..], message.as_bytes());
        assert_eq!(&opened2[..], message.as_bytes());

        let fake2_1 = fake_keypair.open_anonymous(&our_master_key, &sealed1);
        let fake2_2 = fake_keypair.open_anonymous(&our_master_key, &sealed2);
        assert_eq!(fake2_1, Err(Error::CryptoOpenFailed));
        assert_eq!(fake2_2, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn cryptokeypair_curve25519xchacha20poly1305_enc_dec() {
        let mut rng = crate::util::test::rng();
        let sender_master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let sender_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &sender_master_key).unwrap();
        let recipient_master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let recipient_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &recipient_master_key).unwrap();
        let recipient_pubkey = CryptoKeypairPublic::from(recipient_keypair.clone());
        let fake_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &recipient_master_key).unwrap();

        let message = b"HI JERRY I'M BUTCH";
        let sealed1 = recipient_keypair
            .seal(&mut rng, &sender_master_key, &sender_keypair, message)
            .unwrap();
        let sealed2 = recipient_pubkey
            .seal(&mut rng, &sender_master_key, &sender_keypair, message)
            .unwrap();
        let opened1 = recipient_keypair.open(&recipient_master_key, &sender_keypair, &sealed1).unwrap();
        let opened2 = recipient_keypair.open(&recipient_master_key, &sender_keypair, &sealed2).unwrap();

        assert_eq!(&opened1[..], message);
        assert_eq!(&opened2[..], message);

        let fake1 = sender_keypair.open(&sender_master_key, &fake_keypair, &sealed1);
        let fake2 = sender_keypair.open(&sender_master_key, &fake_keypair, &sealed2);
        assert_eq!(fake1, Err(Error::CryptoOpenFailed));
        assert_eq!(fake2, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn cryptokeypair_curve25519xchacha20poly1305_reencrypt() {
        let mut rng = crate::util::test::rng();
        let master_key1 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let master_key2 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        assert!(master_key1 != master_key2);
        let keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key1).unwrap();
        let message = String::from("get a job");
        let sealed = keypair.seal_anonymous(&mut rng, message.as_bytes()).unwrap();
        let keypair = keypair.reencrypt(&mut rng, &master_key1, &master_key2).unwrap();
        let opened = keypair.open_anonymous(&master_key2, &sealed).unwrap();
        assert_eq!(opened.as_slice(), message.as_bytes());
        let res = keypair.clone().reencrypt(&mut rng, &master_key1, &master_key2);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
        let res = keypair.open_anonymous(&master_key1, &sealed);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
    }

    #[test]
    fn cryptokeypair_curve25519xchacha20poly1305_strip_has_private() {
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();
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
