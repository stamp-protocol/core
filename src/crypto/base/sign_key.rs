use crate::{
    crypto::{
        base::{KeyID, SecretKey},
        private::Private,
    },
    error::{Error, Result},
    util::{
        ser::{self, Binary, BinarySecret},
        sign::Signable,
        Public,
    },
};
use rand::{CryptoRng, RngCore};
use rasn::{AsnType, Decode, Encode};
use serde_derive::{Deserialize, Serialize};
use std::ops::Deref;

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
    },
}

impl Clone for SignKeypair {
    fn clone(&self) -> Self {
        match self {
            SignKeypair::Ed25519 {
                public,
                secret: secret_maybe,
            } => SignKeypair::Ed25519 {
                public: public.clone(),
                secret: secret_maybe.as_ref().cloned(),
            },
        }
    }
}

impl SignKeypair {
    fn new_ed25519_from_secret<R: RngCore + CryptoRng>(
        rng: &mut R,
        master_key: &SecretKey,
        secret: ed25519_consensus::SigningKey,
    ) -> Result<Self> {
        let public = secret.verification_key();
        Ok(Self::Ed25519 {
            public: Binary::new(public.to_bytes()),
            secret: Some(Private::seal(rng, master_key, &BinarySecret::new(secret.to_bytes()))?),
        })
    }

    /// Create a new ed25519 keypair
    pub fn new_ed25519<R: RngCore + CryptoRng>(rng: &mut R, master_key: &SecretKey) -> Result<Self> {
        let mut randbuf = [0u8; 32];
        rng.fill_bytes(&mut randbuf);
        let secret = ed25519_consensus::SigningKey::from(randbuf);
        Self::new_ed25519_from_secret(rng, master_key, secret)
    }

    /// Create a new ed25519 keypair from a cryptographic seed
    pub fn new_ed25519_from_bytes<R: RngCore + CryptoRng>(rng: &mut R, master_key: &SecretKey, secret_bytes: [u8; 32]) -> Result<Self> {
        let secret = ed25519_consensus::SigningKey::from(secret_bytes);
        Self::new_ed25519_from_secret(rng, master_key, secret)
    }

    /// Hash a value then sign it, returning the hash and the signature. This is
    /// already how signing works, but we basically control the hash process
    /// ourselves so we can return the hash.
    pub fn sign(&self, master_key: &SecretKey, data: &[u8]) -> Result<SignKeypairSignature> {
        match self {
            Self::Ed25519 {
                secret: ref sec_locked_opt,
                ..
            } => {
                let sec_locked = sec_locked_opt.as_ref().ok_or(Error::CryptoKeyMissing)?;
                let sec_bytes: [u8; 32] = *sec_locked.open(master_key)?.expose_secret();
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
            (
                Self::Ed25519 {
                    public: ref pubkey_bytes, ..
                },
                SignKeypairSignature::Ed25519(ref sig_bytes),
            ) => {
                let pubkey = ed25519_consensus::VerificationKey::try_from(*pubkey_bytes.deref())
                    .map_err(|_| Error::CryptoSignatureVerificationFailed)?;
                let sig_arr: [u8; 64] = *sig_bytes.deref();
                let sig = ed25519_consensus::Signature::from(sig_arr);
                pubkey.verify(&sig, data).map_err(|_| Error::CryptoSignatureVerificationFailed)?;
                Ok(())
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
            Self::Ed25519 {
                public,
                secret: Some(private),
            } => Ok(Self::Ed25519 {
                public,
                secret: Some(private.reencrypt(rng, previous_master_key, new_master_key)?),
            }),
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
            Self::Ed25519 { public: pubkey, .. } => Self::Ed25519 {
                public: pubkey.clone(),
                secret: None,
            },
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
            SignKeypairPublic::Ed25519(pubkey) => SignKeypair::Ed25519 {
                public: pubkey.clone(),
                secret: None,
            },
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[test]
    fn signkeypair_ed25519_sign_verify() {
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let our_keypair = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();

        let msg_real =
            String::from("the old man leaned back in his chair, his face weathered by the ceaseless march of time, pondering his...");
        let msg_fake = String::from(
            "the old man leaned back in his chair, his face weathered by the ceaseless march of NATUREFRESH MILK, pondering his...",
        );
        let sig = our_keypair.sign(&master_key, msg_real.as_bytes()).unwrap();
        let verify_real = our_keypair.verify(&sig, msg_real.as_bytes());
        let verify_fake = our_keypair.verify(&sig, msg_fake.as_bytes());
        assert_eq!(verify_real, Ok(()));
        assert_eq!(verify_fake, Err(Error::CryptoSignatureVerificationFailed));
    }

    #[test]
    fn signkeypair_ed25519_seed_sign_verify() {
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let seed = [
            233, 229, 76, 13, 231, 38, 253, 27, 53, 2, 235, 174, 151, 186, 192, 33, 16, 2, 57, 32, 170, 23, 13, 47, 44, 234, 231, 35, 38,
            107, 93, 198,
        ];
        let our_keypair = SignKeypair::new_ed25519_from_bytes(&mut rng, &master_key, seed).unwrap();

        let msg_real =
            String::from("the old man leaned back in his chair, his face weathered by the ceaseless march of time, pondering his...");
        let msg_fake = String::from(
            "the old man leaned back in his chair, his face weathered by the ceaseless march of NATUREFRESH MILK, pondering his...",
        );
        let sig = our_keypair.sign(&master_key, msg_real.as_bytes()).unwrap();
        match sig {
            SignKeypairSignature::Ed25519(ref sig) => {
                let should_be: Vec<u8> = vec![
                    161, 93, 247, 4, 187, 12, 160, 118, 111, 79, 16, 100, 205, 38, 238, 153, 217, 214, 230, 195, 175, 228, 165, 183, 5,
                    151, 159, 114, 7, 32, 156, 115, 34, 108, 194, 252, 86, 102, 133, 35, 129, 224, 146, 254, 91, 185, 97, 207, 0, 63, 241,
                    184, 144, 15, 20, 26, 187, 235, 95, 207, 43, 144, 216, 6,
                ];
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
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let seed = [
            111, 229, 76, 13, 231, 38, 253, 27, 53, 2, 235, 174, 151, 186, 192, 33, 16, 2, 57, 32, 170, 23, 13, 47, 44, 234, 231, 35, 38,
            107, 93, 198,
        ];
        let seckey = SecretKey::new_xchacha20poly1305_from_bytes(seed).expect("bad seed");
        let bytes: &[u8] = seckey.as_ref();
        let seed: [u8; 32] = bytes[0..32].try_into().unwrap();
        let our_keypair = SignKeypair::new_ed25519_from_bytes(&mut rng, &master_key, seed).unwrap();

        let msg_real =
            String::from("the old man leaned back in his chair, his face weathered by the ceaseless march of time, pondering his...");
        let msg_fake = String::from(
            "the old man leaned back in his chair, his face weathered by the ceaseless march of NATUREFRESH MILK, pondering his...",
        );
        let sig = our_keypair.sign(&master_key, msg_real.as_bytes()).unwrap();
        match sig {
            SignKeypairSignature::Ed25519(ref sig) => {
                let should_be: Vec<u8> = vec![
                    17, 231, 166, 244, 122, 249, 185, 25, 178, 140, 210, 159, 14, 92, 120, 135, 28, 110, 235, 86, 175, 63, 104, 145, 128,
                    242, 145, 72, 127, 184, 232, 35, 213, 6, 226, 12, 188, 212, 101, 194, 225, 178, 224, 234, 137, 157, 209, 149, 106, 139,
                    205, 30, 40, 153, 55, 151, 78, 15, 9, 216, 57, 27, 139, 0,
                ];
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
        let mut rng = crate::util::test::rng();
        let master_key1 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let master_key2 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        assert!(master_key1 != master_key2); // lazy, but ok
        let keypair = SignKeypair::new_ed25519(&mut rng, &master_key1).unwrap();
        let data = vec![1, 2, 3, 4, 5];
        let sig1 = keypair.sign(&master_key1, data.as_slice()).unwrap();
        let keypair = keypair.reencrypt(&mut rng, &master_key1, &master_key2).unwrap();
        let sig2 = keypair.sign(&master_key2, data.as_slice()).unwrap();
        assert_eq!(sig1, sig2);
        let res = keypair.clone().reencrypt(&mut rng, &master_key1, &master_key2);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
        let res = keypair.sign(&master_key1, data.as_slice());
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
    }

    #[test]
    fn signkeypair_ed25519_strip_has_private() {
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let keypair = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
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
        let mut rng = crate::util::test::rng();
        let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let keypair1 = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let keypair2 = keypair1.clone();
        assert_eq!(keypair1, keypair2);
        let keypair3 = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        assert!(keypair1 != keypair3);
    }
}
