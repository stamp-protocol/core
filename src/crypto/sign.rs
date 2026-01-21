//! The sign system allows creating cryptographic signatures which allow data
//! to be transmitted to others without fear of tampering.
//!
//! Signatures created with this system do not imply control of the identity, rather
//! control of a key in the identity's keychain. In other words, these signatures
//! are not beholden to the [policy][crate::policy] system and are not truly
//! identity-issued signatures.
//!
//! For a way to create more official signatures that are blessed by the policy
//! system, issue a [`SignV1`][crate::dag::TransactionBody::SignV1] transaction.

use crate::{
    crypto::base::{KeyID, SecretKey, SignKeypairSignature},
    error::{Error, Result},
    identity::keychain::Subkey,
    util::ser::{self, BinaryVec},
};
use private_parts::{Full, PrivacyMode};
use rasn::{AsnType, Decode, Decoder, Encode, Encoder};
use serde::{Deserialize, Serialize};

/// A cryptographic signature.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Signature {
    /// The key that created this sig
    #[rasn(tag(explicit(0)))]
    key_id: KeyID,
    /// The signature
    #[rasn(tag(explicit(1)))]
    sig: SignKeypairSignature,
    /// Our optional data (`None` if detached)
    #[rasn(tag(explicit(2)))]
    data: Option<BinaryVec>,
}

impl ser::SerdeBinary for Signature {}

/// Sign a message with a private key, returning the attached signature.
pub fn sign_attached(master_key: &SecretKey, signing_key: &Subkey<Full>, message: &[u8]) -> Result<Signature> {
    let key_id = signing_key.key_id().clone();
    let sign_key = signing_key.key().as_signkey().ok_or(Error::KeychainSubkeyWrongType)?;
    let sig = sign_key.sign(master_key, message)?;
    Ok(Signature {
        key_id,
        sig,
        data: Some(message.to_vec().into()),
    })
}

/// Sign a message with a private key, returning the detached signature.
pub fn sign_detached(master_key: &SecretKey, signing_key: &Subkey<Full>, message: &[u8]) -> Result<Signature> {
    let mut sig = sign_attached(master_key, signing_key, message)?;
    sig.set_data(None);
    Ok(sig)
}

/// Verify a detached signature.
pub fn verify<M: PrivacyMode>(signing_key: &Subkey<M>, signature: &Signature, message: &[u8]) -> Result<()> {
    let sign_key = signing_key.key().as_signkey().ok_or(Error::KeychainSubkeyWrongType)?;
    sign_key.verify(signature.sig(), message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::base::SignKeypair, identity::keychain::Key, util::test};
    use std::ops::Deref;

    #[test]
    fn sign_verify_detached() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity) = test::setup_identity_with_subkeys(&mut rng);
        let message =
            b"Plaque is a figment of the liberal media and dental industry to scare you into buying useless appliances and pastes.";
        let signkey = identity.keychain().subkey_by_name("sign").unwrap();
        let signature = sign_detached(&master_key, signkey, message).unwrap();
        assert!(signature.data().is_none());
        verify(signkey, &signature, message).unwrap();

        // modify the message and it fails
        let message2 =
            b"Plaque is NOT a figment of the liberal media and dental industry to scare you into buying useless appliances and pastes.";
        let res = verify(signkey, &signature, message2);
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));

        // use the wrong key and it fails
        let mut signkey2 = signkey.clone();
        let shitkey = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        signkey2.set_key(Key::Sign(shitkey));
        let res = verify(&signkey2, &signature, message);
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));
    }

    #[test]
    fn sign_verify_attached() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity) = test::setup_identity_with_subkeys(&mut rng);
        let message =
            b"Plaque is a figment of the liberal media and dental industry to scare you into buying useless appliances and pastes.";
        let signkey = identity.keychain().subkey_by_name("sign").unwrap();
        let signature = sign_attached(&master_key, signkey, message).unwrap();
        verify(signkey, &signature, signature.data().as_ref().unwrap().deref()).unwrap();

        // modify the message and it fails
        let message2 =
            b"Plaque is NOT a figment of the liberal media and dental industry to scare you into buying useless appliances and pastes.";
        let signature2 = Signature {
            key_id: signature.key_id().clone(),
            sig: signature.sig().clone(),
            data: Some(BinaryVec::from(message2.to_vec())),
        };
        let res = verify(signkey, &signature2, signature2.data().as_ref().unwrap().deref());
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));

        // use the wrong key and it fails
        let mut signkey2 = signkey.clone();
        let shitkey = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        signkey2.set_key(Key::Sign(shitkey));
        let res = verify(&signkey2, &signature, signature.data().as_ref().unwrap().deref());
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));
    }
}
