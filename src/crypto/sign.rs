//! The sign system allows creating cryptographic signatures which allow data
//! to be transmitted to others without fear of tampering.

use crate::{
    crypto::{
        SignedObject,
        base::{SecretKey, SignKeypairSignature},
    },
    error::{Error, Result},
    identity::{
        IdentityID,
        keychain::Subkey,
    },
    util::ser::{self, BinaryVec},
};
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};

/// A cryptographic signature.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Signature {
    /// A detached signature
    #[rasn(tag(explicit(0)))]
    Detached {
        #[rasn(tag(explicit(0)))]
        sig: SignedObject<SignKeypairSignature>,
    },
    /// A signature with embedded data.
    #[rasn(tag(explicit(1)))]
    Attached {
        #[rasn(tag(explicit(0)))]
        sig: SignedObject<SignKeypairSignature>,
        #[rasn(tag(explicit(1)))]
        data: BinaryVec,
    },
}

impl Signature {
    /// If this signature is detached, return the signature.
    pub fn detached(&self) -> Option<&SignedObject<SignKeypairSignature>> {
        match self {
            Self::Detached { sig: signed } => Some(signed),
            _ => None,
        }
    }

    /// If this signature has attached/embedded data, return the signature and
    /// data.
    pub fn attached(&self) -> Option<(&SignedObject<SignKeypairSignature>, &Vec<u8>)> {
        match self {
            Self::Attached { sig: signed, data } => Some((signed, data)),
            _ => None,
        }
    }
}

impl ser::SerdeBinary for Signature {}

/// Sign a message with a private key, returning the detached signature.
pub fn sign(master_key: &SecretKey, signing_identity_id: &IdentityID, signing_key: &Subkey, message: &[u8]) -> Result<Signature> {
    let sign_key = signing_key.key().as_signkey()
        .ok_or(Error::KeychainSubkeyWrongType)?;
    let signature = sign_key.sign(master_key, message)?;
    let key_id = signing_key.key_id();
    Ok(Signature::Detached {
        sig: SignedObject::new(signing_identity_id.clone(), key_id, signature)
    })
}

/// Verify a detached signature.
pub fn verify(signing_key: &Subkey, signature: &Signature, message: &[u8]) -> Result<()> {
    let detached = signature.detached()
        .map(|x| x.body())
        .ok_or(Error::CryptoWrongSignatureType)?;
    let sign_key = signing_key.key().as_signkey()
        .ok_or(Error::KeychainSubkeyWrongType)?;
    sign_key.verify(detached, message)
}

/// Sign a message with a private key, returning the detached signature.
pub fn sign_attached(master_key: &SecretKey, signing_identity_id: &IdentityID, signing_key: &Subkey, message: &[u8]) -> Result<Signature> {
    let sign_key = signing_key.key().as_signkey()
        .ok_or(Error::KeychainSubkeyWrongType)?;
    let signature = sign_key.sign(master_key, message)?;
    let key_id = signing_key.key_id();
    Ok(Signature::Attached {
        sig: SignedObject::new(signing_identity_id.clone(), key_id, signature),
        data: message.to_vec().into(),
    })
}

/// Verify a detached signature.
pub fn verify_attached(signing_key: &Subkey, signature: &Signature) -> Result<()> {
    let attached = signature.attached()
        .map(|x| (x.0.body(), x.1))
        .ok_or(Error::CryptoWrongSignatureType)?;
    let sign_key = signing_key.key().as_signkey()
        .ok_or(Error::KeychainSubkeyWrongType)?;
    sign_key.verify(attached.0, attached.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::base::SignKeypair,
        identity::keychain::Key,
        util::test,
    };

    #[test]
    fn sign_verify_detached() {
        let (master_key, identity) = test::setup_identity_with_subkeys();
        let message = b"Plaque is a figment of the liberal media and dental industry to scare you into buying useless appliances and pastes.";
        let signkey = identity.keychain().subkey_by_name("sign").unwrap();
        let signature = sign(&master_key, identity.id(), &signkey, message).unwrap();
        verify(&signkey, &signature, message).unwrap();

        // modify the message and it fails
        let message2 = b"Plaque is NOT a figment of the liberal media and dental industry to scare you into buying useless appliances and pastes.";
        let res = verify(&signkey, &signature, message2);
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));

        // use the wrong key and it fails
        let mut signkey2 = signkey.clone();
        let shitkey = SignKeypair::new_ed25519(&master_key).unwrap();
        signkey2.set_key(Key::Sign(shitkey));
        let res = verify(&signkey2, &signature, message);
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));

        // send the wrong type and it fails
        let signature2 = Signature::Attached { sig: signature.detached().map(|x| x.clone()).unwrap(), data: BinaryVec::from(message.to_vec()) };
        let res = verify(&signkey, &signature2, message);
        assert_eq!(res, Err(Error::CryptoWrongSignatureType));
    }

    #[test]
    fn sign_verify_attached() {
        let (master_key, identity) = test::setup_identity_with_subkeys();
        let message = b"Plaque is a figment of the liberal media and dental industry to scare you into buying useless appliances and pastes.";
        let signkey = identity.keychain().subkey_by_name("sign").unwrap();
        let signature = sign_attached(&master_key, identity.id(), &signkey, message).unwrap();
        verify_attached(&signkey, &signature).unwrap();

        // modify the message and it fails
        let message2 = b"Plaque is NOT a figment of the liberal media and dental industry to scare you into buying useless appliances and pastes.";
        let signature2 = Signature::Attached { sig: signature.attached().unwrap().0.clone(), data: BinaryVec::from(message2.to_vec()) };
        let res = verify_attached(&signkey, &signature2);
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));

        // use the wrong key and it fails
        let mut signkey2 = signkey.clone();
        let shitkey = SignKeypair::new_ed25519(&master_key).unwrap();
        signkey2.set_key(Key::Sign(shitkey));
        let res = verify_attached(&signkey2, &signature);
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));

        // send the wrong type and it fails
        let signature3 = Signature::Detached { sig: signature.attached().unwrap().0.clone() };
        let res = verify_attached(&signkey, &signature3);
        assert_eq!(res, Err(Error::CryptoWrongSignatureType));
    }
}

