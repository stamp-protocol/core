//! The sign system allows creating cryptographic signatures which allow data
//! to be transmitted to others without fear of tampering.

use crate::{
    crypto::{
        SignedObject,
        key::{SecretKey, SignKeypairSignature},
    },
    error::{Error, Result},
    identity::{
        IdentityID,
        Subkey,
    },
    util::ser,
};
use serde_derive::{Serialize, Deserialize};

/// A cryptographic signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Signature {
    /// A detached signature
    Detached(SignedObject<SignKeypairSignature>),
    /// A signature with embedded data.
    Attached(SignedObject<SignKeypairSignature>, Vec<u8>),
}

impl Signature {
    /// If this signature is detached, return the signature.
    pub fn detached(&self) -> Option<&SignedObject<SignKeypairSignature>> {
        match self {
            Self::Detached(signed) => Some(signed),
            _ => None,
        }
    }

    /// If this signature has attached/embedded data, return the signature and
    /// data.
    pub fn attached(&self) -> Option<(&SignedObject<SignKeypairSignature>, &Vec<u8>)> {
        match self {
            Self::Attached(signed, data) => Some((signed, data)),
            _ => None,
        }
    }
}

impl ser::SerdeBinary for Signature {}

/// Sign a message with a private key, returning the detached signature.
pub fn sign(master_key: &SecretKey, signing_identity_id: &IdentityID, signing_key: &Subkey, message: &[u8]) -> Result<Signature> {
    let sign_key = signing_key.key().as_signkey()
        .ok_or(Error::IdentitySubkeyWrongType)?;
    let signature = sign_key.sign(master_key, message)?;
    Ok(Signature::Detached(SignedObject::new(signing_identity_id.clone(), signing_key.id().clone(), signature)))
}

/// Verify a detached signature.
pub fn verify(signing_key: &Subkey, signature: &Signature, message: &[u8]) -> Result<()> {
    let detached = signature.detached()
        .map(|x| x.body())
        .ok_or(Error::CryptoWrongSignatureType)?;
    let sign_key = signing_key.key().as_signkey()
        .ok_or(Error::IdentitySubkeyWrongType)?;
    sign_key.verify(detached, message)
}

/// Sign a message with a private key, returning the detached signature.
pub fn sign_attached(master_key: &SecretKey, signing_identity_id: &IdentityID, signing_key: &Subkey, message: &[u8]) -> Result<Signature> {
    let sign_key = signing_key.key().as_signkey()
        .ok_or(Error::IdentitySubkeyWrongType)?;
    let signature = sign_key.sign(master_key, message)?;
    Ok(Signature::Attached(SignedObject::new(signing_identity_id.clone(), signing_key.id().clone(), signature), message.to_vec()))
}

/// Verify a detached signature.
pub fn verify_attached(signing_key: &Subkey, signature: &Signature) -> Result<()> {
    let attached = signature.attached()
        .map(|x| (x.0.body(), x.1))
        .ok_or(Error::CryptoWrongSignatureType)?;
    let sign_key = signing_key.key().as_signkey()
        .ok_or(Error::IdentitySubkeyWrongType)?;
    sign_key.verify(attached.0, attached.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::key::SignKeypair,
        identity::Key,
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
        signkey2.key_mut().set_key(Key::Sign(shitkey));
        let res = verify(&signkey2, &signature, message);
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));

        // send the wrong type and it fails
        let signature2 = Signature::Attached(signature.detached().map(|x| x.clone()).unwrap(), message.to_vec());
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
        let signature2 = Signature::Attached(signature.attached().unwrap().0.clone(), message2.to_vec());
        let res = verify_attached(&signkey, &signature2);
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));

        // use the wrong key and it fails
        let mut signkey2 = signkey.clone();
        let shitkey = SignKeypair::new_ed25519(&master_key).unwrap();
        signkey2.key_mut().set_key(Key::Sign(shitkey));
        let res = verify_attached(&signkey2, &signature);
        assert_eq!(res, Err(Error::CryptoSignatureVerificationFailed));

        // send the wrong type and it fails
        let signature3 = Signature::Detached(signature.attached().unwrap().0.clone());
        let res = verify_attached(&signkey, &signature3);
        assert_eq!(res, Err(Error::CryptoWrongSignatureType));
    }
}

