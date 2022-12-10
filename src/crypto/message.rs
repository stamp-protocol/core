//! The message system allows sending of messages between identities in a secure
//! manner.

use crate::{
    crypto::{
        SignedObject,
        base::{SecretKey, CryptoKeypairMessage},
    },
    error::{Error, Result},
    identity::{
        identity::{IdentityID},
        keychain::Subkey,
    },
    util::ser,
};
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};

/// A wrapper around some encrypted message data, allowing us to provide easy
/// serialization/deserialization methods.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Message {
    /// An anonymous message without any signature information.
    #[rasn(tag(explicit(0)))]
    Anonymous(Vec<u8>),
    /// A message signed by the sender that the recipient can use to verify the
    /// message came from where they think it came from.
    #[rasn(tag(explicit(1)))]
    Signed(SignedObject<CryptoKeypairMessage>),
}

impl Message {
    /// If this message is anonymous, returns the data of the anonymous message.
    pub fn anonymous(&self) -> Option<&Vec<u8>> {
        match self {
            Self::Anonymous(anon) => Some(anon),
            _ => None,
        }
    }

    /// IF this message is signed, returns the data of the signed message.
    pub fn signed(&self) -> Option<&SignedObject<CryptoKeypairMessage>> {
        match self {
            Self::Signed(signed) => Some(signed),
            _ => None,
        }
    }
}

impl ser::SerdeBinary for Message {}

/// Send a message to an identity.
///
/// We use the sender's/recipient's subkeys for messaging, which is the most
/// general container we can use (passing just an identity object won't do here
/// because an identity could have many CryptoKeypairs).
pub fn send(sender_master_key: &SecretKey, sender_identity_id: &IdentityID, sender_key: &Subkey, recipient_key: &Subkey, message: &[u8]) -> Result<Message> {
    let sender_crypto = sender_key.key().as_cryptokey()
        .ok_or(Error::KeychainSubkeyWrongType)?;
    let recipient_crypto = recipient_key.key().as_cryptokey()
        .ok_or(Error::KeychainSubkeyWrongType)?;
    let sealed = recipient_crypto.seal(sender_master_key, sender_crypto, message)?;
    let key_id = sender_key.key_id();
    let signed_msg = SignedObject::new(sender_identity_id.clone(), key_id, sealed);
    Ok(Message::Signed(signed_msg))
}

/// Open a message sent with [send].
///
/// Note that we need the sender's public key to verify the signature on the
/// message, which signs the *outside* of the message (not the inside).
pub fn open(recipient_master_key: &SecretKey, recipient_key: &Subkey, sender_key: &Subkey, sealed: &Message) -> Result<Vec<u8>> {
    let sender_crypto = sender_key.key().as_cryptokey()
        .ok_or(Error::KeychainSubkeyWrongType)?;
    let recipient_crypto = recipient_key.key().as_cryptokey()
        .ok_or(Error::KeychainSubkeyWrongType)?;
    let signed_message = match sealed {
        Message::Signed(SignedObject { ref body, .. }) => body,
        _ => Err(Error::CryptoWrongMessageType)?,
    };
    recipient_crypto.open(recipient_master_key, sender_crypto, signed_message)
}

/// Send an anonymous message.
///
/// Anonymous messages are not signed by the sender, so their source cannot be
/// cryptographically verified.
pub fn send_anonymous(recipient_key: &Subkey, message: &[u8]) -> Result<Message> {
    let recipient_crypto = recipient_key.key().as_cryptokey()
        .ok_or(Error::KeychainSubkeyWrongType)?;
    let sealed = recipient_crypto.seal_anonymous(message)?;
    Ok(Message::Anonymous(sealed))
}

/// Open an anonymous message send with [send_anonymous].
pub fn open_anonymous(recipient_master_key: &SecretKey, recipient_key: &Subkey, sealed: &Message) -> Result<Vec<u8>> {
    let recipient_crypto = recipient_key.key().as_cryptokey()
        .ok_or(Error::KeychainSubkeyWrongType)?;
    let anon_message = match sealed {
        Message::Anonymous(ref data) => data,
        _ => Err(Error::CryptoWrongMessageType)?,
    };
    recipient_crypto.open_anonymous(recipient_master_key, anon_message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::base::{KeyID, CryptoKeypair},
        identity::{
            Key,
        },
        util::test,
    };

    #[test]
    fn message_anonymous_signed_maybe() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let sender_key = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let recipient_key = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();

        let sealed = recipient_key.seal(&master_key, &sender_key, b"'I KNOW!' SAID THE BOY, AS HE LEAPT TO HIS FEET").unwrap();
        let msg1 = Message::Signed(SignedObject::new(IdentityID::blank(), KeyID::random_crypto(), sealed));
        let msg2 = Message::Anonymous(vec![1, 2, 3, 42]);

        assert_eq!(msg1.anonymous(), None);
        match msg1.signed() {
            Some(signed) => {
                assert_eq!(signed.signed_by_identity(), &IdentityID::blank());
            }
            _ => panic!("Invalid return for signed"),
        }
        assert_eq!(msg2.anonymous(), Some(&vec![1, 2, 3, 42]));
        assert_eq!(msg2.signed().is_none(), true);
    }

    #[test]
    fn msg_send_open() {
        let (sender_master_key, sender_identity) = test::setup_identity_with_subkeys();
        let (recipient_master_key, recipient_identity) = test::setup_identity_with_subkeys();

        let sender_subkey = sender_identity.keychain().subkey_by_name("cryptololol").unwrap();
        let recipient_subkey = recipient_identity.keychain().subkey_by_name("cryptololol").unwrap();

        let msg = b"And if you ever put your goddamn hands on my wife again, I will...";
        let sealed = send(&sender_master_key, sender_identity.id(), &sender_subkey, recipient_subkey, msg).unwrap();
        match sealed {
            Message::Signed(_) => {},
            _ => panic!("Bad message format returned"),
        }
        let opened = open(&recipient_master_key, &recipient_subkey, &sender_subkey, &sealed).unwrap();

        // Now read it back to me, Francine
        assert_eq!(opened.as_slice(), msg);

        // modify the stinkin' message and verify it fails
        let mut sealed2 = sealed.clone();
        match &mut sealed2 {
            Message::Signed(SignedObject { body: ref mut cm, .. }) => {
                let cipher = cm.ciphertext_mut();
                let len = cipher.len();
                let val = &mut cipher[len - 3];
                // modify the ciphertext
                if val == &mut 42 { *val = 17; } else { *val = 42; }
            }
            _ => panic!("How??"),
        }
        let res = open(&recipient_master_key, &recipient_subkey, &sender_subkey, &sealed2);
        assert_eq!(res, Err(Error::CryptoOpenFailed));

        // now generate a NEW crypto key and try to open the message with it.
        let sender_identity2 = sender_identity
            .add_subkey(Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(&sender_master_key).unwrap()), "fake-ass-key", None).unwrap();
        let sender_fake_subkey = sender_identity2.keychain().subkey_by_name("fake-ass-key").unwrap();
        let res = open(&recipient_master_key, &recipient_subkey, &sender_fake_subkey, &sealed);
        assert_eq!(res, Err(Error::CryptoOpenFailed));

        let res = open_anonymous(&recipient_master_key, &recipient_subkey, &sealed);
        assert_eq!(res, Err(Error::CryptoWrongMessageType));
    }

    #[test]
    fn msg_send_open_anonymous() {
        let (recipient_master_key, recipient_identity) = test::setup_identity_with_subkeys();

        let recipient_subkey = recipient_identity.keychain().subkey_by_name("cryptololol").unwrap();

        let msg = b"The government protecting their profits from the poor. The rich and the fortunate chaining up the door";
        let sealed = send_anonymous(&recipient_subkey, msg).unwrap();
        match sealed {
            Message::Anonymous(_) => {},
            _ => panic!("Bad message format returned"),
        }
        let opened = open_anonymous(&recipient_master_key, &recipient_subkey, &sealed).unwrap();
        assert_eq!(opened.as_slice(), msg);

        // modify the stinkin' message and verify it fails
        let mut sealed2 = sealed.clone();
        match &mut sealed2 {
            Message::Anonymous(ref mut cipher) => {
                let len = cipher.len();
                let val = &mut cipher[len - 3];
                // modify the ciphertext
                if val == &mut 42 { *val = 17; } else { *val = 42; }
            }
            _ => panic!("How??"),
        }
        let res = open_anonymous(&recipient_master_key, &recipient_subkey, &sealed2);
        assert_eq!(res, Err(Error::CryptoOpenFailed));
    }
}

