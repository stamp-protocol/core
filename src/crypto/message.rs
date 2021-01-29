//! The message system allows sending of messages between identities in a secure
//! manner.

use crate::{
    crypto::key::{SecretKey, CryptoKeypair},
    error::{Error, Result},
    identity::{
        VersionedIdentity,
        keychain::Subkey,
    },
};
use getset;
use serde_derive::{Serialize, Deserialize};

/// A wrapper around some encrypted message data, allowing us to provide easy
/// serialization/deserialization methods.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Message {
    /// The message's encrypted data.
    data: Vec<u8>,
}

/*
/// Send a message to an identity.
///
/// We use the sender's/recipient's subkeys for messaging, which is the most
/// general container we can use (passing just an identity object won't do here
/// because an identity could have many CryptoKeypairs).
pub fn send(sender_master_key: &SecretKey, sender_key: &Subkey, recipient_key: &Subkey, message: &[u8]) -> Result<Message> {
    let sender_crypto = sender_key.key().as_cryptokey()
        .ok_or(Error::IdentitySubkeyWrongType)?;
    let recipient_crypto = recipient_key.key().as_cryptokey()
        .ok_or(Error::IdentitySubkeyWrongType)?;
    let sealed = recipient_crypto.seal(sender_master_key, &sender_crypto
    Ok(Message{data: vec![]})
}
*/

