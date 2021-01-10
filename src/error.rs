//! The main error enum for the project lives here, and documents the various
//! conditions that can arise while interacting with the system.

use thiserror::Error;

/// This is our error enum. It contains an entry for any part of the system in
/// which an expectation is not met or a problem occurs.
#[derive(Error, Debug)]
pub enum Error {
    /// Trying to use an xsalsa20poly1305 (or other) nonce with a
    /// NON-xsalsa20poly1305 algo, or vice versa, etc.
    #[error("cryptographic algorithm mismatch")]
    CryptoAlgoMismatch,

    /// Bad salt given to a cryptographic function.
    #[error("incorrect salt given for kdf")]
    CryptoBadSalt,

    /// Error creating hash digest
    #[error("could not create hash digest")]
    CryptoHashStateDigestError,

    /// Error creating hash state
    #[error("could not init hash state")]
    CryptoHashStateInitError,

    /// Error updating hash state
    #[error("could not update hash state")]
    CryptoHashStateUpdateError,

    /// An HMAC failed to verify.
    #[error("the given HMAC combo does not verify")]
    CryptoHmacVerificationFailed,

    /// Could not generate key from password
    #[error("key derivation from password failed")]
    CryptoKDFFailed,

    /// A key is missing from a crypto operation
    #[error("crypto key missing")]
    CryptoKeyMissing,

    /// Failed to open a sealed message. This is a bummer, man.
    #[error("failed to open a sealed object")]
    CryptoOpenFailed,

    /// Failed to produce a signature
    #[error("failed to create a signature")]
    CryptoSignatureFailed,

    /// A signature failed to verify.
    #[error("the given signature/public key/data combo does not verify")]
    CryptoSignatureVerificationFailed,

    /// An error while engaging in deserialization.
    #[error("deserialization error")]
    Deserialize(#[from] rmp_serde::decode::Error),

    /// The claim being operated on wasn't found
    #[error("identity claim not found")]
    IdentityClaimNotFound,

    /// The identity is missing one or more recovery key entries.
    #[error("identity missing recovery key")]
    IdentityRecoveryKeyMissing,

    /// The subkey being operated on wasn't found
    #[error("identity subkey not found")]
    IdentitySubkeyNotFound,

    /// Verification of an identity failed.
    #[error("Verification of identity failed: {0}")]
    IdentityVerificationFailed(String),

    /// An IO/net error
    #[error("io error {0:?}")]
    IoError(#[from] std::io::Error),

    /// Tried to open a private container that has no data
    #[error("attempt to open private object which has no data")]
    PrivateDataMissing,

    /// An error while engaging in msgpack serialization.
    #[error("msgpack serialization error")]
    SerializeMsgPack(#[from] rmp_serde::encode::Error),

    /// An error while engaging in yaml serialization.
    #[error("yaml serialization error")]
    SerializeYaml(#[from] serde_yaml::Error),

    #[cfg(test)]
    #[error("generic serialization error")]
    SerializeError,
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        // i'm sorry...
        //
        // TODO: implement a real PartialEq. cannot derive because
        // std::io::Error et al are not eq-able. tonight we dine in hell.
        format!("{:?}", self) == format!("{:?}", other)
    }
}

/// Wraps `std::result::Result` around our `Error` enum
pub type Result<T> = std::result::Result<T, Error>;

