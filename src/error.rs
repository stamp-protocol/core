//! The main error enum for the project lives here, and documents the various
//! conditions that can arise while interacting with the system.

use thiserror::Error;

/// This is our error enum. It contains an entry for any part of the system in
/// which an expectation is not met or a problem occurs.
#[derive(Error, Debug)]
pub enum Error {
    /// Trying to deserialize a value with the wrong length of data (ie, we
    /// usually see this when trying to populate a [u8; 64]
    #[error("incorrect data length")]
    BadLength,

    /// Trying to use an xchacha20poly1305 (or other) nonce with a
    /// NON-xchacha20poly1305 algo, or vice versa, etc.
    #[error("cryptographic algorithm mismatch")]
    CryptoAlgoMismatch,

    /// Bad key.
    #[error("key is invalid")]
    CryptoBadKey,

    /// Bad salt given to a cryptographic function.
    #[error("incorrect salt given for kdf")]
    CryptoBadSalt,

    /// Bad seed given to a cryptographic function.
    #[error("incorrect seed given for keypair")]
    CryptoBadSeed,

    /// Error creating hash digest
    #[error("could not create hash digest")]
    CryptoHashStateDigestError,

    /// Error creating hash state
    #[error("could not init hash state")]
    CryptoHashStateInitError,

    /// Error updating hash state
    #[error("could not update hash state")]
    CryptoHashStateUpdateError,

    /// HMAC failed to build properly
    #[error("HMAC failed to build properly")]
    CryptoHmacBuildFailure,

    /// An HMAC failed to verify.
    #[error("the given HMAC combo does not verify")]
    CryptoHmacVerificationFailed,

    /// Could not generate key from password
    #[error("key derivation from password failed")]
    CryptoKDFFailed,

    /// A key is missing from a crypto operation
    #[error("crypto key missing")]
    CryptoKeyMissing,

    /// Failed to obtain a memory lock
    #[error("failed to obtain memory lock")]
    CryptoMemLockFailed,

    /// Failed to release a memory lock
    #[error("failed to unlock memory")]
    CryptoMemUnlockFailed,

    /// Failed to open a sealed message. This is a bummer, man.
    #[error("failed to open a sealed object")]
    CryptoOpenFailed,

    /// Failed to seal a message.
    #[error("failed to seal a message")]
    CryptoSealFailed,

    /// Failed to produce a signature
    #[error("failed to create a signature")]
    CryptoSignatureFailed,

    /// A signature failed to verify.
    #[error("the given signature/public key/data combo does not verify")]
    CryptoSignatureVerificationFailed,

    /// The message being operated on is the wrong type (for instance, trying to
    /// `open()` a message created with `send_anonymous()`).
    #[error("the given message is in the wrong format")]
    CryptoWrongMessageType,

    /// The signature being operated on is the wrong type (for instance, trying
    /// to `verify()` a message created with `sign_attached()`).
    #[error("the given signature is in the wrong format")]
    CryptoWrongSignatureType,

    /// Could not build identity from DAG
    #[error("DAG build error")]
    DagBuildError,

    /// You're trying to create an identity on a non-empty transaction set. New
    /// identities can only be created on empty transaction sets.
    #[error("cannot create a new identity on an existing transaction chain")]
    DagCreateIdentityOnExistingChain,

    /// Tried to build an identity on an empty DAG chain.
    #[error("cannot build an identity from an empty transaction set")]
    DagEmpty,

    /// A key wasn't found when running a DAG operation
    #[error("key missing while processing transaction")]
    DagKeyNotFound,

    /// The DAG chain looped (so this is more of a DG or G than DAG)
    #[error("an endless loop occurred while processing the transaction set")]
    DagLoop,

    /// An identity was not passed in while applying a transaction
    #[error("an identity is missing when applying a transaction")]
    DagMissingIdentity,

    /// There are no transactions in this DAG chain that have zero previous
    /// transactions.
    #[error("this transaction set has no starting point")]
    DagNoGenesis,

    /// A generic error for when things get "weird" while ordering transactions
    #[error("an error occurred while ordering the transaction set")]
    DagOrderingError,

    /// An error while engaging in deserialization.
    #[error("ASN.1 deserialization error")]
    DeserializeASN,

    /// An error while engaging in deserialization.
    #[error("deserialization error")]
    DeserializeBase64(#[from] base64::DecodeError),

    /// A duplicate name was given.
    #[error("the given name is already in use (names must be unique)")]
    DuplicateName,

    /// The claim being operated on cannot be verified automatically
    #[error("this claim cannot be automatically verified")]
    IdentityClaimVerificationNotAllowed,

    /// The claim being operated on wasn't found
    #[error("identity claim not found")]
    IdentityClaimNotFound,

    /// The forward with that name couldn't be found
    #[error("that forward couldn't be found")]
    IdentityForwardNotFound,

    /// An operation is being performed on an object not owned by the current
    /// identity
    #[error("identity ID mismatch")]
    IdentityIDMismatch,

    /// The identity has no recovery policy but SOMEONE (*not naming any names*)
    /// is trying to execute a recovery request on it.
    #[error("this identity has no recovery policy")]
    IdentityMissingRecoveryPolicy,

    /// There were no private keys found in this identity.
    #[error("identity is not owned, but we attempted an operation requiring ownership")]
    IdentityNotOwned,

    /// This stamp is being duplicated
    #[error("identity stamp already exists")]
    IdentityStampAlreadyExists,

    /// The stamp being operated on wasn't found
    #[error("identity stamp not found")]
    IdentityStampNotFound,

    /// This subkey is already revoked.
    #[error("subkey is already revoked")]
    IdentitySubkeyAlreadyRevoked,

    /// The subkey being operated on wasn't found
    #[error("identity subkey not found")]
    IdentitySubkeyNotFound,

    /// The subkey being operated on is the wrong type
    #[error("the given subkey cannot be used for the requested operation")]
    IdentitySubkeyWrongType,

    /// Verification of an identity failed.
    #[error("Verification of identity failed: {0}")]
    IdentityVerificationFailed(String),

    /// An IO/net error
    #[error("io error {0:?}")]
    IoError(#[from] std::io::Error),

    /// Keygen failed
    #[error("keygen failed")]
    KeygenFailed,

    /// The request doesn't satisfy the policy. 20 beats your 5. I'm sorry, sir.
    #[error("the recovery request does not meet the policy's conditions")]
    PolicyConditionMismatch,

    /// A key cannot be verified against the executed recovery policy chain.
    #[error("policy verification of key failed")]
    PolicyVerificationFailure,

    /// Tried to open a private container that has no data
    #[error("attempt to open private object which has no data")]
    PrivateDataMissing,

    /// Error generating random numbers
    #[error("error generating random")]
    Random,

    /// The recovery policy request's identity does not match the identity we're
    /// recovering.
    #[error("this recovery request is for another identity")]
    RecoveryPolicyRequestIdentityMismatch,

    /// The recovery policy request's policy does not match the policy we're
    /// recovering against.
    #[error("this recovery request is for a different policy")]
    RecoveryPolicyRequestPolicyMismatch,

    /// An error while engaging in msgpack serialization.
    #[error("ASN.1 serialization error")]
    SerializeASN,

    /// An error while engaging in yaml serialization.
    #[error("yaml serialization error")]
    SerializeYaml(#[from] serde_yaml::Error),

    /// We're trying to verify a signature on a value, but it's missing.
    #[error("signature missing on a value")]
    SignatureMissing,

    /// Error parsing a URL
    #[error("URL parse error")]
    Url(#[from] url::ParseError)
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

