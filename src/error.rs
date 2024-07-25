//! The main error enum for the project lives here, and documents the various
//! conditions that can arise while interacting with the system.

use thiserror::Error;

/// This is our error enum. It contains an entry for any part of the system in
/// which an expectation is not met or a problem occurs.
#[derive(Error, Debug)]
pub enum Error {
    /// An error while engaging in deserialization.
    #[error("ASN.1 deserialization error")]
    ASNDeserialize(rasn::error::DecodeErrorKind),

    /// An error while engaging in msgpack serialization.
    #[error("ASN.1 serialization error")]
    ASNSerialize,

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

    /// An MAC failed to verify.
    #[error("the given MAC combo does not verify")]
    CryptoHmacVerificationFailed,

    /// Could not generate key from another key (HKDF)
    #[error("key derivation from secret failed")]
    CryptoHKDFFailed,

    /// Could not generate key from password
    #[error("key derivation from password failed")]
    CryptoKDFFailed,

    /// A key is missing from a crypto operation
    #[error("crypto key missing")]
    CryptoKeyMissing,

    /// Failed to open a sealed message. This is a bummer, man.
    #[error("failed to open a sealed object")]
    CryptoOpenFailed,

    /// Failed to seal a message.
    #[error("failed to seal a message")]
    CryptoSealFailed,

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

    /// An identity was not passed in while applying a transaction
    #[error("an identity is missing when applying a transaction")]
    DagMissingIdentity,

    /// There was a problem finding our singular genesis transaction.
    #[error("this transaction set has no single starting point")]
    DagGenesisError,

    /// A transaction was referenced but is missing from a DAG.
    #[error("missing transaction referenced in DAG: {0}")]
    DagMissingTransaction(String),

    /// Found a transaction that references other transactions (via its
    /// `previous_transactions`) in the DAG that do not exist.
    #[error("orphaned transaction found {0}")]
    DagOrphanedTransaction(String),

    /// An error while engaging in deserialization.
    #[error("deserialization error")]
    DeserializeBase64(#[from] base64::DecodeError),

    /// Trying to sign a transaction with a key that has already signed this transaction.
    #[error("duplicate signature")]
    DuplicateSignature,

    /// A duplicate transaction was pushed to the transaction list
    #[error("a duplicate transaction was pushed to the transaction list")]
    DuplicateTransaction,

    /// A glob pattern failed to build
    #[error("glob compilation error")]
    GlobError(#[from] glob::PatternError),

    /// The claim being operated on cannot be verified automatically
    #[error("this claim cannot be automatically verified")]
    IdentityClaimVerificationNotAllowed,

    /// The claim being operated on wasn't found
    #[error("identity claim not found")]
    IdentityClaimNotFound,

    /// There were no private keys found in this identity.
    #[error("identity is not owned, but we attempted an operation requiring ownership")]
    IdentityNotOwned,

    /// The stamp being operated on wasn't found
    #[error("identity stamp not found")]
    IdentityStampNotFound,

    /// An IO/net error
    #[error("io error {0:?}")]
    IoError(#[from] std::io::Error),

    /// Key not found in [Keychain][crate::identity::keychain::Keychain].
    #[error("keychain key not found: {0}")]
    KeychainKeyNotFound(crate::crypto::base::KeyID),

    /// The subkey being operated on is the wrong type
    #[error("the given subkey cannot be used for the requested operation")]
    KeychainSubkeyWrongType,

    /// The request doesn't satisfy the policy. 20 beats your 5. I'm sorry, sir.
    #[error("the recovery request does not meet the policy's conditions")]
    MultisigPolicyConditionMismatch,

    /// A given policy does not have the capabilities required to perform the
    /// requested action.
    #[error("the policy does not have the capabilities required to perform that action")]
    PolicyCapabilityMismatch,

    /// A capability matched but the context did not
    #[error("the policy does not allow that action in the given context")]
    PolicyContextMismatch,

    /// No policy/capability matched the transaction
    #[error("no matching policy/capability found for the given transaction")]
    PolicyNotFound,

    /// Tried to open a private container that has no data
    #[error("attempt to open private object which has no data")]
    PrivateDataMissing,

    /// An error while engaging in yaml serialization.
    #[error("yaml serialization error")]
    SerializeYaml(#[from] serde_yaml::Error),

    /// The hash of a transaction's body does not match its ID. He's tampered
    /// with it.
    #[error("transaction ID mismatch: {0}")]
    TransactionIDMismatch(crate::dag::TransactionID),

    /// Expected one transaction, got another.
    #[error("transaction mismatch")]
    TransactionMismatch,

    /// This transaction cannot be saved
    #[error("transaction cannot be saved: {0}")]
    TransactionInvalid(String),

    /// This transaction has no signatures. Why don't you try and get one?
    #[error("transaction has no signatures")]
    TransactionNoSignatures,

    /// A signature on a transaction is not valid.
    #[error("transaction signature invalid: {0:?}")]
    TransactionSignatureInvalid(crate::identity::keychain::AdminKeypairPublic),

    /// A missing value was encountered when calculating trust
    #[error("trust calculation had a missing value")]
    TrustMissingValue,

    /// Error parsing a URL
    #[error("URL parse error")]
    Url(#[from] url::ParseError),
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
