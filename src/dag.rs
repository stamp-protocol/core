//! A DAG, or directed acyclic graph, allows us to represent our identity as an
//! ordered list of signed changes, as opposed to a singular object. There are
//! pros and cons to both methods, but for the purposes of this project, a
//! tree of signed transactions that link back to previous changes provides a
//! good amount of security, auditability, and syncability.

use crate::{
    error::{Error, Result},
    crypto::{
        key::{SecretKey, SignKeypairSignature},
    },
    identity::{
        claim::{
            ClaimID,
            ClaimSpec,
        },
        identity::{
            IdentityID,
            ForwardType,
            Identity,
        },
        keychain::{
            ExtendKeypair,
            AlphaKeypair,
            AlphaKeypairSignature,
            PolicyKeypair,
            PolicyKeypairSignature,
            PublishKeypair,
            RootKeypair,
            RootKeypairSignature,
            Key,
            RevocationReason,
        },
        recovery::{
            PolicyID,
            PolicyCondition,
            PolicyRequest,
            PolicyRequestAction,
        },
        stamp::{
            StampID,
            Stamp,
        },
    },
    util::{
        Public,
        PublicMaybe,
        Timestamp,
        ser::{self, SerdeBinary},
    },
};
use getset;
use rasn::{Encode, Decode, AsnType};
use serde_derive::{Serialize, Deserialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

/// This is all of the possible transactions that can be performed on an
/// identity, including the data they require.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum TransactionBody {
    /// Used when a transaction's entire body is private data and we wish to
    /// still include the transaction, but hide the body.
    ///
    /// For instance, if adding a `SecretKey` subkey, there is no public
    /// component to the transaction body, only private data. So if we're
    /// stripping private data, the entire transaction body would be blank. We
    /// need to show something for each transaction though, and using an Option
    /// doesn't make sense just for this one case, so this allows us to still
    /// include a transaction body without needing to use "tricks" in a higher
    /// container.
    Private,

    #[rasn(tag(explicit(0)))]
    CreateIdentityV1 {
        #[rasn(tag(explicit(0)))]
        alpha: AlphaKeypair,
        #[rasn(tag(explicit(1)))]
        policy: PolicyKeypair,
        #[rasn(tag(explicit(2)))]
        publish: PublishKeypair,
        #[rasn(tag(explicit(3)))]
        root: RootKeypair,
    },
    #[rasn(tag(explicit(1)))]
    SetRecoveryPolicyV1 {
        #[rasn(tag(explicit(0)))]
        policy: Option<PolicyCondition>,
    },
    #[rasn(tag(explicit(2)))]
    ExecuteRecoveryPolicyV1 {
        #[rasn(tag(explicit(0)))]
        request: PolicyRequest,
    },
    #[rasn(tag(explicit(3)))]
    MakeClaimV1 {
        #[rasn(tag(explicit(0)))]
        spec: ClaimSpec,
    },
    #[rasn(tag(explicit(4)))]
    DeleteClaimV1 {
        #[rasn(tag(explicit(0)))]
        claim_id: ClaimID,
    },
    #[rasn(tag(explicit(5)))]
    AcceptStampV1 {
        #[rasn(tag(explicit(0)))]
        stamp: Stamp,
    },
    #[rasn(tag(explicit(6)))]
    DeleteStampV1 {
        #[rasn(tag(explicit(0)))]
        stamp_id: StampID,
    },
    #[rasn(tag(explicit(7)))]
    SetPolicyKeyV1 {
        #[rasn(tag(explicit(0)))]
        keypair: PolicyKeypair,
        #[rasn(tag(explicit(1)))]
        reason: RevocationReason,
    },
    #[rasn(tag(explicit(8)))]
    SetPublishKeyV1 {
        #[rasn(tag(explicit(0)))]
        keypair: PublishKeypair,
        #[rasn(tag(explicit(1)))]
        reason: RevocationReason,
    },
    #[rasn(tag(explicit(9)))]
    SetRootKeyV1 {
        #[rasn(tag(explicit(0)))]
        keypair: RootKeypair,
        #[rasn(tag(explicit(1)))]
        reason: RevocationReason,
    },
    #[rasn(tag(explicit(10)))]
    AddSubkeyV1 { 
        #[rasn(tag(explicit(0)))]
        key: Key,
        #[rasn(tag(explicit(1)))]
        name: String,
        #[rasn(tag(explicit(2)))]
        desc: Option<String>,
    },
    #[rasn(tag(explicit(11)))]
    EditSubkeyV1 {
        #[rasn(tag(explicit(0)))]
        name: String,
        #[rasn(tag(explicit(1)))]
        new_name: String,
        #[rasn(tag(explicit(2)))]
        desc: Option<String>,
    },
    #[rasn(tag(explicit(12)))]
    RevokeSubkeyV1 {
        #[rasn(tag(explicit(0)))]
        name: String,
        #[rasn(tag(explicit(1)))]
        reason: RevocationReason,
        #[rasn(tag(explicit(2)))]
        new_name: Option<String>,
    },
    #[rasn(tag(explicit(13)))]
    DeleteSubkeyV1 {
        #[rasn(tag(explicit(0)))]
        name: String,
    },
    #[rasn(tag(explicit(14)))]
    SetNicknameV1 {
        #[rasn(tag(explicit(0)))]
        nickname: Option<String>,
    },
    #[rasn(tag(explicit(15)))]
    AddForwardV1 {
        #[rasn(tag(explicit(0)))]
        name: String,
        #[rasn(tag(explicit(1)))]
        ty: ForwardType,
        #[rasn(tag(explicit(2)))]
        default: bool,
    },
    #[rasn(tag(explicit(16)))]
    DeleteForwardV1 { 
        #[rasn(tag(explicit(0)))]
        name: String,
    },
}

impl TransactionBody {
    /// Reencrypt this transaction body
    fn reencrypt(self, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let new_self = match self {
            Self::Private => Self::Private,
            Self::CreateIdentityV1 { alpha, policy, publish, root } => {
                let new_alpha = alpha.reencrypt(old_master_key, new_master_key)?;
                let new_policy = policy.reencrypt(old_master_key, new_master_key)?;
                let new_publish = publish.reencrypt(old_master_key, new_master_key)?;
                let new_root = root.reencrypt(old_master_key, new_master_key)?;
                Self::CreateIdentityV1 {
                    alpha: new_alpha,
                    policy: new_policy,
                    publish: new_publish,
                    root: new_root,
                }
            }
            Self::SetRecoveryPolicyV1 { policy } => Self::SetRecoveryPolicyV1 { policy },
            Self::ExecuteRecoveryPolicyV1 { request } => Self::ExecuteRecoveryPolicyV1 {
                request: request.reencrypt(old_master_key, new_master_key)?,
            },
            Self::MakeClaimV1 { spec } => Self::MakeClaimV1 {
                spec: spec.reencrypt(old_master_key, new_master_key)?,
            },
            Self::DeleteClaimV1 { claim_id } => Self::DeleteClaimV1 { claim_id },
            Self::AcceptStampV1 { stamp } => Self::AcceptStampV1 { stamp },
            Self::DeleteStampV1 { stamp_id } => Self::DeleteStampV1 { stamp_id },
            Self::SetPolicyKeyV1 { keypair, reason } => {
                let new_keypair = keypair.reencrypt(old_master_key, new_master_key)?;
                Self::SetPolicyKeyV1 { keypair: new_keypair, reason }
            }
            Self::SetPublishKeyV1 { keypair, reason } => {
                let new_keypair = keypair.reencrypt(old_master_key, new_master_key)?;
                Self::SetPublishKeyV1 { keypair: new_keypair, reason }
            }
            Self::SetRootKeyV1 { keypair, reason } => {
                let new_keypair = keypair.reencrypt(old_master_key, new_master_key)?;
                Self::SetRootKeyV1 { keypair: new_keypair, reason }
            }
            Self::AddSubkeyV1 { key, name, desc } => {
                let new_subkey = key.reencrypt(old_master_key, new_master_key)?;
                Self::AddSubkeyV1 { key: new_subkey, name, desc }
            }
            Self::EditSubkeyV1 { name, new_name, desc } => Self::EditSubkeyV1 { name, new_name, desc },
            Self::RevokeSubkeyV1 { name, reason, new_name } => Self::RevokeSubkeyV1 { name, reason, new_name },
            Self::DeleteSubkeyV1 { name } => Self::DeleteSubkeyV1 { name },
            Self::SetNicknameV1 { nickname } => Self::SetNicknameV1 { nickname },
            Self::AddForwardV1 { name, ty, default } => Self::AddForwardV1 { name, ty, default },
            Self::DeleteForwardV1 { name } => Self::DeleteForwardV1 { name },
        };
        Ok(new_self)
    }
}

impl Public for TransactionBody {
    fn strip_private(&self) -> Self {
        match self.clone() {
            Self::Private => Self::Private,
            Self::CreateIdentityV1 { alpha, policy, publish, root } => {
                Self::CreateIdentityV1 {
                    alpha: alpha.strip_private(),
                    policy: policy.strip_private(),
                    publish: publish.strip_private(),
                    root: root.strip_private(),
                }
            }
            Self::SetRecoveryPolicyV1 { policy } => Self::SetRecoveryPolicyV1 { policy },
            Self::ExecuteRecoveryPolicyV1 { request } => Self::ExecuteRecoveryPolicyV1 { request: request.strip_private() },
            Self::MakeClaimV1 { spec } => Self::MakeClaimV1 { spec: spec.strip_private() },
            Self::DeleteClaimV1 { claim_id } => Self::DeleteClaimV1 { claim_id },
            Self::AcceptStampV1 { stamp } => Self::AcceptStampV1 { stamp: stamp.strip_private() },
            Self::DeleteStampV1 { stamp_id } => Self::DeleteStampV1 { stamp_id },
            Self::SetPolicyKeyV1 { keypair, reason } => {
                Self::SetPolicyKeyV1 {
                    keypair: keypair.strip_private(),
                    reason,
                }
            }
            Self::SetPublishKeyV1 { keypair, reason } => {
                Self::SetPublishKeyV1 {
                    keypair: keypair.strip_private(),
                    reason,
                }
            }
            Self::SetRootKeyV1 { keypair, reason } => {
                Self::SetRootKeyV1 {
                    keypair: keypair.strip_private(),
                    reason,
                }
            }
            Self::AddSubkeyV1 { key, name, desc } => {
                // here's a good place to use Self::Private -- if stripping the
                // key removes ALL of its data, then we probably don't want to
                // include the transaction body.
                match key.strip_private_maybe() {
                    Some(stripped) => Self::AddSubkeyV1 { key: stripped, name, desc },
                    None => Self::Private,
                }
            }
            Self::EditSubkeyV1 { name, new_name, desc: new_desc } => Self::EditSubkeyV1 { name, new_name, desc: new_desc },
            Self::RevokeSubkeyV1 { name, reason, new_name } => Self::RevokeSubkeyV1 { name, reason, new_name },
            Self::DeleteSubkeyV1 { name } => Self::DeleteSubkeyV1 { name },
            Self::SetNicknameV1 { nickname } => Self::SetNicknameV1 { nickname },
            Self::AddForwardV1 { name, ty, default } => Self::AddForwardV1 { name, ty, default },
            Self::DeleteForwardV1 { name } => Self::DeleteForwardV1 { name },
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::Private => false,
            Self::CreateIdentityV1 { alpha, policy, publish, root } => {
                alpha.has_private() || policy.has_private() || publish.has_private() || root.has_private()
            }
            Self::SetRecoveryPolicyV1 { .. } => false,
            Self::ExecuteRecoveryPolicyV1 { request } => request.has_private(),
            Self::MakeClaimV1 { spec } => spec.has_private(),
            Self::DeleteClaimV1 { .. } => false,
            Self::AcceptStampV1 { .. } => false,
            Self::DeleteStampV1 { .. } => false,
            Self::SetPolicyKeyV1 { keypair, .. } => keypair.has_private(),
            Self::SetPublishKeyV1 { keypair, .. } => keypair.has_private(),
            Self::SetRootKeyV1 { keypair, .. } => keypair.has_private(),
            Self::AddSubkeyV1 { key, .. } => key.has_private(),
            Self::EditSubkeyV1 { .. } => false,
            Self::RevokeSubkeyV1 { .. } => false,
            Self::DeleteSubkeyV1 { .. } => false,
            Self::SetNicknameV1 { .. } => false,
            Self::AddForwardV1 { .. } => false,
            Self::DeleteForwardV1 { .. } => false,
        }
    }
}

/// The TransactionID holds the signature of a transaction by a particular key.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum TransactionID {
    #[rasn(tag(explicit(0)))]
    Alpha(AlphaKeypairSignature),
    #[rasn(tag(explicit(1)))]
    Policy(PolicyKeypairSignature),
    #[rasn(tag(explicit(2)))]
    Root(RootKeypairSignature),
}

impl Deref for TransactionID {
    type Target = SignKeypairSignature;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Alpha(inner) => inner.deref(),
            Self::Policy(inner) => inner.deref(),
            Self::Root(inner) => inner.deref(),
        }
    }
}

impl From<TransactionID> for String {
    fn from(id: TransactionID) -> Self {
        ser::base64_encode(id.deref().as_ref())
    }
}

impl From<&TransactionID> for String {
    fn from(id: &TransactionID) -> Self {
        ser::base64_encode(id.deref().as_ref())
    }
}

impl Hash for TransactionID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let stringified = String::from(self.clone());
        stringified.hash(state);
    }
}

impl Eq for TransactionID {}

#[cfg(test)]
impl TransactionID {
    pub(crate) fn random_alpha() -> Self {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let sig = alpha_keypair.sign(&master_key, "hi im jerry".as_bytes()).unwrap();
        Self::Alpha(sig)
    }
}

/// The body of an identity transaction. Holds the transaction's references to
/// its previous transactions and the transaction type/data itself.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct TransactionEntry {
    /// When this transaction was created.
    #[rasn(tag(explicit(0)))]
    created: Timestamp,
    /// This is a list of previous transactions that are not already listed by
    /// another transaction.
    ///
    /// In general, this will only list the last transaction, but it's possible
    /// that you might make two separate changes on two separate devices and
    /// when they sync, you will have two leading transactions. The next change
    /// you make to your identity would sign both of those transactions, and
    /// merge the "tree" back into a single trunk.
    ///
    /// Note that when listing previous transactions, their `created` times must
    /// be *less than* this transaction's created time. Future transactions
    /// cannot be signed into a past one.
    #[rasn(tag(explicit(1)))]
    previous_transactions: Vec<TransactionID>,
    /// This holds the actual transaction data.
    #[rasn(tag(explicit(2)))]
    body: TransactionBody,
}

impl TransactionEntry {
    /// Create a new entry.
    fn new<T: Into<Timestamp>>(created: T, previous_transactions: Vec<TransactionID>, body: TransactionBody) -> Self {
        Self {
            created: created.into(),
            previous_transactions,
            body,
        }
    }
}

impl Public for TransactionEntry {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_body(self.body().strip_private());
        clone
    }

    fn has_private(&self) -> bool {
        self.body().has_private()
    }
}

/// A transaction represents a single change on an identity object. In order to
/// build an identity, all transactions are played in order from start to finish.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Transaction {
    /// This is a signature of this transaction's `entry`.
    #[rasn(tag(explicit(0)))]
    id: TransactionID,
    /// This holds our transaction body: any references to previous
    /// transactions as well as the transaction type/data.
    #[rasn(tag(explicit(1)))]
    entry: TransactionEntry,
}

impl Transaction {
    pub(crate) fn new(master_key: &SecretKey, identity_maybe: &Option<Identity>, sign_with: SignWith, entry: TransactionEntry) -> Result<Self> {
        let serialized = ser::serialize(&entry.strip_private())?;
        let id = match identity_maybe.as_ref() {
            // we have an identity, meaning this is NOT a create/genesis trans
            // and we can pull the keys directly from the identity object itself...
            Some(identity) => {
                let regular_ol_sign = || -> Result<TransactionID> {
                    Ok(match sign_with {
                        SignWith::Alpha => TransactionID::Alpha(identity.keychain().alpha().sign(master_key, serialized.as_slice())?),
                        SignWith::Policy => TransactionID::Policy(identity.keychain().policy().sign(master_key, serialized.as_slice())?),
                        SignWith::Root => TransactionID::Root(identity.keychain().root().sign(master_key, serialized.as_slice())?),
                    })
                };
                // ...unless we're executing a recovery policy, in which case
                // the signature must come from the POLICY key
                match entry.body() {
                    TransactionBody::CreateIdentityV1 { .. } => Err(Error::DagCreateIdentityOnExistingChain)?,
                    TransactionBody::ExecuteRecoveryPolicyV1 { request } => {
                        match request.entry().action() {
                            PolicyRequestAction::ReplaceKeys { policy, .. } => {
                                match sign_with {
                                    SignWith::Policy => TransactionID::Policy(policy.sign(master_key, serialized.as_slice())?),
                                    // recovery transactions must be signed by
                                    // new root key
                                    _ => Err(Error::DagKeyNotFound)?,
                                }
                            }
                        }
                    }
                    _ => regular_ol_sign()?
                }
            }
            // we do NOT have an identity, meaning this transaction is likely
            // the one creating the identity. so we search for the key we need
            // (always the alpha for the creation) within the body of the
            // transaction itself.
            None => {
                match entry.body() {
                    TransactionBody::CreateIdentityV1 { ref alpha, .. } => {
                        match sign_with {
                            SignWith::Alpha => TransactionID::Alpha(alpha.sign(master_key, serialized.as_slice())?),
                            // you can only sign a blank identity with the alpha key
                            _ => Err(Error::DagKeyNotFound)?,
                        }
                    }
                    _ => Err(Error::DagKeyNotFound)?,
                }
            }
        };
        Ok(Self {
            id,
            entry,
        })
    }

    /// Verify this transaction's signature against its public data.
    pub(crate) fn verify(&self, identity_maybe: Option<&Identity>) -> Result<()> {
        let serialized = ser::serialize(&self.entry().strip_private())?;
        match identity_maybe.as_ref() {
            // if we have an identity, we can verify this transaction using the
            // public keys contained in the identity
            Some(identity) => {
                let regular_ol_verify = || {
                    match self.id() {
                        TransactionID::Alpha(ref sig) => identity.keychain().alpha().verify(sig, &serialized),
                        TransactionID::Policy(ref sig) => identity.keychain().policy().verify(sig, &serialized),
                        TransactionID::Root(ref sig) => identity.keychain().root().verify(sig, &serialized),
                    }
                };
                match self.entry().body() {
                    TransactionBody::ExecuteRecoveryPolicyV1 { request } => {
                        match request.entry().action() {
                            PolicyRequestAction::ReplaceKeys { policy, .. } => {
                                match self.id() {
                                    TransactionID::Policy(ref sig) => policy.verify(sig, &serialized),
                                    // recovery transactions must be signed by
                                    // new root key
                                    _ => Err(Error::DagKeyNotFound)?,
                                }
                            }
                        }
                    }
                    _ => regular_ol_verify(),
                }
            }
            // we don't have an identity, so this is necessarily the genesis
            // transaction that creates it.
            None => {
                match self.entry().body() {
                    TransactionBody::CreateIdentityV1 { ref alpha, .. } => {
                        match self.id() {
                            TransactionID::Alpha(ref sig) => alpha.verify(sig, &serialized),
                            // genesis transaction must be signed by alpha
                            _ => Err(Error::DagKeyNotFound)?,
                        }
                    }
                    _ => Err(Error::DagKeyNotFound)?,
                }
            }
        }
    }

    /// Reencrypt this transaction.
    fn reencrypt(mut self, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let new_body = self.entry().body().clone().reencrypt(old_master_key, new_master_key)?;
        self.entry_mut().set_body(new_body);
        Ok(self)
    }
}

impl Public for Transaction {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_entry(self.entry().strip_private());
        clone
    }

    fn has_private(&self) -> bool {
        self.entry().has_private()
    }
}

/// A trait used for grabbing information about transactions that allows us to
/// build a DAG or ordered list of transactions from them.
pub trait GraphInfo {
    /// Grab the ID for this transaction.
    fn id(&self) -> &TransactionID;

    /// Grab the creation date for this transactions.
    fn created(&self) -> &Timestamp;

    /// Grab the transactions that this transaction signs.
    fn previous_transactions(&self) -> &Vec<TransactionID>;
}

/// This enum helps us version our transactions so that we can make dumb
/// mistakes that don't haunt us until the end of time.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum TransactionVersioned {
    #[rasn(tag(explicit(0)))]
    V1(Transaction),
}

impl TransactionVersioned {
    /// Reencrypt this transaction.
    fn reencrypt(self, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        match self {
            Self::V1(trans) => Ok(Self::V1(trans.reencrypt(old_master_key, new_master_key)?)),
        }
    }
}

// NOTE: if we ever add more versions, this will need to be removed and we'll
// have to add a more dedicated interface. but for now, we do the lazy way and
// just point all versioned transactions to their inner transaction and call it
// a day. this is still useful, because although adding a version will require
// changing an assload of code, it makes sure our storage layer is future-proof
// which is what's really important. code can change, dealing with unversioned
// protocols is a bit trickier.
impl Deref for TransactionVersioned {
    type Target = Transaction;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::V1(trans) => trans,
        }
    }
}

impl GraphInfo for TransactionVersioned {
    fn id(&self) -> &TransactionID {
        self.deref().id()
    }

    fn created(&self) -> &Timestamp {
        self.deref().entry().created()
    }

    fn previous_transactions(&self) -> &Vec<TransactionID> {
        self.deref().entry().previous_transactions()
    }
}

impl From<Transaction> for TransactionVersioned {
    fn from(trans: Transaction) -> Self {
        Self::V1(trans)
    }
}

impl Public for TransactionVersioned {
    fn strip_private(&self) -> Self {
        match self {
            Self::V1(trans) => Self::V1(trans.strip_private()),
        }
    }

    fn has_private(&self) -> bool {
        self.deref().has_private()
    }
}

/// Used to tell the transaction system which key to sign the transaction with.
pub(crate) enum SignWith {
    Alpha,
    Policy,
    Root,
}

/// A container that holds a set of transactions.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Transactions {
    /// The actual transactions.
    #[rasn(tag(explicit(0)))]
    transactions: Vec<TransactionVersioned>,
}

impl Transactions {
    /// Create a new, empty transaction set.
    pub fn new() -> Self {
        Self {transactions: vec![]}
    }

    /// Returns an iterator over these transactions
    pub fn iter(&self) -> core::slice::Iter<'_, TransactionVersioned> {
        self.transactions().iter()
    }

    /// Run a transaction and return the output
    fn apply_transaction(identity: Option<Identity>, transaction: &TransactionVersioned) -> Result<Identity> {
        match transaction {
            TransactionVersioned::V1(trans) => {
                match trans.entry().body().clone() {
                    // if this is a private transaction, just pass the identity
                    // back as-is
                    TransactionBody::Private => {
                        identity.ok_or(Error::DagMissingIdentity)
                    }
                    TransactionBody::CreateIdentityV1 { alpha, policy, publish, root } => {
                        let identity_id = IdentityID(trans.id().deref().clone());
                        Ok(Identity::create(identity_id, alpha, policy, publish, root, trans.entry().created().clone()))
                    }
                    TransactionBody::SetRecoveryPolicyV1 { policy: policy_condition } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .set_recovery(PolicyID(trans.id().deref().clone()), policy_condition);
                        Ok(identity_mod)
                    }
                    TransactionBody::ExecuteRecoveryPolicyV1 { request } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .execute_recovery(request)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::MakeClaimV1 { spec } => {
                        let claim_id = ClaimID(trans.id().deref().clone());
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .make_claim(claim_id, spec, trans.entry().created().clone());
                        Ok(identity_mod)
                    }
                    TransactionBody::DeleteClaimV1 { claim_id } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .delete_claim(&claim_id)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::AcceptStampV1 { stamp } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .accept_stamp(stamp)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::DeleteStampV1 { stamp_id } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .delete_stamp(&stamp_id)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::SetPolicyKeyV1 { keypair, reason } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .set_policy_key(keypair, reason)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::SetPublishKeyV1 { keypair, reason } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .set_publish_key(keypair, reason)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::SetRootKeyV1 { keypair, reason } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .set_root_key(keypair, reason)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::AddSubkeyV1 { key, name, desc } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .add_subkey(key, name, desc)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::EditSubkeyV1 { name, new_name, desc } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .edit_subkey(&name, new_name, desc)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::RevokeSubkeyV1 { name, reason, new_name } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .revoke_subkey(&name, reason, new_name)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::DeleteSubkeyV1 { name } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .delete_subkey(&name)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::SetNicknameV1 { nickname } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .set_nickname(nickname);
                        Ok(identity_mod)
                    }
                    TransactionBody::AddForwardV1 { name, ty, default } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .add_forward(name, ty, default)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::DeleteForwardV1 { name } => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .delete_forward(&name)?;
                        Ok(identity_mod)
                    }
                }
            }
        }
    }

    /// Build an identity from our heroic transactions.
    ///
    /// Sounds easy, but it's actually a bit...odd. First we reverse our tree
    /// of transactions so it's forward-looking. This means for any transaction
    /// we can see which transactions come directly after it (as opposed to
    /// directly before it).
    ///
    /// Then, we walk the tree and assign a unique branch number any time the
    /// transactions branch or merge. This branch number can be looked up by
    /// txid.
    ///
    /// Lastly, instead of trying to order the transactions what we do is push
    /// the first one onto a "pending transactions" list, then run it. Once run,
    /// we add any transactions that come after it to the pending list. The
    /// pending list is them sorted by the transactions dates ascending (oldest
    /// first) and we loop again, plucking the oldest transaction off the list
    /// and running it. Now, for each transaction we run, we also apply it to
    /// an identity that is specific to each previous branch the transaction
    /// descended from. This allows us to easily merge identities from many
    /// trees as we move along, but also has the benefit that the branch-
    /// specific identity for our first branch (0) is also our *final* identity
    /// because ALL transactions have been applied to it. It's a big, burly mess
    /// but it works...
    ///
    /// NOTE: this algorithm handles signing key conflicts by only using the
    /// nearest branch-level identity to *validate* the current transaction,
    /// although the transaction is applied to all identities from previous
    /// branches as well. However, this algorithm does not handle other
    /// conflicts (such as duplicate entries).
    pub fn build_identity(&self) -> Result<Identity> {
        if self.transactions().len() == 0 {
            Err(Error::DagEmpty)?;
        }
        let transactions = self.transactions.clone();
        if transactions.len() == 0 {
            Err(Error::DagEmpty)?;
        }

        // use the `previous_transactions` collection to build a feed-forward
        // index for transactions (basically, reverse the order of our tree).
        // also, index our transactions by id.
        let mut transaction_idx: HashMap<TransactionID, &TransactionVersioned> = HashMap::new();
        let mut next_transactions_idx: HashMap<TransactionID, Vec<TransactionID>> = HashMap::new();
        for trans in &transactions {
            transaction_idx.insert(trans.id().clone(), trans);
            let prev = trans.entry().previous_transactions();
            if prev.len() == 0 { continue; }
            for trans_prev in prev {
                let entry = next_transactions_idx.entry(trans_prev.clone()).or_insert(Vec::new());
                (*entry).push(trans.id().clone());
            }
        }

        for trans in &transactions {
            // make sure we don't have any orphaned transactions
            for prev in trans.entry().previous_transactions() {
                if !transaction_idx.contains_key(prev) {
                    Err(Error::DagOrphanedTransaction(String::from(trans.id())))?;
                }
            }
        }

        // populate a transaction_id -> branchnum index
        let mut transaction_branch_idx: HashMap<TransactionID, Vec<u32>> = HashMap::new();
        fn walker_identity_ranger(transaction_idx: &HashMap<TransactionID, &TransactionVersioned>, next_transactions_idx: &HashMap<TransactionID, Vec<TransactionID>>, transaction_branch_idx: &mut HashMap<TransactionID, Vec<u32>>, transaction: &TransactionVersioned, cur_branch: Vec<u32>) -> Result<()> {
            fn push_branch(list: &Vec<u32>, branch_num: u32) -> Vec<u32> {
                let mut list = list.clone();
                if list.contains(&branch_num) {
                    return list;
                }
                list.append(&mut vec![branch_num]);
                list
            }
            let mut new_branch = 0;
            // if this transaction merges one or more branches, it gets its own
            // branch id
            if transaction.previous_transactions().len() > 1 {
                new_branch += 1;
            }
            let default = Vec::new();
            let next = next_transactions_idx.get(transaction.id()).unwrap_or(&default);
            transaction_branch_idx.insert(transaction.id().clone(), push_branch(&cur_branch, new_branch));
            // if this is a branch, give each branch a unique id
            if next.len() > 1 {
                new_branch += 1;
            }
            for trans_id in next {
                let trans = transaction_idx.get(trans_id).ok_or(Error::DagBuildError)?;
                walker_identity_ranger(transaction_idx, next_transactions_idx, transaction_branch_idx, trans, push_branch(&cur_branch, new_branch))?;
                new_branch += 1;
            }
            Ok(())
        }
        walker_identity_ranger(&transaction_idx, &next_transactions_idx, &mut transaction_branch_idx, &transactions[0], vec![0])?;

        #[derive(Debug, Default)]
        struct WalkState<'a> {
            // tracks our current run list
            transactions_to_run: Vec<&'a TransactionVersioned>,
            // tracks merge transactions, and how many ancestors have been run.
            // when this number reaches previous_transactions().len(), then the
            // merge is free to run.
            pending_merges: HashMap<TransactionID, usize>,
        }

        impl<'a> WalkState<'a> {
            fn next(&self) -> Option<&TransactionVersioned> {
                self.transactions_to_run.get(0).map(|x| *x)
            }

            fn remove_first(&mut self) {
                let tx_id = self.transactions_to_run[0].id();
                self.transactions_to_run.retain(|tx| tx.id() != tx_id);
            }

            fn pop_transaction(&mut self, transaction_idx: &HashMap<TransactionID, &'a TransactionVersioned>, next_transactions_idx: &HashMap<TransactionID, Vec<TransactionID>>) -> Result<bool> {
                if self.transactions_to_run.len() == 0 {
                    return Err(Error::DagBuildError)?;
                }
                let trans = self.transactions_to_run[0];
                self.remove_first();
                if let Some(next) = next_transactions_idx.get(trans.id()) {
                    for next_trans_id in next {
                        let entry = self.pending_merges.entry(next_trans_id.clone()).or_insert(0);
                        (*entry) += 1;
                        self.transactions_to_run.push(transaction_idx.get(next_trans_id).ok_or(Error::DagBuildError)?);
                    }
                    // TODO: optimize. sorting on every loop, tsk tsk.
                    self.transactions_to_run.sort_by_key(|t| t.created());
                }
                Ok(true)
            }
        }

        let mut state = WalkState::default();
        state.transactions_to_run.push(
            transactions.iter().find(|x| x.previous_transactions().len() == 0).ok_or(Error::DagNoGenesis)?
        );
        let first_trans = match state.next() {
            Some(trans) => trans,
            None => Err(Error::DagBuildError)?,
        };
        first_trans.verify(None)?;

        // tracks our per-branch identities
        let mut branch_identities: HashMap<u32, Identity> = HashMap::new();
        branch_identities.insert(0, Transactions::apply_transaction(None, first_trans)?);
        state.pop_transaction(&transaction_idx, &next_transactions_idx)?;
        loop {
            if let Some(trans) = state.next() {
                let root_identity = branch_identities.get(&0).ok_or(Error::DagMissingIdentity)?.clone();
                let ancestors = transaction_branch_idx.get(trans.id()).ok_or(Error::DagBuildError)?;
                let previous_len = trans.previous_transactions().len();
                if previous_len > 1 {
                    let pending_count = state.pending_merges.get(trans.id()).unwrap_or(&0);
                    // ONLY run a merge transaction if all of its children have
                    // run!!1
                    if *pending_count >= previous_len {
                        let ancestor_collection = trans.previous_transactions().iter()
                            .map(|x| {
                                transaction_branch_idx.get(x)
                                    .map(|ancestors| ancestors.clone().into_iter().rev().collect::<Vec<_>>())
                                    .ok_or(Error::DagBuildError)
                            })
                            .collect::<Result<Vec<Vec<u32>>>>()?;
                        // now find the highest (ie, youngest) branch that is the
                        // common ancestor to the N branches we're merging right now
                        let first = ancestor_collection.get(0).ok_or(Error::DagBuildError)?;
                        let mut found_branch = None;
                        for branch in first {
                            let mut has = true;
                            for anc in &ancestor_collection[1..] {
                                if !has || !anc.contains(branch) {
                                    has = false;
                                }
                            }
                            if has {
                                found_branch = Some(branch);
                                break;
                            }
                        }
                        let found_branch = found_branch.ok_or(Error::DagBuildError)?;
                        {
                            let common_ancestor_identity = branch_identities.get_mut(found_branch).ok_or(Error::DagBuildError)?;
                            trans.verify(Some(&common_ancestor_identity))?;
                        }
                        // apply this transaction to all of its ancestor branches
                        let mut tracker = HashMap::new();
                        for ancestors in ancestor_collection {
                            for branch in &ancestors {
                                if tracker.get(branch).is_some() {
                                    continue;
                                }
                                let branch_identity = branch_identities.entry(*branch).or_insert(root_identity.clone());
                                (*branch_identity) = Transactions::apply_transaction(Some((*branch_identity).clone()), trans)?;
                                tracker.insert(*branch, true);
                            }
                        }
                    } else {
                        state.remove_first();
                        continue;
                    }
                } else {
                    let current_branch_identity = branch_identities.entry(*(*ancestors).last().unwrap()).or_insert(root_identity.clone());
                    trans.verify(Some(&current_branch_identity))?;
                    // apply this transaction to all of its ancestor branches
                    for branch in ancestors {
                        let branch_identity = branch_identities.entry(*branch).or_insert(root_identity.clone());
                        (*branch_identity) = Transactions::apply_transaction(Some((*branch_identity).clone()), trans)?;
                    }
                }
                state.pop_transaction(&transaction_idx, &next_transactions_idx)?;
            } else {
                break;
            }
        }
        Ok(branch_identities.get(&0).ok_or(Error::DagMissingIdentity)?.clone())
    }

    /// Find any transactions that are not referenced as previous transactions.
    /// Effectively, the leaves of our graph.
    fn find_leaf_transactions<T: GraphInfo>(transaction_list: &Vec<T>) -> Vec<TransactionID> {
        let mut seen: HashMap<TransactionID, bool> = HashMap::new();
        for trans in transaction_list {
            for prev in trans.previous_transactions() {
                seen.insert(prev.clone(), true);
            }
        }
        transaction_list.iter()
            .filter_map(|t| {
                if seen.get(t.id()).is_some() {
                    None
                } else {
                    Some(t.id().clone())
                }
            })
            .collect::<Vec<_>>()
    }

    /// Push a transaction into the transactions list, and return the resulting
    /// identity object from running all transactions in order.
    fn push_transaction<T: Into<Timestamp>>(&mut self, master_key: &SecretKey, sign_with: SignWith, now: T, body: TransactionBody) -> Result<Identity> {
        let leaves = Self::find_leaf_transactions(self.transactions());
        let entry = TransactionEntry::new(now, leaves, body);
        let identity_maybe = match self.build_identity() {
            Ok(id) => Some(id),
            Err(Error::DagEmpty) => None,
            Err(e) => Err(e)?,
        };
        let trans = Transaction::new(master_key, &identity_maybe, sign_with, entry)?;
        let versioned = trans.into();
        let identity = Self::apply_transaction(identity_maybe, &versioned)?;
        self.transactions_mut().push(versioned);
        Ok(identity)
    }

    /// Push a raw transaction onto this transaction set. Generally, this might
    /// come from a syncing source (StampNet's private syncing) that passes
    /// around singular transactions. We verify this transactions by building
    /// the identity after pushing.
    pub fn push_transaction_raw(&mut self, versioned: TransactionVersioned) -> Result<Identity> {
        let identity_maybe = match self.build_identity() {
            Ok(id) => Some(id),
            Err(Error::DagEmpty) => None,
            Err(e) => Err(e)?,
        };
        let identity = Self::apply_transaction(identity_maybe, &versioned)?;
        self.transactions_mut().push(versioned);
        // build it again
        let _identity_maybe = match self.build_identity() {
            Ok(id) => Some(id),
            Err(Error::DagEmpty) => None,
            Err(e) => Err(e)?,
        };
        Ok(identity)
    }

    /// Merge the transactions from two transaction sets together.
    pub fn merge(mut branch1: Self, branch2: Self) -> Result<Self> {
        for trans2 in branch2.transactions() {
            // if it already exists, don't merge it
            if branch1.transactions().iter().find(|t| t.id() == trans2.id()).is_some() {
                continue;
            }
            branch1.transactions_mut().push(trans2.clone());
        }
        // make sure it's all copasetic.
        branch1.build_identity()?;
        Ok(branch1)
    }

    /// Reset a set of transactions to a previous state.
    ///
    /// Effectively, we take a transaction ID and remove any transactions that
    /// came after it. This may create many trailing transactions, which will be
    /// connected the next time a new transaction is created.
    pub fn reset(mut self, txid: &TransactionID) -> Result<Self> {
        // recursively find all transactions referencing the given one
        fn find_tx_to_rm(transactions: &Vec<TransactionVersioned>, txid: &TransactionID) -> Vec<TransactionID> {
            let mut to_remove = Vec::new();
            for trans in transactions {
                if trans.entry().previous_transactions().contains(txid) {
                    to_remove.push(trans.id().clone()); // i hate this clone, but w/e
                    to_remove.append(&mut find_tx_to_rm(transactions, trans.id()));
                }
            }
            to_remove
        }
        let remove_tx = find_tx_to_rm(self.transactions(), txid);
        self.transactions_mut().retain(|t| !remove_tx.contains(t.id()));
        Ok(self)
    }

    // -------------------------------------------------------------------------

    /// Create an identity.
    pub fn create_identity<T: Into<Timestamp> + Clone>(mut self, master_key: &SecretKey, now: T, alpha: AlphaKeypair, policy: PolicyKeypair, publish: PublishKeypair, root: RootKeypair) -> Result<Self> {
        if self.transactions().len() > 0 {
            Err(Error::DagCreateIdentityOnExistingChain)?;
        }
        let body = TransactionBody::CreateIdentityV1 { alpha, policy, publish, root };
        self.push_transaction(master_key, SignWith::Alpha, now.clone(), body)?;
        Ok(self)
    }

    /// Set a recovery policy.
    pub fn set_recovery_policy<T: Into<Timestamp> + Clone>(mut self, master_key: &SecretKey, now: T, policy: Option<PolicyCondition>) -> Result<Self> {
        let body = TransactionBody::SetRecoveryPolicyV1 { policy };
        self.push_transaction(master_key, SignWith::Policy, now, body)?;
        Ok(self)
    }

    /// Execute a recovery policy (replace your keys via a policy).
    pub fn execute_recovery_policy<T: Into<Timestamp> + Clone>(mut self, master_key: &SecretKey, now: T, request: PolicyRequest) -> Result<Self> {
        let body = TransactionBody::ExecuteRecoveryPolicyV1 { request };
        self.push_transaction(master_key, SignWith::Policy, now, body)?;
        Ok(self)
    }

    /// Make a new claim.
    pub fn make_claim<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, spec: ClaimSpec) -> Result<Self> {
        let body = TransactionBody::MakeClaimV1 { spec };
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Delete an existing claim.
    pub fn delete_claim<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, claim_id: ClaimID) -> Result<Self> {
        let body = TransactionBody::DeleteClaimV1 { claim_id };
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Accept a stamp someone, or some*thing*, has made on a claim of ours.
    pub fn accept_stamp<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, stamp: Stamp) -> Result<Self> {
        let body = TransactionBody::AcceptStampV1 { stamp };
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Delete an existing stamp.
    pub fn delete_stamp<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, stamp_id: StampID) -> Result<Self> {
        let body = TransactionBody::DeleteStampV1 { stamp_id };
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Assign a new policy key to this identity. Requires an alpha sig.
    pub fn set_policy_key<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, keypair: PolicyKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        let body = TransactionBody::SetPolicyKeyV1 { keypair, reason: revocation_reason };
        self.push_transaction(master_key, SignWith::Alpha, now, body)?;
        Ok(self)
    }

    /// Assign a new publish key to this identity. Requires an alpha sig.
    pub fn set_publish_key<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, keypair: PublishKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        let body = TransactionBody::SetPublishKeyV1 { keypair, reason: revocation_reason };
        self.push_transaction(master_key, SignWith::Alpha, now, body)?;
        Ok(self)
    }

    /// Assign a new root key to this identity. Requires an alpha sig.
    pub fn set_root_key<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, keypair: RootKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        let body = TransactionBody::SetRootKeyV1 { keypair, reason: revocation_reason };
        self.push_transaction(master_key, SignWith::Alpha, now, body)?;
        Ok(self)
    }

    /// Add a new subkey to our keychain.
    pub fn add_subkey<T, S>(mut self, master_key: &SecretKey, now: T, key: Key, name: S, description: Option<S>) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::AddSubkeyV1 {
            key,
            name: name.into(),
            desc: description.map(|x| x.into()),
        };
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Edit a subkey.
    pub fn edit_subkey<T, S>(mut self, master_key: &SecretKey, now: T, name: S, new_name: S, description: Option<S>) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::EditSubkeyV1 {
            name: name.into(),
            new_name: new_name.into(),
            desc: description.map(|x| x.into()),
        };
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Revoke a subkey.
    pub fn revoke_subkey<T, S>(mut self, master_key: &SecretKey, now: T, name: S, revocation_reason: RevocationReason, new_name: Option<S>) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::RevokeSubkeyV1 {
            name: name.into(),
            reason: revocation_reason,
            new_name: new_name.map(|x| x.into()),
        };
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Delete a subkey.
    pub fn delete_subkey<T, S>(mut self, master_key: &SecretKey, now: T, name: S) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::DeleteSubkeyV1 { name: name.into() };
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Set the nickname on this identity.
    pub fn set_nickname<T, S>(mut self, master_key: &SecretKey, now: T, nickname: Option<S>) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::SetNicknameV1 { nickname: nickname.map(|x| x.into()) };
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Add a new forward.
    pub fn add_forward<T, S>(mut self, master_key: &SecretKey, now: T, name: S, ty: ForwardType, is_default: bool) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::AddForwardV1 { name: name.into(), ty, default: is_default };
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Delete an existing forward.
    pub fn delete_forward<T, S>(mut self, master_key: &SecretKey, now: T, name: S) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::DeleteForwardV1 { name: name.into() };
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Reencrypt this transaction set with a new master key.
    pub fn reencrypt(mut self, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        for trans in self.transactions_mut() {
            *trans = trans.clone().reencrypt(old_master_key, new_master_key)?;
        }
        Ok(self)
    }

    /// Determine if this identity is owned (ie, we have the private keys stored
    /// locally) or it is imported (ie, someone else's identity).
    pub fn is_owned(&self) -> bool {
        let mut has_private = false;
        for trans in self.transactions() {
            has_private = match trans {
                TransactionVersioned::V1(trans) => {
                    match trans.entry().body() {
                        TransactionBody::CreateIdentityV1 { .. } => trans.entry().body().has_private(),
                        TransactionBody::SetPolicyKeyV1 { .. } => trans.entry().body().has_private(),
                        TransactionBody::SetPublishKeyV1 { .. } => trans.entry().body().has_private(),
                        TransactionBody::SetRootKeyV1 { .. } => trans.entry().body().has_private(),
                        _ => false,
                    }
                }
            };
            if has_private {
                break;
            }
        }
        has_private
    }

    /// Test if a master key is correct.
    pub fn test_master_key(&self, master_key: &SecretKey) -> Result<()> {
        if !self.is_owned() {
            Err(Error::IdentityNotOwned)?;
        }

        let identity = self.build_identity()?;
        identity.test_master_key(master_key)
    }
}

impl Public for Transactions {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        let stripped = self.transactions().iter().map(|x| x.strip_private()).collect::<Vec<_>>();
        clone.set_transactions(stripped);
        clone
    }

    fn has_private(&self) -> bool {
        self.transactions().iter().find(|x| x.has_private()).is_some()
    }
}

impl IntoIterator for Transactions {
    type Item = TransactionVersioned;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let Transactions { transactions } = self;
        transactions.into_iter()
    }
}

impl SerdeBinary for Transactions {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::key::{SignKeypair, CryptoKeypair},
        identity::{
            claim::{ClaimContainer, Relationship, RelationshipType},
            recovery::PolicyRequestEntry,
            stamp::Confidence,
        },
        private::{Private, MaybePrivate},
        util::{Date, Url, ser::BinaryVec},
    };
    use std::str::FromStr;

    macro_rules! assert_signkey {
        ($trans:expr, $keyty:ident) => {
            match $trans.id() {
                TransactionID::$keyty(..) => {}
                _ => panic!("Expected sign key type {}, found {:?}", stringify!($keyty), $trans.id()),
            }
        }
    }

    #[test]
    fn trans_body_strip_has_private() {
        fn test_privates(body: &TransactionBody) {
            match body {
                TransactionBody::Private => {}
                TransactionBody::CreateIdentityV1 { alpha, policy, publish, root } => {
                    assert!(body.has_private());
                    let body2 = TransactionBody::CreateIdentityV1 {
                        alpha: alpha.strip_private(),
                        policy: policy.clone(),
                        publish: publish.clone(),
                        root: root.clone(),
                    };
                    assert!(body2.has_private());
                    let body3 = TransactionBody::CreateIdentityV1 {
                        alpha: alpha.strip_private(),
                        policy: policy.strip_private(),
                        publish: publish.clone(),
                        root: root.clone(),
                    };
                    assert!(body3.has_private());
                    let body4 = TransactionBody::CreateIdentityV1 {
                        alpha: alpha.strip_private(),
                        policy: policy.strip_private(),
                        publish: publish.strip_private(),
                        root: root.clone(),
                    };
                    assert!(body4.has_private());
                    let body5 = TransactionBody::CreateIdentityV1 {
                        alpha: alpha.strip_private(),
                        policy: policy.strip_private(),
                        publish: publish.strip_private(),
                        root: root.strip_private(),
                    };
                    assert!(!body5.has_private());
                    let body6 = body.strip_private();
                    assert!(!body6.has_private());
                    let body7 = body6.strip_private();
                    assert!(!body7.has_private());
                }
                TransactionBody::SetRecoveryPolicyV1 { .. } => {}
                TransactionBody::ExecuteRecoveryPolicyV1 { request } => {
                    assert!(body.has_private());
                    let body2 = TransactionBody::ExecuteRecoveryPolicyV1 { request: request.strip_private() };
                    assert!(!body2.has_private());
                    let body3 = body.strip_private();
                    assert!(!body3.has_private());
                    let body4 = body3.strip_private();
                    assert!(!body4.has_private());
                }
                TransactionBody::MakeClaimV1 { spec } => {
                    assert_eq!(body.has_private(), spec.has_private());
                    let body2 = TransactionBody::MakeClaimV1 { spec: spec.strip_private() };
                    assert!(!body2.has_private());
                    let body3 = body.strip_private();
                    assert!(!body3.has_private());
                    let body4 = body3.strip_private();
                    assert!(!body4.has_private());
                }
                TransactionBody::DeleteClaimV1 { .. } => {}
                TransactionBody::AcceptStampV1 { stamp } => {
                    assert!(!body.has_private());
                    let body2 = TransactionBody::AcceptStampV1 { stamp: stamp.strip_private() };
                    assert!(!body2.has_private());
                    let body3 = body.strip_private();
                    assert!(!body3.has_private());
                    let body4 = body3.strip_private();
                    assert!(!body4.has_private());
                }
                TransactionBody::DeleteStampV1 { .. } => {}
                TransactionBody::SetPolicyKeyV1 { keypair, reason } => {
                    assert!(body.has_private());
                    let body2 = TransactionBody::SetPolicyKeyV1 {
                        keypair: keypair.strip_private(),
                        reason: reason.clone(),
                    };
                    assert!(!body2.has_private());
                    let body3 = body.strip_private();
                    assert!(!body3.has_private());
                    let body4 = body3.strip_private();
                    assert!(!body4.has_private());
                }
                TransactionBody::SetPublishKeyV1 { keypair, reason } => {
                    assert!(body.has_private());
                    let body2 = TransactionBody::SetPublishKeyV1 {
                        keypair: keypair.strip_private(),
                        reason: reason.clone(),
                    };
                    assert!(!body2.has_private());
                    let body3 = body.strip_private();
                    assert!(!body3.has_private());
                    let body4 = body3.strip_private();
                    assert!(!body4.has_private());
                }
                TransactionBody::SetRootKeyV1 { keypair, reason } => {
                    assert!(body.has_private());
                    let body2 = TransactionBody::SetRootKeyV1 {
                        keypair: keypair.strip_private(),
                        reason: reason.clone(),
                    };
                    assert!(!body2.has_private());
                    let body3 = body.strip_private();
                    assert!(!body3.has_private());
                    let body4 = body3.strip_private();
                    assert!(!body4.has_private());
                }
                TransactionBody::AddSubkeyV1 { key, name, desc } => {
                    assert!(body.has_private());
                    match key.strip_private_maybe() {
                        Some(stripped) => {
                            let body2 = TransactionBody::AddSubkeyV1 {
                                key: stripped,
                                name: name.clone(),
                                desc: desc.clone(),
                            };
                            assert!(!body2.has_private());
                            let body3 = body.strip_private();
                            assert!(!body3.has_private());
                            let body4 = body3.strip_private();
                            assert!(!body4.has_private());
                        }
                        None => {}
                    }
                }
                TransactionBody::EditSubkeyV1 { .. } => {}
                TransactionBody::RevokeSubkeyV1 { .. } => {}
                TransactionBody::DeleteSubkeyV1 { .. } => {}
                TransactionBody::SetNicknameV1 { .. } => {}
                TransactionBody::AddForwardV1 { .. } => {}
                TransactionBody::DeleteForwardV1 { .. } => {}
            }
        }
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let body = TransactionBody::CreateIdentityV1 {
            alpha: alpha_keypair.clone(),
            policy: policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair.clone(),
        };
        test_privates(&body);

        test_privates(&TransactionBody::SetRecoveryPolicyV1 { policy: Some(PolicyCondition::Deny) });

        let action = PolicyRequestAction::ReplaceKeys {
            policy: policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair.clone(),
        };
        let entry = PolicyRequestEntry::new(IdentityID::random(), PolicyID::random(), action);
        let req = PolicyRequest::new(&master_key, &policy_keypair, entry).unwrap();
        test_privates(&TransactionBody::ExecuteRecoveryPolicyV1 { request: req });

        test_privates(&TransactionBody::MakeClaimV1 { spec: ClaimSpec::Name(MaybePrivate::new_public(String::from("Negative Nancy"))) });
        test_privates(&TransactionBody::MakeClaimV1 { spec: ClaimSpec::Name(MaybePrivate::new_private(&master_key, String::from("Positive Pyotr")).unwrap()) });
        test_privates(&TransactionBody::DeleteClaimV1 { claim_id: ClaimID::random() });

        let claim_con = ClaimContainer::new(ClaimID::random(), ClaimSpec::Name(MaybePrivate::new_private(&master_key, String::from("Hangry Hank")).unwrap()), Timestamp::now());
        let stamp = Stamp::stamp(&master_key, &root_keypair, &IdentityID::random(), &IdentityID::random(), Confidence::Low, Timestamp::now(), claim_con.claim(), Some(Timestamp::now())).unwrap();
        test_privates(&TransactionBody::AcceptStampV1 { stamp });
        test_privates(&TransactionBody::DeleteStampV1 { stamp_id: StampID::random() });
        test_privates(&TransactionBody::SetPolicyKeyV1 {
            keypair: policy_keypair.clone(),
            reason: RevocationReason::Unspecified,
        });
        test_privates(&TransactionBody::SetPublishKeyV1 {
            keypair: publish_keypair.clone(),
            reason: RevocationReason::Compromised,
        });
        test_privates(&TransactionBody::SetRootKeyV1 {
            keypair:root_keypair.clone(),
            reason: RevocationReason::Recovery,
        });

        let key = Key::new_sign(root_keypair.deref().clone());
        test_privates(&TransactionBody::AddSubkeyV1 {
            key,
            name: "MY DOGECOIN KEY".into(),
            desc: Some("plz send doge".into()),
        });
        test_privates(&TransactionBody::EditSubkeyV1 {
            name: "MY DOGECOIN KEY".into(),
            new_name: "MAI DOGE KEY".into(),
            desc: None,
        });
        test_privates(&TransactionBody::RevokeSubkeyV1 {
            name: "MAI DOGE KEY".into(),
            reason: RevocationReason::Compromised,
            new_name: Some("REVOKED DOGE KEY".into()),
        });
        test_privates(&TransactionBody::DeleteSubkeyV1 { name: "REVOKED DOGE KEY".into() });
        test_privates(&TransactionBody::SetNicknameV1 { nickname: Some("wreck-dum".into()) });
        test_privates(&TransactionBody::AddForwardV1 {
            name: "EMAIL".into(),
            ty: ForwardType::Social { ty: "mobile".into(), handle: "web2.0".into() },
            default: true,
        });
        test_privates(&TransactionBody::DeleteForwardV1 { name: "EMAIL".into() });
    }

    #[test]
    fn trans_entry_strip_has_private() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let body = TransactionBody::MakeClaimV1 {
            spec: ClaimSpec::Name(MaybePrivate::new_private(&master_key, "Jackie Chrome".into()).unwrap()),
        };
        let entry = TransactionEntry::new(Timestamp::now(), vec![TransactionID::random_alpha()], body);
        assert!(entry.has_private());
        assert!(entry.body().has_private());
        let entry2 = entry.strip_private();
        assert!(!entry2.has_private());
        assert!(!entry2.body().has_private());
    }

    #[test]
    fn trans_new_verify() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let identity = Identity::create(IdentityID::random(), alpha_keypair.clone(), policy_keypair.clone(), publish_keypair.clone(), root_keypair.clone(), Timestamp::now());

        let body = TransactionBody::CreateIdentityV1 {
            alpha: alpha_keypair.clone(),
            policy: policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair.clone(),
        };
        let now = Timestamp::now();
        let entry = TransactionEntry::new(now.clone(), vec![], body);
        let trans = Transaction::new(&master_key, &None, SignWith::Alpha, entry.clone()).unwrap();
        trans.verify(None).unwrap();

        let res = Transaction::new(&master_key, &None, SignWith::Policy, entry.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));

        let res = Transaction::new(&master_key, &None, SignWith::Root, entry.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));

        let body2 = TransactionBody::DeleteForwardV1 { name: "blassssstodon".into() };
        let entry2 = TransactionEntry::new(Timestamp::now(), vec![], body2);
        let res = Transaction::new(&master_key, &None, SignWith::Alpha, entry2.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));

        let res = Transaction::new(&master_key, &Some(identity.clone()), SignWith::Root, entry.clone());
        assert_eq!(res.err(), Some(Error::DagCreateIdentityOnExistingChain));

        let new_policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        assert!(new_policy_keypair != policy_keypair);
        let action = PolicyRequestAction::ReplaceKeys {
            policy: new_policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair.clone(),
        };
        let entry = PolicyRequestEntry::new(IdentityID::random(), PolicyID::random(), action);
        let req = PolicyRequest::new(&master_key, &new_policy_keypair, entry).unwrap();
        let body_recover = TransactionBody::ExecuteRecoveryPolicyV1 { request: req };
        let entry_recover = TransactionEntry::new(Timestamp::now(), vec![], body_recover);
        let trans_recover = Transaction::new(&master_key, &Some(identity.clone()), SignWith::Policy, entry_recover.clone()).unwrap();
        trans_recover.verify(Some(&identity)).unwrap();
        let res = Transaction::new(&master_key, &None, SignWith::Alpha, entry_recover.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));
        let res = Transaction::new(&master_key, &Some(identity.clone()), SignWith::Alpha, entry_recover.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));
        let res = Transaction::new(&master_key, &Some(identity.clone()), SignWith::Root, entry_recover.clone());
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));

        let mut trans2 = trans.clone();
        trans2.set_id(TransactionID::random_alpha());
        assert_eq!(trans2.verify(None).err(), Some(Error::CryptoSignatureVerificationFailed));

        let mut trans3 = trans.clone();
        let then = Timestamp::from(now.deref().clone() - chrono::Duration::seconds(2));
        trans3.entry_mut().set_created(then);
        assert_eq!(trans3.verify(None).err(), Some(Error::CryptoSignatureVerificationFailed));

        let mut trans4 = trans.clone();
        trans4.entry_mut().set_previous_transactions(vec![TransactionID::random_alpha()]);
        assert_eq!(trans4.verify(None).err(), Some(Error::CryptoSignatureVerificationFailed));

        let mut trans5 = trans.clone();
        let root_keypair2 = RootKeypair::new_ed25519(&master_key).unwrap();
        assert!(root_keypair != root_keypair2);
        let body = TransactionBody::CreateIdentityV1 {
            alpha: alpha_keypair.clone(),
            policy: policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair2.clone(),
        };
        trans5.entry_mut().set_body(body);
        assert_eq!(trans5.verify(None).err(), Some(Error::CryptoSignatureVerificationFailed));
    }

    #[test]
    fn trans_strip_has_private() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();

        let body = TransactionBody::CreateIdentityV1 {
            alpha: alpha_keypair.clone(),
            policy: policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair.clone(),
        };
        let entry = TransactionEntry::new(Timestamp::now(), vec![], body);
        let trans = Transaction::new(&master_key, &None, SignWith::Alpha, entry.clone()).unwrap();

        assert!(trans.has_private());
        assert!(trans.entry().has_private());
        assert!(trans.entry().body().has_private());
        let trans2 = trans.strip_private();
        assert!(!trans2.has_private());
        assert!(!trans2.entry().has_private());
        assert!(!trans2.entry().body().has_private());
    }

    #[test]
    fn trans_versioned_deref() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();

        let body = TransactionBody::CreateIdentityV1 {
            alpha: alpha_keypair.clone(),
            policy: policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair.clone(),
        };
        let entry = TransactionEntry::new(Timestamp::now(), vec![], body);
        let trans = Transaction::new(&master_key, &None, SignWith::Alpha, entry.clone()).unwrap();
        let versioned = TransactionVersioned::from(trans.clone());

        match &versioned {
            TransactionVersioned::V1(ref trans) => {
                assert!(std::ptr::eq(trans, versioned.deref()));
            }
        }
    }

    #[test]
    fn trans_versioned_graphinfo() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();

        let body = TransactionBody::CreateIdentityV1 {
            alpha: alpha_keypair.clone(),
            policy: policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair.clone(),
        };
        let entry = TransactionEntry::new(Timestamp::now(), vec![], body);
        let trans = Transaction::new(&master_key, &None, SignWith::Alpha, entry.clone()).unwrap();
        let versioned = TransactionVersioned::from(trans.clone());

        assert_eq!(versioned.id(), trans.id());
        assert_eq!(versioned.created(), trans.entry().created());
        assert_eq!(versioned.previous_transactions(), trans.entry().previous_transactions());
    }

    #[test]
    fn trans_versioned_strip_has_private() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();

        let body = TransactionBody::CreateIdentityV1 {
            alpha: alpha_keypair.clone(),
            policy: policy_keypair.clone(),
            publish: publish_keypair.clone(),
            root: root_keypair.clone(),
        };
        let entry = TransactionEntry::new(Timestamp::now(), vec![], body);
        let trans = Transaction::new(&master_key, &None, SignWith::Alpha, entry.clone()).unwrap();
        let versioned = TransactionVersioned::from(trans.clone());
        assert!(versioned.has_private());
        assert!(versioned.deref().has_private());
        assert!(versioned.deref().entry().has_private());
        assert!(versioned.deref().entry().body().has_private());

        let versioned2 = versioned.strip_private();
        assert!(!versioned2.has_private());
        assert!(!versioned2.deref().has_private());
        assert!(!versioned2.deref().entry().has_private());
        assert!(!versioned2.deref().entry().body().has_private());
    }

    fn genesis_time(now: Timestamp) -> (SecretKey, Transactions) {
        let transactions = Transactions::new();
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let alpha = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root = RootKeypair::new_ed25519(&master_key).unwrap();
        let transactions2 = transactions.create_identity(&master_key, now, alpha.clone(), policy.clone(), publish.clone(), root.clone()).unwrap();
        (master_key, transactions2)
    }

    fn genesis() -> (SecretKey, Transactions) {
        genesis_time(Timestamp::now())
    }

    #[test]
    fn transactions_push_raw() {
        let now = Timestamp::from_str("2021-04-20T00:00:10Z").unwrap();
        let (master_key_1, mut transactions_1) = genesis_time(now.clone());
        let (_master_key_2, mut transactions_2) = genesis_time(now.clone());
        let transactions_1_2 = transactions_1.clone()
            .make_claim(&master_key_1, now.clone(), ClaimSpec::Name(MaybePrivate::new_public("Hooty McOwl".to_string()))).unwrap();
        let raw = transactions_1_2.transactions()[1].clone();
        transactions_1.push_transaction_raw(raw.clone()).unwrap();
        transactions_2.build_identity().unwrap();
        match transactions_2.push_transaction_raw(raw.clone()) {
            Ok(_) => panic!("pushed a bad raw transaction: {}", String::from(raw.id())),
            Err(e) => assert_eq!(e, Error::DagOrphanedTransaction(String::from(raw.id()))),
        }
    }

    #[test]
    fn transactions_merge_reset() {
        let (master_key, transactions) = genesis_time(Timestamp::from_str("2021-04-20T00:00:00Z").unwrap());
        // make some claims on my smart refrigerator
        let new_root1 = RootKeypair::new_ed25519(&master_key).unwrap();
        let new_root2 = RootKeypair::new_ed25519(&master_key).unwrap();
        let branch1 = transactions.clone()
            .make_claim(&master_key, Timestamp::from_str("2021-04-20T00:00:10Z").unwrap(), ClaimSpec::Name(MaybePrivate::new_public("Hooty McOwl".to_string()))).unwrap()
            .set_root_key(&master_key, Timestamp::from_str("2021-04-20T00:01:00Z").unwrap(), new_root1.clone(), RevocationReason::Unspecified).unwrap()
            .set_nickname(&master_key, Timestamp::from_str("2021-04-20T00:01:33Z").unwrap(), Some("dirk-delta")).unwrap();
        // make some claims on my Facebook (TM) (R) (C) Brain (AND NOW A WORD FROM OUR SPONSORS) Implant
        let branch2 = transactions.clone()
            .add_forward(&master_key, Timestamp::from_str("2021-04-20T00:00:30Z").unwrap(), "my-website", ForwardType::Url("https://www.cactus-petes.com/yeeeehawwww".into()), false).unwrap()
            .set_root_key(&master_key, Timestamp::from_str("2021-04-20T00:01:36Z").unwrap(), new_root2.clone(), RevocationReason::Unspecified).unwrap()
            .set_nickname(&master_key, Timestamp::from_str("2021-04-20T00:01:45Z").unwrap(), Some("liberal hokes")).unwrap()
            .make_claim(&master_key, Timestamp::from_str("2021-04-20T00:01:56Z").unwrap(), ClaimSpec::Email(MaybePrivate::new_public(String::from("dirk.delta@hollywood.com")))).unwrap();
        let identity1 = branch1.build_identity().unwrap();
        let identity2 = branch2.build_identity().unwrap();
        assert_eq!(identity1.extra_data().nickname(), &Some(String::from("dirk-delta")));
        assert_eq!(identity1.keychain().root(), &new_root1);
        assert_eq!(identity2.extra_data().nickname(), &Some(String::from("liberal hokes")));
        assert!(identity2.keychain().root() != &new_root1);
        assert_eq!(identity2.keychain().root(), &new_root2);
        let transactions2 = Transactions::merge(branch1.clone(), branch2.clone()).unwrap();
        assert_eq!(branch1.transactions().len(), 4);
        assert_eq!(branch2.transactions().len(), 5);
        assert_eq!(transactions2.transactions().len(), 8);
        let transactions3 = transactions2.clone()
            .add_forward(&master_key, Timestamp::from_str("2021-04-20T00:05:22Z").unwrap(), "get-a-job", ForwardType::Url("https://www.cactus-petes.com/yeeeehawwww".into()), false).unwrap();
        assert_eq!(transactions3.transactions().len(), 9);
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.extra_data().nickname(), &Some(String::from("liberal hokes")));
        assert_eq!(identity3.claims().len(), 2);
        assert_eq!(identity3.extra_data().forwards().len(), 2);
        assert_eq!(identity3.keychain().root(), &new_root2);
    }

    #[test]
    fn transactions_genesis() {
        let (master_key, transactions) = genesis();

        let alpha = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root = RootKeypair::new_ed25519(&master_key).unwrap();
        let res = transactions.create_identity(&master_key, Timestamp::now(), alpha, policy, publish, root);
        assert_eq!(res.err(), Some(Error::DagCreateIdentityOnExistingChain));

        let transactions2 = Transactions::new();
        let res = transactions2.make_claim(&master_key, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public("Stinky Wizzleteets".into())));
        assert_eq!(res.err(), Some(Error::DagKeyNotFound));
    }

    #[test]
    fn transactions_create_identity() {
        let (_master_key, transactions) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert_eq!(identity.id(), &IdentityID(transactions.transactions()[0].id().deref().clone()));
        match transactions.transactions()[0].entry().body() {
            TransactionBody::CreateIdentityV1{ ref alpha, ref policy, ref publish, ref root } => {
                assert_eq!(identity.keychain().alpha(), alpha);
                assert_eq!(identity.keychain().policy(), policy);
                assert_eq!(identity.keychain().publish(), publish);
                assert_eq!(identity.keychain().root(), root);
            }
            _ => panic!("bad transaction type"),
        }
        assert_signkey! { transactions.transactions()[0], Alpha }
    }

    #[test]
    fn transactions_set_recovery() {
        let (master_key, transactions) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert!(identity.recovery_policy().is_none());
        assert_eq!(transactions.transactions().len(), 1);

        let transactions2 = transactions.clone().set_recovery_policy(&master_key, Timestamp::now(), None).unwrap();
        let identity2 = transactions2.build_identity().unwrap();
        assert!(identity2.recovery_policy().is_none());
        assert_eq!(transactions2.transactions().len(), 2);
        assert_signkey! { transactions2.transactions()[1], Policy }

        let transactions3 = transactions.clone().set_recovery_policy(&master_key, Timestamp::now(), Some(PolicyCondition::Deny)).unwrap();
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.recovery_policy().as_ref().unwrap().id(), &PolicyID(transactions3.transactions[1].id().deref().clone()));
        assert_eq!(identity3.recovery_policy().as_ref().unwrap().conditions(), &PolicyCondition::Deny);
        assert_eq!(transactions3.transactions().len(), 2);

        let transactions4 = transactions3.clone().set_recovery_policy(&master_key, Timestamp::now(), None).unwrap();
        let identity4 = transactions4.build_identity().unwrap();
        assert!(identity4.recovery_policy().is_none());
        assert_eq!(transactions4.transactions().len(), 3);
    }

    #[test]
    fn transactions_execute_recovery() {
        fn id_with_subkey() -> (SecretKey, Transactions) {
            let (master_key, transactions) = genesis();
            let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
            let transactions2 = transactions
                .add_subkey(&master_key, Timestamp::now(), Key::new_sign(sign_keypair), "sign", None).unwrap();
            (master_key, transactions2)
        }
        let (gus_master, gus) = id_with_subkey();
        let (marty_master, marty) = id_with_subkey();
        let (jackie_master, jackie) = id_with_subkey();

        let gus_sign = gus.build_identity().unwrap().keychain().subkey_by_name("sign").unwrap().as_signkey().unwrap().clone();
        let marty_sign = marty.build_identity().unwrap().keychain().subkey_by_name("sign").unwrap().as_signkey().unwrap().clone();
        let jackie_sign = jackie.build_identity().unwrap().keychain().subkey_by_name("sign").unwrap().as_signkey().unwrap().clone();

        let (master_key, transactions) = genesis();

        let transactions2 = transactions.clone()
            .set_recovery_policy(
                &master_key,
                Timestamp::now(),
                Some(PolicyCondition::OfN {
                    must_have: 3,
                    pubkeys: vec![
                        gus_sign.clone().into(),
                        marty_sign.clone().into(),
                        jackie_sign.clone().into(),
                    ],
                })
            )
            .unwrap();

        let new_policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let new_publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let new_root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let action = PolicyRequestAction::ReplaceKeys {
            policy: new_policy_keypair.clone(),
            publish: new_publish_keypair.clone(),
            root: new_root_keypair.clone(),
        };

        // cannot open a request unless you have an actual recovery policy
        let res = transactions.build_identity().unwrap()
            .create_recovery_request(&master_key, &new_policy_keypair, action.clone());
        assert_eq!(res.err(), Some(Error::IdentityMissingRecoveryPolicy));

        let identity2 = transactions2.build_identity().unwrap();
        let req = identity2.create_recovery_request(&master_key, &new_policy_keypair, action.clone()).unwrap();

        let res = transactions.clone().execute_recovery_policy(&master_key, Timestamp::now(), req.clone());
        assert_eq!(res.err(), Some(Error::IdentityMissingRecoveryPolicy));

        let res = transactions2.clone().execute_recovery_policy(&master_key, Timestamp::now(), req.clone());
        assert_eq!(res.err(), Some(Error::PolicyConditionMismatch));

        let req_signed_1 = gus.build_identity().unwrap()
            .sign_recovery_request(&gus_master, &gus_sign, req.clone()).unwrap();
        let req_signed_2 = marty.build_identity().unwrap()
            .sign_recovery_request(&marty_master, &marty_sign, req_signed_1.clone()).unwrap();
        let req_signed_3 = jackie.build_identity().unwrap()
            .sign_recovery_request(&jackie_master, &jackie_sign, req_signed_2.clone()).unwrap();

        let res = transactions2.clone()
            .execute_recovery_policy(&master_key, Timestamp::now(), req_signed_1.clone());
        assert_eq!(res.err(), Some(Error::PolicyConditionMismatch));
        let res = transactions2.clone()
            .execute_recovery_policy(&master_key, Timestamp::now(), req_signed_2.clone());
        assert_eq!(res.err(), Some(Error::PolicyConditionMismatch));

        let transactions3 = transactions2.clone()
            .execute_recovery_policy(&master_key, Timestamp::now(), req_signed_3.clone()).unwrap();
        let identity3 = transactions3.build_identity().unwrap();

        assert_signkey! { transactions3.transactions()[2], Policy }
        assert!(identity2.keychain().policy() != identity3.keychain().policy());
        assert!(identity2.keychain().publish() != identity3.keychain().publish());
        assert!(identity2.keychain().root() != identity3.keychain().root());
        assert_eq!(identity2.keychain().subkeys().len(), 0);
        assert_eq!(identity3.keychain().policy(), &new_policy_keypair);
        assert_eq!(identity3.keychain().publish(), &new_publish_keypair);
        assert_eq!(identity3.keychain().root(), &new_root_keypair);
        assert_eq!(identity3.keychain().subkeys().len(), 3);
        assert_eq!(identity3.keychain().subkeys()[0].name(), &format!("revoked:policy:{}", identity2.keychain().policy().key_id().as_string()));
        assert_eq!(identity3.keychain().subkeys()[1].name(), &format!("revoked:publish:{}", identity2.keychain().publish().key_id().as_string()));
        assert_eq!(identity3.keychain().subkeys()[2].name(), &format!("revoked:root:{}", identity2.keychain().root().key_id().as_string()));
    }

    #[test]
    fn transactions_make_claim() {
        let (master_key, transactions) = genesis();

        macro_rules! make_specs {
            ($master:expr, $claimmaker:expr, $val:expr) => {{
                let val = $val.clone();
                let maybe_private = MaybePrivate::new_private(&$master, val.clone()).unwrap();
                let maybe_public = MaybePrivate::new_public(val.clone());
                let spec_private = $claimmaker(maybe_private, val.clone());
                let spec_public = $claimmaker(maybe_public, val.clone());
                (spec_private, spec_public)
            }}
        }

        macro_rules! assert_claim {
            (raw, $claimmaker:expr, $val:expr, $get_maybe:expr) => {
                let val = $val;
                let (spec_private, spec_public) = make_specs!(master_key, $claimmaker, val);

                let transactions2 = transactions.clone().make_claim(&master_key, Timestamp::now(), spec_private).unwrap();
                let identity2 = transactions2.build_identity().unwrap();
                let maybe = $get_maybe(identity2.claims()[0].claim().spec().clone());
                assert_eq!(maybe.open(&master_key).unwrap(), val);
                assert_eq!(identity2.claims().len(), 1);
                assert_eq!(transactions2.transactions().len(), 2);

                let transactions2 = transactions.clone().make_claim(&master_key, Timestamp::now(), spec_public).unwrap();
                let identity2 = transactions2.build_identity().unwrap();
                let maybe = $get_maybe(identity2.claims()[0].claim().spec().clone());
                assert_eq!(maybe.open(&master_key).unwrap(), val);
                assert_eq!(identity2.claims().len(), 1);
                assert_eq!(transactions2.transactions().len(), 2);
                assert_signkey! { transactions2.transactions()[1], Root }
            };

            ($claimty:ident, $val:expr) => {
                assert_claim! {
                    raw,
                    |maybe, _| ClaimSpec::$claimty(maybe),
                    $val,
                    |spec: ClaimSpec| if let ClaimSpec::$claimty(maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimty)) }
                }
            };
        }

        let identity = transactions.build_identity().unwrap();
        assert_eq!(identity.claims().len(), 0);
        assert_eq!(transactions.transactions().len(), 1);

        let val = identity.id().clone();
        let spec = ClaimSpec::Identity(val.clone());
        let transactions2 = transactions.clone().make_claim(&master_key, Timestamp::now(), spec).unwrap();
        let identity2 = transactions2.build_identity().unwrap();
        match identity2.claims()[0].claim().spec() {
            ClaimSpec::Identity(val2) => {
                assert_eq!(&val, val2);
            }
            _ => panic!("bad claim type {:?}", identity2.claims()[0].claim().spec()),
        }
        assert_eq!(identity2.claims().len(), 1);
        assert_eq!(transactions2.transactions().len(), 2);

        assert_claim!{ Name, String::from("Marty Malt") }
        assert_claim!{ Birthday, Date::from_str("2010-01-03").unwrap() }
        assert_claim!{ Email, String::from("marty@sids.com") }
        assert_claim!{ Photo, BinaryVec::from(vec![1, 2, 3]) }
        assert_claim!{ Pgp, String::from("12345") }
        assert_claim!{ Domain, String::from("slappy.com") }
        assert_claim!{ Url, Url::parse("https://killtheradio.net/").unwrap() }
        assert_claim!{ HomeAddress, String::from("111 blumps ln") }
        assert_claim!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        assert_claim!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, BinaryVec::from(vec![1, 2, 3, 4, 5])) }
        assert_claim!{
            raw,
            |maybe, _| ClaimSpec::Extension { key: String::from("id:state:ca"), value: maybe },
            BinaryVec::from(vec![7, 3, 2, 90]),
            |spec: ClaimSpec| if let ClaimSpec::Extension { value: maybe, .. } = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
        }
    }

    #[test]
    fn transactions_delete_claim() {
        let (master_key, transactions) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert_eq!(identity.claims().len(), 0);
        assert_eq!(transactions.transactions().len(), 1);

        let identity_id = IdentityID(transactions.transactions()[0].deref().id().deref().clone());
        let transactions2 = transactions.make_claim(&master_key, Timestamp::now(), ClaimSpec::Identity(identity_id)).unwrap();
        assert_eq!(transactions2.transactions().len(), 2);

        let identity = transactions2.build_identity().unwrap();
        let claim_id = identity.claims()[0].claim().id().clone();
        let transactions3 = transactions2.clone().delete_claim(&master_key, Timestamp::now(), claim_id.clone()).unwrap();
        assert_eq!(transactions3.transactions().len(), 3);
        assert_signkey! { transactions3.transactions()[2], Root }

        let res = transactions2.clone().delete_claim(&master_key, Timestamp::now(), ClaimID::random());
        assert_eq!(res.err(), Some(Error::IdentityClaimNotFound));
        let res = transactions3.clone().delete_claim(&master_key, Timestamp::now(), claim_id.clone());
        assert_eq!(res.err(), Some(Error::IdentityClaimNotFound));
    }

    #[test]
    fn transactions_accept_stamp() {
        let (master_key, transactions) = genesis();
        let identity_id = IdentityID(transactions.transactions()[0].deref().id().deref().clone());
        let transactions2 = transactions.make_claim(&master_key, Timestamp::now(), ClaimSpec::Identity(identity_id)).unwrap();
        let identity = transactions2.build_identity().unwrap();
        assert_eq!(identity.claims()[0].stamps().len(), 0);
        let claim = identity.claims()[0].claim().clone();

        let (master_key_stamper, transactions_stamper) = genesis();
        let identity_stamper = transactions_stamper.build_identity().unwrap();
        let stamp = identity_stamper.stamp(&master_key_stamper, Confidence::Low, Timestamp::now(), identity.id(), &claim, Some(Timestamp::from_str("2060-01-01T06:59:00Z").unwrap())).unwrap();

        let transactions3 = transactions2.accept_stamp(&master_key, Timestamp::now(), stamp.clone()).unwrap();
        assert_eq!(transactions3.transactions().len(), 3);
        assert_signkey! { transactions3.transactions()[2], Root }
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.claims()[0].stamps().len(), 1);

        let res = transactions3.clone().accept_stamp(&master_key, Timestamp::now(), stamp.clone());
        assert_eq!(res.err(), Some(Error::IdentityStampAlreadyExists));

        let transactions4 = transactions3.clone().delete_claim(&master_key, Timestamp::now(), claim.id().clone()).unwrap();
        let res = transactions4.accept_stamp(&master_key, Timestamp::now(), stamp.clone());
        assert_eq!(res.err(), Some(Error::IdentityClaimNotFound));
    }

    #[test]
    fn transactions_delete_stamp() {
        let (master_key, transactions) = genesis();
        let identity_id = IdentityID(transactions.transactions()[0].deref().id().deref().clone());
        let transactions2 = transactions.make_claim(&master_key, Timestamp::now(), ClaimSpec::Identity(identity_id)).unwrap();
        let identity = transactions2.build_identity().unwrap();
        assert_eq!(identity.claims()[0].stamps().len(), 0);
        let claim = identity.claims()[0].claim().clone();

        let (master_key_stamper, transactions_stamper) = genesis();
        let identity_stamper = transactions_stamper.build_identity().unwrap();
        let stamp = identity_stamper.stamp(&master_key_stamper, Confidence::Low, Timestamp::now(), identity.id(), &claim, Some(Timestamp::from_str("2060-01-01T06:59:00Z").unwrap())).unwrap();

        let transactions3 = transactions2.accept_stamp(&master_key, Timestamp::now(), stamp.clone()).unwrap();
        assert_eq!(transactions3.transactions().len(), 3);
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.claims()[0].stamps().len(), 1);

        let transactions4 = transactions3.clone().delete_stamp(&master_key, Timestamp::now(), stamp.id().clone()).unwrap();
        let identity4 = transactions4.build_identity().unwrap();
        assert_eq!(identity4.claims()[0].stamps().len(), 0);
        assert_signkey! { transactions4.transactions()[3], Root }

        let res = transactions4.clone().delete_stamp(&master_key, Timestamp::now(), stamp.id().clone());
        assert_eq!(res.err(), Some(Error::IdentityStampNotFound));
    }

    macro_rules! key_setter {
        ($ty:ident, $keychain_getter:ident, $transaction_fn:ident, $key_getter:ident, $strname:expr) => {{
            let (master_key, transactions) = genesis();
            let identity = transactions.build_identity().unwrap();
            let current_keypair = identity.keychain().$keychain_getter();
            assert_eq!(identity.keychain().subkeys().len(), 0);

            let new_keypair = $ty::new_ed25519(&master_key).unwrap();
            assert!(&new_keypair != current_keypair);
            let transactions2 = transactions.$transaction_fn(&master_key, Timestamp::now(), new_keypair.clone(), RevocationReason::Superseded).unwrap();
            assert_signkey! { transactions2.transactions()[1], Alpha }
            let identity2 = transactions2.build_identity().unwrap();
            assert_eq!(identity2.keychain().$keychain_getter(), &new_keypair);
            assert_eq!(identity2.keychain().subkeys()[0].key().$key_getter().as_ref().unwrap(), &current_keypair);
            assert_eq!(identity2.keychain().subkeys()[0].name(), &format!($strname, current_keypair.key_id().as_string()));

            let transactions3 = transactions2.$transaction_fn(&master_key, Timestamp::now(), new_keypair.clone(), RevocationReason::Superseded).unwrap();
            assert_signkey! { transactions3.transactions()[2], Alpha }
            let identity3 = transactions3.build_identity().unwrap();
            assert_eq!(identity3.keychain().$keychain_getter(), &new_keypair);
            assert_eq!(identity3.keychain().subkeys()[0].key().$key_getter().as_ref().unwrap(), &current_keypair);
            assert_eq!(identity3.keychain().subkeys()[0].name(), &format!($strname, current_keypair.key_id().as_string()));
            assert_eq!(identity3.keychain().subkeys()[1].key().$key_getter().unwrap(), &new_keypair);
            assert_eq!(identity3.keychain().subkeys()[1].name(), &format!($strname, new_keypair.key_id().as_string()));
            transactions3
        }}
    }

    #[test]
    fn transactions_set_policy_key() {
        key_setter! {
            PolicyKeypair,
            policy,
            set_policy_key,
            as_policykey,
            "revoked:policy:{}"
        };
    }

    #[test]
    fn transactions_set_publish_key() {
        key_setter! {
            PublishKeypair,
            publish,
            set_publish_key,
            as_publishkey,
            "revoked:publish:{}"
        };
    }

    #[test]
    fn transactions_set_root_key() {
        key_setter! {
            RootKeypair,
            root,
            set_root_key,
            as_rootkey,
            "revoked:root:{}"
        };
    }

    #[test]
    fn transactions_add_subkey() {
        let (master_key, transactions) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert_eq!(identity.keychain().subkeys().len(), 0);

        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = Private::seal(&master_key, &SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let transactions2 = transactions
            .add_subkey(&master_key, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things")).unwrap()
            .add_subkey(&master_key, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails")).unwrap()
            .add_subkey(&master_key, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key")).unwrap();
        assert_signkey! { transactions2.transactions()[1], Root }
        assert_signkey! { transactions2.transactions()[2], Root }
        assert_signkey! { transactions2.transactions()[3], Root }
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.keychain().subkeys()[0].name(), "default:sign");
        assert_eq!(identity2.keychain().subkeys()[1].name(), "default:crypto");
        assert_eq!(identity2.keychain().subkeys()[2].name(), "default:secret");
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let res = transactions2.clone()
            .add_subkey(&master_key, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things"));
        assert_eq!(res.err(), Some(Error::DuplicateName));
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let res = transactions2.clone()
            .add_subkey(&master_key, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails"));
        assert_eq!(res.err(), Some(Error::DuplicateName));
        let secret_key = Private::seal(&master_key, &SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let res = transactions2.clone()
            .add_subkey(&master_key, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key"));
        assert_eq!(res.err(), Some(Error::DuplicateName));
    }

    #[test]
    fn transactions_revoke_subkey() {
        let (master_key, transactions) = genesis();

        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = Private::seal(&master_key, &SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let transactions2 = transactions
            .add_subkey(&master_key, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things")).unwrap()
            .add_subkey(&master_key, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails")).unwrap()
            .add_subkey(&master_key, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key")).unwrap();
        let transactions3 = transactions2.clone()
            .revoke_subkey(&master_key, Timestamp::now(), "default:crypto", RevocationReason::Superseded, Some("revoked:default:crypto")).unwrap();
        assert_signkey! { transactions3.transactions()[4], Root }
        let identity3 = transactions3.build_identity().unwrap();
        assert!(identity3.keychain().subkeys()[0].revocation().is_none());
        assert_eq!(identity3.keychain().subkeys()[1].revocation().as_ref().map(|x| x.reason()), Some(&RevocationReason::Superseded));
        assert!(identity3.keychain().subkeys()[2].revocation().is_none());

        let res = transactions3.clone()
            .revoke_subkey(&master_key, Timestamp::now(), "default:crypto", RevocationReason::Superseded, Some("revoked:default:crypto"));
        assert_eq!(res.err(), Some(Error::IdentitySubkeyNotFound));
        let res = transactions3.clone()
            .revoke_subkey(&master_key, Timestamp::now(), "revoked:default:crypto", RevocationReason::Superseded, Some("revoked:default:crypto"));
        assert_eq!(res.err(), Some(Error::IdentitySubkeyAlreadyRevoked));
    }

    #[test]
    fn transactions_delete_subkey() {
        let (master_key, transactions) = genesis();

        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = Private::seal(&master_key, &SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let transactions2 = transactions
            .add_subkey(&master_key, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things")).unwrap()
            .add_subkey(&master_key, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails")).unwrap()
            .add_subkey(&master_key, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key")).unwrap();

        let transactions3 = transactions2.clone()
            .delete_subkey(&master_key, Timestamp::now(), "default:sign").unwrap();
        assert_signkey! { transactions3.transactions()[4], Root }
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.keychain().subkeys()[0].name(), "default:crypto");
        assert_eq!(identity3.keychain().subkeys()[1].name(), "default:secret");
        assert_eq!(identity3.keychain().subkeys().len(), 2);

        let res = transactions3.clone()
            .delete_subkey(&master_key, Timestamp::now(), "default:sign");
        assert_eq!(res.err(), Some(Error::IdentitySubkeyNotFound));
    }

    #[test]
    fn transactions_set_nickname() {
        let (master_key, transactions) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert_eq!(identity.extra_data().nickname(), &None);

        let transactions2 = transactions
            .set_nickname(&master_key, Timestamp::now(), Some("dirk-delta")).unwrap();
        assert_signkey! { transactions2.transactions()[1], Root }
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.extra_data().nickname(), &Some("dirk-delta".into()));

        let no_name: Option<String> = None;
        let transactions3 = transactions2
            .set_nickname(&master_key, Timestamp::now(), no_name).unwrap();
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.extra_data().nickname(), &None);
    }

    #[test]
    fn transactions_add_forward() {
        let (master_key, transactions) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert_eq!(identity.extra_data().forwards().len(), 0);

        let transactions2 = transactions
            .add_forward(&master_key, Timestamp::now(), "email", ForwardType::Email("jackie@chrome.com".into()), true).unwrap()
            .add_forward(&master_key, Timestamp::now(), "my-website", ForwardType::Url("https://www.cactus-petes.com/yeeeehawwww".into()), false).unwrap()
            .add_forward(&master_key, Timestamp::now(), "twitter", ForwardType::Social { ty: "twitter".into(), handle: "lol_twitter_sux".into() }, false).unwrap();
        assert_signkey! { transactions2.transactions()[1], Root }
        assert_signkey! { transactions2.transactions()[2], Root }
        assert_signkey! { transactions2.transactions()[3], Root }
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.extra_data().forwards().len(), 3);
        assert_eq!(identity2.extra_data().forwards()[0].name(), "email");
        assert_eq!(identity2.extra_data().forwards()[1].name(), "my-website");
        assert_eq!(identity2.extra_data().forwards()[2].name(), "twitter");

        let res = transactions2.clone()
            .add_forward(&master_key, Timestamp::now(), "email", ForwardType::Email("jack.mama@highland.edu".into()), true);
        assert_eq!(res.err(), Some(Error::DuplicateName));
    }

    #[test]
    fn transactions_delete_forward() {
        let (master_key, transactions) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert_eq!(identity.extra_data().forwards().len(), 0);

        let transactions2 = transactions
            .add_forward(&master_key, Timestamp::now(), "email", ForwardType::Email("jackie@chrome.com".into()), true).unwrap()
            .add_forward(&master_key, Timestamp::now(), "my-website", ForwardType::Url("https://www.cactus-petes.com/yeeeehawwww".into()), false).unwrap()
            .add_forward(&master_key, Timestamp::now(), "twitter", ForwardType::Social { ty: "twitter".into(), handle: "lol_twitter_sux".into() }, false).unwrap();
        let transactions3 = transactions2
            .delete_forward(&master_key, Timestamp::now(), "my-website").unwrap();
        assert_signkey! { transactions3.transactions()[4], Root }
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.extra_data().forwards().len(), 2);
        assert_eq!(identity3.extra_data().forwards()[0].name(), "email");
        assert_eq!(identity3.extra_data().forwards()[1].name(), "twitter");

        let res = transactions3.clone()
            .delete_forward(&master_key, Timestamp::now(), "my-website");
        assert_eq!(res.err(), Some(Error::IdentityForwardNotFound));
    }

    #[test]
    fn transactions_reencrypt() {
        let (master_key, transactions) = genesis();
        let transactions = transactions
            .make_claim(&master_key, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_private(&master_key, "Hooty McOwl".to_string()).unwrap())).unwrap()
            .set_root_key(&master_key, Timestamp::now(), RootKeypair::new_ed25519(&master_key).unwrap(), RevocationReason::Unspecified).unwrap()
            .set_nickname(&master_key, Timestamp::now(), Some("dirk-delta")).unwrap()
            .add_forward(&master_key, Timestamp::now(), "my-website", ForwardType::Url("https://www.cactus-petes.com/yeeeehawwww".into()), false).unwrap();
        transactions.test_master_key(&master_key).unwrap();
        let identity = transactions.build_identity().unwrap();
        match identity.claims()[0].claim().spec() {
            ClaimSpec::Name(maybe) => {
                let val = maybe.open(&master_key).unwrap();
                assert_eq!(val, "Hooty McOwl".to_string());
            }
            _ => panic!("bad claim type"),
        }
        let sig = identity.keychain().root().sign(&master_key, "KILL...ME....".as_bytes()).unwrap();

        let master_key_new = SecretKey::new_xchacha20poly1305().unwrap();
        let transactions2 = transactions.reencrypt(&master_key, &master_key_new).unwrap();
        transactions2.test_master_key(&master_key_new).unwrap();
        let res = transactions2.test_master_key(&master_key);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
        let identity2 = transactions2.build_identity().unwrap();
        let sig2 = identity2.keychain().root().sign(&master_key_new, "KILL...ME....".as_bytes()).unwrap();
        assert_eq!(sig, sig2);
        match identity2.claims()[0].claim().spec() {
            ClaimSpec::Name(maybe) => {
                let val = maybe.open(&master_key_new).unwrap();
                assert_eq!(val, "Hooty McOwl".to_string());
                let res = maybe.open(&master_key);
                assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
            }
            _ => panic!("bad claim type"),
        }
    }

    #[test]
    fn transactions_is_owned() {
        let (master_key, transactions) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert!(transactions.is_owned());
        assert!(identity.is_owned());

        let mut transactions2 = transactions.clone();
        transactions2.transactions_mut()[0] = transactions2.transactions_mut()[0].strip_private();
        let identity2 = transactions2.build_identity().unwrap();
        assert!(!transactions2.is_owned());
        assert!(!identity2.is_owned());

        let policy = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root = RootKeypair::new_ed25519(&master_key).unwrap();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = Private::seal(&master_key, &SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let transactions3 = transactions.clone()
            .add_subkey(&master_key, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things")).unwrap()
            .add_subkey(&master_key, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails")).unwrap()
            .add_subkey(&master_key, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key")).unwrap()
            .set_policy_key(&master_key, Timestamp::now(), policy.clone(), RevocationReason::Unspecified).unwrap()
            .set_publish_key(&master_key, Timestamp::now(), publish.clone(), RevocationReason::Unspecified).unwrap()
            .set_root_key(&master_key, Timestamp::now(), root.clone(), RevocationReason::Unspecified).unwrap();
        let identity3 = transactions3.build_identity().unwrap();
        assert!(transactions3.is_owned());
        assert!(identity3.is_owned());

        let mut transactions4 = transactions3.clone();
        for trans in transactions4.transactions_mut() {
            let entry = trans.entry().clone();
            match entry.body() {
                TransactionBody::CreateIdentityV1 { .. } | TransactionBody::SetPolicyKeyV1 { .. } | TransactionBody::SetPublishKeyV1 { .. } | TransactionBody::SetRootKeyV1 { .. } => {
                    match trans {
                        TransactionVersioned::V1(ref mut inner) => {
                            inner.set_entry(entry.strip_private());
                        }
                    }
                }
                _ => {}
            }
        }
        let identity4 = transactions4.build_identity().unwrap();
        assert!(!transactions4.is_owned());
        assert!(!identity4.is_owned());
    }

    #[test]
    fn transactions_test_master_key() {
        let (master_key, transactions) = genesis();
        transactions.test_master_key(&master_key).unwrap();
        let master_key_fake = SecretKey::new_xchacha20poly1305().unwrap();
        assert!(master_key_fake != master_key);
        let res = transactions.test_master_key(&master_key_fake);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
    }

    #[test]
    fn transactions_strip_has_private() {
        let (master_key, transactions) = genesis();

        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = Private::seal(&master_key, &SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let transactions2 = transactions
            .add_subkey(&master_key, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things")).unwrap()
            .add_subkey(&master_key, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails")).unwrap()
            .add_subkey(&master_key, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key")).unwrap()
            .make_claim(&master_key, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_private(&master_key, "Danny Dinkel".to_string()).unwrap())).unwrap()
            .make_claim(&master_key, Timestamp::now(), ClaimSpec::Email(MaybePrivate::new_public("twinkie.doodle@amateur-spotlight.net".to_string()))).unwrap();

        let mut has_priv: Vec<bool> = Vec::new();
        for trans in transactions2.transactions() {
            has_priv.push(trans.has_private());
        }
        assert_eq!(has_priv.iter().filter(|x| **x).count(), 5);

        assert!(transactions2.has_private());
        let transactions3 = transactions2.strip_private();
        assert!(!transactions3.has_private());

        let mut has_priv: Vec<bool> = Vec::new();
        for trans in transactions3.transactions() {
            has_priv.push(trans.has_private());
        }
        assert_eq!(has_priv.iter().filter(|x| **x).count(), 0);
    }

    #[test]
    fn transactions_serde_binary() {
        let (_master_key, transactions) = genesis();
        let identity = transactions.build_identity().unwrap();
        let ser = transactions.serialize_binary().unwrap();
        let des = Transactions::deserialize_binary(ser.as_slice()).unwrap();
        let identity2 = des.build_identity().unwrap();
        // quick and dirty. oh well.
        assert_eq!(identity.id(), identity2.id());
    }
}

