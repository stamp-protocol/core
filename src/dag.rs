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
        ser,
    },
};
use getset;
use serde_derive::{Serialize, Deserialize};
use std::collections::HashMap;
use std::ops::Deref;

/// This is all of the possible transactions that can be performed on an
/// identity, including the data they require.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    CreateIdentityV1(AlphaKeypair, PolicyKeypair, PublishKeypair, RootKeypair),
    SetRecoveryPolicyV1(Option<PolicyCondition>),
    ExecuteRecoveryPolicyV1(PolicyRequest),
    MakeClaimV1(ClaimSpec),
    DeleteClaimV1(ClaimID),
    AcceptStampV1(Stamp),
    DeleteStampV1(StampID),
    SetPolicyKeyV1(PolicyKeypair, RevocationReason),
    SetPublishKeyV1(PublishKeypair, RevocationReason),
    SetRootKeyV1(RootKeypair, RevocationReason),
    AddSubkeyV1(Key, String, Option<String>),
    EditSubkeyV1(String, String, Option<String>),
    RevokeSubkeyV1(String, RevocationReason, Option<String>),
    DeleteSubkeyV1(String),
    SetNicknameV1(Option<String>),
    AddForwardV1(String, ForwardType, bool),
    DeleteForwardV1(String),
}

impl Public for TransactionBody {
    fn strip_private(&self) -> Self {
        match self.clone() {
            Self::Private => Self::Private,
            Self::CreateIdentityV1(alpha, policy, publish, root) => {
                Self::CreateIdentityV1(alpha.strip_private(), policy.strip_private(), publish.strip_private(), root.strip_private())
            }
            Self::SetRecoveryPolicyV1(policy) => Self::SetRecoveryPolicyV1(policy),
            Self::ExecuteRecoveryPolicyV1(request) => Self::ExecuteRecoveryPolicyV1(request.strip_private()),
            Self::MakeClaimV1(spec) => Self::MakeClaimV1(spec.strip_private()),
            Self::DeleteClaimV1(claim_id) => Self::DeleteClaimV1(claim_id),
            Self::AcceptStampV1(stamp) => Self::AcceptStampV1(stamp.strip_private()),
            Self::DeleteStampV1(stamp_id) => Self::DeleteStampV1(stamp_id),
            Self::SetPolicyKeyV1(keypair, revocation) => {
                Self::SetPolicyKeyV1(keypair.strip_private(), revocation)
            }
            Self::SetPublishKeyV1(keypair, revocation) => {
                Self::SetPublishKeyV1(keypair.strip_private(), revocation)
            }
            Self::SetRootKeyV1(keypair, revocation) => {
                Self::SetRootKeyV1(keypair.strip_private(), revocation)
            }
            Self::AddSubkeyV1(key, name, desc) => {
                // here's a good place to use Self::Private -- if stripping the
                // key removes ALL of its data, then we probably don't want to
                // include the transaction body.
                match key.strip_private_maybe() {
                    Some(stripped) => Self::AddSubkeyV1(stripped, name, desc),
                    None => Self::Private,
                }
            }
            Self::EditSubkeyV1(name, new_name, new_desc) => Self::EditSubkeyV1(name, new_name, new_desc),
            Self::RevokeSubkeyV1(key_id, revocation, new_name) => Self::RevokeSubkeyV1(key_id, revocation, new_name),
            Self::DeleteSubkeyV1(key_id) => Self::DeleteSubkeyV1(key_id),
            Self::SetNicknameV1(nick) => Self::SetNicknameV1(nick),
            Self::AddForwardV1(name, forward, default) => Self::AddForwardV1(name, forward, default),
            Self::DeleteForwardV1(name) => Self::DeleteForwardV1(name),
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::Private => false,
            Self::CreateIdentityV1(alpha, policy, publish, root) => {
                alpha.has_private() || policy.has_private() || publish.has_private() || root.has_private()
            }
            Self::SetRecoveryPolicyV1(..) => false,
            Self::ExecuteRecoveryPolicyV1(request) => request.has_private(),
            Self::MakeClaimV1(spec) => spec.has_private(),
            Self::DeleteClaimV1(..) => false,
            Self::AcceptStampV1(..) => false,
            Self::DeleteStampV1(..) => false,
            Self::SetPolicyKeyV1(keypair, ..) => keypair.has_private(),
            Self::SetPublishKeyV1(keypair, ..) => keypair.has_private(),
            Self::SetRootKeyV1(keypair, ..) => keypair.has_private(),
            Self::AddSubkeyV1(key, ..) => key.has_private(),
            Self::EditSubkeyV1(..) => false,
            Self::RevokeSubkeyV1(..) => false,
            Self::DeleteSubkeyV1(..) => false,
            Self::SetNicknameV1(..) => false,
            Self::AddForwardV1(..) => false,
            Self::DeleteForwardV1(..) => false,
        }
    }
}

/// The TransactionID holds the signature of a transaction by a particular key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionID {
    Alpha(AlphaKeypairSignature),
    Policy(PolicyKeypairSignature),
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

/// The body of an identity transaction. Holds the transaction's references to
/// its previous transactions and the transaction type/data itself.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct TransactionEntry {
    /// When this transaction was created.
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
    previous_transactions: Vec<TransactionID>,
    /// This holds the actual transaction data.
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
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Transaction {
    /// This is a signature of this transaction's `entry`.
    id: TransactionID,
    /// This holds our transaction body: any references to previous
    /// transactions as well as the transaction type/data.
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
                    TransactionBody::ExecuteRecoveryPolicyV1(request) => {
                        match request.entry().action() {
                            PolicyRequestAction::ReplaceKeys(policy, ..) => {
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
                    TransactionBody::CreateIdentityV1(ref alpha, ..) => {
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
                    TransactionBody::ExecuteRecoveryPolicyV1(request) => {
                        match request.entry().action() {
                            PolicyRequestAction::ReplaceKeys(policy, ..) => {
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
                    TransactionBody::CreateIdentityV1(ref alpha, ..) => {
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionVersioned {
    V1(Transaction),
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
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Transactions {
    /// The actual transactions.
    transactions: Vec<TransactionVersioned>,
}

impl Transactions {
    /// Create a new, empty transaction set.
    pub fn new() -> Self {
        Self {transactions: vec![]}
    }

    /// Make sure the given transaction list is ordered based on the graph of
    /// the entries in it.
    ///
    /// Uses Kahn's algorithm: https://en.wikipedia.org/wiki/Topological_sorting#Kahn's_algorithm
    /// Thanks, Kahn. I tried doing it my own way but flubbed it pretty hard.
    pub(crate) fn order_transactions<T: GraphInfo>(transaction_list: &Vec<T>) -> Result<Vec<&T>> {
        let first = transaction_list.iter().find(|t| t.previous_transactions().len() == 0)
            .ok_or(Error::DagNoGenesis)?;
        let mut index: HashMap<String, &T> = HashMap::new();
        let mut edges_idx: HashMap<String, Vec<TransactionID>> = HashMap::new();
        let mut transaction_list = transaction_list.iter().collect::<Vec<_>>();
        // this always gives us a deterministic result, regardless of the order
        // of the given list.
        transaction_list.sort_by_key(|t| t.created());
        for trans in &transaction_list {
            let key = String::from(trans.id().clone());
            index.insert(key.clone(), trans);
            edges_idx.insert(key, trans.previous_transactions().clone());
        }
        let mut res = Vec::new();
        let mut start = vec![first];
        let mut start_idx = 0;
        loop {
            let current = start[start_idx];
            res.push(current);
            for next in &transaction_list {
                let key = String::from(next.id().clone());
                let edges = edges_idx.get_mut(&key).ok_or(Error::DagOrderingError)?;
                let edges_len = edges.len();
                edges.retain(|x| x != current.id());
                // if our len has changed, it means that the `next` transaction
                // we're looking at referenced the `current` transaction, and if
                // the current -> next edge is removed AND that leaves `next`
                // with no more edges, we push it onto our list of "start" nodes
                // (ie, nodes that don't reference any other nodes).
                if edges_len != edges.len() && edges.len() == 0 {
                    start.push(next);
                }
            }
            start_idx += 1;
            if start_idx >= start.len() {
                break;
            }
        }
        Ok(res)
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
                    TransactionBody::CreateIdentityV1(alpha, policy, publish, root) => {
                        let identity_id = IdentityID(trans.id().deref().clone());
                        Ok(Identity::create(identity_id, alpha, policy, publish, root, trans.entry().created().clone()))
                    }
                    TransactionBody::SetRecoveryPolicyV1(policy_condition) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .set_recovery(PolicyID(trans.id().deref().clone()), policy_condition);
                        Ok(identity_mod)
                    }
                    TransactionBody::ExecuteRecoveryPolicyV1(request) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .execute_recovery(request)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::MakeClaimV1(spec) => {
                        let claim_id = ClaimID(trans.id().deref().clone());
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .make_claim(claim_id, spec);
                        Ok(identity_mod)
                    }
                    TransactionBody::DeleteClaimV1(claim_id) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .delete_claim(&claim_id)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::AcceptStampV1(stamp) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .accept_stamp(stamp)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::DeleteStampV1(stamp_id) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .delete_stamp(&stamp_id)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::SetPolicyKeyV1(keypair, revocation_reason) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .set_policy_key(keypair, revocation_reason)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::SetPublishKeyV1(keypair, revocation_reason) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .set_publish_key(keypair, revocation_reason)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::SetRootKeyV1(keypair, revocation_reason) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .set_root_key(keypair, revocation_reason)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::AddSubkeyV1(key, name, desc) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .add_subkey(key, name, desc)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::EditSubkeyV1(name, new_name, new_desc) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .edit_subkey(&name, new_name, new_desc)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::RevokeSubkeyV1(key_id, revocation_reason, new_name) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .revoke_subkey(&key_id, revocation_reason, new_name)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::DeleteSubkeyV1(key_id) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .delete_subkey(&key_id)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::SetNicknameV1(nickname) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .set_nickname(nickname);
                        Ok(identity_mod)
                    }
                    TransactionBody::AddForwardV1(name, ty, is_default) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .add_forward(name, ty, is_default)?;
                        Ok(identity_mod)
                    }
                    TransactionBody::DeleteForwardV1(name) => {
                        let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                            .delete_forward(&name)?;
                        Ok(identity_mod)
                    }
                }
            }
        }
    }

    /// Build an identity by replaying our transactions in order.
    pub fn build_identity(&self) -> Result<Identity> {
        if self.transactions().len() == 0 {
            Err(Error::DagEmpty)?;
        }
        let transactions = Self::order_transactions(self.transactions())?;
        if transactions.len() == 0 {
            Err(Error::DagEmpty)?;
        }
        fn looper(transactions: &[&TransactionVersioned], identity: Identity) -> Result<Identity> {
            if transactions.len() == 0 {
                Ok(identity)
            } else {
                transactions[0].verify(Some(&identity))?;
                looper(&transactions[1..], Transactions::apply_transaction(Some(identity), transactions[0])?)
            }
        }
        transactions[0].verify(None)?;
        looper(&transactions[1..], Transactions::apply_transaction(None, transactions[0])?)
    }

    /// Find any transactions that are not referenced as previous transactions.
    /// Effectively, the leaves of our graph.
    fn find_leaf_transactions<T: GraphInfo>(transaction_list: &Vec<T>) -> Vec<TransactionID> {
        let mut seen: HashMap<String, bool> = HashMap::new();
        for trans in transaction_list {
            for prev in trans.previous_transactions() {
                seen.insert(String::from(prev.clone()), true);
            }
        }
        transaction_list.iter()
            .filter_map(|t| {
                if seen.get(&String::from(t.id().clone())).is_some() {
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

    /// Create an identity.
    pub fn create_identity<T: Into<Timestamp> + Clone>(mut self, master_key: &SecretKey, now: T, alpha: AlphaKeypair, policy: PolicyKeypair, publish: PublishKeypair, root: RootKeypair) -> Result<Self> {
        if self.transactions().len() > 0 {
            Err(Error::DagCreateIdentityOnExistingChain)?;
        }
        let body = TransactionBody::CreateIdentityV1(alpha.clone(), policy, publish, root);
        self.push_transaction(master_key, SignWith::Alpha, now.clone(), body)?;
        Ok(self)
    }

    /// Set a recovery policy.
    pub fn set_recovery_policy<T: Into<Timestamp> + Clone>(mut self, master_key: &SecretKey, now: T, policy: Option<PolicyCondition>) -> Result<Self> {
        let body = TransactionBody::SetRecoveryPolicyV1(policy);
        self.push_transaction(master_key, SignWith::Policy, now, body)?;
        Ok(self)
    }

    /// Execute a recovery policy (replace your keys via a policy).
    pub fn execute_recovery_policy<T: Into<Timestamp> + Clone>(mut self, master_key: &SecretKey, now: T, request: PolicyRequest) -> Result<Self> {
        let body = TransactionBody::ExecuteRecoveryPolicyV1(request);
        self.push_transaction(master_key, SignWith::Policy, now, body)?;
        Ok(self)
    }

    /// Make a new claim.
    pub fn make_claim<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, spec: ClaimSpec) -> Result<Self> {
        let body = TransactionBody::MakeClaimV1(spec);
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Delete an existing claim.
    pub fn delete_claim<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, claim_id: ClaimID) -> Result<Self> {
        let body = TransactionBody::DeleteClaimV1(claim_id);
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Accept a stamp someone, or some*thing*, has made on a claim of ours.
    pub fn accept_stamp<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, stamp: Stamp) -> Result<Self> {
        let body = TransactionBody::AcceptStampV1(stamp);
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Delete an existing stamp.
    pub fn delete_stamp<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, stamp_id: StampID) -> Result<Self> {
        let body = TransactionBody::DeleteStampV1(stamp_id);
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Assign a new policy key to this identity. Requires an alpha sig.
    pub fn set_policy_key<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, keypair: PolicyKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        let body = TransactionBody::SetPolicyKeyV1(keypair, revocation_reason);
        self.push_transaction(master_key, SignWith::Alpha, now, body)?;
        Ok(self)
    }

    /// Assign a new publish key to this identity. Requires an alpha sig.
    pub fn set_publish_key<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, keypair: PublishKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        let body = TransactionBody::SetPublishKeyV1(keypair, revocation_reason);
        self.push_transaction(master_key, SignWith::Alpha, now, body)?;
        Ok(self)
    }

    /// Assign a new root key to this identity. Requires an alpha sig.
    pub fn set_root_key<T: Into<Timestamp>>(mut self, master_key: &SecretKey, now: T, keypair: RootKeypair, revocation_reason: RevocationReason) -> Result<Self> {
        let body = TransactionBody::SetRootKeyV1(keypair, revocation_reason);
        self.push_transaction(master_key, SignWith::Alpha, now, body)?;
        Ok(self)
    }

    /// Add a new subkey to our keychain.
    pub fn add_subkey<T, S>(mut self, master_key: &SecretKey, now: T, key: Key, name: S, description: Option<S>) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::AddSubkeyV1(key, name.into(), description.map(|x| x.into()));
        self.push_transaction(master_key, SignWith::Alpha, now, body)?;
        Ok(self)
    }

    /// Edit a subkey.
    pub fn edit_subkey<T, S>(mut self, master_key: &SecretKey, now: T, name: S, new_name: S, description: Option<S>) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::EditSubkeyV1(name.into(), new_name.into(), description.map(|x| x.into()));
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Revoke a subkey.
    pub fn revoke_subkey<T, S>(mut self, master_key: &SecretKey, now: T, name: S, revocation_reason: RevocationReason, new_name: Option<S>) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::RevokeSubkeyV1(name.into(), revocation_reason, new_name.map(|x| x.into()));
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Delete a subkey.
    pub fn delete_subkey<T, S>(mut self, master_key: &SecretKey, now: T, name: S) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::DeleteSubkeyV1(name.into());
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Set the nickname on this identity.
    pub fn set_nickname<T, S>(mut self, master_key: &SecretKey, now: T, nickname: Option<S>) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::SetNicknameV1(nickname.map(|x| x.into()));
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Add a new forward.
    pub fn add_forward<T, S>(mut self, master_key: &SecretKey, now: T, name: S, ty: ForwardType, is_default: bool) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::AddForwardV1(name.into(), ty, is_default);
        self.push_transaction(master_key, SignWith::Root, now, body)?;
        Ok(self)
    }

    /// Delete an existing forward.
    pub fn delete_forward<T, S>(mut self, master_key: &SecretKey, now: T, name: S) -> Result<Self>
        where T: Into<Timestamp>,
              S: Into<String>,
    {
        let body = TransactionBody::DeleteForwardV1(name.into());
        self.push_transaction(master_key, SignWith::Root, now, body)?;
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
                        TransactionBody::CreateIdentityV1(..) => trans.entry().body().has_private(),
                        TransactionBody::SetPolicyKeyV1(..) => trans.entry().body().has_private(),
                        TransactionBody::SetPublishKeyV1(..) => trans.entry().body().has_private(),
                        TransactionBody::SetRootKeyV1(..) => trans.entry().body().has_private(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::{
            claim::{ClaimBin, Relationship, RelationshipType},
        },
        private::MaybePrivate,
        util::{self, Date},
    };
    use std::str::FromStr;
    use url::Url;

    #[test]
    fn trans_body_strip() {
        unimplemented!();
    }

    #[test]
    fn trans_entry_strip() {
        unimplemented!();
    }

    #[test]
    fn trans_new_verify() {
        unimplemented!();
    }

    #[test]
    fn trans_strip() {
        unimplemented!();
    }

    #[test]
    fn trans_versioned_verify() {
        unimplemented!();
    }

    #[test]
    fn trans_versioned_strip() {
        unimplemented!();
    }

    #[test]
    fn transactions_order() {
        #[derive(Debug, Clone)]
        struct MyTransaction {
            id: TransactionID,
            created: Timestamp,
            prev: Vec<TransactionID>,
        }

        impl GraphInfo for MyTransaction {
            fn id(&self) -> &TransactionID { &self.id }
            fn created(&self) -> &Timestamp { &self.created }
            fn previous_transactions(&self) -> &Vec<TransactionID> { &self.prev }
        }

        let mut idx = 0;
        let master_key = SecretKey::new_xsalsa20poly1305();
        let mut make_trans = |prev: Vec<&TransactionID>| {
            let root = RootKeypair::new_ed25519(&master_key).unwrap();
            let sig = root.sign(&master_key, format!("idx:{}", idx).as_bytes()).unwrap();
            let id = TransactionID::Root(sig);
            idx += 1;
            util::test::sleep(2);
            MyTransaction {
                id,
                created: Timestamp::now(),
                prev: prev.into_iter().map(|x| x.clone()).collect::<Vec<_>>(),
            }
        };

        fn assert_order(transactions: Vec<&MyTransaction>, shouldbe_ids: Vec<&TransactionID>) {
            let list = transactions.into_iter().map(|x| x.clone()).collect::<Vec<_>>();
            let ordered = Transactions::order_transactions(&list).unwrap();
            assert_eq!(
                ordered.iter().map(|x| x.id()).collect::<Vec<_>>(), 
                shouldbe_ids
            );
        }

        // make some basic graphs and hand-fuzz them. honestly need some kind of
        // input fuzzing lib for this.

        let ta = make_trans(vec![]);
        let tb = make_trans(vec![ta.id()]);
        let tc = make_trans(vec![ta.id()]);
        let td = make_trans(vec![tc.id(), tb.id()]);
        assert_order(vec![&td, &tb, &ta, &tc], vec![ta.id(), tb.id(), tc.id(), td.id()]);
        assert_order(vec![&ta, &td, &tc, &tb], vec![ta.id(), tb.id(), tc.id(), td.id()]);
        assert_order(vec![&tb, &td, &ta, &tc], vec![ta.id(), tb.id(), tc.id(), td.id()]);
        assert_order(vec![&tc, &td, &tb, &ta], vec![ta.id(), tb.id(), tc.id(), td.id()]);

        let t01 = make_trans(vec![]);
        let t02 = make_trans(vec![t01.id()]);
        let t03 = make_trans(vec![t01.id()]);
        let t04 = make_trans(vec![t03.id()]);
        let t05 = make_trans(vec![t03.id(), t02.id()]);
        let t06 = make_trans(vec![t05.id(), t03.id(), t04.id()]);

        assert_order(
            vec![&t05, &t03, &t01, &t02, &t04, &t06],
            vec![t01.id(), t02.id(), t03.id(), t04.id(), t05.id(), t06.id()]
        );
        assert_order(
            vec![&t06, &t03, &t05, &t02, &t04, &t01],
            vec![t01.id(), t02.id(), t03.id(), t04.id(), t05.id(), t06.id()]
        );
        assert_order(
            vec![&t05, &t04, &t02, &t01, &t03, &t06],
            vec![t01.id(), t02.id(), t03.id(), t04.id(), t05.id(), t06.id()]
        );
        assert_order(
            vec![&t01, &t05, &t04, &t03, &t02, &t06],
            vec![t01.id(), t02.id(), t03.id(), t04.id(), t05.id(), t06.id()]
        );
    }

    fn genesis() -> (SecretKey, Transactions) {
        let transactions = Transactions::new();
        let master_key = SecretKey::new_xsalsa20poly1305();
        let now = Timestamp::now();
        let alpha = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root = RootKeypair::new_ed25519(&master_key).unwrap();
        let transactions2 = transactions.create_identity(&master_key, now, alpha.clone(), policy.clone(), publish.clone(), root.clone()).unwrap();
        (master_key, transactions2)
    }

    #[test]
    fn transactions_create_identity() {
        let (_master_key, transactions) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert_eq!(identity.id(), &IdentityID(transactions.transactions()[0].id().deref().clone()));
        match &transactions.transactions()[0].entry().body() {
            TransactionBody::CreateIdentityV1(ref alpha, ref policy, ref publish, ref root) => {
                assert_eq!(identity.keychain().alpha(), alpha);
                assert_eq!(identity.keychain().policy(), policy);
                assert_eq!(identity.keychain().publish(), publish);
                assert_eq!(identity.keychain().root(), root);
            }
            _ => panic!("bad transaction type"),
        }
        match identity.claims()[0].claim().spec() {
            ClaimSpec::Identity(ref id) => {
                assert_eq!(id, identity.id())
            }
            _ => panic!("bad claim type"),
        }
    }

    #[test]
    fn transactions_set_recovery() {
        unimplemented!();
    }

    #[test]
    fn transactions_execute_recovery() {
        unimplemented!();
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

                let transactions2 = transactions.clone().make_claim(&master_key, Timestamp::now(), spec_public).unwrap();
                let identity2 = transactions2.build_identity().unwrap();
                let maybe = $get_maybe(identity2.claims()[0].claim().spec().clone());
                assert_eq!(maybe.open(&master_key).unwrap(), val);
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

        assert_claim!{ Name, String::from("Marty Malt") }
        assert_claim!{ Birthday, Date::from_str("2010-01-03").unwrap() }
        assert_claim!{ Email, String::from("marty@sids.com") }
        assert_claim!{ Photo, ClaimBin(vec![1, 2, 3]) }
        assert_claim!{ Pgp, String::from("12345") }
        assert_claim!{ Domain, String::from("slappy.com") }
        assert_claim!{ Url, Url::parse("https://killtheradio.net/").unwrap() }
        assert_claim!{ HomeAddress, String::from("111 blumps ln") }
        assert_claim!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        assert_claim!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, ClaimBin(vec![1, 2, 3, 4, 5])) }
        assert_claim!{
            raw,
            |maybe, _| ClaimSpec::Extension(String::from("id:state:ca"), maybe),
            ClaimBin(vec![7, 3, 2, 90]),
            |spec: ClaimSpec| if let ClaimSpec::Extension(_, maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
        }
    }

    #[test]
    fn transactions_delete_claim() {
        unimplemented!();
    }

    #[test]
    fn transactions_accept_stamp() {
        unimplemented!();
    }

    #[test]
    fn transactions_delete_stamp() {
        unimplemented!();
    }

    #[test]
    fn transactions_set_policy_key() {
        unimplemented!();
    }

    #[test]
    fn transactions_set_publish_key() {
        unimplemented!();
    }

    #[test]
    fn transactions_set_root_key() {
        unimplemented!();
    }

    #[test]
    fn transactions_add_subkey() {
        unimplemented!();
    }

    #[test]
    fn transactions_revoke_subkey() {
        unimplemented!();
    }

    #[test]
    fn transactions_delete_subkey() {
        unimplemented!();
    }

    #[test]
    fn transactions_set_nickname() {
        unimplemented!();
    }

    #[test]
    fn transactions_add_forward() {
        unimplemented!();
    }

    #[test]
    fn transactions_delete_forward() {
        unimplemented!();
    }

    #[test]
    fn transactions_is_owned() {
        unimplemented!();
    }

    #[test]
    fn transactions_test_master_key() {
        unimplemented!();
    }

    #[test]
    fn transactions_strip() {
        unimplemented!();
    }
}

