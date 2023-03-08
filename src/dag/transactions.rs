//! This module holds the logic of the DAG and also assists in the create of
//! valid [Transaction] objects.

use crate::{
    error::{Error, Result},
    crypto::base::{KeyID, SecretKey},
    dag::{TransactionBody, TransactionID, TransactionEntry, Transaction},
    identity::{
        claim::{
            ClaimID,
            ClaimSpec,
        },
        identity::{
            IdentityID,
            Identity,
        },
        keychain::{
            AdminKey,
            AdminKeyID,
            Key,
            RevocationReason,
        },
        stamp::{
            Stamp,
            StampID,
            StampEntry,
            StampRevocation,
            StampRevocationEntry,
            StampRevocationID,
        },
    },
    policy::{Policy, PolicyContainer, PolicyID},
    util::{
        Public,
        Timestamp,
        ser::{BinaryVec, KeyValEntry, SerdeBinary, SerText},
    },
};
use getset;
use rasn::{Encode, Decode, AsnType};
use serde_derive::{Serialize, Deserialize};
use std::collections::HashMap;

/// A container that holds a set of transactions.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Transactions {
    /// The actual transactions.
    #[rasn(tag(explicit(0)))]
    transactions: Vec<Transaction>,
}

impl Transactions {
    /// Create a new, empty transaction set.
    pub fn new() -> Self {
        Self {transactions: vec![]}
    }

    /// Returns an iterator over these transactions
    pub fn iter(&self) -> core::slice::Iter<'_, Transaction> {
        self.transactions().iter()
    }

    /// Grab the [IdentityID] from this transaction set.
    pub fn identity_id(&self) -> Option<IdentityID> {
        if self.transactions().len() > 0 {
            Some(self.transactions()[0].id().clone().into())
        } else {
            None
        }
    }

    /// Creates a new transaction that references the trailing transactions in the
    /// current set.
    pub(crate) fn prepare_transaction<T: Into<Timestamp> + Clone>(&self, now: T, body: TransactionBody) -> Result<Transaction> {
        let leaves = Self::find_leaf_transactions(self.transactions());
        Transaction::new(TransactionEntry::new(now, leaves, body))
    }

    /// Run a transaction and return the output
    fn apply_transaction(identity: Option<Identity>, transaction: &Transaction) -> Result<Identity> {
        match transaction.entry().body().clone() {
            TransactionBody::CreateIdentityV1 { admin_keys, policies } => {
                if identity.is_some() {
                    Err(Error::DagCreateIdentityOnExistingChain)?;
                }
                let policies_con = policies
                    .iter()
                    .map(|x| PolicyContainer::try_from(x.clone()))
                    .collect::<Result<Vec<PolicyContainer>>>()?;
                let identity_id = IdentityID::from(transaction.id().clone());
                Ok(Identity::create(identity_id, admin_keys, policies_con, transaction.entry().created().clone()))
            }
            TransactionBody::ResetIdentityV1 { admin_keys, policies } => {
                let policies_con = if let Some(policies) = policies {
                    let containerized = policies
                        .iter()
                        .map(|x| PolicyContainer::try_from(x.clone()))
                        .collect::<Result<Vec<PolicyContainer>>>()?;
                    Some(containerized)
                } else {
                    None
                };
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .reset(admin_keys, policies_con)?;
                Ok(identity_mod)
            }
            TransactionBody::AddAdminKeyV1 { admin_key } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .add_admin_key(admin_key)?;
                Ok(identity_mod)
            }
            TransactionBody::EditAdminKeyV1 { id, name, description } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .edit_admin_key(&id, name, description)?;
                Ok(identity_mod)
            }
            TransactionBody::RevokeAdminKeyV1 { id, reason, new_name } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .revoke_admin_key(&id, reason, new_name)?;
                Ok(identity_mod)
            }
            TransactionBody::AddPolicyV1 { policy } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .add_policy(PolicyContainer::try_from(policy)?)?;
                Ok(identity_mod)
            }
            TransactionBody::DeletePolicyV1 { id  } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .delete_policy(&id)?;
                Ok(identity_mod)
            }
            TransactionBody::MakeClaimV1 { spec, name } => {
                let claim_id = ClaimID::from(transaction.id().clone());
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .make_claim(claim_id, spec, name)?;
                Ok(identity_mod)
            }
            TransactionBody::EditClaimV1 { claim_id, name } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .edit_claim(&claim_id, name)?;
                Ok(identity_mod)
            }
            TransactionBody::DeleteClaimV1 { claim_id } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .delete_claim(&claim_id)?;
                Ok(identity_mod)
            }
            TransactionBody::MakeStampV1 { stamp: entry } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .make_stamp(Stamp::new(StampID::from(transaction.id().clone()), entry))?;
                Ok(identity_mod)
            }
            TransactionBody::RevokeStampV1 { revocation: entry } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .revoke_stamp(StampRevocation::new(StampRevocationID::from(transaction.id().clone()), entry))?;
                Ok(identity_mod)
            }
            TransactionBody::AcceptStampV1 { stamp_transaction } => {
                stamp_transaction.verify_signatures()?;
                let identity_mod = match stamp_transaction.entry().body() {
                    TransactionBody::MakeStampV1 { stamp: entry } => {
                        let stamp = Stamp::new(StampID::from(stamp_transaction.id().clone()), entry.clone());
                        identity.ok_or(Error::DagMissingIdentity)?
                            .accept_stamp(stamp)?
                    }
                    _ => Err(Error::TransactionMismatch)?,
                };
                Ok(identity_mod)
            }
            TransactionBody::DeleteStampV1 { stamp_id } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .delete_stamp(&stamp_id)?;
                Ok(identity_mod)
            }
            TransactionBody::AddSubkeyV1 { key, name, desc } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .add_subkey(key, name, desc)?;
                Ok(identity_mod)
            }
            TransactionBody::EditSubkeyV1 { id, new_name, new_desc } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .edit_subkey(&id, new_name, new_desc)?;
                Ok(identity_mod)
            }
            TransactionBody::RevokeSubkeyV1 { id, reason, new_name } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .revoke_subkey(&id, reason, new_name)?;
                Ok(identity_mod)
            }
            TransactionBody::DeleteSubkeyV1 { id } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?
                    .delete_subkey(&id)?;
                Ok(identity_mod)
            }
            TransactionBody::PublishV1 { .. } => {
                // NOPE
                Err(Error::TransactionInvalid("Publish transactions cannot be applied to identities".into()))
            }
            TransactionBody::SignV1 { .. } => {
                // NOPE
                Err(Error::TransactionInvalid("Sign transactions cannot be applied to identities".into()))
            }
            TransactionBody::ExtV1 { .. } => {
                // NOPE
                Err(Error::TransactionInvalid("Ext transactions cannot be applied to identities".into()))
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
        let mut transaction_idx: HashMap<TransactionID, &Transaction> = HashMap::new();
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
                    Err(Error::DagOrphanedTransaction(trans.id().as_string()))?;
                }
            }
        }

        // populate a transaction_id -> branchnum index
        let mut transaction_branch_idx: HashMap<TransactionID, Vec<u32>> = HashMap::new();
        fn walker_identity_ranger(transaction_idx: &HashMap<TransactionID, &Transaction>, next_transactions_idx: &HashMap<TransactionID, Vec<TransactionID>>, transaction_branch_idx: &mut HashMap<TransactionID, Vec<u32>>, transaction: &Transaction, cur_branch: Vec<u32>) -> Result<()> {
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
            if transaction.entry().previous_transactions().len() > 1 {
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
            transactions_to_run: Vec<&'a Transaction>,
            // tracks merge transactions, and how many ancestors have been run.
            // when this number reaches previous_transactions().len(), then the
            // merge is free to run.
            pending_merges: HashMap<TransactionID, usize>,
        }

        impl<'a> WalkState<'a> {
            fn next(&self) -> Option<&Transaction> {
                self.transactions_to_run.get(0).map(|x| *x)
            }

            fn remove_first(&mut self) {
                let tx_id = self.transactions_to_run[0].id();
                self.transactions_to_run.retain(|tx| tx.id() != tx_id);
            }

            fn pop_transaction(&mut self, transaction_idx: &HashMap<TransactionID, &'a Transaction>, next_transactions_idx: &HashMap<TransactionID, Vec<TransactionID>>) -> Result<bool> {
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
                    self.transactions_to_run.sort_by_key(|t| t.entry().created());
                }
                Ok(true)
            }
        }

        let mut state = WalkState::default();
        state.transactions_to_run.push(
            transactions.iter().find(|x| x.entry().previous_transactions().len() == 0).ok_or(Error::DagNoGenesis)?
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
                let previous_len = trans.entry().previous_transactions().len();
                if previous_len > 1 {
                    let pending_count = state.pending_merges.get(trans.id()).unwrap_or(&0);
                    // ONLY run a merge transaction if all of its children have
                    // run!!1
                    if *pending_count >= previous_len {
                        let ancestor_collection = trans.entry().previous_transactions().iter()
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
    fn find_leaf_transactions(transaction_list: &Vec<Transaction>) -> Vec<TransactionID> {
        let mut seen: HashMap<TransactionID, bool> = HashMap::new();
        for trans in transaction_list {
            for prev in trans.entry().previous_transactions() {
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

    /// Push a transaction created by one of the transaction-creating functions
    /// onto this transaction set. We consume and return the transaction set for
    /// this.
    pub fn push_transaction(mut self, transaction: Transaction) -> Result<Self> {
        self.push_transaction_raw(transaction)?;
        Ok(self)
    }

    /// Push a transaction onto this transaction set, returning the fully-built
    /// identity created from running all transactions (including the one being
    /// pushed).
    ///
    /// Unless you know you want an [`Identity`] instead of [`Transactions`], or
    /// when in doubt, use [`push_transaction()`][Transactions::push_transaction]
    /// instead of this method.
    pub fn push_transaction_raw(&mut self, transaction: Transaction) -> Result<Identity> {
        if self.transactions().iter().find(|x| x.id() == transaction.id()).is_some() {
            Err(Error::DuplicateTransaction)?;
        }
        let identity_maybe = match self.build_identity() {
            Ok(id) => Some(id),
            Err(Error::DagEmpty) => None,
            Err(e) => Err(e)?,
        };
        let identity = Self::apply_transaction(identity_maybe, &transaction)?;
        self.transactions_mut().push(transaction);
        // build it again
        let _identity_maybe = match self.build_identity() {
            Ok(id) => Some(id),
            Err(Error::DagEmpty) => None,
            Err(e) => Err(e)?,
        };
        Ok(identity)
    }

    /// Merge the transactions from two transaction sets together.
    ///
    /// This is handy if you have two identities with the same root transaction
    /// that have diverged (due to syncing issues, living on a mountain in solitude
    /// for 17 years, etc) and you wish to merge the two diverged identities into
    /// one.
    ///
    /// This is not for turning two separate identities into one. Don't do that.
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
        fn find_tx_to_rm(transactions: &Vec<Transaction>, txid: &TransactionID) -> Vec<TransactionID> {
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
        self.transactions().iter().find(|trans| {
            match trans.entry().body() {
                TransactionBody::CreateIdentityV1 { .. } => trans.entry().body().has_private(),
                TransactionBody::AddAdminKeyV1 { .. } => trans.entry().body().has_private(),
                _ => false,
            }
        }).is_some()
    }

    /// Test if a master key is correct.
    pub fn test_master_key(&self, master_key: &SecretKey) -> Result<()> {
        if !self.is_owned() {
            Err(Error::IdentityNotOwned)?;
        }

        let identity = self.build_identity()?;
        identity.test_master_key(master_key)
    }

    // -------------------------------------------------------------------------
    // The actual transaction builder methods
    // -------------------------------------------------------------------------

    /// Create a new identity. The [ID][TransactionID] of this transaction will
    /// be the identity's public ID forever after.
    pub fn create_identity<T: Into<Timestamp> + Clone>(&self, now: T, admin_keys: Vec<AdminKey>, policies: Vec<Policy>) -> Result<Transaction> {
        let body = TransactionBody::CreateIdentityV1 {
            admin_keys,
            policies,
        };
        self.prepare_transaction(now, body)
    }

    /// Replace optionally both the [admin keys][AdminKey] in the
    /// [Keychain][crate::identity::keychain::Keychain]
    /// and the [policies][Policy] attached to the identity.
    ///
    /// This is more or less a hailmary recovery option that allows gaining
    /// access to identity after some kind of catastrophic event.
    pub fn reset_identity<T: Into<Timestamp> + Clone>(&self, now: T, admin_keys: Option<Vec<AdminKey>>, policies: Option<Vec<Policy>>) -> Result<Transaction> {
        let body = TransactionBody::ResetIdentityV1 {
            admin_keys,
            policies,
        };
        self.prepare_transaction(now, body)
    }

    /// Add a new [admin key][AdminKey] to the [Keychain][crate::identity::keychain::Keychain].
    pub fn add_admin_key<T: Into<Timestamp> + Clone>(&self, now: T, admin_key: AdminKey) -> Result<Transaction> {
        let body = TransactionBody::AddAdminKeyV1 {
            admin_key,
        };
        self.prepare_transaction(now, body)
    }

    /// Edit an [admin key][AdminKey].
    pub fn edit_admin_key<T, S>(&self, now: T, id: AdminKeyID, name: Option<S>, description: Option<Option<S>>) -> Result<Transaction>
        where T: Into<Timestamp> + Clone,
              S: Into<String>,
    {
        let body = TransactionBody::EditAdminKeyV1 {
            id,
            name: name.map(|x| x.into()),
            description: description.map(|x| x.map(|y| y.into())),
        };
        self.prepare_transaction(now, body)
    }

    /// Revokes an [AdminKey] key and moves it into the subkeys, optionally
    /// renaming it.
    pub fn revoke_admin_key<T, S>(&self, now: T, id: AdminKeyID, reason: RevocationReason, new_name: Option<S>) -> Result<Transaction>
        where T: Into<Timestamp> + Clone,
              S: Into<String>,
    {
        let body = TransactionBody::RevokeAdminKeyV1 {
            id,
            reason,
            new_name: new_name.map(|x| x.into()),
        };
        self.prepare_transaction(now, body)
    }

    /// Add a new [policy][Policy] to the identity.
    pub fn add_policy<T: Into<Timestamp> + Clone>(&self, now: T, policy: Policy) -> Result<Transaction> {
        let body = TransactionBody::AddPolicyV1 {
            policy,
        };
        self.prepare_transaction(now, body)
    }

    /// Delete (by name) a [Policy] from the identity.
    pub fn delete_policy<T: Into<Timestamp> + Clone>(&self, now: T, id: PolicyID) -> Result<Transaction> {
        let body = TransactionBody::DeletePolicyV1 {
            id,
        };
        self.prepare_transaction(now, body)
    }

    /// Make a new [Claim][ClaimSpec].
    pub fn make_claim<T, S>(&self, now: T, spec: ClaimSpec, name: Option<S>) -> Result<Transaction>
        where T: Into<Timestamp> + Clone,
              S: Into<String>,
    {
        let body = TransactionBody::MakeClaimV1 {
            spec,
            name: name.map(|x| x.into()),
        };
        self.prepare_transaction(now, body)
    }

    /// Edit a claim.
    pub fn edit_claim<T, S>(&self, now: T, claim_id: ClaimID, name: Option<S>) -> Result<Transaction>
        where T: Into<Timestamp> + Clone,
              S: Into<String>,
    {
        let body = TransactionBody::EditClaimV1 {
            claim_id,
            name: name.map(|x| x.into()),
        };
        self.prepare_transaction(now, body)
    }

    /// Delete an existing claim.
    pub fn delete_claim<T: Into<Timestamp> + Clone>(&self, now: T, claim_id: ClaimID) -> Result<Transaction> {
        let body = TransactionBody::DeleteClaimV1 {
            claim_id,
        };
        self.prepare_transaction(now, body)
    }

    /// Make a transaction that stamps a claim. This transaction can be saved
    /// with the stemping identity (stamper) in order to advertise it as a public
    /// stamp.
    ///
    /// It can also not be added to the identity and sent directly to the stampee.
    pub fn make_stamp<T: Into<Timestamp> + Clone>(&self, now: T, stamp: StampEntry) -> Result<Transaction> {
        let body = TransactionBody::MakeStampV1 {
            stamp,
        };
        self.prepare_transaction(now, body)
    }

    /// Revoke a stamp we previously created and store this revocation with the
    /// identity.
    pub fn revoke_stamp<T: Into<Timestamp> + Clone>(&self, now: T, revocation: StampRevocationEntry) -> Result<Transaction> {
        let body = TransactionBody::RevokeStampV1 {
            revocation,
        };
        self.prepare_transaction(now, body)
    }

    /// Accept a stamp someone, or some*thing*, has made on a claim of ours.
    pub fn accept_stamp<T: Into<Timestamp> + Clone>(&self, now: T, stamp_transaction: Transaction) -> Result<Transaction> {
        if !matches!(stamp_transaction.entry().body(), TransactionBody::MakeStampV1 { .. }) {
            Err(Error::TransactionMismatch)?;
        }
        let body = TransactionBody::AcceptStampV1 {
            stamp_transaction: Box::new(stamp_transaction),
        };
        self.prepare_transaction(now, body)
    }

    /// Delete an existing stamp.
    pub fn delete_stamp<T: Into<Timestamp> + Clone>(&self, now: T, stamp_id: StampID) -> Result<Transaction> {
        let body = TransactionBody::DeleteStampV1 {
            stamp_id,
        };
        self.prepare_transaction(now, body)
    }

    /// Add a new subkey to our keychain.
    pub fn add_subkey<T, S>(&self, now: T, key: Key, name: S, desc: Option<S>) -> Result<Transaction>
        where T: Into<Timestamp> + Clone,
              S: Into<String>,
    {
        if matches!(key, Key::Admin(_)) {
            Err(Error::TransactionInvalid("Admin keys cannot be added as subkeys".into()))?;
        }
        let body = TransactionBody::AddSubkeyV1 {
            key,
            name: name.into(),
            desc: desc.map(|x| x.into()),
        };
        self.prepare_transaction(now, body)
    }

    /// Edit a subkey.
    pub fn edit_subkey<T, S>(&self, now: T, id: KeyID, new_name: Option<S>, new_desc: Option<Option<S>>) -> Result<Transaction>
        where T: Into<Timestamp> + Clone,
              S: Into<String>,
    {
        let body = TransactionBody::EditSubkeyV1 {
            id,
            new_name: new_name.map(|x| x.into()),
            new_desc: new_desc.map(|x| x.map(|y| y.into())),
        };
        self.prepare_transaction(now, body)
    }

    /// Revoke a subkey.
    pub fn revoke_subkey<T, S>(&self, now: T, id: KeyID, reason: RevocationReason, new_name: Option<S>) -> Result<Transaction>
        where T: Into<Timestamp> + Clone,
              S: Into<String>,
    {
        let body = TransactionBody::RevokeSubkeyV1 {
            id,
            reason,
            new_name: new_name.map(|x| x.into()),
        };
        self.prepare_transaction(now, body)
    }

    /// Delete a subkey.
    pub fn delete_subkey<T: Into<Timestamp> + Clone>(&self, now: T, id: KeyID) -> Result<Transaction> {
        let body = TransactionBody::DeleteSubkeyV1 {
            id,
        };
        self.prepare_transaction(now, body)
    }

    /// Publish this identity
    pub fn publish<T: Into<Timestamp> + Clone>(&self, now: T) -> Result<Transaction> {
        let body = TransactionBody::PublishV1 {
            transactions: Box::new(self.strip_private()),
        };
        // leave previous transactions blank (irrelevant here)
        Transaction::new(TransactionEntry::new(now, vec![], body))
    }

    /// Sign a message
    pub fn sign<T: Into<Timestamp> + Clone>(&self, now: T, body: BinaryVec) -> Result<Transaction> {
        let creator = self.identity_id().ok_or(Error::DagEmpty)?;
        let body = TransactionBody::SignV1 {
            creator,
            body: Some(body),
        };
        // leave previous transactions blank (irrelevant here)
        Transaction::new(TransactionEntry::new(now, vec![], body))
    }

    /// Create a transaction for use in an external system.
    pub fn ext<T: Into<Timestamp> + Clone>(&self, now: T, previous_transactions: Vec<TransactionID>, ty: Option<BinaryVec>, context: Option<Vec<KeyValEntry>>, payload: BinaryVec) -> Result<Transaction> {
        let creator = self.identity_id().ok_or(Error::DagEmpty)?;
        let body = TransactionBody::ExtV1 {
            creator,
            ty,
            context,
            payload,
        };
        Transaction::new(TransactionEntry::new(now, previous_transactions, body))
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
    type Item = Transaction;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let Transactions { transactions } = self;
        transactions.into_iter()
    }
}

impl SerdeBinary for Transactions {}
impl SerText for Transactions {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::base::{SignKeypair, CryptoKeypair},
        identity::{
            claim::{Relationship, RelationshipType},
            keychain::{AdminKeypair, ExtendKeypair},
            stamp::Confidence,
        },
        policy::{Capability, Context, MultisigPolicy, MultisigPolicySignature, Policy, TransactionBodyType},
        private::{PrivateWithMac, MaybePrivate},
        util::{Date, Url, ser::BinaryVec, test},
    };
    use std::str::FromStr;

    macro_rules! sign_and_push {
        ($master_key:expr, $admin_key:expr, $transactions:expr, $([ $fn:ident, $($args:expr),* ])*) => {{
            let mut trans_tmp = $transactions;
            $(
                let trans = trans_tmp.$fn($($args),*).unwrap();
                let trans_signed = trans.sign($master_key, $admin_key).unwrap();
                trans_tmp = trans_tmp.push_transaction(trans_signed).unwrap();
            )*
            trans_tmp
        }};
    }

    fn genesis_time(now: Timestamp) -> (SecretKey, Transactions, AdminKey) {
        test::create_fake_identity(now)
    }

    fn genesis() -> (SecretKey, Transactions, AdminKey) {
        genesis_time(Timestamp::now())
    }

    #[test]
    fn transactions_identity_id_is_genesis_transaction() {
        let (_master_key, transactions, _admin_key) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert_eq!(IdentityID::from(transactions.transactions()[0].id().clone()), identity.id().clone());
    }

    #[test]
    fn transactions_push() {
        let now = Timestamp::from_str("2021-04-20T00:00:10Z").unwrap();
        let (master_key_1, transactions_1, admin_key_1) = genesis_time(now.clone());
        let (_master_key_2, mut transactions_2, _admin_key_2) = genesis_time(now.clone());
        let trans_claim_signed = transactions_1
            .make_claim(now.clone(), ClaimSpec::Name(MaybePrivate::new_public("Hooty McOwl".to_string())), None::<String>).unwrap()
            .sign(&master_key_1, &admin_key_1).unwrap();
        transactions_1.push_transaction(trans_claim_signed.clone()).unwrap();
        transactions_2.build_identity().unwrap();
        match transactions_2.push_transaction_raw(trans_claim_signed.clone()) {
            Ok(_) => panic!("pushed a bad raw transaction: {}", trans_claim_signed.id().as_string()),
            Err(e) => assert_eq!(e, Error::DagOrphanedTransaction(trans_claim_signed.id().as_string())),
        }
    }

    #[test]
    fn transactions_merge_reset() {
        let (master_key, transactions, admin_key) = genesis_time(Timestamp::from_str("2021-04-20T00:00:00Z").unwrap());
        // make some claims on my smart refrigerator
        let admin_key_2 = AdminKey::new(AdminKeypair::from(SignKeypair::new_ed25519(&master_key).unwrap()), "Alpha", None);
        let admin_key_3 = AdminKey::new(AdminKeypair::from(SignKeypair::new_ed25519(&master_key).unwrap()), "Alpha", None);
        let branch1 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ make_claim, Timestamp::from_str("2021-04-20T00:00:10Z").unwrap(), ClaimSpec::Name(MaybePrivate::new_public("Hooty McOwl".to_string())), None::<String> ]
            [ add_admin_key, Timestamp::from_str("2021-04-20T00:01:00Z").unwrap(), admin_key_2.clone() ]
            [ revoke_admin_key, Timestamp::from_str("2021-04-20T00:01:01Z").unwrap(), admin_key_2.key_id(), RevocationReason::Superseded, Some("CYA") ]
            [ make_claim, Timestamp::from_str("2021-04-20T00:01:33Z").unwrap(), ClaimSpec::Address(MaybePrivate::new_public("1112 Dirk Delta Ln.".to_string())), Some(String::from("primary")) ]
        };
        // make some claims on my Facebook (TM) (R) (C) Brain (AND NOW A WORD FROM OUR SPONSORS) Implant
        let branch2 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ make_claim, Timestamp::from_str("2021-04-20T00:00:30Z").unwrap(), ClaimSpec::Url(MaybePrivate::new_public(Url::parse("https://www.cactus-petes.com/yeeeehawwww").unwrap())), None::<String> ]
            [ add_admin_key, Timestamp::from_str("2021-04-20T00:01:36Z").unwrap(), admin_key_3.clone() ]
            [ make_claim, Timestamp::from_str("2021-04-20T00:01:45Z").unwrap(), ClaimSpec::Address(MaybePrivate::new_public("1112 Liberal Hokes ave.".to_string())), Some(String::from("primary")) ]
            [ make_claim, Timestamp::from_str("2021-04-20T00:01:56Z").unwrap(), ClaimSpec::Email(MaybePrivate::new_public(String::from("dirk.delta@hollywood.com"))), None::<String> ]
        };
        let identity1 = branch1.build_identity().unwrap();
        let identity2 = branch2.build_identity().unwrap();
        assert_eq!(identity1.keychain().admin_keys().len(), 1);
        assert_eq!(identity1.keychain().subkeys()[0].key_id(), admin_key_2.key_id().into());
        assert_eq!(identity1.claims().len(), 2);
        match identity1.find_claim_by_name("primary").unwrap().spec() {
            ClaimSpec::Address(val) => assert_eq!(val.open_public().unwrap().as_str(), "1112 Dirk Delta Ln."),
            _ => panic!("wrong"),
        }

        assert_eq!(identity2.keychain().admin_keys()[1].key_id(), admin_key_3.key_id());
        assert_eq!(identity2.keychain().admin_keys().len(), 2);
        assert_eq!(identity2.claims().len(), 3);
        match identity2.find_claim_by_name("primary").unwrap().spec() {
            ClaimSpec::Address(val) => assert_eq!(val.open_public().unwrap().as_str(), "1112 Liberal Hokes ave."),
            _ => panic!("wrong"),
        }
        let transactions2 = Transactions::merge(branch1.clone(), branch2.clone()).unwrap();
        assert_eq!(branch1.transactions().len(), 5);
        assert_eq!(branch2.transactions().len(), 5);
        assert_eq!(transactions2.transactions().len(), 9);
        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [ make_claim, Timestamp::from_str("2021-04-20T00:05:22Z").unwrap(), ClaimSpec::Url(MaybePrivate::new_public(Url::parse("https://www.ITSJUSTAFLU.com/logic-and-facts").unwrap())), None::<String> ]
        };
        assert_eq!(transactions3.transactions().len(), 10);
        let identity3 = transactions3.build_identity().unwrap();
        match identity3.find_claim_by_name("primary").unwrap().spec() {
            ClaimSpec::Address(val) => assert_eq!(val.open_public().unwrap().as_str(), "1112 Liberal Hokes ave."),
            _ => panic!("wrong"),
        }
        assert_eq!(identity3.claims().len(), 6);
        assert_eq!(identity3.keychain().admin_keys().len(), 2);
        assert_eq!(identity3.keychain().admin_keys()[1].key_id(), admin_key_3.key_id());
        assert_eq!(identity3.keychain().subkeys().len(), 1);
        assert_eq!(identity3.keychain().subkeys()[0].key_id(), admin_key_2.key_id().into());
    }

    #[test]
    fn transactions_genesis() {
        let (master_key, transactions, admin_key) = genesis();
        let identity = transactions.build_identity().unwrap();
        let policies = identity.policies().iter().map(|x| x.policy().clone()).collect::<Vec<_>>();
        let res = transactions.clone().push_transaction(
            transactions
                .create_identity(Timestamp::now(), identity.keychain().admin_keys().clone(), policies).unwrap()
                .sign(&master_key, &admin_key).unwrap()
        );
        assert_eq!(res.err(), Some(Error::DagCreateIdentityOnExistingChain));

        let transactions2 = Transactions::new();
        let res = transactions2.clone().push_transaction(
            transactions2
                .make_claim(Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public("Stinky Wizzleteets".into())), None::<String>).unwrap()
                .sign(&master_key, &admin_key).unwrap()
        );
        assert_eq!(res.err(), Some(Error::DagMissingIdentity));
    }

    #[test]
    fn transactions_create_identity() {
        let (master_key, transactions, admin_key) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert_eq!(identity.id(), &IdentityID::from(transactions.transactions()[0].id().clone()));
        assert_eq!(identity.keychain().admin_keys().len(), 1);
        assert_eq!(identity.policies().len(), 1);

        let res = transactions.clone().push_transaction(
            transactions
                .create_identity(Timestamp::now(), vec![], vec![]).unwrap()
                .sign(&master_key, &admin_key).unwrap()
        );
        assert_eq!(res.err(), Some(Error::DagCreateIdentityOnExistingChain));
    }

    #[test]
    fn transactions_reset_identity() {
        let (master_key, transactions, admin_key) = genesis();
        let admin_key2 = AdminKey::new(AdminKeypair::new_ed25519(&master_key).unwrap(), "Alpha", None);
        let admin_key3 = AdminKey::new(AdminKeypair::new_ed25519(&master_key).unwrap(), "Zing", None);
        let capability2 = Capability::Transaction { body_type: TransactionBodyType::ResetIdentityV1, context: Context::Permissive };
        let capability3 = Capability::Transaction { body_type: TransactionBodyType::AcceptStampV1, context: Context::IdentityID(IdentityID::random()) };
        let policy1 = match transactions.transactions()[0].entry().body() {
            TransactionBody::CreateIdentityV1 { policies, .. } => policies[0].clone(),
            _ => panic!("WRONG"),
        };
        let policy2 = Policy::new(
            vec![capability2],
            MultisigPolicy::MOfN { must_have: 0, participants: vec![] }
        );
        let policy3 = Policy::new(
            vec![capability3],
            MultisigPolicy::MOfN { must_have: 1, participants: vec![] }
        );
        let identity1 = transactions.build_identity().unwrap();
        assert_eq!(identity1.keychain().admin_keys().len(), 1);
        assert!(identity1.keychain().admin_key_by_name("Alpha").is_some());
        assert_eq!(identity1.policies().len(), 1);
        assert_eq!(identity1.policies()[0].id(), &policy1.gen_id().unwrap());
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ reset_identity, Timestamp::now(), Some(vec![admin_key2.clone(), admin_key3.clone()]), Some(vec![policy2.clone(), policy3.clone()]) ]
        };
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.keychain().admin_keys().len(), 2);
        assert_eq!(identity2.keychain().admin_key_by_name("Alpha").unwrap().key(), admin_key2.key());
        assert!(identity2.keychain().admin_key_by_name("Zing").is_some());
        assert_eq!(identity2.policies().len(), 2);
        assert_eq!(identity2.policies()[0].id(), &policy2.gen_id().unwrap());
        assert_eq!(identity2.policies()[1].id(), &policy3.gen_id().unwrap());
    }

    #[test]
    fn transactions_add_admin_key() {
        let (master_key, transactions, admin_key) = genesis();
        let identity1 = transactions.build_identity().unwrap();
        assert_eq!(identity1.keychain().admin_keys().len(), 1);
        assert_eq!(identity1.keychain().admin_key_by_keyid(&admin_key.key_id()).map(|x| x.key()), Some(admin_key.key()));

        let admin_key2 = AdminKey::new(AdminKeypair::new_ed25519(&master_key).unwrap(), "publish key lol", None);
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ add_admin_key, Timestamp::now(), admin_key2.clone() ]
        };
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.keychain().admin_keys().len(), 2);
        assert_eq!(identity2.keychain().admin_key_by_name("Alpha").map(|x| x.key()), Some(admin_key.key()));
        assert_eq!(identity2.keychain().admin_key_by_name("publish key lol").map(|x| x.key()), Some(admin_key2.key()));

        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [ add_admin_key, Timestamp::now(), admin_key2.clone() ]
        };
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.keychain().admin_keys().len(), 2);
        assert_eq!(identity3.keychain().admin_key_by_name("Alpha").map(|x| x.key()), Some(admin_key.key()));
        assert_eq!(identity3.keychain().admin_key_by_name("publish key lol").map(|x| x.key()), Some(admin_key2.key()));
    }

    #[test]
    fn transactions_edit_admin_key() {
        let (master_key, transactions, admin_key) = genesis();
        let identity1 = transactions.build_identity().unwrap();
        assert_eq!(identity1.keychain().admin_keys().len(), 1);
        assert_eq!(identity1.keychain().subkeys().len(), 0);
        assert_eq!(identity1.keychain().admin_key_by_keyid(&admin_key.key_id()).map(|x| x.key()), Some(admin_key.key()));

        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ revoke_admin_key, Timestamp::now(), admin_key.key_id(), RevocationReason::Compromised, Some("rotten") ]
        };
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.keychain().admin_keys().len(), 0);
        assert!(identity2.keychain().admin_key_by_keyid(&admin_key.key_id()).is_none());
        assert_eq!(identity2.keychain().subkeys().len(), 1);
        assert!(identity2.keychain().subkey_by_name("Alpha").is_none());
        assert!(matches!(identity2.keychain().subkey_by_name("rotten").unwrap().key(), Key::Admin(_)));

        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [ revoke_admin_key, Timestamp::now(), admin_key.key_id(), RevocationReason::Compromised, Some("rotten") ]
        };
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.keychain().admin_keys().len(), 0);
        assert!(identity3.keychain().admin_key_by_keyid(&admin_key.key_id()).is_none());
        assert_eq!(identity3.keychain().subkeys().len(), 1);
        assert!(identity3.keychain().subkey_by_name("Alpha").is_none());
        assert!(matches!(identity3.keychain().subkey_by_name("rotten").unwrap().key(), Key::Admin(_)));
    }

    #[test]
    fn transactions_revoke_admin_key() {
        let (master_key, transactions, admin_key) = genesis();
        let identity1 = transactions.build_identity().unwrap();
        assert_eq!(identity1.keychain().admin_keys().len(), 1);
        assert_eq!(identity1.keychain().subkeys().len(), 0);
        assert_eq!(identity1.keychain().admin_key_by_keyid(&admin_key.key_id()).map(|x| x.key()), Some(admin_key.key()));

        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ revoke_admin_key, Timestamp::now(), admin_key.key_id(), RevocationReason::Compromised, Some("rotten") ]
        };
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.keychain().admin_keys().len(), 0);
        assert!(identity2.keychain().admin_key_by_name("Alpha").is_none());
        assert_eq!(identity2.keychain().subkeys().len(), 1);
        assert!(identity2.keychain().subkey_by_name("Alpha").is_none());
        assert!(matches!(identity2.keychain().subkey_by_name("rotten").unwrap().key(), Key::Admin(_)));

        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [ revoke_admin_key, Timestamp::now(), admin_key.key_id(), RevocationReason::Compromised, Some("rotten") ]
        };
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.keychain().admin_keys().len(), 0);
        assert!(identity3.keychain().admin_key_by_name("Alpha").is_none());
        assert_eq!(identity3.keychain().subkeys().len(), 1);
        assert!(identity3.keychain().subkey_by_name("Alpha").is_none());
        assert!(matches!(identity3.keychain().subkey_by_name("rotten").unwrap().key(), Key::Admin(_)));
    }

    #[test]
    fn transactions_add_policy() {
        let (master_key, transactions, admin_key) = genesis();
        let capability2 = Capability::Transaction { body_type: TransactionBodyType::ResetIdentityV1, context: Context::Permissive };
        let policy1 = match transactions.transactions()[0].entry().body() {
            TransactionBody::CreateIdentityV1 { policies, .. } => policies[0].clone(),
            _ => panic!("WRONG"),
        };
        let policy2 = Policy::new(
            vec![capability2],
            MultisigPolicy::MOfN { must_have: 0, participants: vec![] }
        );

        let identity1 = transactions.build_identity().unwrap();
        assert_eq!(identity1.policies().len(), 1);
        assert_eq!(identity1.policies()[0].id(), &policy1.gen_id().unwrap());

        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ add_policy, Timestamp::now(), policy2.clone() ]
        };
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.policies().len(), 2);
        assert_eq!(identity2.policies()[0].id(), &policy1.gen_id().unwrap());
        assert_eq!(identity2.policies()[1].id(), &policy2.gen_id().unwrap());

        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [ add_policy, Timestamp::now(), policy2.clone() ]
        };
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.policies().len(), 2);
        assert_eq!(identity3.policies()[0].id(), &policy1.gen_id().unwrap());
        assert_eq!(identity3.policies()[1].id(), &policy2.gen_id().unwrap());
    }

    #[test]
    fn transactions_delete_policy() {
        let (master_key, transactions, admin_key) = genesis();
        let identity = transactions.build_identity().unwrap();
        let policy_id = identity.policies()[0].id().clone();
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ delete_policy, Timestamp::now(), policy_id.clone() ]
        };
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.policies().len(), 0);

        let res = transactions2.clone().push_transaction(
            transactions2
                .delete_policy(Timestamp::now(), policy_id.clone()).unwrap()
                .sign(&master_key, &admin_key).unwrap()
        );
        assert_eq!(res.err(), Some(Error::PolicyNotFound));
    }

    #[test]
    fn transactions_make_claim() {
        let (master_key, transactions, admin_key) = genesis();

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

                let transactions2 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
                    [ make_claim, Timestamp::now(), spec_private, None::<String> ]
                };
                let identity2 = transactions2.build_identity().unwrap();
                let maybe = $get_maybe(identity2.claims()[0].spec().clone());
                assert_eq!(maybe.open(&master_key).unwrap(), val);
                assert_eq!(identity2.claims().len(), 1);
                assert_eq!(transactions2.transactions().len(), 2);

                let transactions2 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
                    [ make_claim, Timestamp::now(), spec_public, None::<String> ]
                };
                let identity2 = transactions2.build_identity().unwrap();
                let maybe = $get_maybe(identity2.claims()[0].spec().clone());
                assert_eq!(maybe.open(&master_key).unwrap(), val);
                assert_eq!(identity2.claims().len(), 1);
                assert_eq!(transactions2.transactions().len(), 2);
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

        assert_claim!{ Identity, identity.id().clone() }
        assert_claim!{ Name, String::from("Marty Malt") }
        assert_claim!{ Birthday, Date::from_str("2010-01-03").unwrap() }
        assert_claim!{ Email, String::from("marty@sids.com") }
        assert_claim!{ Photo, BinaryVec::from(vec![1, 2, 3]) }
        assert_claim!{ Pgp, String::from("12345") }
        assert_claim!{ Domain, String::from("slappy.com") }
        assert_claim!{ Url, Url::parse("https://killtheradio.net/").unwrap() }
        assert_claim!{ Address, String::from("111 blumps ln") }
        assert_claim!{ Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        assert_claim!{ RelationExtension, Relationship::new(RelationshipType::OrganizationMember, BinaryVec::from(vec![1, 2, 3, 4, 5])) }
        assert_claim!{
            raw,
            |maybe, _| ClaimSpec::Extension { key: Vec::from("id:state:ca".as_bytes()).into(), value: maybe },
            BinaryVec::from(vec![7, 3, 2, 90]),
            |spec: ClaimSpec| if let ClaimSpec::Extension { value: maybe, .. } = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
        }
    }

    #[test]
    fn transactions_edit_claim() {
        let (master_key, transactions, admin_key) = genesis();
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ make_claim, Timestamp::now(), ClaimSpec::Url(MaybePrivate::new_public(Url::parse("https://www.cactus-petes.com/yeeeehawwww").unwrap())), Some("OpenID") ]
        };
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.claims().len(), 1);
        assert_eq!(identity2.claims()[0].name(), &Some("OpenID".into()));

        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [ edit_claim, Timestamp::now(), identity2.claims()[0].id().clone(), None::<String> ]
        };
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.claims().len(), 1);
        assert_eq!(identity3.claims()[0].name(), &None);
    }

    #[test]
    fn transactions_delete_claim() {
        let (master_key, transactions, admin_key) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert_eq!(identity.claims().len(), 0);
        assert_eq!(transactions.transactions().len(), 1);

        let identity_id = IdentityID::from(transactions.transactions()[0].id().clone());
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ make_claim, Timestamp::now(), ClaimSpec::Identity(MaybePrivate::new_public(identity_id)), None::<String> ]
        };
        assert_eq!(transactions2.transactions().len(), 2);

        let identity = transactions2.build_identity().unwrap();
        let claim_id = identity.claims()[0].id().clone();
        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [delete_claim, Timestamp::now(), claim_id.clone()]
        };
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.claims().len(), 0);

        let transactions4 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [ delete_claim, Timestamp::now(), ClaimID::random() ]
        };
        let identity4 = transactions4.build_identity().unwrap();
        assert_eq!(identity4.claims().len(), 1);

        let transactions5 = sign_and_push! { &master_key, &admin_key, transactions3.clone(),
            [ delete_claim, Timestamp::now(), claim_id.clone() ]
        };
        let identity5 = transactions5.build_identity().unwrap();
        assert_eq!(identity5.claims().len(), 0);
    }

    #[test]
    fn transactions_make_stamp() {
        let (master_key, transactions, admin_key) = genesis();
        let identity_id = IdentityID::from(transactions.transactions()[0].id().clone());
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ make_claim, Timestamp::now(), ClaimSpec::Identity(MaybePrivate::new_public(identity_id)), None::<String> ]
        };
        let identity = transactions2.build_identity().unwrap();
        let claim = identity.claims()[0].clone();

        let (master_key_stamper, transactions_stamper, admin_key_stamper) = genesis();

        let identity_stamper1 = transactions_stamper.build_identity().unwrap();
        assert_eq!(identity_stamper1.stamps().stamps().len(), 0);

        let entry = StampEntry::new(
            IdentityID::from(transactions_stamper.transactions()[0].id().clone()),
            identity.id().clone(),
            claim.id().clone(),
            Confidence::Low, 
            Some(Timestamp::from_str("2060-01-01T06:59:00Z").unwrap())
        );

        let make_stamp_trans = transactions_stamper
            .make_stamp(Timestamp::now(), entry).unwrap()
            .sign(&master_key_stamper, &admin_key_stamper).unwrap();
        let transactions_stamper2 = transactions_stamper
            .push_transaction(make_stamp_trans.clone())
            .unwrap();
        let identity_stamper2 = transactions_stamper2.build_identity().unwrap();
        assert_eq!(identity_stamper2.stamps().stamps().len(), 1);
    }

    #[test]
    fn transactions_revoke_stamp() {
        let (master_key, transactions, admin_key) = genesis();
        let identity_id = IdentityID::from(transactions.transactions()[0].id().clone());
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ make_claim, Timestamp::now(), ClaimSpec::Identity(MaybePrivate::new_public(identity_id)), None::<String> ]
        };

        let (master_key_stamper, transactions_stamper, admin_key_stamper) = genesis();
        let identity_stamper1 = transactions_stamper.build_identity().unwrap();
        assert_eq!(identity_stamper1.stamps().stamps().len(), 0);

        let identity_stampee2 = transactions2.build_identity().unwrap();
        let claim = identity_stampee2.claims()[0].clone();
        let entry = StampEntry::new(
            IdentityID::from(transactions_stamper.transactions()[0].id().clone()),
            identity_stampee2.id().clone(),
            claim.id().clone(),
            Confidence::Low, 
            Some(Timestamp::from_str("2060-01-01T06:59:00Z").unwrap())
        );

        let make_stamp_trans = transactions_stamper
            .make_stamp(Timestamp::now(), entry).unwrap()
            .sign(&master_key_stamper, &admin_key_stamper).unwrap();
        let transactions_stamper2 = transactions_stamper
            .push_transaction(make_stamp_trans.clone())
            .unwrap();
        let identity_stamper2 = transactions_stamper2.build_identity().unwrap();
        assert_eq!(identity_stamper2.stamps().stamps().len(), 1);

        let revocation = StampRevocationEntry::new(
            identity_stamper2.id().clone(),
            identity_stampee2.id().clone(),
            identity_stamper2.stamps().stamps()[0].id().clone()
        );
        let revoke_trans = transactions_stamper2
                .revoke_stamp(Timestamp::now(), revocation.clone()).unwrap()
                .sign(&master_key_stamper, &admin_key_stamper).unwrap();
        let transactions_stamper3 = transactions_stamper2.clone()
            .push_transaction(revoke_trans.clone()).unwrap();

        // same revocation, different id, should work fine
        sign_and_push! { &master_key_stamper, &admin_key_stamper, transactions_stamper3.clone(),
            [ revoke_stamp, Timestamp::now(), revocation.clone() ]
        };
    }

    #[test]
    fn transactions_accept_stamp() {
        let (master_key, transactions, admin_key) = genesis();
        let identity_id = IdentityID::from(transactions.transactions()[0].id().clone());
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ make_claim, Timestamp::now(), ClaimSpec::Identity(MaybePrivate::new_public(identity_id)), None::<String> ]
        };
        let identity = transactions2.build_identity().unwrap();
        assert_eq!(identity.claims()[0].stamps().len(), 0);
        let claim = identity.claims()[0].clone();

        let (master_key_stamper, transactions_stamper, admin_key_stamper) = genesis();
        let entry = StampEntry::new(
            IdentityID::from(transactions_stamper.transactions()[0].id().clone()),
            identity.id().clone(),
            claim.id().clone(),
            Confidence::Low, 
            Some(Timestamp::from_str("2060-01-01T06:59:00Z").unwrap())
        );
        let stamp_transaction_unsigned = transactions_stamper
            .make_stamp(Timestamp::now(), entry).unwrap();
        let stamp_transaction = stamp_transaction_unsigned.clone()
            .sign(&master_key_stamper, &admin_key_stamper).unwrap();
        let not_stamp_transaction = transactions_stamper
            .make_claim(Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public("Butch".into())), None::<String>).unwrap()
            .sign(&master_key_stamper, &admin_key_stamper).unwrap();

        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2,
            [ accept_stamp, Timestamp::now(), stamp_transaction.clone() ]
        };
        assert_eq!(transactions3.transactions().len(), 3);
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.claims()[0].stamps().len(), 1);

        let res = transactions3.clone().push_transaction(
            transactions3
                .accept_stamp(Timestamp::now(), stamp_transaction_unsigned.clone()).unwrap()
                .sign(&master_key, &admin_key).unwrap()
        );
        assert_eq!(res.err(), Some(Error::TransactionNoSignatures));

        let res = transactions3
            .accept_stamp(Timestamp::now(), not_stamp_transaction.clone());
        assert_eq!(res.err(), Some(Error::TransactionMismatch));

        let res = transactions3.clone().push_transaction(
            transactions3
                .accept_stamp(Timestamp::now(), stamp_transaction.clone()).unwrap()
                .sign(&master_key, &admin_key).unwrap()
        );
        assert_eq!(res.err(), None);

        let transactions4 = sign_and_push! { &master_key, &admin_key, transactions3.clone(),
            [ delete_claim, Timestamp::now(), claim.id().clone() ]
        };
        let res = transactions4.clone().push_transaction(
            transactions4
                .accept_stamp(Timestamp::now(), stamp_transaction.clone()).unwrap()
                .sign(&master_key, &admin_key).unwrap()
        );
        assert_eq!(res.err(), Some(Error::IdentityClaimNotFound));
    }

    #[test]
    fn transactions_delete_stamp() {
        let (master_key, transactions, admin_key) = genesis();
        let identity_id = IdentityID::from(transactions.transactions()[0].id().clone());
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ make_claim, Timestamp::now(), ClaimSpec::Identity(MaybePrivate::new_public(identity_id)), None::<String> ]
        };
        let identity = transactions2.build_identity().unwrap();
        assert_eq!(identity.claims()[0].stamps().len(), 0);
        let claim = identity.claims()[0].clone();

        let (master_key_stamper, transactions_stamper, admin_key_stamper) = genesis();
        let entry = StampEntry::new(
            IdentityID::from(transactions_stamper.transactions()[0].id().clone()),
            identity.id().clone(),
            claim.id().clone(),
            Confidence::Low, 
            Some(Timestamp::from_str("2060-01-01T06:59:00Z").unwrap())
        );
        let stamp_transaction = transactions_stamper
            .make_stamp(Timestamp::now(), entry).unwrap()
            .sign(&master_key_stamper, &admin_key_stamper).unwrap();

        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2,
            [ accept_stamp, Timestamp::now(), stamp_transaction.clone() ]
        };
        assert_eq!(transactions3.transactions().len(), 3);
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.claims()[0].stamps().len(), 1);

        let transactions4 = sign_and_push! { &master_key, &admin_key, transactions3.clone(),
            [ delete_stamp, Timestamp::now(), StampID::from(stamp_transaction.id().clone()) ]
        };
        let identity4 = transactions4.build_identity().unwrap();
        assert_eq!(identity4.claims()[0].stamps().len(), 0);

        let res = transactions4.clone().push_transaction(
            transactions4
                .delete_stamp(Timestamp::now(), StampID::from(stamp_transaction.id().clone())).unwrap()
                .sign(&master_key, &admin_key).unwrap()
        );
        assert_eq!(res.err(), Some(Error::IdentityStampNotFound));
    }

    #[test]
    fn transactions_add_subkey() {
        let (master_key, transactions, admin_key) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert_eq!(identity.keychain().subkeys().len(), 0);

        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = PrivateWithMac::seal(&master_key, SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair.clone()), "default:sign", Some("The key I use to sign things") ]
            [ add_subkey, Timestamp::now(), Key::new_crypto(crypto_keypair.clone()), "default:crypto", Some("Use this to send me emails") ]
            [ add_subkey, Timestamp::now(), Key::new_secret(secret_key.clone()), "default:secret", Some("Encrypt/decrypt things locally with this key") ]
        };
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.keychain().subkeys()[0].name(), "default:sign");
        assert_eq!(identity2.keychain().subkeys()[1].name(), "default:crypto");
        assert_eq!(identity2.keychain().subkeys()[2].name(), "default:secret");
        assert_eq!(identity2.keychain().subkeys().len(), 3);

        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair.clone()), "get a job", None ]
        };
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.keychain().subkeys()[0].name(), "default:sign");
        assert_eq!(identity3.keychain().subkeys()[1].name(), "default:crypto");
        assert_eq!(identity3.keychain().subkeys()[2].name(), "default:secret");
        assert_eq!(identity3.keychain().subkeys().len(), 3);
        assert!(identity3.keychain().subkey_by_name("get a job").is_none());
    }

    #[test]
    fn transactions_edit_subkey() {
        let (master_key, transactions, admin_key) = genesis();

        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = PrivateWithMac::seal(&master_key, SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things") ]
            [ add_subkey, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails") ]
            [ add_subkey, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key") ]
        };

        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(identity2.keychain().subkeys().len(), 3);

        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [ edit_subkey, Timestamp::now(), identity2.keychain().subkey_by_name("default:crypto").unwrap().key_id(), Some("default:MYLITTLEPONY"), Some(Some("Tonga")) ]
            [ edit_subkey, Timestamp::now(), identity2.keychain().subkey_by_name("default:secret").unwrap().key_id(), Some("default:secret"), None ]
        };
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.keychain().subkeys().len(), 3);
        assert!(identity3.keychain().subkey_by_name("default:sign").is_some());
        assert!(identity3.keychain().subkey_by_name("default:MYLITTLEPONY").is_some());
        assert!(identity3.keychain().subkey_by_name("default:crypto").is_none());
        assert_eq!(identity3.keychain().subkey_by_name("default:MYLITTLEPONY").unwrap().description(), &Some("Tonga".into()));
        assert_eq!(identity3.keychain().subkey_by_name("default:secret").unwrap().description(), &Some("Encrypt/decrypt things locally with this key".into()));

        let randkey = KeyID::random_secret();
        let res = transactions3.clone().push_transaction(
            transactions3
                .edit_subkey(Timestamp::now(), randkey.clone(), Some("you want a push i'll show you a push"), None).unwrap()
                .sign(&master_key, &admin_key).unwrap()
        );
        assert_eq!(res.err(), Some(Error::KeychainKeyNotFound(randkey.clone())));
    }

    #[test]
    fn transactions_revoke_subkey() {
        let (master_key, transactions, admin_key) = genesis();

        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = PrivateWithMac::seal(&master_key, SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things") ]
            [ add_subkey, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails") ]
            [ add_subkey, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key") ]
        };
        let identity2 = transactions2.build_identity().unwrap();
        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [ revoke_subkey, Timestamp::now(), identity2.keychain().subkey_by_name("default:crypto").unwrap().key_id(), RevocationReason::Superseded, Some("revoked:default:crypto") ]
        };
        let identity3 = transactions3.build_identity().unwrap();
        assert!(identity3.keychain().subkeys()[0].revocation().is_none());
        assert_eq!(identity3.keychain().subkeys()[1].revocation().as_ref(), Some(&RevocationReason::Superseded));
        assert_eq!(identity3.keychain().subkeys()[1].name(), "revoked:default:crypto");
        assert!(identity3.keychain().subkeys()[2].revocation().is_none());

        let transactions4 = sign_and_push! { &master_key, &admin_key, transactions3.clone(),
            [ revoke_subkey, Timestamp::now(), identity2.keychain().subkey_by_name("default:crypto").unwrap().key_id(), RevocationReason::Unspecified, Some("zingg") ]
        };
        let identity4 = transactions4.build_identity().unwrap();
        assert!(identity4.keychain().subkeys()[0].revocation().is_none());
        assert_eq!(identity4.keychain().subkeys()[1].revocation().as_ref(), Some(&RevocationReason::Superseded));
        assert_eq!(identity4.keychain().subkeys()[1].name(), "revoked:default:crypto");
        assert!(identity4.keychain().subkeys()[2].revocation().is_none());
    }

    #[test]
    fn transactions_delete_subkey() {
        let (master_key, transactions, admin_key) = genesis();

        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = PrivateWithMac::seal(&master_key, SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things") ]
            [ add_subkey, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails") ]
            [ add_subkey, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key") ]
        };
        let identity2 = transactions2.build_identity().unwrap();
        let sign_id = identity2.keychain().subkey_by_name("default:sign").unwrap().key_id();

        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions2.clone(),
            [ delete_subkey, Timestamp::now(), sign_id.clone() ]
        };
        let identity3 = transactions3.build_identity().unwrap();
        assert_eq!(identity3.keychain().subkeys()[0].name(), "default:crypto");
        assert_eq!(identity3.keychain().subkeys()[1].name(), "default:secret");
        assert_eq!(identity3.keychain().subkeys().len(), 2);

        let transactions4 = sign_and_push! { &master_key, &admin_key, transactions3.clone(),
            [ delete_subkey, Timestamp::now(), sign_id.clone() ]
        };
        let identity4 = transactions4.build_identity().unwrap();
        assert_eq!(identity4.keychain().subkeys()[0].name(), "default:crypto");
        assert_eq!(identity4.keychain().subkeys()[1].name(), "default:secret");
        assert_eq!(identity4.keychain().subkeys().len(), 2);
    }

    #[test]
    fn transactions_publish() {
        let (master_key, transactions, admin_key) = genesis();
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ make_claim, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public("Miner 49er".into())), None::<String> ]
            [ make_claim, Timestamp::now(), ClaimSpec::Email(MaybePrivate::new_public("miner@49ers.net".into())), Some(String::from("primary")) ]
        };
        let published = transactions2.publish(Timestamp::now()).unwrap()
            .sign(&master_key, &admin_key).unwrap();
        match published.entry().body() {
            TransactionBody::PublishV1 { transactions: published_trans } => {
                assert!(!published_trans.has_private());
                assert_eq!(published_trans.transactions().len(), 3);
                assert_eq!(published_trans.transactions()[0].id(), transactions2.transactions()[0].id());
                assert_eq!(published_trans.transactions()[1].id(), transactions2.transactions()[1].id());
                assert_eq!(published_trans.transactions()[2].id(), transactions2.transactions()[2].id());
            }
            _ => panic!("Unexpected transaction: {:?}", published),
        }

        let identity = transactions2.build_identity().unwrap();
        published.verify(Some(&identity)).unwrap();

        let mut published2 = published.clone();
        match published2.entry_mut().body_mut() {
            TransactionBody::PublishV1 { transactions: ref mut published_trans2 } => {
                published_trans2.transactions_mut().retain(|x| x.id() != transactions2.transactions()[1].id());
                assert_eq!(published_trans2.transactions().len(), 2);
            }
            _ => panic!("Unexpected transaction: {:?}", published2),
        }

        assert!(matches!(published2.verify(Some(&identity)).unwrap_err(), Error::TransactionIDMismatch(..)));
    }

    #[test]
    fn transactions_sign() {
        let (master_key, transactions, admin_key) = genesis();
        let sig = transactions.sign(Timestamp::now(), BinaryVec::from(Vec::from("get a job".as_bytes()))).unwrap()
            .sign(&master_key, &admin_key).unwrap();
        let identity = transactions.build_identity().unwrap();
        sig.verify(Some(&identity)).unwrap();

        let transactions_blank = Transactions::new();
        let blank_res = transactions_blank.sign(Timestamp::now(), BinaryVec::from(Vec::from("get a job".as_bytes())));
        assert!(matches!(blank_res, Err(Error::DagEmpty)));

        let mut sig_mod = sig.clone();
        match sig_mod.entry_mut().body_mut() {
            TransactionBody::SignV1 { creator: _creator, body: Some(ref mut body) } => {
                *body = BinaryVec::from(Vec::from("hold on...".as_bytes()));
            }
            _ => panic!("Unexpected transaction: {:?}", sig_mod),
        }
        assert!(matches!(sig_mod.verify(Some(&identity)).unwrap_err(), Error::TransactionIDMismatch(..)));
    }

    #[test]
    fn transactions_ext() {
        let (master_key, transactions, admin_key) = genesis();
        let ext = transactions.ext(Timestamp::now(), vec![], None, None, BinaryVec::from(Vec::from("SEND $5 TO SALLY".as_bytes()))).unwrap()
            .sign(&master_key, &admin_key).unwrap();
        let identity = transactions.build_identity().unwrap();
        ext.verify(Some(&identity)).unwrap();

        let transactions_blank = Transactions::new();
        let blank_res = transactions_blank.sign(Timestamp::now(), BinaryVec::from(Vec::from("get a job".as_bytes())));
        assert!(matches!(blank_res, Err(Error::DagEmpty)));

        let mut ext_mod = ext.clone();
        match ext_mod.entry_mut().body_mut() {
            TransactionBody::ExtV1 { creator: _creator, ty: _ty, context: _context, payload: ref mut body } => {
                *body = BinaryVec::from(Vec::from("THE ZING OF THE DAY".as_bytes()));
            }
            _ => panic!("Unexpected transaction: {:?}", ext_mod),
        }
        assert!(matches!(ext_mod.verify(Some(&identity)).unwrap_err(), Error::TransactionIDMismatch(..)));
    }

    #[test]
    fn transactions_push_invalid_sig() {
        let (master_key, transactions, admin_key) = genesis();
        let mut claim_trans = transactions.make_claim(Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public("Mr. Larry Johnson".into())), None::<String>).unwrap();
        let sig = admin_key.key().sign(&master_key, b"haha lol").unwrap();
        let policy_sig = MultisigPolicySignature::Key { key: admin_key.key().clone().into(), signature: sig };
        claim_trans.signatures_mut().push(policy_sig);
        let res = transactions.clone().push_transaction(claim_trans);
        assert!(matches!(res.err(), Some(Error::TransactionSignatureInvalid(_))));
    }

    #[test]
    fn transactions_policy_multisig_verify() {
        let (master_key, transactions, admin_key) = genesis();
        let admin_key1 = AdminKey::new(AdminKeypair::new_ed25519(&master_key).unwrap(), "Frank", None);
        let admin_key2 = AdminKey::new(AdminKeypair::new_ed25519(&master_key).unwrap(), "Gina", None);
        let admin_key3 = AdminKey::new(AdminKeypair::new_ed25519(&master_key).unwrap(), "Ralph", None);
        let admin_key4 = AdminKey::new(AdminKeypair::new_ed25519(&master_key).unwrap(), "Simon", None);

        let cap1 = vec![
            Capability::Transaction {
                body_type: TransactionBodyType::MakeClaimV1,
                context: Context::Permissive,
            },
            Capability::Transaction {
                body_type: TransactionBodyType::AddSubkeyV1,
                context: Context::Name("logins/websites/beeets.com".into()),
            },
        ];
        let multisig1 = MultisigPolicy::MOfN {
            must_have: 2,
            participants: vec![
                admin_key1.key().clone().into(),
                admin_key2.key().clone().into(),
                admin_key3.key().clone().into(),
            ],
        };
        let policy1 = Policy::new(cap1, multisig1);

        let cap2 = vec![
            Capability::Transaction {
                body_type: TransactionBodyType::PublishV1,
                context: Context::Permissive,
            },
        ];
        let multisig2 = MultisigPolicy::All(vec![
            MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![
                    admin_key4.key().clone().into(),
                ],
            },
            MultisigPolicy::MOfN {
                must_have: 2,
                participants: vec![
                    admin_key1.key().clone().into(),
                    admin_key2.key().clone().into(),
                    admin_key3.key().clone().into(),
                ],
            },
        ]);
        let policy2 = Policy::new(cap2, multisig2);

        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ add_policy, Timestamp::now(), policy1 ]
            [ add_policy, Timestamp::now(), policy2 ]
        };

        let trans1 = transactions2.make_claim(Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public("Larry".into())), None::<String>).unwrap();
        assert_eq!(
            transactions2.clone().push_transaction(trans1.clone()).err(),
            Some(Error::TransactionNoSignatures)
        );
        assert_eq!(
            transactions2.clone().push_transaction(
                trans1.clone()
                    .sign(&master_key, &admin_key1).unwrap()
            ).err(),
            Some(Error::PolicyNotFound)
        );
        transactions2.clone().push_transaction(
            trans1.clone()
                .sign(&master_key, &admin_key1).unwrap()
                .sign(&master_key, &admin_key2).unwrap()
        ).unwrap();
        transactions2.clone().push_transaction(
            trans1.clone()
                .sign(&master_key, &admin_key2).unwrap()
                .sign(&master_key, &admin_key3).unwrap()
        ).unwrap();
        transactions2.clone().push_transaction(
            trans1.clone()
                .sign(&master_key, &admin_key2).unwrap()
                .sign(&master_key, &admin_key1).unwrap()
        ).unwrap();
        transactions2.clone().push_transaction(
            trans1.clone()
                .sign(&master_key, &admin_key1).unwrap()
                .sign(&master_key, &admin_key2).unwrap()
                .sign(&master_key, &admin_key3).unwrap()
        ).unwrap();

        let subkey = Key::new_sign(SignKeypair::new_ed25519(&master_key).unwrap());
        let trans2 = transactions2.add_subkey(Timestamp::now(), subkey.clone(), "logins/websites/booots.com", None).unwrap();
        assert_eq!(
            transactions2.clone().push_transaction(
                trans2.clone()
                    .sign(&master_key, &admin_key1).unwrap()
            ).err(),
            Some(Error::PolicyNotFound)
        );
        assert_eq!(
            transactions2.clone().push_transaction(
                trans2.clone()
                    .sign(&master_key, &admin_key1).unwrap()
                    .sign(&master_key, &admin_key2).unwrap()
                    .sign(&master_key, &admin_key3).unwrap()
            ).err(),
            Some(Error::PolicyNotFound)
        );

        let trans3 = transactions2.add_subkey(Timestamp::now(), subkey.clone(), "logins/websites/beeets.com", None).unwrap();
        assert_eq!(
            transactions2.clone().push_transaction(
                trans3.clone()
                    .sign(&master_key, &admin_key1).unwrap()
            ).err(),
            Some(Error::PolicyNotFound)
        );
        transactions2.clone().push_transaction(
            trans3.clone()
                .sign(&master_key, &admin_key1).unwrap()
                .sign(&master_key, &admin_key2).unwrap()
        ).unwrap();
        transactions2.clone().push_transaction(
            trans3.clone()
                .sign(&master_key, &admin_key3).unwrap()
                .sign(&master_key, &admin_key2).unwrap()
        ).unwrap();
        transactions2.clone().push_transaction(
            trans3.clone()
                .sign(&master_key, &admin_key1).unwrap()
                .sign(&master_key, &admin_key3).unwrap()
        ).unwrap();
        transactions2.clone().push_transaction(
            trans3.clone()
                .sign(&master_key, &admin_key1).unwrap()
                .sign(&master_key, &admin_key2).unwrap()
                .sign(&master_key, &admin_key3).unwrap()
        ).unwrap();

        let trans4 = transactions2.publish(Timestamp::now()).unwrap();
        let identity2 = transactions2.build_identity().unwrap();
        assert_eq!(
            trans4.clone()
                .sign(&master_key, &admin_key1).unwrap()
                .verify(Some(&identity2))
                .err(),
            Some(Error::PolicyNotFound)
        );
        assert_eq!(
            trans4.clone()
                .sign(&master_key, &admin_key1).unwrap()
                .sign(&master_key, &admin_key2).unwrap()
                .verify(Some(&identity2))
                .err(),
            Some(Error::PolicyNotFound)
        );
        assert_eq!(
            trans4.clone()
                .sign(&master_key, &admin_key1).unwrap()
                .sign(&master_key, &admin_key2).unwrap()
                .sign(&master_key, &admin_key3).unwrap()
                .verify(Some(&identity2))
                .err(),
            Some(Error::PolicyNotFound)
        );
        assert_eq!(
            trans4.clone()
                .sign(&master_key, &admin_key4).unwrap()
                .sign(&master_key, &admin_key3).unwrap()
                .verify(Some(&identity2))
                .err(),
            Some(Error::PolicyNotFound)
        );
        trans4.clone()
            .sign(&master_key, &admin_key4).unwrap()
            .sign(&master_key, &admin_key1).unwrap()
            .sign(&master_key, &admin_key2).unwrap()
            .verify(Some(&identity2))
            .unwrap();
        trans4.clone()
            .sign(&master_key, &admin_key4).unwrap()
            .sign(&master_key, &admin_key1).unwrap()
            .sign(&master_key, &admin_key3).unwrap()
            .verify(Some(&identity2))
            .unwrap();
        trans4.clone()
            .sign(&master_key, &admin_key4).unwrap()
            .sign(&master_key, &admin_key1).unwrap()
            .sign(&master_key, &admin_key2).unwrap()
            .sign(&master_key, &admin_key3).unwrap()
            .verify(Some(&identity2))
            .unwrap();

        let mut trans5 = trans4.clone()
            .sign(&master_key, &admin_key1).unwrap()
            .sign(&master_key, &admin_key3).unwrap();
        let fakesig = MultisigPolicySignature::Key {
            key: admin_key4.key().clone().into(),
            signature: admin_key4.sign(&master_key, b"GET A JOB").unwrap(),
        };
        trans5.signatures_mut().push(fakesig);
        assert!(matches!(
            trans5.verify(Some(&identity2)),
            Err(Error::TransactionSignatureInvalid(_))
        ));
    }

    #[test]
    fn transactions_prohibit_duplicates() {
        let (master_key, transactions, admin_key) = genesis();
        let now = Timestamp::now();
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ make_claim, now.clone(), ClaimSpec::Name(MaybePrivate::new_public("Dirk Delta from........Hollywood".into())), None::<String> ]
        };
        let claim_trans = transactions2.transactions()[1].clone();
        let res = transactions2.clone().push_transaction(claim_trans);
        assert_eq!(res.err(), Some(Error::DuplicateTransaction));
    }

    #[test]
    fn transactions_reencrypt() {
        let (master_key, transactions, admin_key) = genesis();
        let admin_key2 = AdminKey::new(AdminKeypair::new_ed25519(&master_key).unwrap(), "Second", None);
        let transactions = sign_and_push! { &master_key, &admin_key, transactions,
            [ make_claim, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_private(&master_key, "Hooty McOwl".to_string()).unwrap()), None::<String> ]
            [ add_admin_key, Timestamp::now(), admin_key2 ]
            [ make_claim, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public("dirk-delta".to_string())), Some(String::from("name")) ]
        };
        transactions.test_master_key(&master_key).unwrap();
        let identity = transactions.build_identity().unwrap();
        match identity.claims()[0].spec() {
            ClaimSpec::Name(maybe) => {
                let val = maybe.open(&master_key).unwrap();
                assert_eq!(val, "Hooty McOwl".to_string());
            }
            _ => panic!("bad claim type"),
        }
        let sig = identity.keychain().admin_keys()[0].key().sign(&master_key, b"KILL...ME....").unwrap();

        let master_key_new = SecretKey::new_xchacha20poly1305().unwrap();
        let transactions2 = transactions.reencrypt(&master_key, &master_key_new).unwrap();
        transactions2.test_master_key(&master_key_new).unwrap();
        let res = transactions2.test_master_key(&master_key);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
        let identity2 = transactions2.build_identity().unwrap();
        let sig2 = identity2.keychain().admin_keys()[0].key().sign(&master_key_new, b"KILL...ME....").unwrap();
        assert_eq!(sig, sig2);
        match identity2.claims()[0].spec() {
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
        let (master_key, transactions, admin_key) = genesis();
        let identity = transactions.build_identity().unwrap();
        assert!(transactions.is_owned());
        assert!(identity.is_owned());

        let mut transactions2 = transactions.clone();
        transactions2.transactions_mut()[0] = transactions2.transactions_mut()[0].strip_private();
        let identity2 = transactions2.build_identity().unwrap();
        assert!(!transactions2.is_owned());
        assert!(!identity2.is_owned());

        let admin_key2 = AdminKey::new(AdminKeypair::new_ed25519(&master_key).unwrap(), "Second", None);
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = PrivateWithMac::seal(&master_key, SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let transactions3 = sign_and_push! { &master_key, &admin_key, transactions.clone(),
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things") ]
            [ add_subkey, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails") ]
            [ add_subkey, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key") ]
            [ add_admin_key, Timestamp::now(), admin_key2 ]
        };
        let identity3 = transactions3.build_identity().unwrap();
        assert!(transactions3.is_owned());
        assert!(identity3.is_owned());

        let mut transactions4 = transactions3.clone();
        for trans in transactions4.transactions_mut() {
            let entry = trans.entry().clone();
            match entry.body() {
                TransactionBody::CreateIdentityV1 { .. } | TransactionBody::AddAdminKeyV1 { .. } => {
                    trans.set_entry(entry.strip_private());
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
        let (master_key, transactions, _admin_key) = genesis();
        transactions.test_master_key(&master_key).unwrap();
        let master_key_fake = SecretKey::new_xchacha20poly1305().unwrap();
        assert!(master_key_fake != master_key);
        let res = transactions.test_master_key(&master_key_fake);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
    }

    #[test]
    fn transactions_strip_has_private() {
        let (master_key, transactions, admin_key) = genesis();

        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = PrivateWithMac::seal(&master_key, SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let transactions2 = sign_and_push! { &master_key, &admin_key, transactions,
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things") ]
            [ add_subkey, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails") ]
            [ add_subkey, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key") ]
            [ make_claim, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_private(&master_key, "Danny Dinkel".to_string()).unwrap()), None::<String> ]
            [ make_claim, Timestamp::now(), ClaimSpec::Email(MaybePrivate::new_public("twinkie.doodle@amateur-spotlight.net".to_string())), None::<String> ]
        };

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
        let (_master_key, transactions, _admin_key) = genesis();
        let identity = transactions.build_identity().unwrap();
        let ser = transactions.serialize_binary().unwrap();
        let des = Transactions::deserialize_binary(ser.as_slice()).unwrap();
        let identity2 = des.build_identity().unwrap();
        // quick and dirty. oh well.
        assert_eq!(identity.id(), identity2.id());
    }
}

