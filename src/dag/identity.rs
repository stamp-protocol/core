//! This models an identity as a DAG of [`Transaction`] objects.

use crate::{
    crypto::{
        base::{Hash, HashAlgo, KeyID, SecretKey},
        private::{PrivateContainer, ReEncrypt},
    },
    dag::{Dag, Ext, StampTransaction, Transaction, TransactionBody, TransactionEntry, TransactionID},
    error::{Error, Result},
    identity::{
        claim::{ClaimID, ClaimSpec},
        instance::{IdentityID, IdentityInstance},
        keychain::{AdminKey, AdminKeyID, Key, RevocationReason},
        stamp::{RevocationReason as StampRevocationReason, Stamp, StampEntry, StampID},
    },
    policy::{Policy, PolicyContainer, PolicyID},
    util::{
        ser::{BinaryVec, HashMapAsn1, SerText, SerdeBinary},
        Timestamp,
    },
};
use private_parts::{Full, PrivacyMode, PrivateParts, Public};
use rand::{CryptoRng, RngCore};
use rasn::{AsnType, Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A container that holds a set of transactions.
#[derive(Debug, Default, Clone, PrivateParts, AsnType, Encode, Decode, Serialize, Deserialize)]
#[parts(private_data = "PrivateContainer")]
#[rasn(delegate)]
pub struct Identity<M: PrivacyMode>(Vec<Transaction<M>>);

impl<M> Identity<M>
where
    M: PrivacyMode,
    TransactionEntry<M>: Into<TransactionEntry<Public>>,
{
    /// Create a new, empty transaction set.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Transaction list getter
    pub fn transactions(&self) -> &Vec<Transaction<M>> {
        &self.0
    }

    /// Return the mutable transaction list
    pub fn transactions_mut(&mut self) -> &mut Vec<Transaction<M>> {
        &mut self.0
    }

    /// Set the transaction list
    pub fn set_transactions(&mut self, value: Vec<Transaction<M>>) {
        self.0 = value
    }

    /// Returns an iterator over these transactions
    pub fn iter(&self) -> core::slice::Iter<'_, Transaction<M>> {
        self.transactions().iter()
    }

    /// Grab the [IdentityID] from this transaction set.
    ///
    /// This requires building the DAG so don't go calling this 1000 times a second.
    pub fn identity_id(&self) -> Option<IdentityID> {
        if !self.transactions().is_empty() {
            let nodes = self.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
            let dag: Dag<TransactionID, Transaction<M>> = Dag::from_nodes(&[&nodes]);
            match dag.head()[..] {
                [node] => Some(node.clone().into()),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Run a transaction and return the output
    fn apply_transaction(identity: Option<IdentityInstance<M>>, transaction: &Transaction<M>) -> Result<IdentityInstance<M>> {
        if identity.as_ref().map(|i| *i.revoked()).unwrap_or(false) {
            Err(Error::IdentityRevoked)?;
        }
        match transaction.entry().body().clone() {
            TransactionBody::CreateIdentityV1 { admin_keys, policies } => {
                if identity.is_some() {
                    Err(Error::DagCreateIdentityOnExistingChain)?;
                }
                let policies_con = policies
                    .iter()
                    .enumerate()
                    .map(|(idx, x)| PolicyContainer::from_policy_transaction(transaction.id(), idx, x.clone()))
                    .collect::<Result<Vec<PolicyContainer>>>()?;
                let identity_id = IdentityID::from(transaction.id().clone());
                Ok(IdentityInstance::create(
                    identity_id,
                    admin_keys,
                    policies_con,
                    transaction.entry().created().clone(),
                ))
            }
            TransactionBody::ResetIdentityV1 { admin_keys, policies } => {
                let policies_con = if let Some(policies) = policies {
                    let containerized = policies
                        .iter()
                        .enumerate()
                        .map(|(idx, x)| PolicyContainer::from_policy_transaction(transaction.id(), idx, x.clone()))
                        .collect::<Result<Vec<PolicyContainer>>>()?;
                    Some(containerized)
                } else {
                    None
                };
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.reset(admin_keys, policies_con)?;
                Ok(identity_mod)
            }
            TransactionBody::RevokeIdentityV1 => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.revoke()?;
                Ok(identity_mod)
            }
            TransactionBody::AddAdminKeyV1 { admin_key } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.add_admin_key(admin_key)?;
                Ok(identity_mod)
            }
            TransactionBody::EditAdminKeyV1 { id, name, description } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.edit_admin_key(&id, name, description)?;
                Ok(identity_mod)
            }
            TransactionBody::RevokeAdminKeyV1 { id, reason, new_name } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.revoke_admin_key(&id, reason, new_name)?;
                Ok(identity_mod)
            }
            TransactionBody::AddPolicyV1 { policy } => {
                let identity_mod = identity
                    .ok_or(Error::DagMissingIdentity)?
                    .add_policy(PolicyContainer::from_policy_transaction(transaction.id(), 0, policy)?)?;
                Ok(identity_mod)
            }
            TransactionBody::DeletePolicyV1 { id } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.delete_policy(&id)?;
                Ok(identity_mod)
            }
            TransactionBody::MakeClaimV1 { spec, name } => {
                let claim_id = ClaimID::from(transaction.id().clone());
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.make_claim(claim_id, spec, name)?;
                Ok(identity_mod)
            }
            TransactionBody::EditClaimV1 { claim_id, name } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.edit_claim(&claim_id, name)?;
                Ok(identity_mod)
            }
            TransactionBody::DeleteClaimV1 { claim_id } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.delete_claim(&claim_id)?;
                Ok(identity_mod)
            }
            TransactionBody::MakeStampV1 { stamp: entry } => {
                let created = transaction.entry().created().clone();
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.make_stamp(Stamp::new(
                    StampID::from(transaction.id().clone()),
                    entry,
                    created,
                ))?;
                Ok(identity_mod)
            }
            TransactionBody::RevokeStampV1 { stamp_id, reason } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.revoke_stamp(&stamp_id, reason)?;
                Ok(identity_mod)
            }
            TransactionBody::AcceptStampV1 { stamp_transaction } => {
                stamp_transaction.verify_hash_and_signatures()?;
                let identity_mod = match stamp_transaction.entry().body() {
                    TransactionBody::MakeStampV1 { stamp: entry } => {
                        let created = stamp_transaction.entry().created().clone();
                        let stamp = Stamp::new(StampID::from(stamp_transaction.id().clone()), entry.clone(), created);
                        identity.ok_or(Error::DagMissingIdentity)?.accept_stamp(stamp)?
                    }
                    _ => Err(Error::TransactionMismatch)?,
                };
                Ok(identity_mod)
            }
            TransactionBody::DeleteStampV1 { stamp_id } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.delete_stamp(&stamp_id)?;
                Ok(identity_mod)
            }
            TransactionBody::AddSubkeyV1 { key, name, description } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.add_subkey(key, name, description)?;
                Ok(identity_mod)
            }
            TransactionBody::EditSubkeyV1 { id, name, description } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.edit_subkey(&id, name, description)?;
                Ok(identity_mod)
            }
            TransactionBody::RevokeSubkeyV1 { id, reason, new_name } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.revoke_subkey(&id, reason, new_name)?;
                Ok(identity_mod)
            }
            TransactionBody::DeleteSubkeyV1 { id } => {
                let identity_mod = identity.ok_or(Error::DagMissingIdentity)?.delete_subkey(&id)?;
                Ok(identity_mod)
            }
            TransactionBody::PublishV1 { .. } => {
                // NOPE
                Err(Error::TransactionInvalid(
                    transaction.id().clone(),
                    "Publish transactions cannot be applied to identities".into(),
                ))
            }
            TransactionBody::SignV1 { .. } => {
                // NOPE
                Err(Error::TransactionInvalid(
                    transaction.id().clone(),
                    "Sign transactions cannot be applied to identities".into(),
                ))
            }
            TransactionBody::ExtV1 { .. } => {
                // NOPE
                Err(Error::TransactionInvalid(
                    transaction.id().clone(),
                    "Ext transactions cannot be applied to identities".into(),
                ))
            }
        }
    }

    fn build_identity_impl(transactions: &[Transaction<M>]) -> Result<IdentityInstance<M>> {
        if transactions.is_empty() {
            Err(Error::DagEmpty)?;
        }
        let nodes = transactions.iter().map(|x| x.into()).collect::<Vec<_>>();
        let dag: Dag<TransactionID, Transaction<M>> = Dag::from_nodes(&[&nodes]);

        if !dag.missing().is_empty() {
            #[allow(suspicious_double_ref_op)]
            Err(Error::DagMissingTransactions(dag.missing().iter().map(|x| x.clone().clone()).collect::<Vec<_>>()))?;
        }
        let mut branch_identities: HashMap<TransactionID, IdentityInstance<M>> = HashMap::new();
        let identity = dag
            .apply(
                &mut branch_identities,
                |node| Identity::apply_transaction(None, node.node()),
                |_node| false,
                |identity, node| node.node().authorize(Some(identity)),
                |identity, node| {
                    let id = identity.clone();
                    (*identity) = Identity::apply_transaction(Some(id), node.node())?;
                    Ok(())
                },
            )?
            .clone();

        // note here we grab the identity at branch 0...this is the root identity that all the
        // transactions have been applied to in-order.
        Ok(identity)
    }

    /// Build an identity from our heroic transactions.
    ///
    /// This happens using the [`Dag`] utility helper to process and walk the transactions of the
    /// DAG in order. Inside that walk function, each branch of the DAG gets its own branch ID, and
    /// we use these branch IDs to create a set of identities (one-per-branch) that remains updated
    /// as the transactions are walked. the nearest common branch to a transaction (or set of
    /// transactions in the case of a merge) is used to *verify* the transaction, and if
    /// verification passes, the transaction is then applied to ALL identities in its ancestry.
    ///
    /// The end result is that when we pluck the root identity off of the branch tracker, it has
    /// had all the transactions validated and applied to it *in order*, giving us a final
    /// identity!
    ///
    /// Easy, right??
    ///
    /// NOTE: this algorithm handles signing key conflicts by only using the
    /// nearest branch-level identity to *validate* the current transaction,
    /// although the transaction is applied to all identities from previous
    /// branches as well. However, this algorithm does not handle other
    /// conflicts (such as duplicate entries).
    pub fn build_identity_instance(&self) -> Result<IdentityInstance<M>> {
        Self::build_identity_impl(self.transactions())
    }

    /// Builds an identity using a set of transaction IDs as the stopping point.
    ///
    /// Basically this means we look at those transaction IDs, work backwards to find the entire
    /// identity DAG leading up to those transaction IDs, and omit any transactions not in that
    /// tree. The idea here is that we can build the identity at a certain point in history to
    /// verify the validity of some transaction that may have been issued in the past (which is no
    /// longer valid).
    pub fn build_identity_instance_at_point_in_history(&self, past_transactions: &[TransactionID]) -> Result<IdentityInstance<M>> {
        let mut transactions_idx = HashMap::with_capacity(self.transactions().len());
        for trans in self.transactions().iter() {
            transactions_idx.insert(trans.id(), trans);
        }

        fn transaction_finder<'a, M: PrivacyMode>(
            idx: &'a HashMap<&TransactionID, &Transaction<M>>,
            prev: &'a [TransactionID],
            visited: &mut HashSet<&'a TransactionID>,
            final_list: &mut Vec<Transaction<M>>,
        ) -> Result<()> {
            for txid in prev {
                if visited.contains(txid) {
                    continue;
                }
                let trans = idx.get(&txid).ok_or_else(|| Error::DagMissingTransactions(vec![txid.clone()]))?;
                visited.insert(txid);
                #[allow(suspicious_double_ref_op)]
                final_list.push(trans.clone().clone());
                transaction_finder(idx, trans.entry().previous_transactions(), visited, final_list)?;
            }
            Ok(())
        }
        let mut visited = HashSet::new();
        let mut transactions = Vec::new();
        transaction_finder(&transactions_idx, past_transactions, &mut visited, &mut transactions)?;

        Self::build_identity_impl(&transactions)
    }

    /// Find any transactions that are not referenced as previous transactions.
    /// Effectively, the leaves of our graph.
    fn find_leaf_transactions(transaction_list: &[Transaction<M>]) -> Vec<&TransactionID> {
        let mut seen: HashSet<&TransactionID> = HashSet::new();
        for trans in transaction_list {
            for prev in trans.entry().previous_transactions() {
                seen.insert(prev);
            }
        }
        transaction_list
            .iter()
            .filter_map(|t| if seen.get(t.id()).is_some() { None } else { Some(t.id()) })
            .collect::<Vec<_>>()
    }

    /// Push a transaction created by one of the transaction-creating functions
    /// onto this transaction set. We consume and return the transaction set for
    /// this.
    pub fn push_transaction(mut self, transaction: Transaction<M>) -> Result<Self> {
        self.push_transaction_mut(transaction)?;
        Ok(self)
    }

    /// Push a transaction onto this transaction set, returning the fully-built
    /// identity created from running all transactions (including the one being
    /// pushed).
    ///
    /// Unless you know you want an [`IdentityInstance`] instead of [`Identity`], or
    /// when in doubt, use [`push_transaction()`][Identity::push_transaction]
    /// instead of this method.
    pub fn push_transaction_mut(&mut self, transaction: Transaction<M>) -> Result<IdentityInstance<M>> {
        if transaction.signatures().is_empty() {
            Err(Error::TransactionNoSignatures)?;
        }
        if self.transactions().iter().any(|x| x.id() == transaction.id()) {
            Err(Error::DuplicateTransaction)?;
        }
        let identity_instance_maybe = match self.build_identity_instance() {
            Ok(id) => Some(id),
            Err(Error::DagEmpty) => None,
            Err(e) => Err(e)?,
        };
        let identity_instance = Self::apply_transaction(identity_instance_maybe, &transaction)?;
        self.transactions_mut().push(transaction);
        // build it again
        let _identity_maybe = match self.build_identity_instance() {
            Ok(id) => Some(id),
            Err(Error::DagEmpty) => None,
            Err(e) => Err(e)?,
        };
        Ok(identity_instance)
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
            if branch1.transactions().iter().any(|t| t.id() == trans2.id()) {
                continue;
            }
            branch1.transactions_mut().push(trans2.clone());
        }
        // make sure it's all copasetic.
        branch1.build_identity_instance()?;
        Ok(branch1)
    }

    /// Reset a set of transactions to a previous state.
    ///
    /// Effectively, we take a transaction ID and remove any transactions that
    /// came after it. This may create many trailing transactions, which will be
    /// connected the next time a new transaction is created.
    pub fn reset(mut self, txid: &TransactionID) -> Result<Self> {
        // recursively find all transactions referencing the given one
        fn find_tx_to_rm<M: PrivacyMode>(transactions: &[Transaction<M>], txid: &TransactionID) -> Vec<TransactionID> {
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
}

impl Identity<Full> {
    /// Test if a master key is correct.
    pub fn test_master_key(&self, master_key: &SecretKey) -> Result<()> {
        let identity_instance = self.build_identity_instance()?;
        identity_instance.test_master_key(master_key)
    }

    /// Creates a new transaction that references the trailing transactions in the
    /// current set.
    pub(crate) fn prepare_transaction<T: Into<Timestamp> + Clone>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        body: TransactionBody<Full>,
    ) -> Result<Transaction<Full>> {
        let leaves = Self::find_leaf_transactions(self.transactions());
        Transaction::<Full>::new(TransactionEntry::<Full>::new(now, leaves.into_iter().cloned().collect::<Vec<_>>(), body), hash_with)
    }

    // -------------------------------------------------------------------------
    // The actual transaction builder methods
    // -------------------------------------------------------------------------

    /// Create a new identity. The [ID][TransactionID] of this transaction will
    /// be the identity's public ID forever after.
    pub fn create_identity<T: Into<Timestamp> + Clone>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        admin_keys: Vec<AdminKey<Full>>,
        policies: Vec<Policy>,
    ) -> Result<Transaction<Full>> {
        let body = TransactionBody::CreateIdentityV1 { admin_keys, policies };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Replace optionally both the [admin keys][AdminKey] in the
    /// [Keychain][crate::identity::keychain::Keychain]
    /// and the [policies][Policy] attached to the identity.
    ///
    /// This is more or less a hailmary recovery option that allows gaining
    /// access to identity after some kind of catastrophic event.
    pub fn reset_identity<T: Into<Timestamp> + Clone>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        admin_keys: Option<Vec<AdminKey<Full>>>,
        policies: Option<Vec<Policy>>,
    ) -> Result<Transaction<Full>> {
        let body = TransactionBody::ResetIdentityV1 { admin_keys, policies };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Add a new [admin key][AdminKey] to the [Keychain][crate::identity::keychain::Keychain].
    pub fn add_admin_key<T: Into<Timestamp> + Clone>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        admin_key: AdminKey<Full>,
    ) -> Result<Transaction<Full>> {
        let body = TransactionBody::AddAdminKeyV1 { admin_key };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Edit an [admin key][AdminKey].
    pub fn edit_admin_key<T, S>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        id: AdminKeyID,
        name: Option<S>,
        description: Option<Option<S>>,
    ) -> Result<Transaction<Full>>
    where
        T: Into<Timestamp> + Clone,
        S: Into<String>,
    {
        let body = TransactionBody::EditAdminKeyV1 {
            id,
            name: name.map(|x| x.into()),
            description: description.map(|x| x.map(|y| y.into())),
        };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Revokes an [AdminKey] key and moves it into the subkeys, optionally
    /// renaming it.
    pub fn revoke_admin_key<T, S>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        id: AdminKeyID,
        reason: RevocationReason,
        new_name: Option<S>,
    ) -> Result<Transaction<Full>>
    where
        T: Into<Timestamp> + Clone,
        S: Into<String>,
    {
        let body = TransactionBody::RevokeAdminKeyV1 {
            id,
            reason,
            new_name: new_name.map(|x| x.into()),
        };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Add a new [policy][Policy] to the identity.
    pub fn add_policy<T: Into<Timestamp> + Clone>(&self, hash_with: &HashAlgo, now: T, policy: Policy) -> Result<Transaction<Full>> {
        let body = TransactionBody::AddPolicyV1 { policy };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Delete (by name) a [Policy] from the identity.
    pub fn delete_policy<T: Into<Timestamp> + Clone>(&self, hash_with: &HashAlgo, now: T, id: PolicyID) -> Result<Transaction<Full>> {
        let body = TransactionBody::DeletePolicyV1 { id };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Make a new [Claim][ClaimSpec].
    pub fn make_claim<T, S>(&self, hash_with: &HashAlgo, now: T, spec: ClaimSpec<Full>, name: Option<S>) -> Result<Transaction<Full>>
    where
        T: Into<Timestamp> + Clone,
        S: Into<String>,
    {
        let body = TransactionBody::MakeClaimV1 {
            spec,
            name: name.map(|x| x.into()),
        };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Edit a claim.
    pub fn edit_claim<T, S>(&self, hash_with: &HashAlgo, now: T, claim_id: ClaimID, name: Option<S>) -> Result<Transaction<Full>>
    where
        T: Into<Timestamp> + Clone,
        S: Into<String>,
    {
        let body = TransactionBody::EditClaimV1 {
            claim_id,
            name: name.map(|x| x.into()),
        };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Delete an existing claim.
    pub fn delete_claim<T: Into<Timestamp> + Clone>(&self, hash_with: &HashAlgo, now: T, claim_id: ClaimID) -> Result<Transaction<Full>> {
        let body = TransactionBody::DeleteClaimV1 { claim_id };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Make a transaction that stamps a claim. This transaction can be saved
    /// with the stemping identity (stamper) in order to advertise it as a public
    /// stamp.
    ///
    /// It can also not be added to the identity and sent directly to the stampee.
    pub fn make_stamp<T: Into<Timestamp> + Clone>(&self, hash_with: &HashAlgo, now: T, stamp: StampEntry) -> Result<Transaction<Full>> {
        let body = TransactionBody::MakeStampV1 { stamp };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Revoke a stamp we previously created and store this revocation with the
    /// identity.
    pub fn revoke_stamp<T: Into<Timestamp> + Clone>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        stamp_id: StampID,
        reason: StampRevocationReason,
    ) -> Result<Transaction<Full>> {
        let body = TransactionBody::RevokeStampV1 { stamp_id, reason };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Accept a stamp someone, or some*thing*, has made on a claim of ours.
    pub fn accept_stamp<T: Into<Timestamp> + Clone>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        stamp_transaction: StampTransaction,
    ) -> Result<Transaction<Full>> {
        let body = TransactionBody::AcceptStampV1 {
            stamp_transaction: Box::new(stamp_transaction),
        };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Delete an existing stamp.
    pub fn delete_stamp<T: Into<Timestamp> + Clone>(&self, hash_with: &HashAlgo, now: T, stamp_id: StampID) -> Result<Transaction<Full>> {
        let body = TransactionBody::DeleteStampV1 { stamp_id };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Add a new subkey to our keychain.
    pub fn add_subkey<T, S>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        key: Key<Full>,
        name: S,
        description: Option<S>,
    ) -> Result<Transaction<Full>>
    where
        T: Into<Timestamp> + Clone,
        S: Into<String>,
    {
        let body = TransactionBody::AddSubkeyV1 {
            key,
            name: name.into(),
            description: description.map(|x| x.into()),
        };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Edit a subkey.
    pub fn edit_subkey<T, S>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        id: KeyID,
        name: Option<S>,
        description: Option<Option<S>>,
    ) -> Result<Transaction<Full>>
    where
        T: Into<Timestamp> + Clone,
        S: Into<String>,
    {
        let body = TransactionBody::EditSubkeyV1 {
            id,
            name: name.map(|x| x.into()),
            description: description.map(|x| x.map(|y| y.into())),
        };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Revoke a subkey.
    pub fn revoke_subkey<T, S>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        id: KeyID,
        reason: RevocationReason,
        new_name: Option<S>,
    ) -> Result<Transaction<Full>>
    where
        T: Into<Timestamp> + Clone,
        S: Into<String>,
    {
        let body = TransactionBody::RevokeSubkeyV1 {
            id,
            reason,
            new_name: new_name.map(|x| x.into()),
        };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Delete a subkey.
    pub fn delete_subkey<T: Into<Timestamp> + Clone>(&self, hash_with: &HashAlgo, now: T, id: KeyID) -> Result<Transaction<Full>> {
        let body = TransactionBody::DeleteSubkeyV1 { id };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Publish this identity
    pub fn publish<T: Into<Timestamp> + Clone>(&self, hash_with: &HashAlgo, now: T) -> Result<Transaction<Full>> {
        let identity_pub: Identity<Public> = self.clone().into();
        let body = TransactionBody::PublishV1 { identity: identity_pub };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Sign a message
    pub fn sign<T: Into<Timestamp> + Clone>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        body_hash_with: &HashAlgo,
        body: &[u8],
    ) -> Result<Transaction<Full>> {
        let identity_instance = self.build_identity_instance()?;
        if *identity_instance.revoked() {
            Err(Error::IdentityRevoked)?;
        }
        let creator = identity_instance.id().clone();
        let body_hash = match body_hash_with {
            HashAlgo::Blake3 => Hash::new_blake3(body)?,
        };
        let body = TransactionBody::SignV1 { creator, body_hash };
        self.prepare_transaction(hash_with, now, body)
    }

    /// Create a transaction for use in an external system.
    pub fn ext<T: Into<Timestamp> + Clone, K: Into<HashMapAsn1<BinaryVec, BinaryVec>>>(
        &self,
        hash_with: &HashAlgo,
        now: T,
        previous_transactions: Vec<TransactionID>,
        ty: Option<BinaryVec>,
        context: Option<K>,
        payload: BinaryVec,
    ) -> Result<Transaction<Full>> {
        let identity_instance = self.build_identity_instance()?;
        if *identity_instance.revoked() {
            Err(Error::IdentityRevoked)?;
        }
        let creator = identity_instance.id().clone();
        let ext = Ext::new(
            creator,
            ty,
            previous_transactions,
            context.map(|x| x.into()).unwrap_or_else(|| HashMapAsn1::default()),
            payload,
        );
        let body = TransactionBody::ExtV1(ext);
        self.prepare_transaction(hash_with, now, body)
    }
}

impl ReEncrypt for Identity<Full> {
    fn reencrypt<R: RngCore + CryptoRng>(mut self, rng: &mut R, old_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        for trans in self.transactions_mut() {
            *trans = trans.clone().reencrypt(rng, old_master_key, new_master_key)?;
        }
        Ok(self)
    }
}

impl<M: PrivacyMode> IntoIterator for Identity<M> {
    type Item = Transaction<M>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let Identity(transactions) = self;
        transactions.into_iter()
    }
}

impl<M> SerdeBinary for Identity<M>
where
    M: PrivacyMode,
    Identity<M>: Encode + Decode,
{
}

impl SerText for Identity<Public> {}

/// Allows creating DAG chains of transactions using a friendly and inviting syntax that will change
/// the way you think and live *forever*.
///
/// You *could* create your transaction lists by hand, starting with the first and painstakingly
/// crafting all the following ones, updating the `previous_transactions` lists by hand...
///
/// OR you could try this handy macro:
///
/// ```rust,ignore
/// let (transaction_list, name_to_tx, id_to_name): (Vec<Transaction>, HashMap<&'static str, Transaction>, HashMap<TransactionID, &'static str>) = tx_chain! {
///     // define your tx here, giving each a short, memorable name, a timestamp, and a lambda
///     // function in the format:
///     //
///     //   |now: Timestamp, previous_transactions: Vec<TransactionID>| -> Transaction
///     //
///     // note that the lambda functions can reference the transactions that come before them
///     // previously *in the DAG* (not as they are defined in the list below, but in the order of
///     // produced DAG nodes).
///     [
///         A = ("2024-01-03T00:01:01Z", |now, prev| { ... });
///         B = ("2024-01-02T00:01:01Z", |now, prev| { ... A.id() ... });
///         C = ("2024-01-03T00:01:01Z", |now, prev| { ... });
///         D = ("2024-01-04T00:01:01Z", |now, prev| { ... B.id() ...});
///         E = ("2024-01-08T00:01:01Z", |now, prev| { ... });
///         F = ("2024-01-05T00:01:01Z", |now, prev| { ... });
///         G = ("2024-01-06T00:01:01Z", |now, prev| { ... B.id() ... F.id() ... });
///     ],
///     // now define all your backlinks. A & B are refrenced by C, C by D & E, E by F, D & F by G
///     // this creates our heroic DAG chain.
///     [
///         [A] <- [B],
///         [A, B] <- [C],
///         [C] <- [D, E],
///         [E] <- [F],
///         [D, F] <- [G],
///     ],
/// };
/// ```
///
/// Note that this macro is only really used for testing, but because it's so useful for testing,
/// it's exported as a public macro.
#[macro_export]
macro_rules! tx_chain {
    (
        [$($name:ident = ($time:expr, $tx:expr);)*],
        [$([$($from:ident),*] <- [$($to:ident),*],)*],
    ) => {{
        /// A type meant to hold some relevant info about our DAG nodes in a format we don't have
        /// to worry about dancing around mutations. This is a type we own and can manipulate to
        /// our cold icy heart's content, but can be converted into a `Transaction` later which is
        /// much more rigid about mutations.
        #[derive(Clone, Debug)]
        struct Node {
            id: $crate::dag::TransactionID,
            timestamp: Timestamp,
            previous_transactions: Vec<$crate::dag::TransactionID>,
        }
        impl Node {
            fn id(&self) -> &$crate::dag::TransactionID { &self.id }
        }
        impl<'a> From<&'a Node> for $crate::dag::DagNode<'a, $crate::dag::TransactionID, Node> {
            fn from(n: &'a Node) -> Self {
                $crate::dag::DagNode::new(&n.id, n, n.previous_transactions.iter().collect::<Vec<_>>(), &n.timestamp)
            }
        }

        // maps temporary node ids to real/new node ids
        let mut node_id_map: std::collections::HashMap<TransactionID, TransactionID> = Default::default();
        // maps node name (ie, "A", "B", ...) to a transaction ID
        let mut name_to_tx: std::collections::HashMap<&'static str, Transaction<Full>> = Default::default();
        // holds our `Node` objects, to be turned into a DAG
        let mut nodes_tmp = Vec::new();

        // loop over our nodes and create `Node` objects for each, with "fake" ids (via Hash(<name>)).
        // then we set up the proper previous nodes for each node given the spec.
        {
            $(
                #[allow(non_snake_case, unused_mut)]
                let mut $name = Node {
                    id: $crate::dag::TransactionID::from(Hash::new_blake3(stringify!($name).as_bytes()).expect("tx_chain!{} hash constructed")),
                    timestamp: $crate::util::Timestamp::from_str($time).expect("tx_chain!{} timestamp parsed"),
                    previous_transactions: Vec::new(),
                };
            )*
            $(
                {
                    let from = vec![$($from.id().clone()),*];
                    $(
                        for prev in &from {
                            $to.previous_transactions.push(prev.clone());
                        }
                    )*
                }
            )*
            // push our nodes into a temp vec
            $(
                nodes_tmp.push($name);
            )*
        }

        // now create a named variable for each of the transactions we'll build. this allows
        // transaction creation functions to reference other transactions by name, ASSUMING the
        // referenced transactions happen BEFORE the current one in the DAG chain. if not, you'll
        // get blank [0000...] ids for everything, so don't be silly and try to get ids for future
        // DAG nodes. nobody thinks you're funny, Parker.
        //
        // this also saves us from having to pass a name->transaction mapping hash in each call!
        let fake_trans = $crate::dag::Transaction::<Full>::create_raw_with_id(
            $crate::dag::TransactionID::from($crate::crypto::base::Hash::new_blake3_from_bytes([0u8; 32])),
            $crate::util::Timestamp::from_str("1900-01-01T06:43:22Z").expect("tx_chain!{} timestamp parsed"),
            Vec::new(),
            $crate::dag::TransactionBody::DeletePolicyV1 { id: $crate::policy::PolicyID::from($crate::dag::TransactionID::from($crate::crypto::base::Hash::new_blake3_from_bytes([0u8; 32]))) },
        );
        $(
            // start each named transaction with a fake clone. we'll populate these properly as the
            // DAG progresses.
            #[allow(non_snake_case, unused, unused_mut)]
            let mut $name: Transaction<Full> = fake_trans.clone();
        )*

        // holds our final transaction list
        let mut transactions: Vec<Transaction<Full>> = Vec::with_capacity(nodes_tmp.len());
        // holds a mapping of final node ids (not temporary) to node name
        let mut id_to_name = std::collections::HashMap::new();
        // convert our temp node list a list of `DagNode`s, then build our DAG and walk it.
        let nodes = nodes_tmp.iter().map(|x| x.into()).collect::<Vec<_>>();
        let dag: Dag<TransactionID, Node> = Dag::from_nodes(&[&nodes]);

        for node_id in dag.visited() {
            let node = dag.index().get(node_id).expect("tx_chain!{} dag index has node");
            // loop over this node's previous transactions list, converting the temporary ids
            // contained there into proper IDs via our old->new id mapping (which is populated just
            // below).
            let prev = node.node().previous_transactions.iter().map(|x| node_id_map.get(x).expect("tx_chain!{} id map has entry")).cloned().collect::<Vec<_>>();
            // create a giant if {} block that matches nodes via the deterministic hash id
            // (Hash(<name>)), allowing us to run our transaction creation fn for the current node.
            if false {}
            $(
                else if node.node().id() == &$crate::dag::TransactionID::from(Hash::new_blake3(stringify!($name).as_bytes()).expect("tx_chain!{} hash constructed")) {
                    let name: &'static str = stringify!($name);
                    // run our $tx (transaction creation function) for the current node
                    $name = $tx(node.node().timestamp.clone(), prev);
                    // map our old node id to the new node id so future transactions can get an
                    // updated `previous_transactions` list.
                    node_id_map.insert(node.node().id().clone(), $name.id().clone());
                    // update our name/id mappings
                    name_to_tx.insert(name, $name.clone());
                    id_to_name.insert($name.id().clone(), name);
                    // final save
                    transactions.push($name.clone());
                }
            )*
        }
        // send it
        (transactions, name_to_tx, id_to_name)
    }};
}

#[allow(unused_imports)]
pub use tx_chain;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{
            base::{CryptoKeypair, SignKeypair},
            private::{MaybePrivate, PrivateWithHmac},
        },
        dag::DagTamperUtil,
        identity::{
            claim::{Relationship, RelationshipType},
            keychain::AdminKeypair,
            stamp::Confidence,
        },
        policy::{Capability, Context, MultisigPolicy, MultisigPolicySignature, Policy, PolicyContainer, TransactionBodyType},
        util::{
            ser::{self, BinaryVec},
            test::{self, sign_and_push},
            Date, Url,
        },
    };
    use std::str::FromStr;

    #[test]
    fn identity_identity_id_is_genesis_transaction() {
        let mut rng = crate::util::test::rng();
        let (_master_key, identity, _admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity_instance = identity.build_identity_instance().unwrap();
        assert_eq!(IdentityID::from(identity.transactions()[0].id().clone()), identity_instance.id().clone());
    }

    #[test]
    fn identity_build_identity_instance_at_point_in_history() {
        let mut rng = crate::util::test::rng_seeded(b"beans");
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let mktx = |now, prev, body| Transaction::create_raw(&HashAlgo::Blake3, now, prev, body).unwrap();
        let (tx, name_to_tx, _id_to_name): (
            Vec<Transaction<Full>>,
            HashMap<&'static str, Transaction<Full>>,
            HashMap<TransactionID, &'static str>,
        ) = tx_chain! {
            [
                GEN = ("2024-01-01T00:00:00Z", |now, prev| mktx(now, prev, identity.transactions()[0].entry().body().clone()));
                NAM1 = ("2024-01-01T00:00:00Z", |now, prev| mktx(now, prev, TransactionBody::MakeClaimV1 { spec: ClaimSpec::Name(MaybePrivate::new_public("terrance".into())), name: None }));
                DOM1 = ("2024-01-02T00:00:00Z", |now, prev| mktx(now, prev, TransactionBody::MakeClaimV1 { spec: ClaimSpec::Domain(MaybePrivate::new_public("plaque.is.a.figment.of.the.liberal.media".into())), name: Some("site/primary".into()) }));
                DOM2 = ("2024-01-03T00:00:00Z", |now, prev| mktx(now, prev, TransactionBody::MakeClaimV1 { spec: ClaimSpec::Domain(MaybePrivate::new_public("plaque.is.a.figment.of.the.dental.industry".into())), name: Some("site/primary".into()) }));
                EM1 = ("2024-01-04T00:00:00Z", |now, prev| mktx(now, prev, TransactionBody::MakeClaimV1 { spec: ClaimSpec::Email(MaybePrivate::new_public("fossil@niceyniceyzoozoo.com".into())), name: Some("email/personal".into()) }));
                EM2 = ("2024-01-05T00:00:00Z", |now, prev| mktx(now, prev, TransactionBody::MakeClaimV1 { spec: ClaimSpec::Email(MaybePrivate::new_public("balloon.face@artbyvince.com".into())), name: Some("email/personal".into()) }));
                URL1 = ("2024-01-06T00:00:00Z", |now, prev| mktx(now, prev, TransactionBody::MakeClaimV1 { spec: ClaimSpec::Url(MaybePrivate::new_public(Url::parse("https://uploads.vidbox.legitimate-vids.com.ru/watch/YOUR.WIFE.WITH.THE.NEXTDOOR.NEIGHBOR.mp4.avi.zip.exe").unwrap())), name: Some("urllol".into()) }));
            ],
            [
                [GEN] <- [NAM1],
                [NAM1] <- [DOM1, DOM2],
                [DOM1] <- [EM1],
                [DOM2] <- [EM2],
                [EM1, EM2] <- [URL1],
            ],
        };
        let names_to_ids =
            |names: &[&str]| -> Vec<TransactionID> { names.iter().map(|n| name_to_tx.get(n).unwrap().id().clone()).collect::<Vec<_>>() };
        let tx = tx.into_iter().map(|t| t.sign(&master_key, &admin_key).unwrap()).collect::<Vec<_>>();
        let mut identity = Identity::new();
        for t in tx {
            identity.push_transaction_mut(t).unwrap();
        }

        {
            let identity_instance = identity.build_identity_instance().unwrap();
            assert_eq!(identity_instance.names(), vec!["terrance".to_string()]);
            assert_eq!(
                identity_instance.emails(),
                vec!["fossil@niceyniceyzoozoo.com".to_string(), "balloon.face@artbyvince.com".to_string()]
            );
            match identity_instance.find_claim_by_name("site/primary").unwrap().spec() {
                ClaimSpec::Domain(MaybePrivate::Public(val)) => {
                    assert_eq!(val, "plaque.is.a.figment.of.the.dental.industry");
                }
                _ => panic!("bad variant"),
            }
            match identity_instance.find_claim_by_name("email/personal").unwrap().spec() {
                ClaimSpec::Email(MaybePrivate::Public(val)) => {
                    assert_eq!(val, "balloon.face@artbyvince.com");
                }
                _ => panic!("bad variant"),
            }
            match identity_instance.find_claim_by_name("urllol").unwrap().spec() {
                ClaimSpec::Url(MaybePrivate::Public(val)) => {
                    assert_eq!(
                        val,
                        &Url::parse(
                            "https://uploads.vidbox.legitimate-vids.com.ru/watch/YOUR.WIFE.WITH.THE.NEXTDOOR.NEIGHBOR.mp4.avi.zip.exe"
                        )
                        .unwrap()
                    );
                }
                _ => panic!("bad variant"),
            }
        }

        {
            let identity_instance = identity
                .build_identity_instance_at_point_in_history(&names_to_ids(&["DOM1"]))
                .unwrap();
            assert_eq!(identity_instance.names(), vec!["terrance".to_string()]);
            assert_eq!(identity_instance.emails(), Vec::<String>::new());
            match identity_instance.find_claim_by_name("site/primary").unwrap().spec() {
                ClaimSpec::Domain(MaybePrivate::Public(domain)) => {
                    assert_eq!(domain, "plaque.is.a.figment.of.the.liberal.media");
                }
                _ => panic!("bad variant"),
            }
            assert!(identity_instance.find_claim_by_name("email/personal").is_none());
            assert!(identity_instance.find_claim_by_name("urllol").is_none());
        }

        {
            let identity_instance = identity
                .build_identity_instance_at_point_in_history(&names_to_ids(&["DOM2", "EM1"]))
                .unwrap();
            assert_eq!(identity_instance.names(), vec!["terrance".to_string()]);
            assert_eq!(identity_instance.emails(), vec!["fossil@niceyniceyzoozoo.com".to_string()]);
            match identity_instance.find_claim_by_name("site/primary").unwrap().spec() {
                ClaimSpec::Domain(MaybePrivate::Public(val)) => {
                    assert_eq!(val, "plaque.is.a.figment.of.the.dental.industry");
                }
                _ => panic!("bad variant"),
            }
            match identity_instance.find_claim_by_name("email/personal").unwrap().spec() {
                ClaimSpec::Email(MaybePrivate::Public(val)) => {
                    assert_eq!(val, "fossil@niceyniceyzoozoo.com");
                }
                _ => panic!("bad variant"),
            }
            assert!(identity_instance.find_claim_by_name("urllol").is_none());
        }

        {
            let txid = TransactionID::from(Hash::new_blake3(b"not today, jerry").unwrap());
            let res = identity.build_identity_instance_at_point_in_history(&[txid.clone()]);
            assert_eq!(res.err().unwrap(), Error::DagMissingTransactions(vec![txid]));
        }
    }

    #[test]
    fn identity_push() {
        let mut rng = crate::util::test::rng();
        let now = Timestamp::from_str("2021-04-20T00:00:10Z").unwrap();
        let (master_key_1, identity1, admin_key_1) = test::create_fake_identity(&mut rng, now.clone());
        let (_master_key_2, mut identity2, _admin_key_2) = test::create_fake_identity(&mut rng, now.clone());
        let trans_claim_signed = identity1
            .make_claim(
                &HashAlgo::Blake3,
                now.clone(),
                ClaimSpec::Name(MaybePrivate::new_public("Hooty McOwl".to_string())),
                None::<String>,
            )
            .unwrap()
            .sign(&master_key_1, &admin_key_1)
            .unwrap();
        identity1.push_transaction(trans_claim_signed.clone()).unwrap();
        identity2.build_identity_instance().unwrap();
        match identity2.push_transaction_mut(trans_claim_signed.clone()) {
            Ok(_) => {
                panic!("pushed a bad raw transaction: {}", trans_claim_signed.id().as_string())
            }
            Err(e) => {
                assert_eq!(
                    e,
                    Error::DagMissingTransactions(vec![trans_claim_signed.entry().previous_transactions()[0].clone()])
                )
            }
        }
    }

    #[test]
    fn identity_merge_reset() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::from_str("2021-04-20T00:00:00Z").unwrap());
        // make some claims on my smart refrigerator
        let admin_key_2 = AdminKey::new(AdminKeypair::from(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap()), "Alpha", None);
        let admin_key_3 = AdminKey::new(AdminKeypair::from(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap()), "Alpha", None);
        let branch1 = sign_and_push! { &master_key, &admin_key, identity.clone(),
            [ make_claim, Timestamp::from_str("2021-04-20T00:00:10Z").unwrap(), ClaimSpec::Name(MaybePrivate::new_public("Hooty McOwl".to_string())), None::<String> ]
            [ add_admin_key, Timestamp::from_str("2021-04-20T00:01:00Z").unwrap(), admin_key_2.clone() ]
            [ revoke_admin_key, Timestamp::from_str("2021-04-20T00:01:01Z").unwrap(), admin_key_2.key_id(), RevocationReason::Superseded, Some("CYA") ]
            [ make_claim, Timestamp::from_str("2021-04-20T00:01:33Z").unwrap(), ClaimSpec::Address(MaybePrivate::new_public("1112 Dirk Delta Ln.".to_string())), Some(String::from("primary")) ]
        };
        // make some claims on my Facebook (TM) (R) (C) Brain (AND NOW A WORD FROM OUR SPONSORS) Implant
        let branch2 = sign_and_push! { &master_key, &admin_key, identity.clone(),
            [ make_claim, Timestamp::from_str("2021-04-20T00:00:30Z").unwrap(), ClaimSpec::Url(MaybePrivate::new_public(Url::parse("https://www.cactus-petes.com/yeeeehawwww").unwrap())), None::<String> ]
            [ add_admin_key, Timestamp::from_str("2021-04-20T00:01:36Z").unwrap(), admin_key_3.clone() ]
            [ make_claim, Timestamp::from_str("2021-04-20T00:01:45Z").unwrap(), ClaimSpec::Address(MaybePrivate::new_public("1112 Liberal Hokes ave.".to_string())), Some(String::from("primary")) ]
            [ make_claim, Timestamp::from_str("2021-04-20T00:01:56Z").unwrap(), ClaimSpec::Email(MaybePrivate::new_public(String::from("dirk.delta@hollywood.com"))), None::<String> ]
        };
        let identity1_instance = branch1.build_identity_instance().unwrap();
        assert_eq!(identity1_instance.keychain().admin_keys().len(), 2);
        assert_eq!(identity1_instance.keychain().admin_keys()[0].key_id(), admin_key.key_id());
        assert_eq!(identity1_instance.keychain().admin_keys()[1].key_id(), admin_key_2.key_id());
        assert_eq!(identity1_instance.keychain().subkeys().len(), 0);
        assert_eq!(identity1_instance.claims().len(), 2);
        match identity1_instance.find_claim_by_name("primary").unwrap().spec() {
            ClaimSpec::Address(val) => {
                assert_eq!(val.open_public().unwrap().as_str(), "1112 Dirk Delta Ln.")
            }
            _ => panic!("wrong"),
        }

        let identity2_instance = branch2.build_identity_instance().unwrap();
        assert_eq!(identity2_instance.keychain().admin_keys()[1].key_id(), admin_key_3.key_id());
        assert_eq!(identity2_instance.keychain().admin_keys().len(), 2);
        assert_eq!(identity2_instance.claims().len(), 3);
        match identity2_instance.find_claim_by_name("primary").unwrap().spec() {
            ClaimSpec::Address(val) => {
                assert_eq!(val.open_public().unwrap().as_str(), "1112 Liberal Hokes ave.")
            }
            _ => panic!("wrong"),
        }
        let identity2 = Identity::merge(branch1.clone(), branch2.clone()).unwrap();
        assert_eq!(branch1.transactions().len(), 5);
        assert_eq!(branch2.transactions().len(), 5);
        assert_eq!(identity2.transactions().len(), 9);
        let identity3 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [ make_claim, Timestamp::from_str("2021-04-20T00:05:22Z").unwrap(), ClaimSpec::Url(MaybePrivate::new_public(Url::parse("https://www.ITSJUSTAFLU.com/logic-and-facts").unwrap())), None::<String> ]
        };
        assert_eq!(identity3.transactions().len(), 10);
        let identity3_instance = identity3.build_identity_instance().unwrap();
        match identity3_instance.find_claim_by_name("primary").unwrap().spec() {
            ClaimSpec::Address(val) => {
                assert_eq!(val.open_public().unwrap().as_str(), "1112 Liberal Hokes ave.")
            }
            _ => panic!("wrong"),
        }
        assert_eq!(identity3_instance.claims().len(), 6);
        assert_eq!(identity3_instance.keychain().admin_keys().len(), 3);
        assert_eq!(identity3_instance.keychain().admin_keys()[1].key_id(), admin_key_2.key_id());
        assert_eq!(identity3_instance.keychain().admin_keys()[2].key_id(), admin_key_3.key_id());
        assert_eq!(identity3_instance.keychain().subkeys().len(), 0);
    }

    #[test]
    fn identity_genesis() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity_instance = identity.build_identity_instance().unwrap();
        let policies = identity_instance.policies().iter().map(|x| x.policy().clone()).collect::<Vec<_>>();
        let res = identity.clone().push_transaction(
            identity
                .create_identity(&HashAlgo::Blake3, Timestamp::now(), identity_instance.keychain().admin_keys().clone(), policies)
                .unwrap()
                .sign(&master_key, &admin_key)
                .unwrap(),
        );
        assert_eq!(res.err(), Some(Error::DagCreateIdentityOnExistingChain));

        let identity2 = Identity::new();
        let res = identity2.clone().push_transaction(
            identity2
                .make_claim(
                    &HashAlgo::Blake3,
                    Timestamp::now(),
                    ClaimSpec::Name(MaybePrivate::new_public("Stinky Wizzleteets".into())),
                    None::<String>,
                )
                .unwrap()
                .sign(&master_key, &admin_key)
                .unwrap(),
        );
        assert_eq!(res.err(), Some(Error::DagMissingIdentity));
    }

    #[test]
    fn identity_create_identity() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity_instance = identity.build_identity_instance().unwrap();
        assert_eq!(identity_instance.id(), &IdentityID::from(identity.transactions()[0].id().clone()));
        assert_eq!(identity_instance.keychain().admin_keys().len(), 1);
        assert_eq!(identity_instance.policies().len(), 1);

        let res = identity.clone().push_transaction(
            identity
                .create_identity(&HashAlgo::Blake3, Timestamp::now(), vec![], vec![])
                .unwrap()
                .sign(&master_key, &admin_key)
                .unwrap(),
        );
        assert_eq!(res.err(), Some(Error::DagCreateIdentityOnExistingChain));
    }

    #[test]
    fn identity_reset_identity() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let admin_key2 = AdminKey::new(AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap(), "Alpha", None);
        let admin_key3 = AdminKey::new(AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap(), "Zing", None);
        let capability2 = Capability::Transaction {
            body_type: vec![TransactionBodyType::ResetIdentityV1],
            context: Context::Permissive,
        };
        let capability3 = Capability::Transaction {
            body_type: vec![TransactionBodyType::AcceptStampV1],
            context: Context::IdentityID(IdentityID::random()),
        };
        let policy2 = Policy::new(
            vec![capability2],
            MultisigPolicy::MOfN {
                must_have: 0,
                participants: vec![],
            },
        );
        let policy3 = Policy::new(
            vec![capability3],
            MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![],
            },
        );
        let identity1_instances = identity.build_identity_instance().unwrap();
        assert_eq!(identity1_instances.keychain().admin_keys().len(), 1);
        assert!(identity1_instances.keychain().admin_key_by_name("Alpha").is_some());
        assert_eq!(identity1_instances.policies().len(), 1);
        assert_eq!(
            identity1_instances.policies()[0].id(),
            &PolicyContainer::gen_id(identity.transactions()[0].id(), 0).unwrap()
        );
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ reset_identity, Timestamp::now(), Some(vec![admin_key2.clone(), admin_key3.clone()]), Some(vec![policy2.clone(), policy3.clone()]) ]
        };
        let identity2_instances = identity2.build_identity_instance().unwrap();
        assert_eq!(identity2_instances.keychain().admin_keys().len(), 2);
        assert_eq!(identity2_instances.keychain().admin_key_by_name("Alpha").unwrap().key(), admin_key2.key());
        assert!(identity2_instances.keychain().admin_key_by_name("Zing").is_some());
        assert_eq!(identity2_instances.policies().len(), 2);
        assert_eq!(
            identity2_instances.policies()[0].id(),
            &PolicyContainer::gen_id(identity2.transactions()[1].id(), 0).unwrap()
        );
        assert_eq!(
            identity2_instances.policies()[1].id(),
            &PolicyContainer::gen_id(identity2.transactions()[1].id(), 1).unwrap()
        );
    }

    #[test]
    fn identity_revoke_identity() {
        todo!("Revoked identities should bar any changes/updates");
    }

    #[test]
    fn identity_add_admin_key() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity1_instance = identity.build_identity_instance().unwrap();
        assert_eq!(identity1_instance.keychain().admin_keys().len(), 1);
        assert_eq!(
            identity1_instance
                .keychain()
                .admin_key_by_keyid(&admin_key.key_id())
                .map(|x| x.key()),
            Some(admin_key.key())
        );

        let admin_key2 = AdminKey::new(AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap(), "publish key lol", None);
        let identity2 = sign_and_push! { &master_key, &admin_key, identity.clone(),
            [ add_admin_key, Timestamp::now(), admin_key2.clone() ]
        };
        let identity2_instance = identity2.build_identity_instance().unwrap();
        assert_eq!(identity2_instance.keychain().admin_keys().len(), 2);
        assert_eq!(identity2_instance.keychain().admin_key_by_name("Alpha").map(|x| x.key()), Some(admin_key.key()));
        assert_eq!(
            identity2_instance.keychain().admin_key_by_name("publish key lol").map(|x| x.key()),
            Some(admin_key2.key())
        );

        let identity3 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [ add_admin_key, Timestamp::now(), admin_key2.clone() ]
        };
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert_eq!(identity3_instance.keychain().admin_keys().len(), 2);
        assert_eq!(identity3_instance.keychain().admin_key_by_name("Alpha").map(|x| x.key()), Some(admin_key.key()));
        assert_eq!(
            identity3_instance.keychain().admin_key_by_name("publish key lol").map(|x| x.key()),
            Some(admin_key2.key())
        );
    }

    #[test]
    fn identity_edit_admin_key() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity1_instance = identity.build_identity_instance().unwrap();
        assert_eq!(
            identity1_instance
                .keychain()
                .admin_key_by_keyid(&admin_key.key_id())
                .unwrap()
                .name(),
            "Alpha"
        );
        assert_eq!(
            identity1_instance
                .keychain()
                .admin_key_by_keyid(&admin_key.key_id())
                .unwrap()
                .description(),
            &None
        );

        let identity2 = sign_and_push! { &master_key, &admin_key, identity.clone(),
            [ edit_admin_key, Timestamp::now(), admin_key.key_id(), None, Some(Some("get a job")) ]
        };
        let identity2_instance = identity2.build_identity_instance().unwrap();
        assert_eq!(
            identity2_instance
                .keychain()
                .admin_key_by_keyid(&admin_key.key_id())
                .unwrap()
                .name(),
            "Alpha"
        );
        assert_eq!(
            identity2_instance
                .keychain()
                .admin_key_by_keyid(&admin_key.key_id())
                .unwrap()
                .description(),
            &Some("get a job".into())
        );

        let identity3 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [ edit_admin_key, Timestamp::now(), admin_key.key_id(), Some("Jerkface"), None ]
        };
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert_eq!(
            identity3_instance
                .keychain()
                .admin_key_by_keyid(&admin_key.key_id())
                .unwrap()
                .name(),
            "Jerkface"
        );
        assert_eq!(
            identity3_instance
                .keychain()
                .admin_key_by_keyid(&admin_key.key_id())
                .unwrap()
                .description(),
            &Some("get a job".into())
        );

        let identity4 = sign_and_push! { &master_key, &admin_key, identity3.clone(),
            [ edit_admin_key, Timestamp::now(), admin_key.key_id(), None::<String>, Some(None) ]
        };
        let identity4_instance = identity4.build_identity_instance().unwrap();
        assert_eq!(
            identity4_instance
                .keychain()
                .admin_key_by_keyid(&admin_key.key_id())
                .unwrap()
                .name(),
            "Jerkface"
        );
        assert_eq!(
            identity4_instance
                .keychain()
                .admin_key_by_keyid(&admin_key.key_id())
                .unwrap()
                .description(),
            &None
        );
    }

    #[test]
    fn identity_revoke_admin_key() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity1_instance = identity.build_identity_instance().unwrap();
        assert_eq!(identity1_instance.keychain().admin_keys().len(), 1);
        assert_eq!(identity1_instance.keychain().subkeys().len(), 0);
        assert_eq!(
            identity1_instance
                .keychain()
                .admin_key_by_keyid(&admin_key.key_id())
                .map(|x| x.key()),
            Some(admin_key.key())
        );
        assert_eq!(identity1_instance.keychain().admin_key_by_name("Alpha").unwrap().revocation(), &None);
        assert_eq!(identity1_instance.keychain().admin_key_by_name("Alpha").unwrap().name(), "Alpha");

        let key_id = identity1_instance.keychain().admin_key_by_name("Alpha").unwrap().key_id();

        let identity2 = sign_and_push! { &master_key, &admin_key, identity.clone(),
            [ revoke_admin_key, Timestamp::now(), admin_key.key_id(), RevocationReason::Compromised, Some("rotten") ]
        };
        let identity2_instance = identity2.build_identity_instance().unwrap();
        assert_eq!(identity2_instance.keychain().admin_keys().len(), 1);
        assert!(identity2_instance.keychain().admin_key_by_name("Alpha").is_none());
        assert_eq!(
            identity2_instance.keychain().admin_key_by_keyid(&key_id).unwrap().revocation(),
            &Some(RevocationReason::Compromised)
        );
        assert_eq!(identity2_instance.keychain().admin_key_by_keyid(&key_id).unwrap().name(), "rotten");
        assert_eq!(identity2_instance.keychain().subkeys().len(), 0);
        assert!(identity2_instance.keychain().subkey_by_name("Alpha").is_none());
        assert!(identity2_instance.keychain().subkey_by_name("rotten").is_none());
        assert!(identity2_instance.keychain().subkey_by_keyid(&key_id).is_none());

        let identity3 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [ revoke_admin_key, Timestamp::now(), admin_key.key_id(), RevocationReason::Compromised, Some("toast") ]
        };
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert_eq!(identity3_instance.keychain().admin_keys().len(), 1);
        assert!(identity3_instance.keychain().admin_key_by_name("Alpha").is_none());
        assert_eq!(
            identity3_instance.keychain().admin_key_by_keyid(&key_id).unwrap().revocation(),
            &Some(RevocationReason::Compromised)
        );
        assert_eq!(identity3_instance.keychain().admin_key_by_keyid(&key_id).unwrap().name(), "toast");
        assert_eq!(identity3_instance.keychain().subkeys().len(), 0);
        assert!(identity3_instance.keychain().subkey_by_name("Alpha").is_none());
        assert!(identity3_instance.keychain().subkey_by_name("rotten").is_none());
        assert!(identity3_instance.keychain().subkey_by_keyid(&key_id).is_none());
    }

    #[test]
    fn identity_add_policy() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let capability2 = Capability::Transaction {
            body_type: vec![TransactionBodyType::ResetIdentityV1],
            context: Context::Permissive,
        };
        let policy2 = Policy::new(
            vec![capability2],
            MultisigPolicy::MOfN {
                must_have: 0,
                participants: vec![],
            },
        );

        let identity1_instance = identity.build_identity_instance().unwrap();
        assert_eq!(identity1_instance.policies().len(), 1);
        assert_eq!(
            identity1_instance.policies()[0].id(),
            &PolicyContainer::gen_id(identity.transactions()[0].id(), 0).unwrap()
        );

        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ add_policy, Timestamp::now(), policy2.clone() ]
        };
        let identity2_instance = identity2.build_identity_instance().unwrap();
        assert_eq!(identity2_instance.policies().len(), 2);
        assert_eq!(
            identity2_instance.policies()[0].id(),
            &PolicyContainer::gen_id(identity2.transactions()[0].id(), 0).unwrap()
        );
        assert_eq!(
            identity2_instance.policies()[1].id(),
            &PolicyContainer::gen_id(identity2.transactions()[1].id(), 0).unwrap()
        );

        let identity3 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [ add_policy, Timestamp::now(), policy2.clone() ]
        };
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert_eq!(identity3_instance.policies().len(), 3);
        assert_eq!(
            identity3_instance.policies()[0].id(),
            &PolicyContainer::gen_id(identity3.transactions()[0].id(), 0).unwrap()
        );
        assert_eq!(
            identity3_instance.policies()[1].id(),
            &PolicyContainer::gen_id(identity3.transactions()[1].id(), 0).unwrap()
        );
        assert_eq!(
            identity3_instance.policies()[2].id(),
            &PolicyContainer::gen_id(identity3.transactions()[2].id(), 0).unwrap()
        );
    }

    #[test]
    fn identity_delete_policy() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity_instance = identity.build_identity_instance().unwrap();
        let policy_id = identity_instance.policies()[0].id().clone();
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ delete_policy, Timestamp::now(), policy_id.clone() ]
        };
        let identity2_instance = identity2.build_identity_instance().unwrap();
        assert_eq!(identity2_instance.policies().len(), 0);

        let res = identity2.clone().push_transaction(
            identity2
                .delete_policy(&HashAlgo::Blake3, Timestamp::now(), policy_id.clone())
                .unwrap()
                .sign(&master_key, &admin_key)
                .unwrap(),
        );
        assert_eq!(res.err(), Some(Error::PolicyNotFound));
    }

    #[test]
    fn identity_make_claim() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());

        macro_rules! make_specs {
            ($rng:expr, $master:expr, $claimmaker:expr, $val:expr) => {{
                let val = $val.clone();
                let maybe_private = MaybePrivate::new_private_verifiable($rng, &$master, val.clone()).unwrap();
                let maybe_public = MaybePrivate::new_public(val.clone());
                let spec_private = $claimmaker(maybe_private, val.clone());
                let spec_public = $claimmaker(maybe_public, val.clone());
                (spec_private, spec_public)
            }};
        }

        macro_rules! assert_claim {
            (raw, $claimmaker:expr, $val:expr, $get_maybe:expr) => {
                let mut rng = crate::util::test::rng();
                let val = $val;
                let (spec_private, spec_public) = make_specs!(&mut rng, master_key, $claimmaker, val);

                let identity2 = sign_and_push! { &master_key, &admin_key, identity.clone(),
                    [ make_claim, Timestamp::now(), spec_private, None::<String> ]
                };
                let identity2_instance = identity2.build_identity_instance().unwrap();
                let maybe = $get_maybe(identity2_instance.claims()[0].spec().clone());
                assert_eq!(maybe.open(&master_key).unwrap(), val);
                assert_eq!(identity2_instance.claims().len(), 1);
                assert_eq!(identity2.transactions().len(), 2);

                let identity2 = sign_and_push! { &master_key, &admin_key, identity.clone(),
                    [ make_claim, Timestamp::now(), spec_public, None::<String> ]
                };
                let identity2_instance = identity2.build_identity_instance().unwrap();
                let maybe = $get_maybe(identity2_instance.claims()[0].spec().clone());
                assert_eq!(maybe.open(&master_key).unwrap(), val);
                assert_eq!(identity2_instance.claims().len(), 1);
                assert_eq!(identity2.transactions().len(), 2);
            };

            ($claimty:ident, $val:expr) => {
                assert_claim! {
                    raw,
                    |maybe, _| ClaimSpec::<Full>::$claimty(maybe),
                    $val,
                    |spec: ClaimSpec<Full>| if let ClaimSpec::$claimty(maybe) = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimty)) }
                }
            };
        }

        let identity_instance = identity.build_identity_instance().unwrap();
        assert_eq!(identity_instance.claims().len(), 0);
        assert_eq!(identity.transactions().len(), 1);

        assert_claim! { Identity, identity_instance.id().clone() }
        assert_claim! { Name, String::from("Marty Malt") }
        assert_claim! { Birthday, Date::from_str("2010-01-03").unwrap() }
        assert_claim! { Email, String::from("marty@sids.com") }
        assert_claim! { Photo, BinaryVec::from(vec![1, 2, 3]) }
        assert_claim! { Pgp, String::from("12345") }
        assert_claim! { Domain, String::from("slappy.com") }
        assert_claim! { Url, Url::parse("https://killtheradio.net/").unwrap() }
        assert_claim! { Address, String::from("111 blumps ln") }
        assert_claim! { Relation, Relationship::new(RelationshipType::OrganizationMember, IdentityID::random()) }
        assert_claim! { RelationExtension, Relationship::new(RelationshipType::OrganizationMember, BinaryVec::from(vec![1, 2, 3, 4, 5])) }
        assert_claim! {
            raw,
            |maybe, _| ClaimSpec::<Full>::Extension { key: Vec::from("id:state:ca".as_bytes()).into(), value: maybe },
            BinaryVec::from(vec![7, 3, 2, 90]),
            |spec: ClaimSpec<Full>| if let ClaimSpec::<Full>::Extension { value: maybe, .. } = spec { maybe } else { panic!("bad claim type: {}", stringify!($claimtype)) }
        }
    }

    #[test]
    fn identity_edit_claim() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity2 = sign_and_push! { &master_key, &admin_key, identity.clone(),
            [ make_claim, Timestamp::now(), ClaimSpec::Url(MaybePrivate::new_public(Url::parse("https://www.cactus-petes.com/yeeeehawwww").unwrap())), Some("OpenID") ]
        };
        let identity2_instance = identity2.build_identity_instance().unwrap();
        assert_eq!(identity2_instance.claims().len(), 1);
        assert_eq!(identity2_instance.claims()[0].name(), &Some("OpenID".into()));

        let identity3 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [ edit_claim, Timestamp::now(), identity2_instance.claims()[0].id().clone(), None::<String> ]
        };
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert_eq!(identity3_instance.claims().len(), 1);
        assert_eq!(identity3_instance.claims()[0].name(), &None);
    }

    #[test]
    fn identity_delete_claim() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity_instance = identity.build_identity_instance().unwrap();
        assert_eq!(identity_instance.claims().len(), 0);
        assert_eq!(identity.transactions().len(), 1);

        let identity_id = IdentityID::from(identity.transactions()[0].id().clone());
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ make_claim, Timestamp::now(), ClaimSpec::Identity(MaybePrivate::new_public(identity_id)), None::<String> ]
        };
        assert_eq!(identity2.transactions().len(), 2);

        let identity_instance = identity2.build_identity_instance().unwrap();
        let claim_id = identity_instance.claims()[0].id().clone();
        let identity3 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [delete_claim, Timestamp::now(), claim_id.clone()]
        };
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert_eq!(identity3_instance.claims().len(), 0);

        let identity4 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [ delete_claim, Timestamp::now(), ClaimID::random() ]
        };
        let identity4_instance = identity4.build_identity_instance().unwrap();
        assert_eq!(identity4_instance.claims().len(), 1);

        let identity5 = sign_and_push! { &master_key, &admin_key, identity3.clone(),
            [ delete_claim, Timestamp::now(), claim_id.clone() ]
        };
        let identity5_instance = identity5.build_identity_instance().unwrap();
        assert_eq!(identity5_instance.claims().len(), 0);
    }

    #[test]
    fn identity_make_stamp() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity_id = IdentityID::from(identity.transactions()[0].id().clone());
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ make_claim, Timestamp::now(), ClaimSpec::Identity(MaybePrivate::new_public(identity_id)), None::<String> ]
        };
        let identity_instance = identity2.build_identity_instance().unwrap();
        let claim = identity_instance.claims()[0].clone();

        let (master_key_stamper, identity_stamper, admin_key_stamper) = test::create_fake_identity(&mut rng, Timestamp::now());

        let identity_stamper1 = identity_stamper.build_identity_instance().unwrap();
        assert_eq!(identity_stamper1.stamps().len(), 0);

        let entry = StampEntry::new(
            IdentityID::from(identity_stamper.transactions()[0].id().clone()),
            identity_instance.id().clone(),
            claim.id().clone(),
            Confidence::Low,
            Some(Timestamp::from_str("2060-01-01T06:59:00Z").unwrap()),
        );

        let make_stamp_trans = identity_stamper
            .make_stamp(&HashAlgo::Blake3, Timestamp::now(), entry)
            .unwrap()
            .sign(&master_key_stamper, &admin_key_stamper)
            .unwrap();
        let identity_stamper2 = identity_stamper.push_transaction(make_stamp_trans.clone()).unwrap();
        let identity_stamper2_instance = identity_stamper2.build_identity_instance().unwrap();
        assert_eq!(identity_stamper2_instance.stamps().len(), 1);
        assert_eq!(identity_stamper2_instance.stamps()[0].revocation(), &None);
    }

    #[test]
    fn identity_revoke_stamp() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity_id = IdentityID::from(identity.transactions()[0].id().clone());
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ make_claim, Timestamp::now(), ClaimSpec::Identity(MaybePrivate::new_public(identity_id)), None::<String> ]
        };

        let (master_key_stamper, identity_stamper, admin_key_stamper) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity_stamper1_instance = identity_stamper.build_identity_instance().unwrap();
        assert_eq!(identity_stamper1_instance.stamps().len(), 0);

        let identity_stampee2_instance = identity2.build_identity_instance().unwrap();
        let claim = identity_stampee2_instance.claims()[0].clone();
        let entry = StampEntry::new(
            IdentityID::from(identity_stamper.transactions()[0].id().clone()),
            identity_stampee2_instance.id().clone(),
            claim.id().clone(),
            Confidence::Low,
            Some(Timestamp::from_str("2060-01-01T06:59:00Z").unwrap()),
        );

        let make_stamp_trans = identity_stamper
            .make_stamp(&HashAlgo::Blake3, Timestamp::now(), entry)
            .unwrap()
            .sign(&master_key_stamper, &admin_key_stamper)
            .unwrap();
        let identity_stamper2 = identity_stamper.push_transaction(make_stamp_trans.clone()).unwrap();
        let identity_stamper2_instance = identity_stamper2.build_identity_instance().unwrap();
        assert_eq!(identity_stamper2_instance.stamps().len(), 1);
        assert_eq!(identity_stamper2_instance.stamps()[0].revocation(), &None);

        let stamp_id = identity_stamper2_instance.stamps()[0].id();
        let revoke_trans = identity_stamper2
            .revoke_stamp(&HashAlgo::Blake3, Timestamp::now(), stamp_id.clone(), StampRevocationReason::Compromised)
            .unwrap()
            .sign(&master_key_stamper, &admin_key_stamper)
            .unwrap();
        let identity_stamper3 = identity_stamper2.clone().push_transaction(revoke_trans.clone()).unwrap();
        let identity_stamper3_instance = identity_stamper3.build_identity_instance().unwrap();
        assert_eq!(identity_stamper3_instance.stamps().len(), 1);
        assert_eq!(
            identity_stamper3_instance.stamps()[0].revocation().as_ref().unwrap(),
            &StampRevocationReason::Compromised
        );

        // same revocation, different id, should work fine
        let identity_stamper4 = sign_and_push! { &master_key_stamper, &admin_key_stamper, identity_stamper3.clone(),
            [ revoke_stamp, Timestamp::now(), stamp_id.clone(), StampRevocationReason::Unspecified ]
        };
        let identity_stamper4_instance = identity_stamper4.build_identity_instance().unwrap();
        // should use the reason from the most recent transaction
        assert_eq!(
            identity_stamper4_instance.stamps()[0].revocation().as_ref().unwrap(),
            &StampRevocationReason::Unspecified
        );
    }

    #[test]
    fn identity_accept_stamp() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity_id = IdentityID::from(identity.transactions()[0].id().clone());
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ make_claim, Timestamp::now(), ClaimSpec::Identity(MaybePrivate::new_public(identity_id)), None::<String> ]
        };
        let identity_instance = identity2.build_identity_instance().unwrap();
        assert_eq!(identity_instance.claims()[0].stamps().len(), 0);
        let claim = identity_instance.claims()[0].clone();

        let (master_key_stamper, identity_stamper, admin_key_stamper) = test::create_fake_identity(&mut rng, Timestamp::now());
        let entry = StampEntry::new(
            IdentityID::from(identity_stamper.transactions()[0].id().clone()),
            identity_instance.id().clone(),
            claim.id().clone(),
            Confidence::Low,
            Some(Timestamp::from_str("2060-01-01T06:59:00Z").unwrap()),
        );
        let stamp_transaction_unsigned = identity_stamper.make_stamp(&HashAlgo::Blake3, Timestamp::now(), entry).unwrap();
        let stamp_transaction = stamp_transaction_unsigned
            .clone()
            .sign(&master_key_stamper, &admin_key_stamper)
            .unwrap();
        let not_stamp_transaction = identity_stamper
            .make_claim(
                &HashAlgo::Blake3,
                Timestamp::now(),
                ClaimSpec::Name(MaybePrivate::new_public("Butch".into())),
                None::<String>,
            )
            .unwrap()
            .sign(&master_key_stamper, &admin_key_stamper)
            .unwrap();

        let identity3 = sign_and_push! { &master_key, &admin_key, identity2,
            [ accept_stamp, Timestamp::now(), stamp_transaction.clone().try_into().unwrap() ]
        };
        assert_eq!(identity3.transactions().len(), 3);
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert_eq!(identity3_instance.claims()[0].stamps().len(), 1);

        let res = identity3.clone().push_transaction(
            identity3
                .accept_stamp(&HashAlgo::Blake3, Timestamp::now(), stamp_transaction_unsigned.clone().try_into().unwrap())
                .unwrap()
                .sign(&master_key, &admin_key)
                .unwrap(),
        );
        assert_eq!(res.err(), Some(Error::TransactionNoSignatures));

        let res: Result<StampTransaction> = not_stamp_transaction.clone().try_into();
        assert_eq!(res.err(), Some(Error::TransactionMismatch));

        let res = identity3.clone().push_transaction(
            identity3
                .accept_stamp(&HashAlgo::Blake3, Timestamp::now(), stamp_transaction.clone().try_into().unwrap())
                .unwrap()
                .sign(&master_key, &admin_key)
                .unwrap(),
        );
        assert_eq!(res.err(), None);

        let identity4 = sign_and_push! { &master_key, &admin_key, identity3.clone(),
            [ delete_claim, Timestamp::now(), claim.id().clone() ]
        };
        let res = identity4.clone().push_transaction(
            identity4
                .accept_stamp(&HashAlgo::Blake3, Timestamp::now(), stamp_transaction.clone().try_into().unwrap())
                .unwrap()
                .sign(&master_key, &admin_key)
                .unwrap(),
        );
        assert_eq!(res.err(), Some(Error::IdentityClaimNotFound));
    }

    #[test]
    fn identity_delete_stamp() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity_id = IdentityID::from(identity.transactions()[0].id().clone());
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ make_claim, Timestamp::now(), ClaimSpec::Identity(MaybePrivate::new_public(identity_id)), None::<String> ]
        };
        let identity_instance = identity2.build_identity_instance().unwrap();
        assert_eq!(identity_instance.claims()[0].stamps().len(), 0);
        let claim = identity_instance.claims()[0].clone();

        let (master_key_stamper, identity_stamper, admin_key_stamper) = test::create_fake_identity(&mut rng, Timestamp::now());
        let entry = StampEntry::new(
            IdentityID::from(identity_stamper.transactions()[0].id().clone()),
            identity_instance.id().clone(),
            claim.id().clone(),
            Confidence::Low,
            Some(Timestamp::from_str("2060-01-01T06:59:00Z").unwrap()),
        );
        let stamp_transaction = identity_stamper
            .make_stamp(&HashAlgo::Blake3, Timestamp::now(), entry)
            .unwrap()
            .sign(&master_key_stamper, &admin_key_stamper)
            .unwrap();

        let identity3 = sign_and_push! { &master_key, &admin_key, identity2,
            [ accept_stamp, Timestamp::now(), stamp_transaction.clone().try_into().unwrap() ]
        };
        assert_eq!(identity3.transactions().len(), 3);
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert_eq!(identity3_instance.claims()[0].stamps().len(), 1);

        let identity4 = sign_and_push! { &master_key, &admin_key, identity3.clone(),
            [ delete_stamp, Timestamp::now(), StampID::from(stamp_transaction.id().clone()) ]
        };
        let identity4_instance = identity4.build_identity_instance().unwrap();
        assert_eq!(identity4_instance.claims()[0].stamps().len(), 0);

        let res = identity4.clone().push_transaction(
            identity4
                .delete_stamp(&HashAlgo::Blake3, Timestamp::now(), StampID::from(stamp_transaction.id().clone()))
                .unwrap()
                .sign(&master_key, &admin_key)
                .unwrap(),
        );
        assert_eq!(res.err(), Some(Error::IdentityStampNotFound));
    }

    #[test]
    fn identity_add_subkey() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity_instance = identity.build_identity_instance().unwrap();
        assert_eq!(identity_instance.keychain().subkeys().len(), 0);

        let sign_keypair = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();
        let sk_tmp = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let secret_key = PrivateWithHmac::seal(&mut rng, &master_key, sk_tmp).unwrap();
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair.clone()), "default:sign", Some("The key I use to sign things") ]
            [ add_subkey, Timestamp::now(), Key::new_crypto(crypto_keypair.clone()), "default:crypto", Some("Use this to send me emails") ]
            [ add_subkey, Timestamp::now(), Key::new_secret(secret_key.clone()), "default:secret", Some("Encrypt/decrypt things locally with this key") ]
        };
        let identity2_instance = identity2.build_identity_instance().unwrap();
        assert_eq!(identity2_instance.keychain().subkeys()[0].name(), "default:sign");
        assert_eq!(identity2_instance.keychain().subkeys()[1].name(), "default:crypto");
        assert_eq!(identity2_instance.keychain().subkeys()[2].name(), "default:secret");
        assert_eq!(identity2_instance.keychain().subkeys().len(), 3);

        let identity3 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair.clone()), "get a job", None ]
        };
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert_eq!(identity3_instance.keychain().subkeys()[0].name(), "default:sign");
        assert_eq!(identity3_instance.keychain().subkeys()[1].name(), "default:crypto");
        assert_eq!(identity3_instance.keychain().subkeys()[2].name(), "default:secret");
        assert_eq!(identity3_instance.keychain().subkeys().len(), 3);
        assert!(identity3_instance.keychain().subkey_by_name("get a job").is_none());
    }

    #[test]
    fn identity_edit_subkey() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());

        let sign_keypair = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();
        let sk_tmp = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let secret_key = PrivateWithHmac::seal(&mut rng, &master_key, sk_tmp).unwrap();
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things") ]
            [ add_subkey, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails") ]
            [ add_subkey, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key") ]
        };

        let identity2_instance = identity2.build_identity_instance().unwrap();
        assert_eq!(identity2_instance.keychain().subkeys().len(), 3);

        let identity3 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [ edit_subkey, Timestamp::now(), identity2_instance.keychain().subkey_by_name("default:crypto").unwrap().key_id(), Some("default:MYLITTLEPONY"), Some(Some("Tonga")) ]
            [ edit_subkey, Timestamp::now(), identity2_instance.keychain().subkey_by_name("default:secret").unwrap().key_id(), Some("default:secret"), None ]
        };
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert_eq!(identity3_instance.keychain().subkeys().len(), 3);
        assert!(identity3_instance.keychain().subkey_by_name("default:sign").is_some());
        assert!(identity3_instance.keychain().subkey_by_name("default:MYLITTLEPONY").is_some());
        assert!(identity3_instance.keychain().subkey_by_name("default:crypto").is_none());
        assert_eq!(
            identity3_instance
                .keychain()
                .subkey_by_name("default:MYLITTLEPONY")
                .unwrap()
                .description(),
            &Some("Tonga".into())
        );
        assert_eq!(
            identity3_instance
                .keychain()
                .subkey_by_name("default:secret")
                .unwrap()
                .description(),
            &Some("Encrypt/decrypt things locally with this key".into())
        );

        let randkey = KeyID::random_secret();
        let res = identity3.clone().push_transaction(
            identity3
                .edit_subkey(
                    &HashAlgo::Blake3,
                    Timestamp::now(),
                    randkey.clone(),
                    Some("you want a push i'll show you a push"),
                    None,
                )
                .unwrap()
                .sign(&master_key, &admin_key)
                .unwrap(),
        );
        assert_eq!(res.err(), Some(Error::KeychainKeyNotFound(randkey.clone())));
    }

    #[test]
    fn identity_revoke_subkey() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());

        let sign_keypair = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();
        let sk_tmp = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let secret_key = PrivateWithHmac::seal(&mut rng, &master_key, sk_tmp).unwrap();
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things") ]
            [ add_subkey, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails") ]
            [ add_subkey, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key") ]
        };
        let identity2_instance = identity2.build_identity_instance().unwrap();
        let identity3 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [ revoke_subkey, Timestamp::now(), identity2_instance.keychain().subkey_by_name("default:crypto").unwrap().key_id(), RevocationReason::Superseded, Some("revoked:default:crypto") ]
        };
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert!(identity3_instance.keychain().subkeys()[0].revocation().is_none());
        assert_eq!(
            identity3_instance.keychain().subkeys()[1].revocation().as_ref(),
            Some(&RevocationReason::Superseded)
        );
        assert_eq!(identity3_instance.keychain().subkeys()[1].name(), "revoked:default:crypto");
        assert!(identity3_instance.keychain().subkeys()[2].revocation().is_none());

        let identity4 = sign_and_push! { &master_key, &admin_key, identity3.clone(),
            [ revoke_subkey, Timestamp::now(), identity2_instance.keychain().subkey_by_name("default:crypto").unwrap().key_id(), RevocationReason::Unspecified, Some("zingg") ]
        };
        let identity4_instance = identity4.build_identity_instance().unwrap();
        assert!(identity4_instance.keychain().subkeys()[0].revocation().is_none());
        assert_eq!(
            identity4_instance.keychain().subkeys()[1].revocation().as_ref(),
            Some(&RevocationReason::Superseded)
        );
        assert_eq!(identity4_instance.keychain().subkeys()[1].name(), "revoked:default:crypto");
        assert!(identity4_instance.keychain().subkeys()[2].revocation().is_none());
    }

    #[test]
    fn identity_delete_subkey() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());

        let sign_keypair = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();
        let sk_tmp = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let secret_key = PrivateWithHmac::seal(&mut rng, &master_key, sk_tmp).unwrap();
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ add_subkey, Timestamp::now(), Key::new_sign(sign_keypair), "default:sign", Some("The key I use to sign things") ]
            [ add_subkey, Timestamp::now(), Key::new_crypto(crypto_keypair), "default:crypto", Some("Use this to send me emails") ]
            [ add_subkey, Timestamp::now(), Key::new_secret(secret_key), "default:secret", Some("Encrypt/decrypt things locally with this key") ]
        };
        let identity2_instance = identity2.build_identity_instance().unwrap();
        let sign_id = identity2_instance.keychain().subkey_by_name("default:sign").unwrap().key_id();

        let identity3 = sign_and_push! { &master_key, &admin_key, identity2.clone(),
            [ delete_subkey, Timestamp::now(), sign_id.clone() ]
        };
        let identity3_instance = identity3.build_identity_instance().unwrap();
        assert_eq!(identity3_instance.keychain().subkeys()[0].name(), "default:crypto");
        assert_eq!(identity3_instance.keychain().subkeys()[1].name(), "default:secret");
        assert_eq!(identity3_instance.keychain().subkeys().len(), 2);

        let identity4 = sign_and_push! { &master_key, &admin_key, identity3.clone(),
            [ delete_subkey, Timestamp::now(), sign_id.clone() ]
        };
        let identity4_instance = identity4.build_identity_instance().unwrap();
        assert_eq!(identity4_instance.keychain().subkeys()[0].name(), "default:crypto");
        assert_eq!(identity4_instance.keychain().subkeys()[1].name(), "default:secret");
        assert_eq!(identity4_instance.keychain().subkeys().len(), 2);
    }

    #[test]
    fn identity_publish() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let identity2 = sign_and_push! { &master_key, &admin_key, identity,
            [ make_claim, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public("Miner 49er".into())), None::<String> ]
            [ make_claim, Timestamp::now(), ClaimSpec::Email(MaybePrivate::new_public("miner@49ers.net".into())), Some(String::from("primary")) ]
        };
        let published = identity2
            .publish(&HashAlgo::Blake3, Timestamp::now())
            .unwrap()
            .sign(&master_key, &admin_key)
            .unwrap();
        match published.entry().body() {
            TransactionBody::PublishV1 {
                identity: published_identity,
            } => {
                assert_eq!(published_identity.transactions().len(), 3);
                assert_eq!(published_identity.transactions()[0].id(), identity2.transactions()[0].id());
                assert_eq!(published_identity.transactions()[1].id(), identity2.transactions()[1].id());
                assert_eq!(published_identity.transactions()[2].id(), identity2.transactions()[2].id());
            }
            _ => panic!("Unexpected transaction: {published:?}"),
        }

        let identity_instance = identity2.build_identity_instance().unwrap();
        published.authorize(Some(&identity_instance)).unwrap();

        let mut published2 = published.clone();
        match published2.entry_mut().body_mut() {
            TransactionBody::PublishV1 {
                identity: ref mut published_identity2,
            } => {
                published_identity2
                    .transactions_mut()
                    .retain(|x| x.id() != identity2.transactions()[1].id());
                assert_eq!(published_identity2.transactions().len(), 2);
            }
            _ => panic!("Unexpected transaction: {published2:?}"),
        }

        assert!(matches!(
            published2.authorize(Some(&identity_instance)).unwrap_err(),
            Error::TransactionIDMismatch(..)
        ));
    }

    #[test]
    fn identity_sign() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let sig = identity
            .sign(&HashAlgo::Blake3, Timestamp::now(), &HashAlgo::Blake3, Vec::from(b"get a job").as_slice())
            .unwrap()
            .sign(&master_key, &admin_key)
            .unwrap();
        let identity = identity.build_identity_instance().unwrap();
        sig.authorize(Some(&identity)).unwrap();

        let identity_blank = Identity::new();
        let blank_res = identity_blank.sign(&HashAlgo::Blake3, Timestamp::now(), &HashAlgo::Blake3, Vec::from("get a job").as_slice());
        assert!(matches!(blank_res, Err(Error::DagEmpty)));

        let mut sig_mod = sig.clone();
        match sig_mod.entry_mut().body_mut() {
            TransactionBody::SignV1 {
                creator: _creator,
                ref mut body_hash,
            } => {
                *body_hash = Hash::new_blake3(b"hold on...").unwrap();
            }
            _ => panic!("Unexpected transaction: {sig_mod:?}"),
        }
        assert!(matches!(sig_mod.authorize(Some(&identity)).unwrap_err(), Error::TransactionIDMismatch(..)));
    }

    #[test]
    fn identity_ext() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let ext = identity
            .ext(
                &HashAlgo::Blake3,
                Timestamp::now(),
                vec![],
                None,
                Some([("type", "payment")]),
                BinaryVec::from(Vec::from("SEND $5 TO SALLY".as_bytes())),
            )
            .unwrap()
            .sign(&master_key, &admin_key)
            .unwrap();
        let identity = identity.build_identity_instance().unwrap();
        ext.authorize(Some(&identity)).unwrap();

        let identity_blank = Identity::new();
        let blank_res = identity_blank.sign(&HashAlgo::Blake3, Timestamp::now(), &HashAlgo::Blake3, Vec::from(b"get a job").as_slice());
        assert!(matches!(blank_res, Err(Error::DagEmpty)));

        let mut ext_mod = ext.clone();
        match ext_mod.entry_mut().body_mut() {
            TransactionBody::ExtV1(ref mut ext) => {
                ext.set_payload(BinaryVec::from(Vec::from("SEND $6 TO SALLY".as_bytes())));
            }
            _ => panic!("Unexpected transaction: {ext_mod:?}"),
        }
        assert!(matches!(ext_mod.authorize(Some(&identity)).unwrap_err(), Error::TransactionIDMismatch(..)));
    }

    #[test]
    fn identity_push_invalid_sig() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let mut claim_trans = identity
            .make_claim(
                &HashAlgo::Blake3,
                Timestamp::now(),
                ClaimSpec::Name(MaybePrivate::new_public("Mr. Larry Johnson".into())),
                None::<String>,
            )
            .unwrap();
        let sig = admin_key.key().sign(&master_key, b"haha lol").unwrap();
        let policy_sig = MultisigPolicySignature::Key {
            key: admin_key.key().clone().into(),
            signature: sig,
        };
        claim_trans.signatures_mut().push(policy_sig);
        let res = identity.clone().push_transaction(claim_trans);
        assert!(matches!(res.err(), Some(Error::TransactionSignatureInvalid(_, _))));
    }

    #[test]
    fn identity_policy_multisig_verify() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let admin_key1 = AdminKey::new(AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap(), "Frank", None);
        let admin_key2 = AdminKey::new(AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap(), "Gina", None);
        let admin_key3 = AdminKey::new(AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap(), "Ralph", None);
        let admin_key4 = AdminKey::new(AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap(), "Simon", None);

        let cap1 = vec![
            Capability::Transaction {
                body_type: vec![TransactionBodyType::MakeClaimV1],
                context: Context::Permissive,
            },
            Capability::Transaction {
                body_type: vec![TransactionBodyType::AddSubkeyV1],
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

        let cap2 = vec![Capability::Transaction {
            body_type: vec![TransactionBodyType::PublishV1],
            context: Context::Permissive,
        }];
        let multisig2 = MultisigPolicy::All(vec![
            MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![admin_key4.key().clone().into()],
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

        let identity2 = sign_and_push! { &master_key, &admin_key, identity.clone(),
            [ add_policy, Timestamp::now(), policy1 ]
            [ add_policy, Timestamp::now(), policy2 ]
        };

        let trans1 = identity2
            .make_claim(
                &HashAlgo::Blake3,
                Timestamp::now(),
                ClaimSpec::Name(MaybePrivate::new_public("Larry".into())),
                None::<String>,
            )
            .unwrap();
        assert_eq!(identity2.clone().push_transaction(trans1.clone()).err(), Some(Error::TransactionNoSignatures));
        assert_eq!(
            identity2
                .clone()
                .push_transaction(trans1.clone().sign(&master_key, &admin_key1).unwrap())
                .err(),
            Some(Error::PolicyNotFound)
        );
        identity2
            .clone()
            .push_transaction(
                trans1
                    .clone()
                    .sign(&master_key, &admin_key1)
                    .unwrap()
                    .sign(&master_key, &admin_key2)
                    .unwrap(),
            )
            .unwrap();
        identity2
            .clone()
            .push_transaction(
                trans1
                    .clone()
                    .sign(&master_key, &admin_key2)
                    .unwrap()
                    .sign(&master_key, &admin_key3)
                    .unwrap(),
            )
            .unwrap();
        identity2
            .clone()
            .push_transaction(
                trans1
                    .clone()
                    .sign(&master_key, &admin_key2)
                    .unwrap()
                    .sign(&master_key, &admin_key1)
                    .unwrap(),
            )
            .unwrap();
        identity2
            .clone()
            .push_transaction(
                trans1
                    .clone()
                    .sign(&master_key, &admin_key1)
                    .unwrap()
                    .sign(&master_key, &admin_key2)
                    .unwrap()
                    .sign(&master_key, &admin_key3)
                    .unwrap(),
            )
            .unwrap();

        let subkey = Key::new_sign(SignKeypair::new_ed25519(&mut rng, &master_key).unwrap());
        let trans2 = identity2
            .add_subkey(&HashAlgo::Blake3, Timestamp::now(), subkey.clone(), "logins/websites/booots.com", None)
            .unwrap();
        assert_eq!(
            identity2
                .clone()
                .push_transaction(trans2.clone().sign(&master_key, &admin_key1).unwrap())
                .err(),
            Some(Error::PolicyNotFound)
        );
        assert_eq!(
            identity2
                .clone()
                .push_transaction(
                    trans2
                        .clone()
                        .sign(&master_key, &admin_key1)
                        .unwrap()
                        .sign(&master_key, &admin_key2)
                        .unwrap()
                        .sign(&master_key, &admin_key3)
                        .unwrap()
                )
                .err(),
            Some(Error::PolicyNotFound)
        );

        let trans3 = identity2
            .add_subkey(&HashAlgo::Blake3, Timestamp::now(), subkey.clone(), "logins/websites/beeets.com", None)
            .unwrap();
        assert_eq!(
            identity2
                .clone()
                .push_transaction(trans3.clone().sign(&master_key, &admin_key1).unwrap())
                .err(),
            Some(Error::PolicyNotFound)
        );
        identity2
            .clone()
            .push_transaction(
                trans3
                    .clone()
                    .sign(&master_key, &admin_key1)
                    .unwrap()
                    .sign(&master_key, &admin_key2)
                    .unwrap(),
            )
            .unwrap();
        identity2
            .clone()
            .push_transaction(
                trans3
                    .clone()
                    .sign(&master_key, &admin_key3)
                    .unwrap()
                    .sign(&master_key, &admin_key2)
                    .unwrap(),
            )
            .unwrap();
        identity2
            .clone()
            .push_transaction(
                trans3
                    .clone()
                    .sign(&master_key, &admin_key1)
                    .unwrap()
                    .sign(&master_key, &admin_key3)
                    .unwrap(),
            )
            .unwrap();
        identity2
            .clone()
            .push_transaction(
                trans3
                    .clone()
                    .sign(&master_key, &admin_key1)
                    .unwrap()
                    .sign(&master_key, &admin_key2)
                    .unwrap()
                    .sign(&master_key, &admin_key3)
                    .unwrap(),
            )
            .unwrap();

        let trans4 = identity2.publish(&HashAlgo::Blake3, Timestamp::now()).unwrap();
        let identity2_instance = identity2.build_identity_instance().unwrap();
        assert_eq!(
            trans4
                .clone()
                .sign(&master_key, &admin_key1)
                .unwrap()
                .authorize(Some(&identity2_instance))
                .err(),
            Some(Error::PolicyNotFound)
        );
        assert_eq!(
            trans4
                .clone()
                .sign(&master_key, &admin_key1)
                .unwrap()
                .sign(&master_key, &admin_key2)
                .unwrap()
                .authorize(Some(&identity2_instance))
                .err(),
            Some(Error::PolicyNotFound)
        );
        assert_eq!(
            trans4
                .clone()
                .sign(&master_key, &admin_key1)
                .unwrap()
                .sign(&master_key, &admin_key2)
                .unwrap()
                .sign(&master_key, &admin_key3)
                .unwrap()
                .authorize(Some(&identity2_instance))
                .err(),
            Some(Error::PolicyNotFound)
        );
        assert_eq!(
            trans4
                .clone()
                .sign(&master_key, &admin_key4)
                .unwrap()
                .sign(&master_key, &admin_key3)
                .unwrap()
                .authorize(Some(&identity2_instance))
                .err(),
            Some(Error::PolicyNotFound)
        );
        trans4
            .clone()
            .sign(&master_key, &admin_key4)
            .unwrap()
            .sign(&master_key, &admin_key1)
            .unwrap()
            .sign(&master_key, &admin_key2)
            .unwrap()
            .authorize(Some(&identity2_instance))
            .unwrap();
        trans4
            .clone()
            .sign(&master_key, &admin_key4)
            .unwrap()
            .sign(&master_key, &admin_key1)
            .unwrap()
            .sign(&master_key, &admin_key3)
            .unwrap()
            .authorize(Some(&identity2_instance))
            .unwrap();
        trans4
            .clone()
            .sign(&master_key, &admin_key4)
            .unwrap()
            .sign(&master_key, &admin_key1)
            .unwrap()
            .sign(&master_key, &admin_key2)
            .unwrap()
            .sign(&master_key, &admin_key3)
            .unwrap()
            .authorize(Some(&identity2_instance))
            .unwrap();

        let mut trans5 = trans4
            .clone()
            .sign(&master_key, &admin_key1)
            .unwrap()
            .sign(&master_key, &admin_key3)
            .unwrap();
        let fakesig = MultisigPolicySignature::Key {
            key: admin_key4.key().clone().into(),
            signature: admin_key4.sign(&master_key, b"GET A JOB").unwrap(),
        };
        trans5.signatures_mut().push(fakesig);
        assert!(matches!(trans5.authorize(Some(&identity2_instance)), Err(Error::TransactionSignatureInvalid(_, _))));
    }

    #[test]
    fn identity_prohibit_duplicates() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let now = Timestamp::now();
        let identity2 = sign_and_push! { &master_key, &admin_key, identity.clone(),
            [ make_claim, now.clone(), ClaimSpec::Name(MaybePrivate::new_public("Dirk Delta from........Hollywood".into())), None::<String> ]
        };
        let claim_trans = identity2.transactions()[1].clone();
        let res = identity2.clone().push_transaction(claim_trans);
        assert_eq!(res.err(), Some(Error::DuplicateTransaction));
    }

    #[test]
    fn identity_reencrypt() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        let admin_key2 = AdminKey::new(AdminKeypair::new_ed25519(&mut rng, &master_key).unwrap(), "Second", None);
        let identity = sign_and_push! { &master_key, &admin_key, identity,
            [ make_claim, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_private_verifiable(&mut rng, &master_key, "Hooty McOwl".to_string()).unwrap()), None::<String> ]
            [ add_admin_key, Timestamp::now(), admin_key2 ]
            [ make_claim, Timestamp::now(), ClaimSpec::Name(MaybePrivate::new_public("dirk-delta".to_string())), Some(String::from("name")) ]
        };
        identity.test_master_key(&master_key).unwrap();
        let identity_instance = identity.build_identity_instance().unwrap();
        match identity_instance.claims()[0].spec() {
            ClaimSpec::Name(maybe) => {
                let val = maybe.open(&master_key).unwrap();
                assert_eq!(val, "Hooty McOwl".to_string());
            }
            _ => panic!("bad claim type"),
        }
        let sig = identity_instance.keychain().admin_keys()[0]
            .key()
            .sign(&master_key, b"KILL...ME....")
            .unwrap();

        let master_key_new = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let identity2 = identity.reencrypt(&mut rng, &master_key, &master_key_new).unwrap();
        identity2.test_master_key(&master_key_new).unwrap();
        let res = identity2.test_master_key(&master_key);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
        let identity2_instance = identity2.build_identity_instance().unwrap();
        let sig2 = identity2_instance.keychain().admin_keys()[0]
            .key()
            .sign(&master_key_new, b"KILL...ME....")
            .unwrap();
        assert_eq!(sig, sig2);
        match identity2_instance.claims()[0].spec() {
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
    fn identity_test_master_key() {
        let mut rng = crate::util::test::rng();
        let (master_key, identity, _admin_key) = test::create_fake_identity(&mut rng, Timestamp::now());
        identity.test_master_key(&master_key).unwrap();
        let master_key_fake = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        assert!(master_key_fake != master_key);
        let res = identity.test_master_key(&master_key_fake);
        assert_eq!(res.err(), Some(Error::CryptoOpenFailed));
    }

    #[test]
    fn tx_chain() {
        let mut rng = test::rng_seeded(b"hi there!");
        let (_master_key, identity, _admin_key) =
            test::create_fake_identity(&mut rng, Timestamp::from_str("2024-01-01T00:00:06Z").unwrap());

        let ext = |now, prev, ref_id: &[&TransactionID], data: &[u8]| {
            let mut ref_str = Vec::new();
            for id in ref_id {
                ref_str.push(format!("{id}"));
            }
            identity
                .ext(
                    &HashAlgo::Blake3,
                    now,
                    prev,
                    Some(Vec::from(b"/stamp/test").into()),
                    Some([("ref", ref_str.join(",").as_str())]),
                    Vec::from(data).into(),
                )
                .unwrap()
        };

        let (identity, _name_to_op, _id_to_name) = tx_chain! {
            [
                G = ("2024-01-04T00:01:01Z", |now, prev| ext(now, prev, &[A.id(), F.id()], b"bathroom??!"));
                B = ("2024-01-02T00:01:01Z", |now, prev| ext(now, prev, &[A.id(), C.id()], b"me"));
                E = ("2024-01-02T00:01:01Z", |now, prev| ext(now, prev, &[], b"i"));
                C = ("2024-01-02T00:01:01Z", |now, prev| ext(now, prev, &[A.id(), B.id()], b"may"));
                D = ("2024-01-04T00:01:01Z", |now, prev| ext(now, prev, &[], b"your"));
                A = ("2024-01-03T00:01:01Z", |now, prev| ext(now, prev, &[], b"pardon"));
                F = ("2024-01-02T00:01:01Z", |now, prev| ext(now, prev, &[], b"use"));
            ],
            [
                [A] <- [B],
                [A, B] <- [C],
                [C] <- [D, E],
                [E] <- [F],
                [D, F] <- [G],
            ],
        };
        let datas = identity
            .iter()
            .map(|t| match t.entry().body() {
                TransactionBody::ExtV1(ext) => ext.payload().clone(),
                _ => panic!("oh no"),
            })
            .collect::<Vec<_>>();
        let contexts = identity
            .iter()
            .map(|t| match t.entry().body() {
                TransactionBody::ExtV1(ext) => ext.context().get(&BinaryVec::from(Vec::from(b"ref"))).unwrap(),
                _ => panic!("oh no"),
            })
            .map(|b| String::from_utf8(b.to_vec()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            datas,
            ["pardon", "me", "may", "i", "use", "your", "bathroom??!"]
                .iter()
                .map(|x| BinaryVec::from(Vec::from(x.as_bytes())))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            contexts,
            vec![
                "",
                "6LEQnTkjyRox3k1rdGgOwo7hPfccJsVzFeqoT2hQ0GAA,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "6LEQnTkjyRox3k1rdGgOwo7hPfccJsVzFeqoT2hQ0GAA,8qZUtltk76ieMRtk771REN8NPmVxtdBqUMpByRhbeIQA",
                "",
                "",
                "",
                "6LEQnTkjyRox3k1rdGgOwo7hPfccJsVzFeqoT2hQ0GAA,CiPzMZtg0ByUgL7dAAP8wV7pSvAvmNPQFjPAeABffO8A"
            ],
        );
    }

    #[test]
    fn identity_serde() {
        let mut rng = crate::util::test::rng_seeded(b"beans");
        let (master_key, identity, admin_key) = test::create_fake_identity(&mut rng, Timestamp::from_str("2026-01-22T00:00:00Z").unwrap());
        let crypto_key = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();
        let identity2 = sign_and_push! { &master_key, &admin_key, identity.clone(),
            [ make_claim, Timestamp::from_str("2026-01-22T00:00:00Z").unwrap(), ClaimSpec::Name(MaybePrivate::new_public("Kay".into())), None::<String> ]
            [ make_claim, Timestamp::from_str("2026-01-22T00:00:01Z").unwrap(), ClaimSpec::Url(MaybePrivate::new_public(Url::parse("https://corpophagia.com").unwrap())), None::<String> ]
            [ add_subkey, Timestamp::from_str("2026-01-22T00:00:02Z").unwrap(), Key::new_crypto(crypto_key), "email", None::<&str> ]
        };

        let ser1 = ser::base64_encode(&ser::serialize(&identity).unwrap());
        let ser2 = ser::base64_encode(&ser::serialize(&identity2).unwrap());

        let ser1_expected = "MIIBozCCAZ-gJKAiBCBx0wGhMEpiydDAebeks8SkJNox8X6FmC-Tfauywkx9jaGB_DCB-aAIAgYBm-MANAChAjAAooHooIHlMIHioIGSMIGPMIGMoIGAoH4wfKAiBCDqwobkyCMMiGa3b96sdbDH2oxENmSry2MrLCbhuUCGo6FWMFSgHKAaBBg-u3LN6iMBLGPp3nikzhSeyvWOIPEmvHihNAQyyzdamgrpU4TLdJb_sTQ7bsm5RcrCP0dEBGqelrTqQP9TAg7ZDmk9N_LMjI0YhJs00FChBwwFQWxwaGGhSzBJMEegBjAEoAIFAKE9ojswOaADAgEBoTIwMKAuMCyhKqAoMCagIgQg6sKG5MgjDIhmt2_erHWwx9qMRDZkq8tjKywm4blAhqOhAKJ4MHagdDByoCqgKDAmoCIEIOrChuTIIwyIZrdv3qx1sMfajEQ2ZKvLYyssJuG5QIajoQChRKBCBEAQbMib1Fz9lGTTmDtxg9w1wz1Ywnd93oZDqXX6dn_Fz5HcO8grjJWZfmC3ZFlisNZRlD1NY3NU9HOfTCGRAIkH";
        let ser2_expected = "MIIFADCCAZ-gJKAiBCBx0wGhMEpiydDAebeks8SkJNox8X6FmC-Tfauywkx9jaGB_DCB-aAIAgYBm-MANAChAjAAooHooIHlMIHioIGSMIGPMIGMoIGAoH4wfKAiBCDqwobkyCMMiGa3b96sdbDH2oxENmSry2MrLCbhuUCGo6FWMFSgHKAaBBg-u3LN6iMBLGPp3nikzhSeyvWOIPEmvHihNAQyyzdamgrpU4TLdJb_sTQ7bsm5RcrCP0dEBGqelrTqQP9TAg7ZDmk9N_LMjI0YhJs00FChBwwFQWxwaGGhSzBJMEegBjAEoAIFAKE9ojswOaADAgEBoTIwMKAuMCyhKqAoMCagIgQg6sKG5MgjDIhmt2_erHWwx9qMRDZkq8tjKywm4blAhqOhAKJ4MHagdDByoCqgKDAmoCIEIOrChuTIIwyIZrdv3qx1sMfajEQ2ZKvLYyssJuG5QIajoQChRKBCBEAQbMib1Fz9lGTTmDtxg9w1wz1Ywnd93oZDqXX6dn_Fz5HcO8grjJWZfmC3ZFlisNZRlD1NY3NU9HOfTCGRAIkHMIHnoCSgIgQgLeEVX77MsWHt1rjuT3NH5W9sTK1sYgaccsyQliNCAH6hRTBDoAgCBgGb4wA0AKEmMCSgIgQgcdMBoTBKYsnQwHm3pLPEpCTaMfF-hZgvk32rssJMfY2iD6gNMAugCaEHoAUMA0theaJ4MHagdDByoCqgKDAmoCIEIOrChuTIIwyIZrdv3qx1sMfajEQ2ZKvLYyssJuG5QIajoQChRKBCBECssN_HaigVNbQlSsOGAujpVk7V1kujrSomrOasyrUbc7sr9AEY28FdIlmqsgHPEk-VZ10ruhDKNOPLUVUkFlwOMIH8oCSgIgQgKJa4jQQebaSWL58XVh454SeVJ5fKdxq62OehgwRhd96hWjBYoAgCBgGb4wA36KEmMCSgIgQgLeEVX77MsWHt1rjuT3NH5W9sTK1sYgaccsyQliNCAH6iJKgiMCCgHqccoBoMGGh0dHBzOi8vY29ycG9waGFnaWEuY29tL6J4MHagdDByoCqgKDAmoCIEIOrChuTIIwyIZrdv3qx1sMfajEQ2ZKvLYyssJuG5QIajoQChRKBCBECwIqlzxS7LhNRAnJYtCJcIoZujpewpEdvNj3JO-gTmlJBc0TGgLLk2XAn0Scpdro6QDlpiqQ8T_noKnfhTcVkAMIIBcKAkoCIEIPRn7DvE8_oSgzVN4Y0ZuHGNTygWb5FA9ueL2wSpW9yOoYHNMIHKoAgCBgGb4wA70KEmMCSgIgQgKJa4jQQebaSWL58XVh454SeVJ5fKdxq62OehgwRhd96igZWvgZIwgY-ggYOhgYCgfjB8oCIEIGOz8cefZOg_SYgmjcEr1jb8Rajl9EKWVBAixSa13uMgoVYwVKAcoBoEGONZTcpG2EYP3hH1RQ-qRzNRpfBSHC7cLKE0BDK0IkwA5zSZwE7xy_jpAJuhxIX4ikLlipy7AnUA93yUwj0N65m_AT9sX2KljIb3Z3byZqEHDAVlbWFpbKJ4MHagdDByoCqgKDAmoCIEIOrChuTIIwyIZrdv3qx1sMfajEQ2ZKvLYyssJuG5QIajoQChRKBCBEAZFrJHX7rAII-zA5m-WLef_8EGEZL20-n8ie3Dx9UgDei_rNCHYDKujepjVOu7j0uKlqxEo0R31tIPADmopvkC";

        assert_eq!(ser1, ser1_expected);
        assert_eq!(ser2, ser2_expected);

        {
            let identity_deser: Identity<Full> = ser::deserialize(&ser::base64_decode(&ser1_expected).unwrap()).unwrap();
            for tx in identity_deser.iter() {
                tx.verify_hash_and_signatures().unwrap();
            }
            assert_eq!(
                identity.transactions().iter().map(|x| x.id()).collect::<Vec<_>>(),
                identity_deser.transactions().iter().map(|x| x.id()).collect::<Vec<_>>(),
            );
        }
        {
            let identity_deser: Identity<Full> = ser::deserialize(&ser::base64_decode(&ser2_expected).unwrap()).unwrap();
            for tx in identity_deser.iter() {
                tx.verify_hash_and_signatures().unwrap();
            }
            assert_eq!(
                identity2.transactions().iter().map(|x| x.id()).collect::<Vec<_>>(),
                identity_deser.transactions().iter().map(|x| x.id()).collect::<Vec<_>>(),
            );
        }
    }
}
