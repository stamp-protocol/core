//! A DAG, or directed acyclic graph, allows us to represent our identity as an
//! ordered list of signed changes, as opposed to a singular object. There are
//! pros and cons to both methods, but for the purposes of this project, a
//! tree of signed transactions that link back to previous changes provides a
//! good amount of security, auditability, and syncability.
//!
//! This module contains general utilities for working with DAGs in the context of Stamp
//! transactions. They are less concerned with verifying transaction validity and more so focused
//! on providing functions for traversing DAGs and running their nodes in order.

mod identity;
mod transaction;

pub use crate::{
    crypto::base::HashAlgo,
    dag::{
        identity::{tx_chain, Identity},
        transaction::{
            ExtTransaction, PublishTransaction, SignTransaction, StampTransaction, Transaction, TransactionBody, TransactionEntry,
            TransactionID,
        },
    },
    error::Result,
};
use crate::{error::Error, util::Timestamp};
use getset::{Getters, MutGetters};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::Hash;

/// Defines a node in a DAG. Each node can have multiple previous nodes and multiple next nodes.
/// It's crazy out here.
#[derive(Debug, Getters, MutGetters)]
#[getset(get = "pub", get_mut = "pub(crate)")]
pub struct DagNode<'a, I, T> {
    /// This node's ID
    id: &'a I,
    /// The nodes that came before this one
    prev: Vec<&'a I>,
    /// The nodes that come after this one
    next: Vec<&'a I>,
    /// The node this points to.
    node: &'a T,
    /// Timestamp of this node, used for ordering
    timestamp: &'a Timestamp,
}

impl<'a, I, T> DagNode<'a, I, T> {
    /// Create a new DagNode
    pub fn new(id: &'a I, node: &'a T, prev: Vec<&'a I>, timestamp: &'a Timestamp) -> Self {
        Self {
            id,
            prev,
            next: Vec::new(),
            node,
            timestamp,
        }
    }
}

impl<'a, I, T> Clone for DagNode<'a, I, T> {
    fn clone(&self) -> Self {
        DagNode {
            id: self.id,
            prev: self.prev.clone(),
            next: self.next.clone(),
            node: self.node,
            timestamp: self.timestamp,
        }
    }
}

/// Allows modeling a DAG (directed acyclic graph) using a linked list-ish structure that can be
/// traversed both forward and back.
#[derive(Clone, Debug, Default, Getters, MutGetters)]
#[getset(get = "pub", get_mut = "pub(crate)")]
pub struct Dag<'a, I, T> {
    /// The head/start of the DAG. Can be multiple nodes because technically we can start with
    /// "conflicting" branches. In the case of Stamp DAGs, this is not true: we must have *one
    /// single start node* (the genesis) and this will be enforced. However, for other DAGs
    /// that might use Stamp as a medium, we cannot assume they will always start out with only one
    /// single node that all others branch from.
    head: Vec<&'a I>,
    /// The tail/end of our DAG. This is any nodes that are not listed in some known
    /// node's `previous_nodes` list.
    tail: Vec<&'a I>,
    /// Holds an index of node IDs to internal DAG nodes. This is useful because instead of
    /// DAG nodes referencing each other directly and having to have `Box<Blah>` everywhere, we just
    /// store the IDs and put the nodes in one single lookup table.
    index: HashMap<&'a I, DagNode<'a, I, T>>,
    /// Nodes that we processed while walking the DAG, in the order they were processed.
    /// If this has less nodes in it than the `index` then it means we have a broken chain
    /// and/or a circular reference somewhere. In a healthy DAG, `visited` and `index` will have
    /// the same number of entries.
    visited: Vec<&'a I>,
    /// Nodes that were not processed while creating the DAG. This is generally because of
    /// missing links or missing nodes in the chain. This will be mutually exclusive from
    /// `missing`, so to get *all unprocessed nodes* you would combine the sets.
    unvisited: HashSet<&'a I>,
    /// Nodes that we don't have in our `index` but were referenced while building the DAG.
    /// These generally represent nodes that we are waiting to sync on and are "breaking the
    /// chain" so to speak.
    missing: HashSet<&'a I>,
}

impl<'a, I, T> Dag<'a, I, T>
where
    I: Clone + Eq + Hash + Ord,
{
    /// Create a new, empty DAG
    pub fn new() -> Self {
        Self {
            head: Vec::new(),
            tail: Vec::new(),
            index: HashMap::new(),
            visited: Vec::new(),
            unvisited: HashSet::new(),
            missing: HashSet::new(),
        }
    }

    /// Takes a list of a list of nodes and returns a of DAG that models those nodes.
    ///
    /// The reason we don't just do a flat list is sometimes we want to build a DAG by mashing a
    /// number of nodes from multiple places together. We can support that internally, but
    /// representing that as a structure that can be passed in naturally is difficult. So instead
    /// we make the interface slightly more awkward by forcing you to wrap your collection in an
    /// extra `&[...]` but ultimately it gives us more performance because you don't have to clone
    /// your nodes to all be in one vec.
    ///
    /// Note that the *order of the node collections matters*. Nodes in later collections will
    /// override nodes in previous collections, both in data and in previous node relationships.
    /// Later nodes always take precedence. This allows creating a DAG with modified nodes without
    /// having to modify/clone the original list and instead passing the original list first, and
    /// the list with *only* the modified nodes after.
    pub fn from_nodes(node_collections: &[&[DagNode<'a, I, T>]]) -> Dag<'a, I, T> {
        // create our DAG object.
        let mut dag = Dag::new();

        // index our nodes into the DAG.
        for nodes in node_collections {
            for node in nodes.iter() {
                dag.index_mut().insert(*node.id(), node.clone());
            }
        }

        // holds locations at which our chain breaks, ie we reference a node that cannot be
        // found. this helps us split up our DAGs later on.
        let mut missing_nodes: HashSet<&'a I> = HashSet::new();

        // stores nodes we encounter that have no previous nodes (ie, they start the
        // DAG). we make a separate container instead of pushing directly into `dag.head` because
        // we need to also push in the node's timestamp, which dag.head doesn't care about.
        // we do this so we can sort by timestamp before processing the dag, with the goal of
        // getting deterministic outputs in our final DAG object regardless of the order of
        // nodes passed in.
        let mut head_nodes = Vec::new();

        // this is a temporary index that stores &nodeid -> &Timestamp lookups, allowing us
        // to iterate and sort the `next` elements for each DAG node.
        let mut trans_created_idx = HashMap::with_capacity(node_collections.iter().map(|x| x.len()).sum());

        // now loop over our nodes again and update our .next[] references.
        // after this, we'll have both forward and backward links for all available nodes.
        //
        // order is important here! we're looping over our collections in *reverse order* and
        // tracking which nodes we've seen previously, skipping already visited ones.
        //
        // the idea here is nodes later in the collection can override nodes (by id) earlier in the
        // collection, including the prev list.
        {
            let mut seen: HashSet<&I> = HashSet::new();
            // reverse our collections
            for node_collection in node_collections.iter().rev() {
                for node in *node_collection {
                    // track which nodes we've seen, so we can ignore already visited ones. this
                    // allows using *only the latest* version of a node.
                    if seen.contains(node.id()) {
                        continue;
                    }
                    seen.insert(node.id());
                    trans_created_idx.insert(node.id(), node.timestamp().timestamp_millis());
                    let prev = node.prev();
                    if prev.is_empty() {
                        // cool, we found a head node. track it.
                        head_nodes.push((node.timestamp(), node.id()));
                    } else {
                        for prev_id in prev {
                            match dag.index_mut().get_mut(prev_id) {
                                Some(previous_node) => {
                                    previous_node.next_mut().push(node.id());
                                }
                                None => {
                                    // we're referencing a node we cannot find. this means we have a break in
                                    // our DAG chain
                                    missing_nodes.insert(prev_id);
                                }
                            }
                        }
                    }
                }
            }
        }

        // now, for each DAG node, sort its `prev` and `next` nodes by (timestamp ASC, transction_id
        // ASC). this gives us detemrinistic ordering in our DAG.
        for node in dag.index_mut().values_mut() {
            node.prev_mut().sort_unstable_by_key(|tid| {
                let created = trans_created_idx.get(tid).copied().unwrap_or(i64::MAX);
                (created, *tid)
            });
            node.prev_mut().dedup();
            node.next_mut().sort_unstable_by_key(|tid| {
                let created = trans_created_idx.get(tid).copied().unwrap_or(i64::MAX);
                (created, *tid)
            });
            node.next_mut().dedup();
        }

        // sort our head nodes by create time ASC, node id ASC, then store the sorted
        // node IDs into `dag.head`. this makes walking the DAG deterministic.
        head_nodes.sort_unstable();
        *dag.head_mut() = head_nodes.into_iter().map(|(_, tid)| *tid).collect::<Vec<_>>();

        // walk our dag and look for tail nodes and problems (missing nodes, circular links, etc)
        let mut tail_nodes = Vec::new();
        // NOTE: we unwrap() here because we know for a fact that this walk() always returns Ok().
        // if this changes in the future, *please* update the logic accordingly, possibly wrapping
        // `from_nodes()` in a Result...
        let (visited, missing) = dag
            .walk(|node, _ancestry, _ancestry_idx| {
                if node.next().is_empty() {
                    tail_nodes.push(*node.id());
                }
                Ok::<(), Error>(())
            })
            .expect("Dag::from_nodes()::walk() returned without error");
        for entry in missing {
            missing_nodes.insert(entry);
        }
        dag.visited = visited;
        dag.unvisited = dag.find_unvisited();
        dag.missing = missing_nodes;
        dag.tail = tail_nodes;
        dag
    }

    /// Walk the DAG, starting from the head, and running a function on each node in-order.
    ///
    /// In-order here means we follow causal order, but between branches of the DAG nodes, we sort
    /// by (timestamp ASC, node id ASC). This gives us consistent ordering that preserves
    /// the causal chain, but where we cannot order via the DAG chain we rely on timestamp instead,
    /// and in the case of timestamp conflict, we run the node ID with the lower sort order
    /// first.
    ///
    /// If we hit a merge, we don't continue past the merge of the branches until each of the
    /// branches has run. This also tracks branches and merges via a numeric value assigned to each
    /// branch/merge, passing these branch IDs in as a list, allowing the op fn to have a sense of
    /// ancestry (with the current/most recent branch being last in the list).
    ///
    /// The way that branches/merges are handled also happens to somewhat gracefully deal with
    /// circular references as well (AKA a G instead of a DAG)...circular references are not
    /// possible without merges that reference future nodes, so we'll effectively just
    /// return without finishing walking the DAG.
    ///
    /// It's also important to note that a valid merkle-DAG cannot HAVE circular references without
    /// finding some weird hash collisions. If you're sending a circular graph in, you aren't
    /// sending valid Stamp data, sooooo...... WET WILLY FOR YOU.
    ///
    /// We can also send in two completely independent DAGs in and they will still get processed
    /// like normal: start at the head nodes and recursively march forward. We don't attempt to
    /// distinguish between disconnected DAGs and singular ones because for our purposes, it
    /// doesn't really matter that much. The things we care about are:
    ///
    /// - Known nodes visited during the walk
    /// - Nodes referenced by some visited node that don't exist in the DAG (missing nodes)
    ///
    /// And so these are the things we return. In that order. As a tuple.
    pub fn walk<F, E>(&self, mut opfn: F) -> core::result::Result<(Vec<&'a I>, HashSet<&'a I>), E>
    where
        F: FnMut(&DagNode<'a, I, T>, &[&'a I], &HashMap<&'a I, Vec<&'a I>>) -> core::result::Result<(), E>,
    {
        /// stored with the `pending_nodes` as a way to instruct nodes whether they should
        /// use the given ancestry as-is or whether they should grab a new branch and append it to
        /// the end.
        ///
        /// this makes it so we don't have to sort the node.next() entries, and instead can
        /// lazy-load our ancetry so it corresponds directly to node order.
        struct AncestryGrabber<'a, I> {
            /// The ancestry of the previous node
            ancestry: Vec<(u32, &'a I)>,
            /// Whether or not we should append the current transaction being processed to the
            /// ancestry list. In general, you'd do this after a branch.
            append_next_transaction: bool,
        }

        impl<'a, I> AncestryGrabber<'a, I> {
            fn new(ancestry: Vec<(u32, &'a I)>, append_next_transaction: bool) -> Self {
                Self {
                    ancestry,
                    append_next_transaction,
                }
            }

            fn consume(self) -> (Vec<(u32, &'a I)>, bool) {
                let Self {
                    ancestry,
                    append_next_transaction,
                } = self;
                (ancestry, append_next_transaction)
            }
        }

        // the nodes we have visited *in the order we visited them*
        let mut visited: Vec<&'a I> = Vec::with_capacity(self.index().len());
        // the nodes we have visited in a format that allows for quick lookups
        let mut visited_set: HashSet<&'a I> = HashSet::with_capacity(self.index().len());
        // nodes we've come across that were referenced by id but could not be found in the
        // index
        let mut missing_nodes: HashSet<&'a I> = Default::default();
        // our main ordering mechanism. when processing a node, we push the next
        // nodes into this ordered set. when done, we pop the first node off the set
        // and loop again. this effectively allows sorting by causal order BUT with the benefit
        // that pending nodes are ordered by timestamp/node ID as well.
        //
        // the key is the node's timestamp, the node's ID, and the node that
        // created this entry (if any). the value is a struct that stores ancestry and determines
        // if we need to create a new branch for this node when it runs.
        //
        // NOTE: although temping to remove the `Option<&'a I>` from the key, please don't! allows
        // multiple pending entries for merge nodes, which is exactly what you want. so although we
        // never actually USE the value itself, it's used to segment different DAG paths from each
        // other. leave it.
        let mut pending_nodes: BTreeMap<(&'a Timestamp, &'a I, Option<&'a I>), AncestryGrabber<'a, I>> = Default::default();
        // allows sorting branch trackers causally via an incrementing number
        let mut branch_sort: u32 = 0;
        // Stores the ancestry of each node as they are being processed. This allows ancestry
        // lookups of nodes that have been previously seen.
        let mut branch_tracker: HashMap<&'a I, Vec<&'a I>> = HashMap::with_capacity(self.index().len());
        // this is used by merging nodes (ie, has prev_nodes.len() > 1) to store the
        // ancestry of the previous nodes so they can all be merged together when the merge is
        // ready.
        let mut branch_merge_tracker: HashMap<&'a I, Vec<Vec<(u32, &'a I)>>> = HashMap::new();

        let mut next_branch_sort = || {
            let prev = branch_sort;
            branch_sort += 1;
            prev
        };

        // a helper macro to keep me from getting carpal tunnel. effectively looks in the main
        // index for a node and if found, runs the given block, otherwise pushes the
        // node ID into the missing nodes list.
        macro_rules! with_trans {
            ($id:expr, $node:ident, $run:block) => {{
                match self.index().get($id) {
                    Some($node) => $run,
                    None => {
                        missing_nodes.insert($id);
                    }
                }
            }};
        }

        // loop over our head nodes and push them into the pending list. they are going to kick off
        // our main loop
        for tid in self.head() {
            with_trans! { tid, node, {
                // NOTE: we can assign branch ids sequentially here because the head nodes are
                // sorted before this function is ever called. therefor, the head nodes are going
                // to be in the same position in the btree that they are when we loop over them.
                pending_nodes.insert(
                    (node.timestamp(), tid, None),
                    AncestryGrabber::new(vec![(next_branch_sort(), tid)], false),
                );
            }}
        }

        // this is the main loop. we pop an item off the pending list and run it. if it has
        // nodes following, they will be added to the pending list and we continue ad
        // nauseum. if the node is a merge, we do not process it until all the nodes
        // before it have been run.
        while let Some(((_, tid, _prev_node_id), ancestry_grabber)) = pending_nodes.pop_first() {
            // check if we're looping. this should likely never be true, but can't be too careful
            // these days...
            if visited_set.contains(&tid) {
                // we've already seen this node. circular references are bad, m'kay?
                continue;
            }

            let (mut ancestry, ancestry_append_next_transaction) = ancestry_grabber.consume();

            with_trans! { &tid, node, {
                // if we have more than one previous node, we have to make sure that all the
                // previous nodes have run before we can run this one!
                if node.prev().len() > 1 {
                    // push the ancestors we were given for the previous node into our merge
                    // tracker for THIS node.
                    let entry = branch_merge_tracker.entry(tid).or_default();
                    (*entry).push(ancestry.clone());

                    if entry.len() < node.prev().len() {
                        continue;
                    }

                    // gee whillickers, we've visited all the previous nodes! harvest their
                    // dumb ancestry and add it to our own, adding another branch to signify our
                    // merge on this joyous occasion.
                    match branch_merge_tracker.remove(&tid) {
                        Some(ancestor_vec_vec) => {
                            for ancestor_vec in ancestor_vec_vec {
                                for ancestor in ancestor_vec {
                                    ancestry.push(ancestor);
                                }
                            }
                        }
                        None => {
                            missing_nodes.insert(tid);
                            continue;
                        }
                    }
                    ancestry.push((next_branch_sort(), tid));
                    ancestry.sort_by(|a, b| a.0.cmp(&b.0));
                    ancestry.dedup();
                } else if ancestry_append_next_transaction {
                    // we got a signal from a previous transaction that we should create a new
                    // ancestry branch. this is likely because this transaction is one of a few
                    // that branches off a past transaction.
                    ancestry.push((next_branch_sort(), tid));
                }

                let ancestry_flat = ancestry.iter().map(|(_, x)| *x).collect::<Vec<_>>();
                branch_tracker.insert(tid, ancestry_flat.clone());

                // track that we've seen this node
                visited.push(tid);
                visited_set.insert(tid);

                // run our user-supplied operation
                opfn(node, &ancestry_flat, &branch_tracker)?;

                // if we only have one next node, we don't need to fuss with ancestry at all: we
                // can just set it as is.
                //
                // however if we have multiple next nodes, we need to create a new branch id for
                // each of them.
                if node.next().len() == 1 {
                    let ntid = node.next()[0];
                    with_trans! { ntid, node_next, {
                        pending_nodes.insert(
                            (node_next.timestamp(), ntid, Some(tid)),
                            AncestryGrabber::new(ancestry, false),
                        );
                    }}
                } else {
                    // the next nodes were sorted before walk() is called, so we can sequentially
                    // assign branch nums here.
                    for &ntid in node.next() {
                        with_trans! { ntid, next_node, {
                            pending_nodes.insert(
                                (next_node.timestamp(), ntid, Some(tid)),
                                AncestryGrabber::new(ancestry.clone(), true),
                            );
                        }}
                    }
                }
            }}
        }

        // cool, we're done!
        Ok((visited, missing_nodes))
    }

    /// Build a state from a DAG.
    ///
    /// This works by walking the DAG forward, while tracking node ancestry and validating nodes
    /// and applying them backwards as the DAG advances, ultimately returning the state from the
    /// FIRST node, which will receive all of the updates *in order* BUT WITH THE CAVEAT that each
    /// node will be validated based on its branch-local state. This means it validates nodes based
    /// on their ancestry (previous_transactions) with no bearing on what is happening in
    /// concurrent branches within the DAG.
    ///
    /// Note that this assumes your DAG starts with one head element! If this is not the case,
    /// you'll want to deal with your own state application manually.
    pub fn apply<'b, S, E, FN, FS, FV, FA>(
        &self,
        branch_state: &'b mut HashMap<I, S>,
        new_initial_state_fn: FN,
        skip_fn: FS,
        validate_fn: FV,
        apply_fn: FA,
    ) -> core::result::Result<&'b S, E>
    where
        I: Clone + std::fmt::Debug,
        E: From<Error>,
        S: Clone,
        FN: Fn(&DagNode<'a, I, T>) -> core::result::Result<S, E>,
        FS: Fn(&DagNode<'a, I, T>) -> bool,
        FV: Fn(&S, &DagNode<'a, I, T>) -> core::result::Result<(), E>,
        FA: Fn(&mut S, &DagNode<'a, I, T>) -> core::result::Result<(), E>,
    {
        if self.head().len() != 1 {
            Err(Error::DagGenesisError)?;
        }

        if !self.missing().is_empty() {
            // ideally we'd return actual transaction IDs here, but it's incredibly limiting to
            // need I: Into<TransactionID> just so we can show you an error that you should really
            // be checking for yourself, so...
            Err(Error::DagMissingTransactions(Vec::new()))?;
        }

        self.walk(|node, ancestry, branch_tracker| {
            let current_ancestor_id = ancestry.last().expect("ancestry is not empty");
            let skip_current_node = skip_fn(node);
            if !skip_current_node {
                // check if this is a merge transaction or not.
                if node.prev().len() > 1 {
                    // ok, we're merging a set of transactions together.
                    //
                    // we first need to verify this transaction is valid. the best way to do this is to
                    // find the branch that all the to-be-merged transactions have in common, pull out
                    // the identity for that branch, and use it to verify our merge transaction.

                    // so first, grab all the ancestors from our previous transactions, and put them
                    // into BTreeSets so they're pre-sorted for us.
                    let ancestry_sets = node
                        .prev()
                        .iter()
                        .map(|tid| {
                            branch_tracker
                                .get(tid)
                                .map(|ancestors| ancestors.iter().copied().collect::<BTreeSet<_>>())
                                .ok_or_else(|| {
                                    Error::DagBuildError(format!("apply() -- {:?} merge: collect ancestors: {:?}", node.id(), tid)).into()
                                })
                        })
                        .collect::<core::result::Result<Vec<BTreeSet<&I>>, E>>()?;
                    // now we're going to run the intersection of all the ancestry sets...
                    let intersected = match ancestry_sets.len() {
                        0 => BTreeSet::new(),
                        _ => ancestry_sets[1..].iter().fold(ancestry_sets[0].clone(), |mut acc, set| {
                            acc.retain(|item| set.contains(item));
                            acc
                        }),
                    };
                    let first_ancestry_set = branch_tracker.get(&node.prev()[0]).ok_or_else(|| {
                        Error::DagBuildError(format!("apply() -- {:?} merge: grab first ancestor: {:?}", node.id(), node.prev()[0]))
                    })?;
                    // and grab the highest-sorted common branch (aka the most recent one)
                    // take any ancestry set in our previous list and walk it *in reverse* (see the
                    // rev()??) until we find a node that's in our intersected set. that's our nearest
                    // common ancestor, and we'll use it to validate this dumb node.
                    let most_recent_common_branch = first_ancestry_set
                        .iter()
                        .rev()
                        .find(|tid| intersected.contains(*tid))
                        .ok_or_else(|| Error::DagBuildError(format!("apply() -- {:?} merge: no nearest common ancestor", node.id())))?;
                    // now grab the identity associated with this common branch and verify...
                    let most_recent_common_ancestor_state = branch_state.get(most_recent_common_branch).ok_or_else(|| {
                        Error::DagBuildError(format!("apply() -- {:?} merge: missing nearest common ancestor", node.id()))
                    })?;
                    validate_fn(most_recent_common_ancestor_state, node)?;

                    // verified!
                    //
                    // now apply this transaction to all of its ancestor branches, making sure to only
                    // apply the transaction once-per-branch
                    let mut seen_branch: HashSet<&I> = HashSet::new();
                    for ancestors in ancestry_sets {
                        // we're kind of going in reverse order here (oldest -> newest) but it
                        // doesn't really matter.
                        for branch in &ancestors {
                            if seen_branch.contains(branch) {
                                continue;
                            }
                            let root_state = branch_state
                                .get(self.head()[0])
                                .ok_or_else(|| {
                                    Error::DagBuildError(format!(
                                        "apply() -- {:?} merge: missing root state {:?}",
                                        node.id(),
                                        self.head()[0]
                                    ))
                                })?
                                .clone();
                            #[allow(suspicious_double_ref_op)]
                            let state = branch_state.entry(branch.clone().clone()).or_insert_with(|| root_state.clone());
                            apply_fn(state, node)?;
                            seen_branch.insert(*branch);
                        }
                    }
                    // lastly, save our current merged state into the branch state tracker. this
                    // allows a branch operation to happen directly after this merge (which
                    // requires the state to exist in branch tracker to copy into the next nodes).
                    let state = branch_state.get(most_recent_common_branch).ok_or_else(|| {
                        Error::DagBuildError(format!("apply() -- {:?} merge: missing nearest common ancestor 2", node.id()))
                    })?;
                    #[allow(suspicious_double_ref_op)]
                    branch_state.insert(node.id().clone().clone(), state.clone());
                } else if node.prev().len() == 1 {
                    // this is NOT a merge transaction, so we can simply verify the transaction against
                    // the current branch identity and if all goes well, apply it to all the ancestor
                    // identities.
                    let current_branch_state = if branch_state.contains_key(current_ancestor_id) {
                        branch_state.get_mut(current_ancestor_id).ok_or_else(|| {
                            Error::DagBuildError(format!(
                                "apply() -- {:?} next: missing ancestor branch state: {:?}",
                                node.id(),
                                current_ancestor_id
                            ))
                        })?
                    } else {
                        let ancestor_before_id = ancestry.iter().rev().nth(1).ok_or_else(|| {
                            Error::DagBuildError(format!(
                                "apply() -- {:?} next: missing next nearest ancestor id: {:?}",
                                node.id(),
                                ancestry
                            ))
                        })?;
                        let ancestor_before = branch_state
                            .get(ancestor_before_id)
                            .ok_or_else(|| {
                                Error::DagBuildError(format!(
                                    "apply() -- {:?} next: missing next nearest ancestor in branch state: {:?}",
                                    node.id(),
                                    ancestor_before_id,
                                ))
                            })?
                            .clone();
                        #[allow(suspicious_double_ref_op)]
                        branch_state.insert(current_ancestor_id.clone().clone(), ancestor_before);
                        branch_state.get_mut(current_ancestor_id).ok_or_else(|| {
                            Error::DagBuildError(format!(
                                "apply() -- {:?} next: missing ancestor in branch state: {:?}",
                                node.id(),
                                current_ancestor_id
                            ))
                        })?
                    };
                    // first verify the transaction is valid against the CURRENT branch state.
                    validate_fn(current_branch_state, node)?;
                    // now apply this transaction to all of its ancestor branches
                    for branch in ancestry {
                        #[allow(suspicious_double_ref_op)]
                        let state = branch_state.get_mut(branch).ok_or_else(|| {
                            Error::DagBuildError(format!("apply() -- {:?} next: missing branch state: {:?}", node.id(), branch))
                        })?;
                        apply_fn(state, node)?;
                    }
                } else {
                    // we're processing our genesis transaction
                    let state = new_initial_state_fn(node)?;
                    validate_fn(&state, node)?;
                    #[allow(suspicious_double_ref_op)]
                    branch_state.insert(
                        ancestry
                            .last()
                            .ok_or_else(|| Error::DagBuildError(format!("apply() -- {:?} genesis: ancestry chain is blank", node.id())))?
                            .clone()
                            .clone(),
                        state,
                    );
                }
            }

            // now some trickery. if this node is the head of a branch, we want to pre-populate
            // the state of the following nodes to be a copy of this node so they don't pollute
            // each other's state.
            //
            // if we don't do this, consider:
            //
            //     A
            //    / \
            //   B   |
            //   |   C
            //    \ /
            //     D
            //
            // If A is permissive and allows C, but B is restrictive and denies C, and B runs
            // before C, then if we allow B to "pollute" the ancestry by sending its updates to
            // A before C runs, then when we try to run C it'll grab the current state of A and
            // will not validate (because B's updates propagated back to it).
            //
            // So the solve here is for A to say "oh, I'm branching, let me copy my unspoiled
            // state to both B and C so they can validate against it (because they validate
            // using the nearest ancestor and if that doesn't exist we copy one ancestor back)
            // without interfering with each other.
            if node.next().len() > 1 {
                let cur_state = branch_state
                    .get(current_ancestor_id)
                    .ok_or_else(|| {
                        Error::DagBuildError(format!(
                            "apply() -- {:?} branch: missing branch state for ancestor: (ancestor: {:?}) {:?}",
                            node.id(),
                            current_ancestor_id,
                            branch_state.keys().collect::<Vec<_>>()
                        ))
                    })?
                    .clone();
                for next in node.next() {
                    // don't override an existing state entry
                    //
                    // this is possible if we add transactions in multiple stages
                    if !branch_state.contains_key(next) {
                        #[allow(suspicious_double_ref_op)]
                        branch_state.insert(next.clone().clone(), cur_state.clone());
                    }
                }
            }
            Ok::<(), E>(())
        })?;
        Ok(branch_state
            .get(self.head()[0])
            .ok_or_else(|| Error::DagBuildError(format!("apply() -- return: missing root state: {:?}", self.head()[0])))?)
    }

    /// Given the id of a node in this DAG, find all the ancestor nodes within the node's causal
    /// chain. This order of nodes returned cannot be relied upon.
    pub fn get_causal_chain(&'a self, node_id: &'a I) -> HashSet<&'a I> {
        let mut walk_queue = VecDeque::new();
        let mut seen = HashSet::new();
        walk_queue.push_back(node_id);
        while let Some(id) = walk_queue.pop_front() {
            if seen.contains(id) {
                continue;
            }
            let tx = if let Some(x) = self.index().get(id) {
                x
            } else {
                continue;
            };
            seen.insert(id);
            for prev in tx.prev() {
                if seen.contains(prev) {
                    continue;
                }
                walk_queue.push_back(prev);
            }
        }
        seen
    }

    /// Given a set of nodes visited from [`Dag::walk()`], find the nodes that are unvisited from
    /// that walk (ie, any known nodes we didn't walk to).
    pub fn find_unvisited(&self) -> HashSet<&'a I> {
        let mut unvisited = HashSet::new();
        for trans_id in self.index().keys() {
            if !self.visited().contains(trans_id) {
                unvisited.insert(*trans_id);
            }
        }
        unvisited
    }
}

/// Utilities for modifying DAG nodes in efficient ways. This *will* break signatures and hashes,
/// so just be mindful to only use this for throwaway DAG stuff.
pub trait DagTamperUtil: Sized {
    /// The type used for transaction IDs
    type ID;

    /// the type used for transaction bodies
    type Body;

    /// A very unsafe function that is sometimes required in situations where a DAG needs to be
    /// hand-created (forged) and we don't have all the information to do it ze proper way.
    ///
    /// For instance, if removing nodes from a DAG and then later re-creating them with fake
    /// entries (that would never verify BTW so it's not some workaround to break integrity) we
    /// might want to recreate the removed DAG nodes given just an ID and timestamp.
    fn create_raw_with_id<T: Into<Timestamp>>(id: Self::ID, created: T, previous_transactions: Vec<Self::ID>, body: Self::Body) -> Self;

    /// Create a new transaction with hand-supplied values for the create time, previous
    /// transactions, and body.
    ///
    /// You almost never want this! Use the dag::Transactions::<create_identity|add_subkey|...>
    /// functions instead. This function's main utility is raw DAG manipulation.
    fn create_raw<T: Into<Timestamp>>(
        hash_with: &HashAlgo,
        created: T,
        previous_transactions: Vec<Self::ID>,
        body: Self::Body,
    ) -> Result<Self>;

    /// Allows modification of the `previous_transactions` field of an ExtV1 body. This is useful
    /// in situations where an application needs to do some DAG manipulation but can't do it
    /// directly because the official functions don't allow modifications of the `Transaction` or
    /// inner fields.
    ///
    /// We can do the same by cloning a bunch of garbage and using [`Transaction::create_raw`] but
    /// this allows the same without copy.
    fn try_mod_ext_previous_transaction(&mut self, new_ext_previous_transactions: Vec<Self::ID>) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::Error,
        util::{
            ser::{BinaryVec, HashMapAsn1},
            test::make_dag_chain,
            Timestamp,
        },
    };
    use private_parts::Full;
    use std::str::FromStr;

    #[test]
    fn dag_from_nodes_walk_simple() {
        let mut rng = crate::util::test::rng();
        let (_master_key, identity, _admin_key) = crate::util::test::create_fake_identity(&mut rng, Timestamp::now());
        #[allow(non_snake_case, unused_mut)]
        let (transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           identity,
           [A(0), B(1), C(2), D(3), E(4), F(5), G(6)],
           [
               [A, B] <- [C],
               [C] <- [D, E],
               [E] <- [F],
               [D, F] <- [G],
           ],
           []
        };
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&[&nodes]);
        assert_eq!(dag.head().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["A", "B"],);
        assert_eq!(dag.tail().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["G"],);
        assert_eq!(
            dag.visited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A", "B", "C", "D", "E", "F", "G"],
        );
        assert_eq!(dag.missing().len(), 0);

        let dag_nodes = dag
            .index()
            .iter()
            .map(|(tid, node)| {
                (
                    *tid_to_name.get(tid).unwrap(),
                    (
                        node.prev().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
                        node.next().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
                    ),
                )
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(dag_nodes.len(), 7);
        assert_eq!(dag_nodes.get("A").unwrap(), &(vec![], vec!["C"]));
        assert_eq!(dag_nodes.get("B").unwrap(), &(vec![], vec!["C"]));
        assert_eq!(dag_nodes.get("C").unwrap(), &(vec!["A", "B"], vec!["D", "E"]));
        assert_eq!(dag_nodes.get("D").unwrap(), &(vec!["C"], vec!["G"]));
        assert_eq!(dag_nodes.get("E").unwrap(), &(vec!["C"], vec!["F"]));
        assert_eq!(dag_nodes.get("F").unwrap(), &(vec!["E"], vec!["G"]));
        assert_eq!(dag_nodes.get("G").unwrap(), &(vec!["D", "F"], vec![]));

        let mut visited = Vec::new();
        dag.walk(|node, ancestry, _| {
            visited.push((
                *tid_to_name.get(node.id()).unwrap(),
                ancestry.iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            ));
            Ok::<(), Error>(())
        })
        .unwrap();
        assert_eq!(
            visited,
            vec![
                ("A", vec!["A"]),
                ("B", vec!["B"]),
                ("C", vec!["A", "B", "C"]),
                ("D", vec!["A", "B", "C", "D"]),
                ("E", vec!["A", "B", "C", "E"]),
                ("F", vec!["A", "B", "C", "E"]),
                ("G", vec!["A", "B", "C", "D", "E", "G"]),
            ],
        );
    }

    // given the same set of transactions *but in a different order* the exact same DAG
    // structure should be returned.
    #[test]
    fn dag_from_nodes_walk_deterministic() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let mut rng = crate::util::test::rng_seeded(b"hi i'm butch");
        let (_master_key, identity, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
        #[allow(non_snake_case, unused_mut)]
        let (mut transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           identity,
           [A(0), B(1), C(2), D(3), E(4), F(5), G(6)],
           [
               [A, B] <- [C],
               [C] <- [D, E],
               [E] <- [F],
               [D, F] <- [G],
           ],
           []
        };
        transaction_list.sort_by_key(|x| x.id().clone());
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&[&nodes]);
        assert_eq!(dag.head().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["A", "B"],);
        assert_eq!(dag.tail().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["G"],);
        assert_eq!(
            dag.visited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A", "B", "C", "D", "E", "F", "G"],
        );
        assert_eq!(dag.missing().len(), 0);

        let dag_nodes = dag
            .index()
            .iter()
            .map(|(tid, node)| {
                (
                    *tid_to_name.get(tid).unwrap(),
                    (
                        node.prev().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
                        node.next().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
                    ),
                )
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(dag_nodes.len(), 7);
        assert_eq!(dag_nodes.get("A").unwrap(), &(vec![], vec!["C"]));
        assert_eq!(dag_nodes.get("B").unwrap(), &(vec![], vec!["C"]));
        assert_eq!(dag_nodes.get("C").unwrap(), &(vec!["A", "B"], vec!["D", "E"]));
        assert_eq!(dag_nodes.get("D").unwrap(), &(vec!["C"], vec!["G"]));
        assert_eq!(dag_nodes.get("E").unwrap(), &(vec!["C"], vec!["F"]));
        assert_eq!(dag_nodes.get("F").unwrap(), &(vec!["E"], vec!["G"]));
        assert_eq!(dag_nodes.get("G").unwrap(), &(vec!["D", "F"], vec![]));

        let mut visited = Vec::new();
        dag.walk(|node, ancestry, _| {
            visited.push((
                *tid_to_name.get(node.id()).unwrap(),
                ancestry.iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            ));
            Ok::<(), Error>(())
        })
        .unwrap();
        assert_eq!(
            visited,
            vec![
                ("A", vec!["A"]),
                ("B", vec!["B"]),
                ("C", vec!["A", "B", "C"]),
                ("D", vec!["A", "B", "C", "D"]),
                ("E", vec!["A", "B", "C", "E"]),
                ("F", vec!["A", "B", "C", "E"]),
                ("G", vec!["A", "B", "C", "D", "E", "G"]),
            ],
        );
    }

    #[test]
    fn dag_from_nodes_walk_missing() {
        let mut rng = crate::util::test::rng();
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let (_master_key, identity, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
        #[allow(non_snake_case, unused_mut)]
        let (mut transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           identity,
           [A(0), B(1), C(2), D(3), E(4), F(5), G(6)],
           [
               [A, B] <- [C],
               [C] <- [D, E],
               [E] <- [F],
               [D, F] <- [G],
           ],
           [C]  // remove C
        };
        transaction_list.sort_by_key(|x| x.id().clone());
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&[&nodes]);
        assert_eq!(dag.head().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["A", "B"],);
        assert_eq!(dag.tail().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["A", "B"],);
        assert_eq!(dag.visited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["A", "B"],);
        let mut unvisited = dag.unvisited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>();
        unvisited.sort_unstable();
        assert_eq!(unvisited, vec!["D", "E", "F", "G"],);
        assert_eq!(dag.missing().len(), 1);

        let dag_nodes = dag
            .index()
            .iter()
            .map(|(tid, node)| {
                (
                    *tid_to_name.get(tid).unwrap(),
                    (
                        node.prev().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
                        node.next().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
                    ),
                )
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(dag_nodes.len(), 6);
        assert_eq!(dag_nodes.get("A").unwrap(), &(vec![], vec![]));
        assert_eq!(dag_nodes.get("B").unwrap(), &(vec![], vec![]));
        assert_eq!(dag_nodes.get("C"), None);
        assert_eq!(dag_nodes.get("D").unwrap(), &(vec!["C"], vec!["G"]));
        assert_eq!(dag_nodes.get("E").unwrap(), &(vec!["C"], vec!["F"]));
        assert_eq!(dag_nodes.get("F").unwrap(), &(vec!["E"], vec!["G"]));
        assert_eq!(dag_nodes.get("G").unwrap(), &(vec!["D", "F"], vec![]));

        let mut visited = Vec::new();
        dag.walk(|node, ancestry, _| {
            visited.push((
                *tid_to_name.get(node.id()).unwrap(),
                ancestry.iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            ));
            Ok::<(), Error>(())
        })
        .unwrap();
        assert_eq!(visited, vec![("A", vec!["A"]), ("B", vec!["B"])]);
    }

    #[test]
    fn dag_from_nodes_walk_node_order() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let mut rng = crate::util::test::rng_seeded(b"HI i'm Butch");
        let (_master_key, identity, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
        #[allow(non_snake_case, unused_mut)]
        let (mut transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           identity,
           // set up a chain where B's timestamp comes after C, which means if we sort just be
           // timestamp then the causal chain will break. however, if we sort by causal chain THEN
           // timestamp when running identity, we're gonna have a good time.
           //
           // note that A and E have the same timestamp. with our deterministic identity, we've
           // created a situation where E's ID is lower than A's. thus, E should come before A in
           // the sort.
           [A(0), B(20), C(10), D(30), E(0), F(15), G(16), H(5)],
           [
               [A] <- [B],
               [B] <- [C],
               [C] <- [D],
               [E] <- [F],
               [F] <- [G],
               [D, G] <- [H],
           ],
           []
        };
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&[&nodes]);
        assert_eq!(
            dag.visited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["E", "A", "F", "G", "B", "C", "D", "H"],
        );
        let mut visited = Vec::new();
        dag.walk(|node, _ancestry, _anc_idx| {
            visited.push(*node.id());
            Ok::<(), Error>(())
        })
        .unwrap();
        assert_eq!(
            visited.iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["E", "A", "F", "G", "B", "C", "D", "H"],
        );
    }

    #[test]
    fn dag_from_nodes_walk_complex_branch() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let mut rng = crate::util::test::rng_seeded(b"hi I'm Butch.");
        let (_master_key, identity, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
        #[allow(non_snake_case, unused_mut)]
        let (mut transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           identity,
           [A(0), B(20), C(10), D(30), E(0), F(15), G(16), H(5), I(6), J(2), K(22), L(30), M(20), N(20), O(0), P(13), Q(24)],
           [
               [A] <- [B],
               [B] <- [C, D, E],
               [A, C] <- [F, G],
               [D] <- [H, I],
               [E] <- [J],
               [H, I, J] <- [K],
               [F] <- [L],
               [G, K, L] <- [M],
               [M, L] <- [N],
               [M] <- [O],
               [N] <- [P],
               [P] <- [Q],
           ],
           []
        };
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&[&nodes]);
        assert_eq!(dag.head().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["A"],);
        assert_eq!(dag.tail().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["O", "Q"],);
        assert_eq!(
            dag.visited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A", "B", "E", "J", "C", "F", "G", "D", "H", "I", "K", "L", "M", "O", "N", "P", "Q"],
        );
        assert_eq!(
            dag.unvisited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            Vec::<&'static str>::new(),
        );
        assert_eq!(dag.missing.len(), 0);
        let mut visited = Vec::new();
        dag.walk(|node, ancestry, idx| {
            visited.push((
                *node.id(),
                ancestry.iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
                idx.get(node.id()).map(|x| x.as_slice()) == Some(ancestry),
            ));
            Ok::<(), Error>(())
        })
        .unwrap();
        assert_eq!(
            visited
                .into_iter()
                .map(|(tid, ancestry, eq)| (*tid_to_name.get(tid).unwrap(), ancestry, eq))
                .collect::<Vec<_>>(),
            vec![
                ("A", vec!["A"], true),
                ("B", vec!["A", "B"], true),
                ("E", vec!["A", "B", "E"], true),
                ("J", vec!["A", "B", "E"], true),
                ("C", vec!["A", "B", "C"], true),
                ("F", vec!["A", "B", "C", "F"], true),
                ("G", vec!["A", "B", "C", "G"], true),
                ("D", vec!["A", "B", "D"], true),
                ("H", vec!["A", "B", "D", "H"], true),
                ("I", vec!["A", "B", "D", "I"], true),
                ("K", vec!["A", "B", "E", "D", "H", "I", "K"], true),
                ("L", vec!["A", "B", "C", "F"], true),
                ("M", vec!["A", "B", "E", "C", "F", "G", "D", "H", "I", "K", "M"], true),
                ("O", vec!["A", "B", "E", "C", "F", "G", "D", "H", "I", "K", "M", "O"], true),
                ("N", vec!["A", "B", "E", "C", "F", "G", "D", "H", "I", "K", "M", "N"], true),
                ("P", vec!["A", "B", "E", "C", "F", "G", "D", "H", "I", "K", "M", "N"], true),
                ("Q", vec!["A", "B", "E", "C", "F", "G", "D", "H", "I", "K", "M", "N"], true),
            ],
        )
    }

    #[test]
    fn dag_from_nodes_duplicate_links() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let mut rng = crate::util::test::rng_seeded(b"Hi I'm Butch");
        let (_master_key, identity, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
        #[allow(non_snake_case, unused_mut)]
        let (mut transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           identity,
           [A(0), B(10), C(20)],
           [
               [A] <- [B],
               [A] <- [B],
               [B] <- [C],
           ],
           []
        };
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&[&nodes]);
        assert_eq!(dag.head().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["A"],);
        assert_eq!(dag.tail().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["C"],);
        assert_eq!(dag.visited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(), vec!["A", "B", "C"],);
        assert_eq!(
            dag.unvisited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            Vec::<&'static str>::new(),
        );
        assert_eq!(dag.missing.len(), 0);
        let mut visited = Vec::new();
        dag.walk(|node, ancestry, idx| {
            visited.push((*node.id(), Vec::from(ancestry), idx.get(node.id()).map(|x| x.as_slice()) == Some(ancestry)));
            Ok::<(), Error>(())
        })
        .unwrap();
        assert_eq!(
            visited
                .into_iter()
                .map(|(tid, ancestry, eq)| (
                    *tid_to_name.get(tid).unwrap(),
                    ancestry.iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
                    eq
                ))
                .collect::<Vec<_>>(),
            vec![("A", vec!["A"], true), ("B", vec!["A"], true), ("C", vec!["A"], true),],
        )
    }

    #[test]
    fn dag_multiple_node_sources() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let mut rng = crate::util::test::rng_seeded(b"Hi I'm Butch");
        let (_master_key, identity, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
        #[allow(non_snake_case, unused_mut)]
        let (transaction_list1, tid_to_name1, _name_to_tid) = make_dag_chain! {
           identity,
           [A(0), B(10), C(20)],
           [
               [A] <- [B],
               [B] <- [C],
           ],
           []
        };
        let (transaction_list2, tid_to_name2, _name_to_tid) = make_dag_chain! {
           identity,
           [D(5), E(40), F(40)],
           [
               [D] <- [E, F],
               [E] <- [F],
           ],
           []
        };
        let nodes1 = transaction_list1.iter().map(|x| x.into()).collect::<Vec<_>>();
        let nodes2 = transaction_list2.iter().map(|x| x.into()).collect::<Vec<_>>();
        let dag: Dag<TransactionID, Transaction<Full>> = Dag::from_nodes(&[&nodes1[..], &nodes2[..]]);
        assert_eq!(
            dag.visited()
                .iter()
                .map(|tid| *tid_to_name1.get(tid).or_else(|| tid_to_name2.get(tid)).unwrap())
                .collect::<Vec<_>>(),
            vec!["A", "D", "B", "C", "E", "F"],
        )
    }

    #[test]
    fn dag_get_causal_chain() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let mut rng = crate::util::test::rng_seeded(b"Hi I'm Butch");
        let (_master_key, identity, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
        #[allow(non_snake_case, unused_mut)]
        let (transaction_list, tid_to_name, name_to_tid) = make_dag_chain! {
           identity,
           [A(0), B(10), C(20), D(30), E(29), F(40), G(42), H(69)],
           [
               [A] <- [B, C],
               [B] <- [C],
               [B] <- [D],
               [D] <- [E, F],
               [A] <- [G],
               [F, G] <- [H],
           ],
           []
        };
        let nodes = transaction_list.iter().map(|x| x.into()).collect::<Vec<_>>();
        let dag: Dag<TransactionID, Transaction<Full>> = Dag::from_nodes(&[&nodes]);

        macro_rules! get_chain {
            ($node_name:expr) => {{
                dag.get_causal_chain(name_to_tid.get($node_name).unwrap())
                    .into_iter()
                    .map(|id| tid_to_name.get(id).unwrap())
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
            }};
        }

        assert_eq!(get_chain!("A"), vec!["A"]);
        assert_eq!(get_chain!("G"), vec!["A", "G"]);
        assert_eq!(get_chain!("H"), vec!["A", "B", "D", "F", "G", "H"]);
        assert_eq!(get_chain!("E"), vec!["A", "B", "D", "E"]);
        assert_eq!(get_chain!("C"), vec!["A", "B", "C"]);
    }

    /// A simple transaction operation. Can allow even numbers, block even numbers, and increment
    /// the state by some value.
    #[derive(Clone, Debug)]
    enum TransOp {
        AllowEven,
        BlockEven,
        Inc(u32),
    }

    /// A painfully simple transaction for constructing DAGs and allowing maintaining a state.
    #[derive(Clone, Debug)]
    struct Trans {
        id: TransactionID,
        created: Timestamp,
        prev: Vec<TransactionID>,
        op: TransOp,
    }

    impl Trans {
        fn new<R: crate::crypto::base::rng::RngCore + crate::crypto::base::rng::CryptoRng>(
            rng: &mut R,
            created: &str,
            prev: Vec<&Trans>,
            op: TransOp,
        ) -> Self {
            let mut randbuf = [0u8; 32];
            rng.fill_bytes(&mut randbuf);
            let created = Timestamp::from_str(created).unwrap();
            let prev = prev.into_iter().map(|t| t.id.clone()).collect::<Vec<_>>();
            Self {
                id: TransactionID::from(crate::crypto::base::Hash::new_blake3_from_bytes(randbuf)),
                created,
                prev,
                op,
            }
        }
    }

    impl<'a> From<&'a Trans> for DagNode<'a, TransactionID, Trans> {
        fn from(t: &'a Trans) -> Self {
            DagNode::new(&t.id, t, t.prev.iter().collect::<Vec<_>>(), &t.created)
        }
    }

    /// A state object that can be updated via transactions in our heroic DAG.
    #[derive(Clone, Debug)]
    struct State {
        allow_even: bool,
        val: u32,
    }

    impl State {
        fn from_trans(trans: &Trans) -> Self {
            match trans.op {
                TransOp::AllowEven => Self { allow_even: true, val: 0 },
                TransOp::BlockEven => Self { allow_even: false, val: 0 },
                TransOp::Inc(val) => Self { allow_even: true, val },
            }
        }

        fn validate(&self, transaction: &Trans) -> crate::error::Result<()> {
            if let TransOp::Inc(val) = transaction.op {
                if !self.allow_even && (val & 1) == 0 {
                    Err(crate::error::Error::TransactionInvalid(transaction.id.clone(), String::from("no evens!")))?;
                }
            }
            Ok(())
        }

        fn apply(&mut self, transaction: &Trans) -> crate::error::Result<()> {
            match transaction.op {
                TransOp::AllowEven => {
                    self.allow_even = true;
                }
                TransOp::BlockEven => {
                    self.allow_even = false;
                }
                TransOp::Inc(val) => {
                    self.val += val;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn dag_multiple_node_sources_order_precedence() {
        let mut rng = crate::util::test::rng_seeded(b"i got a question about you, mortician...");
        //   A
        //  / \
        // B   C
        //  \ /
        //   D
        let trans_a = Trans::new(&mut rng, "2047-12-01T00:00:00Z", vec![], TransOp::BlockEven);
        let trans_b = Trans::new(&mut rng, "2047-12-02T00:00:00Z", vec![&trans_a], TransOp::Inc(3));
        let trans_c = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_a], TransOp::Inc(7));
        let trans_d = Trans::new(&mut rng, "2047-12-03T00:00:03Z", vec![&trans_c, &trans_b], TransOp::Inc(4));

        let mut trans_c_mod = trans_c.clone();
        //   A
        //   |
        //   B
        //  / \
        // C   |
        //  \ /
        //   D
        trans_c_mod.prev = vec![trans_b.id.clone()];
        let list1 = vec![trans_a.clone(), trans_b.clone(), trans_c.clone()];
        let list2 = [trans_c_mod.clone(), trans_d.clone()];

        let nodes1 = list1.iter().map(|x| x.into()).collect::<Vec<_>>();
        let nodes2 = list2.iter().map(|x| x.into()).collect::<Vec<_>>();
        // dag1 should have order A, C, B, D
        let dag1: Dag<TransactionID, Trans> = Dag::from_nodes(&[&nodes2, &nodes1]);
        // dag2 should have order A, B, C, D
        let dag2: Dag<TransactionID, Trans> = Dag::from_nodes(&[&nodes1, &nodes2]);

        assert_eq!(dag1.visited(), &vec![&trans_a.id, &trans_c.id, &trans_b.id, &trans_d.id]);
        assert_eq!(dag1.index().get(&trans_c.id).unwrap().prev(), &vec![&trans_a.id]);
        assert_eq!(dag2.visited(), &vec![&trans_a.id, &trans_b.id, &trans_c.id, &trans_d.id]);
        assert_eq!(dag2.index().get(&trans_c.id).unwrap().prev(), &vec![&trans_b.id]);
    }

    #[test]
    fn dag_apply_branch_validation() {
        // test some basic validation failures
        {
            let mut rng = crate::util::test::rng_seeded(b"i got a question about you, mortician...");
            let trans_a = Trans::new(&mut rng, "2047-12-01T00:00:00Z", vec![], TransOp::BlockEven);
            let trans_b = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_a], TransOp::Inc(7));
            let trans_c = Trans::new(&mut rng, "2047-12-01T00:00:03Z", vec![&trans_b], TransOp::Inc(4));

            let transactions = vec![trans_a, trans_b, trans_c.clone()];
            let nodes = transactions.iter().map(|x| x.into()).collect::<Vec<_>>();
            let dag: Dag<TransactionID, Trans> = Dag::from_nodes(&[&nodes]);
            let mut state_tracker: HashMap<TransactionID, State> = HashMap::new();
            let res = dag.apply(
                &mut state_tracker,
                |node| Ok(State::from_trans(node.node())),
                |_| false,
                |state, node| state.validate(node.node()),
                |state, node| state.apply(node.node()),
            );
            match res {
                Err(Error::TransactionInvalid(ref id, ..)) => {
                    assert_eq!(id, &trans_c.id);
                }
                _ => panic!("unexpected error: {res:?}"),
            }
        }

        // now test what happens if validation takes competing branches/paths and our state
        // diverges as a result. what then?!?!
        fn run<R: crate::crypto::base::rng::RngCore + crate::crypto::base::rng::CryptoRng>(rng: &mut R) {
            let trans_a = Trans::new(rng, "2047-12-01T00:00:00Z", vec![], TransOp::AllowEven);
            let trans_b = Trans::new(rng, "2047-12-01T00:00:02Z", vec![&trans_a], TransOp::BlockEven);
            let trans_c = Trans::new(rng, "2047-12-01T00:00:02Z", vec![&trans_a], TransOp::Inc(4));
            let trans_d = Trans::new(rng, "2047-12-01T00:00:02Z", vec![&trans_c], TransOp::Inc(6));
            let trans_e = Trans::new(rng, "2047-12-01T00:00:02Z", vec![&trans_b, &trans_d], TransOp::Inc(7));

            let transactions = vec![trans_a, trans_b, trans_c, trans_d, trans_e];
            let nodes = transactions.iter().map(|x| x.into()).collect::<Vec<_>>();
            let dag: Dag<TransactionID, Trans> = Dag::from_nodes(&[&nodes]);

            let mut state_tracker: HashMap<TransactionID, State> = HashMap::new();
            let state = dag
                .apply(
                    &mut state_tracker,
                    |node| Ok(State::from_trans(node.node())),
                    |_| false,
                    |state, node| state.validate(node.node()),
                    |state, node| state.apply(node.node()),
                )
                .expect("dag applies properly");
            assert_eq!(state.val, 17);
        }
        // run our tests with a new random state each time, trying to make sure ordering via
        // transaction ID has no bearing
        let mut rng = crate::util::test::rng_seeded(b"Hi I'm Butch");
        for _ in 0..1000 {
            run(&mut rng);
        }
    }

    #[test]
    fn dag_apply_skip() {
        let mut rng = crate::util::test::rng_seeded(b"Hi I'm Butch");
        let trans_a = Trans::new(&mut rng, "2047-12-01T00:00:00Z", vec![], TransOp::BlockEven);
        let trans_b = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_a], TransOp::AllowEven);
        let trans_c = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_a], TransOp::BlockEven);
        let trans_d = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_b], TransOp::Inc(2));
        let trans_e = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_b], TransOp::Inc(6));
        let trans_f = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_d, &trans_e], TransOp::Inc(2));
        let trans_g = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_f, &trans_c], TransOp::Inc(7));

        let transactions = vec![trans_a, trans_b, trans_c, trans_d, trans_e, trans_f, trans_g];
        let mut state_tracker: HashMap<TransactionID, State> = HashMap::new();

        {
            // grab a few nodes and run them.
            let nodes = transactions[0..4].iter().map(|x| x.into()).collect::<Vec<_>>();
            let dag: Dag<TransactionID, Trans> = Dag::from_nodes(&[&nodes]);
            let num_validate = std::cell::RefCell::new(0);
            let state = dag
                .apply(
                    &mut state_tracker,
                    |node| Ok(State::from_trans(node.node())),
                    |_| false,
                    |state, node| {
                        (*num_validate.borrow_mut()) += 1;
                        state.validate(node.node())
                    },
                    |state, node| state.apply(node.node()),
                )
                .expect("dag applies properly");
            assert_eq!(state.val, 2);
            assert_eq!(num_validate.take(), 4);
        }
        {
            // grab the rest of the nodes and run them, making sure to mark the nodes we already
            // ran above as skips. we also use the same state object as the last run, so we
            // build onto our existing state. this lets us stream in new transactions to a saved
            // state without having to re-run/re-build our entire state front the back.
            let nodes = transactions.iter().map(|x| x.into()).collect::<Vec<_>>();
            let skip = transactions[0..4].iter().map(|x| x.id.clone()).collect::<HashSet<_>>();
            let dag: Dag<TransactionID, Trans> = Dag::from_nodes(&[&nodes]);
            let num_validate = std::cell::RefCell::new(0);
            let state = dag
                .apply(
                    &mut state_tracker,
                    |node| Ok(State::from_trans(node.node())),
                    |node| skip.contains(node.id()),
                    |state, node| {
                        (*num_validate.borrow_mut()) += 1;
                        state.validate(node.node())
                    },
                    |state, node| state.apply(node.node()),
                )
                .expect("dag applies properly");
            assert_eq!(state.val, 17);
            assert_eq!(num_validate.take(), 3);
        }
    }

    #[test]
    fn dag_apply_merge_then_branch() {
        let mut rng = crate::util::test::rng_seeded(b"Hi I'm Butch");
        let trans_a = Trans::new(&mut rng, "2047-12-01T00:00:00Z", vec![], TransOp::AllowEven);
        let trans_b = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_a], TransOp::Inc(1));
        let trans_c = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_a], TransOp::Inc(1));
        // merge, then immediately branch.
        let trans_d = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_b, &trans_c], TransOp::Inc(2));
        let trans_e = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_d], TransOp::Inc(6));
        let trans_f = Trans::new(&mut rng, "2047-12-01T00:00:02Z", vec![&trans_d], TransOp::Inc(2));

        let transactions = vec![trans_a, trans_b, trans_c, trans_d, trans_e, trans_f];
        let mut state_tracker: HashMap<TransactionID, State> = HashMap::new();

        {
            let nodes = transactions.iter().map(|x| x.into()).collect::<Vec<_>>();
            let dag: Dag<TransactionID, Trans> = Dag::from_nodes(&[&nodes]);
            let state = dag
                .apply(
                    &mut state_tracker,
                    |node| Ok(State::from_trans(node.node())),
                    |_| false,
                    |state, node| state.validate(node.node()),
                    |state, node| state.apply(node.node()),
                )
                .expect("dag should allow branch after merge");
            assert_eq!(state.val, 12);
        }
    }
}
