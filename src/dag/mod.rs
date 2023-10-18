//! A DAG, or directed acyclic graph, allows us to represent our identity as an
//! ordered list of signed changes, as opposed to a singular object. There are
//! pros and cons to both methods, but for the purposes of this project, a
//! tree of signed transactions that link back to previous changes provides a
//! good amount of security, auditability, and syncability.
//!
//! This module contains general utilities for working with DAGs in the context of Stamp
//! transactions. They are less concerned with verifying transaction validity and more so focused
//! on providing functions for traversing DAGs and running their nodes in order.

mod transaction;
mod transactions;

pub use crate::{
    dag::{
        transaction::{
            TransactionBody,
            TransactionID,
            TransactionEntry,
            Transaction,
        },
        transactions::{
            Transactions,
        },
    },
    error::{Error, Result},
};
use getset::{Getters, MutGetters};
use std::collections::{HashMap, HashSet};

/// Defines a node in a DAG. Each node can have multiple previous nodes and multiple next nodes.
/// It's crazy out here.
#[derive(Clone, Debug, PartialEq, Getters, MutGetters)]
#[getset(get = "pub", get_mut = "pub(crate)")]
pub struct DagNode {
    /// The nodes that came before this one
    prev: Vec<TransactionID>,
    /// The nodes that come after this one
    next: Vec<TransactionID>,
    /// The transaction this node points to.
    transaction_id: TransactionID,
}

impl DagNode {
    fn new_with_prev(transaction_id: TransactionID, prev: Vec<TransactionID>) -> Self {
        Self {
            prev,
            next: Vec::new(),
            transaction_id,
        }
    }
}

/// Allows modeling a DAG (directed acyclic graph) using a linked list-ish structure that can be
/// traversed both forward and back.
#[derive(Clone, Debug, Default, PartialEq, Getters, MutGetters)]
#[getset(get = "pub", get_mut = "pub(crate)")]
pub struct Dag {
    /// The head/start of the DAG. Can be multiple nodes because technically we can start with
    /// "conflicting" branches. In the case of Stamp DAGs, this is not true: we must have *one
    /// single start transaction* (the genesis) and this will be enforced. However, for other DAGs
    /// that might use Stamp as a medium, we cannot assume they will always start out with only one
    /// single transaction that all others branch from.
    head: Vec<TransactionID>,
    /// The tail/end of our DAG. This is any transactions that are not listed in some known
    /// transaction's `previous_transactions` list.
    tail: Vec<TransactionID>,
    /// Holds an index of transaction IDs to internal DAG nodes
    index: HashMap<TransactionID, DagNode>,
    /// Transactions that we processed while walking the DAG. If this has less transactions in it
    /// than the `index` then it means we have a broken chain and/or a circular reference
    /// somewhere. In a healthy DAG, `visited` and `index` will have the same number of entries.
    visited: HashSet<TransactionID>,
    /// Transactions that we don't have in our `index` but were referenced while building the DAG.
    /// These generally represent transactions that we are waiting to sync on and are "breaking the
    /// chain" so to speak.
    missing: HashSet<TransactionID>,
}

impl Dag {
    /// Takes a flat list of transactions and returns a set of DAGs that model those transactions.
    pub fn from_transactions(transactions: &Vec<Transaction>) -> Dag {
        // create our DAG object.
        let mut dag = Dag::default();

        // index our transactions into the DAG.
        for trans in transactions {
            dag.index_mut().insert(trans.id().clone(), DagNode::new_with_prev(trans.id().clone(), trans.entry().previous_transactions().clone()));
        }

        // holds locations at which our chain breaks, ie we reference a transaction that cannot be
        // found. this helps us split up our DAGs later on.
        let mut missing_transactions = HashSet::new();

        // now loop over our transactions again and update our .next[] references.
        // after this, we'll have both forward and backward links for all available transactions.
        for trans in transactions {
            let prev = trans.entry().previous_transactions();
            if prev.len() == 0 {
                // cool, we found a head node. track it.
                dag.head_mut().push(trans.id().clone());
            } else {
                for prev_id in prev {
                    match dag.index_mut().get_mut(&prev_id) {
                        Some(previous_node) => {
                            previous_node.next_mut().push(trans.id().clone());
                        }
                        None => {
                            // we're referencing a node we cannot find. this means we have a break in
                            // our DAG chain
                            missing_transactions.insert(prev_id.clone());
                        }
                    }
                }
            }
        }

        // walk our dag and look for tail nodes and problems (missing nodes, circular links, etc)
        let mut tail_nodes = Vec::new();
        let (visited, missing) = dag.walk(|node, ancestry| {
            println!("- walk: {} -- {:?}", node.transaction_id(), ancestry);
            if node.next().len() == 0 {
                tail_nodes.push(node.transaction_id().clone());
            }
        });
        for entry in missing {
            missing_transactions.insert(entry);
        }
        dag.visited = visited;
        dag.missing = missing_transactions;
        dag.tail = tail_nodes;
        dag
    }

    /// Walk the DAG, starting from the head, and running a function on each node in-order.
    ///
    /// If we hit a merge, we don't continue past the merge of the branches until each of the
    /// branches has run. This also tracks branches and merges via a numeric value assigned to each
    /// branch/merge, passing these branch IDs in as a list, allowing the op fn to have a sense of
    /// ancestry (with the current/most recent branch being last in the list).
    ///
    /// The way that branches/merges are handled also happens to somewhat gracefully deal with
    /// circular references as well (AKA a G instead of a DAG)...circular references are not
    /// possible without merges that reference future transactions, so we'll effectively just
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
    /// And so these are the things we return. In that order.
    pub fn walk<F>(&self, opfn: F) -> (HashSet<TransactionID>, HashSet<TransactionID>)
        where F: FnMut(&DagNode, &Vec<u32>),
    {
        /// A state object to help us track our DAG walk
        struct WalkState<'a, F> {
            cur_branch: u32,
            index: &'a HashMap<TransactionID, DagNode>,
            visited: HashSet<TransactionID>,
            missing_transactions: HashSet<TransactionID>,
            branch_tracker: HashMap<&'a TransactionID, Vec<u32>>,
            opfn: F,
        }

        impl<'a, F> WalkState<'a, F>
            where F: FnMut(&'a DagNode, &Vec<u32>),
        {
            /// Create a new state.
            fn new(index: &'a HashMap<TransactionID, DagNode>, opfn: F) -> Self {
                WalkState {
                    cur_branch: 0,
                    index,
                    visited: Default::default(),
                    missing_transactions: Default::default(),
                    branch_tracker: Default::default(),
                    opfn,
                }
            }

            /// Increments our branch number and returns the original.
            fn next_branch(&mut self) -> u32 {
                let branch_num = self.cur_branch;
                // add one to cur_branch
                self.cur_branch += 1;
                branch_num
            }

            /// Helps us merge branches into one transaction, tracking our ancestors as we go.
            fn merge_branch(&mut self, mut ancestors: Vec<u32>, transaction_id: &TransactionID) -> Vec<u32> {
                if let Some(prev_ancestors) = self.branch_tracker.remove(transaction_id) {
                    for ancestor in prev_ancestors {
                        ancestors.push(ancestor);
                    }
                }
                ancestors.push(self.next_branch());
                ancestors.sort();
                ancestors.dedup();
                ancestors
            }

            /// This recursive function does all our dirty work. Such a dirty boy.
            ///
            /// This walks the DAG, following branches it finds until a merge, at which point it
            /// waits for all the other branches going into that merge to be run before continuing.
            /// In effect, this runs our `opfn()` function for each transaction branch in order.
            fn visit(&mut self, transaction_id: &'a TransactionID, ancestry: &Vec<u32>) {
                // find the DagNode associated with this transaction ID. if we don't have one, mark
                // it as missing and move on with life.
                let node = match self.index.get(transaction_id) {
                    Some(node) => node,
                    None => {
                        self.missing_transactions.insert(transaction_id.clone());
                        return;
                    }
                };

                // clone the ancestry we were given. it's ours now.
                let mut ancestry = ancestry.clone();

                // if we have more than one previous node, we need to determine if all the previous
                // nodes have already been visited. if not, we cannot "run" this node yet. so stop
                // asking.
                if node.prev().len() > 1 {
                    let mut all_prev_nodes_visited = true;
                    for prev in node.prev() {
                        if self.visited.get(prev).is_none() {
                            all_prev_nodes_visited = false;
                        }
                    }

                    if !all_prev_nodes_visited {
                        // push our ancestors into a temporary holding location until this
                        // transaction is ready to merge. effectively, this allows us to track
                        // which branches got us to this point so that when the merge happens, it
                        // can note ALL the ancestors that fed into it, not just the one that
                        // triggered the final merge.
                        //
                        // note that we don't care about order or dupes here. this will be fixed
                        // and we have people that do these things for us. the best people. see
                        // `WalkState.merge_branch()`
                        let entry = self.branch_tracker.entry(transaction_id).or_insert(Vec::new());
                        for x in ancestry {
                            entry.push(x);
                        }
                        // we can't run this node, so go running back up the stack to mommy.
                        return;
                    }

                    // we can run this node!
                    //
                    // so what we're going to do is create a new branch for this merge, then merge
                    // all the ancestors of the branches that fed into this node into one ancestor
                    // set which is what `merge_branch()` does for us.
                    ancestry = self.merge_branch(ancestry, transaction_id);
                }

                // ok at this point we're ready to run our node, so we mark it as visited (as one
                // might do) and run our heroic opfn(), passing it the node and the ancestry.
                self.visited.insert(node.transaction_id().clone());
                (self.opfn)(node, &ancestry);

                // now recurth uhhhhuhuhuhuh.
                let next_len = node.next().len();
                for trans_id in node.next() {
                    // clone our ancestry *again* (sorry) since each next node will potentially get
                    // its own unique copy
                    let mut ancestry_next = ancestry.clone();
                    // if we have more than one next node, each one should get a new branch num
                    // assigned to it, so we push that onto the end of our ancestry. if we only
                    // have one next node, it should have the same branch number as the current
                    // node, so we don't futz with ancestry at all.
                    if next_len > 1 {
                        ancestry_next.push(self.next_branch());
                    }
                    // now do it all again on the next node!!!1
                    self.visit(trans_id, &ancestry_next);
                }
            }
        }

        let mut state = WalkState::new(self.index(), opfn);
        // loop over each of the nodes in our DAG head and run our visitor on them. each one gets a
        // unique branch id.
        for trans_id in self.head() {
            let ancestry = vec![state.next_branch()];
            state.visit(trans_id, &ancestry);
        }
        // grab the important stuff and .. the rest into stack-allocated oblivion
        let WalkState { visited, missing_transactions, .. } = state;
        (visited, missing_transactions)
    }

    /// Given a set of nodes visited from [`Dag::walk()`], find the nodes that are unvisited from
    /// that walk (ie, any known nodes we didn't walk to).
    pub fn find_unvisited(&self) -> HashSet<TransactionID> {
        let mut unvisited = HashSet::new();
        for trans_id in self.index().keys() {
            if !self.visited().contains(trans_id) {
                unvisited.insert(trans_id.clone());
            }
        }
        unvisited
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::base::HashAlgo,
        util::{
            Timestamp,
            ser::{BinaryVec, HashMapAsn1}
        }
    };

    macro_rules! make_chain {
        (
            $transactions:expr,
            [$($names:ident),*],
            [$([$($from:ident),*] <- [$($to:ident),*],)*],
            [$($omit:ident),*]
        ) => {{
            let trans = &$transactions;
            $(
                let mut $names = trans.ext(&HashAlgo::Blake2b256, Timestamp::now(), vec![], None, None::<HashMapAsn1<BinaryVec, BinaryVec>>, Vec::from(format!("{} HERE", stringify!($names)).as_bytes()).into()).unwrap();
                $names.entry_mut().set_previous_transactions(vec![]);
            )*
            $(
                {
                    let from = vec![$($from.id().clone()),*];
                    $(
                        // note that we can override the previous transactions without re-signing
                        // here because we don't verify sigs at all for these tests
                        for prev in &from {
                            $to.entry_mut().previous_transactions_mut().push(prev.clone());
                        }
                    )*
                }
            )*
            let omit = vec![$($omit.id().clone()),*];
            let mut ret = vec![$($names),*];
            ret.retain(|x| !omit.contains(x.id()));
            ret
        }}
    }

    #[test]
    fn order_dag_works() {
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity(Timestamp::now());
        #[allow(non_snake_case, unused_mut)]
        //let transaction_list = make_chain! {
           //transactions,
           //[A, B, C, D, E, F, G],
           //[
               //[A, B] <- [C],
               //[C] <- [D, E],
               //[E] <- [F],
               //[D, F] <- [G],
           //],
           //[]
        //};
        let transaction_list = make_chain! {
          transactions,
          [A, B, C, D, E, F, G],
          [
              [A, B] <- [C],
              [C] <- [D],
              [D] <- [E],
              [E] <- [F, G],
          ],
          []
        };
        //let transaction_list = make_chain! {
           //transactions,
           //[A, B, C, D],
           //[
               //[A] <- [B],
               //[B] <- [C],
               //[C] <- [D],
           //],
           //[C]
        //};
        println!("--- transaction chain ---");
        for trans in &transaction_list {
            println!("{}", trans.id());
            for prev in trans.entry().previous_transactions() {
                println!("  > {}", prev);
            }
        }
        println!("---");
        let dag = Dag::from_transactions(&transaction_list);
        println!("{:?}", dag);
    }

    // given the same set of transactions *but in a different order* the exact same DAG
    // structure should be returned.
    #[test]
    fn order_dag_deterministic() {
        todo!();
    }
}

