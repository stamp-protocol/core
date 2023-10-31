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
    util::Timestamp,
};
use getset::{Getters, MutGetters};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Defines a node in a DAG. Each node can have multiple previous nodes and multiple next nodes.
/// It's crazy out here.
#[derive(Clone, Debug, Getters, MutGetters)]
#[getset(get = "pub", get_mut = "pub(crate)")]
pub struct DagNode<'a> {
    /// The nodes that came before this one
    prev: Vec<&'a TransactionID>,
    /// The nodes that come after this one
    next: Vec<&'a TransactionID>,
    /// The transaction this node points to.
    transaction: &'a Transaction,
}

impl<'a> DagNode<'a> {
    fn new_from_transaction(transaction: &'a Transaction) -> Self {
        Self {
            prev: transaction.entry().previous_transactions().iter().collect::<Vec<_>>(),
            next: Vec::new(),
            transaction,
        }
    }
}

/// Allows modeling a DAG (directed acyclic graph) using a linked list-ish structure that can be
/// traversed both forward and back.
#[derive(Clone, Debug, Default, Getters, MutGetters)]
#[getset(get = "pub", get_mut = "pub(crate)")]
pub struct Dag<'a> {
    /// The head/start of the DAG. Can be multiple nodes because technically we can start with
    /// "conflicting" branches. In the case of Stamp DAGs, this is not true: we must have *one
    /// single start transaction* (the genesis) and this will be enforced. However, for other DAGs
    /// that might use Stamp as a medium, we cannot assume they will always start out with only one
    /// single transaction that all others branch from.
    head: Vec<TransactionID>,
    /// The tail/end of our DAG. This is any transactions that are not listed in some known
    /// transaction's `previous_transactions` list.
    tail: Vec<TransactionID>,
    /// Holds an index of transaction IDs to internal DAG nodes. This is useful because instead of
    /// DAG nodes referencing each other directly and having to have Box<Blah> everywhere, we just
    /// store the IDs and put the nodes in one single lookup table.
    index: HashMap<TransactionID, DagNode<'a>>,
    /// Transactions that we processed while walking the DAG, in the order they were processed.
    /// If this has less transactions in it than the `index` then it means we have a broken chain
    /// and/or a circular reference somewhere. In a healthy DAG, `visited` and `index` will have
    /// the same number of entries.
    visited: Vec<TransactionID>,
    /// Transactions that were not processed while creating the DAG. This is generally because of
    /// missing links or missing transactions in the chain. This will be mutually exclusive from
    /// `missing`, so to get *all unprocessed transactions* you would combine the sets.
    unvisited: HashSet<TransactionID>,
    /// Transactions that we don't have in our `index` but were referenced while building the DAG.
    /// These generally represent transactions that we are waiting to sync on and are "breaking the
    /// chain" so to speak.
    missing: HashSet<TransactionID>,
}

impl<'a> Dag<'a> {
    /// Takes a flat list of transactions and returns a set of DAGs that model those transactions.
    pub fn from_transactions(transactions: &[&'a Transaction]) -> Dag<'a> {
        // create our DAG object.
        let mut dag = Dag::default();

        // index our transactions into the DAG.
        for trans in transactions {
            dag.index_mut().insert(trans.id().clone(), DagNode::new_from_transaction(trans));
        }

        // holds locations at which our chain breaks, ie we reference a transaction that cannot be
        // found. this helps us split up our DAGs later on.
        let mut missing_transactions = HashSet::new();

        // stores transactions we encounter that have no previous transactions (ie, they start the
        // DAG). we make a separate container instead of pushing directly into `dag.head` because
        // we need to also push in the transaction's timestamp, which dag.head doesn't care about.
        // we do this so we can sort by timestamp before processing the dag, with the goal of
        // getting deterministic outputs in our final DAG object regardless of the order of
        // transactions passed in.
        let mut head_transactions = Vec::new();

        // this is a temporary index that stores &TransactionID -> &Timestamp lookups, allowing us
        // to iterate and sort the `next` elements for each DAG node.
        let mut trans_created_idx = HashMap::with_capacity(transactions.len());

        // now loop over our transactions again and update our .next[] references.
        // after this, we'll have both forward and backward links for all available transactions.
        for trans in transactions {
            trans_created_idx.insert(trans.id(), trans.entry().created().timestamp_millis());
            let prev = trans.entry().previous_transactions();
            if prev.is_empty() {
                // cool, we found a head node. track it.
                head_transactions.push((trans.entry().created(), trans.id().clone()));
            } else {
                for prev_id in prev {
                    match dag.index_mut().get_mut(prev_id) {
                        Some(previous_node) => {
                            previous_node.next_mut().push(trans.id());
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

        // now, for each DAG node, sort its `prev` and `next` nodes by (timestamp ASC, transction_id
        // ASC). this gives us detemrinistic ordering in our DAG.
        for node in dag.index_mut().values_mut() {
            node.prev_mut().sort_unstable_by_key(|tid| {
                let created = trans_created_idx.get(tid).copied().unwrap_or(i64::MAX);
                (created, *tid)
            });
            node.next_mut().sort_unstable_by_key(|tid| {
                let created = trans_created_idx.get(tid).copied().unwrap_or(i64::MAX);
                (created, *tid)
            });
        }

        // sort our head transactions by create time ASC, transaction id ASC, then store the sorted
        // transaction IDs into `dag.head`. this makes walking the DAG deterministic.
        head_transactions.sort_unstable();
        *dag.head_mut() = head_transactions.into_iter()
            .map(|(_, tid)| tid)
            .collect::<Vec<_>>();

        // walk our dag and look for tail nodes and problems (missing nodes, circular links, etc)
        let mut tail_nodes = Vec::new();
        // NOTE: we unwrap() here because we know for a fact that this walk() always returns Ok().
        // if this changes in the future, *please* update the logic accordingly, possibly wrapping
        // `from_transactions()` in a Result...
        let (visited, missing) = dag.walk(|node, _ancestry, _ancestry_idx| {
            if node.next().is_empty() {
                tail_nodes.push(node.transaction().id().clone());
            }
            Ok(())
        }).unwrap();
        for entry in missing {
            missing_transactions.insert(entry);
        }
        dag.visited = visited;
        dag.unvisited = dag.find_unvisited();
        dag.missing = missing_transactions;
        dag.tail = tail_nodes;
        dag
    }

    /// Walk the DAG, starting from the head, and running a function on each node in-order.
    ///
    /// In-order here means we follow causal order, but between branches of the DAG nodes, we sort
    /// by (timestamp ASC, transaction id ASC). This gives us consistent ordering that preserves
    /// the causal chain, but where we cannot order via the DAG chain we rely on timestamp instead,
    /// and in the case of timestamp conflict, we run the transaction ID with the lower sort order
    /// first.
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
    /// And so these are the things we return. In that order. As a tuple.
    pub fn walk<F>(&self, mut opfn: F) -> Result<(Vec<TransactionID>, HashSet<TransactionID>)>
        where F: FnMut(&DagNode, &[u32], &HashMap<TransactionID, Vec<u32>>) -> Result<()>,
    {
        // the nodes we have visited *in the order we visited them*
        let mut visited = Vec::with_capacity(self.index().len());
        // the nodes we have visited in a format that allows for quick lookups
        let mut visited_set: HashSet<TransactionID> = HashSet::with_capacity(self.index().len());
        // transactions we've come across that were referenced by id but could not be found in the
        // index
        let mut missing_transactions: HashSet<TransactionID> = Default::default();
        // our main ordering mechanism. when processing a transaction, we push the next
        // transactions into this ordered set. when done, we pop the first transaction off the set
        // and loop again. this effectively allows sorting by causal order BUT with the benefit
        // that pending transactions are ordered by timestamp/transaction ID as well.
        let mut pending_transactions: BTreeSet<(Timestamp, TransactionID)> = Default::default();
        // this tracks the current branch number, user to catalog branches/merges and ancestry.
        let mut cur_branch: u32 = 0;
        // this assigns an ancestry (aka Vec<Branch>) to each node.
        //
        // it's important to note that nodes are assigned ancestry in a feed-forward way: the
        // current node being processed assigns the ancestry for the node(s) that come after it!
        let mut branch_tracker: HashMap<TransactionID, Vec<u32>> = HashMap::new();

        // a helper function to grab the current branch id and increment the counter.
        let mut next_branch = || {
            let prev = cur_branch;
            cur_branch += 1;
            prev
        };

        // a helper macro to keep me from getting carpal tunnel. effectively looks in the main
        // index for a transaction and if found, runs the given block, otherwise pushes the
        // transaction ID into the missing transactions list.
        macro_rules! with_trans {
            ($id:expr, $node:ident, $run:block) => {{
                match self.index().get($id) {
                    Some($node) => { $run }
                    None => {
                        missing_transactions.insert($id.clone());
                    }
                }
            }}
        }

        // loop over our head nodes and push them into the pending list. they are going to kick off
        // our main loop
        for tid in self.head() {
            with_trans! { tid, node, {
                // NOTE: we can assign branch ids sequentially here because the head nodes are
                // sorted before this function is ever called. therefor, the head nodes are going
                // to be in the same position in the btree that they are when we loop over them.
                pending_transactions.insert((node.transaction().entry().created().clone(), tid.clone()));
                // each head node gets its own branch.
                branch_tracker.insert(tid.clone(), vec![next_branch()]);
            }}
        }

        // this is the main loop. we pop an item off the pending list and run it. if it has
        // transactions following, they will be added to the pending list and we continue ad
        // nauseum. if the transaction is a merge, we do not process it until all the transactions
        // before it have been run.
        while let Some((_, tid)) = pending_transactions.pop_first() {
            // grab our ancestry from the branch tracker.
            let mut ancestry = match branch_tracker.get(&tid) {
                Some(anc) => anc.clone(),
                // should NOT happen, but unwrap isn't acceptable here soooo...
                None => {
                    missing_transactions.insert(tid.clone());
                    continue;
                }
            };

            // check if we're looping. this should likely never be true, but can't be too careful
            // these days...
            if visited_set.contains(&tid) {
                // we've already seen this node. circular references are bad, m'kay?
                continue;
            }

            with_trans! { &tid, node, {
                // if we have more than one previous transaction, we have to make sure that all the
                // previous transactions have run before we can run this one!
                if node.prev().len() > 1 {
                    let mut visited_all_prev = true;
                    for tid_prev in node.prev() {
                        if !visited_set.contains(tid_prev) {
                            visited_all_prev = false;
                            break;
                        }
                    }

                    // if we still have previous transactions that have yet to run, bail. they will
                    // add this transaction into the pending list again and we'll have our time to
                    // shine.
                    if !visited_all_prev {
                        continue;
                    }

                    // gee whillickers, we've visited all the previous transactions! harvest their
                    // dumb ancestry and add it to our own, adding another branch to signify our
                    // merge on this joyous occasion.
                    for tid_prev in node.prev() {
                        if let Some(prev_ancestors) = branch_tracker.get(tid_prev) {
                            for prev_ancestor in prev_ancestors {
                                ancestry.push(*prev_ancestor);
                            }
                        }
                    }
                    ancestry.push(next_branch());
                    ancestry.sort();
                    ancestry.dedup();
                }

                // track that we've seen this transaction
                visited.push(tid.clone());
                visited_set.insert(tid.clone());

                // run our user-supplied operation
                opfn(node, &ancestry, &branch_tracker)?;

                // if we only have one next node, we don't need to fuss with ancestry at all: we
                // can just set it as is.
                //
                // however if we have multiple next nodes, we need to create a new branch id for
                // each of them.
                if node.next().len() == 1 {
                    let ntid = node.next()[0];
                    with_trans! { ntid, node_next, {
                        branch_tracker.insert(ntid.clone(), ancestry);
                        pending_transactions.insert((node_next.transaction().entry().created().clone(), ntid.clone()));
                    }}
                } else {
                    // the next nodes were sorted before walk() is called, so we can sequentially
                    // assign branch nums here.
                    for &ntid in node.next() {
                        with_trans! { ntid, next_node, {
                            let mut ancestry_next = ancestry.clone();
                            ancestry_next.push(next_branch());
                            branch_tracker.insert(ntid.clone(), ancestry_next);
                            pending_transactions.insert((next_node.transaction().entry().created().clone(), ntid.clone()));
                        }}
                    }
                }
            }}
        }

        // cool, we're done!
        Ok((visited, missing_transactions))
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
        util::{
            Timestamp,
            ser::{BinaryVec, HashMapAsn1},
            test::make_dag_chain,
        }
    };
    use std::str::FromStr;

    #[test]
    fn dag_from_transactions_walk_simple() {
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity(Timestamp::now());
        #[allow(non_snake_case, unused_mut)]
        let (transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           transactions,
           [A(0), B(1), C(2), D(3), E(4), F(5), G(6)],
           [
               [A, B] <- [C],
               [C] <- [D, E],
               [E] <- [F],
               [D, F] <- [G],
           ],
           []
        };
        let dag = Dag::from_transactions(&transaction_list.iter().collect::<Vec<_>>());
        assert_eq!(
            dag.head().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A", "B"],
        );
        assert_eq!(
            dag.tail().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["G"],
        );
        assert_eq!(
            dag.visited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A", "B", "C", "D", "E", "F", "G"],
        );
        assert_eq!(dag.missing().len(), 0);

        let dag_nodes = dag.index().iter()
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
        assert_eq!(
            dag_nodes.get("A").unwrap(),
            &(vec![], vec!["C"])
        );
        assert_eq!(
            dag_nodes.get("B").unwrap(),
            &(vec![], vec!["C"])
        );
        assert_eq!(
            dag_nodes.get("C").unwrap(),
            &(vec!["A", "B"], vec!["D", "E"])
        );
        assert_eq!(
            dag_nodes.get("D").unwrap(),
            &(vec!["C"], vec!["G"])
        );
        assert_eq!(
            dag_nodes.get("E").unwrap(),
            &(vec!["C"], vec!["F"])
        );
        assert_eq!(
            dag_nodes.get("F").unwrap(),
            &(vec!["E"], vec!["G"])
        );
        assert_eq!(
            dag_nodes.get("G").unwrap(),
            &(vec!["D", "F"], vec![])
        );

        let mut visited = Vec::new();
        dag.walk(|node, ancestry, _| { visited.push((*tid_to_name.get(node.transaction().id()).unwrap(), Vec::from(ancestry))); Ok(()) }).unwrap();
        assert_eq!(
            visited,
            vec![
                ("A", vec![0]),
                ("B", vec![1]),
                ("C", vec![0, 1, 2]),
                ("D", vec![0, 1, 2, 3]),
                ("E", vec![0, 1, 2, 4]),
                ("F", vec![0, 1, 2, 4]),
                ("G", vec![0, 1, 2, 3, 4, 5]),
            ],
        );
    }

    // given the same set of transactions *but in a different order* the exact same DAG
    // structure should be returned.
    #[test]
    fn dag_from_transactions_walk_deterministic() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity_deterministic(now, b"hi i'm butch");
        #[allow(non_snake_case, unused_mut)]
        let (mut transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           transactions,
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
        let dag = Dag::from_transactions(&transaction_list.iter().collect::<Vec<_>>());
        assert_eq!(
            dag.head().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A", "B"],
        );
        assert_eq!(
            dag.tail().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["G"],
        );
        assert_eq!(
            dag.visited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A", "B", "C", "D", "E", "F", "G"],
        );
        assert_eq!(dag.missing().len(), 0);

        let dag_nodes = dag.index().iter()
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
        assert_eq!(
            dag_nodes.get("A").unwrap(),
            &(vec![], vec!["C"])
        );
        assert_eq!(
            dag_nodes.get("B").unwrap(),
            &(vec![], vec!["C"])
        );
        assert_eq!(
            dag_nodes.get("C").unwrap(),
            &(vec!["A", "B"], vec!["D", "E"])
        );
        assert_eq!(
            dag_nodes.get("D").unwrap(),
            &(vec!["C"], vec!["G"])
        );
        assert_eq!(
            dag_nodes.get("E").unwrap(),
            &(vec!["C"], vec!["F"])
        );
        assert_eq!(
            dag_nodes.get("F").unwrap(),
            &(vec!["E"], vec!["G"])
        );
        assert_eq!(
            dag_nodes.get("G").unwrap(),
            &(vec!["D", "F"], vec![])
        );

        let mut visited = Vec::new();
        dag.walk(|node, ancestry, _| { visited.push((*tid_to_name.get(node.transaction().id()).unwrap(), Vec::from(ancestry))); Ok(()) }).unwrap();
        assert_eq!(
            visited,
            vec![
                ("A", vec![0]),
                ("B", vec![1]),
                ("C", vec![0, 1, 2]),
                ("D", vec![0, 1, 2, 3]),
                ("E", vec![0, 1, 2, 4]),
                ("F", vec![0, 1, 2, 4]),
                ("G", vec![0, 1, 2, 3, 4, 5]),
            ],
        );
    }

    #[test]
    fn dag_from_transactions_walk_missing() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity(now);
        #[allow(non_snake_case, unused_mut)]
        let (mut transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           transactions,
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
        let dag = Dag::from_transactions(&transaction_list.iter().collect::<Vec<_>>());
        assert_eq!(
            dag.head().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A", "B"],
        );
        assert_eq!(
            dag.tail().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A", "B"],
        );
        assert_eq!(
            dag.visited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A", "B"],
        );
        let mut unvisited = dag.unvisited().iter()
            .map(|x| *tid_to_name.get(x).unwrap())
            .collect::<Vec<_>>();
        unvisited.sort_unstable();
        assert_eq!(
            unvisited,
            vec!["D", "E", "F", "G"],
        );
        assert_eq!(dag.missing().len(), 1);

        let dag_nodes = dag.index().iter()
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
        assert_eq!(
            dag_nodes.get("A").unwrap(),
            &(vec![], vec![])
        );
        assert_eq!(
            dag_nodes.get("B").unwrap(),
            &(vec![], vec![])
        );
        assert_eq!(dag_nodes.get("C"), None);
        assert_eq!(
            dag_nodes.get("D").unwrap(),
            &(vec!["C"], vec!["G"])
        );
        assert_eq!(
            dag_nodes.get("E").unwrap(),
            &(vec!["C"], vec!["F"])
        );
        assert_eq!(
            dag_nodes.get("F").unwrap(),
            &(vec!["E"], vec!["G"])
        );
        assert_eq!(
            dag_nodes.get("G").unwrap(),
            &(vec!["D", "F"], vec![])
        );

        let mut visited = Vec::new();
        dag.walk(|node, ancestry, _| { visited.push((*tid_to_name.get(node.transaction().id()).unwrap(), Vec::from(ancestry))); Ok(()) }).unwrap();
        assert_eq!(
            visited,
            vec![
                ("A", vec![0]),
                ("B", vec![1]),
            ],
        );
    }

    #[test]
    fn dag_from_transactions_walk_transaction_order() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity_deterministic(now, b"Hi I'm Butch");
        #[allow(non_snake_case, unused_mut)]
        let (mut transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           transactions,
           // set up a chain where B's timestamp comes after C, which means if we sort just be
           // timestamp then the causal chain will break. however, if we sort by causal chain THEN
           // timestamp when running transactions, we're gonna have a good time.
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
        let dag = Dag::from_transactions(&transaction_list.iter().collect::<Vec<_>>());
        assert_eq!(
            dag.visited().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["E", "A", "F", "G", "B", "C", "D", "H"],
        );
        let mut visited = Vec::new();
        dag.walk(|node, _ancestry, _anc_idx| {
            visited.push(node.transaction().id().clone());
            Ok(())
        }).unwrap();
        assert_eq!(
            visited.iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["E", "A", "F", "G", "B", "C", "D", "H"],
        );
    }

    #[test]
    fn dag_from_transactions_walk_complex_branch() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity_deterministic(now, b"Hi I'm Butch");
        #[allow(non_snake_case, unused_mut)]
        let (mut transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           transactions,
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
        let dag = Dag::from_transactions(&transaction_list.iter().collect::<Vec<_>>());
        assert_eq!(
            dag.head().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A"],
        );
        assert_eq!(
            dag.tail().iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["O", "Q"],
        );
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
        dag.walk(|node, _, _| {
            visited.push(node.transaction().id().clone());
            Ok(())
        }).unwrap();
        assert_eq!(
            visited.iter().map(|x| *tid_to_name.get(x).unwrap()).collect::<Vec<_>>(),
            vec!["A", "B", "E", "J", "C", "F", "G", "D", "H", "I", "K", "L", "M", "O", "N", "P", "Q"],
        )
    }
}

