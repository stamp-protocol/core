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

pub use crate::dag::{
    transaction::{Transaction, TransactionBody, TransactionEntry, TransactionID},
    transactions::Transactions,
};
use crate::{error::Error, util::Timestamp};
use getset::{Getters, MutGetters};
use std::collections::{BTreeMap, HashMap, HashSet};
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
            prev: prev,
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

    /// Takes a flat list of nodes and returns a of DAG that models those nodes.
    pub fn from_nodes(nodes: &[DagNode<'a, I, T>]) -> Dag<'a, I, T> {
        // create our DAG object.
        let mut dag = Dag::new();

        // index our nodes into the DAG.
        for node in nodes {
            dag.index_mut().insert(*node.id(), node.clone());
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
        let mut trans_created_idx = HashMap::with_capacity(nodes.len());

        // now loop over our nodes again and update our .next[] references.
        // after this, we'll have both forward and backward links for all available nodes.
        for node in nodes {
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
            .unwrap();
        for entry in missing {
            missing_nodes.insert(&entry);
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
        F: FnMut(&DagNode<'a, I, T>, &[u32], &HashMap<&'a I, Vec<u32>>) -> core::result::Result<(), E>,
    {
        /// stored with the `pending_nodes` as a way to instruct nodes whether they should
        /// use the given ancestry as-is or whether they should grab a new branch and append it to
        /// the end.
        ///
        /// this makes it so we don't have to sort the node.next() entries, and instead can
        /// lazy-load our ancetry so it corresponds directly to node order.
        struct AncestryGrabber {
            /// The ancestry of the previous node
            ancestry: Vec<u32>,
            /// Whether or not we should register a new branch
            grab_next_branch: bool,
        }

        impl AncestryGrabber {
            fn new(ancestry: Vec<u32>, grab_next_branch: bool) -> Self {
                Self {
                    ancestry,
                    grab_next_branch,
                }
            }

            fn consume(self) -> (Vec<u32>, bool) {
                let Self {
                    ancestry,
                    grab_next_branch,
                } = self;
                (ancestry, grab_next_branch)
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
        let mut pending_nodes: BTreeMap<(&'a Timestamp, &'a I, Option<&'a I>), AncestryGrabber> = Default::default();
        // this tracks the current branch number, user to catalog branches/merges and ancestry.
        let mut cur_branch: u32 = 0;
        // Stores the ancestry of each node as they are being processed. This allows ancestry
        // lookups of nodes that have been previously seen.
        let mut branch_tracker: HashMap<&'a I, Vec<u32>> = HashMap::with_capacity(self.index().len());
        // this is used by merging nodes (ie, has prev_nodes.len() > 1) to store the
        // ancestry of the previous nodes so they can all be merged together when the merge is
        // ready.
        let mut branch_merge_tracker: HashMap<&'a I, Vec<Vec<u32>>> = HashMap::new();

        // a helper function to grab the current branch id and increment the counter.
        let mut next_branch = || {
            let prev = cur_branch;
            cur_branch += 1;
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
                    AncestryGrabber::new(vec![], true),
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

            let (mut ancestry, grab_next_branch) = ancestry_grabber.consume();

            with_trans! { &tid, node, {
                // if we have more than one previous node, we have to make sure that all the
                // previous nodes have run before we can run this one!
                if node.prev().len() > 1 {
                    // push the ancestors we were given for the previous node into our merge
                    // tracker for THIS node.
                    let entry = branch_merge_tracker.entry(&tid).or_default();
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
                            missing_nodes.insert(&tid);
                            continue;
                        }
                    }
                    ancestry.push(next_branch());
                    ancestry.sort();
                    ancestry.dedup();
                } else if grab_next_branch {
                    ancestry.push(next_branch());
                }

                branch_tracker.insert(&tid, ancestry.clone());

                // track that we've seen this node
                visited.push(&tid);
                visited_set.insert(&tid);

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
    use std::str::FromStr;

    #[test]
    fn dag_from_nodes_walk_simple() {
        let mut rng = crate::util::test::rng();
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity(&mut rng, Timestamp::now());
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
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&nodes);
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
            visited.push((*tid_to_name.get(node.id()).unwrap(), Vec::from(ancestry)));
            Ok::<(), Error>(())
        })
        .unwrap();
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
    fn dag_from_nodes_walk_deterministic() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let mut rng = crate::util::test::rng_seeded(b"hi i'm butch");
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
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
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&nodes);
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
            visited.push((*tid_to_name.get(node.id()).unwrap(), Vec::from(ancestry)));
            Ok::<(), Error>(())
        })
        .unwrap();
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
    fn dag_from_nodes_walk_missing() {
        let mut rng = crate::util::test::rng();
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
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
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&nodes);
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
            visited.push((*tid_to_name.get(node.id()).unwrap(), Vec::from(ancestry)));
            Ok::<(), Error>(())
        })
        .unwrap();
        assert_eq!(visited, vec![("A", vec![0]), ("B", vec![1]),],);
    }

    #[test]
    fn dag_from_nodes_walk_node_order() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let mut rng = crate::util::test::rng_seeded(b"hi i'm Butch");
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
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
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&nodes);
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
        let mut rng = crate::util::test::rng_seeded(b"Hi I'm Butch.");
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
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
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&nodes);
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
            visited.push((*node.id(), Vec::from(ancestry), idx.get(node.id()).map(|x| x.as_slice()) == Some(ancestry)));
            Ok::<(), Error>(())
        })
        .unwrap();
        assert_eq!(
            visited
                .into_iter()
                .map(|(tid, ancestry, eq)| (*tid_to_name.get(&tid).unwrap(), ancestry, eq))
                .collect::<Vec<_>>(),
            vec![
                ("A", vec![0], true),
                ("B", vec![0, 1], true),
                ("E", vec![0, 1, 2], true),
                ("J", vec![0, 1, 2], true),
                ("C", vec![0, 1, 3], true),
                ("F", vec![0, 1, 3, 4], true),
                ("G", vec![0, 1, 3, 5], true),
                ("D", vec![0, 1, 6], true),
                ("H", vec![0, 1, 6, 7], true),
                ("I", vec![0, 1, 6, 8], true),
                ("K", vec![0, 1, 2, 6, 7, 8, 9], true),
                ("L", vec![0, 1, 3, 4], true),
                ("M", vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], true),
                ("O", vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], true),
                ("N", vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12], true),
                ("P", vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12], true),
                ("Q", vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12], true),
            ],
        )
    }

    #[test]
    fn dag_from_nodes_duplicate_links() {
        let now = Timestamp::from_str("2047-02-17T04:12:00Z").unwrap();
        let mut rng = crate::util::test::rng_seeded(b"Hi I'm Butch");
        let (_master_key, transactions, _admin_key) = crate::util::test::create_fake_identity(&mut rng, now);
        #[allow(non_snake_case, unused_mut)]
        let (mut transaction_list, tid_to_name, _name_to_tid) = make_dag_chain! {
           transactions,
           [A(0), B(10), C(20)],
           [
               [A] <- [B],
               [A] <- [B],
               [B] <- [C],
           ],
           []
        };
        let nodes = transaction_list.iter().map(|t| t.into()).collect::<Vec<_>>();
        let dag = Dag::from_nodes(&nodes);
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
                .map(|(tid, ancestry, eq)| (*tid_to_name.get(&tid).unwrap(), ancestry, eq))
                .collect::<Vec<_>>(),
            vec![("A", vec![0], true), ("B", vec![0], true), ("C", vec![0], true),],
        )
    }
}
