//! The trust module contains objects and functions for determining trust levels between
//! identities.

use crate::{
    dag::{Dag, DagNode, TransactionID},
    error::{Error, Result},
    identity::{
        claim::ClaimID,
        stamp::{Confidence, Stamp, StampEntry},
        Identity, IdentityID,
    },
    util::Timestamp,
};
use getset::{Getters, MutGetters};
use std::collections::HashMap;
use std::ops::Deref;
use std::str::FromStr;

/// Allows creating custom trust algorithms.
///
/// The goal is to ultimately assign an i8 value to an identity:
///
/// - -128 being abhorrent, despicable, jackal-hearted, and treacherous (do not trust, and
///   transfer this lack of trust to recipients by some degree).
/// - 0 being "no trust" (ie, dead end)
/// - 127 being honest, honorable, and dependable (full trust)
pub trait TrustAlgo {
    /// Generate a trust value from a set of [`Stamps`][crate::identity::stamp::StampEntry].
    ///
    /// This is meant to be called on ALL the stamps for a given identity -> identity pair at once,
    /// reducing the trust relationship to a single value.
    fn trust_from_stamps(&self, stamps: &[&StampEntry]) -> i8;

    /// Takes multiple trust values, assigned to an identity via different paths in the trust
    /// graph, and merges them. They could be added, averaged, maxed, minned...whatever you desire.
    fn merge(&self, trust_values: &[i8]) -> i8;

    /// Takes a trust value and evaluates how much it should decay based on how far the given
    /// identity is from us.
    ///
    /// this can be simple like:
    ///
    /// ```rust
    /// # fn trust(trust: i8, distance_from_me: usize) -> i8 {
    /// if distance_from_me >= 5 { 0 } else { trust }
    /// # }
    /// ```
    ///
    /// or this could be a uh, a lot more uh, uh, uh, uh, complex, I mean it's not just, it might
    /// not be, just such a simple, uh... you know?
    fn decay(&self, trust: i8, distance_from_me: usize) -> i8;

    /// Returns the maximum distance (or, number of hops) until we no longer search for paths in
    /// the trust chain. This informs the network search algorithm when (or if) it should stop
    /// searching, so effectively the higher the value (or if `None`) the longer the search may
    /// take.
    fn max_distance(&self) -> Option<usize>;
}

/// A default trust algorithm. Create it via `TrustAlgoDefault::new()`;
pub struct TrustAlgoDefault {}

impl TrustAlgoDefault {
    /// Create a new default trust algorithm.
    pub fn new() -> Self {
        Self {}
    }
}

impl TrustAlgo for TrustAlgoDefault {
    fn trust_from_stamps(&self, stamps: &[&StampEntry]) -> i8 {
        fn confidence_trust(c: &Confidence) -> i8 {
            match c {
                &Confidence::Negative => -128,
                &Confidence::Low => 10,
                &Confidence::Medium => 40,
                &Confidence::High => 80,
                &Confidence::Ultimate => 127,
            }
        }
        // ignore the claim spec and just tally confidence for now lol
        let confidence_vals = stamps.iter().map(|x| x.confidence()).map(confidence_trust).collect::<Vec<_>>();

        // merge the trust values
        self.merge(&confidence_vals)
    }

    fn merge(&self, trust_values: &[i8]) -> i8 {
        // do an average, without floats because they suck
        let sum = trust_values.iter().fold(0i64, |acc, &x| {
            let cast = x as i64;
            // detect overflows
            if acc >= 0 && i64::MAX - acc < cast {
                i64::MAX
            } else if acc < 0 && i64::MIN - acc > -cast {
                i64::MIN
            } else {
                acc + cast
            }
        });
        (sum / (trust_values.len() as i64)) as i8
    }

    fn decay(&self, trust: i8, distance_from_me: usize) -> i8 {
        if distance_from_me < 5 {
            ((trust as i64) / (2i64.pow(distance_from_me as u32))) as i8
        } else {
            0
        }
    }

    fn max_distance(&self) -> Option<usize> {
        Some(5)
    }
}

#[derive(Clone, Default)]
struct Network<'a> {
    links: HashMap<&'a TransactionID, Vec<&'a StampEntry>>,
}

impl<'a> Network<'a> {
    fn new() -> Self {
        Self { links: HashMap::new() }
    }

    fn index_stamp(&mut self, identity_id: &'a IdentityID, stamp: &'a Stamp) {
        if stamp.revocation().is_some() {
            return;
        }
        let entry = self.links.entry(identity_id.deref()).or_insert_with(|| Vec::new());
        if !(*entry).contains(&stamp.entry()) {
            (*entry).push(stamp.entry());
        }
    }

    fn add_node(&mut self, identity: &'a Identity) {
        for stamp in identity.stamps() {
            self.index_stamp(identity.id(), stamp);
        }
        for claim in identity.claims() {
            for stamp in claim.stamps() {
                self.index_stamp(stamp.entry().stamper(), stamp);
            }
        }
    }

    fn find_paths(&'a self, from: &'a IdentityID, to: &'a IdentityID, max_distance: Option<usize>) -> Vec<Vec<&'a StampEntry>> {
        #[derive(Debug, Default)]
        struct PathWalker<'a> {
            matches: Vec<Vec<&'a StampEntry>>,
        }

        impl<'a> PathWalker<'a> {
            fn push(&mut self, path: Vec<&'a StampEntry>) {
                self.matches.push(path);
            }

            fn to_matches(self) -> Vec<Vec<&'a StampEntry>> {
                let Self { matches, .. } = self;
                matches
            }
        }

        let mut walker = PathWalker::default();
        fn walk<'a>(
            links: &HashMap<&'a TransactionID, Vec<&'a StampEntry>>,
            walker: &mut PathWalker<'a>,
            current_identity: &'a IdentityID,
            start_identity: &'a IdentityID,
            target_identity: &'a IdentityID,
            current_path: Vec<&'a StampEntry>,
            max_distance: usize,
        ) {
            if current_path.len() > max_distance {
                return;
            }
            if current_identity == target_identity {
                walker.push(current_path);
            } else {
                let stamps = match links.get(current_identity.deref()) {
                    Some(stamps) => {
                        // we clone and sort here so given a network with any given set of links,
                        // start, and end point, we always find the same paths in the same order
                        // every time.
                        let mut stamps = stamps.clone();
                        stamps.sort_unstable_by_key(|k| (k.stampee().deref(), k.claim_id().deref()));
                        stamps
                    }
                    None => return,
                };
                'recurse: for stamp in stamps {
                    // check if the stamp we're recursing on has already been visited, and if so
                    // then skip it.
                    if stamp.stampee() == start_identity {
                        continue 'recurse;
                    }
                    for path_stamp in &current_path {
                        if path_stamp.stampee() == stamp.stampee() {
                            continue 'recurse;
                        }
                    }
                    let mut next_path = current_path.clone();
                    next_path.push(stamp);
                    walk(links, walker, stamp.stampee(), start_identity, target_identity, next_path, max_distance);
                }
            }
        }
        walk(&self.links, &mut walker, from, from, to, vec![], max_distance.unwrap_or(usize::MAX));
        walker.to_matches()
    }
}

/// A report that shows how much trust was generated for a single claim.
///
/// This report is mostly for debugging/visualization because the values may or may not be
/// indicative of the final `trust_stamps` value in [`TrustReportFromEntry`].
#[derive(Clone, Debug, Getters, MutGetters)]
#[getset(get = "pub", get_mut = "pub(crate)")]
pub struct TrustReportStamp {
    /// The claim this trust value is for
    claim_id: ClaimID,
    /// The raw trust value assigned to this claim, with no other processing added. This is
    /// basically the output of [`TrustAlgo.trust_from_stamps`][TrustAlgo::trust_from_stamps] if it
    /// was fed only a single claim.
    ///
    /// Keep in mind, this trust value isn't necessarily used in the final calculation:
    /// `trust_from_stamps()` calculates a single trust value for *all* stamps between two
    /// identities, not just a single one.
    trust: i8,
}

impl TrustReportStamp {
    fn new(claim_id: ClaimID, trust: i8) -> Self {
        Self { claim_id, trust }
    }
}

/// A report that gives details on the transfer of trust from a single identity to a given node.
#[derive(Clone, Debug, Getters, MutGetters)]
#[getset(get = "pub", get_mut = "pub(crate)")]
pub struct TrustReportFromEntry {
    /// The identity that assigned this trust. Keep in mind that an identity can have multiple
    /// incoming `from` entries.
    from: IdentityID,
    /// Sheds some light on how a particular claim is scored. This is mainly useful for debugging,
    /// as the real result of stamp trust is held in `trust_stamps`.
    stamp_trust_details: Vec<TrustReportStamp>,
    /// The trust value of the previous node (aka, `from`)
    trust_previous_node: i8,
    /// How far this node is from the trust originator
    distance_from_originator: usize,
    /// The trust we calculated from all of the incoming stamps from `from`. This value supersedes
    /// any trust values in `stamp_trust_details`.
    trust_stamps: i8,
    /// Given the `trust_previous_node / TRUST_MAX` as a ratio, multiply it by our `trust_stamps`
    /// value to get the total amount of trust transferred from the previous node (`from`) to this
    /// node.
    trust_transferred: i8,
    /// This value represents `trust_transferred` after it is run through
    /// [`TrustAlgo.decay`][TrustAlgo::decay], with the distance in `distance_from_originator`.
    /// This gives us our *final* trust value between the previous identity (`from`) and the
    /// current node. If the current node has multiple incoming previous identities, the values of
    /// all of them will be merged via [`TrustAlgo.merge`][TrustAlgo::merge] in order to determine
    /// a single trust value.
    trust_decayed: i8,
}

impl TrustReportFromEntry {
    fn new(
        from: IdentityID,
        stamp_trust_details: Vec<TrustReportStamp>,
        trust_previous_node: i8,
        distance_from_originator: usize,
        trust_stamps: i8,
        trust_transferred: i8,
        trust_decayed: i8,
    ) -> Self {
        Self {
            from,
            stamp_trust_details,
            trust_previous_node,
            distance_from_originator,
            trust_stamps,
            trust_transferred,
            trust_decayed,
        }
    }
}

/// The full trust report for a node.
#[derive(Clone, Debug, Getters, MutGetters)]
#[getset(get = "pub", get_mut = "pub(crate)")]
pub struct NodeTrustReport {
    /// This node's [`IdentityID`]
    identity_id: IdentityID,
    /// The final trust value for this node
    trust: i8,
    /// The reports on incoming identity trust for this node.
    from_entries: Vec<TrustReportFromEntry>,
}

impl NodeTrustReport {
    fn new(identity_id: IdentityID, trust: i8, from_entries: Vec<TrustReportFromEntry>) -> Self {
        Self {
            identity_id,
            trust,
            from_entries,
        }
    }
}

/// Determine the trust between our identity and a subject identity, given a network of
/// identities linking the two via stamps. This walks the network, scoring each identity,
/// transferring trust as it goes.
pub fn trust_score<T: TrustAlgo>(
    ours: &IdentityID,
    theirs: &IdentityID,
    trust_network: &[&Identity],
    trust_algo: &T,
) -> Result<Option<(i8, Vec<NodeTrustReport>)>> {
    let mut network = Network::new();
    for id in trust_network {
        network.add_node(id);
    }
    let paths = network.find_paths(ours, theirs, trust_algo.max_distance());

    if paths.len() == 0 {
        return Ok(None);
    }

    #[derive(Debug)]
    struct TrustNode<'a> {
        id: &'a TransactionID, // ie, IdentityID
        prev: Vec<&'a TransactionID>,
        stamps: Vec<&'a StampEntry>,
        timestamp: Timestamp,
    }

    impl<'a> TrustNode<'a> {
        fn new(id: &'a TransactionID) -> Self {
            // sorry to unwrap...
            let timestamp = Timestamp::from_str("1999-12-31T23:59:59.999Z").unwrap();
            Self {
                id,
                prev: Vec::new(),
                stamps: Vec::new(),
                timestamp,
            }
        }
    }

    impl<'a> From<&'a TrustNode<'a>> for DagNode<'a, TransactionID, TrustNode<'a>> {
        fn from(n: &'a TrustNode) -> Self {
            DagNode::new(&n.id, n, n.prev.clone(), &n.timestamp)
        }
    }

    // for each of our paths, update a series of nodes that point to previous nodes that also store
    // the stamps (with the stamper). this gives us a structure we can use to "walk" our path
    // iteratively, creating a trust score as we move along
    //
    // along the way, we also store the shortest distance from any given node to the genesis node.
    // this gives us a distance value we can use in our calculations later.
    let mut nodes: HashMap<&TransactionID, TrustNode> = HashMap::new();
    // maps a (node, prev node) -> distance value. this lets us look up how far a given node is
    // from the genesis node when we're doing our calculations
    let mut dist_map: HashMap<(&TransactionID, &TransactionID), usize> = HashMap::new();
    let timestamp = Timestamp::from_str("1999-12-31T23:59:59.999Z").unwrap();
    for path in &paths {
        for (dist, edge) in path.iter().enumerate() {
            let entry_stamper = nodes.entry(edge.stamper()).or_insert_with(|| TrustNode::new(edge.stamper()));
            (*entry_stamper).stamps.push(edge);
            let entry_stampee = nodes.entry(edge.stampee()).or_insert_with(|| TrustNode::new(edge.stampee()));
            (*entry_stampee).prev.push(edge.stamper());
            // map our (this node, prev node) -> distance. if we already have an entry, use the
            // lowest of the two values.
            let entry_dist = dist_map.entry((edge.stampee(), edge.stamper())).or_insert(usize::MAX);
            (*entry_dist) = std::cmp::min(*entry_dist, dist);
        }
    }

    println!("--- dist ---");
    for ((to, from), dist) in dist_map.iter() {
        println!("  {} -> {}    {}", from, to, dist);
    }

    if nodes.len() == 0 {
        return Ok(None);
    }

    let dag_nodes = nodes.values().map(|n| n.into()).collect::<Vec<_>>();
    let mut dag: Dag<TransactionID, TrustNode> = Dag::from_nodes(&dag_nodes);
    let mut trust_scores: HashMap<&TransactionID, i8> = HashMap::new();
    let mut trust_report: Vec<NodeTrustReport> = Vec::with_capacity(dag_nodes.len());
    dag.walk(|node, ancestry, branch_tracker| {
        if node.prev().len() == 0 {
            trust_scores.insert(node.id(), 127);
            return Ok(());
        }

        let trust_values = node
            .prev()
            .iter()
            .map(|prev_id| {
                let stamps = nodes
                    .get(prev_id)
                    .ok_or(Error::TrustMissingValue)?
                    .stamps
                    .iter()
                    .filter(|s| &s.stampee().deref() == node.id())
                    .map(|x| *x)
                    .collect::<Vec<_>>();
                let report_stamps = stamps
                    .iter()
                    .map(|s| {
                        let trust_single = trust_algo.trust_from_stamps(&[s]);
                        TrustReportStamp::new(s.claim_id().clone(), trust_single)
                    })
                    .collect::<Vec<_>>();
                let prev_node_trust = *trust_scores.get(prev_id).ok_or(Error::TrustMissingValue)?;
                let dist = *dist_map.get(&(node.id(), prev_id)).ok_or(Error::TrustMissingValue)?;
                let raw_trust = trust_algo.trust_from_stamps(&stamps);
                let trust_ratio = ((raw_trust as i64 * prev_node_trust as i64) / i8::MAX as i64) as i8;
                let trust = trust_algo.decay(trust_ratio, dist);
                let report_from_entry = TrustReportFromEntry::new(
                    IdentityID::from(prev_id.clone().clone()),
                    report_stamps,
                    prev_node_trust,
                    dist,
                    raw_trust,
                    trust_ratio,
                    trust,
                );
                Ok((trust, report_from_entry))
            })
            .collect::<Result<Vec<_>>>()?;
        let trust = trust_algo.merge(&trust_values.iter().map(|x| x.0).collect::<Vec<_>>());
        let report = NodeTrustReport::new(
            IdentityID::from(node.id().clone().clone()),
            trust,
            trust_values.into_iter().map(|(_, fr)| fr).collect::<Vec<_>>(),
        );
        trust_report.push(report);
        trust_scores.insert(node.id(), trust);
        Ok(())
    })?;
    let final_trust = trust_report.get(trust_report.len() - 1).ok_or(Error::TrustMissingValue)?.trust;
    Ok(Some((final_trust, trust_report)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{
            base::{HashAlgo, SecretKey},
            private::MaybePrivate,
        },
        dag::Transactions,
        identity::{
            claim::ClaimSpec,
            keychain::AdminKey,
            stamp::{Confidence, StampEntry},
        },
        util::Timestamp,
    };
    use std::str::FromStr;

    /// Makes it stupid easy to build a network of identities that link to each other via valid
    /// stamps on one or more claims.
    macro_rules! make_trust_network {
        (
            [$($names:ident($($claimtype:ident),*),)*],
            [$(
                $from:ident -> $to:ident ($claimtype2:ident, $confidence:expr),
            )*],
        ) => {{
            struct IdentityKeys {
                master: SecretKey,
                admin: AdminKey,
                transactions: Transactions,
            }
            impl IdentityKeys {
                fn new(master: SecretKey, admin: AdminKey, transactions: Transactions) -> Self {
                    Self {
                        master,
                        admin,
                        transactions,
                    }
                }

                fn add_claim(&mut self, claimtype: &'static str) {
                    let now = Timestamp::from_str("2016-04-04T02:00:00-0700").unwrap();
                    let spec = match claimtype {
                        "id" => ClaimSpec::Identity(MaybePrivate::new_public(self.transactions.identity_id().unwrap())),
                        "name" => ClaimSpec::Name(MaybePrivate::new_public("Butch".into())),
                        "email" => ClaimSpec::Email(MaybePrivate::new_public("butch@canineclub.info".into())),
                        _ => panic!("make_trust_network!::IdentityKeys::add_claim() -- unknown claim type {}", claimtype),
                    };
                    let trans = self
                        .transactions
                        .make_claim(&HashAlgo::Blake3, now, spec, Some(String::from(claimtype)))
                        .unwrap()
                        .sign(&self.master, &self.admin)
                        .unwrap();
                    self.transactions = self.transactions.clone().push_transaction(trans).unwrap();
                }

                fn make_stamp(&mut self, entry: StampEntry) {
                    let now = Timestamp::from_str("2016-04-04T02:00:00-0700").unwrap();
                    let trans = self
                        .transactions
                        .make_stamp(&HashAlgo::Blake3, now, entry)
                        .unwrap()
                        .sign(&self.master, &self.admin)
                        .unwrap();
                    self.transactions = self.transactions.clone().push_transaction(trans).unwrap();
                }
            }
            let now = Timestamp::from_str("2016-04-04T02:00:00-0700").unwrap();
            let mut identities: HashMap<&'static str, IdentityKeys> = Default::default();
            $({
                let name = stringify!($names);
                let seed = format!("i had a baby {}! and he was perfect in every way!!", name);
                let mut rng = crate::util::test::rng_seeded(seed.as_bytes());
                let (master, transactions, admin) = crate::util::test::create_fake_identity(&mut rng, now.clone());
                let mut ik = IdentityKeys::new(master, admin, transactions);
                ik.add_claim("id"); // always the same.
                $(
                ik.add_claim(stringify!($claimtype));
                )*
                identities.insert(name, ik);
            })*

            $({
                let from_name = stringify!($from);
                let to_name = stringify!($to);
                let claim_name = stringify!($claimtype2);
                let confidence = $confidence;
                let (to_id, claim_id) = {
                    let to = match identities.get(to_name) {
                        Some(id) => id,
                        None => panic!("make_trust_network! -- referenced to id {} in stamps section, but it was not defined in the identities section", to_name),
                    };
                    let to_id = to.transactions.build_identity().unwrap();
                    let claim = match to_id.find_claim_by_name(claim_name) {
                        Some(claim) => claim,
                        None => panic!("make_trust_network! -- id {} is missing claim {} ...was it added to the definitions section??", to_name, claim_name),
                    };
                    (to.transactions.identity_id().unwrap(), claim.id().clone())
                };

                let from = match identities.get_mut(from_name) {
                    Some(id) => id,
                    None => panic!("make_trust_network! -- referenced from id {} in stamps section, but it was not defined in the identities section", from_name),
                };
                from.make_stamp(StampEntry::new(
                    from.transactions.identity_id().unwrap(),
                    to_id,
                    claim_id,
                    confidence,
                    None::<Timestamp>,
                ));
            })*
            let lookup = identities
                .iter()
                .map(|(k, IdentityKeys { transactions, .. })| (transactions.identity_id().unwrap().deref().clone(), k.clone()))
                .collect::<HashMap<_, _>>();
            let id_map = identities
                .into_iter()
                .map(|(k, IdentityKeys { transactions, .. })| (k, transactions))
                .collect::<HashMap<_, _>>();
            (id_map, lookup)
        }};
    }

    fn paths_named(lookup: &HashMap<TransactionID, &'static str>, paths: &Vec<Vec<&StampEntry>>) -> Vec<Vec<&'static str>> {
        paths
            .iter()
            .map(|path| {
                path.iter()
                    .map(|p| *lookup.get(p.stampee().deref()).expect("missing identity in lookup"))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    }

    fn trustnet_to_paths(
        trust_network: &HashMap<&'static str, Transactions>,
        lookup: &HashMap<TransactionID, &'static str>,
        from: &'static str,
        to: &'static str,
        max_dist: Option<usize>,
    ) -> Vec<Vec<&'static str>> {
        let mut network = Network::new();
        let identities = trust_network.values().map(|x| x.build_identity().unwrap()).collect::<Vec<_>>();
        for id in &identities {
            network.add_node(&id);
        }
        let from = trust_network.get(from).unwrap().identity_id().unwrap();
        let to = trust_network.get(to).unwrap().identity_id().unwrap();
        let paths = network.find_paths(&from, &to, max_dist);
        paths_named(&lookup, &paths)
    }

    #[test]
    fn network_find_paths() {
        let (trustnet1, lookup1) = make_trust_network! {
            [ A(name), B(), ],
            [ A -> B (id, Confidence::High), ],
        };
        let paths_named1 = trustnet_to_paths(&trustnet1, &lookup1, "A", "B", None);
        assert_eq!(paths_named1, vec![vec!["B"]]);

        let (trustnet2, lookup2) = make_trust_network! {
            [
                A(),
                B(name, email),
                C(email),
            ],
            [
                A -> B (id, Confidence::Medium),
                A -> B (name, Confidence::Medium),
                A -> B (email, Confidence::Medium),
                B -> C (id, Confidence::Low),
                B -> C (email, Confidence::Low),
                B -> A (id, Confidence::Ultimate),
            ],
        };
        let paths_named2 = trustnet_to_paths(&trustnet2, &lookup2, "A", "C", None);
        assert_eq!(
            paths_named2,
            vec![
                vec!["B", "C"],
                vec!["B", "C"],
                vec!["B", "C"],
                vec!["B", "C"],
                vec!["B", "C"],
                vec!["B", "C"],
            ]
        );

        let (trustnet3, lookup3) = make_trust_network! {
            [
                A(),
                B(),
                C(),
                D(),
                E(),
            ],
            [
                A -> B (id, Confidence::Low),
                A -> C (id, Confidence::Low),
                C -> B (id, Confidence::Low),
                B -> A (id, Confidence::Low),
                A -> B (id, Confidence::Low),
                D -> E (id, Confidence::Low),
            ],
        };
        let paths_named3 = trustnet_to_paths(&trustnet3, &lookup3, "A", "D", None);
        assert_eq!(paths_named3.len(), 0);
        let paths_named3_2 = trustnet_to_paths(&trustnet3, &lookup3, "A", "E", None);
        assert_eq!(paths_named3_2.len(), 0);

        let (trustnet4, lookup4) = make_trust_network! {
            [
                A(),
                B(),
                C(),
                D(),
                E(),
            ],
            [
                A -> B (id, Confidence::Low),
                B -> C (id, Confidence::Low),
                C -> D (id, Confidence::Low),
                D -> A (id, Confidence::Low),
                A -> E (id, Confidence::Low),
            ],
        };
        let paths_named4 = trustnet_to_paths(&trustnet4, &lookup4, "A", "E", None);
        assert_eq!(paths_named4, vec![vec!["E"]]);
    }

    #[test]
    fn network_find_paths_stable_order() {
        let (trustnet1, lookup1) = make_trust_network! {
            [
                A(name),
                B(),
                C(name, email),
                D(),
                E(),
                F(),
                G(name),
            ],
            [
                A -> B (id, Confidence::High),
                B -> C (id, Confidence::High),
                B -> C (name, Confidence::Medium),
                A -> D (id, Confidence::Ultimate),
                C -> E (id, Confidence::Medium),
                D -> E (id, Confidence::Negative),
                E -> F (id, Confidence::High),
                D -> G (id, Confidence::Medium),
                F -> G (name, Confidence::Low),
                D -> B (id, Confidence::Low),
                E -> D (id, Confidence::Negative),
            ],
        };
        let paths_named1 = trustnet_to_paths(&trustnet1, &lookup1, "A", "G", None);
        assert_eq!(
            paths_named1,
            vec![
                vec!["B", "C", "E", "D", "G"],
                vec!["B", "C", "E", "F", "G"],
                vec!["B", "C", "E", "D", "G"],
                vec!["B", "C", "E", "F", "G"],
                vec!["D", "E", "F", "G"],
                vec!["D", "B", "C", "E", "F", "G"],
                vec!["D", "B", "C", "E", "F", "G"],
                vec!["D", "G"],
            ],
        );
        // same network, different ordering of links, should yield same paths
        let (trustnet2, lookup2) = make_trust_network! {
            [
                B(),
                F(),
                E(),
                A(name),
                G(name),
                D(),
                C(name, email),
            ],
            [
                D -> B (id, Confidence::Low),
                D -> G (id, Confidence::Medium),
                F -> G (name, Confidence::Low),
                E -> F (id, Confidence::High),
                C -> E (id, Confidence::Medium),
                E -> D (id, Confidence::Negative),
                B -> C (name, Confidence::Medium),
                A -> B (id, Confidence::High),
                B -> C (id, Confidence::High),
                D -> E (id, Confidence::Negative),
                A -> D (id, Confidence::Ultimate),
            ],
        };
        let paths_named2 = trustnet_to_paths(&trustnet2, &lookup2, "A", "G", None);
        assert_eq!(paths_named1, paths_named2);
    }

    #[test]
    fn network_find_paths_max_distance() {
        let (trustnet1, lookup1) = make_trust_network! {
            [
                A(),
                B(),
                C(),
                D(),
                E(),
                F(),
                G(),
            ],
            [
                A -> B (id, Confidence::High),
                B -> C (id, Confidence::High),
                C -> D (id, Confidence::High),
                D -> E (id, Confidence::High),
                E -> F (id, Confidence::High),
                F -> G (id, Confidence::High),
            ],
        };
        let paths_named1_1 = trustnet_to_paths(&trustnet1, &lookup1, "A", "G", None);
        assert_eq!(paths_named1_1, vec![vec!["B", "C", "D", "E", "F", "G"]]);
        let paths_named1_2 = trustnet_to_paths(&trustnet1, &lookup1, "A", "G", Some(3));
        assert_eq!(paths_named1_2.len(), 0);
        let paths_named1_3 = trustnet_to_paths(&trustnet1, &lookup1, "A", "G", Some(5));
        assert_eq!(paths_named1_3.len(), 0);
        let paths_named1_4 = trustnet_to_paths(&trustnet1, &lookup1, "A", "G", Some(6));
        assert_eq!(paths_named1_4, vec![vec!["B", "C", "D", "E", "F", "G"]]);

        let (trustnet2, lookup2) = make_trust_network! {
            [
                A(),
                B(),
                C(),
                D(),
                E(),
                F(),
                G(),
            ],
            [
                A -> B (id, Confidence::High),
                B -> C (id, Confidence::High),
                C -> D (id, Confidence::High),
                D -> E (id, Confidence::High),
                E -> F (id, Confidence::High),
                F -> G (id, Confidence::High),
                B -> G (id, Confidence::High),
            ],
        };
        let paths_named2_1 = trustnet_to_paths(&trustnet2, &lookup2, "A", "G", None);
        assert_eq!(paths_named2_1, vec![vec!["B", "C", "D", "E", "F", "G"], vec!["B", "G"],]);
        let paths_named2_2 = trustnet_to_paths(&trustnet2, &lookup2, "A", "G", Some(1));
        assert_eq!(paths_named2_2.len(), 0);
        let paths_named2_3 = trustnet_to_paths(&trustnet2, &lookup2, "A", "G", Some(3));
        assert_eq!(paths_named2_3, vec![vec!["B", "G"],]);
        let paths_named2_4 = trustnet_to_paths(&trustnet2, &lookup2, "A", "G", Some(5));
        assert_eq!(paths_named2_4, vec![vec!["B", "G"],]);
        let paths_named2_5 = trustnet_to_paths(&trustnet2, &lookup2, "A", "G", Some(6));
        assert_eq!(paths_named2_5, vec![vec!["B", "C", "D", "E", "F", "G"], vec!["B", "G"],]);

        let (trustnet3, lookup3) = make_trust_network! {
            [
                A(),
                B(),
                C(),
                D(),
                E(),
                F(),
                G(),
            ],
            [
                A -> B (id, Confidence::High),
                B -> C (id, Confidence::High),
                C -> D (id, Confidence::High),
                D -> E (id, Confidence::High),
                E -> F (id, Confidence::High),
                A -> G (id, Confidence::High),
                G -> B (id, Confidence::High),
            ],
        };
        let paths_named3_1 = trustnet_to_paths(&trustnet3, &lookup3, "A", "F", None);
        assert_eq!(paths_named3_1, vec![vec!["B", "C", "D", "E", "F"], vec!["G", "B", "C", "D", "E", "F"],]);
        let paths_named3_2 = trustnet_to_paths(&trustnet3, &lookup3, "A", "F", Some(1));
        assert_eq!(paths_named3_2.len(), 0);
        let paths_named3_3 = trustnet_to_paths(&trustnet3, &lookup3, "A", "F", Some(3));
        assert_eq!(paths_named3_3.len(), 0);
        let paths_named3_4 = trustnet_to_paths(&trustnet3, &lookup3, "A", "F", Some(5));
        assert_eq!(paths_named3_4, vec![vec!["B", "C", "D", "E", "F"],]);
        let paths_named3_5 = trustnet_to_paths(&trustnet3, &lookup3, "A", "F", Some(6));
        assert_eq!(paths_named3_5, vec![vec!["B", "C", "D", "E", "F"], vec!["G", "B", "C", "D", "E", "F"],]);
    }

    #[test]
    fn trust_score_lol() {
        let (trustnet1, lookup1) = make_trust_network! {
            [
                A(),
                B(name),
                C(),
                D(),
            ],
            [
                A -> B (id, Confidence::High),
                A -> B (name, Confidence::Medium),
                B -> C (id, Confidence::High),
                //A -> C (id, Confidence::Low),
                C -> D (id, Confidence::High),
            ],
        };
        let id_a = trustnet1.get("A").unwrap().identity_id().unwrap();
        let id_c = trustnet1.get("C").unwrap().identity_id().unwrap();
        let id_d = trustnet1.get("D").unwrap().identity_id().unwrap();
        for node in trustnet1.values() {
            let id = node.identity_id().unwrap();
            println!("- node {} -- {}", lookup1.get(&id).unwrap(), id);
        }
        let ids = trustnet1.values().map(|x| x.build_identity().unwrap()).collect::<Vec<_>>();
        let ids_borrow = ids.iter().collect::<Vec<_>>();
        let trust_algo = TrustAlgoDefault::new();
        let (score, report) = trust_score(&id_a, &id_d, ids_borrow.as_slice(), &trust_algo).unwrap().unwrap();
        println!(">> trust score: {}", score);
        for node_report in report {
            println!("-- node {} == {}", node_report.identity_id().deref(), node_report.trust());
            for from in node_report.from_entries() {
                println!("   from: {}", from.from().deref());
                println!("   trust (prev node):   {}", from.trust_previous_node());
                println!("   distance:            {}", from.distance_from_originator());
                println!("   stamp trust:         {}", from.trust_stamps());
                println!("   trust tx:            {}", from.trust_transferred());
                println!("   trust decayed:       {}", from.trust_decayed());
            }
        }
    }
}
