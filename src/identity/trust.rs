//! The trust module contains objects and functions for determining trust levels between
//! identities.

use crate::{
    dag::TransactionID,
    identity::{
        claim::ClaimID,
        stamp::{Confidence, Stamp, StampEntry},
        IdentityID, IdentityInstance,
    },
};
use getset::{CopyGetters, Getters, MutGetters};
use private_parts::Public;
use rasn::{AsnType, Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::ops::Deref;

/// A trait that allows reducing an object to an `i8` numeric trust value.
pub trait TrustValue {
    /// Given an object, return a value between -128 and 127 signifying how much trust or
    /// confidence it has (-128 being the least amount (ie, negative and horrible...complete
    /// distrust), and 127 being absolute trust. Zero is "no opinion."
    fn trust_value(&self) -> i8;
}

/// Defines levels of trust one identity can have in another's ability to validate claims. In other
/// words, if an identity is known to issue high confidence in claims known to be invalid, one
/// might mark that identity as having low or nagative trust. If an identity is known to perform
/// rigorous verification of claims, trust might be set to a high level.
///
/// `Trust` is separate from [`Confidence`] because where confidence signifies the validity of a
/// particular claim, trust signifies how much one trusts the stamper of that claim to perform the
/// validation in the first place. `Confidence` is public, `Trust` is personal.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Trust {
    /// You do not trust an identity at all, or you know that it knowingly validates incorrect
    /// claims.
    #[rasn(tag(explicit(0)))]
    Negative,
    /// You believe the identity understands the implications of stamping claims, but it perhaps
    /// isn't as cautious validating claims as you would be.
    #[rasn(tag(explicit(1)))]
    Marginal,
    /// You believe the identity to be fairly rigorous in its validation of claims.
    #[rasn(tag(explicit(2)))]
    High,
    /// You trust this identity as if it was you.
    #[rasn(tag(explicit(3)))]
    Ultimate,
}

impl TrustValue for Trust {
    fn trust_value(&self) -> i8 {
        match self {
            Self::Negative => i8::MIN,
            Self::Marginal => 20,
            Self::High => 80,
            Self::Ultimate => i8::MAX,
        }
    }
}

impl TrustValue for Confidence {
    fn trust_value(&self) -> i8 {
        match self {
            Self::Negative => i8::MIN,
            Self::Low => 10,
            Self::Medium => 50,
            Self::High => 100,
            Self::Ultimate => i8::MAX,
        }
    }
}

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
    /// identity is from an origin node.
    ///
    /// This can be simple like:
    ///
    /// ```rust
    /// fn trust(trust: i8, distance_from_me: usize) -> i8 {
    ///     if distance_from_me >= 5 { 0 } else { trust }
    /// }
    /// ```
    ///
    /// or this could be a uh, a lot more uh, uh, uh, uh, complex, I mean it's not just, it might
    /// not be, just such a simple, uh... you know?
    fn decay(&self, trust: i8, distance_from_me: usize) -> i8;

    /// Returns the maximum distance (or, number of hops) until we no longer search for paths in
    /// the trust chain. This informs the network search algorithm when (or if) it should stop
    /// searching, so effectively the higher the value (or if `None`) the longer the search may
    /// take.
    fn max_distance(&self) -> usize;
}

/// A default trust algorithm. Create it via `TrustAlgoDefault::new()` or
/// `TrustAlgoDefault::default()`;
#[derive(Clone, Debug, CopyGetters, MutGetters)]
#[getset(get_copy = "pub", get_mut = "pub(crate)")]
pub struct TrustAlgoDefault {
    /// How much trust decays by some fixed amount each time we move down the trust chain.
    ///
    /// For instance, If I trust A at 80, and A trusts B, and our trust decay is set to 50,
    /// B can only receive a maximum of 30 trust.
    trust_decay_per_hop: i8,
    /// Allows us to skip N nodes before applying the decay function. Setting this to 0 is probably
    /// too aggressive, so 1 is generally a good value.
    trust_decay_skip: usize,
    /// How many hops away from us we care to crawl our network and assign trust. This is
    /// inclusive, meaning `max_distance == 2` will allow allow nodes 2 hops or less away from an
    /// origin node.
    #[getset(skip)]
    max_distance: usize,
}

impl TrustAlgoDefault {
    /// Create a new default trust algorithm.
    pub fn new(trust_decay_per_hop: i8, trust_decay_skip: usize, max_distance: usize) -> Self {
        Self {
            trust_decay_per_hop,
            trust_decay_skip,
            max_distance,
        }
    }

    fn average(trust_values: &[i8]) -> i8 {
        if trust_values.is_empty() {
            return 0;
        }

        // do an average, without floats because they suck
        let sum = trust_values.iter().fold(0i64, |acc, &x| acc + x as i64);
        (sum / (trust_values.len() as i64)) as i8
    }
}

impl Default for TrustAlgoDefault {
    fn default() -> Self {
        Self::new(64, 1, 1)
    }
}

impl TrustAlgo for TrustAlgoDefault {
    fn trust_from_stamps(&self, stamps: &[&StampEntry]) -> i8 {
        // ignore the claim spec and just tally confidence for now lol
        let confidence_vals = stamps.iter().map(|x| x.confidence()).map(|c| c.trust_value()).collect::<Vec<_>>();

        // average the trust values
        Self::average(&confidence_vals)
    }

    fn merge(&self, trust_values: &[i8]) -> i8 {
        let sum = trust_values.iter().fold(0i64, |acc, &x| acc + x as i64);
        std::cmp::max(i8::MIN as i64, std::cmp::min(i8::MAX as i64, sum)) as i8
    }

    fn decay(&self, trust: i8, distance_from_origin: usize) -> i8 {
        if trust == 0 {
            return trust;
        }
        if distance_from_origin > self.max_distance() {
            return 0;
        }

        let decay_val = std::cmp::max(0, distance_from_origin as i64 - self.trust_decay_skip() as i64) * self.trust_decay_per_hop() as i64;
        if trust >= 0 {
            std::cmp::max(0, trust as i64 - decay_val) as i8
        } else {
            std::cmp::min(0, trust as i64 + decay_val) as i8
        }
    }

    fn max_distance(&self) -> usize {
        self.max_distance
    }
}

/// Represents an ordered path between two nodes in a trust/stamp network.
#[derive(Clone, Debug, Getters, MutGetters)]
#[getset(get = "pub", get_mut = "pub(crate)")]
pub struct Path<'a> {
    /// The connections in this path.
    ///
    /// Each entry of the outer `Vec` is a connection between two nodes, and the inner `Vec`
    /// represents the one or more stamps going from the previous node to the next node.
    nodes: Vec<Vec<&'a StampEntry>>,
}

impl<'a> Path<'a> {
    fn new(nodes: Vec<Vec<&'a StampEntry>>) -> Self {
        Self { nodes }
    }

    /// Consume this `Path` and turn it into a `Vec<Vec<&StampEntry>>`
    pub fn into_vec(self) -> Vec<Vec<&'a StampEntry>> {
        let Self { nodes } = self;
        nodes
    }
}

impl<'a> Deref for Path<'a> {
    type Target = Vec<Vec<&'a StampEntry>>;
    fn deref(&self) -> &Self::Target {
        self.nodes()
    }
}

/// Represents a network of identities, linked via stamps
#[derive(Clone, Default)]
struct Network<'a> {
    /// maps IdentityID -> Vec<outgoing stamps>
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

    fn add_node(&mut self, identity: &'a IdentityInstance<Public>) {
        for stamp in identity.stamps() {
            self.index_stamp(identity.id(), stamp);
        }
        for claim in identity.claims() {
            for stamp in claim.stamps() {
                self.index_stamp(stamp.entry().stamper(), stamp);
            }
        }
    }

    fn find_paths(&self, from: &'a TransactionID, to: &'a TransactionID, max_distance: usize) -> Vec<Path<'a>> {
        #[derive(Debug, Default)]
        struct PathWalker<'a> {
            /// Sorry this is three layers deep, but hear me out.
            ///
            /// Layer 1 (outer) is the set of unique paths between the `from` not and the `to` node
            /// in the given network.
            ///
            /// Layer 2 (middle) represents a full path and has one entry *per identity*.
            ///
            /// Layer 3 (inner) has all of the stamps shared by any given prev/next identity.
            matches: Vec<Vec<Vec<&'a StampEntry>>>,
        }

        impl<'a> PathWalker<'a> {
            fn push(&mut self, path: Vec<Vec<&'a StampEntry>>) {
                self.matches.push(path);
            }

            fn to_matches(self) -> Vec<Vec<Vec<&'a StampEntry>>> {
                let Self { matches, .. } = self;
                matches
            }
        }

        let mut walker = PathWalker::default();
        fn walk<'a>(
            links: &HashMap<&'a TransactionID, Vec<&'a StampEntry>>,
            walker: &mut PathWalker<'a>,
            current_identity: &'a TransactionID,
            start_identity: &'a TransactionID,
            target_identity: &'a TransactionID,
            current_path: Vec<Vec<&'a StampEntry>>,
            max_distance: usize,
        ) {
            if current_path.len() > max_distance {
                return;
            }
            if current_identity == target_identity {
                walker.push(current_path);
            } else {
                let stamps = match links.get(current_identity) {
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

                // group our stamps by previous/next pairs. BTree for consistent sorting
                let stamps_grouped: BTreeMap<(&TransactionID, &TransactionID), Vec<&StampEntry>> =
                    stamps.into_iter().fold(BTreeMap::new(), |mut acc, x| {
                        let entry = acc.entry((x.stamper(), x.stampee())).or_insert_with(|| Vec::new());
                        (*entry).push(x);
                        acc
                    });

                'recurse: for stamps in stamps_grouped.into_values() {
                    let this_node = match stamps.first() {
                        Some(x) => x.stampee().deref(),
                        None => continue 'recurse,
                    };
                    // check if the stamp we're recursing on has already been visited, and if so
                    // then skip it.
                    if this_node == start_identity {
                        continue 'recurse;
                    }
                    for path_stamp in &current_path {
                        if path_stamp.first().map(|x| x.stampee().deref()) == Some(this_node) {
                            continue 'recurse;
                        }
                    }

                    // ok we're off the beaten path, keep walking
                    let mut next_path = current_path.clone();
                    next_path.push(stamps);
                    walk(links, walker, this_node, start_identity, target_identity, next_path, max_distance);
                }
            }
        }
        walk(&self.links, &mut walker, from, from, to, vec![], max_distance);
        walker.to_matches().into_iter().map(|path| Path::new(path)).collect::<Vec<_>>()
    }
}

/// A report that shows how much trust was generated for a single claim.
///
/// This report is mostly for debugging/visualization because the values may or may not be
/// indicative of the final `trust_stamps` value in [`TrustReportPathEntry`].
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
pub struct TrustReportPathEntry {
    /// The identity that assigned this trust.
    from: IdentityID,
    /// The identity that trust is being assigned to.
    to: IdentityID,
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

impl TrustReportPathEntry {
    fn new(
        from: IdentityID,
        to: IdentityID,
        stamp_trust_details: Vec<TrustReportStamp>,
        trust_previous_node: i8,
        distance_from_originator: usize,
        trust_stamps: i8,
        trust_transferred: i8,
        trust_decayed: i8,
    ) -> Self {
        Self {
            from,
            to,
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
pub struct TrustReport {
    /// The different paths that trust took in our network
    paths: Vec<Vec<TrustReportPathEntry>>,
}

impl TrustReport {
    fn new() -> Self {
        Self { paths: Vec::new() }
    }
}

impl std::fmt::Display for TrustReport {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, ">> Trust report")?;
        for (i, path_report) in self.paths().iter().enumerate() {
            writeln!(f, "  -- path {i}")?;
            for entry in path_report {
                writeln!(f, "    ID {} -> ID {}", entry.from().deref(), entry.to().deref())?;
                writeln!(f, "      trust incoming:      {}", entry.trust_previous_node())?;
                writeln!(f, "      stamp trust:         {}", entry.trust_stamps())?;
                for report_stamp in entry.stamp_trust_details() {
                    let claim_id = format!("{}", report_stamp.claim_id().deref());
                    writeln!(f, "        claim {}:  {}", &claim_id[0..16], report_stamp.trust())?;
                }
                writeln!(f, "      trust tx:            {}", entry.trust_transferred())?;
                writeln!(f, "      distance:            {}", entry.distance_from_originator())?;
                writeln!(f, "      trust decayed:       {}", entry.trust_decayed())?;
            }
        }
        Ok(())
    }
}

/// Find the paths between a set of trusted nodes and a subject node, given a network of nodes and
/// a max distance to search.
pub fn find_paths<'a>(
    trust_mapping: &'a HashMap<TransactionID, Trust>,
    subject: &'a TransactionID,
    identity_network: &[&'a IdentityInstance<Public>],
    max_dist: usize,
) -> Vec<Path<'a>> {
    let mut network = Network::new();
    for id in identity_network {
        network.add_node(id);
    }
    let mut paths = Vec::new();
    let mut keys = trust_mapping.keys().collect::<Vec<_>>();
    keys.sort();
    for from in keys {
        let found = network.find_paths(from, subject, max_dist);
        for path in found {
            paths.push(path);
        }
    }
    paths
}

/// Determine the trust between a set of trusted nodes (`trust_mapping`) and a `subject` identity,
/// given a network of identities linked by stamps. You probably always want `trust_mapping` to at
/// the very least have *your* identity, hopefully with a high trust value =].
///
/// This walks the network, finding paths from trusted nodes to the subject, and assigns trust
/// along those paths with the given `TrustAlgo`.
///
/// Note that deriving the `identity_network` is out of scope for this system. It's assumed you can
/// generate this before passing in.
pub fn trust_score<T: TrustAlgo>(
    trust_mapping: &HashMap<TransactionID, Trust>,
    subject: &TransactionID,
    identity_network: &[&IdentityInstance<Public>],
    trust_algo: &T,
) -> Option<(i8, TrustReport)> {
    if trust_mapping.is_empty() {
        return None;
    }
    let paths = find_paths(trust_mapping, subject, identity_network, trust_algo.max_distance());

    if paths.is_empty() {
        return None;
    }

    // we're going to calculate the trust for each path independently, and merge the trust values
    // only at the end of the line when we get to our subject node
    let mut report = TrustReport::new();
    let mut trust_values: Vec<i8> = Vec::new();
    for path in paths {
        if path.is_empty() || path[0].is_empty() {
            continue;
        }
        let mut prev_node_trust = trust_mapping
            .get(path[0][0].stamper().deref())
            .map(|x| x.trust_value())
            .unwrap_or(0);
        let mut last_node_trust = None;
        let mut path_report: Vec<TrustReportPathEntry> = Vec::with_capacity(path.len());
        for (dist, stamps) in path.into_vec().into_iter().enumerate() {
            // distance is not 0-indexed
            let dist = dist + 1;
            let trust_stamps = trust_algo.trust_from_stamps(&stamps);
            let trust_ratio = ((trust_stamps as i64 * prev_node_trust as i64) / i8::MAX as i64) as i8;
            let trust_decayed = trust_algo.decay(trust_ratio, dist);
            let report_stamps = stamps
                .iter()
                .map(|s| {
                    let trust_single = trust_algo.trust_from_stamps(&[s]);
                    TrustReportStamp::new(s.claim_id().clone(), trust_single)
                })
                .collect::<Vec<_>>();
            let trust_report_entry = TrustReportPathEntry::new(
                stamps[0].stamper().clone(),
                stamps[0].stampee().clone(),
                report_stamps,
                prev_node_trust,
                dist,
                trust_stamps,
                trust_ratio,
                trust_decayed,
            );
            path_report.push(trust_report_entry);
            // pull out the direct trust value. we'll use this to check if we have a negative trust
            // value, at which point we stop processing this path.
            let trust_direct = stamps
                .first()
                .and_then(|stamp| trust_mapping.get(stamp.stampee()))
                .map(|t| t.trust_value())
                .unwrap_or(0);
            // if we directly distrust this node, then bail early because there's no point hearing
            // about what nodes they trust
            if trust_direct < 0 || trust_decayed <= 0 {
                last_node_trust = None;
                break;
            }
            prev_node_trust = trust_decayed;
            last_node_trust = Some(trust_decayed);
        }
        report.paths_mut().push(path_report);
        if let Some(trustval) = last_node_trust {
            trust_values.push(trustval);
        }
    }

    let trust = trust_algo.merge(&trust_values);

    Some((trust, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{
            base::{HashAlgo, SecretKey},
            private::{Full, MaybePrivate},
        },
        dag::Identity,
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
            [$($names2:ident($trust:expr),)*],
            [$(
                $from:ident -> $to:ident ($claimtype2:ident, $confidence:expr),
            )*],
        ) => {{
            struct IdentityKeys {
                master: SecretKey,
                admin: AdminKey<Full>,
                transactions: Identity<Public>,
            }
            impl IdentityKeys {
                fn new(master: SecretKey, admin: AdminKey, identity: Identity) -> Self {
                    Self {
                        master,
                        admin,
                        identity,
                    }
                }

                fn add_claim(&mut self, claimtype: &'static str) {
                    let now = Timestamp::from_str("2016-04-04T02:00:00-0700").expect("make_trust_network!{} timestamp parsed");
                    let spec = match claimtype {
                        "id" => ClaimSpec::Identity(MaybePrivate::new_public(self.identity.identity_id().expect("identity has id"))),
                        "name" => ClaimSpec::Name(MaybePrivate::new_public("Butch".into())),
                        "email" => ClaimSpec::Email(MaybePrivate::new_public("butch@canineclub.info".into())),
                        _ => panic!("make_trust_network!::IdentityKeys::add_claim() -- unknown claim type {}", claimtype),
                    };
                    let trans = self
                        .identity
                        .make_claim(&HashAlgo::Blake3, now, spec, Some(String::from(claimtype)))
                        .unwrap()
                        .sign(&self.master, &self.admin)
                        .unwrap();
                    self.identity = self.identity.clone().push_transaction(trans).unwrap();
                }

                fn make_stamp(&mut self, entry: StampEntry) {
                    let now = Timestamp::from_str("2016-04-04T02:00:00-0700").unwrap();
                    let trans = self
                        .identity
                        .make_stamp(&HashAlgo::Blake3, now, entry)
                        .unwrap()
                        .sign(&self.master, &self.admin)
                        .unwrap();
                    self.identity = self.identity.clone().push_transaction(trans).unwrap();
                }
            }
            let now = Timestamp::from_str("2016-04-04T02:00:00-0700").unwrap();
            let mut identities: HashMap<&'static str, IdentityKeys> = Default::default();
            #[allow(unused_mut)]
            let mut trust_mapping: HashMap<TransactionID, Trust> = HashMap::new();
            $({
                let name = stringify!($names);
                // can you hear me??
                let seed = format!("{} boofed gently", name);
                let mut rng = crate::util::test::rng_seeded(seed.as_bytes());
                let (master, identity, admin) = crate::util::test::create_fake_identity(&mut rng, now.clone());
                let mut ik = IdentityKeys::new(master, admin, identity);
                ik.add_claim("id"); // always the same.
                $(
                ik.add_claim(stringify!($claimtype));
                )*
                identities.insert(name, ik);
            })*

            $({
                let name = stringify!($names2);
                let trust: Trust = $trust;
                let ik = identities.get(name).expect("missing id");
                let identity_id = ik.identity.identity_id().unwrap().deref().clone();
                trust_mapping.insert(identity_id, trust);
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
                    let to_id = to.identity.build_identity_instance().unwrap();
                    let claim = match to_id.find_claim_by_name(claim_name) {
                        Some(claim) => claim,
                        None => panic!("make_trust_network! -- id {} is missing claim {} ...was it added to the definitions section??", to_name, claim_name),
                    };
                    (to.identity.identity_id().unwrap(), claim.id().clone())
                };

                let from = match identities.get_mut(from_name) {
                    Some(id) => id,
                    None => panic!("make_trust_network! -- referenced from id {} in stamps section, but it was not defined in the identities section", from_name),
                };
                from.make_stamp(StampEntry::new(
                    from.identity.identity_id().unwrap(),
                    to_id,
                    claim_id,
                    confidence,
                    None::<Timestamp>,
                ));
            })*
            let lookup = identities
                .iter()
                .map(|(k, IdentityKeys { identity, .. })| (identity.identity_id().unwrap().deref().clone(), k.clone()))
                .collect::<HashMap<_, _>>();
            let id_map = identities
                .into_iter()
                .map(|(k, IdentityKeys { identity, .. })| (k, identity))
                .collect::<HashMap<_, _>>();
            (id_map, trust_mapping, lookup)
        }};
    }

    fn paths_named(lookup: &HashMap<TransactionID, &'static str>, paths: &Vec<Vec<Vec<StampEntry>>>) -> Vec<Vec<&'static str>> {
        paths
            .iter()
            .map(|path| {
                path.iter()
                    .map(|p| *lookup.get(p[0].stampee().deref()).expect("missing identity in lookup"))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    }

    fn path_counts(paths: &Vec<Vec<Vec<StampEntry>>>) -> Vec<Vec<usize>> {
        paths
            .iter()
            .map(|path| path.iter().map(|stamps| stamps.len()).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    }

    fn trustnet_to_paths(
        identity_network: &HashMap<&'static str, Identity>,
        from: &'static str,
        to: &'static str,
        max_dist: usize,
    ) -> Vec<Vec<Vec<StampEntry>>> {
        let mut network = Network::new();
        let identities = identity_network
            .values()
            .map(|x| x.build_identity_instance().unwrap())
            .collect::<Vec<_>>();
        for id in &identities {
            network.add_node(id);
        }
        let from = identity_network.get(from).unwrap().identity_id().unwrap();
        let to = identity_network.get(to).unwrap().identity_id().unwrap();
        network
            .find_paths(&from, &to, max_dist)
            .into_iter()
            .map(|path| {
                path.into_vec()
                    .into_iter()
                    .map(|stamps| stamps.into_iter().cloned().collect::<Vec<_>>())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    }

    fn report_to_vals(report: &TrustReport) -> Vec<Vec<[i64; 5]>> {
        report
            .paths()
            .iter()
            .map(|path| {
                path.iter()
                    .map(|entry| {
                        [
                            *entry.trust_previous_node() as i64,
                            *entry.distance_from_originator() as i64,
                            *entry.trust_stamps() as i64,
                            *entry.trust_transferred() as i64,
                            *entry.trust_decayed() as i64,
                        ]
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    }

    #[test]
    fn network_find_paths() {
        {
            let (trustnet, _trustmap, lookup) = make_trust_network! {
                [ A(name), B(), ],
                [],
                [ A -> B (id, Confidence::High), ],
            };
            let paths = trustnet_to_paths(&trustnet, "A", "B", usize::MAX);
            let named = paths_named(&lookup, &paths);
            let counts = path_counts(&paths);
            assert_eq!(counts, vec![vec![1]]);
            assert_eq!(paths.len(), 1);
            assert_eq!(paths[0].len(), 1);
            assert_eq!(paths[0][0].len(), 1);
            assert_eq!(named, vec![vec!["B"]]);
        }

        {
            let (trustnet, _trustmap, lookup) = make_trust_network! {
                [
                    A(),
                    B(name, email),
                    C(email),
                ],
                [],
                [
                    A -> B (id, Confidence::Medium),
                    A -> B (name, Confidence::Medium),
                    A -> B (email, Confidence::Medium),
                    B -> C (id, Confidence::Low),
                    B -> C (email, Confidence::Low),
                    B -> A (id, Confidence::Ultimate),
                ],
            };
            let paths = trustnet_to_paths(&trustnet, "A", "C", usize::MAX);
            let named = paths_named(&lookup, &paths);
            let counts = path_counts(&paths);
            assert_eq!(counts, vec![vec![3, 2]]);
            assert_eq!(named, vec![vec!["B", "C"]]);
        }

        {
            let (trustnet, _trustmap, lookup) = make_trust_network! {
                [
                    A(),
                    B(),
                    C(),
                    D(),
                    E(),
                ],
                [],
                [
                    A -> B (id, Confidence::Low),
                    A -> C (id, Confidence::Low),
                    C -> B (id, Confidence::Low),
                    B -> A (id, Confidence::Low),
                    A -> B (id, Confidence::Low),
                    D -> E (id, Confidence::Low),
                ],
            };
            {
                let paths = trustnet_to_paths(&trustnet, "A", "D", usize::MAX);
                let named = paths_named(&lookup, &paths);
                assert_eq!(paths.len(), 0);
                assert_eq!(named.len(), 0);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "E", usize::MAX);
                let named = paths_named(&lookup, &paths);
                assert_eq!(paths.len(), 0);
                assert_eq!(named.len(), 0);
            }
        }

        {
            let (trustnet, _trustmap, lookup) = make_trust_network! {
                [
                    A(),
                    B(),
                    C(),
                    D(),
                    E(),
                ],
                [],
                [
                    A -> B (id, Confidence::Low),
                    B -> C (id, Confidence::Low),
                    C -> D (id, Confidence::Low),
                    D -> A (id, Confidence::Low),
                    A -> E (id, Confidence::Low),
                ],
            };
            let paths = trustnet_to_paths(&trustnet, "A", "E", usize::MAX);
            let named = paths_named(&lookup, &paths);
            let counts = path_counts(&paths);
            assert_eq!(counts, vec![vec![1]]);
            assert_eq!(named, vec![vec!["E"]]);
        }
    }

    #[test]
    fn network_find_paths_stable_order() {
        let (counts1, named1) = {
            let (trustnet, _trustmap, lookup) = make_trust_network! {
                [
                    A(name),
                    B(),
                    C(name, email),
                    D(),
                    E(),
                    F(),
                    G(name),
                ],
                [],
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
            let paths = trustnet_to_paths(&trustnet, "A", "G", usize::MAX);
            let named = paths_named(&lookup, &paths);
            let counts = path_counts(&paths);
            assert_eq!(
                counts,
                vec![
                    vec![1, 2, 1, 1, 1],
                    vec![1, 2, 1, 1, 1],
                    vec![1, 1, 1, 1],
                    vec![1, 1, 2, 1, 1, 1],
                    vec![1, 1],
                ]
            );
            assert_eq!(
                named,
                vec![
                    vec!["B", "C", "E", "F", "G"],
                    vec!["B", "C", "E", "D", "G"],
                    vec!["D", "E", "F", "G"],
                    vec!["D", "B", "C", "E", "F", "G"],
                    vec!["D", "G"],
                ],
            );
            (counts, named)
        };
        {
            // same network, different ordering of links, should yield same paths
            let (trustnet, _trustmap, lookup) = make_trust_network! {
                [
                    B(),
                    F(),
                    E(),
                    A(name),
                    G(name),
                    D(),
                    C(name, email),
                ],
                [],
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
            let paths = trustnet_to_paths(&trustnet, "A", "G", usize::MAX);
            let named = paths_named(&lookup, &paths);
            let counts = path_counts(&paths);
            assert_eq!(counts, counts1);
            assert_eq!(named, named1);
        }
    }

    #[test]
    fn network_find_paths_max_distance() {
        {
            let (trustnet, _trustmap, lookup) = make_trust_network! {
                [
                    A(),
                    B(),
                    C(),
                    D(),
                    E(),
                    F(),
                    G(),
                ],
                [],
                [
                    A -> B (id, Confidence::High),
                    B -> C (id, Confidence::High),
                    C -> D (id, Confidence::High),
                    D -> E (id, Confidence::High),
                    E -> F (id, Confidence::High),
                    F -> G (id, Confidence::High),
                ],
            };
            {
                let paths = trustnet_to_paths(&trustnet, "A", "G", usize::MAX);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts, vec![vec![1, 1, 1, 1, 1, 1]]);
                assert_eq!(named, vec![vec!["B", "C", "D", "E", "F", "G"]]);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "G", 3);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts.len(), 0);
                assert_eq!(named.len(), 0);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "G", 3);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts.len(), 0);
                assert_eq!(named.len(), 0);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "G", 6);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts, vec![vec![1, 1, 1, 1, 1, 1]]);
                assert_eq!(named, vec![vec!["B", "C", "D", "E", "F", "G"]]);
            }
        }

        {
            let (trustnet, _trustmap, lookup) = make_trust_network! {
                [
                    A(),
                    B(),
                    C(),
                    D(),
                    E(),
                    F(),
                    G(),
                ],
                [],
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
            {
                let paths = trustnet_to_paths(&trustnet, "A", "G", usize::MAX);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts, vec![vec![1, 1, 1, 1, 1, 1], vec![1, 1]]);
                assert_eq!(named, vec![vec!["B", "C", "D", "E", "F", "G"], vec!["B", "G"]]);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "G", 1);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts.len(), 0);
                assert_eq!(named.len(), 0);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "G", 3);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts, vec![vec![1, 1]]);
                assert_eq!(named, vec![vec!["B", "G"]]);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "G", 5);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts, vec![vec![1, 1]]);
                assert_eq!(named, vec![vec!["B", "G"]]);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "G", 6);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts, vec![vec![1, 1, 1, 1, 1, 1], vec![1, 1]]);
                assert_eq!(named, vec![vec!["B", "C", "D", "E", "F", "G"], vec!["B", "G"]]);
            }
        }

        {
            let (trustnet, _trustmap, lookup) = make_trust_network! {
                [
                    A(),
                    B(),
                    C(),
                    D(),
                    E(),
                    F(),
                    G(),
                ],
                [],
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
            {
                let paths = trustnet_to_paths(&trustnet, "A", "F", usize::MAX);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts, vec![vec![1, 1, 1, 1, 1], vec![1, 1, 1, 1, 1, 1]]);
                assert_eq!(named, vec![vec!["B", "C", "D", "E", "F"], vec!["G", "B", "C", "D", "E", "F"],]);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "F", 1);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts.len(), 0);
                assert_eq!(named.len(), 0);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "F", 3);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts.len(), 0);
                assert_eq!(named.len(), 0);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "F", 5);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts, vec![vec![1, 1, 1, 1, 1]]);
                assert_eq!(named, vec![vec!["B", "C", "D", "E", "F"]]);
            }
            {
                let paths = trustnet_to_paths(&trustnet, "A", "F", 6);
                let named = paths_named(&lookup, &paths);
                let counts = path_counts(&paths);
                assert_eq!(counts, vec![vec![1, 1, 1, 1, 1], vec![1, 1, 1, 1, 1, 1]]);
                assert_eq!(named, vec![vec!["B", "C", "D", "E", "F"], vec!["G", "B", "C", "D", "E", "F"],]);
            }
        }
    }

    #[test]
    fn trust_algo_default_stamps() {
        let (trustnet, _trustmap, _lookup) = make_trust_network! {
            [
                A(),
                B(name, email),
                C(name, email),
                D(email),
            ],
            [ ],
            [
                A -> B (id, Confidence::High),
                A -> B (name, Confidence::Medium),
                A -> C (id, Confidence::Low),
                A -> C (email, Confidence::Low),
                B -> C (id, Confidence::High),
                B -> C (name, Confidence::High),
                B -> C (email, Confidence::Medium),
                B -> D (id, Confidence::Negative),
                C -> D (id, Confidence::Low),
                C -> D (email, Confidence::Medium),
            ],
        };
        let id_a = trustnet.get("A").unwrap().build_identity_instance().unwrap();
        let id_b = trustnet.get("B").unwrap().build_identity_instance().unwrap();
        let id_c = trustnet.get("C").unwrap().build_identity_instance().unwrap();
        let id_d = trustnet.get("D").unwrap().build_identity_instance().unwrap();
        let algo = TrustAlgoDefault::default();

        let stamps_a_b = id_a
            .stamps()
            .iter()
            .map(|s| s.entry())
            .filter(|s| s.stampee() == id_b.id())
            .collect::<Vec<_>>();
        let stamps_a_c = id_a
            .stamps()
            .iter()
            .map(|s| s.entry())
            .filter(|s| s.stampee() == id_c.id())
            .collect::<Vec<_>>();
        let stamps_a_d = id_a
            .stamps()
            .iter()
            .map(|s| s.entry())
            .filter(|s| s.stampee() == id_d.id())
            .collect::<Vec<_>>();
        let stamps_b_c = id_b
            .stamps()
            .iter()
            .map(|s| s.entry())
            .filter(|s| s.stampee() == id_c.id())
            .collect::<Vec<_>>();
        let stamps_b_d = id_b
            .stamps()
            .iter()
            .map(|s| s.entry())
            .filter(|s| s.stampee() == id_d.id())
            .collect::<Vec<_>>();
        let stamps_c_d = id_c
            .stamps()
            .iter()
            .map(|s| s.entry())
            .filter(|s| s.stampee() == id_d.id())
            .collect::<Vec<_>>();

        let trust_a_b = algo.trust_from_stamps(&stamps_a_b);
        let trust_a_c = algo.trust_from_stamps(&stamps_a_c);
        let trust_a_d = algo.trust_from_stamps(&stamps_a_d);
        let trust_b_c = algo.trust_from_stamps(&stamps_b_c);
        let trust_b_d = algo.trust_from_stamps(&stamps_b_d);
        let trust_c_d = algo.trust_from_stamps(&stamps_c_d);
        assert_eq!(trust_a_b, 75);
        assert_eq!(trust_a_c, 10);
        assert_eq!(trust_a_d, 0);
        assert_eq!(trust_b_c, 83);
        assert_eq!(trust_b_d, -128);
        assert_eq!(trust_c_d, 30);
    }

    #[test]
    fn trust_algo_default_merge() {
        let algo = TrustAlgoDefault::default();
        assert_eq!(algo.merge(&[]), 0);
        assert_eq!(algo.merge(&[-60, 42, 50]), 32);
        assert_eq!(algo.merge(&[50, 50, 50]), 127);
        assert_eq!(algo.merge(&[100, 50, 75, 10]), 127);
        assert_eq!(algo.merge(&[67, 3, 24]), 94);
        assert_eq!(algo.merge(&[-58, -32]), -90);
        assert_eq!(algo.merge(&[-58, -32, -90]), -128);
    }

    #[test]
    fn trust_algo_default_decay() {
        {
            let algo = TrustAlgoDefault::default();
            assert_eq!(algo.trust_decay_per_hop(), 64);
            assert_eq!(algo.max_distance(), 1);
            assert_eq!(algo.decay(100, 0), 100);
            assert_eq!(algo.decay(100, 1), 100);
            assert_eq!(algo.decay(100, 2), 0);
            assert_eq!(algo.decay(100, 3), 0);
            assert_eq!(algo.decay(100, 4), 0);
            assert_eq!(algo.decay(100, 5), 0);
            assert_eq!(algo.decay(100, 6), 0);
            assert_eq!(algo.decay(100, 7), 0);
            assert_eq!(algo.decay(100, 8), 0);
            assert_eq!(algo.decay(100, 9), 0);
            assert_eq!(algo.decay(100, 10), 0);
        }
        {
            let algo = TrustAlgoDefault::new(5, 2, 5);
            assert_eq!(algo.trust_decay_per_hop(), 5);
            assert_eq!(algo.max_distance(), 5);
            assert_eq!(algo.decay(100, 0), 100);
            assert_eq!(algo.decay(100, 1), 100);
            assert_eq!(algo.decay(100, 2), 100);
            assert_eq!(algo.decay(100, 3), 95);
            assert_eq!(algo.decay(100, 4), 90);
            assert_eq!(algo.decay(100, 5), 85);
            assert_eq!(algo.decay(100, 6), 0);
            assert_eq!(algo.decay(100, 7), 0);
            assert_eq!(algo.decay(100, 8), 0);
            assert_eq!(algo.decay(100, 9), 0);
            assert_eq!(algo.decay(100, 10), 0);
        }
        {
            let algo = TrustAlgoDefault::new(64, 1, 0);
            assert_eq!(algo.trust_decay_per_hop(), 64);
            assert_eq!(algo.max_distance(), 0);
            assert_eq!(algo.decay(100, 0), 100);
            assert_eq!(algo.decay(100, 1), 0);
            assert_eq!(algo.decay(100, 2), 0);
            assert_eq!(algo.decay(100, 3), 0);
            assert_eq!(algo.decay(100, 4), 0);
            assert_eq!(algo.decay(100, 5), 0);
            assert_eq!(algo.decay(100, 6), 0);
            assert_eq!(algo.decay(100, 7), 0);
            assert_eq!(algo.decay(100, 8), 0);
            assert_eq!(algo.decay(100, 9), 0);
            assert_eq!(algo.decay(100, 10), 0);
        }
        {
            let algo = TrustAlgoDefault::new(64, 1, 1);
            assert_eq!(algo.trust_decay_per_hop(), 64);
            assert_eq!(algo.max_distance(), 1);
            assert_eq!(algo.decay(100, 0), 100);
            assert_eq!(algo.decay(100, 1), 100);
            assert_eq!(algo.decay(100, 2), 0);
            assert_eq!(algo.decay(100, 3), 0);
            assert_eq!(algo.decay(100, 4), 0);
            assert_eq!(algo.decay(100, 5), 0);
            assert_eq!(algo.decay(100, 6), 0);
            assert_eq!(algo.decay(100, 7), 0);
            assert_eq!(algo.decay(100, 8), 0);
            assert_eq!(algo.decay(100, 9), 0);
            assert_eq!(algo.decay(100, 10), 0);
        }
        {
            let algo = TrustAlgoDefault::new(20, 1, 2);
            assert_eq!(algo.trust_decay_per_hop(), 20);
            assert_eq!(algo.max_distance(), 2);
            assert_eq!(algo.decay(100, 0), 100);
            assert_eq!(algo.decay(100, 1), 100);
            assert_eq!(algo.decay(100, 2), 80);
            assert_eq!(algo.decay(100, 3), 0);
            assert_eq!(algo.decay(100, 4), 0);
            assert_eq!(algo.decay(100, 5), 0);
            assert_eq!(algo.decay(100, 6), 0);
            assert_eq!(algo.decay(100, 7), 0);
            assert_eq!(algo.decay(100, 8), 0);
            assert_eq!(algo.decay(100, 9), 0);
            assert_eq!(algo.decay(100, 10), 0);
        }
        {
            let algo = TrustAlgoDefault::new(10, 1, 10);
            assert_eq!(algo.trust_decay_per_hop(), 10);
            assert_eq!(algo.max_distance(), 10);
            assert_eq!(algo.decay(100, 0), 100);
            assert_eq!(algo.decay(100, 1), 100);
            assert_eq!(algo.decay(100, 2), 90);
            assert_eq!(algo.decay(100, 3), 80);
            assert_eq!(algo.decay(100, 4), 70);
            assert_eq!(algo.decay(100, 5), 60);
            assert_eq!(algo.decay(100, 6), 50);
            assert_eq!(algo.decay(100, 7), 40);
            assert_eq!(algo.decay(100, 8), 30);
            assert_eq!(algo.decay(100, 9), 20);
            assert_eq!(algo.decay(100, 10), 10);
            assert_eq!(algo.decay(120, 10), 30);
            assert_eq!(algo.decay(120, 11), 0);
        }
    }

    #[test]
    fn trust_score_simple() {
        let (trustnet, trustmap, _lookup) = make_trust_network! {
            [
                A(),
                B(name),
                C(),
                D(),
            ],
            [
                A(Trust::Ultimate),
                C(Trust::Marginal),
            ],
            [
                A -> B (id, Confidence::High),
                A -> B (name, Confidence::Medium),
                B -> C (id, Confidence::Low),
                A -> C (id, Confidence::High),
                C -> D (id, Confidence::High),
            ],
        };
        let id_d = trustnet.get("D").unwrap().identity_id().unwrap();
        let ids = trustnet.values().map(|x| x.build_identity_instance().unwrap()).collect::<Vec<_>>();
        let ids_borrow = ids.iter().collect::<Vec<_>>();
        let trust_algo = TrustAlgoDefault::default();
        let (score, report) = trust_score(&trustmap, &id_d, ids_borrow.as_slice(), &trust_algo).unwrap();
        let report_vals = report_to_vals(&report);
        assert_eq!(score, 15);
        assert_eq!(report_vals, vec![vec![[20, 1, 100, 15, 15]]]);
    }

    #[test]
    fn trust_score_max_dist() {
        let (trustnet, trustmap, _lookup) = make_trust_network! {
            [
                A(),
                B(),
                C(),
                D(),
                E(),
                F(),
                G(),
            ],
            [ A(Trust::Ultimate), ],
            [
                A -> B (id, Confidence::High),
                B -> C (id, Confidence::High),
                C -> D (id, Confidence::High),
                D -> E (id, Confidence::High),
                E -> F (id, Confidence::High),
                F -> G (id, Confidence::High),
            ],
        };
        let id_c = trustnet.get("C").unwrap().identity_id().unwrap();
        let id_f = trustnet.get("F").unwrap().identity_id().unwrap();
        let id_g = trustnet.get("G").unwrap().identity_id().unwrap();
        let ids = trustnet.values().map(|x| x.build_identity_instance().unwrap()).collect::<Vec<_>>();
        let ids_borrow = ids.iter().collect::<Vec<_>>();
        let trust_algo = TrustAlgoDefault::new(i8::MAX / 5, 1, 5);
        {
            let (score, report) = trust_score(&trustmap, &id_c, ids_borrow.as_slice(), &trust_algo).unwrap();
            let report_vals = report_to_vals(&report);
            assert_eq!(score, 53);
            assert_eq!(report_vals, vec![vec![[127, 1, 100, 100, 100], [100, 2, 100, 78, 53]]]);
        }
        {
            let (score, report) = trust_score(&trustmap, &id_f, ids_borrow.as_slice(), &trust_algo).unwrap();
            let report_vals = report_to_vals(&report);
            assert_eq!(score, 0);
            assert_eq!(report_vals, vec![vec![[127, 1, 100, 100, 100], [100, 2, 100, 78, 53], [53, 3, 100, 41, 0],]]);
        }
        {
            let res = trust_score(&trustmap, &id_g, ids_borrow.as_slice(), &trust_algo);
            assert!(res.is_none());
        }
    }

    #[test]
    fn trust_score_branches() {
        {
            let (trustnet, trustmap, _lookup) = make_trust_network! {
                [
                    A(),
                    B(name),
                    C(),
                    D(),
                    E(email),
                ],
                [ A(Trust::Ultimate), D(Trust::Marginal), ],
                [
                    A -> B (id, Confidence::High),
                    A -> B (name, Confidence::Medium),
                    B -> E (id, Confidence::High),
                    B -> E (email, Confidence::High),

                    A -> C (id, Confidence::Ultimate),
                    C -> E (id, Confidence::Medium),

                    A -> D (id, Confidence::Medium),
                    D -> E (id, Confidence::Medium),
                    D -> E (email, Confidence::High),
                ],
            };
            let id_e = trustnet.get("E").unwrap().identity_id().unwrap();
            let ids = trustnet.values().map(|x| x.build_identity_instance().unwrap()).collect::<Vec<_>>();
            let ids_borrow = ids.iter().collect::<Vec<_>>();
            let trust_algo = TrustAlgoDefault::new(50, 1, 4);
            let (score, report) = trust_score(&trustmap, &id_e, ids_borrow.as_slice(), &trust_algo).unwrap();
            let report_vals = report_to_vals(&report);
            assert_eq!(score, 20);
            assert_eq!(
                report_vals,
                vec![
                    vec![[127, 1, 127, 127, 127], [127, 2, 50, 50, 0]],
                    vec![[127, 1, 75, 75, 75], [75, 2, 100, 59, 9]],
                    vec![[127, 1, 50, 50, 50], [50, 2, 75, 29, 0]],
                    vec![[20, 1, 75, 11, 11]],
                ]
            );
        }
    }

    #[test]
    fn trust_score_negative() {
        {
            let (trustnet, trustmap, _lookup) = make_trust_network! {
                [
                    A(),
                    B(),
                    C(),
                    D(),
                ],
                [ A(Trust::Ultimate), C(Trust::Negative), ],
                [
                    A -> B (id, Confidence::High),
                    B -> C (id, Confidence::High),
                    C -> D (id, Confidence::High),
                ],
            };
            let id_d = trustnet.get("D").unwrap().identity_id().unwrap();
            let ids = trustnet.values().map(|x| x.build_identity_instance().unwrap()).collect::<Vec<_>>();
            let ids_borrow = ids.iter().collect::<Vec<_>>();
            let trust_algo = TrustAlgoDefault::default();

            let (score, report) = trust_score(&trustmap, &id_d, ids_borrow.as_slice(), &trust_algo).unwrap();
            let report_vals = report_to_vals(&report);
            assert_eq!(score, 0);
            assert_eq!(report_vals, vec![vec![[-128, 1, 100, -100, -100]],]);
        }
    }
}
