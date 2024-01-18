use crate::{
    crypto::base::{CryptoKeypair, Hash, HashAlgo, SecretKey, SignKeypair},
    dag::{TransactionID, Transactions},
    identity::{
        identity::{IdentityID, Identity},
        keychain::{ExtendKeypair, AdminKey, AdminKeypair, Key},
    },
    policy::{Capability, MultisigPolicy, Participant, Policy, PolicyContainer},
    util::Timestamp,
};
use rand::{CryptoRng, RngCore, SeedableRng};
use std::thread;
use std::time::Duration;

/// Go to sleeeeep
#[allow(dead_code)]
pub(crate) fn sleep(millis: u64) {
    thread::sleep(Duration::from_millis(millis));
}

pub(crate) fn rng() -> rand_chacha::ChaCha20Rng { 
    crate::crypto::base::rng()
}

pub(crate) fn rng_seeded(seed: &[u8]) -> rand_chacha::ChaCha20Rng {
    let seed_hash = Hash::new_blake3(seed).unwrap();
    let seed_bytes: [u8; 32] = seed_hash.as_bytes().try_into().unwrap();
    rand_chacha::ChaCha20Rng::from_seed(seed_bytes)
}

pub(crate) fn create_fake_identity<R: RngCore + CryptoRng>(rng: &mut R, now: Timestamp) -> (SecretKey, Transactions, AdminKey) {
    let transactions = Transactions::new();
    let master_key = SecretKey::new_xchacha20poly1305(rng).unwrap();
    let admin = AdminKeypair::new_ed25519(rng, &master_key).unwrap();
    let admin_key = AdminKey::new(admin, "Alpha", None);
    let policy = Policy::new(
        vec![Capability::Permissive],
        MultisigPolicy::MOfN { must_have: 1, participants: vec![admin_key.key().clone().into()] }
    );
    let trans = transactions
        .create_identity(&HashAlgo::Blake3, now, vec![admin_key.clone()], vec![policy]).unwrap()
        .sign(&master_key, &admin_key).unwrap();
    let transactions2 = transactions.push_transaction(trans).unwrap();
    (master_key, transactions2, admin_key)
}

pub(crate) fn setup_identity_with_subkeys<R: RngCore + CryptoRng>(rng: &mut R) -> (SecretKey, Identity) {
    let master_key = SecretKey::new_xchacha20poly1305(rng).unwrap();
    let admin_keypair = AdminKeypair::new_ed25519(rng, &master_key).unwrap();
    let policy = Policy::new(
        vec![Capability::Permissive],
        MultisigPolicy::MOfN {
            must_have: 1,
            participants: vec![
                Participant::Key { name: Some("Default".into()), key: admin_keypair.clone().into() },
            ],
        }
    );
    let policy_transaction_id = TransactionID::from(Hash::new_blake3(b"policy").unwrap());
    let policy_con = PolicyContainer::from_policy_transaction(&policy_transaction_id, 0, policy).unwrap();
    let admin_key = AdminKey::new(admin_keypair, "Alpha", None);
    let identity = Identity::create(IdentityID::random(), vec![admin_key], vec![policy_con], Timestamp::now())
        .add_subkey(Key::new_sign(SignKeypair::new_ed25519(rng, &master_key).unwrap()), "sign", None).unwrap()
        .add_subkey(Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(rng, &master_key).unwrap()), "cryptololol", None).unwrap();
    (master_key, identity)
}

/// Given a set of values, find all combinations of those values as present or
/// absent in a vec.
///
/// Useful for poor attempts at fuzzing/parameter testing. Should be ripped out
/// and replaced with something more proper.
pub(crate) fn generate_combinations<T: Clone>(vals: &[T]) -> Vec<Vec<T>> {
    // we use binary counting here to accomplish the combination finding.
    // this might seem obtuse, but i have 4 hours of sleep and this seems
    // like the quickest way to get it done.
    let mut out = vec![];
    let combos = 2u32.pow(vals.len() as u32);
    for i in 0..combos {
        let mut combo = vec![];
        let mut bits = i;
        for idx in 0..vals.len() {
            if bits & 1 > 0 {
                combo.push(vals[idx].clone());
            }
            bits = bits >> 1;
        }
        out.push(combo);
    }
    out
}

macro_rules! sign_and_push {
    ($master_key:expr, $admin_key:expr, $transactions:expr, $([ $fn:ident, $($args:expr),* ])*) => {{
        let mut trans_tmp = $transactions;
        $(
            let trans = trans_tmp.$fn(&crate::crypto::base::HashAlgo::Blake3, $($args),*).unwrap();
            let trans_signed = trans.sign($master_key, $admin_key).unwrap();
            trans_tmp = trans_tmp.push_transaction(trans_signed).unwrap();
        )*
        trans_tmp
    }};
}
pub(crate) use sign_and_push;

macro_rules! make_dag_chain {
    (
        $transactions:expr,
        [$($names:ident($ts:expr)),*],
        [$([$($from:ident),*] <- [$($to:ident),*],)*],
        [$($omit:ident),*]
    ) => {{
        let trans = &$transactions;
        let mut name_to_tid = std::collections::HashMap::new();
        let mut tid_to_name = std::collections::HashMap::new();
        $(
            let dt: chrono::DateTime<chrono::Utc> = chrono::DateTime::from_timestamp(2455191939 + $ts, 0).unwrap();
            let now = crate::util::Timestamp::from(dt);
            let mut $names = trans.ext(&crate::crypto::base::HashAlgo::Blake3, now, vec![], None, None::<HashMapAsn1<BinaryVec, BinaryVec>>, Vec::from(format!("{}", stringify!($names)).as_bytes()).into()).unwrap();
            $names.entry_mut().set_previous_transactions(vec![]);
            name_to_tid.insert(stringify!($names), $names.id().clone());
            tid_to_name.insert($names.id().clone(), stringify!($names));
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
        (ret, tid_to_name, name_to_tid)
    }}
}
pub(crate) use make_dag_chain;

