use crate::{
    crypto::base::{SecretKey, SignKeypair, CryptoKeypair},
    dag::Transactions,
    identity::{
        identity::{IdentityID, Identity},
        keychain::{ExtendKeypair, AdminKey, AdminKeypair, Key},
    },
    policy::{Capability, MultisigPolicy, Participant, Policy, PolicyContainer},
    util::Timestamp,
};
use std::thread;
use std::time::Duration;

/// Go to sleeeeep
#[allow(dead_code)]
pub(crate) fn sleep(millis: u64) {
    thread::sleep(Duration::from_millis(millis));
}

pub(crate) fn create_fake_identity(now: Timestamp) -> (SecretKey, Transactions, AdminKey) {
    let transactions = Transactions::new();
    let master_key = SecretKey::new_xchacha20poly1305().unwrap();
    let sign = SignKeypair::new_ed25519(&master_key).unwrap();
    let admin = AdminKeypair::from(sign);
    let admin_key = AdminKey::new(admin, "Alpha", None);
    let policy = Policy::new(
        vec![Capability::Permissive],
        MultisigPolicy::MOfN { must_have: 1, participants: vec![admin_key.key().clone().into()] }
    );
    let trans_id = transactions
        .create_identity(now, vec![admin_key.clone()], vec![policy]).unwrap()
        .sign(&master_key, &admin_key).unwrap();
    let transactions2 = transactions.push_transaction(trans_id).unwrap();
    (master_key, transactions2, admin_key)
}

pub(crate) fn setup_identity_with_subkeys() -> (SecretKey, Identity) {
    let master_key = SecretKey::new_xchacha20poly1305().unwrap();
    let admin_keypair = AdminKeypair::new_ed25519(&master_key).unwrap();
    let policy = Policy::new(
        vec![Capability::Permissive],
        MultisigPolicy::MOfN { must_have: 1, participants: vec![Participant::Key(admin_keypair.clone().into())] }
    );
    let policy_con = PolicyContainer::try_from(policy).unwrap();
    let admin_key = AdminKey::new(admin_keypair, "Alpha", None);
    let identity = Identity::create(IdentityID::random(), vec![admin_key], vec![policy_con], Timestamp::now())
        .add_subkey(Key::new_sign(SignKeypair::new_ed25519(&master_key).unwrap()), "sign", None).unwrap()
        .add_subkey(Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap()), "cryptololol", None).unwrap();
    (master_key, identity)
}

/// Given a set of values, find all combinations of those values as present or
/// absent in a vec.
///
/// Useful for poor attempts at fuzzing/parameter testing. Should be ripped out
/// and replaced with something more proper.
pub(crate) fn generate_combinations<T: Clone>(vals: &Vec<T>) -> Vec<Vec<T>> {
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

