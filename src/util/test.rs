use crate::{
    crypto::key::{SecretKey, SignKeypair, CryptoKeypair},
    identity::{
        identity::{IdentityID, Identity},
        keychain::{ExtendKeypair, AlphaKeypair, PolicyKeypair, PublishKeypair, RootKeypair, Key},
    },
    util::Timestamp,
};
use std::thread;
use std::time::Duration;

/// Go to sleeeeep
#[allow(dead_code)]
pub(crate) fn sleep(millis: u64) {
    thread::sleep(Duration::from_millis(millis));
}

pub(crate) fn setup_identity_with_subkeys() -> (SecretKey, Identity) {
    let master_key = SecretKey::new_xsalsa20poly1305().unwrap();
    let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
    let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
    let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
    let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
    let identity = Identity::create(IdentityID::random(), alpha_keypair, policy_keypair, publish_keypair, root_keypair, Timestamp::now())
        .add_subkey(Key::new_sign(SignKeypair::new_ed25519(&master_key).unwrap()), "sign", None).unwrap()
        .add_subkey(Key::new_crypto(CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap()), "cryptololol", None).unwrap();
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

