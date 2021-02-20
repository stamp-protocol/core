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
pub fn sleep(millis: u64) {
    thread::sleep(Duration::from_millis(millis));
}

pub fn setup_identity_with_subkeys() -> (SecretKey, Identity) {
    let master_key = SecretKey::new_xsalsa20poly1305();
    let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
    let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
    let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
    let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
    let identity = Identity::create(IdentityID::random(), alpha_keypair, policy_keypair, publish_keypair, root_keypair, Timestamp::now())
        .add_subkey(Key::new_sign(SignKeypair::new_ed25519(&master_key).unwrap()), "sign", None).unwrap()
        .add_subkey(Key::new_crypto(CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap()), "cryptololol", None).unwrap();
    (master_key, identity)
}

