use crate::{
    crypto::key::{SecretKey, SignKeypair, CryptoKeypair},
    identity::{
        Key,
        Identity,
    },
    util::Timestamp,
};

pub fn setup_identity_with_subkeys() -> (SecretKey, Identity) {
    let master_key = SecretKey::new_xsalsa20poly1305();
    let identity = Identity::new(&master_key, Timestamp::now()).unwrap()
        .add_subkey(&master_key, Key::new_sign(SignKeypair::new_ed25519(&master_key).unwrap()), "sign", None).unwrap()
        .add_subkey(&master_key, Key::new_crypto(CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap()), "cryptololol", None).unwrap();
    (master_key, identity)
}

