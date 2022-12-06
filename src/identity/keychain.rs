//! The keychain holds all of the keys, active or revoked, for an idntity. It
//! stores keys not only used for the identity itself, but any kind of
//! cryptographic keys the identity holds wishes to use.
//!
//! For instance, they might store an "email" keypair and request that others
//! encrypt emails to them via that key. They might store their dogecoin wallet
//! private keys in the keychain. They could even store the key to their heart
//! (as long as it can be represented cryptographically).
//!
//! Because the keychain stores even revoked keys, it's possible to verify old
//! signatures made with those keys even if they aren't in active use anymore.
//! This gives identities a longevity that wouldn't be possible if they were
//! tied to just a single keypair.

use crate::{
    error::{Error, Result},
    crypto::key::{KeyID, SecretKey, SignKeypairSignature, SignKeypair, SignKeypairPublic, CryptoKeypair},
    private::{PrivateWithMac},
    util::{Public, sign::Signable, ser},
};
use getset;
use rasn::{AsnType, Encode, Decode};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// Allows us to create new signature types from the base SignKeypairSignature.
pub trait ExtendKeypairSignature: From<SignKeypairSignature> + Clone + PartialEq + Deref<Target = SignKeypairSignature> + serde::Serialize + serde::de::DeserializeOwned {}

/// Allows us to create new signing keypair types from the base SignKeypair.
///
/// Now, says to myself, Colm, says I...
pub trait ExtendKeypair: From<SignKeypair> + Clone + PartialEq + Deref<Target = SignKeypair> + Public + PartialEq + Signable + serde::Serialize + serde::de::DeserializeOwned {
    type Signature: ExtendKeypairSignature;

    /// Create a new ed25519 keypair
    fn new_ed25519(master_key: &SecretKey) -> Result<Self> {
        let sign = SignKeypair::new_ed25519(master_key)?;
        Ok(Self::from(sign))
    }

    /// Create a new ed25519 keypair
    fn new_ed25519_from_seed(master_key: &SecretKey, seed_bytes: &[u8; 32]) -> Result<Self> {
        let sign = SignKeypair::new_ed25519_from_seed(master_key, seed_bytes)?;
        Ok(Self::from(sign))
    }

    /// Sign a value with our secret signing key.
    ///
    /// Must be unlocked via our master key.
    fn sign(&self, master_key: &SecretKey, data: &[u8]) -> Result<Self::Signature> {
        let sig = self.deref().sign(master_key, data)?;
        Ok(Self::Signature::from(sig))
    }

    /// Verify a value with a detached signature given the public key of the
    /// signer.
    fn verify(&self, signature: &Self::Signature, data: &[u8]) -> Result<()> {
        self.deref().verify(signature.deref(), data)
    }

    /// REEEEEEEE-encrypt this signing keypair with a new master key.
    fn reencrypt(self, previous_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        Ok(Self::from(self.deref().clone().reencrypt(previous_master_key, new_master_key)?))
    }

    /// Create a KeyID from this keypair.
    fn key_id(&self) -> KeyID {
        let inner: &SignKeypair = self.deref();
        KeyID::SignKeypair(inner.clone().into())
    }
}

macro_rules! make_keytype {
    ($keytype:ident, $keytype_public:ident, $signaturetype:ident, $keyid:ident) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $signaturetype(SignKeypairSignature);

        asn_encdec_newtype! { $signaturetype, SignKeypairSignature }

        impl Deref for $signaturetype {
            type Target = SignKeypairSignature;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl From<SignKeypairSignature> for $signaturetype {
            fn from(sig: SignKeypairSignature) -> Self {
                Self(sig)
            }
        }

        impl AsRef<[u8]> for $signaturetype {
            fn as_ref(&self) -> &[u8] {
                self.deref().as_ref()
            }
        }

        impl ExtendKeypairSignature for $signaturetype {}

        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $keytype_public(SignKeypairPublic);

        asn_encdec_newtype! { $keytype_public, SignKeypairPublic }

        impl From<SignKeypairPublic> for $keytype_public {
            fn from(pubkey: SignKeypairPublic) -> Self {
                Self(pubkey)
            }
        }

        impl Deref for $keytype_public {
            type Target = SignKeypairPublic;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct $keytype(SignKeypair);

        asn_encdec_newtype! { $keytype, SignKeypair }

        impl From<SignKeypair> for $keytype {
            fn from(sign: SignKeypair) -> Self {
                Self(sign)
            }
        }

        impl From<$keytype> for $keytype_public {
            fn from(key: $keytype) -> Self {
                Self(key.deref().clone().into())
            }
        }

        impl Deref for $keytype {
            type Target = SignKeypair;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl Public for $keytype {
            fn strip_private(&self) -> Self {
                Self::from(self.deref().strip_private())
            }

            fn has_private(&self) -> bool {
                self.deref().has_private()
            }
        }

        impl PartialEq for $keytype {
            fn eq(&self, other: &Self) -> bool {
                self.deref().eq(other.deref())
            }
        }

        impl Signable for $keytype {
            type Item = $keytype_public;
            fn signable(&self) -> Self::Item {
                Self::Item::from(self.deref().signable())
            }
        }

        impl ExtendKeypair for $keytype {
            type Signature = $signaturetype;
        }

        #[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
        pub struct $keyid(KeyID);

        impl From<KeyID> for $keyid {
            fn from(id: KeyID) -> Self {
                Self(id)
            }
        }

        impl From<$keyid> for KeyID {
            fn from(id: $keyid) -> Self {
                let $keyid(inner) = id;
                inner
            }
        }

        impl From<SignKeypairPublic> for $keyid {
            fn from(pubkey: SignKeypairPublic) -> Self {
                KeyID::SignKeypair(pubkey).into()
            }
        }

        impl Deref for $keyid {
            type Target = KeyID;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    }
}

make_keytype! { AdminKeypair, AdminKeypairPublic, AdminKeypairSignature, AdminKeyID }

/// Why we are revoking a key.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum RevocationReason {
    /// No reason. Feeling cute today, might revoke my keys, IDK.
    #[rasn(tag(explicit(0)))]
    Unspecified,
    /// This key is being replaced by the recovery mechanism.
    #[rasn(tag(explicit(1)))]
    Recovery,
    /// Replacing this key with another.
    #[rasn(tag(explicit(2)))]
    Superseded,
    /// This key has been compromised.
    #[rasn(tag(explicit(3)))]
    Compromised,
    /// This key was signed by a compromised key and should never be used.
    #[rasn(tag(explicit(4)))]
    Invalid,
}

/// An enum that holds any type of key.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum Key {
    /// An admin key
    #[rasn(tag(explicit(0)))]
    Admin(AdminKeypair),
    /// A signing key.
    #[rasn(tag(explicit(1)))]
    Sign(SignKeypair),
    /// An asymmetric crypto key.
    #[rasn(tag(explicit(2)))]
    Crypto(CryptoKeypair),
    /// A symmetric encryption key.
    #[rasn(tag(explicit(3)))]
    Secret(PrivateWithMac<SecretKey>),
}

impl Key {
    /// Create a new signing keypair
    pub fn new_sign(keypair: SignKeypair) -> Self {
        Self::Sign(keypair)
    }

    /// Create a new signing keypair
    pub fn new_crypto(keypair: CryptoKeypair) -> Self {
        Self::Crypto(keypair)
    }

    /// Create a new secret key
    pub fn new_secret(key: PrivateWithMac<SecretKey>) -> Self {
        Self::Secret(key)
    }

    /// Returns the [AdminKeypair] if this is an admin key.
    pub fn as_adminkey(&self) -> Option<&AdminKeypair> {
        match self {
            Self::Admin(ref x) => Some(x),
            _ => None,
        }
    }

    /// Returns the `SignKeypair` if this is a signing key.
    pub fn as_signkey(&self) -> Option<&SignKeypair> {
        match self {
            Self::Sign(ref x) => Some(x),
            _ => None,
        }
    }

    /// Returns the `CryptoKeypair` if this is a crypto key.
    pub fn as_cryptokey(&self) -> Option<&CryptoKeypair> {
        match self {
            Self::Crypto(ref x) => Some(x),
            _ => None,
        }
    }

    /// Returns the `SecretKey` if this is a secret key.
    pub fn as_secretkey(&self) -> Option<&PrivateWithMac<SecretKey>> {
        match self {
            Self::Secret(ref x) => Some(x),
            _ => None,
        }
    }

    /// Returns a KeyID for this key.
    pub fn key_id(&self) -> KeyID {
        match self {
            Self::Admin(keypair) => keypair.key_id(),
            Self::Sign(keypair) => keypair.key_id(),
            Self::Crypto(keypair) => keypair.key_id(),
            Self::Secret(pwh) => KeyID::SecretKey(pwh.mac().clone()),
        }
    }

    /// Serialize this Key in binary format.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        ser::serialize(self)
    }

    /// Deserialize a Key from a serialized set of bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        ser::deserialize(bytes)
    }

    /// Consumes the key, and re-encryptes it with a new master key.
    pub fn reencrypt(self, previous_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let key = match self {
            Self::Admin(keypair) => Self::Admin(keypair.reencrypt(previous_master_key, new_master_key)?),
            Self::Sign(keypair) => Self::Sign(keypair.reencrypt(previous_master_key, new_master_key)?),
            Self::Crypto(keypair) => Self::Crypto(keypair.reencrypt(previous_master_key, new_master_key)?),
            Self::Secret(secret) => Self::Secret(secret.reencrypt(previous_master_key, new_master_key)?),
        };
        Ok(key)
    }
}

impl Public for Key {
    fn strip_private(&self) -> Self {
        match self {
            Self::Admin(keypair) => Self::Admin(keypair.strip_private()),
            Self::Sign(keypair) => Self::Sign(keypair.strip_private()),
            Self::Crypto(keypair) => Self::Crypto(keypair.strip_private()),
            Self::Secret(container) => Self::Secret(container.strip_private()),
        }
    }

    fn has_private(&self) -> bool {
        match self {
            Self::Admin(keypair) => keypair.has_private(),
            Self::Sign(keypair) => keypair.has_private(),
            Self::Crypto(keypair) => keypair.has_private(),
            Self::Secret(container) => container.has_private(),
        }
    }
}

/// Holds a subkey's key data, (unique) name, an optional descriiption, and an
/// optional revocation.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Subkey {
    /// The key itself.
    ///
    /// Alright, Parker, shut up. Thank you, Parker. Shut up. Thank you.
    ///
    ///
    ///
    ///
    /// ...Nobody thinks you're funny.
    #[rasn(tag(explicit(0)))]
    key: Key,
    /// The key's human-readable name, for example "email".
    #[rasn(tag(explicit(1)))]
    name: String,
    /// The key's human-readable description, for example "Please send me
    /// encrypted emails using this key." Or "HAI THIS IS MY DOGECOIN ADDRESSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS!!!1"
    #[rasn(tag(explicit(2)))]
    description: Option<String>,
    /// Allows revocation of a key.
    #[rasn(tag(explicit(3)))]
    revocation: Option<RevocationReason>,
}

impl Subkey {
    /// Create a new subkey, signed by our root key.
    fn new<T: Into<String>>(key: Key, name: T, description: Option<T>) -> Self {
        Self {
            key,
            name: name.into(),
            description: description.map(|x| x.into()),
            revocation: None,
        }
    }

    /// Revoke this subkey.
    fn revoke(&mut self, reason: RevocationReason, name_change: Option<String>) {
        self.set_revocation(Some(reason));
        if let Some(new_name) = name_change {
            self.set_name(new_name);
        }
    }
}

impl Deref for Subkey {
    type Target = Key;
    fn deref(&self) -> &Self::Target {
        self.key()
    }
}

impl Public for Subkey {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_key(self.key().strip_private());
        clone
    }

    fn has_private(&self) -> bool {
        self.key().has_private()
    }
}

/// Represents an *active* (not revoked) named administration key.
///
/// Admin keys that are stored as [subkeys][Subkey].
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct AdminKey {
    /// The admin keypair.
    #[rasn(tag(explicit(0)))]
    key: AdminKeypair,
    /// The key's human-readable name, for example "claims/manage".
    #[rasn(tag(explicit(1)))]
    name: String,
    /// The key's human-readable description, for example "This key is used to
    /// manage claims"
    #[rasn(tag(explicit(2)))]
    description: Option<String>,
}

impl AdminKey {
    /// Create a new AdminKey
    pub fn new<T: Into<String>>(key: AdminKeypair, name: T, description: Option<T>) -> Self {
        Self {
            key,
            name: name.into(),
            description: description.map(|x| x.into()),
        }
    }

    /// Re-encrypt this signing keypair with a new master key.
    pub fn reencrypt(self, previous_master_key: &SecretKey, new_master_key: &SecretKey) -> Result<Self> {
        let Self { key, name, description } = self;
        Ok(Self::new(key.reencrypt(previous_master_key, new_master_key)?, name, description))
    }

    /// Grab this key's [AdminKeyID].
    pub fn key_id(&self) -> AdminKeyID {
        self.key().key_id().into()
    }
}

impl Deref for AdminKey {
    type Target = AdminKeypair;
    fn deref(&self) -> &Self::Target {
        self.key()
    }
}

impl Public for AdminKey {
    fn strip_private(&self) -> Self {
        let mut clone = self.clone();
        clone.set_key(clone.key().strip_private());
        clone
    }

    fn has_private(&self) -> bool {
        self.key().has_private()
    }
}
/// Holds the keys for our identity.
///
/// This is a set of administration keys which can be used to manage the
/// identity itself (although management can happen with external keys as well)
/// as well as a collection of subkeys, which can be used by various third
/// party applications (including Stamp's CLU/GUI) for cryptography.
///
/// The keys stored here can also be revoked. They can remain stored here for
/// the purposes of verifying old signatures or decrypting old messages, but
/// revoked keys must not be used to sign or encrypt new data.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Keychain {
    /// Holds this identity's owned administration keypairs. These are keys used
    /// to manage the identity, although it's entirely possible to manage the
    /// identity using keys owned by other identities by using the policy system.
    #[rasn(tag(explicit(0)))]
    admin_keys: Vec<AdminKey>,
    /// Holds subkeys, which are non-admin keys owned by this identity. Generally
    /// these are accessed/used by other systems for things like creating messages
    /// or accessing encrypted data. For instance, an application that manages
    /// encrypted notes might store a subkey in the keychain which can be used to
    /// unlock the note data.
    #[rasn(tag(explicit(1)))]
    subkeys: Vec<Subkey>,
}

impl Keychain {
    /// Create a new keychain
    pub(crate) fn new(admin_keys: Vec<AdminKey>) -> Self {
        Self {
            admin_keys,
            subkeys: Vec::new(),
        }
    }

    /// Find an admin key by key id.
    pub fn admin_key_by_keyid(&self, key_id: &AdminKeyID) -> Option<&AdminKey> {
        self.admin_keys().iter().find(|x| &x.key_id() == key_id)
    }

    /// Find an admin key by string key id.
    pub fn admin_key_by_keyid_str(&self, keyid_str: &str) -> Option<&AdminKey> {
        self.admin_keys().iter().find(|x| x.key_id().as_string() == keyid_str)
    }

    /// Find an admin key by key id.
    pub fn admin_key_by_keyid_mut(&mut self, keyid: &AdminKeyID) -> Option<&mut AdminKey> {
        self.admin_keys_mut().iter_mut().find(|x| &x.key_id() == keyid)
    }

    /// Find an admin key by name.
    pub fn admin_key_by_name(&self, name: &str) -> Option<&AdminKey> {
        self.admin_keys().iter().find(|x| x.name() == name)
    }

    /// Find a subkey by ID.
    pub fn subkey_by_keyid(&self, key_id: &KeyID) -> Option<&Subkey> {
        self.subkeys().iter().find(|x| &x.key_id() == key_id)
    }

    /// Find a subkey by ID string
    pub fn subkey_by_keyid_str(&self, keyid_str: &str) -> Option<&Subkey> {
        self.subkeys().iter().find(|x| x.key_id().as_string() == keyid_str)
    }

    /// Find a subkey mut by ID. Relieves a bit of tedium.
    pub fn subkey_by_keyid_mut(&mut self, keyid: &KeyID) -> Option<&mut Subkey> {
        self.subkeys_mut().iter_mut().find(|x| &x.key_id() == keyid)
    }

    /// Find a subkey by name. Relieves a bit of tedium.
    pub fn subkey_by_name(&self, name: &str) -> Option<&Subkey> {
        self.subkeys().iter().find(|x| x.name() == name)
    }

    /// Grab all admin keys (active and revoked).
    pub fn keys_admin(&self) -> Vec<&AdminKeypair> {
        let mut search_keys = self.admin_keys()
            .iter()
            .map(|key| key.key())
            .collect::<Vec<_>>();
        search_keys.append(&mut self.subkeys_admin());
        search_keys
    }

    fn subkeys_admin(&self) -> Vec<&AdminKeypair> {
        self.subkeys().iter()
            .filter_map(|x| x.key().as_adminkey())
            .collect::<Vec<_>>()
    }

    /// Grab all signing subkeys.
    pub fn subkeys_sign(&self) -> Vec<&SignKeypair> {
        self.subkeys().iter()
            .filter_map(|x| x.key().as_signkey())
            .collect::<Vec<_>>()
    }

    /// Grab all crypto subkeys.
    pub fn subkeys_crypto(&self) -> Vec<&CryptoKeypair> {
        self.subkeys().iter()
            .filter_map(|x| x.key().as_cryptokey())
            .collect::<Vec<_>>()
    }

    /// Add an admin key but check for dupes
    fn add_admin_key_impl(&mut self, admin_key: AdminKey) -> Result<()> {
        let admin_key_id = admin_key.key_id();
        if self.admin_keys().iter().find(|x| x.key_id() == admin_key_id).is_none() {
            self.admin_keys_mut().push(admin_key);
        }
        Ok(())
    }

    /// Add a subkey but check for dupes
    fn add_subkey_impl(&mut self, subkey: Subkey) -> Result<()> {
        let key_id = subkey.key_id();
        if self.subkeys().iter().find(|x| x.key_id() == key_id).is_none() {
            self.subkeys_mut().push(subkey);
        }
        Ok(())
    }

    /// Add a new admin keypair.
    pub(crate) fn add_admin_key(mut self, admin_key: AdminKey) -> Result<Self> {
        self.add_admin_key_impl(admin_key)?;
        Ok(self)
    }

    /// Update some info about an admin key
    pub(crate) fn edit_admin_key<T: Into<String>>(mut self, id: &AdminKeyID, name: Option<T>, description: Option<Option<T>>) -> Result<Self> {
        if let Some(key) = self.admin_key_by_keyid_mut(id) {
            if let Some(set_name) = name {
                key.set_name(set_name.into());
            }
            if let Some(desc) = description {
                key.set_description(desc.map(|x| x.into()));
            }
        }
        Ok(self)
    }

    /// Revoke an [Admin key][AdminKeypair].
    pub(crate) fn revoke_admin_key<T: Into<String>>(mut self, id: &AdminKeyID, reason: RevocationReason, new_name: Option<T>) -> Result<Self> {
        if let Some(key) = self.admin_key_by_keyid(id) {
            let new_name: String = new_name
                .map(|x| x.into())
                .unwrap_or_else(|| format!("revoked/admin/{}", key.key().key_id().as_string()));
            let mut subkey = Subkey::new(Key::Admin(key.key().clone()), new_name, Some("revoked admin key".into()));
            subkey.revoke(reason, None);
            drop(key);
            self.add_subkey_impl(subkey)?;
            self.admin_keys_mut().retain(|k| &k.key_id() != id);
        }
        Ok(self)
    }

    /// Add a new subkey to the keychain (and sign it).
    pub(crate) fn add_subkey<T: Into<String>>(mut self, key: Key, name: T, description: Option<T>) -> Result<Self> {
        let subkey = Subkey::new(key, name, description);
        self.add_subkey_impl(subkey)?;
        Ok(self)
    }

    /// Edit a subkey (set name/description).
    pub(crate) fn edit_subkey<T: Into<String>>(mut self, id: &KeyID, name: Option<T>, description: Option<Option<T>>) -> Result<Self> {
        let key = self.subkey_by_keyid_mut(id)
            .ok_or_else(|| Error::KeychainKeyNotFound(id.clone()))?;
        if let Some(set_name) = name {
            key.set_name(set_name.into());
        }
        if let Some(desc) = description {
            key.set_description(desc.map(|x| x.into()));
        }
        Ok(self)
    }

    /// Revoke a subkey.
    pub(crate) fn revoke_subkey(mut self, id: &KeyID, reason: RevocationReason, new_name: Option<String>) -> Result<Self> {
        if let Some(subkey) = self.subkey_by_keyid_mut(id) {
            if subkey.revocation().is_none() {
                subkey.revoke(reason, new_name);
            }
        }
        Ok(self)
    }

    /// Delete a key from the keychain.
    pub(crate) fn delete_subkey(mut self, id: &KeyID) -> Result<Self> {
        if self.subkey_by_keyid(id).is_some() {
            self.subkeys_mut().retain(|x| &x.key_id() != id);
        }
        Ok(self)
    }
}

impl Public for Keychain {
    fn strip_private(&self) -> Self {
        let mut keychain_clone = self.clone();
        let admin_stripped = keychain_clone.admin_keys().clone().into_iter()
            .map(|mut ak| {
                ak.set_key(ak.key().strip_private());
                ak
            })
            .collect::<Vec<_>>();
        let subkeys_stripped = self.subkeys().clone().into_iter()
            .map(|mut sk| {
                sk.set_key(sk.key().strip_private());
                sk
            })
            .collect::<Vec<_>>();
        keychain_clone.set_admin_keys(admin_stripped);
        keychain_clone.set_subkeys(subkeys_stripped);
        keychain_clone
    }

    fn has_private(&self) -> bool {
        self.admin_keys().iter().find(|x| x.key().has_private()).is_some() ||
            self.subkeys().iter().find(|x| x.key().has_private()).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::key::{Hash, SecretKey},
        util,
    };

    fn get_master_key() -> SecretKey {
        let hash = Hash::new_blake2b(b"my goat hurts".as_slice()).unwrap();
        let seed: [u8; 32] = hash.as_bytes()[0..32].try_into().unwrap();
        SecretKey::new_xchacha20poly1305_from_slice(&seed).unwrap()
    }

    #[test]
    fn admin_ser() {
        let master_key = get_master_key();
        let hash = Hash::new_blake2b(b"i will, bye").unwrap();
        let seed: [u8; 32] = hash.as_bytes()[0..32].try_into().unwrap();
        let kp = SignKeypair::new_ed25519_from_seed(&master_key, &seed).unwrap();
        let admin = AdminKeypair::from(kp);
        let sig = admin.sign(&master_key, b"who's this, steve??").unwrap();
        let sig_inner: &SignKeypairSignature = sig.deref();
        let ser = util::ser::serialize(&sig).unwrap();
        let ser_inner = util::ser::serialize(sig_inner).unwrap();
        assert_eq!(ser, ser_inner);
        assert_eq!(
            "oEIEQKcTXzZt0l8VzWJt3oXI1woTLErwye9I4G2mh5yHNljtuDlu4f-5gEaojHFZOXroMolhB1MlsaG9d4qWGb-ERw8",
            util::ser::base64_encode(&ser).as_str()
        );
    }

    #[test]
    fn key_as_type() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let admin_keypair = AdminKeypair::new_ed25519(&master_key).unwrap();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = SecretKey::new_xchacha20poly1305().unwrap();
        let key3 = Key::Admin(admin_keypair.clone());
        let key4 = Key::Sign(sign_keypair.clone());
        let key5 = Key::Crypto(crypto_keypair.clone());
        let key6 = Key::Secret(PrivateWithMac::seal(&master_key, secret_key).unwrap());

        let keys = vec![key3, key4, key5, key6];
        macro_rules! keytype {
            ($keys:ident, $fn:ident) => {
                $keys.iter().map(|x| x.$fn().is_some()).collect::<Vec<_>>()
            }
        }
        assert_eq!(keytype!(keys, as_adminkey), vec![true, false, false, false]);
        assert_eq!(keytype!(keys, as_signkey), vec![false, true, false, false]);
        assert_eq!(keytype!(keys, as_cryptokey), vec![false, false, true, false]);
        assert_eq!(keytype!(keys, as_secretkey), vec![false, false, false, true]);
    }

    #[test]
    fn key_serde() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let secret_key = SecretKey::new_xchacha20poly1305().unwrap();
        let key = Key::Secret(PrivateWithMac::seal(&master_key, secret_key).unwrap());
        let ser = key.serialize().unwrap();
        let key2 = Key::deserialize(ser.as_slice()).unwrap();
        assert!(key.as_secretkey().is_some());
        let sec1 = util::ser::serialize(&key.as_secretkey().unwrap().open_and_verify(&master_key).unwrap()).unwrap();
        let sec2 = util::ser::serialize(&key2.as_secretkey().unwrap().open_and_verify(&master_key).unwrap()).unwrap();
        assert_eq!(sec1, sec2);
    }

    #[test]
    fn key_reencrypt() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let admin_keypair = AdminKeypair::new_ed25519(&master_key).unwrap();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = SecretKey::new_xchacha20poly1305().unwrap();
        let key3 = Key::Admin(admin_keypair.clone());
        let key4 = Key::Sign(sign_keypair.clone());
        let key5 = Key::Crypto(crypto_keypair.clone());
        let key6 = Key::Secret(PrivateWithMac::seal(&master_key, secret_key).unwrap());

        let val3 = key3.as_adminkey().unwrap().sign(&master_key, b"hi i'm larry").unwrap();
        let val4 = key4.as_signkey().unwrap().sign(&master_key, b"hi i'm butch").unwrap();
        let val5 = key5.as_cryptokey().unwrap().seal_anonymous(b"sufferin succotash").unwrap();
        let val6_key = key6.as_secretkey().unwrap().open_and_verify(&master_key).unwrap();
        let val6_nonce = val6_key.gen_nonce().unwrap();
        let val6 = val6_key.seal(b"and your nose like a delicious slope of cream", &val6_nonce).unwrap();

        let master_key2 = SecretKey::new_xchacha20poly1305().unwrap();
        assert!(master_key != master_key2);
        let key3_2 = key3.reencrypt(&master_key, &master_key2).unwrap();
        let key4_2 = key4.reencrypt(&master_key, &master_key2).unwrap();
        let key5_2 = key5.reencrypt(&master_key, &master_key2).unwrap();
        let key6_2 = key6.reencrypt(&master_key, &master_key2).unwrap();

        let val3_2 = key3_2.as_adminkey().unwrap().sign(&master_key2, b"hi i'm larry").unwrap();
        let val4_2 = key4_2.as_signkey().unwrap().sign(&master_key2, b"hi i'm butch").unwrap();
        let val5_2 = key5_2.as_cryptokey().unwrap().open_anonymous(&master_key2, &val5).unwrap();
        let val6_2_key = key6_2.as_secretkey().unwrap().open_and_verify(&master_key2).unwrap();
        let val6_2 = val6_2_key.open(&val6, &val6_nonce).unwrap();

        assert_eq!(val3, val3_2);
        assert_eq!(val4, val4_2);
        assert_eq!(val5_2, b"sufferin succotash");
        assert_eq!(val6_2, b"and your nose like a delicious slope of cream");

        let res3 = key3_2.as_adminkey().unwrap().sign(&master_key, b"hi i'm larry");
        let res4 = key4_2.as_signkey().unwrap().sign(&master_key, b"hi i'm butch");
        let res5 = key5_2.as_cryptokey().unwrap().open_anonymous(&master_key, &val5);
        let res6 = key6_2.as_secretkey().unwrap().open_and_verify(&master_key);

        assert_eq!(res3, Err(Error::CryptoOpenFailed));
        assert_eq!(res4, Err(Error::CryptoOpenFailed));
        assert_eq!(res5, Err(Error::CryptoOpenFailed));
        assert_eq!(res6, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn key_strip_private_has_private() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let admin_keypair = AdminKeypair::new_ed25519(&master_key).unwrap();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = SecretKey::new_xchacha20poly1305().unwrap();
        let key3 = Key::Admin(admin_keypair.clone());
        let key4 = Key::Sign(sign_keypair.clone());
        let key5 = Key::Crypto(crypto_keypair.clone());
        let key6 = Key::Secret(PrivateWithMac::seal(&master_key, secret_key).unwrap());

        assert!(key3.has_private());
        assert!(key4.has_private());
        assert!(key5.has_private());
        assert!(key6.has_private());

        let key3_2 = key3.strip_private();
        let key4_2 = key4.strip_private();
        let key5_2 = key5.strip_private();
        let key6_2 = key6.strip_private();

        assert!(!key3_2.has_private());
        assert!(!key4_2.has_private());
        assert!(!key5_2.has_private());
        assert!(!key6_2.has_private());
    }

    fn keychain_new() -> (SecretKey, Keychain) {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let admin_keypair = AdminKeypair::new_ed25519(&master_key).unwrap();
        let admin_key = AdminKey::new(admin_keypair, "Default", None);

        let keychain = Keychain::new(vec![admin_key]);
        (master_key, keychain)
    }

    #[test]
    fn keychain_add_edit_revoke_admin_key() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let admin_keypair = AdminKeypair::new_ed25519(&master_key).unwrap();
        let admin_key = AdminKey::new(admin_keypair, "Default", None);
        let key_id = admin_key.key_id();

        let keychain = Keychain::new(vec![]);
        assert_eq!(keychain.admin_keys().len(), 0);

        let keychain2 = keychain.add_admin_key(admin_key.clone()).unwrap();
        assert_eq!(keychain2.admin_keys().len(), 1);
        assert_eq!(keychain2.admin_keys()[0].name(), "Default");
        assert_eq!(keychain2.admin_keys()[0].description(), &None::<String>);

        let keychain3 = keychain2.add_admin_key(admin_key.clone()).unwrap();
        assert_eq!(keychain3.admin_keys().len(), 1);
        assert_eq!(keychain3.admin_keys()[0].name(), "Default");
        assert_eq!(keychain3.admin_keys()[0].description(), &None::<String>);

        let keychain4 = keychain3.edit_admin_key(&key_id, Some("frizzy"), Some(Some("SO IT'S CONTINENTAL?"))).unwrap();
        assert_eq!(keychain4.admin_keys().len(), 1);
        assert_eq!(keychain4.admin_keys()[0].name(), "frizzy");
        assert_eq!(keychain4.admin_keys()[0].description(), &Some("SO IT'S CONTINENTAL?".into()));

        let keychain5 = keychain4.edit_admin_key(&AdminKeyID::from(KeyID::random_sign()), Some("GERRRR"), Some(None)).unwrap();
        assert_eq!(keychain5.admin_keys().len(), 1);
        assert_eq!(keychain5.admin_keys()[0].name(), "frizzy");
        assert_eq!(keychain5.admin_keys()[0].description(), &Some("SO IT'S CONTINENTAL?".into()));

        let keychain6 = keychain5.revoke_admin_key(&key_id, RevocationReason::Superseded, Some("WROOONG")).unwrap();
        assert_eq!(keychain6.admin_keys().len(), 0);
        assert_eq!(keychain6.subkeys().len(), 1);
        assert_eq!(keychain6.subkeys()[0].name(), "WROOONG");
        assert_eq!(keychain6.subkeys()[0].description(), &Some("revoked admin key".into()));
    }

    #[test]
    fn keychain_subkeys_sign_verify_position() {
        let (master_key, keychain) = keychain_new();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = PrivateWithMac::seal(&master_key, SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
        let sign = Key::new_sign(sign_keypair);
        let crypto = Key::new_crypto(crypto_keypair);
        let secret = Key::new_secret(secret_key);

        // add a bunch of subkeys and verify their position in the keychain and
        // their signatures against the root key
        //
        // we want to make sure new keys are always added to the end of the
        // keychain.
        let keychain = keychain.add_subkey(sign, "MY signing key", Some("The key I use to sign things generally LOL")).unwrap();
        let last = keychain.subkeys().iter().last().unwrap();
        assert_eq!(last.name(), "MY signing key");
        assert_eq!(Some(last.name()), keychain.subkey_by_name("MY signing key").map(|x| x.name()));
        assert_eq!(Some(last.name()), keychain.subkey_by_keyid(&last.key_id()).map(|x| x.name()));

        let keychain = keychain.add_subkey(crypto, "MY crypto key", Some("Send me messages with this key OR ELSE")).unwrap();
        let last = keychain.subkeys().iter().last().unwrap();
        assert_eq!(last.name(), "MY crypto key");
        assert_eq!(Some(last.name()), keychain.subkey_by_name("MY crypto key").map(|x| x.name()));
        assert_eq!(Some(last.name()), keychain.subkey_by_keyid(&last.key_id()).map(|x| x.name()));

        let keychain = keychain.add_subkey(secret, "MY secret key", Some("I use this to encrypt files and shit")).unwrap();
        let last = keychain.subkeys().iter().last().unwrap();
        assert_eq!(last.name(), "MY secret key");
        assert_eq!(Some(last.name()), keychain.subkey_by_name("MY secret key").map(|x| x.name()));

        // make sure finding by name does what we expect (first matching key
        // with that name)
        match (keychain.subkeys().iter().find(|x| x.name() == "MY crypto key"), keychain.subkey_by_name("MY crypto key")) {
            (Some(key1), Some(key2)) => {
                assert_eq!(key1 as *const Subkey, key2 as *const Subkey);
            }
            _ => panic!("Bad key search"),
        }
    }

    #[test]
    fn keychain_revoke() {
        let (master_key, keychain) = keychain_new();
        let sign = Key::new_sign(SignKeypair::new_ed25519(&master_key).unwrap());
        let keychain = keychain.add_subkey(sign, "sign", None).unwrap();
        // revoke a key, and verify the revocation
        let signkey = keychain.subkey_by_name("sign").unwrap().clone();
        assert!(signkey.revocation.is_none());

        let keychain2 = keychain.clone().revoke_subkey(&signkey.key_id(), RevocationReason::Unspecified, None).unwrap();
        let signkey = keychain2.subkey_by_name("sign").unwrap().clone();
        assert_eq!(signkey.revocation().as_ref().unwrap(), &RevocationReason::Unspecified);

        let keychain3 = keychain.clone().revoke_subkey(&signkey.key_id(), RevocationReason::Unspecified, Some("revoked:sign".into())).unwrap();
        let signkey = keychain3.subkey_by_name("revoked:sign").unwrap().clone();
        assert_eq!(signkey.revocation().as_ref().unwrap(), &RevocationReason::Unspecified);
    }

    #[test]
    fn keychain_delete() {
        let (master_key, keychain) = keychain_new();
        let crypto = Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap());
        let keychain = keychain.add_subkey(crypto, "crypto", None).unwrap();
        // delete a key LOL
        let cryptokey = keychain.subkey_by_name("crypto").unwrap().clone();
        let keychain = keychain.delete_subkey(&cryptokey.key_id()).unwrap();
        let cryptokey2 = keychain.subkey_by_name("crypto");
        // checkmate, liberals
        assert!(cryptokey2.is_none());
    }

    #[test]
    fn keychain_strip_private() {
        let (master_key, keychain) = keychain_new();
        let sign = Key::new_sign(SignKeypair::new_ed25519(&master_key).unwrap());
        let crypto = Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap());
        let secret = Key::new_secret(PrivateWithMac::seal(&master_key, SecretKey::new_xchacha20poly1305().unwrap()).unwrap());
        let keychain = keychain
            .add_subkey(sign, "sign", None).unwrap()
            .add_subkey(crypto, "crypto", None).unwrap()
            .add_subkey(secret, "secret", None).unwrap();
        assert_eq!(keychain.admin_keys().iter().fold(false, |acc, x| acc || x.has_private()), true);
        assert_eq!(keychain.subkey_by_name("sign").unwrap().key().has_private(), true);
        assert_eq!(keychain.subkey_by_name("crypto").unwrap().key().has_private(), true);
        assert!(keychain.subkey_by_name("secret").is_some());

        let keychain = keychain.strip_private();

        assert_eq!(keychain.admin_keys().iter().fold(false, |acc, x| acc || x.has_private()), false);
        assert_eq!(keychain.subkey_by_name("sign").unwrap().key().has_private(), false);
        assert_eq!(keychain.subkey_by_name("crypto").unwrap().key().has_private(), false);
        assert_eq!(keychain.subkey_by_name("secret").unwrap().key().has_private(), false);
    }
}

