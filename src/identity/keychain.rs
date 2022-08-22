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
    policy::CapabilityPolicy,
    private::{Private, PrivateWithHmac},
    util::{Public, sign::Signable, ser, ser::BinaryVec},
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
    ($keytype:ident, $keytype_public:ident, $signaturetype:ident) => {
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

        #[derive(Debug, Clone, Serialize, Deserialize)]
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
    }
}

make_keytype! { AdminKeypair, AdminKeypairPublic, AdminKeypairSignature }

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
    /// Hides our private data (including private claims).
    #[rasn(tag(explicit(3)))]
    Secret(PrivateWithHmac<SecretKey>),
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
    pub fn new_secret(key: PrivateWithHmac<SecretKey>) -> Self {
        Self::Secret(key)
    }

    /// Returns the `SignKeypair` if this is a policy key.
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
    pub fn as_secretkey(&self) -> Option<&Private<SecretKey>> {
        match self {
            Self::Secret(ref x) => Some(x),
            _ => None,
        }
    }

    /// Returns a KeyID for this key, if possible.
    pub fn key_id(&self) -> Option<KeyID> {
        match self {
            Self::Admin(keypair) => Some(keypair.key_id()),
            Self::Sign(keypair) => Some(keypair.key_id()),
            Self::Crypto(keypair) => Some(keypair.key_id()),
            _ => None,
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
    ///
    /// This must be a unique value among all subkeys (even revoked ones). This
    /// is used in many places to reference the key.
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
        let revocation = Revocation::new(reason);
        self.set_revocation(Some(revocation));
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

    fn has_private(&self) => {
        self.key().has_private();
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
    ///
    /// This must be a unique value among all admin keys.
    #[rasn(tag(explicit(1)))]
    name: String,
    /// The key's human-readable description, for example "This key is used to
    /// manage claims"
    #[rasn(tag(explicit(2)))]
    description: Option<String>,
}

impl AdminKey {
    fn new(key: AdminKeypair, name: String, description: Option<String>) -> Self {
        Self { key, name, description }
    }
}

/// Holds the keys for our identity.
///
/// This is a set of administration keys which can be used to manage the
/// identity itself (although management can happen with external keys as well)
/// as well as a collection of subkeys, which can be used by various third
/// party applications (including Stamp's CLU/GUI) for cryptography.
///
/// Aside from keys, the keychain also stores a collection of capabilities and
/// policies which control which actions can be performed by which combinations
/// of keys. This generalized setup allows things as easy as "one key for all
/// actions" or as granular as "three signatures from these five keys can add
/// a new subkey if its name matches to glob pattern "turtl/*". The sky is the
/// limit.
///
/// The keys stored here can also be revoked. They can remain stored here for
/// the purposes of verifying old signatures or decrypting old messages, but
/// revoked keys must not be used to sign or encrypt new data.
#[derive(Debug, Clone, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Keychain {
    /// A collection of capabilities, each eith a key policy attached to it. The
    /// idea here is that we can specify a capability/action such as "add subkey"
    /// and allow that action to be performed if we have the proper signature(s)
    /// as determined by the key policy.
    ///
    /// This allows use to not only run transactions against this identity, but
    /// also allows others to do so as well, given they sign their transactions
    /// according to the given policies.
    #[rasn(tag(explicit(0)))]
    capabilities: Vec<CapabilityPolicy>,
    /// Holds this identity's owned administration keypairs. These are keys used
    /// to manage the identity, although it's entirely possible to manage the
    /// identity using keys owned by other identities by using the policy system.
    #[rasn(tag(explicit(1)))]
    admin_keys: Vec<AdminKey>,
    /// Holds subkeys, which are non-admin keys owned by this identity. Generally
    /// these are accessed/used by other systems for things like creating messages
    /// or accessing encrypted data. For instance, an application that manages
    /// encrypted notes might store a subkey in the keychain which can be used to
    /// unlock the note data.
    #[rasn(tag(explicit(2)))]
    subkeys: Vec<Subkey>,
}

impl Keychain {
    /// Create a new keychain
    pub(crate) fn new() -> Self {
        Self {
            capabilities: Vec::new(),
            admin_keys: Vec::new(),
            subkeys: Vec::new(),
        }
    }

    /// Verify that a signature and a set of data used to generate that
    /// signature can be verified by at least one of our signing keys.
    pub(crate) fn try_keys<F>(keylist: &Vec<&SignKeypair>, sigfn: F) -> Result<()>
        where F: Fn(&SignKeypair) -> Result<()>,
    {
        for sign_keypair in keylist {
            if sigfn(sign_keypair).is_ok() {
                return Ok(());
            }
        }
        Err(Error::CryptoSignatureVerificationFailed)
    }

    /// Find a subkey by ID. Relieves a bit of tedium.
    pub fn subkey_by_keyid(&self, keyid_str: &str) -> Option<&Subkey> {
        self.subkeys().iter().find(|x| {
            if let Some(key_id) = x.key_id() {
                return key_id.as_string().starts_with(keyid_str);
            }
            false
        })
    }

    /// Find a subkey by name. Relieves a bit of tedium.
    pub fn subkey_by_name(&self, name: &str) -> Option<&Subkey> {
        self.subkeys().iter().find(|x| x.name() == name)
    }

    /// Find an admin key by name.
    pub fn admin_key_by_name(&self, name: &str) -> Option<&AdminKey> {
        self.admin_keys().iter().find(|x| x.name() == name)
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
        if self.admin_key_by_name(admin_key.name()).is_some() {
            Err(Error::DuplicateName)?;
        }
        self.admin_keys_mut().push(subkey);
        Ok(())
    }

    /// Add a subkey but check for dupes
    fn add_subkey_impl(&mut self, subkey: Subkey) -> Result<()> {
        if self.subkey_by_name(subkey.name()).is_some() {
            Err(Error::DuplicateName)?;
        }
        self.subkeys_mut().push(subkey);
        Ok(())
    }

    /// Replace our policy signing key.
    ///
    /// This moves the current policy key into the subkeys and revokes it.
    pub(crate) fn set_policy_key(mut self, new_policy_keypair: PolicyKeypair, reason: RevocationReason) -> Result<Self> {
        let policy = self.policy().clone();
        let name = format!("revoked:policy:{}", policy.key_id().as_string());
        let mut subkey = Subkey::new(Key::Policy(policy), name, Some("revoked policy key".into()));
        subkey.revoke(reason, None);
        self.add_subkey_impl(subkey)?;
        self.set_policy(new_policy_keypair);
        Ok(self)
    }

    /// Replace our publish signing key.
    ///
    /// This moves the current publish key into the subkeys and revokes it.
    pub(crate) fn set_publish_key(mut self, new_publish_keypair: PublishKeypair, reason: RevocationReason) -> Result<Self> {
        let publish = self.publish().clone();
        let name = format!("revoked:publish:{}", publish.key_id().as_string());
        let mut subkey = Subkey::new(Key::Publish(publish), name, Some("revoked publish key".into()));
        subkey.revoke(reason, None);
        self.add_subkey_impl(subkey)?;
        self.set_publish(new_publish_keypair);
        Ok(self)
    }

    /// Replace our root signing key.
    ///
    /// This moves the current root key into the subkeys and revokes it.
    pub(crate) fn set_root_key(mut self, new_root_keypair: RootKeypair, reason: RevocationReason) -> Result<Self> {
        let root = self.root().clone();
        let name = format!("revoked:root:{}", root.key_id().as_string());
        let mut subkey = Subkey::new(Key::Root(root), name, Some("revoked root key".into()));
        subkey.revoke(reason, None);
        self.add_subkey_impl(subkey)?;
        self.set_root(new_root_keypair);
        Ok(self)
    }

    /// Add a new admin keypair.
    pub(crate) fn add_admin_key<T: Into<String>>(mut self, key: AdminKeypair, name: T, description: Option<T>) -> Result<Self> {
        let admin_key = AdminKey::new(key, name.into(), description.map(|x| x.into()));
        self.add_admin_key_impl(admin_key)?;
        Ok(self)
    }

    /// Add a new subkey to the keychain (and sign it).
    pub(crate) fn add_subkey<T: Into<String>>(mut self, key: Key, name: T, description: Option<T>) -> Result<Self> {
        let subkey = Subkey::new(key, name, description);
        self.add_subkey_impl(subkey)?;
        Ok(self)
    }

    /// Edit a subkey (set name/description).
    pub(crate) fn edit_subkey<T: Into<String>>(mut self, name: &str, new_name: T, description: Option<T>) -> Result<Self> {
        let key = self.subkeys_mut().iter_mut().find(|x| x.name() == name)
            .ok_or(Error::IdentitySubkeyNotFound)?;
        key.set_name(new_name.into());
        key.set_description(description.map(|x| x.into()));
        Ok(self)
    }

    /// Revoke a subkey.
    pub(crate) fn revoke_subkey(mut self, name: &str, reason: RevocationReason, new_name: Option<String>) -> Result<Self> {
        let key = self.subkeys_mut().iter_mut().find(|x| x.name() == name)
            .ok_or(Error::IdentitySubkeyNotFound)?;
        if key.revocation().is_some() {
            Err(Error::IdentitySubkeyAlreadyRevoked)?;
        }
        key.revoke(reason, new_name);
        Ok(self)
    }

    /// Delete a key from the keychain.
    pub(crate) fn delete_subkey(mut self, name: &str) -> Result<Self> {
        let exists = self.subkey_by_name(name);
        if exists.is_none() {
            Err(Error::IdentitySubkeyNotFound)?;
        }
        self.subkeys_mut().retain(|x| x.name() != name);
        Ok(self)
    }
}

impl Public for Keychain {
    fn strip_private(&self) -> Self {
        let mut keychain_clone = self.clone();
        keychain_clone.set_alpha(self.alpha().strip_private());
        keychain_clone.set_policy(self.policy().strip_private());
        keychain_clone.set_publish(self.publish().strip_private());
        keychain_clone.set_root(self.root().strip_private());
        let subkeys = self.subkeys().clone().into_iter()
            .map(|x| {
                (x.key().strip_private_maybe(), x)
            })
            .filter(|x| x.0.is_some())
            .map(|(key, mut subkey)| {
                subkey.set_key(key.unwrap());
                subkey
            })
            .collect::<Vec<_>>();
        keychain_clone.set_subkeys(subkeys);
        keychain_clone
    }

    fn has_private(&self) -> bool {
        self.alpha().has_private() ||
            self.policy().has_private() ||
            self.publish().has_private() ||
            self.root().has_private() ||
            self.subkeys().iter().find(|x| x.has_private()).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::key::{SecretKey},
        util,
    };

    fn get_master_key() -> SecretKey {
        let hashbytes = util::hash(b"my goat hurts".as_slice()).unwrap();
        let seed: [u8; 32] = hashbytes[0..32].try_into().unwrap();
        SecretKey::new_xchacha20poly1305_from_slice(&seed).unwrap()
    }

    #[test]
    fn alpha_ser() {
        let master_key = get_master_key();
        let hashbytes = util::hash(b"get a job").unwrap();
        let seed: [u8; 32] = hashbytes[0..32].try_into().unwrap();
        let kp = SignKeypair::new_ed25519_from_seed(&master_key, &seed).unwrap();
        let alpha = AlphaKeypair::from(kp);
        let sig = alpha.sign(&master_key, b"who's this, steve??").unwrap();
        let sig_inner: &SignKeypairSignature = sig.deref();
        let ser = util::ser::serialize(&sig).unwrap();
        let ser_inner = util::ser::serialize(sig_inner).unwrap();
        assert_eq!(ser, ser_inner);
        assert_eq!(
            "oEIEQD1K6VIpwXjFMZdpb8XqMmgV2uRPedKr-AxGicJPqkndk79ryzsBzDmMTh2SYC-cscEng5BP4iqHlbyIxpRH5wI",
            util::ser::base64_encode(&ser).as_str()
        );
    }

    #[test]
    fn policy_ser() {
        let master_key = get_master_key();
        let hashbytes = util::hash(b"im detective john kimble").unwrap();
        let seed: [u8; 32] = hashbytes[0..32].try_into().unwrap();
        let kp = SignKeypair::new_ed25519_from_seed(&master_key, &seed).unwrap();
        let policy = PolicyKeypair::from(kp);
        let sig = policy.sign(&master_key, b"who's this, steve??").unwrap();
        let sig_inner: &SignKeypairSignature = sig.deref();
        let ser = util::ser::serialize(&sig).unwrap();
        let ser_inner = util::ser::serialize(sig_inner).unwrap();
        assert_eq!(ser, ser_inner);
        assert_eq!(
            "oEIEQMv99PDoO1W65NLAIxDFKQPdqQKzQWh_ei3tX9Xy088_5m58QpcgfY_2rA0CvC2uKq0pzif5vGw_x4VsfnAAPQI",
            util::ser::base64_encode(&ser).as_str()
        );
    }

    #[test]
    fn publish_ser() {
        let master_key = get_master_key();
        let hashbytes = util::hash(b"yeah sure you are").unwrap();
        let seed: [u8; 32] = hashbytes[0..32].try_into().unwrap();
        let kp = SignKeypair::new_ed25519_from_seed(&master_key, &seed).unwrap();
        let publish = PublishKeypair::from(kp);
        let sig = publish.sign(&master_key, b"who's this, steve??").unwrap();
        let sig_inner: &SignKeypairSignature = sig.deref();
        let ser = util::ser::serialize(&sig).unwrap();
        let ser_inner = util::ser::serialize(sig_inner).unwrap();
        assert_eq!(ser, ser_inner);
        assert_eq!(
            "oEIEQBLSREemDtNKdHdG3iog2PJAQ8Sf2JCXrasZqAkteWQUwFx12BbR3oP6guKGLYClgTlr_0f9mC_OoO9yeGtaAQw",
            util::ser::base64_encode(&ser).as_str()
        );
    }

    #[test]
    fn root_ser() {
        let master_key = get_master_key();
        let hashbytes = util::hash(b"i will, bye").unwrap();
        let seed: [u8; 32] = hashbytes[0..32].try_into().unwrap();
        let kp = SignKeypair::new_ed25519_from_seed(&master_key, &seed).unwrap();
        let root = RootKeypair::from(kp);
        let sig = root.sign(&master_key, b"who's this, steve??").unwrap();
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
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = SecretKey::new_xchacha20poly1305().unwrap();
        let key1 = Key::Policy(policy_keypair.clone());
        let key2 = Key::Publish(publish_keypair.clone());
        let key3 = Key::Root(root_keypair.clone());
        let key4 = Key::Sign(sign_keypair.clone());
        let key5 = Key::Crypto(crypto_keypair.clone());
        let key6 = Key::Secret(Private::seal(&master_key, &secret_key).unwrap());

        let keys = vec![key1, key2, key3, key4, key5, key6];
        macro_rules! keytype {
            ($keys:ident, $fn:ident) => {
                $keys.iter().map(|x| x.$fn().is_some()).collect::<Vec<_>>()
            }
        }
        assert_eq!(keytype!(keys, as_policykey), vec![true, false, false, false, false, false]);
        assert_eq!(keytype!(keys, as_rootkey), vec![false, false, true, false, false, false]);
        assert_eq!(keytype!(keys, as_signkey), vec![false, false, false, true, false, false]);
        assert_eq!(keytype!(keys, as_cryptokey), vec![false, false, false, false, true, false]);
        assert_eq!(keytype!(keys, as_secretkey), vec![false, false, false, false, false, true]);
    }

    #[test]
    fn key_serde() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let secret_key = SecretKey::new_xchacha20poly1305().unwrap();
        let key = Key::Secret(Private::seal(&master_key, &secret_key).unwrap());
        let ser = key.serialize().unwrap();
        let key2 = Key::deserialize(ser.as_slice()).unwrap();
        assert!(key.as_secretkey().is_some());
        let sec1 = util::ser::serialize(&key.as_secretkey().unwrap().open(&master_key).unwrap()).unwrap();
        let sec2 = util::ser::serialize(&key2.as_secretkey().unwrap().open(&master_key).unwrap()).unwrap();
        assert_eq!(sec1, sec2);
    }

    #[test]
    fn key_reencrypt() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = SecretKey::new_xchacha20poly1305().unwrap();
        let key1 = Key::Policy(policy_keypair.clone());
        let key2 = Key::Publish(publish_keypair.clone());
        let key3 = Key::Root(root_keypair.clone());
        let key4 = Key::Sign(sign_keypair.clone());
        let key5 = Key::Crypto(crypto_keypair.clone());
        let key6 = Key::Secret(Private::seal(&master_key, &secret_key).unwrap());

        let val1 = key1.as_policykey().unwrap().sign(&master_key, b"hi i'm jerry").unwrap();
        let val2 = key2.as_publishkey().unwrap().sign(&master_key, b"hi i'm barry").unwrap();
        let val3 = key3.as_rootkey().unwrap().sign(&master_key, b"hi i'm larry").unwrap();
        let val4 = key4.as_signkey().unwrap().sign(&master_key, b"hi i'm butch").unwrap();
        let val5 = key5.as_cryptokey().unwrap().seal_anonymous(b"sufferin succotash").unwrap();
        let val6_key = key6.as_secretkey().unwrap().open(&master_key).unwrap();
        let val6_nonce = val6_key.gen_nonce().unwrap();
        let val6 = val6_key.seal(b"and your nose like a delicious slope of cream", &val6_nonce).unwrap();

        let master_key2 = SecretKey::new_xchacha20poly1305().unwrap();
        assert!(master_key != master_key2);
        let key1_2 = key1.reencrypt(&master_key, &master_key2).unwrap();
        let key2_2 = key2.reencrypt(&master_key, &master_key2).unwrap();
        let key3_2 = key3.reencrypt(&master_key, &master_key2).unwrap();
        let key4_2 = key4.reencrypt(&master_key, &master_key2).unwrap();
        let key5_2 = key5.reencrypt(&master_key, &master_key2).unwrap();
        let key6_2 = key6.reencrypt(&master_key, &master_key2).unwrap();

        let val1_2 = key1_2.as_policykey().unwrap().sign(&master_key2, b"hi i'm jerry").unwrap();
        let val2_2 = key2_2.as_publishkey().unwrap().sign(&master_key2, b"hi i'm barry").unwrap();
        let val3_2 = key3_2.as_rootkey().unwrap().sign(&master_key2, b"hi i'm larry").unwrap();
        let val4_2 = key4_2.as_signkey().unwrap().sign(&master_key2, b"hi i'm butch").unwrap();
        let val5_2 = key5_2.as_cryptokey().unwrap().open_anonymous(&master_key2, &val5).unwrap();
        let val6_2_key = key6_2.as_secretkey().unwrap().open(&master_key2).unwrap();
        let val6_2 = val6_2_key.open(&val6, &val6_nonce).unwrap();

        assert_eq!(val1, val1_2);
        assert_eq!(val2, val2_2);
        assert_eq!(val3, val3_2);
        assert_eq!(val4, val4_2);
        assert_eq!(val5_2, b"sufferin succotash");
        assert_eq!(val6_2, b"and your nose like a delicious slope of cream");

        let res1 = key1_2.as_policykey().unwrap().sign(&master_key, b"hi i'm jerry");
        let res2 = key2_2.as_publishkey().unwrap().sign(&master_key, b"hi i'm barry");
        let res3 = key3_2.as_rootkey().unwrap().sign(&master_key, b"hi i'm larry");
        let res4 = key4_2.as_signkey().unwrap().sign(&master_key, b"hi i'm butch");
        let res5 = key5_2.as_cryptokey().unwrap().open_anonymous(&master_key, &val5);
        let res6 = key6_2.as_secretkey().unwrap().open(&master_key);

        assert_eq!(res1, Err(Error::CryptoOpenFailed));
        assert_eq!(res2, Err(Error::CryptoOpenFailed));
        assert_eq!(res3, Err(Error::CryptoOpenFailed));
        assert_eq!(res4, Err(Error::CryptoOpenFailed));
        assert_eq!(res5, Err(Error::CryptoOpenFailed));
        assert_eq!(res6, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn key_strip_private_has_private() {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = SecretKey::new_xchacha20poly1305().unwrap();
        let key1 = Key::Policy(policy_keypair.clone());
        let key2 = Key::Publish(publish_keypair.clone());
        let key3 = Key::Root(root_keypair.clone());
        let key4 = Key::Sign(sign_keypair.clone());
        let key5 = Key::Crypto(crypto_keypair.clone());
        let key6 = Key::Secret(PrivateWithHmac::seal(&master_key, secret_key).unwrap());

        assert!(key1.has_private());
        assert!(key2.has_private());
        assert!(key3.has_private());
        assert!(key4.has_private());
        assert!(key5.has_private());
        assert!(key6.has_private());

        let key1_2 = key1.strip_private();
        let key2_2 = key2.strip_private();
        let key3_2 = key3.strip_private();
        let key4_2 = key4.strip_private();
        let key5_2 = key5.strip_private();
        let key6_2 = key6.strip_private();

        assert!(!key1_2.has_private());
        assert!(!key2_2.has_private());
        assert!(!key3_2.has_private());
        assert!(!key4_2.has_private());
        assert!(!key5_2.has_private());
        assert!(!key6_2.has_private());
    }

    fn keychain_new() -> (SecretKey, Keychain) {
        let master_key = SecretKey::new_xchacha20poly1305().unwrap();
        let alpha_keypair = AlphaKeypair::new_ed25519(&master_key).unwrap();
        let policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();

        let keychain = Keychain::new(alpha_keypair, policy_keypair, publish_keypair, root_keypair);
        (master_key, keychain)
    }

    #[test]
    fn keychain_set_policy_keys() {
        let (master_key, keychain) = keychain_new();
        assert_eq!(keychain.subkeys().len(), 0);
        let old_key = keychain.policy().clone();
        let new_policy_keypair = PolicyKeypair::new_ed25519(&master_key).unwrap();
        let keychain = keychain.set_policy_key(new_policy_keypair, RevocationReason::Superseded).unwrap();
        assert_eq!(keychain.subkeys().len(), 1);
        assert_eq!(keychain.subkeys()[0].key().as_policykey(), Some(&old_key));
        assert_eq!(keychain.subkeys()[0].name(), &format!("revoked:policy:{}", old_key.key_id().as_string()));
    }

    #[test]
    fn keychain_set_publish() {
        let (master_key, keychain) = keychain_new();
        assert_eq!(keychain.subkeys().len(), 0);
        let old_key = keychain.publish().clone();
        let new_publish_keypair = PublishKeypair::new_ed25519(&master_key).unwrap();
        let keychain = keychain.set_publish_key(new_publish_keypair, RevocationReason::Superseded).unwrap();
        assert_eq!(keychain.subkeys().len(), 1);
        assert_eq!(keychain.subkeys()[0].key().as_publishkey(), Some(&old_key));
        assert_eq!(keychain.subkeys()[0].name(), &format!("revoked:publish:{}", old_key.key_id().as_string()));
    }

    #[test]
    fn keychain_set_root() {
        let (master_key, keychain) = keychain_new();
        assert_eq!(keychain.subkeys().len(), 0);
        let old_key = keychain.root().clone();
        let new_root_keypair = RootKeypair::new_ed25519(&master_key).unwrap();
        let keychain = keychain.set_root_key(new_root_keypair, RevocationReason::Superseded).unwrap();
        assert_eq!(keychain.subkeys().len(), 1);
        assert_eq!(keychain.subkeys()[0].key().as_rootkey(), Some(&old_key));
        assert_eq!(keychain.subkeys()[0].name(), &format!("revoked:root:{}", old_key.key_id().as_string()));
    }

    #[test]
    fn keychain_subkeys_sign_verify_position() {
        let (master_key, keychain) = keychain_new();
        let sign_keypair = SignKeypair::new_ed25519(&master_key).unwrap();
        let crypto_keypair = CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap();
        let secret_key = Private::seal(&master_key, &SecretKey::new_xchacha20poly1305().unwrap()).unwrap();
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
        assert_eq!(Some(last.name()), keychain.subkey_by_keyid(&last.key_id().unwrap().as_string()).map(|x| x.name()));

        let keychain = keychain.add_subkey(crypto, "MY crypto key", Some("Send me messages with this key OR ELSE")).unwrap();
        let last = keychain.subkeys().iter().last().unwrap();
        assert_eq!(last.name(), "MY crypto key");
        assert_eq!(Some(last.name()), keychain.subkey_by_name("MY crypto key").map(|x| x.name()));
        assert_eq!(Some(last.name()), keychain.subkey_by_keyid(&last.key_id().unwrap().as_string()).map(|x| x.name()));

        let keychain = keychain.add_subkey(secret, "MY secret key", Some("I use this to encrypt files and shit")).unwrap();
        let last = keychain.subkeys().iter().last().unwrap();
        assert_eq!(last.name(), "MY secret key");
        assert_eq!(Some(last.name()), keychain.subkey_by_name("MY secret key").map(|x| x.name()));
        assert!(last.key_id().is_none());

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

        let keychain2 = keychain.clone().revoke_subkey(signkey.name(), RevocationReason::Unspecified, None).unwrap();
        let signkey = keychain2.subkey_by_name("sign").unwrap().clone();
        assert_eq!(signkey.revocation().as_ref().unwrap().reason(), &RevocationReason::Unspecified);

        let keychain3 = keychain.clone().revoke_subkey(signkey.name(), RevocationReason::Unspecified, Some("revoked:sign".into())).unwrap();
        let signkey = keychain3.subkey_by_name("revoked:sign").unwrap().clone();
        assert_eq!(signkey.revocation().as_ref().unwrap().reason(), &RevocationReason::Unspecified);
    }

    #[test]
    fn keychain_delete() {
        let (master_key, keychain) = keychain_new();
        let crypto = Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap());
        let keychain = keychain.add_subkey(crypto, "crypto", None).unwrap();
        // delete a key LOL
        let cryptokey = keychain.subkey_by_name("crypto").unwrap().clone();
        let keychain = keychain.delete_subkey(cryptokey.name()).unwrap();
        let cryptokey2 = keychain.subkey_by_name("crypto");
        // checkmate, liberals
        assert!(cryptokey2.is_none());
    }

    #[test]
    fn keychain_strip_private() {
        let (master_key, keychain) = keychain_new();
        let sign = Key::new_sign(SignKeypair::new_ed25519(&master_key).unwrap());
        let crypto = Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(&master_key).unwrap());
        let secret = Key::new_secret(Private::seal(&master_key, &SecretKey::new_xchacha20poly1305().unwrap()).unwrap());
        let keychain = keychain
            .add_subkey(sign, "sign", None).unwrap()
            .add_subkey(crypto, "crypto", None).unwrap()
            .add_subkey(secret, "secret", None).unwrap();
        assert_eq!(keychain.alpha().has_private(), true);
        assert_eq!(keychain.policy().has_private(), true);
        assert_eq!(keychain.publish().has_private(), true);
        assert_eq!(keychain.root().has_private(), true);
        assert_eq!(keychain.subkey_by_name("sign").unwrap().key().has_private(), true);
        assert_eq!(keychain.subkey_by_name("crypto").unwrap().key().has_private(), true);
        assert!(keychain.subkey_by_name("secret").is_some());

        let keychain = keychain.strip_private();

        assert_eq!(keychain.alpha().has_private(), false);
        assert_eq!(keychain.policy().has_private(), false);
        assert_eq!(keychain.publish().has_private(), false);
        assert_eq!(keychain.root().has_private(), false);
        assert_eq!(keychain.subkey_by_name("sign").unwrap().key().has_private(), false);
        assert_eq!(keychain.subkey_by_name("crypto").unwrap().key().has_private(), false);
        assert!(keychain.subkey_by_name("secret").is_none());
    }
}

