use chrono::{DateTime, Utc};
use crate::{
    error::Result,
    key::{SecretKey, SignKeypairSignature, SignKeypair, CryptoKeypair},
    private::{Private, MaybePrivate},
};
use getset;
use serde_derive::{Serialize, Deserialize};

/// A unique identifier for identities. Effectively, we use a randomly-generated
/// ID as the canonical identifier for an identity (as opposed to a public key,
/// which might change over time).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ID(String);

/// A signature on a claim. Contains the date the claim was signed along with
/// the actual signature.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Signature {
    /// Signature of the *publically available* claim data. If the claim is
    /// private, we sign the encrypted claim data, not the decrypted claim data.
    sig: SignKeypairSignature,
    /// The public key that signed this claim
    by_key: SignKeypair,
    /// Filled in by the stamper, the date the claim was stamped
    date_signed: DateTime<Utc>,
}

/// A stamp of approval on a claim.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Stamp {
    /// Who stamped it
    from: ID,
    /// Their signature
    signature: Signature,
    /// The date this stamp was saved (from the claim owner's point of view)
    date_recorded: DateTime<Utc>,
}

/// This is very specific but might be able to be generalized somehow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClaimSpec {
    /// A claim that the ID of this key belongs to the identity's current
    /// keypair
    ID(String),
    /// A claim that the name attached to this identity is mine.
    Name(String),
    /// A claim that I own an email address
    Email(String),
    /// A claim that I own a PGP keypair
    PGP(String),
    /// A claim that I reside at a physical address
    HomeAddress(String),
    /// Any kind of claim of ownership or possession outside the defined types.
    ///
    /// This can be something like a state-issued identification, ownership over
    /// an internet domain name, a social networking screen name, etc.
    ///
    /// Effectively, this exists as a catch-all and allows for many more types
    /// of claims than can be thought of here. This could be a JSON string with
    /// a pre-defined schema stored somewhere. It could be an XML document. It
    /// could be binary-encoded data.
    ///
    /// Anything you can dream up that you wish to claim in any format can exist
    /// here.
    Extension(Vec<u8>),
}

/// A claim made by an identity.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Claim {
    id: String,
    data: MaybePrivate<ClaimSpec>,
    stamps: Vec<Stamp>,
}

/// A Keyset is a set of keys.
///
/// One key to encrypt messages.
/// One key to hide them.
/// One key to verify claims, and in the darkness sign them.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Keyset {
    /// Signs our claims and others' claims
    sign: SignKeypair,
    /// Lets others send us encrypted messages, and us them.
    crypto: CryptoKeypair,
    /// Hides our private claim data
    secret: Private<SecretKey>,
}

impl Keyset {
    pub fn new(master_key: &SecretKey) -> Result<Self> {
        Ok(Self {
            sign: SignKeypair::new_ed25519(master_key)?,
            crypto: CryptoKeypair::new_curve25519xsalsa20poly1305(master_key)?,
            secret: Private::seal(master_key, &SecretKey::new_xsalsa20poly1305())?,
        })
    }
}

/// Describes te various versions our for our identity format, allowing upgrades
/// and downgrades.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IdentityVersion {
    V1,
}

impl Default for IdentityVersion {
    fn default() -> Self {
        Self::V1
    }
}

/// A set of forward types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForwardType {
    /// An email address
    Email(String),
    /// A social identity. This is two strings to represent type and handle/url.
    Social(String, String),
    /// A raw url.
    Url(String),
    /// An extension type, can be used to implement any kind of forward you can
    /// think of.
    Extension(Vec<u8>),
}

/// A pointer to somewhere else.
///
/// This can be useful for pointing either people or machines to a known
/// location. For instance, if you switch Mastodon servers, you could add a new
/// "Mastodon" forward pointing to your new handle and mark it as the default
/// for that forward type. Or you could forward to your personal domain, or
/// your email address.
///
/// Each forward is signed with your signing public key. This is a bit different
/// from a claim, in that claims help verify your identity, and forwards are
/// assertions you can make that don't require external verification. If people
/// trust that this is *your* identity via the signed claims, then they can
/// trust the forwards you assert and sign.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Forward {
    /// The forward type we're creating
    val: ForwardType,
    /// Whether or not this forward is a default. For instance, you could have
    /// ten emails listed, but only one used as the default. If multiple
    /// defaults are given for a particular forward type, then the one with the
    /// most recent `Signature::date_signed` date in the `SignedForward::sig`
    /// field should be used.
    is_default: bool,
}

/// A forward that has been signed by its creator.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct SignedForward {
    /// The forward which is signed
    forward: Forward,
    /// The signature for this forward
    sig: Signature,
}

/// An identity.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Identity {
    /// The version of this identity
    version: IdentityVersion,
    /// The unique identifier for this identity
    id: ID,
    /// The identity's current and default master key set
    keyset: Keyset,
    /// Expired or deprecated or compromised keysets.
    old_keysets: Vec<Keyset>,
    /// The claims this identity makes.
    claims: Vec<Claim>,
    /// A canonical list of places this identity forwards to.
    forwards: Vec<SignedForward>,
}

impl Identity {
    /// Create a new identity
    pub fn new(id: ID, master_key: &SecretKey) -> Result<Self> {
        Ok(Self {
            version: IdentityVersion::default(),
            id,
            keyset: Keyset::new(master_key)?,
            old_keysets: Vec::new(),
            claims: Vec::new(),
            forwards: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        key::derive_master_key,
        util,
    };
    use sodiumoxide::{
        crypto::{
            pwhash::argon2id13,
        },
    };
    use std::convert::TryInto;

    fn gen_master_key() -> SecretKey {
        SecretKey::new_xsalsa20poly1305()
    }

    #[test]
    fn derives_master_key() {
        let id = util::hash("my key".as_bytes()).unwrap();
        let salt = util::hash(id.as_ref()).unwrap();
        let saltbytes: [u8; argon2id13::SALTBYTES] = salt.as_ref()[0..argon2id13::SALTBYTES].try_into().unwrap();
        let master_key = derive_master_key("ZONING IS COMMUNISM".as_bytes(), &saltbytes).unwrap();
        assert_eq!(master_key.as_ref(), &[191, 236, 76, 249, 25, 39, 71, 203, 144, 167, 11, 131, 221, 21, 4, 194, 6, 176, 163, 123, 238, 170, 148, 29, 236, 186, 130, 157, 51, 202, 207, 169]);
    }

    #[test]
    fn init() {
        let id = ID(sodiumoxide::hex::encode(util::hash("id10905542".as_bytes()).unwrap().as_ref()));
        let master_key = gen_master_key();
        let identity = Identity::new(id.clone(), &master_key).unwrap();

        assert_eq!(identity.version(), &IdentityVersion::default());
        assert_eq!(identity.id(), &id);
        assert_eq!(identity.old_keysets().len(), 0);
        assert_eq!(identity.claims().len(), 0);
        assert_eq!(identity.forwards().len(), 0);
    }
}

