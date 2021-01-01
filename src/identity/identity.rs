use crate::{
    error::{Error, Result},
    identity::{
        claim::{ClaimSpec, ClaimContainer},
        keychain::Keychain,
    },
    key::{SecretKey, SignKeypairSignature, SignKeypair},
    ser,
    util::{
        Timestamp,
        sign::{DateSigner, SignedValue},
    },
    IdentityVersion,
    VersionedIdentity,
};
use getset;
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;

/// A unique identifier for identities.
///
/// We generate this by signing the string "This is my stamp." in a `DateSigner`
/// using our initial private signing key.
///
/// `IdentityID`s are permanent and are not regenerated when the keysets are
/// rotated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityID(SignKeypairSignature);

impl Deref for IdentityID {
    type Target = SignKeypairSignature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A set of forward types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForwardType {
    /// An email address
    Email(String),
    /// A social identity. This is two strings to represent type and handle/url.
    Social(String, String),
    /// A PGP keypair ID or URL to a published public key
    PGP(String),
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
/// Each forward is signed with your signing secret key. This is a bit different
/// from a claim in that claims help verify your identity, and forwards are
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

/// Extra public data that is attached to our identity.
///
/// Each entry in this struct is signed by our root signing key. In the case
/// that our identity is re-keyed, the entries in this struct must be re-signed.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct IdentityExtraData {
    /// An always-public nickname that can be used to look up this identity
    /// in various indexed locations. This will always have `stamp://` prepended
    /// to it, so don't include it here.
    ///
    /// For instance, I might set my nickname as "zefram-cochrane" and
    /// from thereafter people will be able to find me via the nickname
    /// `stamp://zefram-cochrane`.
    ///
    /// Note that this necessarily cannot be unique, so services that index the
    /// nickname will need to list *all* known identities using that shortname.
    /// Note that it will be possible to specify a hex ID in long or short-form,
    /// such as `stamp://zefram-cochrane/b07f4429c5`.
    ///
    /// It's up to users of the protocol to pick names that are unique enough to
    /// avoid accidental collisions, and any malicious immitations must be
    /// weeded out by inclusion of an ID (prefix or full), stamp verification
    /// and trust levels.
    nickname: Option<SignedValue<String>>,
    /// A canonical list of places this identity forwards to.
    forwards: Vec<SignedValue<Forward>>,
}

impl IdentityExtraData {
    /// Create a blank identity data container
    pub fn new() -> Self {
        Self {
            nickname: None,
            forwards: Vec::new(),
        }
    }
}

/// An identity.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Identity {
    /// The unique identifier for this identity.
    id: IdentityID,
    /// A signature that is created by collecting all signatures contained in
    /// the identity and signing them with the root signing key.
    ///
    /// This gives any identity a verifiable completeness: if any data is added
    /// or removed that is not authorized by the identity owner, the identity
    /// will fail to validate. This can be useful in cases where an identity is
    /// distributed by a third party.
    ///
    /// This obviously doesn't guard against distributing an old (but unedited)
    /// version of an identity.
    root_signature: SignKeypairSignature,
    /// When this identity was created. This value is signed in the IdentityID
    /// via a `DateSigner`.
    created: Timestamp,
    /// Holds the keys for our identity.
    keychain: Keychain,
    /// The claims this identity makes.
    claims: Vec<ClaimContainer>,
    /// Extra data that can be attached to our identity.
    extra_data: IdentityExtraData,
}

impl Identity {
    /// Create a new identity
    pub fn new(master_key: &SecretKey, now: Timestamp) -> Result<Self> {
        let root_keypair = SignKeypair::new_ed25519(master_key)?;
        let id_string = String::from("This is my stamp.");
        let datesigner = DateSigner::new(&now, &id_string);
        let ser = ser::serialize(&datesigner)?;
        let sig = root_keypair.sign(master_key, &ser)?;
        let id = IdentityID(sig);
        let identity_claim = ClaimContainer::new(master_key, &root_keypair, now.clone(), ClaimSpec::Identity(id.clone()))?;
        let keychain = Keychain::new(root_keypair);
        let extra_data = IdentityExtraData::new();
        let temporary_root_signature = keychain.root().sign(master_key, "temporary".as_bytes())?;
        let mut identity = Self {
            id,
            root_signature: temporary_root_signature,
            created: now,
            keychain,
            claims: vec![identity_claim],
            extra_data,
        };
        identity.set_root_signature(identity.generate_root_signature(master_key)?);
        Ok(identity)
    }

    /// Grab a list of all our identity's sub-signatures.
    fn sub_signatures(&self) -> Vec<&SignKeypairSignature> {
        let mut signatures = vec![
            &self.id().0,
        ];

        // sign the signatures of all our subkeys
        for subkey in self.keychain().subkeys() {
            signatures.push(&subkey.signature());
        }

        // sign our claims and their stamps
        for claim in self.claims() {
            // sign each claim's id (which is itself a signature)
            signatures.push(&claim.claim().id());
            // now sign each claim's accepted stamps. the accepted stamp's
            // signature signs the entire stamp, so we can stop there.
            for stamp in claim.stamps() {
                signatures.push(&stamp.signature());
            }
        }

        // sign our extra data
        if let Some(nickname) = self.extra_data().nickname().as_ref() {
            signatures.push(nickname.signature());
        }
        for forward in self.extra_data().forwards() {
            signatures.push(forward.signature());
        }
        signatures
    }

    /// Generate a signature that is a result of signing all the identity's
    /// contained signatures *in the order they are stored*.
    ///
    /// This makes each identity completely immutable (even the order of the
    /// contained items) by anyone but the owner of the master key/root signing
    /// key.
    ///
    /// One signature to rule them all.
    fn generate_root_signature(&self, master_key: &SecretKey) -> Result<SignKeypairSignature> {
        let signatures = self.sub_signatures();
        let serialized = ser::serialize(&signatures)?;
        self.keychain().root().sign(master_key, &serialized)
    }

    /// Verify that the portions of this identity that can be verified, mainly
    /// by using the identity's public signing key.
    ///
    /// Specifically, we verify our identity's ID, the signatures we've made on
    /// our claims (stored in each claim's ID), and the identity's extra data
    /// entries.
    ///
    /// The idea here is that we can't verify the stamps on our claims inside
    /// the identity (we need the public keys of all the signers for that, which
    /// must not be stored alongside the signatures).
    pub fn verify(&self) -> Result<()> {
        // verify our root signature
        let sub_signatures = self.sub_signatures();
        self.keychain().root().verify(self.root_signature(), &ser::serialize(&sub_signatures)?)?;

        // a helper that tries to verify a signature with all the signing keys
        // in the keychain, even the revoked ones.
        let verify_multi = |sig: &SignKeypairSignature, bytes_to_verify: &[u8]| -> std::result::Result<(), ()> {
            match self.keychain().root().verify(sig, bytes_to_verify) {
                Ok(_) => Ok(()),
                _ => {
                    for sign_keypair in self.keychain().subkeys_sign() {
                        if sign_keypair.verify(sig, bytes_to_verify).is_ok() {
                            return Ok(());
                        }
                    }
                    Err(())
                }
            }
        };

        let id_string = String::from("This is my stamp.");
        let datesigner = DateSigner::new(self.created(), &id_string);
        let ser = ser::serialize(&datesigner)?;
        verify_multi(&self.id().0, &ser)
            .map_err(|_| Error::IdentityVerificationFailed(String::from("identity.id")))?;

        // now check that our claims are signed with one of our sign keys
        for claim in self.claims() {
            let datesigner = DateSigner::new(claim.claim().created(), claim.claim().spec());
            let ser = ser::serialize(&datesigner)?;
            verify_multi(&claim.claim().id(), &ser)
                .map_err(|_| {
                    Error::IdentityVerificationFailed(format!("identity.claims[{}].id", claim.claim().id().to_hex()))
                })?;
        }

        Ok(())
    }
}

impl VersionedIdentity for Identity {
    fn version(self) -> IdentityVersion {
        IdentityVersion::V1(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_master_key() -> SecretKey {
        SecretKey::new_xsalsa20poly1305()
    }

    #[test]
    fn init() {
        let master_key = gen_master_key();
        let now = Timestamp::now();
        let identity = Identity::new(&master_key, now).unwrap();

        assert_eq!(identity.keychain().subkeys().len(), 0);
        assert_eq!(identity.claims().len(), 1);
        assert!(identity.extra_data().nickname().is_none());
        assert_eq!(identity.extra_data().forwards().len(), 0);
    }

    #[test]
    fn verify() {
        let master_key = gen_master_key();
        let now = Timestamp::now();
        let identity = Identity::new(&master_key, now).unwrap();
        assert_eq!(identity.verify(), Ok(()));
    }
}

