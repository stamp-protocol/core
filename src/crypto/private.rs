//! The private module locks data away via a [`SecretKey`]
//! while never storing or serializing or displaying the locked (private) data.
//! It can only be retrieved via the [open](crate::crypto::private::Private::open)
//! method, given the correct unlocking key.
//!
//! This allows for secure storage of things like private keys, or even claims
//! we wish to be verifiable but not publicly available.
//!
//! In this module is also the [`MaybePrivate`]
//! container which gives us a choice to either make something public or to keep
//! it private and sealed away.

use crate::{
    crypto::base::{Hmac, HmacKey, Sealed, SecretKey},
    error::{Error, Result},
    util::ser,
};
use private_parts::{AsOption, Full, MergeError, PrivacyMode, PrivateDataContainer, PrivateParts, Public};
use rand::{CryptoRng, RngCore};
use rasn::{
    types::{Identifier, Tag},
    AsnType, Decode, Decoder, Encode, Encoder,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::marker::PhantomData;

/// Defines an interface for re-encrypting an object with a new key.
pub trait ReEncrypt: Sized {
    /// Re-encrypts the object with a new key. Everyone's doing it.
    fn reencrypt<R: RngCore + CryptoRng>(self, rng: &mut R, previous_seal_key: &SecretKey, new_seal_key: &SecretKey) -> Result<Self>;
}

/// Holds private data stripped from [`Full`] objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateContainer(VecDeque<Sealed>);

impl Default for PrivateContainer {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl PrivateDataContainer for PrivateContainer {
    type Value = Sealed;

    fn push_private(&mut self, val: Self::Value) {
        self.0.push_front(val);
    }

    fn pop_private(&mut self) -> Option<Self::Value> {
        self.0.pop_back()
    }
}

impl AsnType for PrivateContainer {
    const TAG: Tag = Tag::SET;
    const IDENTIFIER: Identifier = Identifier::SET_OF;
}

impl Encode for PrivateContainer {
    fn encode_with_tag_and_constraints<'encoder, E: Encoder<'encoder>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
        identifier: rasn::types::Identifier,
    ) -> std::result::Result<(), E::Error> {
        let values_vec: Vec<Sealed> = self.0.clone().into();
        encoder.encode_sequence_of(tag, &values_vec, constraints, identifier)?;
        Ok(())
    }
}

impl Decode for PrivateContainer {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
    ) -> std::result::Result<Self, D::Error> {
        let values_vec = Vec::<Sealed>::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self(values_vec.into()))
    }
}

/// Holds private data, which can only be opened if you have the special key.
#[derive(Debug, Serialize, Deserialize)]
pub struct Private<M: PrivacyMode, T> {
    /// Allows us to cast this container to T without this container ever
    /// actually storing any T value (because it's encrypted).
    #[serde(skip)]
    _phantom: PhantomData<T>,
    /// The encrypted data stored in this container, created using a
    /// `PrivateVerifiableInner` struct (the actual data alongside an HMAC key).
    sealed: M::Private<Sealed>,
}

impl<T: Encode + Decode> Private<Full, T> {
    /// Create a new Private container from a given serializable data object and
    /// an encrypting key.
    pub fn seal<R: RngCore + CryptoRng>(rng: &mut R, seal_key: &SecretKey, data: &T) -> Result<Self> {
        let serialized = ser::serialize(data)?;
        let sealed = seal_key.seal(rng, &serialized)?;
        Ok(Self {
            _phantom: PhantomData,
            sealed,
        })
    }

    /// Open a Private container with a decrypting key.
    pub fn open(&self, seal_key: &SecretKey) -> Result<T> {
        let open_bytes = seal_key.open(&self.sealed).map_err(|_| Error::CryptoOpenFailed)?;
        let obj: T = ser::deserialize(&open_bytes[..])?;
        Ok(obj)
    }
}

impl<T: Encode + Decode> Private<Public, T> {
    /// Create a blank `Private` for use when converting into a public field.
    pub fn blank() -> Self {
        Self {
            _phantom: PhantomData::<T>,
            sealed: (),
        }
    }
}

impl<T> PrivateParts for Private<Full, T> {
    type PublicView = Private<Public, T>;
    type PrivateData = PrivateContainer;
    type MergeError = MergeError;

    fn strip(self) -> (Self::PublicView, Self::PrivateData) {
        let Self { sealed, _phantom } = self;
        let public = Self::PublicView {
            sealed: (),
            _phantom: PhantomData,
        };
        let mut private = Self::PrivateData::default();
        private.push_private(sealed);
        (public, private)
    }

    fn merge(_public: Self::PublicView, private: &mut Self::PrivateData) -> std::result::Result<Self, Self::MergeError> {
        match private.pop_private() {
            Some(sealed) => Ok(Self {
                sealed,
                _phantom: PhantomData,
            }),
            _ => Err(MergeError::MissingPrivateData),
        }
    }
}

impl<T> ReEncrypt for Private<Full, T> {
    fn reencrypt<R: RngCore + CryptoRng>(self, rng: &mut R, previous_seal_key: &SecretKey, new_seal_key: &SecretKey) -> Result<Self> {
        let serialized = previous_seal_key.open(&self.sealed).map_err(|_| Error::CryptoOpenFailed)?;
        let sealed = new_seal_key.seal(rng, &serialized)?;
        Ok(Self {
            _phantom: PhantomData,
            sealed,
        })
    }
}

impl<M: PrivacyMode, T> AsnType for Private<M, T> {
    const TAG: Tag = <Option<Sealed> as AsnType>::TAG;
}

impl<M: PrivacyMode, T> Encode for Private<M, T> {
    fn encode_with_tag_and_constraints<'encoder, E: Encoder<'encoder>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
        identifier: rasn::types::Identifier,
    ) -> std::result::Result<(), E::Error> {
        let opt: Option<_> = self.sealed.clone().into_option();
        opt.encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

impl<M: PrivacyMode, T> Decode for Private<M, T> {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
    ) -> std::result::Result<Self, D::Error> {
        let opt = Option::<M::Private<_>>::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        let sealed =
            M::Private::try_from_option(opt).map_err(|_| rasn::de::Error::no_valid_choice("incorrect option variant", rasn::Codec::Der))?;
        Ok(Self {
            _phantom: PhantomData,
            sealed,
        })
    }
}

impl<M: PrivacyMode, T> Clone for Private<M, T> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
            sealed: self.sealed.clone(),
        }
    }
}

impl<M: PrivacyMode, T> PartialEq for Private<M, T> {
    fn eq(&self, _other: &Self) -> bool {
        // NEVER
        false
    }
}

/// Stores an HMAC key next to a set of data.
///
/// This is a somewhat ephemeral container used by [`PrivateWithHmac`], mainly used for encryption
/// and decryption and then thrown away.
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
pub struct DataWithHmacKey<T> {
    /// The value we're storing.
    #[rasn(tag(explicit(0)))]
    value: T,
    /// The HMAC key we use to hash the data.
    #[rasn(tag(explicit(1)))]
    hmac_key: HmacKey,
}

/// Holds private data along with an HMAC of the data being stored, allowing
/// the HMAC to be signed for verification without leaking information about the
/// private data itself.
///
/// This works such that:
///
/// - The private data is stored alongside an HMAC key (both encrypted)
/// - The HMAC key can be used to derive a hash of the data
///
/// This allows anybody who has access to the private data to verify that the
/// HMAC matches the data, but makes it nearly impossible for someone who only
/// has a (public) signature of the HMAC to determine what the private data
/// actually is.
///
/// The idea here is that someone can stamp the *HMAC* of a private claim, and
/// others can verify that stamp against the HMAC, but the signature of the
/// HMAC itself reveals no information about the private data.
///
/// This also allows the key that protects the private data to be rotated
/// without the HMAC (and therefor the stamps) on that data being deprecated.
#[derive(
    Clone, Debug, PrivateParts, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters,
)]
#[parts(private_data = "PrivateContainer")]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct PrivateWithHmac<M: PrivacyMode, T> {
    /// Holds the HMAC for this private data so it can be verified without
    /// revealing the data itself
    #[rasn(tag(explicit(0)))]
    pub(crate) hmac: Hmac,
    /// The (encrypted) data AND HMAC key.
    #[rasn(tag(explicit(1)))]
    pub(crate) data: Private<M, DataWithHmacKey<T>>,
}

impl<M: PrivacyMode, T> PrivateWithHmac<M, T> {
    /// Create a new private hmac container
    pub fn new(hmac: Hmac, data: Private<M, DataWithHmacKey<T>>) -> Self {
        Self { hmac, data }
    }
}

impl<T: Encode + Decode> PrivateWithHmac<Full, T> {
    /// Create a new verifiable private container from a given serializable data
    /// object and an encrypting key.
    ///
    /// We generate a random HMAC key and do two things:
    ///
    /// 1. HMAC the data being stored with the HMAC key, then store the data and
    ///    the HMAC key together in a `DataWithHmacKey` container before
    ///    encrypting the container.
    /// 2. Sign the generated HMAC with our private key, then throw away the
    ///    HMAC and *only store the signature*.
    ///
    /// Using this scheme, anybody who knows the stored secret can recreate the
    /// HMAC and thus verify the public signature on the secret. However, the
    /// signature itself reveals nothing about the secret data because the HMAC
    /// obscures the data behind an encrypted key.
    // NOTE: we have `data: T` instead of `data: &T` because of some consistency stuff with
    // MaybePrivate's API.
    pub fn seal<R: RngCore + CryptoRng>(rng: &mut R, seal_key: &SecretKey, data: T) -> Result<Self> {
        // create a new random key and use it to HMAC our data
        let hmac_key = HmacKey::new_blake3(rng)?;
        let hmac = Hmac::new(&hmac_key, &ser::serialize(&data)?)?;
        // store our data alongside our HMAC key, allowing anybody with access
        // to this container to regenerate the HMAC.
        let inner = DataWithHmacKey { value: data, hmac_key };
        let private = Private::seal(rng, seal_key, &inner)?;
        Ok(Self { hmac, data: private })
    }

    /// Open and return the secret stored in this container, provided that the
    /// HMAC stored with this secret is the same as the one we generate when we
    /// HMAC the decrypted data with the decrypted HMAC key.
    ///
    /// If the data has been tampered with and the HMACs don't verify, then we
    /// return an error.
    pub fn open_and_verify(&self, seal_key: &SecretKey) -> Result<T> {
        let inner: DataWithHmacKey<T> = self.data().open(seal_key)?;
        let DataWithHmacKey { value, hmac_key } = inner;
        // verify our hmac against our decrypted data/hmac key
        self.hmac.verify(&hmac_key, &ser::serialize(&value)?)?;
        // success!
        Ok(value)
    }
}

impl<T> ReEncrypt for PrivateWithHmac<Full, T> {
    fn reencrypt<R: RngCore + CryptoRng>(self, rng: &mut R, previous_seal_key: &SecretKey, new_seal_key: &SecretKey) -> Result<Self> {
        let Self { hmac, data: private } = self;
        Ok(Self {
            hmac,
            data: private.reencrypt(rng, previous_seal_key, new_seal_key)?,
        })
    }
}

impl<M: PrivacyMode, T> PartialEq for PrivateWithHmac<M, T> {
    fn eq(&self, other: &Self) -> bool {
        self.hmac() == other.hmac()
    }
}

/// A wrapper that contains either public/plaintext data of type T or encrypted
/// data, which can be deserialized to T.
#[derive(Debug, Clone, PartialEq, PrivateParts, AsnType, Encode, Decode, Serialize, Deserialize)]
#[parts(private_data = "PrivateContainer")]
#[rasn(choice)]
pub enum MaybePrivate<M: PrivacyMode, T> {
    /// Any publicly-viewable data
    #[rasn(tag(explicit(0)))]
    Public(T),
    /// Secret data, which can only be opened with the corresponding decryption
    /// key, stored alongside an HMAC of the secret data which allows verification
    /// without data leakage.
    #[rasn(tag(explicit(1)))]
    PrivateVerifiable(PrivateWithHmac<M, T>),
    /// Secret data which is wrapped in a [`Sealed`] container. Not verifiable without decrypting.
    /// but doesn't require storing an HMAC next to it in cases where verification isn't needed.
    #[rasn(tag(explicit(2)))]
    Private(Private<M, T>),
}

impl<T: Clone, M: PrivacyMode> MaybePrivate<M, T> {
    /// Get the data from this MaybePrivate if it is public
    pub fn open_public(&self) -> Option<T> {
        match self {
            Self::Public(x) => Some(x.clone()),
            _ => None,
        }
    }
}

impl<T: Encode + Decode + Clone> MaybePrivate<Full, T> {
    /// Create a new public MaybePrivate value.
    pub fn new_public(val: T) -> Self {
        Self::Public(val)
    }

    /// Create a new private MaybePrivate value.
    pub fn new_private_verifiable<R: RngCore + CryptoRng>(rng: &mut R, seal_key: &SecretKey, val: T) -> Result<Self> {
        let container = PrivateWithHmac::seal(rng, seal_key, val)?;
        Ok(Self::PrivateVerifiable(container))
    }

    /// Create a new private MaybePrivate value.
    pub fn new_private<R: RngCore + CryptoRng>(rng: &mut R, seal_key: &SecretKey, val: T) -> Result<Self> {
        let private = Private::<Full, T>::seal(rng, seal_key, &val)?;
        Ok(Self::Private(private))
    }

    /// Get the HMAC for this MaybePrivate, if it has one.
    pub fn hmac(&self) -> Option<&Hmac> {
        match self {
            Self::PrivateVerifiable(container) => Some(container.hmac()),
            _ => None,
        }
    }

    /// Open this MaybePrivate container to access the data within (if it even
    /// has data).
    pub fn open(&self, seal_key: &SecretKey) -> Result<T> {
        match self {
            Self::Public(x) => Ok(x.clone()),
            Self::PrivateVerifiable(container) => container.open_and_verify(seal_key),
            Self::Private(private) => {
                let unsealed = seal_key.open(&private.sealed)?;
                ser::deserialize(&unsealed)
            }
        }
    }

    /// Convert this MaybePrivate into a DefinitelyPublic.
    pub fn into_public(self, seal_key: &SecretKey) -> Result<Self> {
        match self {
            Self::Public(x) => Ok(Self::Public(x)),
            Self::PrivateVerifiable(container) => {
                let unsealed = container.open_and_verify(seal_key)?;
                Ok(Self::Public(unsealed))
            }
            Self::Private(private) => {
                let unsealed = seal_key.open(&private.sealed)?;
                Ok(Self::Public(ser::deserialize(&unsealed)?))
            }
        }
    }
}

impl<T> ReEncrypt for MaybePrivate<Full, T> {
    fn reencrypt<R: RngCore + CryptoRng>(self, rng: &mut R, previous_seal_key: &SecretKey, new_seal_key: &SecretKey) -> Result<Self> {
        let maybe = match self {
            Self::Public(x) => Self::Public(x),
            Self::PrivateVerifiable(container) => Self::PrivateVerifiable(container.reencrypt(rng, previous_seal_key, new_seal_key)?),
            Self::Private(private) => Self::Private(private.reencrypt(rng, previous_seal_key, new_seal_key)?),
        };
        Ok(maybe)
    }
}

impl<T: Clone + AsnType + Encode + Decode> From<T> for MaybePrivate<Full, T> {
    fn from(value: T) -> Self {
        MaybePrivate::new_public(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_seal_open() {
        let mut rng = crate::util::test::rng();
        let key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let sealed: Private<Full, String> = Private::seal(&mut rng, &key, &String::from("get a job")).unwrap();
        let opened: String = sealed.open(&key).unwrap();
        assert_eq!(&opened, "get a job");
        let key2 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        assert!(key != key2);
        let res: Result<String> = sealed.open(&key2);
        assert_eq!(res, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn private_reencrypt() {
        let mut rng = crate::util::test::rng();
        let key1 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let key2 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let sealed: Private<Full, String> = Private::seal(&mut rng, &key1, &String::from("get a job")).unwrap();
        let sealed2 = sealed.reencrypt(&mut rng, &key1, &key2).unwrap();
        let opened: String = sealed2.open(&key2).unwrap();
        assert_eq!(&opened, "get a job");
        let res: Result<String> = sealed2.open(&key1);
        assert_eq!(res, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn maybe_private_seal_open_verify() {
        let mut rng = crate::util::test::rng();
        let seal_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let mut fake_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        // fake_key can never == seal_key. unfathomable, but possible.
        while seal_key == fake_key {
            fake_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        }
        let fake_mac_key = HmacKey::new_blake3(&mut rng).unwrap();

        let maybe1: MaybePrivate<Full, String> = MaybePrivate::Public(String::from("hello"));
        let maybe2: MaybePrivate<Full, String> = MaybePrivate::new_private_verifiable(&mut rng, &seal_key, String::from("omg")).unwrap();
        let maybe2_tampered = match maybe2.clone() {
            MaybePrivate::PrivateVerifiable(PrivateWithHmac { data, .. }) => MaybePrivate::PrivateVerifiable(PrivateWithHmac::new(
                Hmac::new(&fake_mac_key, String::from("loool").as_bytes()).unwrap(),
                data,
            )),
            _ => panic!("bad maybeprivate given"),
        };
        let maybe3: MaybePrivate<Full, String> = MaybePrivate::new_private(&mut rng, &seal_key, String::from("zing")).unwrap();

        assert_eq!(maybe1.open(&seal_key).unwrap(), String::from("hello"));
        // fake key can open public data, nobody cares
        assert_eq!(maybe1.open(&fake_key).unwrap(), String::from("hello"));

        assert_eq!(maybe2.open(&seal_key), Ok(String::from("omg")));
        assert_eq!(maybe2_tampered.open(&seal_key), Err(Error::CryptoHmacVerificationFailed));
        // fake key cannot open
        assert_eq!(maybe2.open(&fake_key), Err(Error::CryptoOpenFailed));

        assert_eq!(maybe3.open(&seal_key), Ok(String::from("zing")));
        assert_eq!(maybe3.open(&fake_key), Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn maybe_private_open_public() {
        let mut rng = crate::util::test::rng();
        let seal_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let mut fake_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        // fake_key can never == seal_key. unfathomable, but possible.
        while seal_key == fake_key {
            fake_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        }
        let fake_mac_key = HmacKey::new_blake3(&mut rng).unwrap();

        let maybe1: MaybePrivate<Full, String> = MaybePrivate::Public(String::from("hello"));
        let maybe2: MaybePrivate<Full, String> = MaybePrivate::new_private_verifiable(&mut rng, &seal_key, String::from("omg")).unwrap();
        let maybe3: MaybePrivate<Full, String> = MaybePrivate::new_private(&mut rng, &seal_key, String::from("wtfwtf")).unwrap();
        let maybe4: MaybePrivate<Public, String> = MaybePrivate::PrivateVerifiable(PrivateWithHmac::new(
            Hmac::new(&fake_mac_key, Vec::new().as_slice()).unwrap(),
            Private::<Public, DataWithHmacKey<String>>::blank(),
        ));

        assert_eq!(maybe1.open_public().unwrap(), "hello");
        assert_eq!(maybe2.open_public(), None);
        assert_eq!(maybe3.open_public(), None);
        assert_eq!(maybe4.open_public(), None);
    }

    #[test]
    fn maybe_private_into_public() {
        let mut rng = crate::util::test::rng();
        let seal_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let fake_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        assert!(seal_key != fake_key);

        let maybe1: MaybePrivate<Full, String> = MaybePrivate::Public(String::from("hello"));
        let maybe2: MaybePrivate<Full, String> = MaybePrivate::new_private_verifiable(&mut rng, &seal_key, String::from("omg")).unwrap();
        let maybe3: MaybePrivate<Full, String> = MaybePrivate::new_private(&mut rng, &seal_key, String::from("HELP")).unwrap();

        assert_eq!(maybe1.clone().into_public(&seal_key).unwrap(), MaybePrivate::Public(String::from("hello")));
        // fake key works too because who gives a crap if it's public. grind me up
        // into little pieces and throw me in the river.
        assert_eq!(maybe1.clone().into_public(&fake_key).unwrap(), MaybePrivate::Public(String::from("hello")));
        assert_eq!(maybe2.clone().into_public(&seal_key).unwrap(), MaybePrivate::Public(String::from("omg")));
        assert_eq!(maybe2.clone().into_public(&fake_key), Err(Error::CryptoOpenFailed));
        assert_eq!(maybe3.clone().into_public(&seal_key).unwrap(), MaybePrivate::Public(String::from("HELP")));
        assert_eq!(maybe3.clone().into_public(&fake_key), Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn maybe_private_reencrypt_mac() {
        let mut rng = crate::util::test::rng();
        let seal_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let seal_key2 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();

        let maybe1: MaybePrivate<Full, String> = MaybePrivate::Public(String::from("hello"));
        let maybe2: MaybePrivate<Full, String> = MaybePrivate::new_private_verifiable(&mut rng, &seal_key, String::from("omg")).unwrap();
        let maybe3: MaybePrivate<Full, String> = MaybePrivate::new_private(&mut rng, &seal_key, String::from("LOOOOL")).unwrap();

        let maybe1_2 = maybe1.clone().reencrypt(&mut rng, &seal_key, &seal_key2).unwrap();
        let maybe2_2 = maybe2.clone().reencrypt(&mut rng, &seal_key, &seal_key2).unwrap();
        let maybe3_2 = maybe3.clone().reencrypt(&mut rng, &seal_key, &seal_key2).unwrap();

        // should fail, kinda
        assert_eq!(maybe1_2.open(&seal_key), Ok(String::from("hello")));
        assert_eq!(maybe2_2.open(&seal_key), Err(Error::CryptoOpenFailed));
        assert_eq!(maybe3_2.open(&seal_key), Err(Error::CryptoOpenFailed));

        // should work, mostly
        assert_eq!(maybe1_2.open(&seal_key2), Ok(String::from("hello")));
        assert_eq!(maybe2_2.open(&seal_key2), Ok(String::from("omg")));
        assert_eq!(maybe3_2.open(&seal_key2), Ok(String::from("LOOOOL")));

        // make sure the HMAC stays the same, if present
        assert_eq!(maybe1.hmac(), None);
        assert_eq!(maybe1_2.hmac(), None);
        assert_eq!(maybe3_2.hmac(), None);
    }

    #[test]
    fn private_ser() {
        let mut rng = crate::util::test::rng_seeded(b"jimmy don't");
        let seal_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let myval = String::from("test");
        let private = Private::seal(&mut rng, &seal_key, &myval).unwrap();
        let private_pub = private.clone().strip().0;
        assert_eq!(
            ser::base64_encode(&ser::serialize(&private).unwrap()),
            "MDigHKAaBBhY2IluUNgNFIoGEzjuXmX76BZ7VZ_MsDShGAQW6y9hYXAf297OX6oclrwtOGJOFOuuqg",
        );
        assert_eq!(ser::base64_encode(&ser::serialize(&private_pub).unwrap()), "");
    }

    #[test]
    fn maybe_private_ser() {
        #[derive(Clone, Debug, AsnType, Encode, Decode)]
        struct Packet {
            #[rasn(tag(explicit(0)))]
            ty: String,
            #[rasn(tag(explicit(1)))]
            data: u32,
        }

        let mut rng = crate::util::test::rng_seeded(b"jimmy don't");
        let seal_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();

        let packet = Packet {
            ty: "/stamp/net/v1/packet".into(),
            data: 69,
        };
        let ser1 = ser::serialize(&packet).unwrap();
        let ser2 = ser::serialize(&seal_key.seal(&mut rng, &ser1).unwrap()).unwrap();
        let ser3 = ser::serialize(&MaybePrivate::<Full, _>::Public(packet.clone())).unwrap();
        let ser4 = ser::serialize(&MaybePrivate::new_private(&mut rng, &seal_key, packet.clone()).unwrap()).unwrap();
        let ser5 = ser::serialize(&MaybePrivate::new_private_verifiable(&mut rng, &seal_key, packet.clone()).unwrap()).unwrap();

        assert_eq!(ser::base64_encode(&ser1), "MB2gFgwUL3N0YW1wL25ldC92MS9wYWNrZXShAwIBRQ");
        assert_eq!(
            ser::base64_encode(&ser2),
            "MFGgHKAaBBhY2IluUNgNFIoGEzjuXmX76BZ7VZ_MsDShMQQv1za1Eg9_vjPPTG8VnKn6CO8rweNjF_VAXQOtKnIITr8McBxmC9NtbFhHeUbI9P4",
        );
        assert_eq!(ser::base64_encode(&ser3), "oB8wHaAWDBQvc3RhbXAvbmV0L3YxL3BhY2tldKEDAgFF");
        assert_eq!(
            ser::base64_encode(&ser4),
            "olMwUaAcoBoEGIdb1XYvWYqehYT1DQfbmT03ESR0qrnGFaExBC8UPoA1rhFm_zRT34Ma_9qbDAU_wldnTcguiO7P3rqzVZvMqx7xoRbdosU7NxxySw",
        );
        assert_eq!(ser::base64_encode(&ser5), "oYGoMIGloCSgIgQgFJlpF1hKHxgk1K4WnVjUFtItn7QXl6JBMwKB_jKDNkahfTB7oBygGgQYLHlQYq5zM4d-0_h990YsagfFsXkZdgVkoVsEWdtFv6e9kq89bwF0_3mRolmy6ym8eBmi_AfxNCJy7G5OCjYfyziRCZaI3GRmdPbEXxMVem0IUryTQsaWrakY6-AgQZ_fZ2WDzUsK0f76wjL7Kim28faJZpqC",);
    }
}
