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
    util::{ser, Public},
};
use rand::{CryptoRng, RngCore};
use rasn::{
    types::{
        fields::{Field, Fields},
        Class, Constructed,
    },
    AsnType, Decode, Decoder, Encode, Encoder, Tag,
};
use serde_derive::{Deserialize, Serialize};
use std::marker::PhantomData;

/// Holds private data, which can only be opened if you have the special key.
#[derive(Debug, Serialize, Deserialize)]
pub struct Private<T> {
    /// Allows us to cast this container to T without this container ever
    /// actually storing any T value (because it's encrypted).
    #[serde(skip)]
    _phantom: PhantomData<T>,
    /// The encrypted data stored in this container, created using a
    /// `PrivateVerifiableInner` struct (the actual data alongside an HMAC key).
    sealed: Sealed,
}

impl<T> AsnType for Private<T> {
    const TAG: rasn::Tag = rasn::Tag::SEQUENCE;
}

impl<T> Constructed for Private<T> {
    const FIELDS: Fields = Fields::from_static(&[Field::new_required(Sealed::TAG, Sealed::TAG_TREE, "sealed")]);
}

impl<T: AsnType> Encode for Private<T> {
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
    ) -> std::result::Result<(), E::Error> {
        encoder.encode_sequence::<Self, _>(tag, |encoder| {
            self.sealed
                .encode_with_tag_and_constraints(encoder, Tag::new(Class::Context, 0), constraints)?;
            Ok(())
        })?;
        Ok(())
    }
}

impl<T: AsnType> Decode for Private<T> {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
    ) -> std::result::Result<Self, D::Error> {
        decoder.decode_sequence(tag, None::<fn() -> Self>, |decoder| {
            let sealed = Sealed::decode_with_tag_and_constraints(decoder, Tag::new(Class::Context, 0), constraints)?;
            Ok(Self {
                _phantom: PhantomData,
                sealed,
            })
        })
    }
}

impl<T> Clone for Private<T> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
            sealed: self.sealed.clone(),
        }
    }
}

impl<T: Encode + Decode> Private<T> {
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

    /// Re-encrypt the contained secret value with a new key.
    pub fn reencrypt<R: RngCore + CryptoRng>(self, rng: &mut R, previous_seal_key: &SecretKey, new_seal_key: &SecretKey) -> Result<Self> {
        let serialized = previous_seal_key.open(&self.sealed).map_err(|_| Error::CryptoOpenFailed)?;
        let sealed = new_seal_key.seal(rng, &serialized)?;
        Ok(Self {
            _phantom: PhantomData,
            sealed,
        })
    }
}

/// Holds the inner data for a `SealedTyped` container.
///
/// This is a somewhat ephemeral container, mainly used for encryption and
/// decryption and then thrown away.
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize)]
struct SealedTypedInner<T> {
    /// The value we're storing.
    #[rasn(tag(explicit(0)))]
    value: T,
    /// The HMAC key we use to hash the data.
    #[rasn(tag(explicit(1)))]
    hmac_key: HmacKey,
}

/// A way to attach a type to a [`Sealed`] container, and also adds some utilities around storing
/// a secret value alongside the HMAC key used to create the HMAC for that value which can be
/// verified by others.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SealedTyped<T> {
    /// Allows us to cast this container to T without this container ever
    /// actually storing any T value (because it's encrypted).
    #[serde(skip)]
    _phantom: PhantomData<T>,
    /// The encrypted data stored in this container, created using a
    /// `SealedTypedInner` struct (the actual data alongside an HMAC key).
    sealed: Sealed,
}

impl<T> AsnType for SealedTyped<T> {
    const TAG: rasn::Tag = rasn::Tag::SEQUENCE;
}

impl<T> Constructed for SealedTyped<T> {
    const FIELDS: Fields = Fields::from_static(&[Field::new_required(Sealed::TAG, Sealed::TAG_TREE, "sealed")]);
}

impl<T: AsnType> Encode for SealedTyped<T> {
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
    ) -> std::result::Result<(), E::Error> {
        encoder.encode_sequence::<Self, _>(tag, |encoder| {
            self.sealed
                .encode_with_tag_and_constraints(encoder, Tag::new(Class::Context, 0), constraints)?;
            Ok(())
        })?;
        Ok(())
    }
}

impl<T: AsnType> Decode for SealedTyped<T> {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
    ) -> std::result::Result<Self, D::Error> {
        decoder.decode_sequence(tag, None::<fn() -> Self>, |decoder| {
            let sealed = Sealed::decode_with_tag_and_constraints(decoder, Tag::new(Class::Context, 0), constraints)?;
            Ok(Self {
                _phantom: PhantomData,
                sealed,
            })
        })
    }
}

impl<T: Encode + Decode> SealedTyped<T> {
    /// Create a new verifiable private container from a given serializable data
    /// object and an encrypting key.
    ///
    /// We generate a random HMAC key and do two things:
    ///
    /// 1. HMAC the data being stored with the HMAC key, then store the data and
    ///    the HMAC key together in a `SealedTypedInner` container before
    ///    encrypting the container.
    /// 2. Sign the generated HMAC with our private key, then throw away the
    ///    HMAC and *only store the signature*.
    ///
    /// Using this scheme, anybody who knows the stored secret can recreate the
    /// HMAC and thus verify the public signature on the secret. However, the
    /// signature itself reveals nothing about the secret data because the HMAC
    /// obscures the data behind an encrypted key.
    pub fn seal<R: RngCore + CryptoRng>(rng: &mut R, seal_key: &SecretKey, data: &T) -> Result<(Hmac, Self)> {
        // create a new random key and use it to HMAC our data
        let hmac_key = HmacKey::new_blake3(rng)?;
        let hmac = Hmac::new(&hmac_key, &ser::serialize(data)?)?;
        // store our data alongside our HMAC key, allowing anybody with access
        // to this container to regenerate the HMAC.
        let inner = SealedTypedInner { value: data, hmac_key };
        let serialized_inner = ser::serialize(&inner)?;
        // encrypt the data+hmac_key combo
        let sealed = seal_key.seal(rng, &serialized_inner)?;
        Ok((
            hmac,
            Self {
                _phantom: PhantomData,
                sealed,
            },
        ))
    }

    /// Open and return the secret stored in this container, provided that the
    /// HMAC stored with this secret is the same as the one we generate when we
    /// HMAC the decrypted data with the decrypted HMAC key.
    ///
    /// If the data has been tampered with and the HMACs don't verify, then we
    /// return an error.
    pub fn open_and_verify(&self, seal_key: &SecretKey, hmac: &Hmac) -> Result<T> {
        // decrypt the secret value
        let open_bytes = seal_key.open(&self.sealed).map_err(|_| Error::CryptoOpenFailed)?;
        // deserialize our secret to give us the stored data and the HMAC key.
        let obj: SealedTypedInner<T> = ser::deserialize(&open_bytes[..])?;
        let SealedTypedInner { value, hmac_key } = obj;
        // verify our hmac against our decrypted data/hmac key
        hmac.verify(&hmac_key, &ser::serialize(&value)?)?;
        // success!
        Ok(value)
    }

    /// Re-encrypt the contained secret value with a new key.
    pub fn reencrypt<R: RngCore + CryptoRng>(self, rng: &mut R, previous_seal_key: &SecretKey, new_seal_key: &SecretKey) -> Result<Self> {
        let serialized = previous_seal_key.open(&self.sealed).map_err(|_| Error::CryptoOpenFailed)?;
        let sealed = new_seal_key.seal(rng, &serialized)?;
        Ok(Self {
            _phantom: PhantomData,
            sealed,
        })
    }
}

impl<T> Clone for SealedTyped<T> {
    fn clone(&self) -> Self {
        Self {
            _phantom: Default::default(),
            sealed: self.sealed.clone(),
        }
    }
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
#[derive(Debug, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct PrivateWithHmac<T> {
    /// Holds the HMAC for this private data so it can be verified without
    /// revealing the data itself
    #[rasn(tag(explicit(0)))]
    pub(crate) hmac: Hmac,
    /// The (encrypted) data AND HMAC key.
    #[rasn(tag(explicit(1)))]
    pub(crate) data: Option<SealedTyped<T>>,
}

impl<T> PrivateWithHmac<T> {
    /// Create a new private hmac container
    pub fn new(hmac: Hmac, data: Option<SealedTyped<T>>) -> Self {
        Self { hmac, data }
    }
}

impl<T: Encode + Decode> PrivateWithHmac<T> {
    /// Create a new `PrivateWithHmac` container around our data.
    pub fn seal<R: RngCore + CryptoRng>(rng: &mut R, seal_key: &SecretKey, val: T) -> Result<Self> {
        let (hmac, sealed_typed) = SealedTyped::seal(rng, seal_key, &val)?;
        Ok(Self {
            hmac,
            data: Some(sealed_typed),
        })
    }

    /// Unlock the data held within, and verify it against our heroic HMAC.
    pub fn open_and_verify(&self, seal_key: &SecretKey) -> Result<T> {
        match self.data() {
            Some(prv) => prv.open_and_verify(seal_key, self.hmac()),
            None => Err(Error::PrivateDataMissing)?,
        }
    }

    /// Reencrypt this PrivateWithHmac container with a new key.
    pub(crate) fn reencrypt<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        previous_seal_key: &SecretKey,
        new_seal_key: &SecretKey,
    ) -> Result<Self> {
        let res = match self {
            Self { hmac, data: Some(prv) } => Self {
                hmac,
                data: Some(prv.reencrypt(rng, previous_seal_key, new_seal_key)?),
            },
            Self { hmac, data: None } => Self { hmac, data: None },
        };
        Ok(res)
    }
}

impl<T> Public for PrivateWithHmac<T> {
    fn strip_private(&self) -> Self {
        Self {
            hmac: self.hmac().clone(),
            data: None,
        }
    }

    fn has_private(&self) -> bool {
        self.data().is_some()
    }
}

impl<T> PartialEq for PrivateWithHmac<T> {
    fn eq(&self, other: &Self) -> bool {
        self.hmac() == other.hmac()
    }
}

impl<T> Clone for PrivateWithHmac<T> {
    fn clone(&self) -> Self {
        Self {
            hmac: self.hmac.clone(),
            data: self.data.clone(),
        }
    }
}

/// A wrapper that contains either public/plaintext data of type T or encrypted
/// data, which can be deserialized to T.
#[derive(Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize)]
#[rasn(choice)]
pub enum MaybePrivate<T> {
    /// Any publicly-viewable data
    #[rasn(tag(explicit(0)))]
    Public(T),
    /// Secret data, which can only be opened with the corresponding decryption
    /// key, stored alongside an HMAC of the secret data which allows verification
    /// without data leakage.
    ///
    /// Make sure to check if this object has data via <MaybePrivate::has_data()>
    /// before trying to use it.
    #[rasn(tag(explicit(1)))]
    Private(PrivateWithHmac<T>),
}

impl<T: Encode + Decode + Clone> MaybePrivate<T> {
    /// Create a new public MaybePrivate value.
    pub fn new_public(val: T) -> Self {
        Self::Public(val)
    }

    /// Create a new private MaybePrivate value.
    pub fn new_private<R: RngCore + CryptoRng>(rng: &mut R, seal_key: &SecretKey, val: T) -> Result<Self> {
        let container = PrivateWithHmac::seal(rng, seal_key, val)?;
        Ok(Self::Private(container))
    }

    /// Get the HMAC for this MaybePrivate, if it has one.
    pub fn hmac(&self) -> Option<&Hmac> {
        match self {
            Self::Private(container) => Some(container.hmac()),
            _ => None,
        }
    }

    /// Determines if this container has any data at all.
    ///
    /// If deserializing from a public identity representation, it's quite
    /// possible that the private data has been stripped out, so this function
    /// lets us check if it exists before we go stampeding toward grabbing the
    /// value.
    pub fn has_data(&self) -> bool {
        match self {
            Self::Public(_) => true,
            Self::Private(container) => container.data().is_some(),
        }
    }

    /// Open this MaybePrivate container to access the data within (if it even
    /// has data).
    pub fn open(&self, seal_key: &SecretKey) -> Result<T> {
        match self {
            Self::Public(x) => Ok(x.clone()),
            Self::Private(container) => container.open_and_verify(seal_key),
        }
    }

    /// Get the data from this MaybePrivate if it is public
    pub fn open_public(&self) -> Option<T> {
        match self {
            Self::Public(x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Convert this MaybePrivate into a DefinitelyPublic.
    pub fn into_public(self, seal_key: &SecretKey) -> Result<Self> {
        match self {
            Self::Public(x) => Ok(Self::Public(x)),
            Self::Private(container) => {
                let unsealed = container.open_and_verify(seal_key)?;
                Ok(Self::Public(unsealed))
            }
        }
    }

    /// Reencrypt this MaybePrivate container with a new key.
    pub(crate) fn reencrypt<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        previous_seal_key: &SecretKey,
        new_seal_key: &SecretKey,
    ) -> Result<Self> {
        let maybe = match self {
            Self::Public(x) => Self::Public(x),
            Self::Private(container) => Self::Private(container.reencrypt(rng, previous_seal_key, new_seal_key)?),
        };
        Ok(maybe)
    }
}

impl<T: Clone> Public for MaybePrivate<T> {
    fn strip_private(&self) -> Self {
        match self {
            Self::Public(x) => Self::Public(x.clone()),
            Self::Private(PrivateWithHmac { hmac, .. }) => Self::Private(PrivateWithHmac::new(hmac.clone(), None)),
        }
    }

    fn has_private(&self) -> bool {
        matches!(self, Self::Private(PrivateWithHmac { data: Some(_), .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_seal_open() {
        let mut rng = crate::util::test::rng();
        let key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let sealed: Private<String> = Private::seal(&mut rng, &key, &String::from("get a job")).unwrap();
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
        let sealed: Private<String> = Private::seal(&mut rng, &key1, &String::from("get a job")).unwrap();
        let sealed2 = sealed.reencrypt(&mut rng, &key1, &key2).unwrap();
        let opened: String = sealed2.open(&key2).unwrap();
        assert_eq!(&opened, "get a job");
        let res: Result<String> = sealed2.open(&key1);
        assert_eq!(res, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn sealed_typed_seal_open() {
        let mut rng = crate::util::test::rng();
        let key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let (hmac, sealed) = SealedTyped::<String>::seal(&mut rng, &key, &String::from("get a job")).unwrap();
        let opened: String = sealed.open_and_verify(&key, &hmac).unwrap();
        assert_eq!(&opened, "get a job");
        let key2 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        assert!(key != key2);
        let res: Result<String> = sealed.open_and_verify(&key2, &hmac);
        assert_eq!(res, Err(Error::CryptoOpenFailed));
        let hmac2 = Hmac::new(&HmacKey::new_blake3(&mut rng).unwrap(), b"hello there").unwrap();
        assert!(hmac != hmac2);
        let res: Result<String> = sealed.open_and_verify(&key, &hmac2);
        assert_eq!(res, Err(Error::CryptoHmacVerificationFailed));
    }

    #[test]
    fn sealed_typed_reencrypt() {
        let mut rng = crate::util::test::rng();
        let key1 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let key2 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let (hmac, sealed) = SealedTyped::<String>::seal(&mut rng, &key1, &String::from("get a job")).unwrap();
        let sealed2 = sealed.reencrypt(&mut rng, &key1, &key2).unwrap();
        let opened: String = sealed2.open_and_verify(&key2, &hmac).unwrap();
        assert_eq!(&opened, "get a job");
        let res: Result<String> = sealed2.open_and_verify(&key1, &hmac);
        assert_eq!(res, Err(Error::CryptoOpenFailed));
    }

    #[test]
    fn maybe_private_has_private() {
        let mut rng = crate::util::test::rng();
        let seal_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let maybe1: MaybePrivate<String> = MaybePrivate::Public(String::from("hello"));
        let maybe2: MaybePrivate<String> = MaybePrivate::new_private(&mut rng, &seal_key, String::from("omg")).unwrap();
        let maybe3: MaybePrivate<String> = maybe2.strip_private();

        assert_eq!(maybe1.has_private(), false);
        assert_eq!(maybe2.has_private(), true);
        assert_eq!(maybe3.has_private(), false);
    }

    #[test]
    fn maybe_private_seal_open_verify_has_data() {
        let mut rng = crate::util::test::rng();
        let seal_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let mut fake_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        // fake_key can never == seal_key. unfathomable, but possible.
        while seal_key == fake_key {
            fake_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        }
        let fake_mac_key = HmacKey::new_blake3(&mut rng).unwrap();

        let maybe1: MaybePrivate<String> = MaybePrivate::Public(String::from("hello"));
        let maybe2: MaybePrivate<String> = MaybePrivate::new_private(&mut rng, &seal_key, String::from("omg")).unwrap();
        let maybe3: MaybePrivate<String> =
            MaybePrivate::Private(PrivateWithHmac::new(Hmac::new(&fake_mac_key, Vec::new().as_slice()).unwrap(), None));
        let maybe2_tampered = match maybe2.clone() {
            MaybePrivate::Private(PrivateWithHmac { data, .. }) => {
                MaybePrivate::Private(PrivateWithHmac::new(Hmac::new(&fake_mac_key, String::from("loool").as_bytes()).unwrap(), data))
            }
            _ => panic!("bad maybeprivate given"),
        };

        assert_eq!(maybe1.open(&seal_key).unwrap(), String::from("hello"));
        // fake key can open public data, nobody cares
        assert_eq!(maybe1.open(&fake_key).unwrap(), String::from("hello"));
        assert_eq!(maybe1.has_data(), true);

        assert_eq!(maybe2.open(&seal_key), Ok(String::from("omg")));
        assert_eq!(maybe2_tampered.open(&seal_key), Err(Error::CryptoHmacVerificationFailed));
        // fake key cannot open
        assert_eq!(maybe2.open(&fake_key), Err(Error::CryptoOpenFailed));
        assert_eq!(maybe2.has_data(), true);

        assert_eq!(maybe3.open(&seal_key), Err(Error::PrivateDataMissing));
        assert_eq!(maybe3.open(&fake_key), Err(Error::PrivateDataMissing));
        assert_eq!(maybe3.has_data(), false);
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

        let maybe1: MaybePrivate<String> = MaybePrivate::Public(String::from("hello"));
        let maybe2: MaybePrivate<String> = MaybePrivate::new_private(&mut rng, &seal_key, String::from("omg")).unwrap();
        let maybe3: MaybePrivate<String> =
            MaybePrivate::Private(PrivateWithHmac::new(Hmac::new(&fake_mac_key, Vec::new().as_slice()).unwrap(), None));

        assert_eq!(maybe1.open_public().unwrap(), "hello");
        assert_eq!(maybe2.open_public(), None);
        assert_eq!(maybe3.open_public(), None);
    }

    #[test]
    fn maybe_private_into_public() {
        let mut rng = crate::util::test::rng();
        let seal_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let fake_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        assert!(seal_key != fake_key);
        let fake_mac_key = HmacKey::new_blake3(&mut rng).unwrap();

        let maybe1: MaybePrivate<String> = MaybePrivate::Public(String::from("hello"));
        let maybe2: MaybePrivate<String> = MaybePrivate::new_private(&mut rng, &seal_key, String::from("omg")).unwrap();
        let maybe3: MaybePrivate<String> =
            MaybePrivate::Private(PrivateWithHmac::new(Hmac::new(&fake_mac_key, Vec::new().as_slice()).unwrap(), None));

        assert_eq!(maybe1.clone().into_public(&seal_key).unwrap(), MaybePrivate::Public(String::from("hello")));
        // fake key works too because who gives a crap if it's public. grind me
        // up into little bits and throw me in the river.
        assert_eq!(maybe1.clone().into_public(&fake_key).unwrap(), MaybePrivate::Public(String::from("hello")));
        assert_eq!(maybe2.clone().into_public(&seal_key).unwrap(), MaybePrivate::Public(String::from("omg")));
        assert_eq!(maybe2.clone().into_public(&fake_key), Err(Error::CryptoOpenFailed));
        assert_eq!(maybe3.clone().into_public(&seal_key), Err(Error::PrivateDataMissing));
        assert_eq!(maybe3.clone().into_public(&fake_key), Err(Error::PrivateDataMissing));
    }

    #[test]
    fn maybe_private_reencrypt_mac() {
        let mut rng = crate::util::test::rng();
        let seal_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let seal_key2 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();

        let maybe1: MaybePrivate<String> = MaybePrivate::Public(String::from("hello"));
        let maybe2: MaybePrivate<String> = MaybePrivate::new_private(&mut rng, &seal_key, String::from("omg")).unwrap();
        let maybe3: MaybePrivate<String> = maybe2.strip_private();

        let maybe1_2 = maybe1.clone().reencrypt(&mut rng, &seal_key, &seal_key2).unwrap();
        let maybe2_2 = maybe2.clone().reencrypt(&mut rng, &seal_key, &seal_key2).unwrap();
        let maybe3_2 = maybe3.clone().reencrypt(&mut rng, &seal_key, &seal_key2).unwrap();

        // should fail, kinda
        assert_eq!(maybe1_2.open(&seal_key), Ok(String::from("hello")));
        assert_eq!(maybe2_2.open(&seal_key), Err(Error::CryptoOpenFailed));
        assert_eq!(maybe3_2.open(&seal_key), Err(Error::PrivateDataMissing));

        // should work, mostly
        assert_eq!(maybe1_2.open(&seal_key2), Ok(String::from("hello")));
        assert_eq!(maybe2_2.open(&seal_key2), Ok(String::from("omg")));
        assert_eq!(maybe3_2.open(&seal_key2), Err(Error::PrivateDataMissing));

        // make sure the HMAC stays the same, if present
        assert_eq!(maybe1.hmac(), None);
        assert_eq!(maybe1_2.hmac(), None);
        assert_eq!(maybe2.hmac().unwrap(), maybe2_2.hmac().unwrap());
        assert_eq!(maybe3.hmac().unwrap(), maybe3_2.hmac().unwrap());
    }

    #[test]
    fn maybe_private_strip() {
        let mut rng = crate::util::test::rng();
        let seal_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let maybe: MaybePrivate<String> = MaybePrivate::new_private(&mut rng, &seal_key, String::from("omg")).unwrap();
        assert!(maybe.has_data());
        let maybe2 = maybe.strip_private();
        let hmac = match &maybe {
            MaybePrivate::Private(PrivateWithHmac { hmac, .. }) => hmac.clone(),
            _ => panic!("weird"),
        };
        assert_eq!(maybe2, MaybePrivate::Private(PrivateWithHmac { hmac, data: None }));
        assert!(!maybe2.has_data());
    }
}
