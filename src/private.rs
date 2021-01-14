//! The private module locks data away via a [SecretKey](crate::key::SecretKey)
//! while never storing or serializing or displaying the locked (private) data.
//! It can only be retrieved via the [open](crate::private::Private::open)
//! method, given the correct unlocking key.
//!
//! This allows for secure storage of things like private keys, or even claims
//! we wish to be verifyable but not publicly available.
//!
//! In this module is also the [MaybePrivate](crate::private::MaybePrivate)
//! container which gives us a choice to either make something public or to keep
//! it private and sealed away.

use crate::{
    error::{Error, Result},
    key::{SecretKey, SecretKeyNonce},
    util::ser,
};
use serde_derive::{Serialize, Deserialize};
use sodiumoxide::crypto::auth::hmacsha512;
use std::marker::PhantomData;

/// Holds private data, which can only be opened if you have the special key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Private<T> {
    /// Allows us to cast this container to T without this container ever
    /// actually storing any T value (because it's encrypted).
    #[serde(skip)]
    _phantom: PhantomData<T>,
    /// The encrypted data stored in this container, created using a
    /// `PrivateVerifiableInner` struct (the actual data alongside an HMAC key).
    #[serde(with = "crate::util::ser::human_bytes")]
    sealed: Vec<u8>,
    /// A nonce used to decrypt our heroic data (given the correct secret key).
    nonce: SecretKeyNonce,
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> Private<T> {
    /// Create a new Private container from a given serializable data object and
    /// an encrypting key.
    pub fn seal(seal_key: &SecretKey, data: &T) -> Result<Self> {
        let serialized = ser::serialize(data)?;
        let nonce = seal_key.gen_nonce();
        let sealed = seal_key.seal(&serialized, &nonce)?;
        Ok(Self {
            _phantom: PhantomData,
            sealed,
            nonce,
        })
    }

    /// Open a Private container with a decrypting key.
    pub fn open(&self, seal_key: &SecretKey) -> Result<T> {
        let open_bytes = seal_key.open(&self.sealed, &self.nonce)
            .map_err(|_| Error::CryptoOpenFailed)?;
        let obj: T = ser::deserialize(&open_bytes[..])?;
        Ok(obj)
    }

    /// Re-encrypt the contained secret value with a new key.
    pub fn rekey(self, previous_seal_key: &SecretKey, new_seal_key: &SecretKey) -> Result<Self> {
        let serialized = previous_seal_key.open(&self.sealed, &self.nonce)
            .map_err(|_| Error::CryptoOpenFailed)?;
        let nonce = new_seal_key.gen_nonce();
        let sealed = new_seal_key.seal(&serialized, &nonce)?;
        Ok(Self {
            _phantom: PhantomData,
            sealed,
            nonce,
        })
    }
}

/// Holds the inner data for a `PrivateVerifiable` container.
///
/// This is a somewhat ephemeral container, mainly used for encryption and
/// decryption and then thrown away.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateVerifiableInner<T> {
    /// The value we're storing.
    value: T,
    /// The HMAC key we use to hash the data.
    hmac_key: hmacsha512::Key,
}

/// Holds private data such that
///
/// - The private data is stored alonside an HMAC key (both encrypted)
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivateVerifiable<T> {
    /// Allows us to cast this container to T without this container ever
    /// actually storing any T value (because it's encrypted).
    #[serde(skip)]
    _phantom: PhantomData<T>,
    /// The encrypted data stored in this container, created using a
    /// `PrivateVerifiableInner` struct (the actual data alongside an HMAC key).
    #[serde(with = "crate::util::ser::human_bytes")]
    sealed: Vec<u8>,
    /// A nonce used to decrypt our heroic data (given the correct secret key).
    nonce: SecretKeyNonce,
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> PrivateVerifiable<T> {
    /// Create a new verifiable private container from a given serializable data
    /// object and an encrypting key.
    ///
    /// We generate a random HMAC key and do two things:
    ///
    /// 1. HMAC the data being stored with the HMAC key, then store the data and
    ///    the HMAC key together in a `PrivateVerifiableInner` container before
    ///    encrypting the container.
    /// 2. Sign the generated HMAC with our private key, then throw away the
    ///    HMAC and *only store the signature*.
    ///
    /// Using this scheme, anybody who knows the stored secret can recreate the
    /// HMAC and thus verify the public signature on the secret. However, the
    /// signature itself reveals nothing about the secret data because the HMAC
    /// obscures the data behind an encrypted key.
    pub fn seal(seal_key: &SecretKey, data: &T) -> Result<(hmacsha512::Tag, Self)> {
        // create a new random key and use it to HMAC our data
        let hmac_key = hmacsha512::gen_key();
        let hmac = hmacsha512::authenticate(&ser::serialize(data)?, &hmac_key);
        // store our data alongside our HMAC key, allowing anybody with access
        // to this container to regenerate the HMAC.
        let inner = PrivateVerifiableInner { value: data, hmac_key: hmac_key };
        let serialized_inner = ser::serialize(&inner)?;
        let nonce = seal_key.gen_nonce();
        // encrypt the data+hmac_key combo
        let sealed = seal_key.seal(&serialized_inner, &nonce)?;
        Ok((hmac, Self {
            _phantom: PhantomData,
            sealed,
            nonce,
        }))
    }

    /// Open and return the secret stored in this container, provided that the
    /// HMAC stored with this secret is the same as the one we generate when we
    /// HMAC the decrypted data with the decrypted HMAC key.
    ///
    /// If the data has been tampered with and the HMACs don't verify, then we
    /// return an error.
    pub fn open_and_verify(&self, seal_key: &SecretKey, hmac: &hmacsha512::Tag) -> Result<T> {
        // decrypt the secret value
        let open_bytes = seal_key.open(&self.sealed, &self.nonce)
            .map_err(|_| Error::CryptoOpenFailed)?;
        // deserialize our secret to give us the stored data and the HMAC key.
        let obj: PrivateVerifiableInner<T> = ser::deserialize(&open_bytes[..])?;
        let PrivateVerifiableInner { value, hmac_key } = obj;
        // verify our hmac against our decrypted data/hmac key
        if !hmacsha512::verify(hmac, &ser::serialize(&value)?, &hmac_key) {
            // the data has been tampered with, my friend.
            Err(Error::CryptoHmacVerificationFailed)?;
        }
        // success!
        Ok(value)
    }
}

/// A wrapper that contains either public/plaintext data of type T or encrypted
/// data, which can be deserialized to T.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MaybePrivate<T> {
    /// Any publicly-viewable data
    Public(T),
    /// Secret data, which can only be opened with the corresponding decryption
    /// key, stored alongside a public signature of an HMAC of the secret data.
    ///
    /// Make sure to check if this object has data via <MaybePrivate::has_data()>
    /// before trying to use it.
    Private(hmacsha512::Tag, Option<PrivateVerifiable<T>>),
}

impl<T: serde::Serialize + serde::de::DeserializeOwned + Clone> MaybePrivate<T> {
    /// Create a new public MaybePrivate value.
    pub fn new_public(val: T) -> Self {
        MaybePrivate::Public(val)
    }

    /// Create a new private MaybePrivate value.
    pub fn new_private(seal_key: &SecretKey, val: T) -> Result<Self> {
        let (hmac, private_verifiable) = PrivateVerifiable::seal(seal_key, &val)?;
        Ok(MaybePrivate::Private(hmac, Some(private_verifiable)))
    }

    /// Determines if this container has any data at all.
    ///
    /// If deserializing from a public identity representation, it's quite
    /// possible that the private data has been stripped out, so this function
    /// lets us check if it exists before we go stampeding toward grabbing the
    /// value.
    pub fn has_data(&self) -> bool {
        match self {
            MaybePrivate::Public(_) => true,
            MaybePrivate::Private(_, prv) => prv.is_some(),
        }
    }

    /// Open this MaybePrivate container to access the data within (if it even
    /// has data).
    pub fn open(&self, seal_key: &SecretKey) -> Result<T> {
        match self {
            MaybePrivate::Public(x) => Ok(x.clone()),
            MaybePrivate::Private(ref signature, Some(prv)) => prv.open_and_verify(seal_key, signature),
            MaybePrivate::Private(_, None) => Err(Error::PrivateDataMissing)?,
        }
    }

    /// Strip all private data from this `MaybePrivate`.
    pub(crate) fn strip_private(&self) -> Self {
        match self {
            Self::Public(x) => Self::Public(x.clone()),
            Self::Private(sig, _) => Self::Private(sig.clone(), None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_seal_open() {
        let key = SecretKey::new_xsalsa20poly1305();
        let sealed: Private<String> = Private::seal(&key, &String::from("get a job")).unwrap();
        let opened: String = sealed.open(&key).unwrap();
        assert_eq!(&opened, "get a job");
    }

    #[test]
    fn maybe_private_seal_open_verify() {
        let seal_key = SecretKey::new_xsalsa20poly1305();
        let mut fake_key = SecretKey::new_xsalsa20poly1305();
        // fake_key can never == seal_key. unfathomable, but possible.
        while seal_key == fake_key { fake_key = SecretKey::new_xsalsa20poly1305(); }
        let fake_hmac_key = hmacsha512::gen_key();

        let maybe1: MaybePrivate<String> = MaybePrivate::Public(String::from("hello"));
        let maybe2: MaybePrivate<String> = MaybePrivate::new_private(&seal_key, String::from("omg")).unwrap();
        let maybe3: MaybePrivate<String> = MaybePrivate::Private(hmacsha512::authenticate(Vec::new().as_slice(), &fake_hmac_key), None);
        let maybe2_tampered = match maybe2.clone() {
            MaybePrivate::Private(_, data) => MaybePrivate::Private(hmacsha512::authenticate(String::from("loool").as_bytes(), &fake_hmac_key), data),
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
    fn maybe_private_strip() {
        let seal_key = SecretKey::new_xsalsa20poly1305();
        let maybe: MaybePrivate<String> = MaybePrivate::new_private(&seal_key, String::from("omg")).unwrap();
        assert!(maybe.has_data());
        let maybe2 = maybe.strip_private();
        let hmac = match &maybe {
            MaybePrivate::Private(hmac, _) => hmac.clone(),
            _ => panic!("weird"),
        };
        assert_eq!(maybe2, MaybePrivate::Private(hmac, None));
        assert!(!maybe2.has_data());
    }
}

