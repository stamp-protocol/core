use crate::{
    error::{Error, Result},
    key::{SecretKey, SecretKeyNonce},
    util::ser,
};
use serde_derive::{Serialize, Deserialize};
use std::marker::PhantomData;

/// Holds private data, which can only be opened if you have the special key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Private<T> {
    #[serde(skip)]
    _phantom: PhantomData<T>,
    #[serde(with = "crate::util::ser::human_bytes")]
    sealed: Vec<u8>,
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
    pub fn open(&self, open_key: &SecretKey) -> Result<T> {
        let open_bytes = open_key.open(&self.sealed, &self.nonce)
            .map_err(|_| Error::CryptoOpenFailed)?;
        let obj: T = ser::deserialize(&open_bytes[..])?;
        Ok(obj)
    }
}

/// A wrapper that contains either public/plaintext data of type T or encrypted
/// data, which can be deserialized to T.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaybePrivate<T> {
    /// Any publicly-viewable data
    Public(T),
    /// Secret data, which can only be opened with the corresponding decryption
    /// key. Not always available, so check if this object has data via
    /// <MaybePrivate::has_data()>
    Private(Option<Private<T>>),
}

impl<T: serde::Serialize + serde::de::DeserializeOwned + Clone> MaybePrivate<T> {
    /// Determines if this container has any data at all.
    ///
    /// If deserializing from a public identity representation, it's quite
    /// possible that the private data has been stripped out, so this function
    /// lets us check if it exists before we go stampeding toward grabbing the
    /// value.
    pub fn has_data(&self) -> bool {
        match self {
            MaybePrivate::Public(_) => true,
            MaybePrivate::Private(prv) => prv.is_some(),
        }
    }

    /// Open this MaybePrivate container to access the data within (if it even
    /// has data).
    pub fn open(&self, open_key: &SecretKey) -> Result<T> {
        match self {
            MaybePrivate::Public(x) => Ok(x.clone()),
            MaybePrivate::Private(Some(prv)) => prv.open(open_key),
            MaybePrivate::Private(None) => Err(Error::PrivateDataMissing)?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private() {
        let key = SecretKey::new_xsalsa20poly1305();
        let sealed: Private<String> = Private::seal(&key, &String::from("get a job")).unwrap();
        let opened: String = sealed.open(&key).unwrap();
        assert_eq!(&opened, "get a job");
    }

    #[test]
    fn maybe_private() {
        let key = SecretKey::new_xsalsa20poly1305();
        let mut fake_key = SecretKey::new_xsalsa20poly1305();
        // fake_key can never == key. unfathomable, but possible.
        while key == fake_key { fake_key = SecretKey::new_xsalsa20poly1305(); }

        let maybe1: MaybePrivate<String> = MaybePrivate::Public(String::from("hello"));
        let maybe2: MaybePrivate<String> = MaybePrivate::Private(Some(Private::seal(&key, &String::from("omg")).unwrap()));
        let maybe3: MaybePrivate<String> = MaybePrivate::Private(None);

        assert_eq!(maybe1.open(&key).unwrap(), String::from("hello"));
        // fake key can open public data, nobody cares
        assert_eq!(maybe1.open(&fake_key).unwrap(), String::from("hello"));
        assert_eq!(maybe1.has_data(), true);

        assert_eq!(maybe2.open(&key), Ok(String::from("omg")));
        // fake key cannot open 
        assert_eq!(maybe2.open(&fake_key), Err(Error::CryptoOpenFailed));
        assert_eq!(maybe2.has_data(), true);

        assert_eq!(maybe3.open(&key), Err(Error::PrivateDataMissing));
        assert_eq!(maybe3.open(&fake_key), Err(Error::PrivateDataMissing));
        assert_eq!(maybe3.has_data(), false);
    }
}

