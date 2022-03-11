//! Helpful serialization tools.
//!
//! Helpful for our contexts, anyway. Probably really annoying for deserializing
//! if you're not using this library (or rust in general). But since there are
//! no serialization formats what provide a human-readable format but that can
//! also represent binary data either via hexadecimal or base64 THAT ARE ALSO
//! readily supported by rust, we kind of have to take things into our own hands
//! here and just make some serialization calls.

use crate::{
    error::Result,
    util::Public,
};
use serde::{Serialize, de::DeserializeOwned};

pub(crate) fn serialize<T: Serialize>(obj: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    obj.serialize(&mut rmp_serde::Serializer::new(&mut buf).with_binary())?;
    Ok(buf)
}

pub(crate) fn serialize_human<T>(obj: &T) -> Result<String>
    where T: Serialize + Public
{
    Ok(serde_yaml::to_string(&obj.strip_private())?)
}

pub(crate) fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let obj = T::deserialize(&mut rmp_serde::Deserializer::new(bytes).with_binary())?;
    //let obj = rmp_serde::from_read(bytes)?;
    Ok(obj)
}

pub(crate) fn deserialize_human<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(serde_yaml::from_slice(bytes)?)
}

/// Convert bytes to base64
pub fn base64_encode<T: AsRef<[u8]>>(bytes: T) -> String {
    base64::encode_config(bytes.as_ref(), base64::URL_SAFE_NO_PAD)
}

pub fn base64_decode<T: AsRef<[u8]>>(bytes: T) -> Result<Vec<u8>> {
    Ok(base64::decode_config(bytes.as_ref(), base64::URL_SAFE_NO_PAD)?)
}

/// A default implementation for (de)serializing an object to or from binary
/// format.
pub trait SerdeBinary: Serialize + DeserializeOwned {
    /// Serialize this message
    fn serialize_binary(&self) -> Result<Vec<u8>> {
        serialize(self)
    }

    /// Deserialize this message
    fn deserialize_binary(slice: &[u8]) -> Result<Self> {
        deserialize(slice)
    }
}

pub trait TryFromSlice {
    type Item;
    fn try_from_slice(slice: &[u8]) -> std::result::Result<Self::Item, ()>;
}

macro_rules! impl_try_from_slice {
    ($class:ty, $slice:ident, $op:expr) => {
        impl TryFromSlice for $class {
            type Item = $class;
            fn try_from_slice($slice: &[u8]) -> std::result::Result<Self::Item, ()> {
                $op
            }
        }
    };

    ($class:ty) => {
        impl_try_from_slice! { $class, slice, Self::from_slice(slice).ok_or(()) }
    };
}

pub(crate) mod human_bytes {
    use super::{base64_encode, base64_decode};
    use serde::{Serializer, de, Deserialize, Deserializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&base64_encode(bytes.as_slice()))
        } else {
            serde_bytes::serialize(bytes, serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <String>::deserialize(deserializer)?;
            base64_decode(s).map_err(de::Error::custom)
        } else {
            serde_bytes::deserialize(deserializer)
        }
    }
}

pub(crate) mod human_binary_from_slice {
    use super::{TryFromSlice, base64_encode, base64_decode};
    use serde::{Serializer, de, Deserialize, Deserializer};

    pub fn serialize<S, T>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
              T: AsRef<[u8]> + serde::Serialize,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&base64_encode(bytes))
        } else {
            bytes.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where D: Deserializer<'de>,
              T: TryFromSlice + TryFromSlice<Item = T> + Deserialize<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <String>::deserialize(deserializer)?;
            let vec = base64_decode(s).map_err(de::Error::custom)?;
            let val = T::try_from_slice(&vec[..]).map_err(|_| de::Error::custom(String::from("bad slice length")))?;
            Ok(val)
        } else {
            T::deserialize(deserializer)
        }
    }
}

pub(crate) mod timestamp {
    use chrono::{DateTime, Utc};
    use serde::{Serialize, Serializer, Deserialize, Deserializer};

    pub fn serialize<S>(ts: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        if serializer.is_human_readable() {
            ts.serialize(serializer)
        } else {
            chrono::naive::serde::ts_nanoseconds::serialize(&ts.naive_utc(), serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
        where D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            chrono::DateTime::deserialize(deserializer)
        } else {
            let naive = chrono::naive::serde::ts_nanoseconds::deserialize(deserializer)?;
            Ok(DateTime::<Utc>::from_utc(naive, Utc))
        }
    }
}

macro_rules! standard_impls {
    ($struct:ident) => {
        impl<T> std::ops::Deref for $struct<T> {
            type Target = T;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<T> std::clone::Clone for $struct<T>
            where T: std::clone::Clone,
        {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl<T> std::cmp::PartialEq for $struct<T>
            where T: std::cmp::PartialEq,
        {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }
    }
}

macro_rules! define_byte_serializer {
    ($as_trait:ident, $from_trait:ident, $wrapper:ident, $sermod:ident, $num_bytes:expr) => {
        /// Assists in converting a type to a byte array
        pub trait $as_trait {
            /// Return the byte array representation of this object
            fn as_bytes(&self) -> &[u8; $num_bytes];
        }
        /// Assists in building a type from a byte array
        pub trait $from_trait {
            /// Build this object from a byte array
            fn from_bytes(bytes: [u8; $num_bytes]) -> Self;
        }

        pub(crate) mod $sermod {
            use super::{$as_trait, $from_trait, base64_encode, base64_decode};
            use serde::{Serialize, Serializer, de, Deserialize, Deserializer};
            use std::convert::TryInto;

            pub fn serialize<S, T>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
                where S: Serializer,
                      T: $as_trait,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&base64_encode(&val.as_bytes()[..]))
                } else {
                    (*val.as_bytes()).serialize(serializer)
                }
            }

            pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
                where D: Deserializer<'de>,
                      T: $from_trait,
            {
                if deserializer.is_human_readable() {
                    let s = <String>::deserialize(deserializer)?;
                    let vec = base64_decode(s).map_err(de::Error::custom)?;
                    let arr: [u8; $num_bytes] = vec.try_into().map_err(|_| de::Error::custom(String::from("bad slice length")))?;
                    Ok(T::from_bytes(arr))
                } else {
                    let bytes = <[u8; $num_bytes]>::deserialize(deserializer)?;
                    Ok(T::from_bytes(bytes))
                }
            }
        }

        #[derive(Debug)]
        #[allow(dead_code)]
        pub struct $wrapper<T>(pub(crate) T);

        standard_impls! { $wrapper }

        impl<T> serde::Serialize for $wrapper<T>
            where T: $as_trait,
        {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
                where S: serde::Serializer,
            {
                self.0.as_bytes().serialize(serializer)
            }
        }

        impl<'de, T> serde::Deserialize<'de> for $wrapper<T>
            where T: $from_trait
        {
            fn deserialize<D>(deserializer: D) -> std::result::Result<$wrapper<T>, D::Error>
                where D: serde::Deserializer<'de>,
            {
                let bytes = <[u8; $num_bytes]>::deserialize(deserializer)?;
                Ok($wrapper(T::from_bytes(bytes)))
            }
        }
    }
}

define_byte_serializer! { AsBytes32, FromBytes32, Bytes32, human_bytes32, 32 }

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn to_val<T: Serialize + DeserializeOwned>(obj: &T) -> std::result::Result<rmpv::Value, ()> {
    let ser = serialize(obj).map_err(|_| ())?;
    rmpv::decode::value::read_value(&mut &ser[..])
        .map_err(|_| ())
}

