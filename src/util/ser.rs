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

pub trait TryFromSlice {
    type Item;
    fn try_from_slice(slice: &[u8]) -> std::result::Result<Self::Item, ()>;
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

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn to_val<T: Serialize + DeserializeOwned>(obj: &T) -> std::result::Result<rmpv::Value, ()> {
    let ser = serialize(obj).map_err(|_| ())?;
    rmpv::decode::value::read_value(&mut &ser[..])
        .map_err(|_| ())
}

