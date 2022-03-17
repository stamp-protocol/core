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
    let mut ser = rmp_serde::Serializer::new(&mut buf)
        .with_binary()
        .with_struct_tuple();
    obj.serialize(&mut ser)?;
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

macro_rules! base64_serde {
    ($ty:ident, $ser_trait:ident, $de_trait: ident, $ser_fn:ident, $de_fn:ident, $tmp_ty:ty) => {
        impl<T> serde::Serialize for $ty<T>
            where T: $ser_trait,
        {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
                where S: serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&crate::util::ser::base64_encode(&self.0.$ser_fn()[..]))
                } else {
                    (*self.0.$ser_fn()).serialize(serializer)
                }
            }
        }

        impl<'de, T> serde::Deserialize<'de> for $ty<T>
            where T: $de_trait
        {
            fn deserialize<D>(deserializer: D) -> std::result::Result<$ty<T>, D::Error>
                where D: serde::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    let s = <String>::deserialize(deserializer)?;
                    let tmp: $tmp_ty = crate::util::ser::base64_decode(s).map_err(serde::de::Error::custom)?
                        .try_into()
                        .map_err(|_| serde::de::Error::custom(String::from("bad slice length")))?;
                    Ok($ty(T::$de_fn(tmp)))
                } else {
                    let tmp = <$tmp_ty>::deserialize(deserializer)?;
                    Ok($ty(T::$de_fn(tmp)))
                }
            }
        }
    }
}

// TODO: remove this
// this is dumb and i hate it
macro_rules! define_byte_serializer {
    ($as_trait:ident, $from_trait:ident, $wrapper:ident, $sermod:ident, $num_bytes:expr) => {
        pub(crate) mod $sermod {
            use super::{$as_trait, $from_trait, base64_encode, base64_decode};
            use serde::{Serialize, Serializer, de, Deserialize, Deserializer};
            use std::convert::TryInto;

            pub fn serialize<S, T>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
                where S: Serializer,
                      T: $as_trait,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&base64_encode(&val.to_ser()[..]))
                } else {
                    (*val.to_ser()).serialize(serializer)
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
                    Ok(T::from_des(arr))
                } else {
                    let bytes = <[u8; $num_bytes]>::deserialize(deserializer)?;
                    Ok(T::from_des(bytes))
                }
            }
        }
    }
}

/// Assists in converting a type to a byte slice
pub trait AsByteSlice {
    /// Return the byte slice representaion of this object
    fn to_ser(&self) -> &[u8];
}

/// Assists in building a type from a byte slice
pub trait FromByteSlice {
    /// Build this object from a byte slice
    fn from_des(bytes: Vec<u8>) -> Self;
}

impl AsByteSlice for Vec<u8> {
    fn to_ser(&self) -> &[u8] { self.as_slice() }
}

impl FromByteSlice for Vec<u8> {
    fn from_des(bytes: Vec<u8>) -> Self {
        bytes
    }
}

macro_rules! define_base64_type {
    ($name:ident, $ty:ty, $as_trait:ident, $from_trait:ident) => {
        pub struct $name<T>(pub(crate) T);
        standard_impls! { $name }
        base64_serde! { $name, $as_trait, $from_trait, to_ser, from_des, $ty }
    }
}

/// Assists in converting a type to a byte array
pub trait AsByteArray32 {
    /// Return the byte array representation of this object
    fn to_ser(&self) -> &[u8; 32];
}
/// Assists in building a type from a byte array
pub trait FromByteArray32 {
    /// Build this object from a byte array
    fn from_des(bytes: [u8; 32]) -> Self;
}

impl AsByteArray32 for [u8; 32] {
    fn to_ser(&self) -> &[u8; 32] { &self }
}

impl FromByteArray32 for [u8; 32] {
    fn from_des(bytes: [u8; 32]) -> Self {
        bytes
    }
}

define_byte_serializer! { AsByteArray32, FromByteArray32, Bytes32, human_bytes32, 32 }

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn to_val<T: Serialize + DeserializeOwned>(obj: &T) -> std::result::Result<rmpv::Value, ()> {
    let ser = serialize(obj).map_err(|_| ())?;
    rmpv::decode::value::read_value(&mut &ser[..])
        .map_err(|_| ())
}

