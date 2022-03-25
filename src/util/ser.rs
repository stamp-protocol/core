//! Helpful serialization tools.
//!
//! Helpful for our contexts, anyway. Probably really annoying for deserializing
//! if you're not using this library (or rust in general). But since there are
//! no serialization formats what provide a human-readable format but that can
//! also represent binary data either via hexadecimal or base64 THAT ARE ALSO
//! readily supported by rust, we kind of have to take things into our own hands
//! here and just make some serialization calls.

use crate::{
    error::{Error, Result},
    util::Public,
};
use rasn::{AsnType, Encode, Encoder, Decode, Decoder, Tag};
use serde::{Serialize, ser::Serializer, de::DeserializeOwned, de::Deserializer};
use zeroize::Zeroize;

pub(crate) fn serialize<T: Encode>(obj: &T) -> Result<Vec<u8>> {
    Ok(rasn::der::encode(obj).map_err(|_| Error::SerializeASN)?)
}

pub(crate) fn serialize_human<T>(obj: &T) -> Result<String>
    where T: Serialize + Public
{
    Ok(serde_yaml::to_string(&obj.strip_private())?)
}

pub(crate) fn deserialize<T: Decode>(bytes: &[u8]) -> Result<T> {
    Ok(rasn::der::decode(bytes).map_err(|_| Error::DeserializeASN)?)
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
pub trait SerdeBinary: Encode + Decode {
    /// Serialize this message
    fn serialize_binary(&self) -> Result<Vec<u8>> {
        serialize(self)
    }

    /// Deserialize this message
    fn deserialize_binary(slice: &[u8]) -> Result<Self> {
        deserialize(slice)
    }
}

/// Implements ASN.1 encoding/decoding for a newtype with a slicable member
macro_rules! impl_asn1_binary {
    ($name:ident) => {
        impl<const N: usize> AsnType for $name<N> {
            const TAG: Tag = Tag::OCTET_STRING;
        }

        impl<const N: usize> Encode for $name<N> {
            fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> std::result::Result<(), E::Error> {
                // Accepts a closure that encodes the contents of the sequence.
                encoder.encode_octet_string(tag, &self.0[..])?;
                Ok(())
            }
        }

        impl<const N: usize> Decode for $name<N> {
            fn decode_with_tag<D: Decoder>(decoder: &mut D, tag: Tag) -> std::result::Result<Self, D::Error> {
                let vec = decoder.decode_octet_string(tag)?;
                let arr = vec.try_into()
                    .map_err(|_| rasn::de::Error::no_valid_choice("octet string is incorrect length"))?;
                Ok(Self(arr))
            }
        }
    }
}

/// Defines a container for binary data in octet form. Effectively allows for
/// strictly defining key/nonce/etc sizes and also allowing proper serialization
/// and deserialization.
#[derive(Debug, Clone, PartialEq)]
pub struct Binary<const N: usize>([u8; N]);

impl<const N: usize> Binary<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl_asn1_binary! { Binary }

impl<const N: usize> std::ops::Deref for Binary<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> Serialize for Binary<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64_encode(&self.0[..]))
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for Binary<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = <String>::deserialize(deserializer)?;
        let tmp = base64_decode(s)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom(String::from("bad slice length")))?;
        Ok(Self(tmp))
    }
}

/// Defines a container for SECRET binary data in octet form. This is just like
/// [Binary] except that it implements Zeroize.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct BinarySecret<const N: usize>([u8; N]);

impl<const N: usize> BinarySecret<N> {
    /// Create a new binary secret
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Grab the inner secret value.
    pub fn expose_secret<'a>(&'a self) -> &'a [u8; N] {
        &self.0
    }
}

impl_asn1_binary! { BinarySecret }

impl<const N: usize> std::fmt::Display for BinarySecret<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<secret>")
    }
}

impl<const N: usize> std::fmt::Debug for BinarySecret<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<secret>")
    }
}

impl<const N: usize> Serialize for BinarySecret<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64_encode(&self.0[..]))
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for BinarySecret<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = <String>::deserialize(deserializer)?;
        let tmp = base64_decode(s)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom(String::from("bad slice length")))?;
        Ok(Self(tmp))
    }
}

/// Defines a container for binary data in octet form. Effectively allows for
/// strictly defining key/nonce/etc sizes and also allowing proper serialization
/// and deserialization.
#[derive(Debug, Clone, PartialEq)]
pub struct BinaryVec(Vec<u8>);

impl std::convert::From<Vec<u8>> for BinaryVec {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl std::convert::From<BinaryVec> for Vec<u8> {
    fn from(binary: BinaryVec) -> Self {
        let BinaryVec(inner) = binary;
        inner
    }
}

impl std::ops::Deref for BinaryVec {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[cfg(test)]
impl std::ops::DerefMut for BinaryVec {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl AsnType for BinaryVec {
    const TAG: Tag = Tag::OCTET_STRING;
}

impl Encode for BinaryVec {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> std::result::Result<(), E::Error> {
        // Accepts a closure that encodes the contents of the sequence.
        encoder.encode_octet_string(tag, &self.0[..])?;
        Ok(())
    }
}

impl Decode for BinaryVec {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, tag: Tag) -> std::result::Result<Self, D::Error> {
        let vec = decoder.decode_octet_string(tag)?;
        Ok(Self(vec))
    }
}

impl Serialize for BinaryVec {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64_encode(&self.0[..]))
    }
}

impl<'de> serde::Deserialize<'de> for BinaryVec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = <String>::deserialize(deserializer)?;
        let tmp = base64_decode(s).map_err(serde::de::Error::custom)?;
        Ok(Self(tmp))
    }
}

macro_rules! asn_encdec_newtype {
    ($name:ident, $inner:ty) => {
        impl rasn::AsnType for $name {
            const TAG: rasn::Tag = rasn::Tag::EOC;
        }

        impl rasn::Encode for $name {
            fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, _tag: rasn::Tag) -> std::result::Result<(), E::Error> {
                // Accepts a closure that encodes the contents of the sequence.
                self.0.encode(encoder)?;
                Ok(())
            }
        }

        impl rasn::Decode for $name {
            fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, _tag: rasn::Tag) -> std::result::Result<Self, D::Error> {
                let inner = <$inner>::decode(decoder)?;
                Ok(Self(inner))
            }
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

