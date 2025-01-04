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
use base64::Engine as _;
use core::hash::Hash;
use rasn::{types::Tag, AsnType, Decode, Decoder, Encode, Encoder};
use serde::{
    de::{DeserializeOwned, Deserializer},
    ser::Serializer,
    Deserialize, Serialize,
};
use std::collections::{BTreeMap, HashMap};
use std::convert::From;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Serialize an object into binary.
pub(crate) fn serialize<T: Encode>(obj: &T) -> Result<Vec<u8>> {
    rasn::der::encode(obj).map_err(|_| Error::ASNSerialize)
}

/// Serialize an object into human-readable format.
pub(crate) fn serialize_text<T>(obj: &T) -> Result<String>
where
    T: Serialize + Public,
{
    let stripped: T = obj.strip_private();
    Ok(serde_yaml::to_string(&stripped)?)
}

#[cfg(feature = "yaml-export")]
pub fn text_export<T>(obj: &T) -> Result<String>
where
    T: Serialize,
{
    Ok(serde_yaml::to_string(&obj)?)
}

/// Deserialize an object from binary.
pub(crate) fn deserialize<T: Decode>(bytes: &[u8]) -> Result<T> {
    rasn::der::decode(bytes).map_err(|e| Error::ASNDeserialize(*e.kind))
}

/// Deserialize an object from human-readable format.
pub(crate) fn deserialize_text<T>(ser: &str) -> Result<T>
where
    T: DeserializeOwned + Public,
{
    Ok(serde_yaml::from_str(ser)?)
}

#[cfg(feature = "yaml-export")]
pub fn text_import<T>(ser: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    Ok(serde_yaml::from_str(&ser)?)
}

/// Convert bytes to base64
pub fn base64_encode<T: AsRef<[u8]>>(bytes: T) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_ref())
}

/// Convert base64 to bytes.
pub fn base64_decode<T: AsRef<[u8]>>(bytes: T) -> Result<Vec<u8>> {
    // annoying alloc, but seems necessary as the base64 crate doesn't ignore whitespace
    let mut filter_whitespace = Vec::from(bytes.as_ref());
    filter_whitespace.retain(|b| !b" \n\t\r\x0b\x0c".contains(b));
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&filter_whitespace[..])?)
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

impl<T> SerdeBinary for Vec<T> where T: SerdeBinary {}

/// Allows serializing to human readable format (but not deserializing). This is
/// generally used for things that we want to be able to display in human readable
/// format but aren't for consumption. If you want it consumable, use [SerdeBinary].
pub trait SerText: Serialize + Public + Sized {
    /// Serialize this object to human readable format
    fn serialize_text(&self) -> Result<String> {
        serialize_text(self)
    }
}

/// Allows deserializing a public object from human-readable format.
pub trait DeText: DeserializeOwned + Public + Sized {
    /// Deserialize this object from human readable format
    fn deserialize_text(ser: &str) -> Result<Self> {
        deserialize_text(ser)
    }
}

/// Implements ASN.1 encoding/decoding for a newtype with a slicable member
macro_rules! impl_asn1_binary {
    ($name:ident) => {
        impl<const N: usize> AsnType for $name<N> {
            const TAG: Tag = Tag::OCTET_STRING;
        }

        impl<const N: usize> Encode for $name<N> {
            fn encode_with_tag_and_constraints<E: Encoder>(
                &self,
                encoder: &mut E,
                tag: Tag,
                constraints: rasn::types::constraints::Constraints,
            ) -> std::result::Result<(), E::Error> {
                // Accepts a closure that encodes the contents of the sequence.
                encoder.encode_octet_string(tag, constraints, &self.0[..])?;
                Ok(())
            }
        }

        impl<const N: usize> Decode for $name<N> {
            fn decode_with_tag_and_constraints<D: Decoder>(
                decoder: &mut D,
                tag: Tag,
                constraints: rasn::types::constraints::Constraints,
            ) -> std::result::Result<Self, D::Error> {
                let vec = decoder.decode_octet_string(tag, constraints)?;
                let arr = vec
                    .try_into()
                    .map_err(|_| rasn::de::Error::no_valid_choice("octet string is incorrect length", rasn::Codec::Der))?;
                Ok(Self(arr))
            }
        }
    };
}

/// Defines a container for fixed-length binary data in octet form. Effectively
/// allows for strictly defining key/nonce/etc sizes and also allowing proper
/// serialization and deserialization.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Binary<const N: usize>([u8; N]);

impl<const N: usize> Binary<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl_asn1_binary! { Binary }

impl<const N: usize> Deref for Binary<N> {
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

impl<const N: usize> std::fmt::Debug for Binary<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", base64_encode(self.deref()))
    }
}

/// Defines a container for SECRET fixed-length binary data in octet form. This
/// is just like [Binary] except that it implements Zeroize and masks data from
/// Display/Debug.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct BinarySecret<const N: usize>([u8; N]);

impl<const N: usize> BinarySecret<N> {
    /// Create a new binary secret
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Grab the inner secret value.
    pub fn expose_secret(&self) -> &[u8; N] {
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

/// Defines a container for variable-length binary data in octet form.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BinaryVec(Vec<u8>);

impl From<Vec<u8>> for BinaryVec {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl From<BinaryVec> for Vec<u8> {
    fn from(binary: BinaryVec) -> Self {
        let BinaryVec(inner) = binary;
        inner
    }
}

impl Deref for BinaryVec {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
impl DerefMut for BinaryVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsnType for BinaryVec {
    const TAG: Tag = Tag::OCTET_STRING;
}

impl Encode for BinaryVec {
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
    ) -> std::result::Result<(), E::Error> {
        encoder.encode_octet_string(tag, constraints, &self.0[..])?;
        Ok(())
    }
}

impl Decode for BinaryVec {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
    ) -> std::result::Result<Self, D::Error> {
        let vec = decoder.decode_octet_string(tag, constraints)?;
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

impl std::fmt::Debug for BinaryVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", base64_encode(&self.deref()))
    }
}

/// A struct that represents a single entry in a key-value table.
///
/// Mainly useful for representing hash-table-esque data in places where hash
/// tables are not supported (*cough* ASN1).
#[derive(
    Debug, Clone, PartialEq, AsnType, Encode, Decode, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters,
)]
struct KeyValEntry<K, V> {
    /// The key
    #[rasn(tag(explicit(0)))]
    key: K,
    /// The value
    #[rasn(tag(explicit(1)))]
    val: V,
}

impl<K, V> KeyValEntry<K, V> {
    /// Quick onstructor for KeyValEntry
    pub fn new(key: K, val: V) -> Self {
        Self { key, val }
    }
}

/// Wraps a [BTreeMap] in a way that allows for ASN1 (de)serialization.
///
/// We use `BTreeMap` instead of `HashMap` because we require *stable sort*. Hash maps
/// can lose sorting, which means converting into them will often change the order of
/// the serialized components arbitrarily.
#[derive(Clone, Debug)]
pub struct HashMapAsn1<K, V>(BTreeMap<K, V>);

impl<K, V> Deref for HashMapAsn1<K, V> {
    type Target = BTreeMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> DerefMut for HashMapAsn1<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K, V> From<BTreeMap<K, V>> for HashMapAsn1<K, V> {
    fn from(map: BTreeMap<K, V>) -> Self {
        Self(map)
    }
}

impl<K: Ord, V> From<HashMap<K, V>> for HashMapAsn1<K, V> {
    fn from(map: HashMap<K, V>) -> Self {
        Self(map.into_iter().collect())
    }
}

impl<K: AsnType, V: AsnType> AsnType for HashMapAsn1<K, V> {
    const TAG: Tag = Tag::SEQUENCE;
}

impl<K: Encode, V: Encode> Encode for HashMapAsn1<K, V> {
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
    ) -> std::result::Result<(), E::Error> {
        let entries = self.iter().map(|(k, v)| KeyValEntry::new(k, v)).collect::<Vec<_>>();
        encoder.encode_sequence_of(tag, &entries[..], constraints)?;
        Ok(())
    }
}

impl<K: Decode + Ord, V: Decode> Decode for HashMapAsn1<K, V> {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: rasn::types::constraints::Constraints,
    ) -> std::result::Result<Self, D::Error> {
        let vec: Vec<KeyValEntry<K, V>> = decoder.decode_sequence_of(tag, constraints)?;
        let mut map = BTreeMap::new();
        for KeyValEntry { key, val } in vec {
            map.insert(key, val);
        }
        Ok(Self(map))
    }
}

impl<K: Serialize, V: Serialize> Serialize for HashMapAsn1<K, V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>> serde::Deserialize<'de> for HashMapAsn1<K, V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let map = BTreeMap::<K, V>::deserialize(deserializer)?;
        Ok(Self(map))
    }
}

impl<const N: usize> From<[(&[u8], &[u8]); N]> for HashMapAsn1<BinaryVec, BinaryVec> {
    fn from(map: [(&[u8], &[u8]); N]) -> Self {
        let mut hash = BTreeMap::new();
        for (key, val) in map.into_iter() {
            hash.insert(BinaryVec::from(Vec::from(key)), BinaryVec::from(Vec::from(val)));
        }
        Self(hash)
    }
}

impl<const N: usize> From<[(&str, &str); N]> for HashMapAsn1<BinaryVec, BinaryVec> {
    fn from(map: [(&str, &str); N]) -> Self {
        let mut hash = BTreeMap::new();
        for (key, val) in map.into_iter() {
            hash.insert(BinaryVec::from(Vec::from(key.as_bytes())), BinaryVec::from(Vec::from(val.as_bytes())));
        }
        Self(hash)
    }
}

/// Used to serialize timestamps in ISO format when human readable, but a
/// nanosecond timestamp when in binary (much smaller).
pub(crate) mod timestamp {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(ts: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            ts.serialize(serializer)
        } else {
            chrono::naive::serde::ts_nanoseconds::serialize(&ts.naive_utc(), serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            chrono::DateTime::deserialize(deserializer)
        } else {
            let naive = chrono::naive::serde::ts_nanoseconds::deserialize(deserializer)?;
            Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ser_newtype() {
        #[derive(Debug, PartialEq, rasn::AsnType, rasn::Encode, rasn::Decode)]
        #[rasn(delegate)]
        struct ID1(Binary<8>);

        #[derive(Debug, PartialEq, rasn::AsnType, rasn::Encode, rasn::Decode)]
        #[rasn(delegate)]
        struct ID3(ID1);

        #[derive(Clone, Debug, PartialEq, rasn::AsnType, rasn::Encode, rasn::Decode)]
        #[rasn(choice)]
        enum Choose {
            #[rasn(tag(explicit(0)))]
            Single(String),
        }

        #[derive(Debug, PartialEq, rasn::AsnType, rasn::Encode, rasn::Decode)]
        #[rasn(delegate)]
        struct ID4(Choose);

        #[derive(Debug, PartialEq, rasn::AsnType, rasn::Encode, rasn::Decode)]
        #[rasn(delegate)]
        struct ID5(ID4);

        let id1 = ID1(Binary::new([4; 8]));
        let id3 = ID3(ID1(Binary::new([4; 8])));

        let choice1 = Choose::Single("hello".to_string());
        let id4 = ID4(choice1.clone());
        let id5 = ID5(ID4(choice1.clone()));

        let ser_id1 = serialize(&id1).unwrap();
        let ser_id3 = serialize(&id3).unwrap();
        let ser_choice1 = serialize(&choice1).unwrap();
        let ser_id4 = serialize(&id4).unwrap();
        let ser_id5 = serialize(&id5).unwrap();

        assert_eq!(ser_id1, &[4, 8, 4, 4, 4, 4, 4, 4, 4, 4]);
        assert_eq!(ser_id3, &[4, 8, 4, 4, 4, 4, 4, 4, 4, 4]);
        assert_eq!(ser_choice1, &[160, 7, 12, 5, 104, 101, 108, 108, 111]);
        assert_eq!(ser_id4, &[160, 7, 12, 5, 104, 101, 108, 108, 111]);
        assert_eq!(ser_id5, &[160, 7, 12, 5, 104, 101, 108, 108, 111]);

        let id1_2: ID1 = deserialize(&ser_id1).unwrap();
        let id3_2: ID3 = deserialize(&ser_id3).unwrap();
        let choice1_2: Choose = deserialize(&ser_choice1).unwrap();
        let id4_2: ID4 = deserialize(&ser_id4).unwrap();
        let id5_2: ID5 = deserialize(&ser_id5).unwrap();

        assert_eq!(id1, id1_2);
        assert_eq!(id3, id3_2);
        assert_eq!(choice1, choice1_2);
        assert_eq!(id4, id4_2);
        assert_eq!(id5, id5_2);
    }

    #[test]
    fn ser_vec_enum_implicit_tag() {
        #[derive(Debug, Clone, AsnType, Encode, Decode)]
        #[rasn(choice)]
        pub enum MultisigPolicySignature {
            #[rasn(tag(0))]
            Key {
                #[rasn(tag(0))]
                key: String,
            },
        }

        let transactions1 = vec![MultisigPolicySignature::Key { key: String::from("key") }];

        let ser1 = rasn::der::encode(&transactions1).unwrap();
        let transactions1_2: Vec<MultisigPolicySignature> = rasn::der::decode(&ser1[..]).unwrap();
        assert_eq!(transactions1_2.len(), 1);
    }
}
