use crate::error::Result;
use serde::{Serialize, de::DeserializeOwned};

pub(crate) fn serialize<T: Serialize>(obj: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    obj.serialize(&mut rmp_serde::Serializer::new(&mut buf).with_binary())?;
    Ok(buf)
}

pub(crate) fn serialize_human<T: Serialize>(obj: &T) -> Result<String> {
    Ok(serde_yaml::to_string(obj)?)
}

pub(crate) fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let obj = T::deserialize(&mut rmp_serde::Deserializer::new(bytes).with_binary())?;
    //let obj = rmp_serde::from_read(bytes)?;
    Ok(obj)
}

pub(crate) fn deserialize_human<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(serde_yaml::from_slice(bytes)?)
}

// NOTE to self (ie, serializer.is_human_readable())
// https://github.com/serde-rs/json/issues/360#issuecomment-353752998
// https://docs.serde.rs/serde/trait.Serializer.html#method.is_human_readable

pub trait TryFromSlice {
    type Item;
    fn try_from_slice(slice: &[u8]) -> std::result::Result<Self::Item, ()>;
}

macro_rules! impl_try_from_slice {
    ($class:ty) => {
        impl TryFromSlice for $class {
            type Item = $class;
            fn try_from_slice(slice: &[u8]) -> std::result::Result<Self::Item, ()> {
                Self::from_slice(slice).ok_or(())
            }
        }
    }
}

pub(crate) mod base64_bytes {
    use serde::{Serializer, de, Deserialize, Deserializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&base64::display::Base64Display::with_config(bytes.as_ref(), base64::STANDARD))
        } else {
            //serde_bytes::serialize(bytes, serializer)
            serializer.serialize_bytes(bytes.as_ref())
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <String>::deserialize(deserializer)?;
            base64::decode_config(s, base64::STANDARD).map_err(de::Error::custom)
        } else {
            serde_bytes::deserialize(deserializer)
            //let slice = <Vec<u8>>::deserialize(deserializer)?;
            //Ok(Vec::from(slice))
        }
    }
}

pub(crate) mod base64_binary_from_slice {
    use super::TryFromSlice;
    use serde::{Serializer, de, Deserialize, Deserializer};

    pub fn serialize<S, T>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
              T: AsRef<[u8]>,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&base64::encode_config(bytes.as_ref(), base64::STANDARD))
        } else {
            serializer.serialize_bytes(bytes.as_ref())
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where D: Deserializer<'de>,
              T: TryFromSlice + TryFromSlice<Item = T> + Deserialize<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <String>::deserialize(deserializer)?;
            let vec = base64::decode_config(s, base64::STANDARD).map_err(de::Error::custom)?;
            let val = T::try_from_slice(&vec[..]).map_err(|_| de::Error::custom(String::from("bad slice length")))?;
            Ok(val)
        } else {
            T::deserialize(deserializer)
        }
    }
}

pub(crate) mod timestamp {
    use serde::{Serialize, Serializer, Deserialize, Deserializer};

    pub fn serialize<S>(ts: &chrono::NaiveDateTime, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        if serializer.is_human_readable() {
            ts.serialize(serializer)
        } else {
            chrono::naive::serde::ts_nanoseconds::serialize(ts, serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<chrono::NaiveDateTime, D::Error>
        where D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            chrono::NaiveDateTime::deserialize(deserializer)
        } else {
            chrono::naive::serde::ts_nanoseconds::deserialize(deserializer)
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

