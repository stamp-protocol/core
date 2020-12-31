use crate::error::Result;
use serde::{Serialize, de::DeserializeOwned};

pub(crate) fn serialize<T: Serialize>(obj: &T) -> Result<Vec<u8>> {
    let ser = rmp_serde::to_vec(obj)?;
    Ok(ser)
}

pub(crate) fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let obj = rmp_serde::from_read(bytes)?;
    Ok(obj)
}

// NOTE to self (ie, serializer.is_human_readable())
// https://github.com/serde-rs/json/issues/360#issuecomment-353752998
// https://docs.serde.rs/serde/trait.Serializer.html#method.is_human_readable

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn to_val<T: Serialize + DeserializeOwned>(obj: &T) -> std::result::Result<rmpv::Value, ()> {
    let ser = serialize(obj).map_err(|_| ())?;
    rmpv::decode::value::read_value(&mut &ser[..])
        .map_err(|_| ())
}

