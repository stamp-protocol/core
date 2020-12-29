use crate::error::Result;
use serde::{Serialize, de::DeserializeOwned};

pub(crate) fn serialize_raw<T: Serialize>(obj: &T) -> Result<Vec<u8>> {
    let ser = rmp_serde::to_vec(obj)?;
    Ok(ser)
}

pub(crate) fn deserialize_raw<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let obj = rmp_serde::from_read(bytes)?;
    Ok(obj)
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn to_val<T: Serialize + DeserializeOwned>(obj: &T) -> std::result::Result<rmpv::Value, ()> {
    let ser = serialize_raw(obj).map_err(|_| ())?;
    rmpv::decode::value::read_value(&mut &ser[..])
        .map_err(|_| ())
}

