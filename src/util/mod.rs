//! Utilities. OBVIOUSLY.

use blake2::Digest;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc, Local, TimeZone};
use crate::{
    error::Result,
};
use rasn::{AsnType, Encode, Encoder, Decode, Decoder, Tag};
use serde_derive::{Serialize, Deserialize};
use std::ops::Deref;
use std::str::FromStr;

#[macro_use]
pub(crate) mod ser;
pub(crate) mod sign;
#[cfg(test)]
pub(crate) mod test;

pub use ser::{base64_encode, base64_decode, SerdeBinary, Binary};

macro_rules! object_id {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        #[derive(Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
        $(#[$meta])*
        pub struct $name(pub(crate) crate::crypto::key::SignKeypairSignature);

        asn_encdec_newtype! { $name, crate::crypto::key::SignKeypairSignature }

        impl $name {
            /// Take a full string id and return the shortened ID
            pub fn short(full_id: &str) -> String {
                String::from(&full_id[0..16])
            }
        }

        #[cfg(test)]
        #[allow(dead_code)]
        impl $name {
            pub(crate) fn blank() -> Self {
                let sigbytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
                let sig = crate::crypto::key::SignKeypairSignature::Ed25519(crate::util::ser::Binary::new(sigbytes));
                $name(sig)
            }

            pub(crate) fn random() -> Self {
                let mut sigbytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
                rand::rngs::OsRng.fill_bytes(&mut sigbytes);
                sigbytes[ed25519_dalek::SIGNATURE_LENGTH - 1] = 0;
                let sig = crate::crypto::key::SignKeypairSignature::Ed25519(crate::util::ser::Binary::new(sigbytes));
                $name(sig)
            }
        }

        impl Deref for $name {
            type Target = crate::crypto::key::SignKeypairSignature;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::convert::From<crate::crypto::key::SignKeypairSignature> for $name {
            fn from(sig: crate::crypto::key::SignKeypairSignature) -> Self {
                Self(sig)
            }
        }

        impl std::convert::From<&$name> for String {
            fn from(id: &$name) -> String {
                let ser_val: u8 = match &id.0 {
                    crate::crypto::key::SignKeypairSignature::Ed25519(_) => 0,
                };
                let mut bytes = Vec::from(id.as_ref());
                bytes.push(ser_val);
                crate::util::ser::base64_encode(&bytes)
            }
        }

        impl std::convert::TryFrom<&str> for $name {
            type Error = crate::error::Error;
            fn try_from(id_str: &str) -> std::result::Result<Self, Self::Error> {
                let mut bytes = crate::util::ser::base64_decode(id_str.as_bytes())?;
                let ser_val = bytes.pop().ok_or(crate::error::Error::SignatureMissing)?;
                let id_sig = match ser_val {
                    _ => {
                        let bytes_arr: [u8; ed25519_dalek::SIGNATURE_LENGTH] = bytes.try_into()
                            .map_err(|_| crate::error::Error::BadLength)?;
                        let sig = ed25519_dalek::Signature::from(bytes_arr);
                        crate::crypto::key::SignKeypairSignature::Ed25519(crate::util::ser::Binary::new(sig.to_bytes()))
                    }
                };
                Ok(Self(id_sig))
            }
        }
    }
}

/// Hash arbitrary data using blake2b
pub fn hash(data: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = blake2::Blake2b512::new();
    hasher.update(data);
    let genarr = hasher.finalize();
    Ok(Vec::from(genarr.as_slice()))
}

/// A library-local representation of a time. I can hear you groaning already:
/// "Oh my god, why make a custom date/time object?!" Yes, I was once just like
/// you...young, and foolish. But hear me out:
///
/// - We want to the the Right Thing when serializing, and this is often much
/// easier with a wrapper type.
/// - If the underlying datetime object needs to change, we can do it in one
/// place instead of fifty places now. You'd think this wouldn't be an issue,
/// but some places where Stamp might want to run use their own serializers
/// instead of serde, so we might need to do some tricky things with features.
/// - Any place that takes a `Timestamp` will receive any value that can be
/// converted into a `Timestamp` via `From/Into` which we have implemented for
/// [DateTime<Utc>](chrono::DateTime) and [NaiveDateTime](chrono::NaiveDateTime),
/// and you can always get the underlying type via a `&timestamp` deref.
///
/// So put down the pitchfork.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(#[serde(with = "crate::util::ser::timestamp")] DateTime<Utc>);

impl Timestamp {
    /// Create a new Timestamp from the current date/time.
    pub fn now() -> Self {
        Self(Utc::now())
    }

    pub fn local(&self) -> DateTime<Local> {
        DateTime::from(self.0)
    }
}

impl AsnType for Timestamp {
    const TAG: Tag = Tag::INTEGER;
}

impl Encode for Timestamp {
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, _tag: rasn::Tag) -> std::result::Result<(), E::Error> {
        let ts = self.timestamp_millis();
        ts.encode(encoder)?;
        Ok(())
    }
}

impl Decode for Timestamp {
    fn decode_with_tag<D: rasn::Decoder>(decoder: &mut D, _tag: rasn::Tag) -> std::result::Result<Self, D::Error> {
        let ts = <i64>::decode(decoder)?;
        let dt = match chrono::Utc.timestamp_millis_opt(ts) {
            chrono::offset::LocalResult::Single(dt) => dt,
            _ => Err(rasn::de::Error::custom("could not deserialize Url"))?,
        };
        Ok(dt.into())
    }
}

impl Deref for Timestamp {
    type Target = DateTime<Utc>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl From<NaiveDateTime> for Timestamp {
    fn from(naive: NaiveDateTime) -> Self {
        Self(DateTime::<Utc>::from_utc(naive, Utc))
    }
}

impl From<DateTime<Utc>> for Timestamp {
    fn from(date: DateTime<Utc>) -> Self {
        Self(date)
    }
}

impl FromStr for Timestamp {
    type Err = chrono::format::ParseError;
    fn from_str(s: &str) -> std::result::Result<Timestamp, Self::Err> {
        let datetime: DateTime<Utc> = s.parse()?;
        Ok(Timestamp(datetime))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Date(NaiveDate);

impl From<Timestamp> for Date {
    fn from(ts: Timestamp) -> Self {
        Self(ts.deref().date().naive_utc())
    }
}

impl From<Date> for Timestamp {
    fn from(date: Date) -> Self {
        Self(DateTime::<Utc>::from_utc(date.and_hms(0, 0, 0), Utc))
    }
}

impl AsnType for Date {
    const TAG: Tag = Timestamp::TAG;
}

impl Encode for Date {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _tag: Tag) -> std::result::Result<(), E::Error> {
        let ts: Timestamp = self.clone().into();
        ts.encode(encoder)?;
        Ok(())
    }
}

impl Decode for Date {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _tag: Tag) -> std::result::Result<Self, D::Error> {
        let ts = Timestamp::decode(decoder)?;
        Ok(ts.into())
    }
}

impl Deref for Date {
    type Target = NaiveDate;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl From<NaiveDate> for Date {
    fn from(naive: NaiveDate) -> Self {
        Self(naive)
    }
}

impl FromStr for Date {
    type Err = chrono::format::ParseError;
    fn from_str(s: &str) -> std::result::Result<Date, Self::Err> {
        let date: NaiveDate = s.parse()?;
        Ok(Date(date))
    }
}

pub trait Public: Clone {
    /// Strip the private data from a object, returning only public data.
    fn strip_private(&self) -> Self;

    /// Returns whether or not this object has private data.
    fn has_private(&self) -> bool;
}

pub trait PublicMaybe: Clone {
    /// Strip the private data from a object, unless the object is entirely
    /// private in which case return None.
    fn strip_private_maybe(&self) -> Option<Self>;
}


/// A wrapper around URLs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Url(url::Url);

impl Url {
    pub fn parse(urlstr: &str) -> Result<Self> {
        Ok(url::Url::parse(urlstr).map(|x| x.into())?)
    }
}

impl Deref for Url {
    type Target = url::Url;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl From<url::Url> for Url {
    fn from(url: url::Url) -> Self {
        Self(url)
    }
}

impl AsnType for Url {
    const TAG: Tag = Tag::UTF8_STRING;
}

impl Encode for Url {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _tag: Tag) -> std::result::Result<(), E::Error> {
        let url_str: &str = self.deref().as_ref();
        url_str.encode(encoder)?;
        Ok(())
    }
}

impl Decode for Url {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, tag: Tag) -> std::result::Result<Self, D::Error> {
        let url_str: &str = &decoder.decode_utf8_string(tag)?;
        let url = url::Url::parse(url_str)
            .map_err(|_| rasn::de::Error::custom("could not deserialize Url"))?;
        Ok(Self(url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::key::{SignKeypairSignature},
        util::ser::{self, Binary},
    };
    use rand::prelude::*;
    use std::convert::{TryFrom, TryInto};
    use std::ops::Deref;

    #[test]
    fn object_id_deref_to_from_string() {
        object_id! {
            TestID
        }

        let sigbytes = vec![61, 47, 37, 255, 130, 49, 42, 60, 55, 247, 221, 146, 149, 13, 27, 227, 23, 228, 6, 170, 103, 177, 184, 3, 124, 102, 180, 148, 228, 67, 30, 140, 172, 59, 90, 94, 220, 123, 143, 239, 97, 164, 186, 213, 141, 217, 174, 43, 186, 16, 184, 236, 166, 130, 38, 5, 176, 33, 22, 5, 111, 171, 57, 2];
        let sigarr: [u8; 64] = sigbytes.try_into().unwrap();
        let sig = SignKeypairSignature::Ed25519(Binary::new(sigarr));

        let id = TestID(sig);

        let string_id = String::try_from(&id).unwrap();
        assert_eq!(&string_id, "PS8l_4IxKjw3992SlQ0b4xfkBqpnsbgDfGa0lORDHoysO1pe3HuP72GkutWN2a4ruhC47KaCJgWwIRYFb6s5AgA");

        let id2 = TestID::try_from(string_id.as_str()).unwrap();
        assert_eq!(id, id2);

        match &id {
            TestID(sig) => {
                assert_eq!(sig, id.deref());
            }
        }
    }

    #[test]
    fn timestamp_encdec() {
        let date1 = Timestamp::from_str("1987-04-20T16:44:59.033Z").unwrap();
        let ser1 = ser::serialize(&date1).unwrap();
        let date1_2: Timestamp = ser::deserialize(ser1.as_slice()).unwrap();
        assert_eq!(date1, date1_2);

        let date2 = Timestamp::from_str("1957-12-03T00:10:19.998Z").unwrap();
        let ser2 = ser::serialize(&date2).unwrap();
        let date2_2: Timestamp = ser::deserialize(ser2.as_slice()).unwrap();
        assert_eq!(date2, date2_2);

        let date3 = Timestamp::from_str("890-08-14T14:56:01.003Z").unwrap();
        let ser3 = ser::serialize(&date3).unwrap();
        let date3_2: Timestamp = ser::deserialize(ser3.as_slice()).unwrap();
        assert_eq!(date3, date3_2);
    }

    #[test]
    fn date_encdec() {
        let date1 = Date::from_str("1987-04-20").unwrap();
        let ser1 = ser::serialize(&date1).unwrap();
        let date1_2: Date = ser::deserialize(ser1.as_slice()).unwrap();
        assert_eq!(date1, date1_2);

        let date2 = Date::from_str("1957-12-03").unwrap();
        let ser2 = ser::serialize(&date2).unwrap();
        let date2_2: Date = ser::deserialize(ser2.as_slice()).unwrap();
        assert_eq!(date2, date2_2);

        let date3 = Date::from_str("890-08-14").unwrap();
        let ser3 = ser::serialize(&date3).unwrap();
        let date3_2: Date = ser::deserialize(ser3.as_slice()).unwrap();
        assert_eq!(date3, date3_2);
    }
}

