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

pub use ser::{base64_encode, base64_decode, SerdeBinary, Binary, BinarySecret, BinaryVec};

macro_rules! object_id {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        #[derive(Debug, Clone, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
        $(#[$meta])*
        pub struct $name(pub(crate) crate::dag::TransactionID);

        asn_encdec_newtype! { $name, crate::dag::TransactionID }

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
                let hash = crate::crypto::key::Sha512::from([0u8; crate::crypto::key::SHA512_LEN]);
                $name(crate::dag::TransactionID::from(hash))
            }

            #[cfg(test)]
            pub(crate) fn random() -> Self {
                let hash = crate::crypto::key::Sha512::random();
                $name(crate::dag::TransactionID::from(hash))
            }
        }

        impl Deref for $name {
            type Target = crate::dag::TransactionID;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::convert::From<crate::dag::TransactionID> for $name {
            fn from(hash: crate::dag::TransactionID) -> Self {
                Self(hash)
            }
        }

        impl std::convert::From<&$name> for String {
            fn from(id: &$name) -> String {
                let bytes = id.deref().deref().deref();
                crate::util::ser::base64_encode(bytes)
            }
        }

        impl std::convert::TryFrom<&str> for $name {
            type Error = crate::error::Error;
            fn try_from(id_str: &str) -> std::result::Result<Self, Self::Error> {
                let bytes = crate::util::ser::base64_decode(id_str.as_bytes())?;
                let hash_bytes: [u8; crate::crypto::key::SHA512_LEN] = bytes.try_into()
                    .map_err(|_| crate::error::Error::BadLength)?;
                let hash = crate::crypto::key::Sha512::from(hash_bytes);
                Ok(Self(crate::dag::TransactionID::from(hash)))
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
        Utc::now().into()
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
        // we need to erase any precision below millisecond because it is not
        // serialized and will screw things up for us.
        let ts = date.timestamp_millis();
        // i hate to panic here, but we're literally converting to i64 then
        // from i64 without modification, so it would be very surprising if
        // we failed here
        let dt = chrono::Utc.timestamp_millis(ts);
        Self(dt)
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

pub trait Public {
    /// Strip the private data from a object, returning only public data.
    fn strip_private(&self) -> Self;

    /// Returns whether or not this object has private data.
    fn has_private(&self) -> bool;
}

/// A wrapper around URLs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Url(url::Url);

impl Url {
    /// Parse a string Url
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

#[allow(deprecated)]    // omg stfu
impl From<Url> for String {
    fn from(url: Url) -> Self {
        let Url(inner) = url;
        inner.into_string()
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

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::key::{Sha512},
        dag::TransactionID,
        util::ser::{self, Binary},
    };
    use std::convert::{TryFrom, TryInto};
    use std::ops::Deref;

    #[test]
    fn object_id_deref_to_from_string() {
        object_id! {
            TestID
        }

        let hash = Sha512::hash(b"get a job").unwrap();

        let id = TestID(TransactionID::from(hash));

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

