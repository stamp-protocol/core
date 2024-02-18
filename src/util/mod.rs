//! Utilities. OBVIOUSLY.

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc, Local, SubsecRound, TimeZone};
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

pub use ser::{
    base64_encode,
    base64_decode,
    DeText,
    HashMapAsn1,
    SerdeBinary,
    SerText,
    Binary,
    BinarySecret,
    BinaryVec,
};

#[cfg(feature = "yaml-export")]
pub use ser::{text_export, text_import};

macro_rules! object_id {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        #[derive(Debug, Clone, rasn::AsnType, rasn::Encode, rasn::Decode, PartialEq, serde_derive::Serialize, serde_derive::Deserialize)]
        #[rasn(delegate)]
        $(#[$meta])*
        pub struct $name(pub(crate) crate::dag::TransactionID);

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
                let hash = crate::crypto::base::Hash::Blake3(crate::util::ser::Binary::new([0u8; 32]));
                $name(crate::dag::TransactionID::from(hash))
            }

            #[cfg(test)]
            pub(crate) fn random() -> Self {
                let hash = crate::crypto::base::Hash::random_blake3();
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

        impl std::convert::TryFrom<&$name> for String {
            type Error = crate::error::Error;
            fn try_from(id: &$name) -> std::result::Result<Self, Self::Error>  {
                String::try_from(id.deref())
            }
        }

        impl std::convert::TryFrom<&str> for $name {
            type Error = crate::error::Error;
            fn try_from(id_str: &str) -> std::result::Result<Self, Self::Error> {
                Ok($name::from(crate::dag::TransactionID::try_from(id_str)?))
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.deref())
            }
        }
    }
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
/// [`DateTime<Utc>`](chrono::DateTime) and [`NaiveDateTime`],
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
    fn encode_with_tag_and_constraints<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag, constraints: rasn::types::constraints::Constraints) -> std::result::Result<(), E::Error> {
        let ts = self.timestamp_millis();
        ts.encode_with_tag_and_constraints(encoder, tag, constraints)?;
        Ok(())
    }
}

impl Decode for Timestamp {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(decoder: &mut D, tag: rasn::Tag, constraints: rasn::types::constraints::Constraints) -> std::result::Result<Self, D::Error> {
        let ts = <i64>::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        let dt = match chrono::Utc.timestamp_millis_opt(ts) {
            chrono::offset::LocalResult::Single(dt) => dt,
            _ => Err(rasn::de::Error::custom("could not deserialize Url", rasn::Codec::Der))?,
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
        Self(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
    }
}

impl From<DateTime<Utc>> for Timestamp {
    fn from(date: DateTime<Utc>) -> Self {
        Self(date.trunc_subsecs(3))
    }
}

impl FromStr for Timestamp {
    type Err = chrono::format::ParseError;
    fn from_str(s: &str) -> std::result::Result<Timestamp, Self::Err> {
        let datetime: DateTime<Utc> = s.parse()?;
        Ok(Timestamp(datetime))
    }
}

/// Describes a date without a time. Really, just exists for the birthday claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Date(NaiveDate);

impl From<Timestamp> for Date {
    fn from(ts: Timestamp) -> Self {
        Self(ts.deref().date_naive())
    }
}

impl From<Date> for Timestamp {
    fn from(date: Date) -> Self {
        // UGH I hate unwraps, but this should never fail sooo....
        Self(DateTime::<Utc>::from_naive_utc_and_offset(date.and_hms_opt(0, 0, 0).unwrap(), Utc))
    }
}

impl AsnType for Date {
    const TAG: Tag = Timestamp::TAG;
}

impl Encode for Date {
    fn encode_with_tag_and_constraints<E: Encoder>(&self, encoder: &mut E, tag: Tag, constraints: rasn::types::constraints::Constraints) -> std::result::Result<(), E::Error> {
        let ts: Timestamp = self.clone().into();
        ts.encode_with_tag_and_constraints(encoder, tag, constraints)?;
        Ok(())
    }
}

impl Decode for Date {
    fn decode_with_tag_and_constraints<D: Decoder>(decoder: &mut D, tag: Tag, constraints: rasn::types::constraints::Constraints) -> std::result::Result<Self, D::Error> {
        let ts = Timestamp::decode_with_tag_and_constraints(decoder, tag, constraints)?;
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

/// Marks a type as having a public mode, ie stripped of all private data.
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
    fn encode_with_tag_and_constraints<E: Encoder>(&self, encoder: &mut E, tag: Tag, constraints: rasn::types::constraints::Constraints) -> std::result::Result<(), E::Error> {
        let url_str: &str = self.deref().as_ref();
        url_str.encode_with_tag_and_constraints(encoder, tag, constraints)?;
        Ok(())
    }
}

impl Decode for Url {
    fn decode_with_tag_and_constraints<D: Decoder>(decoder: &mut D, tag: Tag, constraints: rasn::types::constraints::Constraints) -> std::result::Result<Self, D::Error> {
        let url_str: &str = &decoder.decode_utf8_string(tag, constraints)?;
        let url = url::Url::parse(url_str)
            .map_err(|_| rasn::de::Error::custom("could not deserialize Url", rasn::Codec::Der))?;
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
        crypto::base::{Hash},
        dag::TransactionID,
        util::ser,
    };
    use std::convert::TryFrom;
    use std::ops::Deref;

    #[test]
    fn object_id_deref_to_from_string() {
        object_id! {
            TestID
        }

        let hash1 = Hash::new_blake3(b"get a job").unwrap();
        let hash2 = Hash::new_blake3(b"hot one today!").unwrap();
        let hash3 = Hash::new_blake3(b"YEAH?!").unwrap();

        let id1 = TestID::from(TransactionID::from(hash1));
        let id2 = TestID::from(TransactionID::from(hash2));
        let id3 = TestID::from(TransactionID::from(hash3));

        let string_id1 = String::try_from(&id1).unwrap();
        let string_id2 = String::try_from(&id2).unwrap();
        let string_id3 = String::try_from(&id3).unwrap();
        assert_eq!(&string_id1, "He7UaLB48wVhf85NXb5PlCpYuXdYsWCzJ48-IFikVXwA");
        assert_eq!(&string_id2, "Hcbsu5WKLBJZ58TGznj1Beqs0Ta-c4r1pLta6Y0wrnYA");
        assert_eq!(&string_id3, "aVAFYuZJXDC0cT44V0Edi0IhylIs0eaxobc_7LI4KRUA");

        let id1_2 = TestID::try_from(string_id1.as_str()).unwrap();
        let id2_2 = TestID::try_from(string_id2.as_str()).unwrap();
        let id3_2 = TestID::try_from(string_id3.as_str()).unwrap();
        assert_eq!(id1, id1_2);
        assert_eq!(id2, id2_2);
        assert_eq!(id3, id3_2);

        match &id1 {
            TestID(sig) => {
                assert_eq!(sig, id1.deref());
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

        // ser/deser should truncate to millis.
        let date4 = Timestamp::from_str("2023-06-21T04:59:44.023816356Z").unwrap();
        let date4_comp = Timestamp::from_str("2023-06-21T04:59:44.023Z").unwrap();
        let ser4 = ser::serialize(&date4).unwrap();
        let date4_2: Timestamp = ser::deserialize(ser4.as_slice()).unwrap();
        assert_eq!(date4_2, date4_comp);

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

