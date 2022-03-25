//! Includes some utilities helpful for generating signatures.

use crate::{
    util::Timestamp,
};
use getset;
use rasn::{AsnType, Encode, Encoder, Tag, types::Class};

/// Attaches a serializable object to a date for signing.
///
/// This is a one-way object used for comparing signatures, so never needs to be
/// deserialized.
#[derive(Debug, Clone, AsnType, getset::Getters, getset::MutGetters, getset::Setters)]
pub struct DateSigner<'a, 'b, T> {
    /// The date we signed this value.
    date: &'a Timestamp,
    /// The value being signed.
    value: &'b T,
}

impl<'a, 'b, T: Encode> DateSigner<'a, 'b, T> {
    /// Construct a new DateSigner
    pub fn new(date: &'a Timestamp, value: &'b T) -> Self {
        Self {
            date,
            value,
        }
    }
}

impl<'a, 'b, T: Encode> Encode for DateSigner<'a, 'b, T> {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |encoder| {
            encoder.encode_explicit_prefix(Tag::new(Class::Context, 0), &self.date)?;
            encoder.encode_explicit_prefix(Tag::new(Class::Context, 1), &self.value)?;
            Ok(())
        })?;
        Ok(())
    }
}

/// A trait that allows an object to return a signable representation of itself.
pub trait Signable {
    type Item: Encode;

    /// Return the unserialized data that will be signed for this item.
    fn signable(&self) -> Self::Item;
}

impl Signable for String {
    type Item = String;
    fn signable(&self) -> Self::Item {
        self.clone()
    }
}

