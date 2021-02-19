//! Includes some utilities helpful for generating signatures.

use crate::{
    util::Timestamp,
};
use getset;
use serde_derive::Serialize;

/// Attaches a serializable object to a date for signing.
///
/// This is a one-way object used for comparing signatures, so never needs to be
/// deserialized.
#[derive(Debug, Clone, Serialize, getset::Getters, getset::MutGetters, getset::Setters)]
pub struct DateSigner<'a, 'b, T> {
    /// The date we signed this value.
    date: &'a Timestamp,
    /// The value being signed.
    value: &'b T,
}

impl<'a, 'b, T: serde::Serialize> DateSigner<'a, 'b, T> {
    /// Construct a new DateSigner
    pub fn new(date: &'a Timestamp, value: &'b T) -> Self {
        Self {
            date,
            value,
        }
    }
}

/// A trait that allows an object to return a signable representation of itself.
pub trait Signable {
    type Item: serde::Serialize;

    /// Return the unserialized data that will be signed for this item.
    fn signable(&self) -> Self::Item;
}

impl Signable for String {
    type Item = String;
    fn signable(&self) -> Self::Item {
        self.clone()
    }
}

