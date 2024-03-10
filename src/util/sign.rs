//! Includes some utilities helpful for generating signatures.

use rasn::Encode;

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
