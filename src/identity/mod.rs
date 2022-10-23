//! The identity module defines the data types and operations that define a
//! Stamp identity.
//!
//! An identity is essentially a set of keys (signing and encryption), a set of
//! claims made by the identity owner (including the identity itself), any
//! number of signatures that verify those claims, and a set of [capability
//! policies][crate::policy::CapabilityPolicy] that dictate what public key
//! signatures are required to create valid transactions against this identity.
//!
//! This system relies heavily on the [key](crate::crypto::key) module, which
//! provides all the mechanisms necessary for encryption, decryption, signing,
//! and verification of data.

pub mod keychain;
pub mod claim;
pub mod stamp;
pub mod identity;

pub use keychain::*;
pub use claim::*;
pub use stamp::*;
pub use identity::*;

