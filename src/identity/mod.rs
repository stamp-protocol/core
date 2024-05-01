//! The identity module defines the data types and operations that define a
//! Stamp identity.
//!
//! An identity is essentially a set of keys (signing and encryption), a set of
//! claims made by the identity owner (including the identity itself), any
//! number of signatures that verify those claims, and a set of [ policies][crate::policy::Policy]
//! that dictate what public key signatures are required to create valid transactions
//! against this identity.
//!
//! This system relies heavily on the [crypto base][crate::crypto::base] module, which
//! provides all the mechanisms necessary for encryption, decryption, signing,
//! and verification of data.

pub mod claim;
pub mod identity;
pub mod keychain;
pub mod stamp;
pub mod trust;

pub use identity::*;
