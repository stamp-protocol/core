//! Welcome to the Stamp core, a reference implementation of the Stamp protocol.
//!
//! The Stamp protocol is essentially the successor to PGP. It seeks to provide
//! a meaningful cryptographic identity for a given person, which can be signed
//! by either their peers or various institutions. This identity is somewhat
//! detached from the cryptographic keys used to manage it, and is meant to be
//! long-lived *beyond the life of the keys*. Where PGP is an ephemeral master
//! keypair and collection of subkeys, Stamp is a permanent marker of identity
//! and the signatures on one's identity are not meaningfully attached to any
//! particular set of keys.
//!
//! Also, where Stamp deviates is that any number of claims can be made by a
//! Stamp identity, and any of them can be individually signed. For instance, an
//! identity might claim ownership of an email address, and any person or might
//! "stamp" (verify) that claim by having the owner of the identity sign a
//! random string sent over email. Any number of claims or types of claims can
//! be made and signed by any other participant (including the identity itself).
//!
//! The Stamp protocol defines not just methods for encryption, signing, and
//! verification, but also for key recovery among trusted peers or institutions.
//!
//! Stamp also allows an identity to point (or "forward") to other locations or
//! distributed/decentralized systems. Your identity might be the canonical
//! place that your followers on a decentralized social network might find you:
//! switching servers doesn't mean you have to rebuild your network anymore,
//! because you can update your Stamp identity to point at your new location.
//! You can forward interested parties to websites, email address, social
//! networks, or any custom representation of location.
//!
//! The goals of this protocol are as follows:
//!
//! 1. To provide a semi-permanent container for a cryptographically-verified
//! online identity.
//! 1. To allow signing and verification of any number of custom pieces of
//! information ("claims") that assert one's identity, including ones that are
//! private and only accessible by the identity owner (and those who they choose
//! to verify that claim).
//! 1. To allow the identity holder the ultimate control over their identity.
//! 1. To remain as distributed as possible.
//! 1. To be easy to use, by choosing sensible defaults and providing good UX
//! wherever possible.
//! 1. To define paths for recovery that advertise their risks and benefits.
//! 1. To act as a useful mechanism in other distributed or decentralized
//! systems.

pub mod error;
pub mod util;
pub mod ser;
pub mod private;
pub mod identity;
pub mod key;

