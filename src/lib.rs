//! Welcome to the Stamp core, a reference implementation of the Stamp protocol.
//!
//! The Stamp protocol is essentially a successor to PGP. It seeks to provide
//! a meaningful cryptographic identity for a given person, which can be signed
//! by either their peers or various institutions. This identity is meant to be
//! long-lived *beyond the life of the keys*. Where PGP is a somewhat ephemeral
//! master keypair and collection of subkeys, Stamp is a permanent marker of
//! identity which offers various avenues for recovery in the case of lost keys.
//!
//! Also, where Stamp deviates is that any number of claims can be made by a
//! Stamp identity, and any of them can be individually signed. For instance, an
//! identity might claim ownership of an email address, and any person or 
//! organization might "stamp" (verify) that claim by having the owner of the
//! identity sign a random string sent over email and return it to the verifier.
//! Any number of claims or types of claims can be made and signed by any other
//! participant.
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
//! 1. To act as a useful mechanism for discovery in other distributed or
//! decentralized systems.

// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$IF*******FV$MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM$VF*::::::::::::::*F$NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$F**:::::::::::***::::**$NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNV****:**********************$NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$*::*:***********FFFFFFFFF******VNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNF::::::**********FFFFFFFFFFFFFF*::*$MMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN*::::::::*************FFFFFFFFFFF*::*$MMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM$::::::::****************FFFFFFFFFF*::*MMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN*::::::::****************FFFFFFFFFF*::*MMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMF::**:::::::****************FFFFFFF***:*$MMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMF:***::::::::::*******************FF***:IMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM$*****:::::::::::*****************FFF***VMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$****:::::::::::::*F*********:****FFFF**$MMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$***::::::::::::::*FFF*************FFF***NMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNV**::::::::**::::*FFFFF****:::******FFFFVNMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNI**:::::*****:::**FFFFFF*******FF*F**VVFI$NMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNV**::::*****::::*FFFFFFIFF*FFFFFFFF*FN$**$NMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$FF*::::***::::**FFFFFFFFFFFFFFFFFFF$N$**$MMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNVV*:::::::::::****FFF***FFFFFFFF*F$NMVFINMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM$$*::::::::::::*::::******FFFFF**FNNNIVNMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$*::::::::::.:::::*******FFFFF**VNM$$NMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$*::::::::..:::::::*******F**F*VNNN$MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$F*:::::::::::::::::::********F$NN$NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$V*:::::::::::::::::::********V$$NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$*::::::::::*****************V$NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$*::::::::::********F********V$MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM$V*::::::********************F$VNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMV::F**:::********************F$$**MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM:..*FFF*::******************FV$V::NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNI...:*****::::******************:.:F$NMNN$$VFFFFFFV$NNMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMN$VIF****F*::....:::::::::::::::::*:********:.....::**::..........::**F$NNMMMMMMMM
// MMMMMMN$VFFF*****:..................:::::::::::::::::::******:..........:.........:*:::***::F$NMMMMM
// $$VF**:.........:::::.................::::::::::::::******F*............................::::..:FNMMM
// ::....::::::::::*****::................:::::::::::*****FFFF*...................................::VMM
// ...:******::**********:................:*:::::::::**FFFFFFF*.....................................:**
// ...:*******************:................***::::....:::****F*........................................
// ...:FFF****************:..................................::........................................
// ...:VVVFFIF*FF*********:...................::::...............:::...................................
// ...*V$$VV$VFVVV**FFF****....................::::.............:***:..................................
// ..:*V$$VV$$VIV$F*FFVVF**::::::::::...........:::.............::::::.................................
// ..:*V$$VV$$VFV$V*FIV$V***:::****:*:.................................................................
// ...*FIF*V$$$FV$$F*I$VI***::******F:.................................................................
// .......:V$$$VIV$I*FI*F*F*::::::**:................................................................:.
// .......:FV$VFFVVVVVV***F*::**:*:...............................................................:::::
// ........:*FF*:FFVVVV*.:..:::***:..........................................................::..::.:::
// .........:**...:FVVV*......::**:......:::::::...........................................::::..::::::
// ................:***:......:::**....:::::::::::.........................................::::....::.:
//
// [Is it stamped?]

use serde_derive::{Serialize, Deserialize};

pub mod error;
#[macro_use]
pub mod util;
pub mod private;
pub mod key;
pub mod identity;

use crate::{
    key::{SecretKey, SignKeypairSignature},
};
use error::Result;
use util::ser;

/// Allows identity formats to be versioned so as to not break compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VersionedIdentity {
    V1(identity::Identity),
}

impl VersionedIdentity {
    /// Serialize this versioned identity into a byte vector.
    pub fn serialize_binary(&self) -> Result<Vec<u8>> {
        ser::serialize(self)
    }

    /// Deserialize this versioned identity from a byte vector.
    pub fn deserialize_binary(slice: &[u8]) -> Result<Self> {
        ser::deserialize(slice)
    }

    /// Strip all private data from this identity.
    fn strip_private(&self) -> Self {
        match self {
            Self::V1(identity) => Self::V1(identity.strip_private()),
        }
    }
}

/// The container that is used to publish an identity. This is what otherswill
/// import when they verify an identity, stamp the claim for an identity, send
/// the identity a value for signing (for instance for logging in to an online
/// service), etc.
///
/// The published identity must be signed by our publish keypair, which in turn
/// is signed by our alpha keypair.
#[derive(Debug, Clone, Serialize, Deserialize, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct PublishedIdentity {
    /// The signature of this published identity, generated using our publish
    /// keypair.
    signature: SignKeypairSignature,
    /// The versioned identity we're publishing.
    identity: VersionedIdentity,
}

impl PublishedIdentity {
    /// Takes an identity and creates a signed published identity object from
    /// it.
    pub fn publish<T: Into<VersionedIdentity>>(master_key: &SecretKey, identity: T) -> Result<Self> {
        let versioned_identity: VersionedIdentity = identity.into();
        let public_identity = versioned_identity.strip_private();
        let serialized = ser::serialize(&public_identity)?;
        let signature = match &versioned_identity {
            VersionedIdentity::V1(id) => id.keychain().publish().sign(master_key, &serialized),
        }?;
        Ok(Self {
            signature,
            identity: public_identity,
        })
    }

    /// Serialize this versioned identity into a human readable format
    pub fn serialize(&self) -> Result<String> {
        ser::serialize_human(&self)
    }

    /// Deserialize this versioned identity from a byte vector.
    pub fn deserialize(slice: &[u8]) -> Result<Self> {
        ser::deserialize_human(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::keychain,
        key::CryptoKeypair,
    };

    #[test]
    fn published() {
        let master_key = key::SecretKey::new_xsalsa20poly1305();
        let now = util::Timestamp::now();
        let identity = identity::Identity::new(&master_key, now).unwrap()
            .add_subkey(&master_key, keychain::Key::Crypto(CryptoKeypair::new_curve25519xsalsa20poly1305(&master_key).unwrap()), "Email", "Use this to send me emails.").unwrap();
        let published = PublishedIdentity::publish(&master_key, identity).unwrap();
        let human = published.serialize().unwrap();
        println!("--- ser: human\n{}", human);
    }
}

