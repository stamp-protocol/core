//! Welcome to the Stamp core, a reference implementation of the Stamp protocol.
//!
//! The Stamp protocol is essentially the successor to PGP. It seeks to provide
//! a meaningful cryptographic identity for a given person, which can be signed
//! by either their peers or various institutions. This identity is somewhat
//! detached from the cryptographic keys used to manage it, and is meant to be
//! long-lived *beyond the life of the keys*. Where PGP is a somewhat ephemeral
//! master keypair and collection of subkeys, Stamp is a permanent marker of
//! identity and the signatures on one's identity are not meaningfully attached
//! to any particular set of keys.
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

use error::Result;
use util::ser;

/// Allows identity formats to be versioned so as to not break compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityVersion {
    V1(identity::Identity),
}

impl IdentityVersion {
    /// Serialize this versioned identity into a byte vector.
    pub fn serialize_binary(&self) -> Result<Vec<u8>> {
        ser::serialize(self)
    }

    /// Serialize this versioned identity into a human readable format
    pub fn serialize_human_public(&self) -> Result<String> {
        ser::serialize_human(&self.strip_private())
    }

    /// Deserialize this versioned identity from a byte vector.
    pub fn deserialize_binary(slice: &[u8]) -> Result<Self> {
        ser::deserialize(slice)
    }

    /// Deserialize this versioned identity from a byte vector.
    pub fn deserialize_human(slice: &[u8]) -> Result<Self> {
        ser::deserialize_human(slice)
    }

    /// Strip all private data from this identity.
    fn strip_private(&self) -> Self {
        match self {
            Self::V1(identity) => Self::V1(identity.strip_private()),
        }
    }
}

pub trait VersionedIdentity {
    /// Converts an identity into a versioned identity.
    fn version(self) -> IdentityVersion;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_serde() {
        let master_key = key::SecretKey::new_xsalsa20poly1305();
        let now = util::Timestamp::now();
        let identity = identity::Identity::new(&master_key, now).unwrap();
        let version = identity.version();
        let human = version.serialize_human_public().unwrap();
        let machine = version.serialize_binary().unwrap();
        println!("--- ser: human\n{}", human);
        println!("--- ser: machine\n{}", base64::encode(&machine));
    }
}

