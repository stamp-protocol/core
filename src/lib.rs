//! Welcome to the Stamp core, a reference implementation of the Stamp protocol.
//!
//! The Stamp protocol is a p2p cryptographic system for managing personal and group
//! identities. Like PGP, it allows creating a web of trust when users "stamp"
//! the claims made by peers or institutions. However unlike PGP, Stamp is not
//! limited to a single set of owned keys. A Stamp identity can be managed entirely
//! by third parties via multisig transactions, making it a good option for managing
//! identities for groups or organizations.
//!
//! Stamp allows any number of claims to be created on an identity, and any of them
//! can be individually signed ("stamped"). For instance, an
//! identity might claim ownership of an email address, and any person or 
//! organization might "stamp" (verify) that claim by having the owner of the
//! identity sign a random string sent over email and return it to the verifier.
//! Any number of claims or types of claims can be made and signed by any other
//! participant. Some claims, such as domain and URL claims, can be verified in-client
//! without any stamps from others (rendering centralized parties like Keybase
//! *entirely obsolete*).
//!
//! Because of the robust claim system, Stamp identities can also act as forwarding
//! mechanisms for other p2p (or centralized) systems. For instance, you could claim
//! ownership of an email address, an ActivityPub handle, etc and anyone (or anything)
//! reading your identity would know how to reach you. This allows other systems to
//! follow *your identity* and if you were to, say, switch ActivityPub servers, you
//! could take your network with you.
//!
//! The multisig protocol within Stamp allows for another useful feature: recovery.
//! You can create a policy that allows friends, family, or institutions to replace
//! your keys in the event of loss or theft. Losing a private key no longer has to
//! be a catastrophic loss.
//!
//! The goals of this protocol are as follows:
//!
//! 1. To provide a semi-permanent container for a cryptographically-verified
//! online/offline electronic identity for individuals and groups.
//! 1. To allow signing and verification of any number of custom pieces of
//! information ("claims") that assert one's identity, including ones that are
//! private and only accessible by the identity owner (and those who they choose
//! to verify that claim).
//! 1. To allow the identity holder(s) the ultimate control over their identity.
//! 1. To remain as distributed as possible.
//! 1. To be easy to use by choosing sensible defaults, providing good UX
//! wherever possible, and being opinionated wherever needed.
//! 1. To define paths for recovery that advertise their risks and benefits.
//! 1. To act as a foundational layer for other protocols where identity is required.
//! 1. To act as a useful mechanism for discovery in other distributed or
//! decentralized systems.
//!
//! # Usage
//!
//! "Sounds perfect in every way...how do I use it?" you might be wondering.
//!
//! First, let's create an identity:
//!
//! ```
//! use stamp_core::{
//!     crypto::base::{derive_secret_key, Hash, HashAlgo, KDF_OPS_MODERATE, KDF_MEM_MODERATE, SecretKey},
//!     dag::Transactions,
//!     identity::keychain::{AdminKey, AdminKeypair, ExtendKeypair},
//!     policy::{Capability, MultisigPolicy, Policy},
//!     util::Timestamp,
//! };
//! use std::ops::Deref;
//! 
//! // Let's create a master key. This key locks/unlocks the sensitive data within the
//! // identity, such as private keys. Generally, you'd create this using a passphrase:
//! let salt = Hash::new_blake3("2022-12-06T11:59:59-0800".as_bytes()).unwrap();
//! let passphrase = "lumpy coal makes good sandwhiches";
//! // here's how you generate your master key (commented out because it's slow)
//! //let master_key = derive_secret_key(passphrase.as_bytes(), salt.as_bytes(), KDF_OPS_MODERATE, KDF_MEM_MODERATE).unwrap();
//! # let master_key = SecretKey::new_xchacha20poly1305_from_slice(Hash::new_blake3(passphrase.as_bytes()).unwrap().as_bytes()).unwrap();
//!
//! // Next, we'll create an admin key. Admin keys are how we sign changes to our identity,
//! // including its creation. All private/secret keys in the identity (including Admin keys)
//! // are encrypted and only accessible by using the master key, as we're doing here.
//! let admin_keypair = AdminKeypair::new_ed25519(&master_key).unwrap();
//! let admin_key = AdminKey::new(admin_keypair, "Alpha", Some("Our primary admin key"));
//!
//! // Admin keys by themselves cannot actually do anything. They need a policy that describes
//! // what capabilities they have.
//! let policy = Policy::new(
//!     // Each policy can have any number of Capabilities, which additively allow access
//!     // to certain portions of the identity. Here, we grant access to everything.
//!     vec![Capability::Permissive],
//!     // A multisig policy controls which keys can satisfy this policy.
//!     MultisigPolicy::MOfN { must_have: 1, participants: vec![admin_key.clone().into()] }
//! );
//!
//! // An identity is a collection of transactions. Later transactions reference previous
//! // transactions, creating a DAG (Directed Acyclic Graph) of changes that, when applied
//! // in order, create your final identity.
//! let transactions = Transactions::new();
//!
//! // Ok, now to the fun stuff. We author a transaction that creates our identity: a genesis
//! // transaction.
//! let genesis = transactions
//!     // when creating the identity, we pass in our initial set of admin keys and our
//!     // initial policies.
//!     .create_identity(&HashAlgo::Blake3, Timestamp::now(), vec![admin_key.clone()], vec![policy]).unwrap()
//!     // then we sign the transaction, generally with an admin key that's in the policy
//!     // list. notice, again, we pass the master key into the sign fn along with our
//!     // heroic admin key: the admin key cannot be used without first being unlocked by
//!     // the master key... *don't forget your passphrase!*
//!     .sign(&master_key, &admin_key).unwrap();
//!
//! // Fantastic! Now we apply the genesis transaction to our transaction set...
//! let transactions_new = transactions.push_transaction(genesis).unwrap();
//!
//! // If we want to get the actual, finished Identity object from the transaction set, we do:
//! let identity = transactions_new.build_identity().unwrap();
//!
//! // The identity id is always the hash of the genesis transaction.
//! assert_eq!(identity.id().deref(), transactions_new.transactions()[0].id());
//! ```
//!
//! See? Easy. *A child could do it.* While this approach is seemingly complicated, it
//! allows for a lot of flexibility. Where this really shines is if multiple people want
//! to manage a shared group identity. The [policy system][crate::policy] allows for a lot
//! of flexibility in deciding how various key owners can perform certain operations on the
//! identity.
//!
//! And Stamp doesn't stop at the identity itself! It allows fine-grained control of
//! publishing [transactions for external protocols][crate::dag::TransactionBody::ExtV1] as well.
//! Stamp can act as a foundational identity and permission system in your own p2p protocol!
//!
//! Now that you have your initial identity constructed, using it is a matter of creating,
//! signing, and (usually) saving [transactions][crate::dag::Transaction]
//! to the transaction list, for example:
//!
//! - [`make_claim()`][crate::dag::Transactions::make_claim]
//! - [`make_stamp()`][crate::dag::Transactions::make_stamp]
//! - [`add_policy()`][crate::dag::Transactions::add_policy]
//! - [`publish()`][crate::dag::Transactions::publish]
//! - [etc][crate::dag::Transactions]

// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$IF*******FV$MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM$VF*::::::::::::::*F$NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$F**:::::::::::***::::**$NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNV****:**********************$NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN$*::*:***********FFFFFFFFF******VNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMM              MMMMMMMMMMMMMMMNF::::::**********FFFFFFFFFFFFFF*::*$MMMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMM    IS IT     MMMMMMMMMMMMMMN*::::::::*************FFFFFFFFFFF*::*$MMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMM   STAMPED?   MMMMMMMMMMMMMM$::::::::****************FFFFFFFFFF*::*MMMMMMMMMMMMMMMMMMMMMMMMMMMM
// MMMMM              MMMMMMMMMMMMMN*::::::::****************FFFFFFFFFF*::*MMMMMMMMMMMMMMMMMMMMMMMMMMMM
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

pub mod error;
#[macro_use]
pub mod util;
pub mod crypto;
pub mod policy;
pub mod identity;
pub mod dag;

pub use rand;
pub use rasn;

