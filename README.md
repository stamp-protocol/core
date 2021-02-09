# Stamp protocol

Welcome to the Stamp core, a reference implementation of the Stamp protocol.

The Stamp protocol is essentially a successor to PGP. It seeks to provide
a meaningful cryptographic identity for a given person, which can be signed
by either their peers or various institutions.

Stamp deviates from PGP in that any number of claims can be made by a
Stamp identity, and any of them can be individually signed. For instance, an
identity might claim ownership of an email address, and any person or 
organization might "stamp" (verify) that claim by having the owner of the
identity sign a random string sent over email and return it to the verifier.
Any number of claims or types of claims can be made and signed by any other
participant.

The Stamp protocol defines not just methods for encryption, signing, and
verification, but also for key recovery among trusted peers or institutions.

Stamp also allows an identity to point (or "forward") to other locations or
distributed/decentralized systems. Your identity might be the canonical
place that your followers on a decentralized social network might find you:
switching servers doesn't mean you have to rebuild your network anymore,
because you can update your Stamp identity to point at your new location.
You can forward interested parties to websites, email address, social
networks, or any custom representation of location.

The goals of this protocol are as follows:

1. To provide a semi-permanent container for a cryptographically-verified
online identity.
1. To allow signing and verification of any number of custom pieces of
information ("claims") that assert one's identity, including ones that are
private and only accessible by the identity owner (and those who they choose
to verify that claim).
1. To allow the identity holder the ultimate control over their identity.
1. To remain as distributed as possible.
1. To be easy to use by choosing sensible defaults, providing good UX
wherever possible, and being opinionated wherever needed.
1. To define paths for recovery that advertise their risks and benefits.
1. To act as a useful mechanism for discovery in other distributed or
decentralized systems.

## Architecture

Instead of leaving key management best practices up to users, Stamp takes an
opinionated approach and creates a hierarchy of cryptographic signing keys that
each has its own specific function. This key format is as follows:

- `alpha` - The alpha key is the highest key in the identity. It is responsible
for creating the identity's ID, which is a static value used to reference your
identity. The alpha key also signs the keys below it, ensuring that the keys
cannot be tampered with outside of the approval of the holder of the alpha key.
  - `policy` - The policy key is used to sign recovery policies. A recovery policy
  is a set of conditions that allows an identity holder to regenerate their root
  or publish keys, provided they have the signatures from other identities called
  for by the policy. This mechanism allows recovering from lost or stolen keys in
  the case that the alpha key is inaccessible, which allows the identity to live
  beyond lost keys.
  - `publish` - This key is used to sign the identity whenever it is published to
  any public medium. It allows others to verify that the published identity is
  valid (because it is signed by a key signed by the alpha key, or recovered via
  the recovery system).
  - `root` - The root key is responsible for a number of things. First and foremost,
  it signs all aspects of the identity (outside of the alpha, policy, or publish
  keys) into a "root signature" which allows the identity to be verified as a
  singlar object that cannot be tampered with. The root signature also allows the
  signing of all the identity's subkeys, which are keys controlled by the owner
  of the identity that can be used for any purposes they wish.

The identity itself consists of a keychain, a set of claims (which are pieces of
identity information that others can verify and "stamp"), stamps on those claims,
and a set of extra data.

The extra data section of the identity is used for two main purposes.

1. a "nickname" field, which can be used to give your identity a memorable name
others can use to look it up. This nickname is not enforced to be unique, so it
is generally used along with some portion of the identity's ID to differentiate
it from other identities that have the same nickname.
1. A set of forwards that point to other locations. This is particularly impactful
for decentralized or distributed systems (email, Mastodon, Matrix, etc etc) that
might use your Stamp identity as an intermediary that can be kept up to date
with the most recent locations. For instance, if your Mastodon followers
could follow `stamp://andrew-lyon/haha-p_i4hWAgDTT/forwards/social/Mastodon` and
if you happen to change servers, the identity can update the forward to point at
the new server and your followers won't even need to know you changed locations.
This could be implemented for any decentralized or distributed system, and
allows your cryptographic identity to be the canonical place to communicate with
you.

## Stamps

As mentioned, and identity contains a number of claims, and each of those claims
can have any number of stamps on them from other identities.

Stamps are what forms the trust network of the Stamp protocol: a stamp signifies
a transfer of trust between identities, so if an identity you trust stamps
another identity, some of that trust flows through to the recipient of the stamp.
This enables a network of trust that can be used as the foundational layer of
participation in distributed (or even centralized) systems themselves.

## StampNet

StampNet will be a peer-to-peer system allowing publishing and searching of
Stamp identities. The goal is to create something akin to Bittorrent where
identities and the information surrounding them (such as revocations) can be
accessed through some form of DHT.

Another goal of StampNet is to avoid blockchains and the pitfalls surrounding
them. Ideally, Stamp could act as a platform upon which egalitarian blockchain
systems could be built on top of, rather than be a blockchain system itself.
Using a non-blockchain P2P protocol also allows other systems to plug into
StampNet as read-only members without having to "participate" in the parocessing
of transactions, allowing quick lookups of identity information without the BS.

## Roadmap

- [ ] Stamp core proof of concept
  - [x] Key hierarchy
  - [x] Root signature and verification
  - [ ] Keychain management
    - [x] Policy, publish, root key management
    - [ ] Subkey management
      - [x] Add
      - [ ] Update name/description
      - [x] Revoke
      - [x] Delete
    - [x] Reencryption via new master key
  - [ ] Claims system
    - [x] Create, sign, verify claims
    - [ ] Support multiple claim types
      - [x] Identity
      - [x] Name
      - [ ] DOB
      - [x] Email
      - [x] Embedded photo
      - [x] PGP
      - [x] Domain
      - [x] URL
      - [x] Home address
      - [x] Relationship to another stamp identity
      - [x] Relationship to non-stamp identity
      - [x] Extendable claim
    - [ ] Stamp requests (sending private claims to stamper)
    - [x] Private verifiable claims (via HMAC)
    - [x] Stamps
      - [x] Create, sign, verify stamps
      - [x] Accept and sign stamps
      - [x] Revocation
    - [ ] Automatic claim verification
      - [ ] Domain TXT claim verification
      - [ ] URL (https) claim verification
  - [x] Identity versioning
  - [x] Identity human-readable serialization
  - [x] Publishing system and verfication
  - [ ] Cryptographic utilities
    - [x] Encrypted messages between identities
    - [x] Cryptographic signatures
    - [ ] Personal data encryption/decryption
  - [ ] Recovery system
  - [ ] Extra data management
    - [ ] Nickname
    - [ ] Forwards
  - [ ] Whole identity revocation
  - [ ] Trust system
    - [ ] Trust of specific identities
    - [ ] Flow of trust through stamps, using confidence as control valve
- [ ] CLI proof of concept
  - [ ] Interface all available functions of core
- [ ] Formal specification of Stamp protocol
- [ ] StampNet implementation

