use getset;
use serde_derive::{Serialize, Deserialize};

/// This is all of the possible transactions that can be performed on an
/// identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    CreateIdentity(SignKeypair),
    MakeClaim(ClaimSpec),
    RemoveClaim(ClaimID),
    AcceptStamp(Stamp),
    RemoveStamp(StampID),
    SetPolicyKey(SignKeypair, RevocationReason),
    SetPublishKey(SignKeypair, RevocationReason),
    SetRootKey(SignKeypair, RevocationReason),
    AddSubkey(Key, String, Option<String>),
    RevokeSubkey(KeyID, RevocationReason),
    RemoveSubkey(KeyID),
    SetNickname(Option<String>),
    AddForward(String, ForwardType, bool),
    RemoveForward(String),
}

