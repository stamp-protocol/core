use crate::error::{Error, Result};
use sodiumoxide::{
    crypto::generichash,
};

/// Hash arbitrary data using blake2b
pub fn hash(data: &[u8]) -> Result<generichash::Digest> {
    let mut state = generichash::State::new(generichash::DIGEST_MAX, None)
        .map_err(|_| Error::CryptoHashStateInitError)?;
    state.update(data)
        .map_err(|_| Error::CryptoHashStateUpdateError)?;
    state.finalize()
        .map_err(|_| Error::CryptoHashStateDigestError)
}

