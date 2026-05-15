use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("duplicate transaction")]
    Duplicate,
    #[error("mempool full")]
    Full,
    #[error("zero-amount transaction is not allowed")]
    ZeroAmount,
    #[error("coinbase transactions cannot enter the mempool")]
    CoinbaseNotAllowed,
    #[error("nonce {nonce} is already pending for this sender")]
    NonceConflict { nonce: u64 },
    #[error(transparent)]
    InvalidSignature(#[from] nanochain_types::Error),
}
