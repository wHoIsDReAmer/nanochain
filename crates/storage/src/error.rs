use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("block not found")]
    BlockNotFound,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    // --- state transition errors ---
    #[error("invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },
    #[error("balance overflow on recipient")]
    BalanceOverflow,
    #[error("invalid coinbase: {0}")]
    InvalidCoinbase(&'static str),
    #[error(transparent)]
    InvalidSignature(#[from] nanochain_types::Error),
}
