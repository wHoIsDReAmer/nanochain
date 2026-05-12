use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("invalid block: {0}")]
    InvalidBlock(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
}
