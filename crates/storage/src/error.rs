use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("block not found")]
    BlockNotFound,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
