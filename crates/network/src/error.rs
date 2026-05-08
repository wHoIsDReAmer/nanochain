use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("peer not found")]
    PeerNotFound,
}
