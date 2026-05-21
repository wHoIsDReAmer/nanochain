use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not leader")]
    NotLeader,
    #[error("consensus timeout")]
    Timeout,
    #[error("{0}")]
    Internal(&'static str),
    #[error(transparent)]
    Types(#[from] nanochain_types::Error),
    #[error(transparent)]
    Storage(#[from] nanochain_storage::Error),
}
