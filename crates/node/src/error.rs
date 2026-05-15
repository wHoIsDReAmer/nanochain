use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("mempool: {0}")]
    Mempool(#[from] nanochain_mempool::Error),
    #[error("consensus: {0}")]
    Consensus(#[from] nanochain_consensus::Error),
    #[error("storage: {0}")]
    Storage(#[from] nanochain_storage::Error),
    #[error("types: {0}")]
    Types(#[from] nanochain_types::Error),
    #[error("internal: {0}")]
    Internal(&'static str),
}
