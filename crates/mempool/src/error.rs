use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("duplicate transaction")]
    Duplicate,
    #[error("mempool full")]
    Full,
}
