use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not leader")]
    NotLeader,
    #[error("consensus timeout")]
    Timeout,
}
