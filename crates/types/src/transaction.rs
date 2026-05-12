use crate::Hash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

impl Transaction {
    /// Deterministic byte representation. Fields are encoded in fixed order
    /// using little-endian for integers; the variable-length `signature` is
    /// prefixed with its u64 length so it can be parsed unambiguously.
    ///
    /// TODO: replace with commonware-utils or a custom codec later.
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig_len = self.signature.len();
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 8 + 8 + sig_len);
        buf.extend_from_slice(&self.from);
        buf.extend_from_slice(&self.to);
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&(sig_len as u64).to_le_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn hash(&self) -> Hash {
        Hash::digest(&self.to_bytes())
    }
}
