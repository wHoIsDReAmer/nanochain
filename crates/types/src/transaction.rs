use serde::{Deserialize, Serialize};
use crate::Hash;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

impl Transaction {
    pub fn hash(&self) -> Hash {
        let encoded = bincode::serialize(self).expect("serialize tx");
        Hash::digest(&encoded)
    }
}
