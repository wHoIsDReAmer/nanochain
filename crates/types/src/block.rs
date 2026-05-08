use serde::{Deserialize, Serialize};
use crate::{Hash, Transaction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub parent_hash: Hash,
    pub timestamp: u64,
    pub proposer: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn hash(&self) -> Hash {
        let encoded = bincode::serialize(&self.header).expect("serialize header");
        Hash::digest(&encoded)
    }

    pub fn genesis() -> Self {
        Block {
            header: BlockHeader {
                height: 0,
                parent_hash: Hash::zero(),
                timestamp: 0,
                proposer: [0u8; 32],
            },
            transactions: vec![],
        }
    }
}
