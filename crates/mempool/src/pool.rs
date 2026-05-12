use nanochain_types::{Hash, Transaction};
use std::collections::HashMap;

pub struct Mempool {
    txs: HashMap<Hash, Transaction>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            txs: HashMap::new(),
        }
    }

    pub fn insert(&mut self, tx: Transaction) {
        self.txs.insert(tx.hash(), tx);
    }

    pub fn remove(&mut self, hash: &Hash) {
        self.txs.remove(hash);
    }

    pub fn pending(&self) -> Vec<Transaction> {
        self.txs.values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}
