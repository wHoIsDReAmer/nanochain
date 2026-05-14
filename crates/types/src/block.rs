use crate::{Hash, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub parent_hash: Hash,
    pub tx_root: Hash,
    pub timestamp: u64,
    pub proposer: [u8; 32],
}

impl BlockHeader {
    /// 112-byte deterministic encoding (LE for integers).
    /// TODO: swap for commonware-utils.
    pub fn to_bytes(&self) -> [u8; 112] {
        let mut buf = [0u8; 112];
        buf[0..8].copy_from_slice(&self.height.to_le_bytes());
        buf[8..40].copy_from_slice(&self.parent_hash.0);
        buf[40..72].copy_from_slice(&self.tx_root.0);
        buf[72..80].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[80..112].copy_from_slice(&self.proposer);
        buf
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Compute the Merkle root of a transaction list.
    pub fn compute_tx_root(txs: &[Transaction]) -> Hash {
        if txs.is_empty() {
            return Hash::zero();
        }

        let mut layer: Vec<Hash> = txs.iter().map(|tx| tx.hash()).collect();

        while layer.len() > 1 {
            if layer.len() % 2 == 1 {
                layer.push(layer.last().unwrap().clone());
            }
            layer = layer
                .chunks(2)
                .map(|pair| {
                    let mut buf = [0u8; 64];
                    buf[..32].copy_from_slice(&pair[0].0);
                    buf[32..].copy_from_slice(&pair[1].0);
                    Hash::digest(&buf)
                })
                .collect();
        }

        layer.into_iter().next().unwrap()
    }

    pub fn hash(&self) -> Hash {
        Hash::digest(&self.header.to_bytes())
    }

    pub fn genesis() -> Self {
        Block {
            header: BlockHeader {
                height: 0,
                parent_hash: Hash::zero(),
                tx_root: Hash::zero(),
                timestamp: 0,
                proposer: [0u8; 32],
            },
            transactions: vec![],
        }
    }

    /// Block builder. `tx_root` is computed automatically from `transactions`.
    pub fn new(
        height: u64,
        parent_hash: Hash,
        timestamp: u64,
        proposer: [u8; 32],
        transactions: Vec<Transaction>,
    ) -> Self {
        let tx_root = Self::compute_tx_root(&transactions);
        Block {
            header: BlockHeader {
                height,
                parent_hash,
                tx_root,
                timestamp,
                proposer,
            },
            transactions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(amount: u64, nonce: u64) -> Transaction {
        Transaction {
            from: [1u8; 32],
            to: [2u8; 32],
            amount,
            nonce,
            signature: None,
        }
    }

    #[test]
    fn empty_root_is_zero() {
        assert_eq!(Block::compute_tx_root(&[]), Hash::zero());
    }

    #[test]
    fn single_tx_root_is_tx_hash() {
        let t = tx(10, 0);
        let h = t.hash();
        assert_eq!(Block::compute_tx_root(&[t]), h);
    }

    #[test]
    fn modifying_one_tx_changes_root() {
        let a = vec![tx(10, 0), tx(20, 1), tx(30, 2)];
        let mut b = a.clone();
        b[1].amount = 999;
        assert_ne!(Block::compute_tx_root(&a), Block::compute_tx_root(&b));
    }

    #[test]
    fn reordering_changes_root() {
        let a = tx(10, 0);
        let b = tx(20, 1);
        assert_ne!(
            Block::compute_tx_root(&[a.clone(), b.clone()]),
            Block::compute_tx_root(&[b, a]),
        );
    }

    #[test]
    fn block_hash_reacts_to_tx_change() {
        let b1 = Block::new(1, Hash::zero(), 0, [0u8; 32], vec![tx(10, 0)]);
        let b2 = Block::new(1, Hash::zero(), 0, [0u8; 32], vec![tx(99, 0)]);
        assert_ne!(b1.hash(), b2.hash());
    }

    #[test]
    fn odd_layer_handled() {
        let txs = vec![tx(1, 0), tx(2, 1), tx(3, 2)];
        let _ = Block::compute_tx_root(&txs);
    }
}
