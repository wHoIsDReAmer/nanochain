use crate::Error;
use nanochain_types::{Hash, Transaction};
use std::collections::{BTreeMap, HashMap};

pub const DEFAULT_CAPACITY: usize = 1024;

/// Dual-indexed mempool: `hash → tx` for O(1) lookup, plus per-sender
/// `BTreeMap<nonce, hash>` for nonce-ordered iteration and conflict
/// detection. Both indexes are kept in lockstep by every mutator.
pub struct Mempool {
    txs: HashMap<Hash, Transaction>,
    by_sender: HashMap<[u8; 32], BTreeMap<u64, Hash>>,
    capacity: usize,
}

impl Mempool {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Mempool {
            txs: HashMap::with_capacity(capacity),
            by_sender: HashMap::new(),
            capacity,
        }
    }

    /// Validate and insert. See `Error` variants for rejection reasons.
    pub fn insert(&mut self, tx: Transaction) -> Result<Hash, Error> {
        tx.verify_signature()?;

        if tx.amount == 0 {
            return Err(Error::ZeroAmount);
        }

        let hash = tx.hash();
        if self.txs.contains_key(&hash) {
            return Err(Error::Duplicate);
        }

        if let Some(by_nonce) = self.by_sender.get(&tx.from) {
            if by_nonce.contains_key(&tx.nonce) {
                return Err(Error::NonceConflict { nonce: tx.nonce });
            }
        }

        if self.txs.len() >= self.capacity {
            return Err(Error::Full);
        }

        self.by_sender
            .entry(tx.from)
            .or_default()
            .insert(tx.nonce, hash);
        self.txs.insert(hash, tx);
        Ok(hash)
    }

    /// Remove by hash; both indexes stay consistent.
    pub fn remove(&mut self, hash: &Hash) -> Option<Transaction> {
        let tx = self.txs.remove(hash)?;
        if let Some(by_nonce) = self.by_sender.get_mut(&tx.from) {
            by_nonce.remove(&tx.nonce);
            if by_nonce.is_empty() {
                self.by_sender.remove(&tx.from);
            }
        }
        Some(tx)
    }

    pub fn get(&self, hash: &Hash) -> Option<&Transaction> {
        self.txs.get(hash)
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.txs.contains_key(hash)
    }

    /// All pending tx; iteration order is unspecified.
    pub fn pending(&self) -> Vec<Transaction> {
        self.txs.values().cloned().collect()
    }

    /// Pending tx from `sender`, in ascending nonce order.
    pub fn pending_from(&self, sender: &[u8; 32]) -> Vec<Transaction> {
        let Some(by_nonce) = self.by_sender.get(sender) else {
            return Vec::new();
        };
        by_nonce
            .values()
            .filter_map(|h| self.txs.get(h).cloned())
            .collect()
    }

    /// Smallest pending nonce for `sender`.
    pub fn lowest_nonce(&self, sender: &[u8; 32]) -> Option<u64> {
        self.by_sender.get(sender)?.keys().next().copied()
    }

    /// All addresses that currently have pending tx.
    pub fn senders(&self) -> Vec<[u8; 32]> {
        self.by_sender.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn signed_tx(signer: &SigningKey, amount: u64, nonce: u64) -> Transaction {
        Transaction::signed(signer, [9u8; 32], amount, nonce)
    }

    #[test]
    fn insert_signed_tx_succeeds() {
        let mut pool = Mempool::new();
        let tx = signed_tx(&keypair(), 100, 0);
        assert!(pool.insert(tx).is_ok());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn unsigned_tx_is_rejected() {
        let mut pool = Mempool::new();
        let key = keypair();
        let tx = Transaction {
            from: key.verifying_key().to_bytes(),
            to: [9u8; 32],
            amount: 1,
            nonce: 0,
            signature: None,
        };
        assert!(matches!(pool.insert(tx), Err(Error::InvalidSignature(_))));
        assert!(pool.is_empty());
    }

    #[test]
    fn zero_amount_is_rejected() {
        let mut pool = Mempool::new();
        let tx = signed_tx(&keypair(), 0, 0);
        assert!(matches!(pool.insert(tx), Err(Error::ZeroAmount)));
    }

    #[test]
    fn duplicate_hash_is_rejected() {
        let mut pool = Mempool::new();
        let tx = signed_tx(&keypair(), 100, 0);
        pool.insert(tx.clone()).unwrap();
        assert!(matches!(pool.insert(tx), Err(Error::Duplicate)));
    }

    #[test]
    fn same_sender_same_nonce_is_rejected() {
        let mut pool = Mempool::new();
        let key = keypair();
        pool.insert(signed_tx(&key, 100, 0)).unwrap();
        // same sender+nonce, different amount → different hash
        let conflict = signed_tx(&key, 200, 0);
        assert!(matches!(
            pool.insert(conflict),
            Err(Error::NonceConflict { nonce: 0 })
        ));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn same_sender_different_nonce_both_accepted() {
        let mut pool = Mempool::new();
        let key = keypair();
        pool.insert(signed_tx(&key, 100, 0)).unwrap();
        pool.insert(signed_tx(&key, 200, 1)).unwrap();
        pool.insert(signed_tx(&key, 300, 2)).unwrap();
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn pending_from_returns_nonce_sorted() {
        let mut pool = Mempool::new();
        let key = keypair();
        // insert out of nonce order
        pool.insert(signed_tx(&key, 30, 2)).unwrap();
        pool.insert(signed_tx(&key, 10, 0)).unwrap();
        pool.insert(signed_tx(&key, 20, 1)).unwrap();

        let nonces: Vec<u64> = pool
            .pending_from(&key.verifying_key().to_bytes())
            .iter()
            .map(|tx| tx.nonce)
            .collect();
        assert_eq!(nonces, vec![0, 1, 2]);
    }

    #[test]
    fn lowest_nonce_tracks_min() {
        let mut pool = Mempool::new();
        let key = keypair();
        let addr = key.verifying_key().to_bytes();
        assert_eq!(pool.lowest_nonce(&addr), None);

        pool.insert(signed_tx(&key, 1, 5)).unwrap();
        pool.insert(signed_tx(&key, 1, 3)).unwrap();
        pool.insert(signed_tx(&key, 1, 7)).unwrap();
        assert_eq!(pool.lowest_nonce(&addr), Some(3));
    }

    #[test]
    fn capacity_is_enforced() {
        let mut pool = Mempool::with_capacity(2);
        // distinct senders so nonces don't collide
        pool.insert(signed_tx(&keypair(), 1, 0)).unwrap();
        pool.insert(signed_tx(&keypair(), 1, 0)).unwrap();
        let overflow = signed_tx(&keypair(), 1, 0);
        assert!(matches!(pool.insert(overflow), Err(Error::Full)));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn remove_keeps_indexes_consistent() {
        let mut pool = Mempool::new();
        let key = keypair();
        let addr = key.verifying_key().to_bytes();
        let h1 = pool.insert(signed_tx(&key, 10, 0)).unwrap();
        let h2 = pool.insert(signed_tx(&key, 20, 1)).unwrap();

        // remove nonce=0 → lowest advances to 1
        let removed = pool.remove(&h1).expect("present");
        assert_eq!(removed.nonce, 0);
        assert_eq!(pool.lowest_nonce(&addr), Some(1));

        // remove nonce=1 → sender entry disappears entirely
        pool.remove(&h2).expect("present");
        assert_eq!(pool.lowest_nonce(&addr), None);
        assert!(pool.is_empty());
    }

    #[test]
    fn remove_missing_returns_none() {
        let mut pool = Mempool::new();
        let bogus = nanochain_types::zero_hash();
        assert!(pool.remove(&bogus).is_none());
    }
}
