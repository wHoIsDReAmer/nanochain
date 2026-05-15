use crate::Error;
use ed25519_dalek::SigningKey;
use nanochain_mempool::Mempool;
use nanochain_storage::StateStore;
use nanochain_types::{Block, SignedBlock, Transaction};

/// Inputs that pin down a build attempt.
pub struct BuildParams<'a> {
    pub parent: &'a Block,
    pub timestamp: u64,
    pub proposer: &'a SigningKey,
    /// Hard cap on transactions selected into the block.
    pub max_txs: usize,
}

/// Greedily walk the mempool and assemble the next block.
pub fn build_block(
    params: BuildParams<'_>,
    mempool: &Mempool,
    state: &StateStore,
) -> Result<SignedBlock, Error> {
    let mut shadow = state.clone();
    let mut selected: Vec<Transaction> = Vec::new();

    'senders: for sender in mempool.senders() {
        for tx in mempool.pending_from(&sender) {
            if selected.len() >= params.max_txs {
                break 'senders;
            }
            if shadow.apply_transaction(&tx).is_ok() {
                selected.push(tx);
            } else {
                break; // gap or invalid for this sender; later nonces are unusable
            }
        }
    }

    let height = params.parent.header.height + 1;
    let parent_hash = params.parent.hash();
    let proposer_pub = params.proposer.verifying_key().to_bytes();

    let block = Block::new(
        height,
        parent_hash,
        params.timestamp,
        proposer_pub,
        selected,
    );
    Ok(SignedBlock::sign(block, params.proposer)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanochain_types::Block;
    use rand_core::OsRng;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn addr(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    fn genesis() -> Block {
        Block::genesis()
    }

    fn params<'a>(parent: &'a Block, proposer: &'a SigningKey, max_txs: usize) -> BuildParams<'a> {
        BuildParams {
            parent,
            timestamp: 1,
            proposer,
            max_txs,
        }
    }

    #[test]
    fn empty_mempool_yields_empty_block() {
        let proposer = keypair();
        let parent = genesis();
        let pool = Mempool::new();
        let state = StateStore::new();

        let sb = build_block(params(&parent, &proposer, 100), &pool, &state).unwrap();
        assert!(sb.block.transactions.is_empty());
        assert_eq!(sb.block.header.height, 1);
        assert_eq!(sb.block.header.parent_hash, parent.hash());
        assert!(sb.verify().is_ok());
    }

    #[test]
    fn includes_valid_tx_from_single_sender() {
        let proposer = keypair();
        let alice = keypair();
        let bob = [9u8; 32];

        let mut pool = Mempool::new();
        let mut state = StateStore::new();
        state.credit(addr(&alice), 100);

        let tx = Transaction::signed(&alice, bob, 30, 0);
        pool.insert(tx.clone()).unwrap();

        let sb = build_block(params(&genesis(), &proposer, 100), &pool, &state).unwrap();
        assert_eq!(sb.block.transactions.len(), 1);
        assert_eq!(sb.block.transactions[0].nonce, 0);
        assert!(sb.verify().is_ok());
    }

    #[test]
    fn sequential_nonces_from_same_sender_are_packed_in_order() {
        let proposer = keypair();
        let alice = keypair();
        let bob = [9u8; 32];

        let mut pool = Mempool::new();
        let mut state = StateStore::new();
        state.credit(addr(&alice), 100);

        pool.insert(Transaction::signed(&alice, bob, 10, 0))
            .unwrap();
        pool.insert(Transaction::signed(&alice, bob, 10, 1))
            .unwrap();
        pool.insert(Transaction::signed(&alice, bob, 10, 2))
            .unwrap();

        let sb = build_block(params(&genesis(), &proposer, 100), &pool, &state).unwrap();
        let nonces: Vec<u64> = sb.block.transactions.iter().map(|t| t.nonce).collect();
        assert_eq!(nonces, vec![0, 1, 2]);
    }

    #[test]
    fn nonce_gap_stops_sender_early() {
        let proposer = keypair();
        let alice = keypair();
        let bob = [9u8; 32];

        let mut pool = Mempool::new();
        let mut state = StateStore::new();
        state.credit(addr(&alice), 100);

        // nonce 0 missing → 1 and 2 are unusable
        pool.insert(Transaction::signed(&alice, bob, 10, 1))
            .unwrap();
        pool.insert(Transaction::signed(&alice, bob, 10, 2))
            .unwrap();

        let sb = build_block(params(&genesis(), &proposer, 100), &pool, &state).unwrap();
        assert!(sb.block.transactions.is_empty());
    }

    #[test]
    fn respects_max_txs() {
        let proposer = keypair();
        let alice = keypair();
        let bob = [9u8; 32];

        let mut pool = Mempool::new();
        let mut state = StateStore::new();
        state.credit(addr(&alice), 1000);

        for n in 0..5 {
            pool.insert(Transaction::signed(&alice, bob, 1, n)).unwrap();
        }

        let sb = build_block(params(&genesis(), &proposer, 3), &pool, &state).unwrap();
        assert_eq!(sb.block.transactions.len(), 3);
    }

    #[test]
    fn skips_sender_with_insufficient_balance() {
        let proposer = keypair();
        let alice = keypair(); // funded
        let bob_key = keypair(); // unfunded sender
        let dest = [9u8; 32];

        let mut pool = Mempool::new();
        let mut state = StateStore::new();
        state.credit(addr(&alice), 100);
        // bob has zero balance; his tx will fail dry-run

        pool.insert(Transaction::signed(&alice, dest, 30, 0))
            .unwrap();
        pool.insert(Transaction::signed(&bob_key, dest, 30, 0))
            .unwrap();

        let sb = build_block(params(&genesis(), &proposer, 100), &pool, &state).unwrap();
        assert_eq!(sb.block.transactions.len(), 1);
        assert_eq!(sb.block.transactions[0].from, addr(&alice));
    }

    #[test]
    fn produced_block_applies_cleanly_against_state() {
        // End-to-end: build a block, then apply it to a fresh state clone.
        let proposer = keypair();
        let alice = keypair();
        let bob = [9u8; 32];

        let mut pool = Mempool::new();
        let mut state = StateStore::new();
        state.credit(addr(&alice), 100);

        pool.insert(Transaction::signed(&alice, bob, 30, 0))
            .unwrap();
        pool.insert(Transaction::signed(&alice, bob, 20, 1))
            .unwrap();

        let sb = build_block(params(&genesis(), &proposer, 100), &pool, &state).unwrap();

        // Replay on the original state — must succeed.
        state.apply_block(&sb.block).unwrap();
        assert_eq!(state.get_balance(&addr(&alice)), 50);
        assert_eq!(state.get_balance(&bob), 50);
        assert_eq!(state.get_nonce(&addr(&alice)), 2);
    }

    #[test]
    fn signed_block_uses_proposer_pubkey() {
        let proposer = keypair();
        let parent = genesis();
        let pool = Mempool::new();
        let state = StateStore::new();

        let sb = build_block(params(&parent, &proposer, 0), &pool, &state).unwrap();
        assert_eq!(sb.proposer(), addr(&proposer));
        assert!(sb.verify().is_ok());
    }
}
