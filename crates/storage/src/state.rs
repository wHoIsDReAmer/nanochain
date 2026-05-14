use crate::Error;
use nanochain_types::{Block, Transaction};
use std::collections::HashMap;

/// Account state: balance plus the next expected transaction nonce.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
}

/// In-memory account-model state store. Missing accounts read as
/// `Account::default()` (balance=0, nonce=0).
pub struct StateStore {
    accounts: HashMap<[u8; 32], Account>,
}

impl StateStore {
    pub fn new() -> Self {
        StateStore {
            accounts: HashMap::new(),
        }
    }

    pub fn get_balance(&self, account: &[u8; 32]) -> u64 {
        self.accounts.get(account).map_or(0, |a| a.balance)
    }

    pub fn get_nonce(&self, account: &[u8; 32]) -> u64 {
        self.accounts.get(account).map_or(0, |a| a.nonce)
    }

    pub fn get_account(&self, account: &[u8; 32]) -> Account {
        self.accounts.get(account).cloned().unwrap_or_default()
    }

    /// Genesis / test helper: directly add to an account's balance, bypassing
    /// transaction validation. Used to seed initial balances since regular
    /// transfers can only move coins between existing accounts.
    pub fn credit(&mut self, account: [u8; 32], amount: u64) {
        self.accounts.entry(account).or_default().balance += amount;
    }

    /// Apply a single transaction. Validates signature, nonce, balance, and
    /// recipient overflow *before* any mutation; partial application is
    /// impossible — either everything succeeds or state is untouched.
    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), Error> {
        tx.verify_signature()?;

        let expected = self.get_nonce(&tx.from);
        if expected != tx.nonce {
            return Err(Error::InvalidNonce {
                expected,
                got: tx.nonce,
            });
        }

        let from_balance = self.get_balance(&tx.from);
        if from_balance < tx.amount {
            return Err(Error::InsufficientBalance {
                have: from_balance,
                need: tx.amount,
            });
        }

        // Self-transfer is a valid pattern (used to "cancel" a nonce or bump
        // gas in real chains). The net balance change is zero, so an overflow
        // check is meaningless — skip it. For distinct recipients, ensure
        // the addition doesn't wrap u64.
        if tx.from != tx.to {
            let to_balance = self.get_balance(&tx.to);
            if to_balance.checked_add(tx.amount).is_none() {
                return Err(Error::BalanceOverflow);
            }
        }

        // All checks passed; apply.
        {
            let from = self.accounts.entry(tx.from).or_default();
            from.balance -= tx.amount;
            from.nonce += 1;
        }
        if tx.from != tx.to {
            let to = self.accounts.entry(tx.to).or_default();
            to.balance += tx.amount;
        } else {
            // self-transfer: refund the just-debited amount so balance is unchanged.
            self.accounts.entry(tx.from).or_default().balance += tx.amount;
        }
        Ok(())
    }

    /// Apply every transaction in a block atomically. If any transaction
    /// fails validation, every prior tx in the block is rolled back and the
    /// error is returned. A successful call commits the entire block.
    pub fn apply_block(&mut self, block: &Block) -> Result<(), Error> {
        let snapshot = self.accounts.clone();
        for tx in &block.transactions {
            if let Err(e) = self.apply_transaction(tx) {
                self.accounts = snapshot;
                return Err(e);
            }
        }
        Ok(())
    }
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use nanochain_types::{Block, Hash};
    use rand_core::OsRng;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn addr(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    fn block_with(txs: Vec<Transaction>) -> Block {
        Block::new(1, Hash::zero(), 0, [0u8; 32], txs)
    }

    #[test]
    fn missing_account_reads_as_zero() {
        let state = StateStore::new();
        assert_eq!(state.get_balance(&[0u8; 32]), 0);
        assert_eq!(state.get_nonce(&[0u8; 32]), 0);
    }

    #[test]
    fn credit_seeds_balance() {
        let mut state = StateStore::new();
        let alice = [1u8; 32];
        state.credit(alice, 100);
        assert_eq!(state.get_balance(&alice), 100);
        state.credit(alice, 50);
        assert_eq!(state.get_balance(&alice), 150);
    }

    #[test]
    fn happy_transfer_moves_funds_and_bumps_nonce() {
        let alice_key = keypair();
        let alice = addr(&alice_key);
        let bob = [9u8; 32];

        let mut state = StateStore::new();
        state.credit(alice, 100);

        let tx = Transaction::signed(&alice_key, bob, 30, 0);
        state.apply_transaction(&tx).unwrap();

        assert_eq!(state.get_balance(&alice), 70);
        assert_eq!(state.get_balance(&bob), 30);
        assert_eq!(state.get_nonce(&alice), 1);
        assert_eq!(state.get_nonce(&bob), 0); // recipient nonce untouched
    }

    #[test]
    fn wrong_nonce_is_rejected() {
        let alice_key = keypair();
        let alice = addr(&alice_key);
        let mut state = StateStore::new();
        state.credit(alice, 100);

        // alice's expected nonce is 0; submit nonce=5
        let tx = Transaction::signed(&alice_key, [9u8; 32], 10, 5);
        let err = state.apply_transaction(&tx).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidNonce {
                expected: 0,
                got: 5
            }
        ));
        // state untouched
        assert_eq!(state.get_balance(&alice), 100);
        assert_eq!(state.get_nonce(&alice), 0);
    }

    #[test]
    fn insufficient_balance_is_rejected() {
        let alice_key = keypair();
        let alice = addr(&alice_key);
        let mut state = StateStore::new();
        state.credit(alice, 50);

        let tx = Transaction::signed(&alice_key, [9u8; 32], 100, 0);
        let err = state.apply_transaction(&tx).unwrap_err();
        assert!(matches!(
            err,
            Error::InsufficientBalance {
                have: 50,
                need: 100
            }
        ));
        assert_eq!(state.get_balance(&alice), 50);
        assert_eq!(state.get_nonce(&alice), 0);
    }

    #[test]
    fn overflow_on_recipient_is_rejected() {
        let alice_key = keypair();
        let alice = addr(&alice_key);
        let bob = [9u8; 32];
        let mut state = StateStore::new();
        state.credit(alice, u64::MAX);
        state.credit(bob, u64::MAX); // bob already at max

        let tx = Transaction::signed(&alice_key, bob, 1, 0);
        let err = state.apply_transaction(&tx).unwrap_err();
        assert!(matches!(err, Error::BalanceOverflow));
    }

    #[test]
    fn self_transfer_only_bumps_nonce() {
        let alice_key = keypair();
        let alice = addr(&alice_key);
        let mut state = StateStore::new();
        state.credit(alice, 100);

        let tx = Transaction::signed(&alice_key, alice, 30, 0);
        state.apply_transaction(&tx).unwrap();

        assert_eq!(state.get_balance(&alice), 100); // unchanged
        assert_eq!(state.get_nonce(&alice), 1); // bumped
    }

    #[test]
    fn unsigned_tx_is_rejected() {
        let alice_key = keypair();
        let alice = addr(&alice_key);
        let mut state = StateStore::new();
        state.credit(alice, 100);

        let tx = Transaction {
            from: alice,
            to: [9u8; 32],
            amount: 10,
            nonce: 0,
            signature: None,
        };
        let err = state.apply_transaction(&tx).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature(_)));
    }

    #[test]
    fn block_with_sequential_txs_from_same_sender() {
        let alice_key = keypair();
        let alice = addr(&alice_key);
        let bob = [9u8; 32];
        let mut state = StateStore::new();
        state.credit(alice, 100);

        let block = block_with(vec![
            Transaction::signed(&alice_key, bob, 10, 0),
            Transaction::signed(&alice_key, bob, 20, 1),
            Transaction::signed(&alice_key, bob, 30, 2),
        ]);
        state.apply_block(&block).unwrap();

        assert_eq!(state.get_balance(&alice), 40);
        assert_eq!(state.get_balance(&bob), 60);
        assert_eq!(state.get_nonce(&alice), 3);
    }

    #[test]
    fn block_rolls_back_atomically_on_failure() {
        let alice_key = keypair();
        let alice = addr(&alice_key);
        let bob = [9u8; 32];
        let mut state = StateStore::new();
        state.credit(alice, 100);

        // Second tx has bad nonce — block must reject entirely.
        let block = block_with(vec![
            Transaction::signed(&alice_key, bob, 10, 0),
            Transaction::signed(&alice_key, bob, 20, 99), // wrong nonce
        ]);
        assert!(state.apply_block(&block).is_err());

        // First tx's effects must be rolled back too.
        assert_eq!(state.get_balance(&alice), 100);
        assert_eq!(state.get_balance(&bob), 0);
        assert_eq!(state.get_nonce(&alice), 0);
    }

    #[test]
    fn empty_block_is_a_noop() {
        let mut state = StateStore::new();
        state.credit([1u8; 32], 100);
        let block = block_with(vec![]);
        state.apply_block(&block).unwrap();
        assert_eq!(state.get_balance(&[1u8; 32]), 100);
    }
}
