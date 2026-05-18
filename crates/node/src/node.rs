use ed25519_dalek::SigningKey;
use nanochain_consensus::{build_block, BuildParams};
use nanochain_mempool::Mempool;
use nanochain_network::{Network, NetworkConfig};
use nanochain_storage::{BlockStore, StateStore};
use nanochain_types::{Block, Hash, Transaction};
use std::time::Duration;
use tokio::select;
use tracing::info;

use crate::{error::Error, genesis::GenesisConfig};

const MAX_TXS_PER_BLOCK: usize = 1024;
/// How often a node re-announces its mempool, so peers that connect late
/// (or reconnect) still converge.
const ANNOUNCE_INTERVAL_SECS: u64 = 3;

/// In-process node owning mempool + state + block store.
/// No consensus yet — `produce_block` assumes this node is the leader.
pub struct Node {
    state: StateStore,
    blocks: BlockStore,
    mempool: Mempool,
    signer: SigningKey,
}

impl Node {
    /// Credit genesis allocations directly into state, store the (empty)
    /// genesis block, and remember the proposer key.
    pub fn bootstrap(genesis: GenesisConfig, signer: SigningKey) -> Self {
        let mut state = StateStore::new();
        for (addr, balance) in &genesis.allocations {
            state.credit(*addr, *balance);
        }

        let mut blocks = BlockStore::new();
        blocks.insert(Block::genesis());

        Self {
            state,
            blocks,
            mempool: Mempool::new(),
            signer,
        }
    }

    /// Admit a tx into the mempool after validation.
    pub fn submit_tx(&mut self, tx: Transaction) -> Result<Hash, Error> {
        Ok(self.mempool.insert(tx)?)
    }

    /// Build → sign → verify → apply → persist one block. Returns its hash.
    pub fn produce_block(&mut self, timestamp: u64) -> Result<Hash, Error> {
        let parent = self
            .blocks
            .tip()
            .ok_or(Error::Internal("missing tip"))?
            .clone();

        let signed = build_block(
            BuildParams {
                parent: &parent,
                timestamp,
                proposer: &self.signer,
                max_txs: MAX_TXS_PER_BLOCK,
            },
            &self.mempool,
            &self.state,
        )?;

        signed.verify()?;
        self.state.apply_block(&signed.block)?;

        for tx in &signed.block.transactions {
            self.mempool.remove(&tx.hash());
        }

        let hash = signed.block.hash();
        self.blocks.insert(signed.block);
        Ok(hash)
    }

    pub fn tip(&self) -> &Block {
        self.blocks.tip().expect("genesis is always present")
    }

    pub fn tip_height(&self) -> u64 {
        self.tip().header.height
    }

    pub fn tip_hash(&self) -> Hash {
        self.tip().hash()
    }

    pub fn balance(&self, account: &[u8; 32]) -> u64 {
        self.state.get_balance(account)
    }

    pub fn nonce(&self, account: &[u8; 32]) -> u64 {
        self.state.get_nonce(account)
    }

    pub fn pending_tx_count(&self) -> usize {
        self.mempool.len()
    }

    pub fn proposer_pubkey(&self) -> [u8; 32] {
        self.signer.verifying_key().to_bytes()
    }

    /// Run forever: start the p2p network, announce the local mempool to
    /// peers, then admit (and relay) every transaction received from peers.
    pub async fn run<E>(mut self, context: E, net: NetworkConfig)
    where
        E: commonware_runtime::Spawner
            + commonware_runtime::Clock
            + commonware_runtime::Metrics
            + commonware_runtime::Network
            + commonware_runtime::Resolver
            + commonware_runtime::BufferPooler
            + rand_core::CryptoRngCore,
    {
        let seed = net.seed;
        let mut network = Network::start(&context, &net).await;
        info!(seed, "node network started");

        let announce_interval = Duration::from_secs(ANNOUNCE_INTERVAL_SECS);
        let mut next_announce = context.current() + announce_interval;

        loop {
            select! {
                _ = context.sleep_until(next_announce) => {
                    for tx in self.mempool.pending() {
                        let wire = serde_json::to_vec(&tx).expect("serialize tx");
                        network.broadcast(wire).await;
                    }
                    next_announce = context.current() + announce_interval;
                }

                received = network.recv() => {
                    let bytes = match received {
                        Some(b) => b,
                        None => break, // network shut down
                    };
                    match serde_json::from_slice::<Transaction>(&bytes) {
                        Ok(tx) => {
                            let hash = tx.hash();
                            match self.mempool.insert(tx) {
                                Ok(_) => {
                                    info!(
                                        seed,
                                        %hash,
                                        pending = self.mempool.len(),
                                        "admitted peer tx",
                                    );

                                    network.broadcast(bytes).await;
                                }
                                Err(e) => {
                                    info!(seed, %hash, error = %e, "dropped peer tx")
                                }
                            }
                        }
                        Err(e) => info!(seed, error = %e, "undecodable message"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn addr(k: &SigningKey) -> [u8; 32] {
        k.verifying_key().to_bytes()
    }

    #[test]
    fn fresh_node_tip_is_genesis() {
        let node = Node::bootstrap(GenesisConfig::default(), keypair());
        assert_eq!(node.tip_height(), 0);
        assert_eq!(node.pending_tx_count(), 0);
    }

    #[test]
    fn bootstrap_applies_genesis_allocations() {
        let alice = [1u8; 32];
        let genesis = GenesisConfig {
            allocations: vec![(alice, 1_000)],
        };
        let node = Node::bootstrap(genesis, keypair());
        assert_eq!(node.balance(&alice), 1_000);
    }

    #[test]
    fn submit_tx_admits_signed_tx() {
        let mut node = Node::bootstrap(GenesisConfig::default(), keypair());
        let tx = Transaction::signed(&keypair(), [9u8; 32], 100, 0);
        node.submit_tx(tx).expect("admitted");
        assert_eq!(node.pending_tx_count(), 1);
    }

    #[test]
    fn submit_tx_rejects_unsigned() {
        let mut node = Node::bootstrap(GenesisConfig::default(), keypair());
        let tx = Transaction {
            from: [1u8; 32],
            to: [2u8; 32],
            amount: 1,
            nonce: 0,
            signature: None,
        };
        assert!(node.submit_tx(tx).is_err());
        assert_eq!(node.pending_tx_count(), 0);
    }

    #[test]
    fn produce_block_advances_tip_and_moves_funds() {
        let alice = keypair();
        let bob = [9u8; 32];
        let genesis = GenesisConfig {
            allocations: vec![(addr(&alice), 1_000)],
        };
        let mut node = Node::bootstrap(genesis, keypair());

        node.submit_tx(Transaction::signed(&alice, bob, 300, 0))
            .unwrap();
        node.produce_block(1).expect("produce_block");

        assert_eq!(node.tip_height(), 1);
        assert_eq!(node.balance(&addr(&alice)), 700);
        assert_eq!(node.balance(&bob), 300);
        // included tx is dropped from the mempool
        assert_eq!(node.pending_tx_count(), 0);
    }
}
