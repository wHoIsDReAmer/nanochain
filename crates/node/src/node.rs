use ed25519_dalek::SigningKey;
use nanochain_consensus::{build_block, BuildParams};
use nanochain_mempool::Mempool;
use nanochain_network::{Network, NetworkConfig};
use nanochain_storage::{BlockStore, StateStore};
use nanochain_types::{Block, Hash, Transaction};
use std::time::Duration;
use tracing::info;

use crate::{error::Error, genesis::GenesisConfig};

const MAX_TXS_PER_BLOCK: usize = 1024;

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

        // Let peer handshakes settle, then announce our pending transactions
        // once to every connected peer. Stragglers are covered by the relay.
        context.sleep(Duration::from_secs(3)).await;
        for tx in self.mempool.pending() {
            let hash = tx.hash();
            let wire = serde_json::to_vec(&tx).expect("serialize tx");
            let peers = network.broadcast(wire).await;
            info!(seed, %hash, peers, "announced tx");
        }

        // Admit transactions received from peers, then flood them onward.
        loop {
            let bytes = match network.recv().await {
                Some(b) => b,
                None => break, // network shut down
            };
            let tx: Transaction = match serde_json::from_slice(&bytes) {
                Ok(tx) => tx,
                Err(e) => {
                    info!(seed, error = %e, "undecodable message");
                    continue;
                }
            };
            let hash = tx.hash();
            match self.mempool.insert(tx) {
                Ok(_) => {
                    info!(seed, %hash, pending = self.mempool.len(), "admitted peer tx");
                    // Relay onward. Peers that already hold the tx reject the
                    // duplicate and stop relaying, so the flood dies out.
                    network.broadcast(bytes).await;
                }
                Err(e) => info!(seed, %hash, error = %e, "dropped peer tx"),
            }
        }
    }
}
