use ed25519_dalek::SigningKey;
use nanochain_consensus::{build_block, BuildParams};
use nanochain_mempool::Mempool;
use nanochain_storage::{BlockStore, StateStore};
use nanochain_types::{Block, Hash, Transaction};

use crate::{error::Error, genesis::GenesisConfig};

const MAX_TXS_PER_BLOCK: usize = 1024;

/// In-process node owning mempool + state + block store.
/// No network/consensus yet — `produce_block` assumes this node is the leader.
pub struct Node {
    state: StateStore,
    blocks: BlockStore,
    mempool: Mempool,
    signer: SigningKey,
}

impl Node {
    /// Build the genesis block, apply it to fresh state, and store it.
    pub fn bootstrap(genesis: GenesisConfig, signer: SigningKey) -> Self {
        let mut state = StateStore::new();
        let mut blocks = BlockStore::new();

        let genesis_block = genesis.into_block();
        state
            .apply_block(&genesis_block)
            .expect("genesis allocations must apply cleanly");
        blocks.insert(genesis_block);

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
}
