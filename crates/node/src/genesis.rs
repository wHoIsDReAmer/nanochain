use nanochain_types::{Block, Hash, Transaction};

pub type Address = [u8; 32];

/// Initial state baked into the genesis block; identical config → identical
/// genesis hash across nodes.
///
/// TODO: load from a TOML/JSON file instead of building it in code.
#[derive(Debug, Clone, Default)]
pub struct GenesisConfig {
    /// Initial `(address, balance)` pairs minted as coinbase tx at height 0.
    pub allocations: Vec<(Address, u64)>,
    /// Genesis block timestamp (Unix seconds). Defaults to 0 if unspecified.
    pub timestamp: u64,
}

impl GenesisConfig {
    /// Build the genesis block: one coinbase tx per allocation.
    pub fn into_block(&self) -> Block {
        let txs: Vec<Transaction> = self
            .allocations
            .iter()
            .enumerate()
            .map(|(i, (addr, amount))| Transaction::coinbase(*addr, *amount, i as u64))
            .collect();
        Block::new(0, Hash::zero(), self.timestamp, [0u8; 32], txs)
    }
}
