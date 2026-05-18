pub type Address = [u8; 32];

/// Initial balances credited directly into state at bootstrap (the Ethereum
/// `alloc` model). The genesis block itself stays an empty header.
///
/// TODO: load from a TOML/JSON file instead of building it in code.
#[derive(Debug, Clone, Default)]
pub struct GenesisConfig {
    /// Initial `(address, balance)` pairs.
    pub allocations: Vec<(Address, u64)>,
}
