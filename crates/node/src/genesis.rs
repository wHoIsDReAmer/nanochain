pub type Address = [u8; 32];

/// Configuration consumed once at bootstrap time to seed the initial state.
///
/// TODO: load this from a TOML / JSON file (clap + serde) instead of building
/// it in code, so genesis is reproducible across node restarts.
#[derive(Debug, Clone, Default)]
pub struct GenesisConfig {
    /// Initial `(address, balance)` pairs credited before any block runs.
    pub allocations: Vec<(Address, u64)>,
}
