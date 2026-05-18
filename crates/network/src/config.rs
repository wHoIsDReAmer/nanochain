use std::net::SocketAddr;

/// p2p identity and peer directory for one node. Identities are derived
/// deterministically from `u64` seeds so a devnet can wire peers up without a
/// key-distribution step.
pub struct NetworkConfig {
    /// Seed for this node's p2p identity key.
    pub seed: u64,
    /// Socket address this node listens on.
    pub listen: SocketAddr,
    /// `(seed, address)` of every node in the network, including self.
    pub peers: Vec<(u64, SocketAddr)>,
}
