//! nanochain node entry point.
//!
//! Run `nanochain --seed <N>` to launch the node with that identity. Launch
//! several processes with distinct seeds (1, 2, 3) for a local devnet — they
//! find each other through the shared `devnet` roster and gossip transactions.

use commonware_runtime::{tokio::Runner as RuntimeRunner, Runner as _};
use ed25519_dalek::SigningKey;
use nanochain_node::{GenesisConfig, NetworkConfig, Node};
use nanochain_types::Transaction;
use rand_core::OsRng;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn devnet() -> Vec<(u64, SocketAddr)> {
    vec![
        (1, "127.0.0.1:4001".parse().unwrap()),
        (2, "127.0.0.1:4002".parse().unwrap()),
        (3, "127.0.0.1:4003".parse().unwrap()),
    ]
}

fn main() {
    init_tracing();
    let seed = parse_seed();

    let roster = devnet();
    let listen = roster
        .iter()
        .find(|(s, _)| *s == seed)
        .map(|(_, addr)| *addr)
        .unwrap_or_else(|| panic!("seed {seed} is not in the devnet roster"));

    let executor = RuntimeRunner::default();
    executor.start(|context| async move {
        let mut node = Node::bootstrap(GenesisConfig::default(), SigningKey::generate(&mut OsRng));

        // Inject one demo transaction so the node has something to announce.
        // Future: an RPC server feeds real user transactions here.
        let wallet = SigningKey::generate(&mut OsRng);
        node.submit_tx(Transaction::signed(&wallet, [0xBBu8; 32], 100, 0))
            .expect("valid tx");

        info!(seed, %listen, peers = roster.len(), "nanochain node starting");
        node.run(
            context,
            NetworkConfig {
                seed,
                listen,
                peers: roster,
            },
        )
        .await;
    });
}

fn parse_seed() -> u64 {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--seed" {
            return args
                .next()
                .and_then(|v| v.parse().ok())
                .expect("--seed requires a number");
        }
    }
    panic!("usage: nanochain --seed <N>");
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .compact()
        .init();
}
