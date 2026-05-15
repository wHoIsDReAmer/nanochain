//! Thin entry point: wire up tracing, build a `Node` from genesis, and run
//! one round of traffic. Sections marked `Future:` are the seams where CLI
//! parsing, RPC input, and the consensus-driven block loop will attach.

use ed25519_dalek::SigningKey;
use nanochain_node::{GenesisConfig, Node};
use nanochain_types::Transaction;
use rand_core::OsRng;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() {
    init_tracing();
    info!("nanochain bootstrapping");

    // Future: parse CLI args (clap) and load genesis/config from TOML.
    let signer = SigningKey::generate(&mut OsRng);
    let demo = DemoActors::generate();
    let mut node = Node::bootstrap(demo.genesis_config(), signer);

    info!(
        height = node.tip_height(),
        tip = %short_hash(&node.tip_hash().0),
        proposer = %short_addr(&node.proposer_pubkey()),
        "node ready",
    );
    log_balances("genesis", &node, &demo);

    // Future: an RPC server / CLI feeds `submit_tx`. Inline traffic for now.
    for tx in demo.traffic() {
        let from = short_addr(&tx.from);
        let nonce = tx.nonce;
        let amount = tx.amount;
        let hash = node.submit_tx(tx).expect("valid tx must be admitted");
        info!(from = %from, nonce, amount, hash = %short_hash(&hash.0), "tx submitted");
    }
    info!(pending = node.pending_tx_count(), "mempool populated");

    // Future: consensus loop drives this; for now just produce one round.
    let hash = node.produce_block(1).expect("produce_block");
    info!(
        height = node.tip_height(),
        hash = %short_hash(&hash.0),
        pending = node.pending_tx_count(),
        "round complete",
    );

    log_balances("final", &node, &demo);
}

// ---------- demo wiring (will move out once we have real inputs) ----------

struct DemoActors {
    alice: SigningKey,
    bob: SigningKey,
    charlie_addr: [u8; 32],
}

impl DemoActors {
    fn generate() -> Self {
        Self {
            alice: SigningKey::generate(&mut OsRng),
            bob: SigningKey::generate(&mut OsRng),
            charlie_addr: [0xCCu8; 32],
        }
    }

    fn alice_addr(&self) -> [u8; 32] {
        self.alice.verifying_key().to_bytes()
    }

    fn bob_addr(&self) -> [u8; 32] {
        self.bob.verifying_key().to_bytes()
    }

    fn genesis_config(&self) -> GenesisConfig {
        GenesisConfig {
            allocations: vec![(self.alice_addr(), 1_000), (self.bob_addr(), 500)],
            timestamp: 0,
        }
    }

    fn traffic(&self) -> Vec<Transaction> {
        vec![
            Transaction::signed(&self.alice, self.bob_addr(), 200, 0),
            Transaction::signed(&self.alice, self.charlie_addr, 100, 1),
            Transaction::signed(&self.bob, self.charlie_addr, 50, 0),
        ]
    }
}

// ---------- helpers ----------

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .compact()
        .init();
}

fn log_balances(stage: &str, node: &Node, demo: &DemoActors) {
    info!(
        stage,
        alice_balance = node.balance(&demo.alice_addr()),
        alice_nonce = node.nonce(&demo.alice_addr()),
        bob_balance = node.balance(&demo.bob_addr()),
        bob_nonce = node.nonce(&demo.bob_addr()),
        charlie_balance = node.balance(&demo.charlie_addr),
        "balances",
    );
}

fn short_addr(bytes: &[u8; 32]) -> String {
    format!("0x{}…", hex::encode(&bytes[..4]))
}

fn short_hash(bytes: &[u8; 32]) -> String {
    format!("0x{}…", hex::encode(&bytes[..6]))
}
