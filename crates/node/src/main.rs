//! Thin entry point. `Future:` markers flag where CLI, RPC, and the
//! consensus loop will attach.

use commonware_cryptography::{ed25519, Signer as _};
use commonware_p2p::{
    authenticated::lookup::{self, Network as P2pNetwork},
    AddressableManager as _, Receiver as _, Recipients, Sender as _,
};
use commonware_runtime::{tokio::Runner as RuntimeRunner, Quota, Runner as _};
use commonware_utils::{ordered::Map, NZU32};
use ed25519_dalek::SigningKey;
use nanochain_mempool::Mempool;
use nanochain_node::{GenesisConfig, Node};
use nanochain_types::Transaction;
use rand_core::OsRng;
use std::{net::SocketAddr, time::Duration};
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() {
    init_tracing();

    // commonware-runtime drives all async work. Node logic stays synchronous;
    // the p2p network runs on the async `context`.
    let executor = RuntimeRunner::default();
    executor.start(|context| async move {
        run_demo();
        p2p_tx_propagation(context).await;
    });
}

/// Stage 3 demo: node A signs a transaction, serializes it, and broadcasts it
/// over p2p to node B, which deserializes it and admits it to its mempool.
async fn p2p_tx_propagation<E>(context: E)
where
    E: commonware_runtime::Spawner
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + commonware_runtime::Network
        + commonware_runtime::Resolver
        + commonware_runtime::BufferPooler
        + rand_core::CryptoRngCore,
{
    const MAX_MSG: u32 = 1024 * 1024;
    const NAMESPACE: &[u8] = b"nanochain-net";

    // p2p identities (network layer) — distinct from transaction signing keys.
    let sk_a = ed25519::PrivateKey::from_seed(1);
    let sk_b = ed25519::PrivateKey::from_seed(2);
    let pk_a = sk_a.public_key();
    let pk_b = sk_b.public_key();
    let addr_a: SocketAddr = "127.0.0.1:4001".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:4002".parse().unwrap();

    let peers: Map<_, _> = Map::try_from(vec![
        (pk_a.clone(), addr_a.into()),
        (pk_b.clone(), addr_b.into()),
    ])
    .expect("peer map");

    let cfg_a = lookup::Config::local(sk_a, NAMESPACE, addr_a, MAX_MSG);
    let (mut net_a, mut oracle_a) = P2pNetwork::new(context.child("net_a"), cfg_a);
    oracle_a.track(0, peers.clone()).await;
    let (mut sender_a, _recv_a) = net_a.register(0, Quota::per_second(NZU32!(10)), 128);
    net_a.start();

    let cfg_b = lookup::Config::local(sk_b, NAMESPACE, addr_b, MAX_MSG);
    let (mut net_b, mut oracle_b) = P2pNetwork::new(context.child("net_b"), cfg_b);
    oracle_b.track(0, peers).await;
    let (_sender_b, mut recv_b) = net_b.register(0, Quota::per_second(NZU32!(10)), 128);
    net_b.start();

    info!("p2p: two networks started");

    // Node A builds a signed transaction and serializes it for the wire.
    let alice = SigningKey::generate(&mut OsRng);
    let tx = Transaction::signed(&alice, [0xBBu8; 32], 100, 0);
    let wire = serde_json::to_vec(&tx).expect("serialize tx");
    info!(
        hash = %short_hash(&tx.hash().0),
        bytes = wire.len(),
        "p2p: net_a broadcasting tx",
    );

    // A → B, retrying until the handshake completes.
    loop {
        let sent = sender_a
            .send(Recipients::One(pk_b.clone()), wire.clone(), true)
            .await
            .expect("send");
        if !sent.is_empty() {
            break;
        }
        context.sleep(Duration::from_millis(200)).await;
    }

    // Node B receives, deserializes, and admits the tx to a fresh mempool.
    // `Mempool::insert` re-verifies the signature, so a tx corrupted on the
    // wire would be rejected here.
    let mut mempool = Mempool::new();
    let (_from, received) = recv_b.recv().await.expect("recv");
    let received_tx: Transaction =
        serde_json::from_slice(received.as_ref()).expect("deserialize tx");
    match mempool.insert(received_tx) {
        Ok(hash) => info!(
            hash = %short_hash(&hash.0),
            pending = mempool.len(),
            "p2p: net_b admitted tx to mempool",
        ),
        Err(e) => info!(error = %e, "p2p: net_b rejected tx"),
    }
}

/// One round of the single-node demo. Synchronous; network wiring comes later.
fn run_demo() {
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
