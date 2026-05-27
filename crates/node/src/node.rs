use commonware_runtime::{Quota, Storage};
use commonware_utils::NZU32;
use ed25519_dalek::SigningKey;
use nanochain_consensus::app::{make_scheme, Application, Config as AppConfig, Tuning};
use nanochain_mempool::Mempool;
use nanochain_network::{Context, Network, NetworkConfig};
use nanochain_storage::{BlockStore, StateStore};
use nanochain_types::{Block, Transaction};
use std::num::NonZeroUsize;
use tracing::{info, warn};

use crate::consensus::{start_engine, Channels};
use crate::genesis::GenesisConfig;

/// Domain tag binding consensus signatures to this chain.
const NAMESPACE: &[u8] = b"nanochain-consensus";
const MAILBOX_SIZE: usize = 1024;
/// p2p channel ids handed to the consensus engine + block relay.
const CH_VOTE: u64 = 0;
const CH_CERTIFICATE: u64 = 1;
const CH_RESOLVER: u64 = 2;
const CH_BLOCK: u64 = 3;

/// A nanochain validator: genesis allocations, the consensus signing key, and
/// any transactions to seed the mempool with at startup.
pub struct Node {
    genesis: GenesisConfig,
    signer: SigningKey,
    initial_txs: Vec<Transaction>,
}

impl Node {
    pub fn new(genesis: GenesisConfig, signer: SigningKey) -> Self {
        Self {
            genesis,
            signer,
            initial_txs: Vec::new(),
        }
    }

    /// Seed a transaction into the mempool at startup (demo/testing entry point
    /// until an RPC exists).
    pub fn queue_tx(&mut self, tx: Transaction) {
        self.initial_txs.push(tx);
    }

    /// Boot the validator: build chain state, wire the Simplex engine to the
    /// p2p channels, and run consensus until shutdown.
    pub async fn run<E>(self, context: E, net: NetworkConfig)
    where
        E: Context + Storage + Send + 'static,
    {
        let seed = net.seed;

        // Genesis state + block.
        let mut state = StateStore::new();
        for (addr, balance) in &self.genesis.allocations {
            state.credit(*addr, *balance);
        }
        let mut blocks = BlockStore::new();
        blocks.insert(Block::genesis());
        let mut mempool = Mempool::new();
        for tx in self.initial_txs {
            if let Err(e) = mempool.insert(tx) {
                warn!(seed, error = %e, "skipped invalid seed tx");
            }
        }

        // Consensus signing scheme over the validator roster.
        let roster: Vec<u64> = net.peers.iter().map(|(s, _)| *s).collect();
        let scheme = make_scheme(NAMESPACE, &roster, seed)
            .expect("our seed must be in the validator roster");

        // Application owns chain state and answers Simplex's propose/verify.
        let (app, mailbox, reporter, mut blocks_out) = Application::new(
            context.child("app"),
            state,
            blocks,
            mempool,
            AppConfig {
                mailbox_size: NonZeroUsize::new(MAILBOX_SIZE).unwrap(),
                signer: self.signer,
                genesis: Block::genesis(),
            },
        );

        // p2p: register consensus channels + a block-relay channel, grab the
        // oracle (blocker) before the network is consumed by start().
        let mut network = Network::new(&context, &net).await;
        let vote = network.register(CH_VOTE, quota(), 256);
        let certificate = network.register(CH_CERTIFICATE, quota(), 256);
        let resolver = network.register(CH_RESOLVER, quota(), 256);
        let (mut block_tx, mut block_rx) = network.register(CH_BLOCK, quota(), 256).split();
        let oracle = network.oracle.clone();

        app.start();
        let _net = network.start();
        info!(seed, peers = roster.len(), "consensus node started");

        // Outbound: drain blocks the app wants published, broadcast them.
        context.child("block_out").spawn(move |_| async move {
            while let Some(bytes) = blocks_out.recv().await {
                block_tx.broadcast(bytes).await;
            }
        });
        // Inbound: hand peer blocks to the app so it can verify proposals.
        let inbound = mailbox.clone();
        context.child("block_in").spawn(move |_| async move {
            while let Some(bytes) = block_rx.recv().await {
                inbound.store_peer_block(bytes);
            }
        });

        // Engine drives consensus and runs until shutdown.
        let engine = start_engine(
            context.child("engine"),
            scheme,
            mailbox,
            reporter,
            oracle,
            Tuning::default(),
            Channels {
                vote,
                certificate,
                resolver,
            },
        );
        let _ = engine.await;
    }
}

fn quota() -> Quota {
    Quota::per_second(NZU32!(64))
}
