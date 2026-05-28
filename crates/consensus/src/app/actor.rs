use super::ingress::{Mailbox, Message};
use super::Reporter;
use crate::{build_block, BuildParams, Error};
use commonware_actor::mailbox::{self, Receiver};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::types::Epoch;
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
use commonware_utils::channel::mpsc;
use ed25519_dalek::SigningKey;
use nanochain_mempool::Mempool;
use nanochain_storage::{BlockStore, StateStore};
use nanochain_types::{Block, Hash};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use tracing::{info, warn};

const MAX_TXS_PER_BLOCK: usize = 1024;
/// Backlog of serialized blocks awaiting broadcast by the node.
const BLOCKS_OUT_CAPACITY: usize = 256;

pub struct Config {
    pub mailbox_size: NonZeroUsize,
    pub signer: SigningKey,
    pub genesis: Block,
}

/// Owns chain state and drives proposals / verification / finalization in
/// response to messages from Simplex (via the [`Mailbox`]) and from the
/// [`Reporter`] (Finalize on certificate).
pub struct Application<R: Spawner> {
    context: ContextCell<R>,
    mailbox: Receiver<Message>,
    signer: SigningKey,
    state: StateStore,
    blocks: BlockStore,
    mempool: Mempool,
    /// Blocks we proposed locally or received from peers, keyed by digest.
    /// Drained on finalize.
    pending: HashMap<Hash, Block>,
    genesis_digest: Hash,
    /// Serialized blocks the node should broadcast to peers.
    blocks_out: mpsc::Sender<Vec<u8>>,
}

impl<R: Spawner> Application<R> {
    pub fn new(
        context: R,
        state: StateStore,
        blocks: BlockStore,
        mempool: Mempool,
        config: Config,
    ) -> (Self, Mailbox, Reporter, mpsc::Receiver<Vec<u8>>) {
        let (sender, receiver) = mailbox::new::<Message>(config.mailbox_size);
        let (blocks_out, blocks_out_rx) = mpsc::channel(BLOCKS_OUT_CAPACITY);
        let m = Mailbox::new(sender);
        let r = Reporter { mailbox: m.clone() };
        let genesis_digest = config.genesis.hash();
        let app = Self {
            context: ContextCell::new(context),
            mailbox: receiver,
            signer: config.signer,
            state,
            blocks,
            mempool,
            pending: HashMap::new(),
            genesis_digest,
            blocks_out,
        };
        (app, m, r, blocks_out_rx)
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        while let Some(msg) = self.mailbox.recv().await {
            match msg {
                Message::Genesis { epoch, response } => {
                    assert_eq!(epoch, Epoch::zero(), "multi-epoch not supported");
                    let _ = response.send(self.genesis_digest);
                }
                Message::Propose { parent, response } => match self.propose(parent) {
                    Ok(digest) => {
                        let _ = response.send(digest);
                    }
                    Err(e) => warn!(error = %e, "propose failed"),
                },
                Message::Verify {
                    parent,
                    digest,
                    response,
                } => {
                    let _ = response.send(self.verify(parent, digest));
                }
                Message::Finalize { digest } => {
                    if let Err(e) = self.finalize(digest) {
                        warn!(%digest, error = %e, "finalize failed");
                    }
                }
                Message::Broadcast { digest } => self.broadcast_block(digest),
                Message::StoreBlock { bytes } => self.store_block(bytes),
            }
        }
    }

    /// Push the block behind `digest` onto the outbound queue for the node to
    /// broadcast. Best-effort: dropped if unknown locally or the queue is full.
    fn broadcast_block(&mut self, digest: Hash) {
        let Some(block) = self.pending.get(&digest) else {
            warn!(%digest, "broadcast miss: block unknown locally");
            return;
        };
        if self.blocks_out.try_send(block.encode().to_vec()).is_err() {
            warn!(%digest, "block broadcast queue full");
        }
    }

    /// Decode a peer's block bytes and stash it so we can verify/finalize it.
    fn store_block(&mut self, bytes: Vec<u8>) {
        match Block::decode(bytes.as_ref()) {
            Ok(block) => {
                self.pending.insert(block.hash(), block);
            }
            Err(e) => warn!(error = %e, "undecodable peer block"),
        }
    }

    /// A block we know about, proposed/received (pending) or finalized (blocks).
    fn block_by_digest(&self, digest: &Hash) -> Option<&Block> {
        self.pending
            .get(digest)
            .or_else(|| self.blocks.get_by_hash(digest))
    }

    /// Build the next block on the consensus-designated `parent`, stash it,
    /// return its digest.
    fn propose(&mut self, parent: Hash) -> Result<Hash, Error> {
        let parent = self
            .block_by_digest(&parent)
            .ok_or(Error::Internal("propose: parent unknown"))?
            .clone();
        let signed = build_block(
            BuildParams {
                parent: &parent,
                timestamp: now_secs(),
                proposer: &self.signer,
                max_txs: MAX_TXS_PER_BLOCK,
            },
            &self.mempool,
            &self.state,
        )?;
        signed.verify()?;
        let digest = signed.block.hash();
        info!(%digest, height = signed.block.header.height, "proposed");
        self.pending.insert(digest, signed.block);
        Ok(digest)
    }

    /// Accept a proposal iff it builds on the consensus-designated `parent`
    /// with a sequential height. State is dry-run only when `parent` is our
    /// finalized tip (otherwise we lack the parent's state to execute against).
    fn verify(&self, parent: Hash, digest: Hash) -> bool {
        let Some(block) = self.pending.get(&digest) else {
            warn!(%digest, "verify miss: block unknown locally");
            return false;
        };
        if block.header.parent_hash != parent {
            warn!(%digest, "verify: parent_hash does not match consensus parent");
            return false;
        }
        if let Some(parent_block) = self.block_by_digest(&parent) {
            if block.header.height != parent_block.header.height + 1 {
                warn!(%digest, "verify: non-sequential height");
                return false;
            }
        }
        match self.blocks.tip() {
            Some(tip) if tip.hash() == parent => {
                let mut shadow = self.state.clone();
                shadow.apply_block(block).is_ok()
            }
            // Parent is ahead of our finalized tip: structural checks only.
            _ => true,
        }
    }

    /// Commit the block: apply to state, drop included txs from mempool, persist.
    fn finalize(&mut self, digest: Hash) -> Result<(), Error> {
        let block = self
            .pending
            .remove(&digest)
            .ok_or(Error::Internal("finalize: block missing"))?;
        self.state.apply_block(&block)?;
        for tx in &block.transactions {
            self.mempool.remove(&tx.hash());
        }
        info!(%digest, height = block.header.height, "finalized");
        self.blocks.insert(block);
        Ok(())
    }
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
impl<R: Spawner> Application<R> {
    fn balance(&self, account: &[u8; 32]) -> u64 {
        self.state.get_balance(account)
    }

    fn tip_height(&self) -> u64 {
        self.blocks.tip().map(|b| b.header.height).unwrap_or(0)
    }

    fn pending_tx_count(&self) -> usize {
        self.mempool.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner as _};
    use nanochain_types::Transaction;
    use rand_core::OsRng;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn addr(k: &SigningKey) -> [u8; 32] {
        k.verifying_key().to_bytes()
    }

    #[test]
    fn propose_then_finalize_advances_chain() {
        let runner = deterministic::Runner::default();
        runner.start(|ctx| async move {
            let alice = keypair();
            let bob = [9u8; 32];

            let mut state = StateStore::new();
            state.credit(addr(&alice), 1_000);
            let mut blocks = BlockStore::new();
            blocks.insert(Block::genesis());
            let mut pool = Mempool::new();
            pool.insert(Transaction::signed(&alice, bob, 300, 0))
                .unwrap();

            let cfg = Config {
                mailbox_size: NonZeroUsize::new(8).unwrap(),
                signer: keypair(),
                genesis: Block::genesis(),
            };
            let (mut app, _mailbox, _reporter, _blocks_out) =
                Application::new(ctx, state, blocks, pool, cfg);

            assert_eq!(app.tip_height(), 0);
            assert_eq!(app.balance(&addr(&alice)), 1_000);
            assert_eq!(app.pending_tx_count(), 1);

            let genesis = Block::genesis().hash();
            let digest = app.propose(genesis).expect("propose");
            assert!(
                app.verify(genesis, digest),
                "self-proposed block should verify"
            );

            app.finalize(digest).expect("finalize");

            assert_eq!(app.tip_height(), 1);
            assert_eq!(app.balance(&addr(&alice)), 700);
            assert_eq!(app.balance(&bob), 300);
            assert_eq!(app.pending_tx_count(), 0);
        });
    }

    #[test]
    fn verify_rejects_unknown_digest() {
        let runner = deterministic::Runner::default();
        runner.start(|ctx| async move {
            let mut blocks = BlockStore::new();
            blocks.insert(Block::genesis());

            let cfg = Config {
                mailbox_size: NonZeroUsize::new(8).unwrap(),
                signer: keypair(),
                genesis: Block::genesis(),
            };
            let (app, _mailbox, _reporter, _blocks_out) =
                Application::new(ctx, StateStore::new(), blocks, Mempool::new(), cfg);

            assert!(!app.verify(Block::genesis().hash(), nanochain_types::zero_hash()));
        });
    }

    #[test]
    fn finalize_unknown_digest_is_error() {
        let runner = deterministic::Runner::default();
        runner.start(|ctx| async move {
            let mut blocks = BlockStore::new();
            blocks.insert(Block::genesis());

            let cfg = Config {
                mailbox_size: NonZeroUsize::new(8).unwrap(),
                signer: keypair(),
                genesis: Block::genesis(),
            };
            let (mut app, _mailbox, _reporter, _blocks_out) =
                Application::new(ctx, StateStore::new(), blocks, Mempool::new(), cfg);

            assert!(app.finalize(nanochain_types::zero_hash()).is_err());
        });
    }

    #[test]
    fn stored_peer_block_becomes_verifiable() {
        let runner = deterministic::Runner::default();
        runner.start(|ctx| async move {
            let alice = keypair();
            let bob = [9u8; 32];

            let mut state = StateStore::new();
            state.credit(addr(&alice), 1_000);
            let mut blocks = BlockStore::new();
            blocks.insert(Block::genesis());

            let cfg = Config {
                mailbox_size: NonZeroUsize::new(8).unwrap(),
                signer: keypair(),
                genesis: Block::genesis(),
            };
            let (mut app, _mailbox, _reporter, _blocks_out) =
                Application::new(ctx, state, blocks, Mempool::new(), cfg);

            // A peer's block arrives as bytes; before storing, it's unverifiable.
            let peer_block = Block::new(
                1,
                Block::genesis().hash(),
                0,
                [7u8; 32],
                vec![Transaction::signed(&alice, bob, 100, 0)],
            );
            let genesis = Block::genesis().hash();
            let digest = peer_block.hash();
            assert!(!app.verify(genesis, digest));

            app.store_block(peer_block.encode().to_vec());
            assert!(
                app.verify(genesis, digest),
                "stored peer block should verify"
            );
        });
    }
}
