use commonware_actor::mailbox::{Policy, Sender};
use commonware_consensus::{
    simplex::{types::Context, Plan},
    types::Epoch,
    Automaton, CertifiableAutomaton, Relay,
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::channel::oneshot;
use nanochain_types::Hash;
use std::collections::VecDeque;

pub enum Message {
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<Hash>,
    },
    Propose {
        /// Digest of the parent the new block must build on (from `Context`).
        parent: Hash,
        response: oneshot::Sender<Hash>,
    },
    Verify {
        /// Digest of the parent the proposal claims to build on.
        parent: Hash,
        digest: Hash,
        response: oneshot::Sender<bool>,
    },
    Finalize {
        digest: Hash,
    },
    Broadcast {
        digest: Hash,
    },
    StoreBlock {
        bytes: Vec<u8>,
    },
}

impl Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        overflow.push_back(message);
    }
}

/// Cheap-to-clone handle handed to Simplex (Automaton + Relay) and Reporter.
#[derive(Clone)]
pub struct Mailbox {
    pub(crate) sender: Sender<Message>,
}

impl Mailbox {
    pub(super) const fn new(sender: Sender<Message>) -> Self {
        Self { sender }
    }

    pub fn store_peer_block(&self, bytes: Vec<u8>) {
        let _ = self.sender.enqueue(Message::StoreBlock { bytes });
    }
}

impl Automaton for Mailbox {
    type Digest = Hash;
    type Context = Context<Hash, PublicKey>;

    async fn genesis(&mut self, epoch: Epoch) -> Hash {
        let (response, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::Genesis { epoch, response })
                .accepted(),
            "genesis enqueue rejected"
        );
        receiver.await.expect("genesis receiver dropped")
    }

    async fn propose(&mut self, ctx: Context<Hash, PublicKey>) -> oneshot::Receiver<Hash> {
        let (response, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::Propose {
                    parent: ctx.parent.1,
                    response
                })
                .accepted(),
            "propose enqueue rejected"
        );
        receiver
    }

    async fn verify(
        &mut self,
        ctx: Context<Hash, PublicKey>,
        digest: Hash,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::Verify {
                    parent: ctx.parent.1,
                    digest,
                    response
                })
                .accepted(),
            "verify enqueue rejected"
        );
        receiver
    }
}

impl CertifiableAutomaton for Mailbox {}

impl Relay for Mailbox {
    type Digest = Hash;
    type PublicKey = PublicKey;
    type Plan = Plan<PublicKey>;

    async fn broadcast(&mut self, digest: Hash, _plan: Plan<PublicKey>) {
        let _ = self.sender.enqueue(Message::Broadcast { digest });
    }
}
