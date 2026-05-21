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
        response: oneshot::Sender<Hash>,
    },
    Verify {
        digest: Hash,
        response: oneshot::Sender<bool>,
    },
    Finalize {
        digest: Hash,
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

    async fn propose(&mut self, _ctx: Context<Hash, PublicKey>) -> oneshot::Receiver<Hash> {
        let (response, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::Propose { response })
                .accepted(),
            "propose enqueue rejected"
        );
        receiver
    }

    async fn verify(
        &mut self,
        _ctx: Context<Hash, PublicKey>,
        digest: Hash,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        assert!(
            self.sender
                .enqueue(Message::Verify { digest, response })
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

    async fn broadcast(&mut self, _digest: Hash, _plan: Plan<PublicKey>) {
        // Block bytes travel on a dedicated p2p channel, wired in Stage 5.
    }
}
