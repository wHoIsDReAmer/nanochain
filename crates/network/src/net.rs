use commonware_cryptography::{ed25519, Signer as _};
use commonware_p2p::{
    authenticated::lookup::{self, Network as P2p, Receiver as P2pReceiver, Sender as P2pSender},
    AddressableManager as _, Receiver as _, Recipients, Sender as _,
};
use commonware_runtime::{Handle, Quota};
use commonware_utils::{ordered::Map, NZU32};

use crate::NetworkConfig;

const MAX_MSG_SIZE: u32 = 1024 * 1024;
const NAMESPACE: &[u8] = b"nanochain-net";

type PublicKey = ed25519::PublicKey;

/// Bounds the runtime context must satisfy to host the p2p network.
pub trait Context:
    commonware_runtime::Spawner
    + commonware_runtime::Clock
    + commonware_runtime::Metrics
    + commonware_runtime::Network
    + commonware_runtime::Resolver
    + commonware_runtime::BufferPooler
    + rand_core::CryptoRngCore
{
}

impl<E> Context for E where
    E: commonware_runtime::Spawner
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + commonware_runtime::Network
        + commonware_runtime::Resolver
        + commonware_runtime::BufferPooler
        + rand_core::CryptoRngCore
{
}

/// Wraps the commonware-p2p `lookup` network behind a byte-oriented API:
/// callers `broadcast` and `recv` raw `Vec<u8>` without touching p2p types.
pub struct Network<E: Context> {
    sender: P2pSender<PublicKey, E>,
    receiver: P2pReceiver<PublicKey>,
    _task: Handle<()>,
}

impl<E: Context> Network<E> {
    /// Start the p2p network: register the authorized peer set, open a channel,
    /// and spawn the network actors. Borrows `context` (only to spawn a child).
    pub async fn start(context: &E, config: &NetworkConfig) -> Self {
        let entries: Vec<_> = config
            .peers
            .iter()
            .map(|(seed, addr)| {
                (
                    ed25519::PrivateKey::from_seed(*seed).public_key(),
                    (*addr).into(),
                )
            })
            .collect();
        let peers: Map<_, _> = Map::try_from(entries).expect("peer map");

        let sk = ed25519::PrivateKey::from_seed(config.seed);
        let cfg = lookup::Config::local(sk, NAMESPACE, config.listen, MAX_MSG_SIZE);
        let (mut network, mut oracle) = P2p::new(context.child("p2p"), cfg);
        oracle.track(0, peers).await;
        let (sender, receiver) = network.register(0, Quota::per_second(NZU32!(64)), 256);
        let task = network.start();

        Network {
            sender,
            receiver,
            _task: task,
        }
    }

    /// Broadcast `bytes` to every connected peer; returns how many were reached.
    pub async fn broadcast(&mut self, bytes: Vec<u8>) -> usize {
        self.sender
            .send(Recipients::All, bytes, true)
            .await
            .map(|reached| reached.len())
            .unwrap_or(0)
    }

    /// Receive the next message's bytes, or `None` once the network shuts down.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        match self.receiver.recv().await {
            Ok((_from, msg)) => Some(msg.as_ref().to_vec()),
            Err(_) => None,
        }
    }
}
