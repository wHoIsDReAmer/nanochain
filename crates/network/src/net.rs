use commonware_cryptography::{ed25519, Signer as _};
use commonware_p2p::{
    authenticated::lookup::{
        self, Network as P2p, Oracle, Receiver as P2pReceiver, Sender as P2pSender,
    },
    AddressableManager as _, Receiver as _, Recipients, Sender as _,
};
use commonware_runtime::{Handle, Quota};
use commonware_utils::ordered::Map;

use crate::NetworkConfig;

const MAX_MSG_SIZE: u32 = 1024 * 1024;
const NAMESPACE: &[u8] = b"nanochain-net";

pub type PublicKey = ed25519::PublicKey;
pub type PrivateKey = ed25519::PrivateKey;

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

/// p2p network builder: create with `new`, register channels, then `start`.
pub struct Network<E: Context> {
    network: P2p<E, PrivateKey>,
    pub oracle: Oracle<PublicKey>,
}

/// A single registered p2p channel with a byte-oriented API.
pub struct Channel<E: Context> {
    sender: P2pSender<PublicKey, E>,
    receiver: P2pReceiver<PublicKey>,
}

impl<E: Context> Network<E> {
    /// Create the underlying p2p network and track the configured peer set.
    pub async fn new(context: &E, config: &NetworkConfig) -> Self {
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
        let (network, mut oracle) = P2p::new(context.child("p2p"), cfg);
        oracle.track(0, peers).await;

        Network { network, oracle }
    }

    /// Register a logical channel with its own rate limit + in-flight backlog.
    pub fn register(&mut self, channel: u64, quota: Quota, in_flight: usize) -> Channel<E> {
        let (sender, receiver) = self.network.register(channel, quota, in_flight);
        Channel { sender, receiver }
    }

    /// Spawn the underlying network actor. Drop the returned handle to shut down.
    pub fn start(self) -> Handle<()> {
        self.network.start()
    }
}

impl<E: Context> Channel<E> {
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

    /// Split into the underlying p2p sender + receiver, e.g. to hand to
    /// commonware-consensus's Engine which wants the raw pair.
    pub fn into_inner(self) -> (P2pSender<PublicKey, E>, P2pReceiver<PublicKey>) {
        (self.sender, self.receiver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Clock as _, Runner as _, Supervisor as _};
    use commonware_utils::NZU32;
    use std::time::Duration;

    /// Two networks handshake and a message broadcast by one is received by the other.
    #[test]
    fn broadcast_round_trip() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let addr_a = "127.0.0.1:5001".parse().unwrap();
            let addr_b = "127.0.0.1:5002".parse().unwrap();
            let roster = vec![(1u64, addr_a), (2u64, addr_b)];

            let ctx_a = context.child("a");
            let ctx_b = context.child("b");
            let mut net_a = Network::new(
                &ctx_a,
                &NetworkConfig {
                    seed: 1,
                    listen: addr_a,
                    peers: roster.clone(),
                },
            )
            .await;
            let mut net_b = Network::new(
                &ctx_b,
                &NetworkConfig {
                    seed: 2,
                    listen: addr_b,
                    peers: roster,
                },
            )
            .await;
            let mut ch_a = net_a.register(0, Quota::per_second(NZU32!(64)), 256);
            let mut ch_b = net_b.register(0, Quota::per_second(NZU32!(64)), 256);
            let _task_a = net_a.start();
            let _task_b = net_b.start();

            loop {
                if ch_a.broadcast(b"hello".to_vec()).await > 0 {
                    break;
                }
                context.sleep(Duration::from_millis(200)).await;
            }
            assert_eq!(ch_b.recv().await, Some(b"hello".to_vec()));
        });
    }
}
