//! Application actor: bridges commonware Simplex (Automaton/Relay/Reporter)
//! to our state, mempool, and block store.

mod actor;
mod ingress;
mod reporter;

pub use actor::{Application, Config};
pub use ingress::Mailbox;
pub use reporter::Reporter;

use commonware_consensus::types::ViewDelta;
use commonware_cryptography::{ed25519, Signer as _};
use commonware_utils::{ordered::Set, TryCollect as _};
use std::num::NonZeroUsize;
use std::time::Duration;

pub type Scheme = commonware_consensus::simplex::scheme::ed25519::Scheme;

/// Defaults mirror the commonware log example.
pub struct Tuning {
    pub partition: String,
    pub mailbox_size: NonZeroUsize,
    pub replay_buffer: NonZeroUsize,
    pub write_buffer: NonZeroUsize,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub timeout_retry: Duration,
    pub fetch_timeout: Duration,
    pub activity_timeout: ViewDelta,
    pub skip_timeout: ViewDelta,
    pub fetch_concurrent: NonZeroUsize,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            partition: String::from("nanochain"),
            mailbox_size: NonZeroUsize::new(1024).unwrap(),
            replay_buffer: NonZeroUsize::new(1024 * 1024).unwrap(),
            write_buffer: NonZeroUsize::new(1024 * 1024).unwrap(),
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            activity_timeout: ViewDelta::new(10),
            skip_timeout: ViewDelta::new(5),
            fetch_concurrent: NonZeroUsize::new(32).unwrap(),
        }
    }
}

/// `None` if `my_seed` isn't in `roster`.
pub fn make_scheme(namespace: &[u8], roster: &[u64], my_seed: u64) -> Option<Scheme> {
    let validators: Set<ed25519::PublicKey> = roster
        .iter()
        .map(|seed| ed25519::PrivateKey::from_seed(*seed).public_key())
        .try_collect()
        .expect("validator keys must be unique");
    let signer = ed25519::PrivateKey::from_seed(my_seed);
    Scheme::signer(namespace, validators, signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_scheme_succeeds_when_my_seed_is_in_roster() {
        assert!(make_scheme(b"nanochain", &[1, 2, 3], 2).is_some());
    }

    #[test]
    fn make_scheme_fails_when_my_seed_is_outside_roster() {
        assert!(make_scheme(b"nanochain", &[1, 2, 3], 99).is_none());
    }
}
