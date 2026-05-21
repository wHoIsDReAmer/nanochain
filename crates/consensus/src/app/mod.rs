//! Application actor: bridges commonware Simplex (Automaton/Relay/Reporter)
//! to our state, mempool, and block store.

mod actor;
mod ingress;
mod reporter;

pub use actor::{Application, Config};
pub use ingress::Mailbox;
pub use reporter::Reporter;

/// Simplex signing scheme we use end-to-end.
pub type Scheme = commonware_consensus::simplex::scheme::ed25519::Scheme;
