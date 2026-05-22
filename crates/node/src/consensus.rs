//! Assembles and starts a commonware Simplex `Engine`.

use commonware_consensus::{
    simplex::{self, elector::RoundRobin, ForwardingPolicy},
    types::Epoch,
};
use commonware_cryptography::Sha256;
use commonware_p2p::Blocker;
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, Handle, Storage};
use commonware_utils::{NZUsize, NZU16};
use nanochain_consensus::app::{Mailbox, Reporter, Scheme, Tuning};
use nanochain_network::{Channel, Context, PublicKey};

pub struct Channels<E: Context> {
    pub vote: Channel<E>,
    pub certificate: Channel<E>,
    pub resolver: Channel<E>,
}

/// `blocker` is the network oracle.
pub fn start_engine<E, B>(
    context: E,
    scheme: Scheme,
    mailbox: Mailbox,
    reporter: Reporter,
    blocker: B,
    tuning: Tuning,
    channels: Channels<E>,
) -> Handle<()>
where
    E: Context + Storage,
    B: Blocker<PublicKey = PublicKey> + Clone + Send + 'static,
{
    let page_cache = CacheRef::from_pooler(&context, NZU16!(16_384), NZUsize!(10_000));
    let cfg = simplex::Config {
        scheme,
        elector: RoundRobin::<Sha256>::default(),
        blocker,
        automaton: mailbox.clone(),
        relay: mailbox,
        reporter,
        strategy: Sequential,
        partition: tuning.partition,
        mailbox_size: tuning.mailbox_size,
        epoch: Epoch::zero(),
        replay_buffer: tuning.replay_buffer,
        write_buffer: tuning.write_buffer,
        page_cache,
        leader_timeout: tuning.leader_timeout,
        certification_timeout: tuning.certification_timeout,
        timeout_retry: tuning.timeout_retry,
        activity_timeout: tuning.activity_timeout,
        skip_timeout: tuning.skip_timeout,
        fetch_timeout: tuning.fetch_timeout,
        fetch_concurrent: tuning.fetch_concurrent,
        forwarding: ForwardingPolicy::Disabled,
    };
    let engine = simplex::Engine::new(context, cfg);
    engine.start(
        channels.vote.into_inner(),
        channels.certificate.into_inner(),
        channels.resolver.into_inner(),
    )
}
