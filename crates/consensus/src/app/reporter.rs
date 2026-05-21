use super::{ingress::Message, Mailbox, Scheme};
use commonware_actor::Feedback;
use commonware_consensus::simplex::types::Activity;
use nanochain_types::Hash;
use tracing::debug;

/// Forwards consensus activity into the Application actor's mailbox.
/// Right now we only act on `Finalization` (state advance); everything else
/// is observable but ignored.
#[derive(Clone)]
pub struct Reporter {
    pub(super) mailbox: Mailbox,
}

impl commonware_consensus::Reporter for Reporter {
    type Activity = Activity<Scheme, Hash>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Activity::Finalization(f) => self.mailbox.sender.enqueue(Message::Finalize {
                digest: f.proposal.payload,
            }),
            other => {
                debug!(?other, "ignored consensus activity");
                Feedback::Ok
            }
        }
    }
}
