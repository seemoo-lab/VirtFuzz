use libafl::bolts::serdeany::SerdeAny;
use libafl::bolts::tuples::Named;
use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::feedbacks::Feedback;

use libafl::observers::ObserversTuple;
use libafl::prelude::UsesInput;
use libafl::state::{HasClientPerfMonitor, HasMetadata};
use libafl::Error;

#[derive(Debug, Clone)]
pub struct ConstMetadataFeedback<M>
where
    M: SerdeAny + Clone,
{
    metadata: M,
    is_interesting: bool,
}

impl<M> ConstMetadataFeedback<M>
where
    M: SerdeAny + Clone,
{
    #[allow(dead_code)]
    pub fn new_true(metadata: M) -> Self {
        Self {
            metadata,
            is_interesting: true,
        }
    }

    #[allow(dead_code)]
    pub fn new_false(metadata: M) -> Self {
        Self {
            metadata,
            is_interesting: false,
        }
    }
}

impl<M> Named for ConstMetadataFeedback<M>
where
    M: SerdeAny + Clone,
{
    fn name(&self) -> &str {
        "ConstantMetadataFeedback"
    }
}

impl<S, M> Feedback<S> for ConstMetadataFeedback<M>
where
    S: UsesInput + HasClientPerfMonitor,
    M: SerdeAny + Clone,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        _observers: &OT,
        _exit_kind: &libafl::executors::ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(self.is_interesting)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        testcase: &mut Testcase<<S as UsesInput>::Input>,
    ) -> Result<(), Error> {
        testcase.add_metadata(self.metadata.clone());

        Ok(())
    }
}
