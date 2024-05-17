use libafl_bolts::serdeany::SerdeAny;
use libafl_bolts::Named;
use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::feedbacks::Feedback;

use libafl::observers::ObserversTuple;
use libafl::prelude::UsesInput;
use libafl::common::{HasMetadata};
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
    S: UsesInput + libafl::state::State,
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

    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<<S as UsesInput>::Input>,
    )  -> Result<(), Error>
        where EM: EventFirer<State = S>, OT: ObserversTuple<S>, {
        testcase.add_metadata(self.metadata.clone());

        Ok(())
    }
}
