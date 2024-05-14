use std::cell::RefCell;
use std::rc::Rc;

use libafl::bolts::tuples::Named;
use libafl::corpus::Testcase;
use libafl::events::EventFirer;
use libafl::feedbacks::Feedback;

use libafl::observers::ObserversTuple;
use libafl::prelude::UsesInput;
use libafl::state::{HasClientPerfMonitor, HasMetadata};
use libafl::{impl_serdeany, Error};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct ExecutedInputsFeedback {
    inputs: Rc<RefCell<Vec<Vec<u8>>>>,
}

impl ExecutedInputsFeedback {
    pub fn new(inputs: Rc<RefCell<Vec<Vec<u8>>>>) -> Self {
        Self { inputs }
    }
}

impl Named for ExecutedInputsFeedback {
    fn name(&self) -> &str {
        "ExecutedInputsFeedback"
    }
}

impl<S> Feedback<S> for ExecutedInputsFeedback
where
    S: UsesInput + HasClientPerfMonitor,
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
        Ok(true)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        testcase: &mut Testcase<<S as UsesInput>::Input>,
    ) -> Result<(), Error> {
        testcase.add_metadata(ExecutedInputsMetadata {
            previous_frames: self.inputs.borrow().clone(),
        });

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExecutedInputsMetadata {
    pub previous_frames: Vec<Vec<u8>>,
}
impl_serdeany!(ExecutedInputsMetadata);
