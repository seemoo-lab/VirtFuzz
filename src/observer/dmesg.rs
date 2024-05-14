use std::cell::RefCell;
use std::rc::Rc;

use libafl::bolts::tuples::Named;
use libafl::inputs::UsesInput;
use libafl::observers::Observer;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DmesgObserver {
    name: String,

    // TODO: This does not work with syncing. We should take the messages and copy them to the observer or similar
    #[serde(skip)]
    messages: Rc<RefCell<String>>,
}

impl Named for DmesgObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<S: UsesInput> Observer<S> for DmesgObserver {}

impl DmesgObserver {
    pub fn new(name: &str, messages: Rc<RefCell<String>>) -> Self {
        Self {
            name: name.to_string(),
            messages,
        }
    }

    pub fn get_last_log(&self) -> Option<String> {
        Some(self.messages.take())
    }
}
