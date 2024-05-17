use std::hash::{Hash, Hasher};

use ahash::AHasher;
use libafl_bolts::HasLen;
use libafl::inputs::bytes::BytesInput;
use libafl::inputs::Input;
use serde::{Deserialize, Serialize};

pub mod hwsim80211_input;
//pub mod mutator;
//pub mod generator;

pub type MultipleBytesInputsInput = MultipleInputs<BytesInput>;

pub trait HasMultipleInputs<I>: Input
where
    I: Input,
{
    fn multiple_inputs(&self) -> &[I];
    fn multiple_inputs_mut(&mut self) -> &mut Vec<I>;
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct MultipleInputs<I> {
    inputs: Vec<I>,
}

impl<I> MultipleInputs<I>
where
    I: Input,
{
    pub fn new(inputs: Vec<I>) -> Self {
        Self { inputs }
    }
}

impl<I> Input for MultipleInputs<I>
where
    I: Input,
{
    fn generate_name(&self, idx: usize) -> String {
        let mut hasher = AHasher::default();
        if self.inputs.is_empty() {
            return "0000000000000000".to_string();
        }

        for i in &self.inputs {
            hasher.write(i.generate_name(idx).as_bytes());
        }

        format!("{:016x}", hasher.finish())
    }
}

impl<I> HasLen for MultipleInputs<I> {
    fn len(&self) -> usize {
        self.inputs.len()
    }
}

impl<I> HasMultipleInputs<I> for MultipleInputs<I>
where
    I: Input,
{
    fn multiple_inputs(&self) -> &[I] {
        &self.inputs
    }

    fn multiple_inputs_mut(&mut self) -> &mut Vec<I> {
        &mut self.inputs
    }
}
