use core::marker::PhantomData;
use core::result::Result;
use core::result::Result::Ok;

use libafl_bolts::rands::Rand;
use libafl_bolts::tuples::{tuple_list, tuple_list_type, Named};
use libafl::inputs::{HasBytesVec, Input};
use libafl::mutators::{MutationResult, Mutator, *};
use libafl::state::{HasCorpus, HasMaxSize, HasRand};
use libafl::Error;

use crate::input::HasMultipleInputs;

#[macro_export]
macro_rules! inner_multiple_type {
    ($i:ty) => {
            MultipleInputsWrapperMutator<I, S, $i>
    };
}

#[macro_export]
macro_rules! inner_multiple {
    ($x:expr) => {
        MultipleInputsWrapperMutator::new($x)
    };
}

pub struct MultipleInputsWrapperMutator<I, S, M>
where
    I: Input,
    S: HasRand,
    M: Mutator<I, S> + Named,
{
    inner: M,
    name: String,
    phantom: PhantomData<(I, S)>,
}

impl<I, S, M> MultipleInputsWrapperMutator<I, S, M>
where
    I: Input,
    S: HasRand,
    M: Mutator<I, S> + Named,
{
    #[allow(dead_code)]
    pub fn new(inner: M) -> Self {
        Self {
            name: format!("Multiple{}", inner.name()),
            inner,
            phantom: PhantomData::default(),
        }
    }
}

impl<MI, S, I, M> Mutator<MI, S> for MultipleInputsWrapperMutator<I, S, M>
where
    MI: HasMultipleInputs<I>,
    I: Input,
    S: HasRand,
    M: Mutator<I, S> + Named,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MI,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.multiple_inputs().is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let which = state
            .rand_mut()
            .below(input.multiple_inputs().len() as u64 - 1) as usize;

        let inputs = input.multiple_inputs_mut();
        self.inner.mutate(state, &mut inputs[which], stage_idx)
    }
}

impl<S, I, M> Named for MultipleInputsWrapperMutator<I, S, M>
where
    I: Input,
    S: HasRand,
    M: Mutator<I, S> + Named,
{
    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Default)]
pub struct MultipleInputsDuplicateMutator<I>
where
    I: Input,
{
    phantom: PhantomData<I>,
}

impl<I, MI, S> Mutator<MI, S> for MultipleInputsDuplicateMutator<I>
where
    MI: Input + HasMultipleInputs<I>,
    I: Input,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MI,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.multiple_inputs().is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let which = state.rand_mut().below(input.multiple_inputs().len() as u64) as usize;
        let new = input.multiple_inputs()[which].clone();
        input.multiple_inputs_mut().push(new);

        Ok(MutationResult::Mutated)
    }
}

impl<I> Named for MultipleInputsDuplicateMutator<I>
where
    I: Input,
{
    fn name(&self) -> &str {
        "MultipleInputsDuplicateMutator"
    }
}

impl<I> MultipleInputsDuplicateMutator<I>
where
    I: Input,
{
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData::default(),
        }
    }
}

#[derive(Default)]
pub struct MultipleInputsDeleteMutator<I, MI, S>
where
    MI: Input + HasMultipleInputs<I>,
    I: Input,
    S: HasRand,
{
    phantom: PhantomData<(I, MI, S)>,
}

impl<I, MI, S> Mutator<MI, S> for MultipleInputsDeleteMutator<I, MI, S>
where
    MI: Input + HasMultipleInputs<I>,
    I: Input,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MI,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.multiple_inputs().len() <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let which = state.rand_mut().below(input.multiple_inputs().len() as u64) as usize;
        input.multiple_inputs_mut().remove(which);

        Ok(MutationResult::Mutated)
    }
}

impl<I, MI, S> Named for MultipleInputsDeleteMutator<I, MI, S>
where
    MI: Input + HasMultipleInputs<I>,
    I: Input,
    S: HasRand,
{
    fn name(&self) -> &str {
        "MultipleInputsDeleteMutator"
    }
}

impl<I, MI, S> MultipleInputsDeleteMutator<I, MI, S>
where
    MI: Input + HasMultipleInputs<I>,
    I: Input,
    S: HasRand,
{
    /// Creates a new [`MultipleInputsDeleteMutator`].
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

#[allow(dead_code)]
pub fn multiple_bytes_mutators<I, S>() -> tuple_list_type!(
    inner_multiple_type!(BitFlipMutator),
    inner_multiple_type!(ByteFlipMutator),
    inner_multiple_type!(ByteIncMutator),
    inner_multiple_type!(ByteDecMutator),
    inner_multiple_type!(ByteNegMutator),
    inner_multiple_type!(ByteRandMutator),
    inner_multiple_type!(ByteAddMutator),
    inner_multiple_type!(WordAddMutator),
    inner_multiple_type!(DwordAddMutator),
    inner_multiple_type!(QwordAddMutator),
    inner_multiple_type!(ByteInterestingMutator),
    inner_multiple_type!(WordInterestingMutator),
    inner_multiple_type!(DwordInterestingMutator),
    inner_multiple_type!(BytesDeleteMutator),
    inner_multiple_type!(BytesDeleteMutator),
    inner_multiple_type!(BytesDeleteMutator),
    inner_multiple_type!(BytesDeleteMutator),
    inner_multiple_type!(BytesExpandMutator),
    inner_multiple_type!(BytesInsertMutator),
    inner_multiple_type!(BytesRandInsertMutator),
    inner_multiple_type!(BytesSetMutator),
    inner_multiple_type!(BytesRandSetMutator),
    inner_multiple_type!(BytesCopyMutator),
    inner_multiple_type!(BytesInsertCopyMutator),
    inner_multiple_type!(BytesSwapMutator),
)
where
    I: Input + HasBytesVec,
    S: HasRand + HasMaxSize + HasCorpus<I>,
{
    tuple_list!(
        inner_multiple!(BitFlipMutator::new()),
        inner_multiple!(ByteFlipMutator::new()),
        inner_multiple!(ByteIncMutator::new()),
        inner_multiple!(ByteDecMutator::new()),
        inner_multiple!(ByteNegMutator::new()),
        inner_multiple!(ByteRandMutator::new()),
        inner_multiple!(ByteAddMutator::new()),
        inner_multiple!(WordAddMutator::new()),
        inner_multiple!(DwordAddMutator::new()),
        inner_multiple!(QwordAddMutator::new()),
        inner_multiple!(ByteInterestingMutator::new()),
        inner_multiple!(WordInterestingMutator::new()),
        inner_multiple!(DwordInterestingMutator::new()),
        inner_multiple!(BytesDeleteMutator::new()),
        inner_multiple!(BytesDeleteMutator::new()),
        inner_multiple!(BytesDeleteMutator::new()),
        inner_multiple!(BytesDeleteMutator::new()),
        inner_multiple!(BytesExpandMutator::new()),
        inner_multiple!(BytesInsertMutator::new()),
        inner_multiple!(BytesRandInsertMutator::new()),
        inner_multiple!(BytesSetMutator::new()),
        inner_multiple!(BytesRandSetMutator::new()),
        inner_multiple!(BytesCopyMutator::new()),
        inner_multiple!(BytesInsertCopyMutator::new()),
        inner_multiple!(BytesSwapMutator::new()),
    )
}
