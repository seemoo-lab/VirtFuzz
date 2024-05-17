use core::marker::PhantomData;
use core::result::Result;
use core::result::Result::Ok;

use libafl_bolts::rands::Rand;
use libafl::generators::Generator;
use libafl::inputs::Input;
use libafl::state::HasRand;
use libafl::Error;

use crate::input::MultipleInputs;

#[derive(Clone, Debug)]
pub struct MultipleGenerator<G, I, S>
where
    G: Generator<I, S>,
    I: Input,
    S: HasRand,
{
    len: usize,
    generator: G,
    phantom: PhantomData<(I, S)>,
}

impl<G, I, S> Generator<MultipleInputs<I>, S> for MultipleGenerator<G, I, S>
where
    G: Generator<I, S>,
    I: Input,
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<MultipleInputs<I>, Error> {
        let mut len = state.rand_mut().below(self.len as u64);
        if len == 0 {
            len = 1;
        }

        let mut multiple = Vec::new();
        for _ in 0..len {
            multiple.push(self.generator.generate(state).unwrap())
        }

        Ok(MultipleInputs::new(multiple))
    }

    /// Generates up to `DUMMY_BYTES_MAX` non-random dummy bytes (0)
    fn generate_dummy(&self, state: &mut S) -> MultipleInputs<I> {
        MultipleInputs::new(vec![self.generator.generate_dummy(state)])
    }
}

impl<G, I, S> MultipleGenerator<G, I, S>
where
    G: Generator<I, S>,
    I: Input,
    S: HasRand,
{
    /// Returns a new [`RandMultipleBytesGenerator`], generating up to `max_size` random bytes.
    #[allow(dead_code)]
    pub fn new(len: usize, generator: G) -> Self {
        Self {
            len,
            generator,
            phantom: PhantomData,
        }
    }
}
