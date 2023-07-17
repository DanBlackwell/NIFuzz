//! The `ScheduledMutator` schedules multiple mutations internally.

extern crate alloc;
use alloc::{string::String, vec::Vec};
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};

pub use libafl::mutators::{mutations::*, token_mutations::*};
use libafl::{
    bolts::{
        rands::Rand,
        tuples::{tuple_list, tuple_list_type, NamedTuple},
        AsMutSlice, AsSlice,
    },
    corpus::{Corpus, CorpusId},
    mutators::{MutationResult, Mutator, MutatorsTuple, ComposedByMutations, ScheduledMutator},
    prelude::MutationId,
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};

use crate::pub_sec_mutations::PubSecMutator;
use crate::pub_sec_mutational::PubSecMutatorsTuple;

// /// The metadata placed in a [`crate::corpus::Testcase`] by a [`LoggerScheduledMutator`].
// #[derive(Debug, Serialize, Deserialize)]
// pub struct LogMutationMetadata {
//     /// A list of logs
//     pub list: Vec<String>,
// }

// crate::impl_serdeany!(LogMutationMetadata);

// impl AsSlice for LogMutationMetadata {
//     type Entry = String;
//     #[must_use]
//     fn as_slice(&self) -> &[String] {
//         self.list.as_slice()
//     }
// }
// impl AsMutSlice for LogMutationMetadata {
//     type Entry = String;
//     #[must_use]
//     fn as_mut_slice(&mut self) -> &mut [String] {
//         self.list.as_mut_slice()
//     }
// }

// impl LogMutationMetadata {
//     /// Creates new [`struct@LogMutationMetadata`].
//     #[must_use]
//     pub fn new(list: Vec<String>) -> Self {
//         Self { list }
//     }
// }

// /// A [`Mutator`] that composes multiple mutations into one.
// pub trait ComposedByMutations<I, MT, S>
// where
//     MT: MutatorsTuple<I, S>,
// {
//     /// Get the mutations
//     fn mutations(&self) -> &MT;

//     /// Get the mutations (mutable)
//     fn mutations_mut(&mut self) -> &mut MT;
// }

/// A [`Mutator`] scheduling multiple [`Mutator`]s for an input.
// pub trait ScheduledMutator<I, MT, S>: ComposedByMutations<I, MT, S> + Mutator<I, S>
// where
//     MT: MutatorsTuple<I, S>,
// {
//     /// Compute the number of iterations used to apply stacked mutations
//     fn iterations(&self, state: &mut S, input: &I) -> u64;

//     /// Get the next mutation to apply
//     fn schedule(&self, state: &mut S, input: &I) -> MutationId;

//     /// New default implementation for mutate.
//     /// Implementations must forward mutate() to this method
//     fn scheduled_mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut I,
//         stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let mut r = MutationResult::Skipped;
//         let num = self.iterations(state, input);
//         for _ in 0..num {
//             let idx = self.schedule(state, input);
//             let outcome = self
//                 .mutations_mut()
//                 .get_and_mutate(idx, state, input, stage_idx)?;
//             if outcome == MutationResult::Mutated {
//                 r = MutationResult::Mutated;
//             }
//         }
//         Ok(r)
//     }
// }

/// A [`Mutator`] that schedules one of the embedded mutations on each call.
pub struct PubSecScheduledMutator<I, MT, S>
where
    MT: PubSecMutatorsTuple<I, S>,
    S: HasRand,
{
    mutations: MT,
    max_stack_pow: u64,
    phantom: PhantomData<(I, S)>,
}

impl<I, MT, S> Debug for PubSecScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PubSecScheduledMutator with {} mutations for Input type {}",
            self.mutations.len(),
            core::any::type_name::<I>()
        )
    }
}

impl<I, MT, S> Mutator<I, S> for PubSecScheduledMutator<I, MT, S>
where
    MT: PubSecMutatorsTuple<I, S>,
    S: HasRand,
{
    #[inline]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }
}

impl<I, MT, S> ComposedByMutations<I, MT, S> for PubSecScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Get the mutations
    #[inline]
    fn mutations(&self) -> &MT {
        &self.mutations
    }

    // Get the mutations (mutable)
    #[inline]
    fn mutations_mut(&mut self) -> &mut MT {
        &mut self.mutations
    }
}

impl<I, MT, S> ScheduledMutator<I, MT, S> for PubSecScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        1 << (1 + state.rand_mut().below(self.max_stack_pow))
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(!self.mutations().is_empty());
        state.rand_mut().below(self.mutations().len() as u64).into()
    }

    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let mut r = MutationResult::Skipped;
        let num = self.iterations(state, input);
        self.mutation_log.clear();
        for _ in 0..num {
            let idx = self.schedule(state, input);
            self.mutation_log.push(idx);
            let outcome = self
                .mutations_mut()
                .get_and_pub_sec_mutate(idx, state, input, stage_idx)?;
            if outcome == MutationResult::Mutated {
                r = MutationResult::Mutated;
            }
        }
        Ok(r)
    }
}

impl<I, MT, S> PubSecScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Create a new [`PubSecScheduledMutator`] instance specifying mutations
    pub fn new(mutations: MT) -> Self {
        PubSecScheduledMutator {
            mutations,
            max_stack_pow: 7,
            phantom: PhantomData,
        }
    }

    /// Create a new [`PubSecScheduledMutator`] instance specifying mutations and the maximun number of iterations
    pub fn with_max_stack_pow(mutations: MT, max_stack_pow: u64) -> Self {
        PubSecScheduledMutator {
            mutations,
            max_stack_pow,
            phantom: PhantomData,
        }
    }
}