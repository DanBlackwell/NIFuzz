//! Schedule the access to the Corpus.

extern crate alloc;
use alloc::borrow::ToOwned;
use core::marker::PhantomData;

use libafl_bolts::rands::Rand;
use libafl::{
    corpus::{Corpus, CorpusId, HasTestcase},
    inputs::UsesInput,
    random_corpus_id,
    state::{HasCorpus, HasRand, UsesState},
    prelude::{Scheduler},
    Error,
};

use crate::leak_fuzzer_state::{HasViolations, ViolationsTargetingApproach};

/// Feed the fuzzer simply with a random testcase on request
#[derive(Debug, Clone)]
pub struct RandLeakScheduler<S> {
    phantom: PhantomData<S>,
}

impl<S> UsesState for RandLeakScheduler<S>
where
    S: UsesInput + HasTestcase,
{
    type State = S;
}

impl<S> Scheduler for RandLeakScheduler<S>
where
    S: HasCorpus + HasRand + HasTestcase + HasViolations,
{
    fn on_add(&mut self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        // Set parent id
        let current_idx = *state.corpus().current();
        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .set_parent_id_optional(current_idx);

        Ok(())
    }

    /// Gets the next entry at random
    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        if state.corpus().count() == 0 {
            Err(Error::empty("No entries in corpus".to_owned()))
        } else {
            if state.targeting_violations() == ViolationsTargetingApproach::None {
                let id = random_corpus_id!(state.corpus(), state.rand_mut());
                self.set_current_scheduled(state, Some(id))?;
                Ok(id)
            } else {
                let next = random_corpus_id!(state.violations(), state.rand_mut());
                *state.violations_mut().current_mut() = Some(next);
                Ok(next)
            }
        }
    }
}

impl<S> RandLeakScheduler<S> {
    /// Create a new [`RandScheduler`] that just schedules randomly.
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<S> Default for RandLeakScheduler<S> {
    fn default() -> Self {
        Self::new()
    }
}
