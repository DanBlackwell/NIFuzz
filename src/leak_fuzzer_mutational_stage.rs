
use core::marker::PhantomData;

#[cfg(feature = "introspection")]
use libafl::monitors::PerfFeature;
use libafl::{
    corpus::{Corpus, CorpusId, Testcase},
    fuzzer::Evaluator,
    mark_feature_time,
    mutators::{MutationResult, Mutator},
    prelude::{mutational::{DEFAULT_MUTATIONAL_MAX_ITERATIONS, MutatedTransform}, UsesInput},
    stages::{Stage, MutationalStage, mutational::MutatedTransformPost},
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasRand, UsesState},
    Error,
};
use libafl_bolts::rands::Rand;
use crate::{leak_fuzzer_state::HasViolations, pub_sec_mutations::SecretUniformMutator, pub_sec_input::{PubSecInput, CurrentMutateTarget}};


/// Default value, how many iterations each stage gets, as an upper bound.
/// It may randomly continue earlier.
// pub static DEFAULT_MUTATIONAL_MAX_ITERATIONS: u64 = 128;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct LeakFuzzerMutationalStage<E, EM, I, M, Z> {
    mutator: M,
    uniform_mutator: SecretUniformMutator,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, Z)>,
}

impl<E, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for LeakFuzzerMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasViolations,
    <<Z as UsesState>::State as UsesInput>::Input: PubSecInput,
    I: MutatedTransform<Self::Input, Self::State> + Clone + PubSecInput,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    fn iterations(&self, state: &mut Z::State, _corpus_idx: CorpusId) -> Result<u64, Error> {
        Ok(1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS))
    }

    /// Runs this (mutational) stage for the given testcase
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let num = self.iterations(state, corpus_idx)?;

        start_timer!(state);
        if state.targeting_violations() {
            // We'll mutate the secret part of the input by selecting from uniform
            let idx = state.violations().current().unwrap();
            let mut testcase = state.violations().get(idx)?.borrow_mut();
            let Ok(input) = I::try_transform_from(&mut testcase, state, corpus_idx) else { return Ok(()); };
            drop(testcase);

            for i in 0..1_000 {
                let mut input = input.clone();

                let mutated = self.uniform_mutator.mutate(state, &mut input, i as i32)?;
                if mutated == MutationResult::Skipped {
                    panic!("This mutator shouldn't have skipped anything...");
                }
                
                // Time is measured directly the `evaluate_input` function
                let (untransformed, post) = input.try_transform_into(state)?;

                let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;
   
                start_timer!(state);
                self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
                post.post_exec(state, i as i32, corpus_idx)?;
                mark_feature_time!(state, PerfFeature::MutatePostExec);
            }

            return Ok(());
        }
   
        let mut testcase: std::cell::RefMut<'_, Testcase<<<Z as UsesState>::State as UsesInput>::Input>> = state.corpus().get(corpus_idx)?.borrow_mut();
        let Ok(mut input) = I::try_transform_from(&mut testcase, state, corpus_idx) else { return Ok(()); };
        drop(testcase);

        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);
        let orig_mutate_target = input.get_current_mutate_target();
        let mut phase = 0;
        let mut cached_input = input.clone();
   
        let iters = if orig_mutate_target == CurrentMutateTarget::All { num * 2 } else { num };
        for i in 0..iters {

            let mut input = if orig_mutate_target == CurrentMutateTarget::All {
                match phase {
                    0 => {
                        input.set_current_mutate_target(CurrentMutateTarget::Public);
                        input.clone()
                    },
                    _ => { 
                        input.set_current_mutate_target(CurrentMutateTarget::Secret);
                        cached_input.clone()
                    },
                }
            } else {
                input.clone()
            };

            // let (pub_before, sec_before) = (input.get_public_part_bytes().len(), input.get_secret_part_bytes().len());
   
            start_timer!(state);
            let mutated = self.mutator_mut().mutate(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            // println!("mutated from pub: {pub_before}, sec: {sec_before}. to pub: {}, sec: {}", input.get_public_part_bytes().len(), input.get_secret_part_bytes().len());
   
            if mutated == MutationResult::Skipped {
                continue;
            }

            if orig_mutate_target == CurrentMutateTarget::All {
                if phase == 0 { cached_input = input.clone(); }
                phase = (phase + 1) % 3;
            }
   
            // Time is measured directly the `evaluate_input` function
            let (untransformed, post) = input.try_transform_into(state)?;
            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;
   
            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            post.post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }

        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let input_ref = testcase.input_mut().as_mut().unwrap();
        let next_target = match input_ref.get_current_mutate_target() {
            CurrentMutateTarget::All => CurrentMutateTarget::Public,
            CurrentMutateTarget::Public => CurrentMutateTarget::Secret,
            CurrentMutateTarget::Secret => CurrentMutateTarget::All
        };
        input_ref.set_current_mutate_target(next_target);

        Ok(())
    }
}

impl<E, EM, I, M, Z> UsesState for LeakFuzzerMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    type State = Z::State;
}

impl<E, EM, I, M, Z> Stage<E, EM, Z> for LeakFuzzerMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasViolations,
    <<Z as UsesState>::State as UsesInput>::Input: PubSecInput,
    I: MutatedTransform<Self::Input, Self::State> + Clone + PubSecInput,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        ret
    }
}

impl<E, EM, M, Z> LeakFuzzerMutationalStage<E, EM, Z::Input, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::Input, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        Self::transforming(mutator)
    }
}

impl<E, EM, I, M, Z> LeakFuzzerMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    /// Creates a new transforming mutational stage
    pub fn transforming(mutator: M) -> Self {
        Self {
            mutator,
            uniform_mutator: SecretUniformMutator::new(),
            phantom: PhantomData,
        }
    }
}