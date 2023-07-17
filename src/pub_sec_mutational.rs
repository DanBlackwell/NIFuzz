//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use core::marker::PhantomData;

#[cfg(feature = "introspection")]
use libafl::monitors::PerfFeature;
use libafl::{
    bolts::rands::Rand,
    corpus::{Corpus, CorpusId, Testcase},
    fuzzer::Evaluator,
    inputs::Input,
    mark_feature_time,
    mutators::{MultipleMutator, MutationResult, Mutator},
    prelude::{MutationId, HasConstLen, Named},
    stages::{Stage, mutational::{MutatedTransform, MutationalStage, MutatedTransformPost}},
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasRand, UsesState},
    Error,
};

use crate::pub_sec_mutations::PubSecMutator;

/// A `Tuple` of `Mutators` that can execute multiple `Mutators` in a row.
pub trait PubSecMutatorsTuple<I, S>: HasConstLen {
    // /// Runs the `mutate` function on all `Mutators` in this `Tuple`.
    // fn mutate_all(
    //     &mut self,
    //     state: &mut S,
    //     input: &mut I,
    //     stage_idx: i32,
    // ) -> Result<MutationResult, Error>;

    // /// Runs the `post_exec` function on all `Mutators` in this `Tuple`.
    // fn post_exec_all(
    //     &mut self,
    //     state: &mut S,
    //     stage_idx: i32,
    //     corpus_idx: Option<CorpusId>,
    // ) -> Result<(), Error>;

    /// Gets the [`Mutator`] at the given index and runs the `mutate` function on it.
    fn get_and_pub_sec_mutate(
        &mut self,
        index: MutationId,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error>;

    // /// Gets the [`Mutator`] at the given index and runs the `post_exec` function on it.
    // fn get_and_post_exec(
    //     &mut self,
    //     index: usize,
    //     state: &mut S,
    //     stage_idx: i32,
    //     corpus_idx: Option<CorpusId>,
    // ) -> Result<(), Error>;
}

impl<I, S> PubSecMutatorsTuple<I, S> for () {
    // fn mutate_all(
    //     &mut self,
    //     _state: &mut S,
    //     _input: &mut I,
    //     _stage_idx: i32,
    // ) -> Result<MutationResult, Error> {
    //     Ok(MutationResult::Skipped)
    // }

    // fn post_exec_all(
    //     &mut self,
    //     _state: &mut S,
    //     _stage_idx: i32,
    //     _corpus_idx: Option<CorpusId>,
    // ) -> Result<(), Error> {
    //     Ok(())
    // }

    fn get_and_pub_sec_mutate(
        &mut self,
        _index: MutationId,
        _state: &mut S,
        _input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        Ok(MutationResult::Skipped)
    }

    // fn get_and_post_exec(
    //     &mut self,
    //     _index: usize,
    //     _state: &mut S,
    //     _stage_idx: i32,
    //     _corpus_idx: Option<CorpusId>,
    // ) -> Result<(), Error> {
    //     Ok(())
    // }
}

impl<Head, Tail, I, S> PubSecMutatorsTuple<I, S> for (Head, Tail)
where
    Head: PubSecMutator<I, S> + Named,
    Tail: PubSecMutatorsTuple<I, S>,
{
    // fn mutate_all(
    //     &mut self,
    //     state: &mut S,
    //     input: &mut I,
    //     stage_idx: i32,
    // ) -> Result<MutationResult, Error> {
    //     let r = self.0.mutate(state, input, stage_idx)?;
    //     if self.1.mutate_all(state, input, stage_idx)? == MutationResult::Mutated {
    //         Ok(MutationResult::Mutated)
    //     } else {
    //         Ok(r)
    //     }
    // }

    // fn post_exec_all(
    //     &mut self,
    //     state: &mut S,
    //     stage_idx: i32,
    //     corpus_idx: Option<CorpusId>,
    // ) -> Result<(), Error> {
    //     self.0.post_exec(state, stage_idx, corpus_idx)?;
    //     self.1.post_exec_all(state, stage_idx, corpus_idx)
    // }

    fn get_and_pub_sec_mutate(
        &mut self,
        index: MutationId,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if index.0 == 0 {
            self.0.mutate_pub_sec(state, input, stage_idx)
        } else {
            self.1
                .get_and_pub_sec_mutate((index.0 - 1).into(), state, input, stage_idx)
        }
    }

    // fn get_and_post_exec(
    //     &mut self,
    //     index: usize,
    //     state: &mut S,
    //     stage_idx: i32,
    //     corpus_idx: Option<CorpusId>,
    // ) -> Result<(), Error> {
    //     if index == 0 {
    //         self.0.post_exec(state, stage_idx, corpus_idx)
    //     } else {
    //         self.1
    //             .get_and_post_exec(index - 1, state, stage_idx, corpus_idx)
    //     }
    // }
}

// TODO multi mutators stage

// /// Action performed after the un-transformed input is executed (e.g., updating metadata)
// #[allow(unused_variables)]
// pub trait PubSecMutatedTransformPost<S>: Sized {
//     /// Perform any post-execution steps necessary for the transformed input (e.g., updating metadata)
//     #[inline]
//     fn post_exec(
//         self,
//         state: &mut S,
//         stage_idx: i32,
//         corpus_idx: Option<CorpusId>,
//     ) -> Result<(), Error> {
//         Ok(())
//     }
// }

// impl<S> PubSecMutatedTransformPost<S> for () {}

// /// A type which may both be transformed from and into a given input type, used to perform
// /// mutations over inputs which are not necessarily performable on the underlying type
// ///
// /// This trait is implemented such that all testcases inherently transform to their inputs, should
// /// the input be cloneable.
// pub trait PubSecMutatedTransform<I, S>: Sized
// where
//     I: Input,
// {
//     /// Type indicating actions to be taken after the post-transformation input is executed
//     type Post: PubSecMutatedTransformPost<S>;

//     /// Transform the provided testcase into this type
//     fn try_transform_from(
//         base: &mut Testcase<I>,
//         state: &S,
//         corpus_idx: CorpusId,
//     ) -> Result<Self, Error>;

//     /// Transform this instance back into the original input type
//     fn try_transform_into(self, state: &S) -> Result<(I, Self::Post), Error>;
// }

// // reflexive definition
// impl<I, S> PubSecMutatedTransform<I, S> for I
// where
//     I: Input + Clone,
//     S: HasCorpus<Input = I>,
// {
//     type Post = ();

//     #[inline]
//     fn try_transform_from(
//         base: &mut Testcase<I>,
//         state: &S,
//         _corpus_idx: CorpusId,
//     ) -> Result<Self, Error> {
//         state.corpus().load_input_into(base)?;
//         Ok(base.input().as_ref().unwrap().clone())
//     }

//     #[inline]
//     fn try_transform_into(self, _state: &S) -> Result<(I, Self::Post), Error> {
//         Ok((self, ()))
//     }
// }

/// A Mutational stage is the stage in a fuzzing run that mutates inputs.
/// Mutational stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
pub trait PubSecMutationalStage<E, EM, I, M, Z>: Stage<E, EM, Z>
where
    E: UsesState<State = Self::State>,
    M: PubSecMutator<I, Self::State> + Mutator<I, Self::State>,
    EM: UsesState<State = Self::State>,
    Z: Evaluator<E, EM, State = Self::State>,
    Self::State: HasClientPerfMonitor + HasCorpus,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut Z::State, corpus_idx: CorpusId) -> Result<u64, Error>;

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
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let Ok(input) = I::try_transform_from(&mut testcase, state, corpus_idx) else {
            return Ok(());
        };
        drop(testcase);
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        for i in 0..num {
            let mut input = input.clone();

            start_timer!(state);
            let mutated = self.mutator_mut().mutate_pub_sec(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            if mutated == MutationResult::Skipped {
                continue;
            }

            // Time is measured directly the `evaluate_input` function
            let (untransformed, post) = input.try_transform_into(state)?;
            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;

            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            post.post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }
        Ok(())
    }
}

/// Default value, how many iterations each stage gets, as an upper bound.
/// It may randomly continue earlier.
pub static DEFAULT_MUTATIONAL_MAX_ITERATIONS: u64 = 128;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct StdPubSecMutationalStage<E, EM, I, M, Z> {
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, Z)>,
}

impl<E, EM, I, M, Z> PubSecMutationalStage<E, EM, I, M, Z> for StdPubSecMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: PubSecMutator<I, Z::State> + Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
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
}

impl<E, EM, I, M, Z> UsesState for StdPubSecMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: PubSecMutator<I, Z::State> + Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    type State = Z::State;
}

impl<E, EM, I, M, Z> Stage<E, EM, Z> for StdPubSecMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: PubSecMutator<I, Z::State> + Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
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

impl<E, EM, M, Z> StdPubSecMutationalStage<E, EM, Z::Input, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: PubSecMutator<Z::Input, Z::State> + Mutator<Z::Input, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        Self::transforming(mutator)
    }
}

impl<E, EM, I, M, Z> StdPubSecMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: PubSecMutator<I, Z::State> + Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    /// Creates a new transforming mutational stage
    pub fn transforming(mutator: M) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
}

// /// The default mutational stage
// #[derive(Clone, Debug)]
// pub struct MultipleMutationalStage<E, EM, I, M, Z> {
//     mutator: M,
//     #[allow(clippy::type_complexity)]
//     phantom: PhantomData<(E, EM, I, Z)>,
// }

// impl<E, EM, I, M, Z> UsesState for MultipleMutationalStage<E, EM, I, M, Z>
// where
//     E: UsesState<State = Z::State>,
//     EM: UsesState<State = Z::State>,
//     M: MultipleMutator<I, Z::State>,
//     Z: Evaluator<E, EM>,
//     Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
// {
//     type State = Z::State;
// }

// impl<E, EM, I, M, Z> Stage<E, EM, Z> for MultipleMutationalStage<E, EM, I, M, Z>
// where
//     E: UsesState<State = Z::State>,
//     EM: UsesState<State = Z::State>,
//     M: MultipleMutator<I, Z::State>,
//     Z: Evaluator<E, EM>,
//     Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
//     I: MutatedTransform<Self::Input, Self::State> + Clone,
// {
//     #[inline]
//     #[allow(clippy::let_and_return)]
//     #[allow(clippy::cast_possible_wrap)]
//     fn perform(
//         &mut self,
//         fuzzer: &mut Z,
//         executor: &mut E,
//         state: &mut Z::State,
//         manager: &mut EM,
//         corpus_idx: CorpusId,
//     ) -> Result<(), Error> {
//         let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
//         let Ok(input) = I::try_transform_from(&mut testcase, state, corpus_idx) else { return Ok(()); };
//         drop(testcase);

//         let mut generated = vec![];
//         let _ = self.mutator.mutate(state, &input, &mut generated, 0)?;
//         // println!("Generated {}", generated.len());
//         for (i, new_input) in generated.into_iter().enumerate() {
//             // Time is measured directly the `evaluate_input` function
//             let (untransformed, post) = new_input.try_transform_into(state)?;
//             let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;
//             self.mutator.post_exec(state, i as i32, corpus_idx)?;
//             post.post_exec(state, i as i32, corpus_idx)?;
//         }
//         // println!("Found {}", found);

//         Ok(())
//     }
// }

// impl<E, EM, M, Z> MultipleMutationalStage<E, EM, Z::Input, M, Z>
// where
//     E: UsesState<State = Z::State>,
//     EM: UsesState<State = Z::State>,
//     M: MultipleMutator<Z::Input, Z::State>,
//     Z: Evaluator<E, EM>,
//     Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
// {
//     /// Creates a new default mutational stage
//     pub fn new(mutator: M) -> Self {
//         Self::transforming(mutator)
//     }
// }

// impl<E, EM, I, M, Z> MultipleMutationalStage<E, EM, I, M, Z>
// where
//     E: UsesState<State = Z::State>,
//     EM: UsesState<State = Z::State>,
//     M: MultipleMutator<I, Z::State>,
//     Z: Evaluator<E, EM>,
//     Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
// {
//     /// Creates a new transforming mutational stage
//     pub fn transforming(mutator: M) -> Self {
//         Self {
//             mutator,
//             phantom: PhantomData,
//         }
//     }
// }

// #[cfg(feature = "python")]
// #[allow(missing_docs)]
// /// `PubSecMutationalStage` Python bindings
// pub mod pybind {
//     use pyo3::prelude::*;

//     use crate::{
//         events::pybind::PythonEventManager,
//         executors::pybind::PythonExecutor,
//         fuzzer::pybind::PythonStdFuzzer,
//         inputs::BytesInput,
//         mutators::pybind::PythonMutator,
//         stages::{pybind::PythonStage, PubSecMutationalStage},
//     };

//     #[pyclass(unsendable, name = "StdMutationalStage")]
//     #[derive(Debug)]
//     /// Python class for StdMutationalStage
//     pub struct PythonStdMutationalStage {
//         /// Rust wrapped StdMutationalStage object
//         pub inner: StdMutationalStage<
//             PythonExecutor,
//             PythonEventManager,
//             BytesInput,
//             PythonMutator,
//             PythonStdFuzzer,
//         >,
//     }

//     #[pymethods]
//     impl PythonStdMutationalStage {
//         #[new]
//         fn new(mutator: PythonMutator) -> Self {
//             Self {
//                 inner: StdMutationalStage::new(mutator),
//             }
//         }

//         fn as_stage(slf: Py<Self>) -> PythonStage {
//             PythonStage::new_std_mutational(slf)
//         }
//     }

//     /// Register the classes to the python module
//     pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
//         m.add_class::<PythonStdMutationalStage>()?;
//         Ok(())
//     }
// }
