
use core::marker::PhantomData;

use hashbrown::HashSet;
use rand::{seq::IteratorRandom, thread_rng};

#[cfg(feature = "introspection")]
use libafl::monitors::PerfFeature;
use libafl::{
    corpus::{Corpus, CorpusId},
    fuzzer::Evaluator,
    mark_feature_time,
    mutators::{MutationResult, Mutator},
    prelude::{mutational::{DEFAULT_MUTATIONAL_MAX_ITERATIONS, MutatedTransform}, UsesInput},
    stages::{Stage, MutationalStage, mutational::MutatedTransformPost},
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasRand, UsesState},
    Error, HasScheduler,
};
use libafl_bolts::rands::Rand;
use crate::{
    leak_fuzzer_state::{HasViolations, ViolationsTargetingApproach}, 
    pub_sec_mutations::SecretUniformMutator, 
    pub_sec_input::{PubSecInput, CurrentMutateTarget}, 
    output_leak_fuzzer::HasHypertestFeedback, 
    hypertest_feedback::HypertestFeedback
};


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

// #[derive(Serialize, Deserialize, SerdeAny, Debug, Clone)]
// pub struct LeakQuantifyMetadata {
//     /// Reference to the output with no bits flipped
//     pub original_output: OutputData,
//     /// A list of bits that have been flipped for the current input
//     pub current_bitflips: Vec<usize>,
//     /// Flipping the bit at [index] causes 1 bit flip at the output
//     pub bitflip_flips_output_bit: Vec<Option<usize>>,
//     /// Have we completed the deterministic bit flipping stage
//     pub completed_deterministic_bitflips: bool,
//     /// set to true if we find that bitflips in input don't map directly to output
//     pub bitflips_do_not_map: bool
// }

impl<E, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for LeakFuzzerMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM> + HasScheduler + HasHypertestFeedback,
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
        if state.targeting_violations() != ViolationsTargetingApproach::None {
            // We'll mutate the secret part of the input by selecting from uniform
            let idx = state.violations().current().unwrap();
            let mut testcase = state.violations().get(idx)?.borrow_mut();

            let Ok(input) = I::try_transform_from(&mut testcase, state, idx) else { return Ok(()); };

            match state.targeting_violations() {
                ViolationsTargetingApproach::SingleBitFlips => {
                    drop(testcase);
                    self.leak_test_all_bitflips(fuzzer, executor, state, manager, idx)?;
                },
                ViolationsTargetingApproach::RandomBitFlips => {
                    drop(testcase);
                    self.leak_test_random_bitflip_combos(fuzzer, executor, state, manager, idx)?;
                },
                ViolationsTargetingApproach::UniformSampling => {
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
                },
                _ => panic!()
            }

            return Ok(());
        }
   
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
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
    Z: Evaluator<E, EM> + HasScheduler + HasHypertestFeedback,
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

impl<E, EM, I, M, Z> LeakFuzzerMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM> + HasScheduler + HasHypertestFeedback,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasViolations,
    <<Z as UsesState>::State as UsesInput>::Input: PubSecInput,
    I: MutatedTransform<<Self as UsesInput>::Input, <Self as UsesState>::State> + Clone + PubSecInput,
{
    pub fn leak_test_all_bitflips(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        violation_idx: CorpusId,
    ) -> Result<(), Error> {
        let mut input;
        {
            let mut testcase = state.violations().get(violation_idx)?.borrow_mut();
            if let Ok(i) = Z::Input::try_transform_from(&mut testcase, state, violation_idx) {
                input = i.clone();
            } else { 
                return Ok(()); 
            }
        }
        println!("Will leak test all bitflips for input of len {} bits", input.get_secret_part_bytes().len() * 8);
        input.set_current_mutate_target(CurrentMutateTarget::Secret);
        let cur = input.get_mutable_current_buf_seg().to_owned();
        assert!(input.get_secret_part_bytes() == cur);
        assert!(cur.len() > 0);

        for i in 0..(8 * input.get_secret_part_bytes().len()) {
            let mut input = input.clone();

            let buf = input.get_mutable_current_buf_seg();
            let byte = i / 8;
            let bitmask: u8 = 0x80 >> (i % 8);
            buf[byte] ^= bitmask;

            let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input)?;
            metadata.current_bitflips = vec![i];
        
            // Time is measured directly the `evaluate_input` function
            let (untransformed, post) = input.try_transform_into(state)?;

            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;

            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            post.post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }

        let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input)?;
        metadata.current_bitflips.clear();

        let mut seen_output_flips = HashSet::new();
        let mut dupes = HashSet::new();
        for flip_map in &metadata.bitflip_flips_output_bits {
            for out_flip in flip_map {
                if !seen_output_flips.insert(*out_flip) {
                    dupes.insert(*out_flip);
                }
            }
        }

        let mut mapped_bitflips = 0;
        if dupes.is_empty() {
            // no need to filter out the dupes (it's empty)
            mapped_bitflips = metadata.bitflip_flips_output_bits.iter()
                .filter(|flips| !flips.is_empty())
                .count();
        } else {
            // Filter out all the dupes so we don't get caught out later!
            let mut filtered = vec![];
            for bitflip_map in &metadata.bitflip_flips_output_bits {
                // filter out any bits that get affected by many input bits
                let temp = bitflip_map.iter()
                    .filter(|&x| !dupes.contains(x))
                    .map(|&x| x)
                    .collect::<Vec<usize>>();

                if !temp.is_empty() { mapped_bitflips += 1; }

                filtered.push(temp);
            }
            metadata.bitflip_flips_output_bits = filtered;
        }

        println!("Removing dupes: {:?}", dupes);
        metadata.ignored_output_bitflips = dupes;

        match mapped_bitflips {
            0 => metadata.bitflips_do_not_map = true,
            // there are no 'random combos' to test...
            1 => metadata.completed_deterministic_bitflips = true,
            _ => (),
        };

        Ok(())
    }

    pub fn leak_test_random_bitflip_combos(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        violation_idx: CorpusId,
    ) -> Result<(), Error> {
        // Try random combos of bitflips to check that they do map as expected
        // println!("Ok, should try random combos now!");

        let input;
        {
            let mut testcase = state.violations().get(violation_idx)?.borrow_mut();
            match Z::Input::try_transform_from(&mut testcase, state, violation_idx) {
                Ok(i) => input = i,
                Err(_) => return Ok(()),
            };
        }


        let mut input = input.clone();
        input.set_current_mutate_target(CurrentMutateTarget::Secret);
        let sec_len_bits = 8 * input.get_secret_part_bytes().len();

        for stage in 0..sec_len_bits {
            let output_mapped_bits = {
                let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata(&input)?;
                metadata.bitflip_flips_output_bits.iter()
                    .enumerate()
                    .filter(|(_idx, val)| !val.is_empty())
                    .map(|(idx, _)| idx)
                    .collect::<Vec<usize>>()
            };
    
            let mut input = input.clone();
            let secret = input.get_mutable_current_buf_seg();
            let mut rand = thread_rng();

            let bits_to_flip = match stage {
                0 => output_mapped_bits.clone(),
                1 => output_mapped_bits[0..(output_mapped_bits.len() / 2)].to_owned(),
                2 => output_mapped_bits[(output_mapped_bits.len() / 2)..].to_owned(),
                _ => output_mapped_bits.clone().into_iter().choose_multiple(
                    &mut rand,
                    if stage < sec_len_bits / 8 {
                            3 * output_mapped_bits.len() / 4
                    } else if stage < sec_len_bits / 4 {
                            std::cmp::max(std::cmp::min(sec_len_bits, 4), output_mapped_bits.len() / 2)
                    } else if stage < sec_len_bits / 2 {
                            std::cmp::max(std::cmp::min(sec_len_bits, 3), output_mapped_bits.len() / 4)
                    } else {
                            std::cmp::max(std::cmp::min(sec_len_bits, 2), output_mapped_bits.len() / 8)
                    }
                )
            };

            // no point checking single bit flips again...
            if bits_to_flip.len() <= 1 { break; }

            for bit in &bits_to_flip {
                secret[bit / 8] ^= (0x80 >> (bit % 8)) as u8;
            }

            {
                let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input)?;
                if bits_to_flip.is_empty() {
                    panic!("supposed to flips {} bits (from possible {:?}), in input of len: {}", bits_to_flip.len(), output_mapped_bits, sec_len_bits);
                }
                metadata.current_bitflips = bits_to_flip;
            }

            let (untransformed, post) = input.try_transform_into(state)?;

            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;

            start_timer!(state);
            let i = 0;
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            post.post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }

        let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input)?;
        metadata.current_bitflips.clear();
        metadata.completed_deterministic_bitflips = true;
        println!("Completed deterministic bitflips for an input!");
        Ok(())
    }
}
