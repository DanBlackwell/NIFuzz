
use core::marker::PhantomData;
use bitvec::prelude::{BitVec, Msb0};
use hashbrown::{HashSet, HashMap};
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
    Error, HasScheduler, executors::HasObservers,
};
use libafl_bolts::{rands::Rand, tuples::MatchName};
use crate::{
    leak_fuzzer_state::{HasViolations, ViolationsTargetingApproach}, 
    pub_sec_mutations::UniformMutator, 
    pub_sec_input::{PubSecInput, MutateTarget, InputContentsFlags}, 
    output_leak_fuzzer::HasHypertestFeedback, 
    hypertest_feedback::{HypertestFeedback, BitflipMap, InputBitLocation, OutputBitLocation}, output_feedback::{OutputSource, OutputData}, output_observer::OutputObserver
};

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct LeakFuzzerMutationalStage<E, EM, I, M, Z> {
    mutator: M,
    uniform_mutator: UniformMutator,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, Z)>,
}

impl<E, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for LeakFuzzerMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State> + HasObservers,
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
        start_timer!(state);
        if state.targeting_violations() != ViolationsTargetingApproach::None {
            // We'll mutate the secret part of the input by selecting from uniform
            let idx = state.violations().current().unwrap();
            let mut testcase = state.violations().get(idx)?.borrow_mut();
            let original_input = testcase.input().as_ref().unwrap().clone();
            let Ok(input) = I::try_transform_from(&mut testcase, state, idx) else { return Ok(()); };
            drop(testcase);
            mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

            match state.targeting_violations() {
                ViolationsTargetingApproach::BitFlips => {
                    self.find_leaked_bitflips(fuzzer, executor, state, manager, idx)?;
                },
                ViolationsTargetingApproach::UniformSampling => {
                    #[cfg(feature = "std")]
                    let start_time = std::time::SystemTime::now();
                    let mut total_iterations = 0;
                    let mut iterations_since_find = 0;
                    let mut unique_uniform_outputs = fuzzer.hypertest_feedback().get_uniform_sampled_output_count(&original_input);

                    loop {
                        let mut input = input.clone();
        
                        input.set_current_mutate_target(MutateTarget::SecretExplicitInput);
                        let mutated = self.uniform_mutator.mutate(state, &mut input, 0 as i32)?;
                        if mutated == MutationResult::Skipped { panic!("This mutator should never skip..."); }
                        
                        // Time is measured directly the `evaluate_input` function
                        let (untransformed, post) = input.try_transform_into(state)?;
        
                        let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;
        
                        start_timer!(state);
                        self.mutator_mut().post_exec(state, 0 as i32, corpus_idx)?;
                        post.post_exec(state, 0 as i32, corpus_idx)?;
                        mark_feature_time!(state, PerfFeature::MutatePostExec);

                        let prev = unique_uniform_outputs;
                        unique_uniform_outputs = fuzzer.hypertest_feedback().get_uniform_sampled_output_count(&original_input);
                        total_iterations += 1;
                        if unique_uniform_outputs > prev {
                            iterations_since_find = 0;
                        } else if iterations_since_find > 1000 {
                            // println!("Escaping after finding {unique_uniform_outputs} unique outputs in {total_iterations} iterations");
                            break;
                        } else {
                            iterations_since_find += 1;
                        }

                        #[cfg(feature = "std")]
                        if std::time::SystemTime::now().duration_since(start_time).unwrap().as_millis() > 15_000 {
                            // println!("15 seconds up! found {unique_uniform_outputs} unique outputs in {total_iterations} iterations");
                            break;
                        }


                    }
                },
                _ => panic!()
            }

            return Ok(());
        }
   
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let Ok(input) = I::try_transform_from(&mut testcase, state, corpus_idx) else { return Ok(()); };
        drop(testcase);

        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);
        match input.get_current_mutate_target() {
            MutateTarget::All => self.run_hypertests(fuzzer, executor, state, manager, corpus_idx, &input)?,
            _ => {
                let num = self.iterations(state, corpus_idx)?;
                for i in 0..num {
                    let mut input = input.clone();

                    start_timer!(state);
                    let mutated = self.mutator_mut().mutate(state, &mut input, i as i32)?;
                    mark_feature_time!(state, PerfFeature::Mutate);

                    if mutated == MutationResult::Skipped { continue; }

                    // Time is measured directly the `evaluate_input` function
                    let (untransformed, post) = input.try_transform_into(state)?;
                    let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;
        
                    start_timer!(state);
                    self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
                    post.post_exec(state, i as i32, corpus_idx)?;
                    mark_feature_time!(state, PerfFeature::MutatePostExec);
                }
            }
        }

        if !state.estimate_cmi_mode() {
            let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
            let input_ref = testcase.input_mut().as_mut().unwrap();
            let next_target = match input_ref.get_current_mutate_target() {
                MutateTarget::All => MutateTarget::PublicExplicitInput,
                MutateTarget::PublicExplicitInput => MutateTarget::All,
                _ => MutateTarget::All, // this case only occurs if a new testcase was stored during Secret mutation
            };
            input_ref.set_current_mutate_target(next_target);
        }

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
    E: UsesState<State = Z::State> + HasObservers,
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
            uniform_mutator: UniformMutator::new(),
            phantom: PhantomData,
        }
    }
}

impl<E, EM, I, M, Z> LeakFuzzerMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State> + HasObservers,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM> + HasScheduler + HasHypertestFeedback,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasViolations,
    <<Z as UsesState>::State as UsesInput>::Input: PubSecInput,
    I: MutatedTransform<<Self as UsesInput>::Input, <Self as UsesState>::State> + Clone + PubSecInput,
{
    pub fn run_hypertests(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
        input: &I
    ) -> Result<(), Error> {
        let mut phase = 0;
        let mut original_input = input.clone();
        original_input.set_current_mutate_target(MutateTarget::PublicExplicitInput);
        let mut cached_input = input.clone();
   
        let num = if state.estimate_cmi_mode() {
            100_000
        } else {
            2 * self.iterations(state, corpus_idx).unwrap()
        };
        // do double the number of iterations to generate and test `num` hypertests
        for i in 0..num {
            let mut input = match phase {
                0 => {
                    original_input.clone()
                },
                _ => { 
                    let mut input = cached_input.clone();
                    input.set_current_mutate_target(MutateTarget::SecretExplicitInput);
                    let mem_pattern = if phase == 1 { [0xAA] } else { [0x55] };
                    if input.get_part_bytes(InputContentsFlags::SecretStackMemory).is_some() {
                        input.set_part_bytes(InputContentsFlags::SecretStackMemory, &mem_pattern);
                    }
                    if input.get_part_bytes(InputContentsFlags::SecretHeapMemory).is_some() {
                        input.set_part_bytes(InputContentsFlags::SecretHeapMemory, &mem_pattern);
                    }
                    input
                },
            };
   
            let should_mutate;
            if input.get_current_mutate_target() == MutateTarget::SecretExplicitInput {
                should_mutate = input.get_part_bytes(InputContentsFlags::SecretExplicitInput).is_some();
                if !should_mutate {
                    input.set_current_mutate_target(MutateTarget::PublicExplicitInput);
                }
            } else {
                should_mutate = true;
            }

            // if we're mutating public, or the program has an explicit secret input (not all do)
            if should_mutate {
                start_timer!(state);
                let mutated = self.mutator_mut().mutate(state, &mut input, i as i32)?;
                mark_feature_time!(state, PerfFeature::Mutate);

                if mutated == MutationResult::Skipped { continue; }
            }


            if phase == 0 { cached_input = input.clone(); println!("public: {:?}", input.get_part_bytes(InputContentsFlags::PublicExplicitInput))}
            let max_phases = if state.estimate_cmi_mode() { 100_000 } else { 3 };
            phase = (phase + 1) % max_phases;

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

    pub fn find_leaked_bitflips(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        violation_idx: CorpusId,
    ) -> Result<(), Error> {
        let input;
        {
            let mut testcase = state.violations().get(violation_idx)?.borrow_mut();
            if let Ok(i) = Z::Input::try_transform_from(&mut testcase, state, violation_idx) {
                input = i.clone();
            } else { 
                return Ok(()); 
            }
        }

        let potential_parts = [
            InputContentsFlags::SecretExplicitInput,
            InputContentsFlags::SecretStackMemory,
            InputContentsFlags::SecretHeapMemory,
        ];
        let mut effectual_parts = vec![];
        let mut longest_part_bits = 0;
        // {
        //     let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input).unwrap();
        //     println!("ORIGINAL OUTPUT: {}", metadata.original_output.to_string());
        // }
        for part in potential_parts {
            if let Some(buf) = input.get_part_bytes(part) {
                let inverted = buf.iter().map(|byte| byte ^ 0xFF).collect::<Vec<u8>>();
                let mut input = input.clone();
                input.set_part_bytes(part, &inverted);
                let output = self.execute_input_and_collect_output(fuzzer, executor, state, manager, &input).unwrap();
                let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input).unwrap();

                // println!("{:?} FLIPPED OUTPUT: {}", part, output.to_string());
                if output != metadata.original_output {
                    effectual_parts.push(part);
                    // println!("Ok, adding {:?} to the effectual_parts list", part);
                    longest_part_bits = std::cmp::max(8 * buf.len(), longest_part_bits);
                }
            }
        }

        if effectual_parts.is_empty() {
            let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input).unwrap();
            metadata.bitflips_do_not_map = true;
            metadata.completed_deterministic_bitflips = true;
            return Ok(());
        }

        let bitflip_map = if longest_part_bits > 1000 {
            self.quick_find_all_bitflips(fuzzer, executor, state, manager, &input, &effectual_parts)
        } else {
            self.leak_test_all_individual_bitflips(fuzzer, executor, state, manager, &input, &effectual_parts)
        }.unwrap();

        // For input bits that map to many output bit flips, find the furthest distance 
        // as we will extend the secret input by this amount
        let mut max_dists: HashMap<InputContentsFlags, usize> = HashMap::new();
        for (in_bit_location, out_bit_locations) in bitflip_map.iterate_map() {
            let mut mins_and_maxes = HashMap::new();
            for out_bit in out_bit_locations {
                if let Some((min, max)) = mins_and_maxes.get_mut(&out_bit.source) {
                    if out_bit.bit_num < *min { *min = out_bit.bit_num; }
                    if out_bit.bit_num > *max { *max = out_bit.bit_num; }
                } else {
                    mins_and_maxes.insert(out_bit.source, (out_bit.bit_num, out_bit.bit_num));
                }
            }

            for (_source, (min, max)) in mins_and_maxes {
                if let Some(cur_dist) = max_dists.get_mut(&in_bit_location.part) {
                    if max - min > *cur_dist { *cur_dist = max - min; }
                } else {
                    max_dists.insert(in_bit_location.part, max - min);
                }
            }
        }

        {
            let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input).unwrap();
            metadata.bitflip_flips_output_bits = bitflip_map;

            // Ok, no one-to-many mappings so don't bother extending the input for now
            if max_dists.iter().filter(|(_, &extend_dist)| extend_dist > 0).count() == 0 {
                println!("didn't find any need to extend");
                if metadata.bitflip_flips_output_bits.mapped_inputs_counts().is_empty() {
                    metadata.bitflips_do_not_map = true;
                }
                metadata.completed_deterministic_bitflips = true;

                return Ok(());
            }
        }

        // TODO: If EVERY bit (from the middle to end, or start to end) of 
        //       the explicit secret input leaks to output then we should probably also extend; 
        //       just in case

        let mut extended_input = input.clone();
        drop(input);
        let mut extensions = vec![];
        for (input_part, extend_dist) in max_dists {
            if extend_dist > 0 {
                let mut current_bytes = extended_input.get_part_bytes(input_part).unwrap().to_owned();
                println!("Extending {:?} by {} bytes (from {})", input_part, extend_dist / 8, current_bytes.len());
                current_bytes.append(&mut vec![0u8; (extend_dist as f64 / 8.0f64).ceil() as usize]);
                extended_input.set_part_bytes(input_part, &current_bytes);
                longest_part_bits = std::cmp::max(8 * current_bytes.len(), longest_part_bits);
                extensions.push(input_part);
            }
        }

        // Collect new `original_output` for this extended input
        self.collect_original_output_data(fuzzer, executor, state, manager, &extended_input)?;

        let extended_bitflip_map = if longest_part_bits > 1000 {
            self.quick_find_all_bitflips(fuzzer, executor, state, manager, &extended_input, &extensions)
        } else {
            self.leak_test_all_individual_bitflips(fuzzer, executor, state, manager, &extended_input, &extensions)
        }.unwrap();

        let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&extended_input).unwrap();
        metadata.bitflip_flips_output_bits = extended_bitflip_map;
        metadata.completed_deterministic_bitflips = true;
        if metadata.bitflip_flips_output_bits.mapped_inputs_counts().is_empty() {
            metadata.bitflips_do_not_map = true;
            return Ok(());
        }

        let input = {
            let mut testcase = state.violations_mut().get(violation_idx).unwrap().borrow_mut();
            let input = testcase.input_mut().as_mut().unwrap();
            for part in extensions {
                input.set_part_bytes(part, extended_input.get_part_bytes(part).unwrap());
            }
            input.clone()
        };

        self.leak_test_random_bitflip_combos(fuzzer, executor, state, manager, &input)?;
        // let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input).unwrap();
        // let mut unmapped_end_bitflips = 0;
        // for out_flips in metadata.bitflip_flips_output_bits.iter().rev() {
        //     if out_flips.is_empty() {
        //         unmapped_end_bitflips += 1;
        //     } else {
        //         break;
        //     }
        // }

        // let mut meta_len = 0;
        // if unmapped_end_bitflips / 8 > 0 {
        //     let trimmed_secret_len = secret.len() - unmapped_end_bitflips / 8;
        //     let trimmed_secret = &secret[0..trimmed_secret_len];
        //     metadata.bitflip_flips_output_bits.truncate(8 * trimmed_secret_len);
        //     meta_len = metadata.bitflip_flips_output_bits.len();
        //     let input = {
        //         let mut testcase = state.violations().get(violation_idx)?.borrow_mut();
        //         testcase.input_mut().as_mut().unwrap().set_secret_part_bytes(trimmed_secret);
        //         testcase.input().as_ref().unwrap().to_owned()
        //     };
        //     println!("Trimming {} unmapped_end_bits from secret ({:?}); new len: {}", unmapped_end_bitflips / 8, violation_idx, input.get_secret_part_bytes().len());
        //     self.collect_original_output_data(fuzzer, executor, state, manager, &input)?;
        // }

        // let testcase = state.violations().get(violation_idx).unwrap().borrow();
        // let input = testcase.input().as_ref().unwrap();
        // println!("Gonna check the length now (after trimmed {} bytes, to len {})!", unmapped_end_bitflips / 8, input.get_secret_part_bytes().len());
        // if unmapped_end_bitflips >= 8 && input.get_secret_part_bytes().len() * 8 != meta_len {
        //     panic!("after trimming {} bytes from secret, ended up with {} bitflips in the map (should have {})",
        //         unmapped_end_bitflips / 8, meta_len, 8 * input.get_secret_part_bytes().len());
        // }

        Ok(())
    }

    fn execute_input_and_collect_output(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        input: &<<Z as UsesState>::State as UsesInput>::Input,
    ) -> Result<OutputData, Error> {
        self.execute_input(fuzzer, executor, state, manager, input)?;
        let observer = executor.observers().match_name::<OutputObserver>("output").unwrap();
        let stdout = observer.stdout.as_ref().unwrap().to_owned();
        let stderr = observer.stderr.as_ref().unwrap().to_owned();
        Ok(OutputData { stdout, stderr })
    }

    fn execute_input(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        input: &<<Z as UsesState>::State as UsesInput>::Input,
    ) -> Result<(), Error> {
        let (untransformed, _post) = input.clone().try_transform_into(state)?;
        let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;
        if let Some(new_idx) = corpus_idx {
            println!("Unexpectedly found new queue entry at {:?}", new_idx);
        }
        Ok(())
    }

    fn collect_original_output_data(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        input: &<<Z as UsesState>::State as UsesInput>::Input,
    ) -> Result<(), Error> {
        let output_data = self.execute_input_and_collect_output(fuzzer, executor, state, manager, input)?;
        let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input)?;
        metadata.original_output = output_data;
        Ok(())
    }

    pub fn retrieve_bitflip_differences(out1: &OutputData, out2: &OutputData) -> Vec<OutputBitLocation> {
        let outputs = [
            (OutputSource::Stdout, &out1.stdout, &out2.stdout),
            (OutputSource::Stderr, &out2.stdout, &out2.stderr),
        ];

        let mut flipped_bits = vec![];
        for (source, orig, new) in outputs {
            // For each byte in the stdout output
            for byte in 0..std::cmp::min(new.len(), orig.len()) {
                // Check if any bits differ
                let diff = new[byte] ^ orig[byte];
                for bit in 0..8 {
                    if diff & (0x80 >> bit) != 0 {
                        flipped_bits.push(OutputBitLocation { source, bit_num: 8 * byte + bit });
                    }
                }
            }
        }

        flipped_bits
    }

    fn quick_find_all_bitflips(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        input: &<<Z as UsesState>::State as UsesInput>::Input,
        input_parts: &[InputContentsFlags],
    ) -> Result<BitflipMap, Error> {
        let mut bitflip_map = BitflipMap::new();
        // let mut stdout_bitflip_sources = vec![];
        // let mut stderr_bitflip_sources = vec![];
        for &input_part in input_parts {
            let input_len_bits = (8 * input.get_part_bytes(input_part).unwrap().len()) as u32;
            let highest_bit = 1 << input_len_bits.ilog2();
            let mut output_bitflips = vec![];

            let (original_bitvec_stdout, original_bitvec_stderr) = {
                let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input).unwrap();
                let original_output = &metadata.original_output;
                (
                    BitVec::<_, Msb0>::from_slice(&original_output.stdout), 
                    BitVec::<_, Msb0>::from_slice(&original_output.stderr)
                )
            };

            let mut current_bit = 0;
            while current_bit <= highest_bit {
                let mut input = input.clone();
                let secret_bytes = input.get_part_bytes(input_part).unwrap();
                let mut secret_bits = BitVec::<_, Msb0>::from_slice(secret_bytes);
                for bit_num in 0..secret_bits.len() {
                    // to start with flip every single bit
                    if current_bit == 0 || (bit_num / current_bit) % 2 == 1 { 
                        let cur = secret_bits[bit_num];
                        secret_bits.set(bit_num, !cur);
                    }
                }
                input.set_part_bytes(input_part, &secret_bits.into_vec());

                let output = self.execute_input_and_collect_output(fuzzer, executor, state, manager, &input)?;
                let xored = OutputData {
                    stdout: (BitVec::<_, Msb0>::from_vec(output.stdout) ^ original_bitvec_stdout.clone()).into_vec(),
                    stderr: (BitVec::<_, Msb0>::from_vec(output.stderr) ^ original_bitvec_stderr.clone()).into_vec(),
                };
                output_bitflips.push(xored);

                // macro_rules! add_pos {
                //     ($xored: expr, $sources: ident) => {
                //         for (index, bit) in $xored.iter().enumerate() {
                //             if index >= $sources.len() { $sources.push(None); }
                //             if bit {
                //                 let pos = $sources[index].unwrap_or(0);
                //                 $sources[index] = Some(pos + (1 << current_bit));
                //             }
                //         }
                //     };
                // }

                // add_pos!(xored.stdout, stdout_bitflip_sources);
                // add_pos!(xored.stderr, stderr_bitflip_sources);

                if current_bit == 0 {
                    current_bit = 1;
                } else {
                    current_bit <<= 1;
                }
            }
            
            let (longest_stdout, longest_stderr) = {
                let mut longest_stdout = 0usize;
                let mut longest_stderr = 0usize;
                for output in &output_bitflips {
                    if output.stdout.len() > longest_stdout {
                        if longest_stdout > 0 {
                            println!("Unexpectedly found a stdout that was longer ({}) than the previous ({})",
                                output.stdout.len(), longest_stdout);
                        }
                        longest_stdout = output.stdout.len();
                    }
                    if output.stderr.len() > longest_stderr {
                        if longest_stderr > 0 {
                            println!("Unexpectedly found a stderr that was longer ({}) than the previous ({})",
                                output.stdout.len(), longest_stderr);
                        }
                        longest_stderr = output.stderr.len();
                    }
                }
                (longest_stdout, longest_stderr)
            };
            let mut consolidated_stdout = vec![None; 8 * longest_stdout];
            let mut consolidated_stderr = vec![None; 8 * longest_stderr];
            for (index, output_data) in output_bitflips.into_iter().enumerate() {
                if index == 0 {
                    for (index, bit) in BitVec::<_, Msb0>::from_vec(output_data.stdout).iter().enumerate() {
                        if *bit { consolidated_stdout[index] = Some(0); }
                    }
                    for (index, bit) in BitVec::<_, Msb0>::from_vec(output_data.stderr).iter().enumerate() {
                        if *bit { consolidated_stderr[index] = Some(0); }
                    }
                } else {
                    let bit_value = 1usize << (index - 1);
                    for (index, bit) in BitVec::<_, Msb0>::from_vec(output_data.stdout).iter().enumerate() {
                        if *bit { 
                            if let Some(current_val) = consolidated_stdout[index] {
                                consolidated_stdout[index] = Some(current_val + bit_value);
                            } else {
                                println!("Found bit flip at index {} of stdout, when all bitflips did not discover this - discarding", index);
                            }
                        }
                    }
                    for (index, bit) in BitVec::<_, Msb0>::from_vec(output_data.stderr).iter().enumerate() {
                        if *bit { 
                            if let Some(current_val) = consolidated_stderr[index] {
                                consolidated_stderr[index] = Some(current_val + bit_value);
                            } else {
                                println!("Found bit flip at index {} of stderr, when all bitflips did not discover this - discarding", index);
                            }
                        }
                    }
                }
            }

            // println!("After all that, we have a mapping from input bit to stdout: {:?}", consolidated_stdout);
            let mut input_to_output_mapping = HashMap::<InputBitLocation, Vec<OutputBitLocation>>::new();
            for (index, input_bit_num) in consolidated_stdout.iter().enumerate() {
                if let Some(input_bit_num) = input_bit_num {
                    let input_location = InputBitLocation { part: input_part, bit_num: *input_bit_num};
                    let output_location = OutputBitLocation { source: OutputSource::Stdout, bit_num: index };
                    if let Some(out_vec) = input_to_output_mapping.get_mut(&input_location) {
                        out_vec.push(output_location);
                    } else {
                        input_to_output_mapping.insert(input_location, vec![output_location]);
                    }
                }
            }
            for (index, input_bit_num) in consolidated_stderr.iter().enumerate() {
                if let Some(input_bit_num) = input_bit_num {
                    let input_location = InputBitLocation { part: input_part, bit_num: *input_bit_num };
                    let output_location = OutputBitLocation { source: OutputSource::Stderr, bit_num: index };
                    if let Some(out_vec) = input_to_output_mapping.get_mut(&input_location) {
                        out_vec.push(output_location);
                    } else {
                        input_to_output_mapping.insert(input_location, vec![output_location]);
                    }
                }
            }

            for (input_location, output_locations) in input_to_output_mapping {
                bitflip_map.insert_entry(input_location, output_locations);
            }
        }

        Ok(bitflip_map)
    }

    pub fn leak_test_all_individual_bitflips(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        input: &<<Z as UsesState>::State as UsesInput>::Input,
        input_parts: &[InputContentsFlags],
    ) -> Result<BitflipMap, Error> {

        let mut bitflip_map = BitflipMap::new();

        for &input_part in input_parts {
            let secret_bytes = input.get_part_bytes(input_part).unwrap();
            let num_bits = 8 * secret_bytes.len();
            for i in 0..num_bits {
                let mut input = input.clone();

                let mut buf = secret_bytes.to_vec();
                let byte = i / 8;
                let bitmask: u8 = 0x80 >> (i % 8);
                buf[byte] ^= bitmask;
                input.set_part_bytes(input_part, &buf);
            
                let output_data = self.execute_input_and_collect_output(fuzzer, executor, state, manager, &input)?;
                let diffs = {
                    let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input).unwrap();
                    Self::retrieve_bitflip_differences(&metadata.original_output, &output_data)
                };

                // println!("Observed diffs for input bit at {:?} {}: {:?}", input_part, i, diffs);
                bitflip_map.insert_entry(InputBitLocation { part: input_part, bit_num: i }, diffs);
            }
        }

        // match mapped_bitflips {
        //     0 => metadata.bitflips_do_not_map = true,
        //     // there are no 'random combos' to test...
        //     1 => metadata.completed_deterministic_bitflips = true,
        //     _ => (),
        // };

        Ok(bitflip_map)
    }

    pub fn leak_test_random_bitflip_combos(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        input: &<<Z as UsesState>::State as UsesInput>::Input,
    ) -> Result<(), Error> {
        // Try random combos of bitflips to check that they do map as expected
        // println!("Ok, should try random combos now!");

        let mut combos_since_failure = 0;
        loop {
            let mut input = input.clone();

            let output_mapped_bits = {
                let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata(&input).unwrap();
                metadata.bitflip_flips_output_bits.iterate_map()
                    .map(|(i, _)| i.clone())
                    .collect::<Vec<InputBitLocation>>()
            };

            let exit_checks_count = std::cmp::min(output_mapped_bits.len(), 10_000);

            // We ended up removing all the suspected bitflip mappings :/
            if output_mapped_bits.is_empty() {
                let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input).unwrap();
                metadata.completed_deterministic_bitflips = true;
                metadata.bitflips_do_not_map = true;
                break;
            }
    
            let mut rand = thread_rng();

            let bits_to_flip = match combos_since_failure {
                0 => output_mapped_bits.clone(),
                1 => output_mapped_bits[0..(output_mapped_bits.len() / 2)].to_owned(),
                2 => output_mapped_bits[(output_mapped_bits.len() / 2)..].to_owned(),
                _ => output_mapped_bits.clone().into_iter().choose_multiple(
                    &mut rand,
                    {
                        let count = if combos_since_failure < exit_checks_count / 8 {
                            3 * output_mapped_bits.len() / 4
                        } else if combos_since_failure < exit_checks_count / 4 {
                                output_mapped_bits.len() / 2
                        } else if combos_since_failure < exit_checks_count / 2 {
                                output_mapped_bits.len() / 4
                        } else {
                                output_mapped_bits.len() / 8
                        };

                        if output_mapped_bits.len() <= 1 {
                            1
                        } else if count < 2 {
                            2
                        } else {
                            count
                        }
                    }
                )
            };

            // println!("Flipping {} bits from possible {} ({:?})", 
            //     bits_to_flip.len(), output_mapped_bits.len(), 
            //     if bits_to_flip.len() > 20 { "omitted".to_string() } else { format!("{:?}", bits_to_flip) });

            let mut new_secrets = HashMap::new();
            for input_loc in &bits_to_flip {
                if new_secrets.get(&input_loc.part).is_none() {
                    let cur_bytes = input.get_part_bytes(input_loc.part).unwrap().to_owned();
                    new_secrets.insert(input_loc.part, cur_bytes);
                }
                let updated = new_secrets.get_mut(&input_loc.part).unwrap();

                let bit = input_loc.bit_num;
                if bit / 8 >= updated.len() {
                    println!("in violation, input of len {} bits; selected bit {bit} from target bits {:?} to flip from full set {:?}", 8 * updated.len(), bits_to_flip, output_mapped_bits);
                }
                updated[bit / 8] ^= (0x80 >> (bit % 8)) as u8;
            }

            for (part, updated) in new_secrets {
                input.set_part_bytes(part, &updated);
            }

            let output_data = self.execute_input_and_collect_output(fuzzer, executor, state, manager, &input)?;
            let output_flips = {
                let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input).unwrap();
                let vec = Self::retrieve_bitflip_differences(&metadata.original_output, &output_data);
                HashSet::from_iter(vec.iter().cloned())
            };

            let metadata = fuzzer.hypertest_feedback_mut().get_leak_quantify_metadata_mut(&input).unwrap();
            let passed = metadata.bitflip_flips_output_bits
                .check_multibit_flip_result(&bits_to_flip, &output_flips);

            if passed {
                // println!("All output bit flips matched as expected, combos_since_failure: {} (exiting at {})",
                //     combos_since_failure, exit_checks_count);
                combos_since_failure += 1;
            } else {
                println!("resetting combos_since_failure to 0");
                combos_since_failure = 0;
            }

            if combos_since_failure >= exit_checks_count {
                metadata.completed_deterministic_bitflips = true;
                break;
            }
        }

        Ok(())
    }
}
