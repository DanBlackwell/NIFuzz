//! The `Fuzzer` is the main struct for a fuzz campaign.

extern crate alloc;
use core::{fmt::Debug, marker::PhantomData};

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    output_observer::{ObserverWithOutput, OutputObserver}, 
    pub_sec_input::{PubSecInput, InputContentsFlags}, 
    output_feedback::{OutputDataRefs, OutputData}, leak_fuzzer_state::ViolationsTargetingApproach
};
use crate::hypertest_feedback::HypertestFeedback;
use crate::leak_fuzzer_state::HasViolations;

#[cfg(feature = "introspection")]
use libafl::monitors::PerfFeature;
use libafl_bolts::{current_time, rands::Rand};
use libafl::{
    corpus::{Corpus, CorpusId, HasTestcase, Testcase},
    events::{Event, EventConfig, EventFirer, EventProcessor, ProgressReporter},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::UsesInput,
    mark_feature_time,
    observers::ObserversTuple,
    schedulers::Scheduler,
    stages::StagesTuple,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMetadata, HasSolutions, UsesState, HasRand, HasLastReportTime},
    fuzzer::{HasScheduler, HasFeedback, HasObjective, ExecutionProcessor, EvaluatorObservers, Evaluator, Fuzzer, ExecuteInputResult, ExecutesInput},
    Error, prelude::{Input, HasTargetBytes},
};

/// Send a monitor update all 15 (or more) seconds
// const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

/// The corpus this input should be added to
#[derive(Debug, PartialEq, Eq)]
pub enum LeakExecuteInputResult {
    /// No special input
    None,
    /// This input should be stored in the corpus
    Corpus,
    /// This input helps expose an information leak
    Violation,
    /// This input leads to a solution
    Solution,
}


/// Your default fuzzer instance, for everyday use.
#[derive(Debug)]
pub struct LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasClientPerfMonitor + HasCorpus + UsesInput,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    scheduler: CS,
    feedback: F,
    hypertest_feedback: HTF,
    objective: OF,
    phantom: PhantomData<OT>,
}

pub trait HasHypertestFeedback: UsesInput
{
    type HypertestFeedback: HypertestFeedback<<Self as UsesInput>::Input>;
    fn hypertest_feedback(&self) -> &Self::HypertestFeedback;
    fn hypertest_feedback_mut(&mut self) -> &mut Self::HypertestFeedback;
}

impl<CS, F, OF, OT, HTF> HasHypertestFeedback for LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasClientPerfMonitor + HasCorpus + UsesInput,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    type HypertestFeedback = HTF;
    fn hypertest_feedback(&self) -> &HTF {
        &self.hypertest_feedback
    }

    fn hypertest_feedback_mut(&mut self) -> &mut HTF {
        &mut self.hypertest_feedback
    }
}

impl<CS, F, OF, OT, HTF> UsesState for LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasClientPerfMonitor + HasCorpus,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    type State = CS::State;
}

impl<CS, F, OF, OT, HTF> HasScheduler for LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasClientPerfMonitor + HasCorpus,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    type Scheduler = CS;

    fn scheduler(&self) -> &CS {
        &self.scheduler
    }

    fn scheduler_mut(&mut self) -> &mut CS {
        &mut self.scheduler
    }
}

impl<CS, F, OF, OT, HTF> HasFeedback for LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasClientPerfMonitor + HasCorpus,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    type Feedback = F;

    fn feedback(&self) -> &Self::Feedback {
        &self.feedback
    }

    fn feedback_mut(&mut self) -> &mut Self::Feedback {
        &mut self.feedback
    }
}

impl<CS, F, OF, OT, HTF> HasObjective for LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasClientPerfMonitor + HasCorpus,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    type Objective = OF;

    fn objective(&self) -> &OF {
        &self.objective
    }

    fn objective_mut(&mut self) -> &mut OF {
        &mut self.objective
    }
}

impl<CS, F, OF, OT, HTF> ExecutionProcessor<OT> for LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    CS::State: HasCorpus + HasSolutions + HasClientPerfMonitor + HasExecutions,
    <<CS as UsesState>::State as UsesInput>::Input: Input,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    /// Evaluate if a set of observation channels has an interesting state
    fn process_execution<EM>(
        &mut self,
        state: &mut CS::State,
        manager: &mut EM,
        input: <CS::State as UsesInput>::Input,
        observers: &OT,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>
    where
        EM: EventFirer<State = Self::State>,
    {
        let mut res = ExecuteInputResult::None;

        #[cfg(not(feature = "introspection"))]
        let is_solution = self
            .objective_mut()
            .is_interesting(state, manager, &input, observers, exit_kind)?;

        #[cfg(feature = "introspection")]
        let is_solution = self
            .objective_mut()
            .is_interesting_introspection(state, manager, &input, observers, exit_kind)?;

        if is_solution {
            res = ExecuteInputResult::Solution;
        } else {
            #[cfg(not(feature = "introspection"))]
            let is_corpus = self
                .feedback_mut()
                .is_interesting(state, manager, &input, observers, exit_kind)?;

            #[cfg(feature = "introspection")]
            let is_corpus = self
                .feedback_mut()
                .is_interesting_introspection(state, manager, &input, observers, exit_kind)?;

            if is_corpus {
                res = ExecuteInputResult::Corpus;
            }
        }

        match res {
            ExecuteInputResult::None => {
                self.feedback_mut().discard_metadata(state, &input)?;
                self.objective_mut().discard_metadata(state, &input)?;
                Ok((res, None))
            }
            ExecuteInputResult::Corpus => {
                // Not a solution
                self.objective_mut().discard_metadata(state, &input)?;

                // Add the input to the main corpus
                let mut testcase = Testcase::with_executions(input.clone(), *state.executions());
                self.feedback_mut()
                    .append_metadata(state, observers, &mut testcase)?;
                let idx = state.corpus_mut().add(testcase)?;
                self.scheduler_mut().on_add(state, idx)?;

                if send_events {
                    // TODO set None for fast targets
                    let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
                        None
                    } else {
                        manager.serialize_observers::<OT>(observers)?
                    };
                    manager.fire(
                        state,
                        Event::NewTestcase {
                            input,
                            observers_buf,
                            exit_kind: *exit_kind,
                            corpus_size: state.corpus().count(),
                            client_config: manager.configuration(),
                            time: current_time(),
                            executions: *state.executions(),
                            forward_id: None,
                        },
                    )?;
                }
                Ok((res, Some(idx)))
            }
            ExecuteInputResult::Solution => {
                // Not interesting
                self.feedback_mut().discard_metadata(state, &input)?;

                // The input is a solution, add it to the respective corpus
                let mut testcase = Testcase::with_executions(input, *state.executions());
                testcase.set_parent_id_optional(*state.corpus().current());
                self.objective_mut()
                    .append_metadata(state, observers, &mut testcase)?;
                state.solutions_mut().add(testcase)?;

                if send_events {
                    manager.fire(
                        state,
                        Event::Objective {
                            objective_size: state.solutions().count(),
                        },
                    )?;
                }

                Ok((res, None))
            }
        }
    }
}

impl<CS, F, OF, OT, HTF> EvaluatorObservers<OT> for LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasCorpus + HasSolutions + HasClientPerfMonitor + HasExecutions + HasViolations,
    <<CS as UsesState>::State as UsesInput>::Input: Input + HasTargetBytes + PubSecInput,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input_with_observers<E, EM>(
        &mut self,
        state: &mut Self::State,
        executor: &mut E,
        manager: &mut EM,
        input: <Self::State as UsesInput>::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error>
    where
        E: Executor<EM, Self> + HasObservers<Observers = OT, State = Self::State>,
        EM: EventFirer<State = Self::State>,
    {
        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        if exit_kind == ExitKind::Timeout { 
            // println!("Timeout on input with pub len: {}, sec len: {}", 
            //     input.get_public_part_bytes().len(), input.get_secret_part_bytes().len()); 
            // println!("{:?}", input.get_raw_bytes());
            self.scheduler.on_evaluation(state, &input, executor.observers())?;
            return self.process_execution(state, manager, input, executor.observers(), &exit_kind, send_events);
        }
        // let observers = executor.observers();

        self.scheduler.on_evaluation(state, &input, executor.observers())?;

        if state.targeting_violations() != ViolationsTargetingApproach::None {
            let observer = executor.observers().match_name::<OutputObserver>("output").unwrap();
            let empty = Vec::new();
            let stdout = match observer.stdout() { None => &empty, Some(o) => o };
            let stderr = match observer.stderr() { None => &empty, Some(o) => o };
            let output_data = OutputData { stdout: stdout.to_owned(), stderr: stderr.to_owned() };

            let mut inconsistent = false;
            for i in 0..3 {
                start_timer!(state);
                let cur_exit = self.execute_input(state, executor, manager, &input)?;
                mark_feature_time!(state, PerfFeature::TargetExecution);

                if cur_exit != exit_kind {
                    panic!("last time got exit: {:?}, this time ({}) got {:?}", exit_kind, i, cur_exit);
                }

                let observer = executor.observers().match_name::<OutputObserver>("output").unwrap();

                let empty = Vec::new();
                let stdout = match observer.stdout() { None => &empty, Some(o) => o };
                let stderr = match observer.stderr() { None => &empty, Some(o) => o };

                if output_data.stdout != *stdout || output_data.stderr != *stderr {
                    inconsistent = true;
                    println!("Received inconsistent output on run {i}");
                    break;
                }
            }

            if !inconsistent {
              match state.targeting_violations() {
                  ViolationsTargetingApproach::SingleBitFlips | ViolationsTargetingApproach::RandomBitFlips => {
                      self.hypertest_feedback.check_for_bitflip_output(&input, &output_data);
                  }
                  ViolationsTargetingApproach::UniformSampling => 
                      self.hypertest_feedback.store_uniform_sampled_secret_output(&input, &output_data),
                  _ => panic!("unhandled case!")
              };
            }
        }

        let observer = executor.observers().match_name::<OutputObserver>("output").unwrap();
        let (needs_rerun, output_data) = self.hypertest_feedback.needs_rerun(&input, &observer);

        if needs_rerun {
            let output_data = output_data.unwrap();
            let mut inconsistent = false;
            for i in 0..10 {
                *state.executions_mut() += 1;
                start_timer!(state);
                let cur_exit = executor.run_target(self, state, manager, &input)?;
                mark_feature_time!(state, PerfFeature::TargetExecution);
                // let cur_exit = self.execute_input(state, executor, manager, &input)?;

                if cur_exit != exit_kind {
                    panic!("last time got exit: {:?}, this time ({}) got {:?}", exit_kind, i, cur_exit);
                    // inconsistent = true;
                    // break;
                }

                let observer = executor.observers().match_name::<OutputObserver>("output").unwrap();

                let empty = Vec::new();
                let stdout = match observer.stdout() { None => &empty, Some(o) => o };
                let stderr = match observer.stderr() { None => &empty, Some(o) => o };

                if output_data.stdout != *stdout || output_data.stderr != *stderr {
                    inconsistent = true;
                    println!("Received inconsistent output on run {i}");
                    // println!("Expected consistent output: {:?} {:?} but got {:?} {:?} on run {}", 
                    //     output_data.stdout, output_data.stderr, *stdout, *stderr, i);
                    break;
                }
            }

            if !inconsistent {
                let res = self.hypertest_feedback.exposes_fault(&input, &output_data);
                match res {
                    Some((ref failing_hypertest, is_new_violation)) => { 
                        if is_new_violation {
                            println!("Found new violation!");
                            assert!(failing_hypertest.test_one.0.get_public_input_hash() ==
                                    failing_hypertest.test_two.0.get_public_input_hash());
                            assert!(failing_hypertest.test_one.1 != failing_hypertest.test_two.1);
                            let t1in = failing_hypertest.test_one.0.clone();
                            let t1out = failing_hypertest.test_one.1.clone();
                            let t2in = failing_hypertest.test_two.0.clone();
                            let t2out = failing_hypertest.test_two.1.clone();


                            for (input, output_data) in [(&t1in, &t1out), (&t2in, &t2out)] {
                                *state.executions_mut() += 1;
                                start_timer!(state);
                                let _cur_exit = executor.run_target(self, state, manager, &input)?;
                                mark_feature_time!(state, PerfFeature::TargetExecution);
                               //  let cur_exit = self.execute_input(state, executor, manager, &input)?;
                                let observer = executor.observers().match_name::<OutputObserver>("output").unwrap();

                                let empty = Vec::new();
                                let stdout = match observer.stdout() { None => &empty, Some(o) => o };
                                let stderr = match observer.stderr() { None => &empty, Some(o) => o };
                
                                let mut matched = true;
                                if output_data.stdout != *stdout {
                                    println!("Received differing output for failing hypertest: expected len {}, got {} ({:?} vs {:?})", output_data.stdout.len(), stdout.len(), output_data.stdout, stdout);
                                    matched = false;
                                }
                                if output_data.stderr != *stderr {
                                    println!("Received differing outinput for failing hypertest: expected len {}, got {} ({:?} vs {:?})", output_data.stderr.len(), stderr.len(), output_data.stderr, stderr);
                                    matched = false;
                                }
                                if matched { println!("Retested both inputs and got the expected outputs - seems this is a real violation"); }
                            }

                            macro_rules! maybe_truncate {
                                ($arr:expr) => {
                                    if $arr.len() > 60 { &$arr[..60] } else { $arr }
                                };
                            }

                            macro_rules! get_part {
                                ($testcase: ident, $flag: expr) => {
                                    if let Some(part) = $testcase.get_part_bytes($flag) {
                                        format!("{:?}", maybe_truncate!(part))
                                    } else {
                                        "N/A".to_string()
                                    }
                                }
                            }

                            println!("  test 1 in : {{ explicit_secret: {:?}, stack_mem: {:?}, heap_mem: {:?} }}", 
                                get_part!(t1in, InputContentsFlags::SecretExplicitInput),
                                get_part!(t1in, InputContentsFlags::SecretStackMemory),
                                get_part!(t1in, InputContentsFlags::SecretHeapMemory),
                            );
                            let t1_output = t1out.to_string();
                            let t1_chars = t1_output.chars().into_iter().collect::<Vec<char>>();
                            let t1_trunc = maybe_truncate!(&t1_chars);
                            println!("  test 1 out: {}", t1_trunc.into_iter().collect::<String>());

                            println!("  test 2 in : {{ explicit_secret: {:?}, stack_mem: {:?}, heap_mem: {:?} }}", 
                                get_part!(t2in, InputContentsFlags::SecretExplicitInput),
                                get_part!(t2in, InputContentsFlags::SecretStackMemory),
                                get_part!(t2in, InputContentsFlags::SecretHeapMemory),
                            );
                            let t2_output = t2out.to_string();
                            let t2_chars = t2_output.chars().into_iter().collect::<Vec<char>>();
                            let t2_trunc = maybe_truncate!(&t2_chars);
                            println!("  test 2 out: {}", t2_trunc.into_iter().collect::<String>());

                            macro_rules! secret_is_not_empty {
                                ($testcase: ident) => {
                                    !$testcase.get_part_bytes(InputContentsFlags::SecretExplicitInput).unwrap_or_else(|| &[]).is_empty() ||
                                    !$testcase.get_part_bytes(InputContentsFlags::SecretStackMemory).unwrap_or_else(|| &[]).is_empty() ||
                                    !$testcase.get_part_bytes(InputContentsFlags::SecretHeapMemory).unwrap_or_else(|| &[]).is_empty()
                                }
                            }
                            assert!(secret_is_not_empty!(t1in) || secret_is_not_empty!(t2in));

                            let (quanti_input, quanti_out) = if secret_is_not_empty!(t1in) {
                                (t1in, t1out)
                            } else {
                                (t2in, t2out)
                            };
                            let cloned_out = quanti_out.to_owned();

                            if self.hypertest_feedback_mut().get_leak_quantify_metadata(&quanti_input).is_err() {
                                for idx in state.violations().ids() {
                                    let testcase = state.violations().get(idx).unwrap().borrow();
                                    let input = testcase.input().as_ref().unwrap();
                                    if input.get_public_input_hash() == quanti_input.get_public_input_hash() {
                                        panic!("public input for new violation matched that at idx {:?}", idx);
                                    }
                                }
                                self.hypertest_feedback_mut().create_leak_quantify_metadata_for(&quanti_input, &cloned_out);
                                let new_testcase = Testcase::new(quanti_input);
                                state.violations_mut().add(new_testcase).unwrap();
                            }
                        }
                    },
                    _ => ()
                };
            }
        }
        
        self.process_execution(state, manager, input, executor.observers(), &exit_kind, send_events)
    }
}

impl<CS, E, EM, F, OF, OT, HTF> Evaluator<E, EM> for LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    E: HasObservers<State = CS::State, Observers = OT> + Executor<EM, Self>,
    EM: EventFirer<State = CS::State>,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    CS::State: HasCorpus + HasSolutions + HasClientPerfMonitor + HasExecutions + HasViolations,
    <<CS as UsesState>::State as UsesInput>::Input: Input + HasTargetBytes + PubSecInput,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input_events(
        &mut self,
        state: &mut CS::State,
        executor: &mut E,
        manager: &mut EM,
        input: <CS::State as UsesInput>::Input,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<CorpusId>), Error> {
        self.evaluate_input_with_observers(state, executor, manager, input, send_events)
    }

    /// Adds an input, even if it's not considered `interesting` by any of the executors
    fn add_input(
        &mut self,
        state: &mut CS::State,
        executor: &mut E,
        manager: &mut EM,
        input: <CS::State as UsesInput>::Input,
    ) -> Result<CorpusId, Error> {
        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();
        // Always consider this to be "interesting"

        // However, we still want to trigger the side effects of objectives and feedbacks.
        #[cfg(not(feature = "introspection"))]
        let _is_solution = self
            .objective_mut()
            .is_interesting(state, manager, &input, observers, &exit_kind)?;

        #[cfg(feature = "introspection")]
        let _is_solution = self
            .objective_mut()
            .is_interesting_introspection(state, manager, &input, observers, &exit_kind)?;

        #[cfg(not(feature = "introspection"))]
        let _is_corpus = self
            .feedback_mut()
            .is_interesting(state, manager, &input, observers, &exit_kind)?;

        #[cfg(feature = "introspection")]
        let _is_corpus = self
            .feedback_mut()
            .is_interesting_introspection(state, manager, &input, observers, &exit_kind)?;

        // Not a solution
        self.objective_mut().discard_metadata(state, &input)?;

        // several is_interesting implementations collect some data about the run, later used in
        // append_metadata; we *must* invoke is_interesting here to collect it
        let _: bool = self
            .feedback_mut()
            .is_interesting(state, manager, &input, observers, &exit_kind)?;

        // Add the input to the main corpus
        let mut testcase = Testcase::with_executions(input.clone(), *state.executions());
        self.feedback_mut()
            .append_metadata(state, observers, &mut testcase)?;
        let idx = state.corpus_mut().add(testcase)?;
        self.scheduler_mut().on_add(state, idx)?;

        let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
            None
        } else {
            manager.serialize_observers::<OT>(observers)?
        };
        manager.fire(
            state,
            Event::NewTestcase {
                input,
                observers_buf,
                exit_kind,
                corpus_size: state.corpus().count(),
                client_config: manager.configuration(),
                time: current_time(),
                executions: *state.executions(),
                forward_id: None,
            },
        )?;
        Ok(idx)
    }
}

impl<CS, E, EM, F, OF, OT, ST, HTF> Fuzzer<E, EM, ST> for LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    E: UsesState<State = CS::State>,
    EM: ProgressReporter + EventProcessor<E, Self, State = CS::State>,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasClientPerfMonitor + HasExecutions + HasMetadata + HasCorpus + HasTestcase + HasViolations + HasRand + HasLastReportTime,
    ST: StagesTuple<E, EM, CS::State, Self>,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    fn fuzz_one(
        &mut self,
        stages: &mut ST,
        executor: &mut E,
        state: &mut CS::State,
        manager: &mut EM,
    ) -> Result<CorpusId, Error> {
        // Init timer for scheduler
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().start_timer();

        let should_target_violations = state.violations().count() > 0 && 
            state.rand_mut().below(2) == 1u64;

        // This is set so that the scheduler picks a CorpusId from the correct Corpus (queue or violations)
        state.set_targeting_violations(if should_target_violations { 
            ViolationsTargetingApproach::ToBeDecided 
        } else {
            ViolationsTargetingApproach::None
        });
        
        // Get the next index from the scheduler
        let idx = self.scheduler.next(state)?;

        if should_target_violations {
            let approach;
            {
                let testcase = state.violations_mut().get(idx)?.borrow_mut();
                let input = testcase.input().as_ref().unwrap();
                approach = self.hypertest_feedback.get_next_violation_targeting_approach(&input);
            }
            state.set_targeting_violations(approach);
        }

        // Mark the elapsed time for the scheduler
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().mark_scheduler_time();

        // Mark the elapsed time for the scheduler
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().reset_stage_index();

        // Execute all stages
        stages.perform_all(self, executor, state, manager, idx)?;

        // Init timer for manager
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().start_timer();

        // Execute the manager
        manager.process(self, state, executor)?;

        // Mark the elapsed time for the manager
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().mark_manager_time();

        {
            let mut testcase = if should_target_violations {
                self.hypertest_feedback.estimate_leakage();
                state.violations_mut().get(idx)?.borrow_mut()
            } else {
                state.corpus_mut().get(idx)?.borrow_mut()
            };

            // let mut testcase = state.testcase_mut(idx)?;
            let scheduled_count = testcase.scheduled_count();

            // increase scheduled count, this was fuzz_level in afl
            testcase.set_scheduled_count(scheduled_count + 1);
        }

        Ok(idx)
    }
}

impl<CS, F, OF, OT, HTF> LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: UsesInput + HasExecutions + HasClientPerfMonitor + HasCorpus,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    /// Create a new `LeakFuzzer` with standard behavior.
    pub fn new(scheduler: CS, feedback: F, objective: OF, hypertest_feedback: HTF) -> Self {
        Self {
            scheduler,
            feedback,
            hypertest_feedback,
            objective,
            phantom: PhantomData,
        }
    }

    /// Runs the input and triggers observers and feedback
    pub fn execute_input<E, EM>(
        &mut self,
        state: &mut CS::State,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &<CS::State as UsesInput>::Input,
    ) -> Result<ExitKind, Error>
    where
        E: Executor<EM, Self> + HasObservers<Observers = OT, State = CS::State>,
        EM: UsesState<State = CS::State>,
        OT: ObserversTuple<CS::State>,
    {
        start_timer!(state);
        executor.observers_mut().pre_exec_all(state, input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        *state.executions_mut() += 1;

        start_timer!(state);
        let exit_kind = executor.run_target(self, state, event_mgr, input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);

        start_timer!(state);
        executor
            .observers_mut()
            .post_exec_all(state, input, &exit_kind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        Ok(exit_kind)
    }
}

impl<CS, E, EM, F, OF, HTF> ExecutesInput<E, EM> for LeakFuzzer<CS, F, OF, E::Observers, HTF>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    E: Executor<EM, Self> + HasObservers<State = CS::State>,
    EM: UsesState<State = CS::State>,
    CS::State: UsesInput + HasExecutions + HasClientPerfMonitor + HasCorpus,
    E::Observers: Serialize + DeserializeOwned,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input>,
{
    /// Runs the input and triggers observers and feedback
    fn execute_input(
        &mut self,
        state: &mut CS::State,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &<CS::State as UsesInput>::Input,
    ) -> Result<ExitKind, Error> {
        start_timer!(state);
        executor.observers_mut().pre_exec_all(state, input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        *state.executions_mut() += 1;

        start_timer!(state);
        let exit_kind = executor.run_target(self, state, event_mgr, input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);

        start_timer!(state);
        executor
            .observers_mut()
            .post_exec_all(state, input, &exit_kind)?;
        mark_feature_time!(state, PerfFeature::PostExecObservers);

        Ok(exit_kind)
    }
}
