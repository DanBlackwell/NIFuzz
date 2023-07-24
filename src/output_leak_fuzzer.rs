//! The `Fuzzer` is the main struct for a fuzz campaign.

extern crate alloc;
use alloc::string::ToString;
use hashbrown::HashMap;
use core::{fmt::Debug, marker::PhantomData, time::Duration};
use std::{hash::{Hash, Hasher}, collections::hash_map::DefaultHasher};

use serde::{de::DeserializeOwned, Serialize};

use crate::pub_sec_input::PubSecInput;
use crate::output_observer::{ObserverWithOutput, OutputObserver};

#[cfg(feature = "introspection")]
use libafl::monitors::PerfFeature;
use libafl::{
    bolts::current_time,
    corpus::{Corpus, CorpusId, HasTestcase, Testcase},
    events::{Event, EventConfig, EventFirer, EventProcessor, ProgressReporter},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::UsesInput,
    mark_feature_time,
    observers::{Observer, ObserversTuple},
    schedulers::Scheduler,
    stages::StagesTuple,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMetadata, HasSolutions, UsesState},
    fuzzer::{HasScheduler, HasFeedback, HasObjective, ExecutionProcessor, EvaluatorObservers, Evaluator, Fuzzer, ExecuteInputResult, ExecutesInput},
    Error, prelude::{Input, HasBytesVec},
};

/// Send a monitor update all 15 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

/// The corpus this input should be added to
#[derive(Debug, PartialEq, Eq)]
pub enum LeakExecuteInputResult {
    /// No special input
    None,
    /// This input should be stored in the corpus
    Corpus,
    /// This input helps expose an information leak
    InfoLeak,
    /// This input leads to a solution
    Solution,
}

pub struct OutputData {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>
}

impl OutputData {
    fn to_string(&self)  -> String{
        format!("stdout: {:?}, stderr: {:?}", 
            std::string::String::from_utf8_lossy(&self.stdout),
            std::string::String::from_utf8_lossy(&self.stderr))
    }
}

pub struct IOHashValue {
    pub public_input_hash: u64,
    pub public_input_full: Option<Vec<u8>>,
    pub secret_input_hashes: Vec<u64>,
    pub public_output_hashes: Vec<u64>,

    pub secret_inputs_full: Vec<Vec<u8>>,
    pub public_outputs_full: Vec<OutputData>
}

impl IOHashValue {
    fn info_string(&self) -> String {
        format!("[pub_in: {:20}, (sec_in, pub_out)s: {:?}]", 
            self.public_input_hash, 
            self.secret_input_hashes.iter().zip(self.public_output_hashes.iter())
            .collect::<Vec<(&u64, &u64)>>()
        )
    }

    fn extended_info_string(&self) -> String {
        if self.public_input_full.is_none() { return self.info_string(); }

        format!("[pub_in: {:20}, (sec_in, pub_out)s: {:?}]", 
            std::string::String::from_utf8_lossy(&self.public_input_full.as_ref().unwrap()).into_owned(), 
            self.secret_inputs_full
                .iter()
                .zip(self.public_outputs_full.iter())
                .map(|(si, po)| (std::string::String::from_utf8_lossy(si).into_owned(), std::string::String::from_utf8_lossy(&po.stdout).into_owned()))
                .collect::<Vec<(String, String)>>()
        )
    }
}

pub struct InfoLeakChecker<I> {
    dict: HashMap<u64, IOHashValue>,    
    prev_sec_in: Vec<u8>,
    prev_pub_in: Vec<u8>,
    prev_output: OutputData,
    phantom: PhantomData<I>
}

impl<I> InfoLeakChecker<I> {
}

// pub struct FailingHypertest<I> {
//     test_one: I,
//     test_two: I
// }

pub enum HypertestResult<I> {
    Failing(I, I),
    NeedsRerun,
    Boring,
}

pub trait HypertestFeedback<I, S, OT> 
where 
    I: Input, 
    S: HasCorpus,
    OT: ObserversTuple<S> + Serialize + DeserializeOwned,
{
    fn new() -> Self;
    fn exposes_fault(&mut self, input: &I, observers: &OT) -> HypertestResult<I>;
}

impl<I, S, OT> HypertestFeedback<I, S, OT> for InfoLeakChecker<I>
where
    I: Input + PubSecInput,
    S: HasCorpus,
    OT: ObserversTuple<S> + Serialize + DeserializeOwned,
{
    fn new() -> Self {
        Self {
            dict: HashMap::new(),
            prev_pub_in: Vec::new(),
            prev_sec_in: Vec::new(),
            prev_output: OutputData { stdout: Vec::new(), stderr: Vec::new() },
            phantom: PhantomData
        }
    }

    fn exposes_fault(&mut self, input: &I, observers: &OT) -> HypertestResult<I> {
        let observer = observers.match_name::<OutputObserver>("output").unwrap();

        let empty = Vec::new();
        let stdout = match observer.stdout() {
            None => &empty,
            Some(o) => o
        };
        let stderr = match observer.stderr() {
            None => &empty,
            Some(o) => o
        };


        // println!("input: {:?}", input.bytes());
        let hash = |val: &[u8]| {
            let mut hasher = DefaultHasher::new();
            val.hash(&mut hasher);
            hasher.finish()
        };

        let pub_in_hash = hash(input.get_public_part_bytes());
        let sec_in_hash = hash(input.get_secret_part_bytes());

        let mut hasher = DefaultHasher::new();
        stdout.hash(&mut hasher);
        stderr.hash(&mut hasher);
        let pub_out_hash = hasher.finish();

        if let Some(hash_val) = self.dict.get_mut(&pub_in_hash) {
            if !hash_val.public_output_hashes.contains(&pub_out_hash) {
                if hash_val.secret_input_hashes.contains(&sec_in_hash) {
                    println!("Made the following observations (secret_in: public_out) for public_in: {:?}:", 
                        std::string::String::from_utf8_lossy(input.get_public_part_bytes()));
                    let output_data = OutputData { stdout: stdout.to_vec(), stderr: stderr.to_vec() };

                    if hash_val.public_outputs_full.len() == 0 {
                        println!("For public in: {:?} and secret_in: {:?} found two different outputs: (hash only) {:?} and {:?}",
                            std::string::String::from_utf8_lossy(input.get_public_part_bytes()),
                            std::string::String::from_utf8_lossy(input.get_secret_part_bytes()),
                            hash_val.public_output_hashes[0],
                            output_data.to_string());

                    } else if hash_val.secret_inputs_full.len() < hash_val.public_outputs_full.len() {
                        println!("(hash only) {}: {:?}",
                            hash_val.secret_input_hashes[0],
                            std::string::String::from_utf8_lossy(&hash_val.public_outputs_full[0].stdout));
                        for i in 0..hash_val.secret_inputs_full.len() {
                            println!("{:?}: {:?}",
                                std::string::String::from_utf8_lossy(&hash_val.secret_inputs_full[i]),
                                std::string::String::from_utf8_lossy(&hash_val.public_outputs_full[i + 1].stdout));
                        }

                    } else {
                        for i in 0..hash_val.secret_inputs_full.len() {
                            println!("{:?}: {:?}",
                                std::string::String::from_utf8_lossy(&hash_val.secret_inputs_full[i]),
                                std::string::String::from_utf8_lossy(&hash_val.public_outputs_full[i].stdout));
                        }

                    }

                    println!("Note: prev pub_in: {:?},\nsec_in: {:?},\npub_stdout: {:?},\npub_stderr: {:?}",
                        std::string::String::from_utf8_lossy(&self.prev_pub_in),
                        std::string::String::from_utf8_lossy(&self.prev_sec_in),
                        std::string::String::from_utf8_lossy(&self.prev_output.stdout),
                        std::string::String::from_utf8_lossy(&self.prev_output.stderr),
                    );

                    self.prev_pub_in = input.get_public_part_bytes().to_owned();
                    self.prev_sec_in = input.get_secret_part_bytes().to_owned();
                    self.prev_output = OutputData { stdout: stdout.to_vec(), stderr: stderr.to_vec() };

                    // return HypertestResult::NeedsRerun;
                    panic!("Likely non-determinism");
                }

                let mut matches = false;
                for secret_in in &hash_val.secret_inputs_full {
                    if input.get_secret_part_bytes() == secret_in {
                        matches = true;
                        break;
                    }
                }

                if !matches {
                    if hash_val.public_input_full.is_none() {
                        hash_val.public_input_full = Some(input.get_public_part_bytes().to_vec());
                    }

                    hash_val.secret_inputs_full.push(input.get_secret_part_bytes().to_vec());
                    let output_data = OutputData { stdout: stdout.to_vec(), stderr: stderr.to_vec() };
                    hash_val.public_outputs_full.push(output_data);
                    hash_val.public_output_hashes.push(pub_out_hash);

                    if hash_val.secret_inputs_full.len() > 2 && hash_val.secret_inputs_full.len() % 2 == 0 {
                        println!("Found a leak!, stdout: {:?}", std::string::String::from_utf8_lossy(stdout));
                        println!("leak detected: {}", hash_val.extended_info_string());

                        self.prev_pub_in = input.get_public_part_bytes().to_owned();
                        self.prev_sec_in = input.get_secret_part_bytes().to_owned();
                        self.prev_output = OutputData { stdout: stdout.to_vec(), stderr: stderr.to_vec() };
                        
                        return HypertestResult::Failing(
                            I::from_pub_sec_bytes(
                                input.get_public_part_bytes(), 
                                &hash_val.secret_inputs_full[hash_val.secret_inputs_full.len() - 2]       
                            ),
                            I::from_pub_sec_bytes(
                                input.get_public_part_bytes(),
                                input.get_secret_part_bytes()
                            )
                        );
                    }
                }

            // We didn't store the original output the first time so let's do that now!
            } else if hash_val.public_output_hashes.len() > 1 &&
                hash_val.secret_inputs_full.len() < hash_val.public_output_hashes.len() &&
                hash_val.public_output_hashes[0] == pub_out_hash 
            {

                let output_data = OutputData { stdout: stdout.to_vec(), stderr: stderr.to_vec() };
                hash_val.public_outputs_full.insert(0, output_data);
                hash_val.secret_inputs_full.insert(0, input.get_secret_part_bytes().to_vec());
                println!("Found a leak! stdout: {{{:?}:{:?}}} vs {{{:?}:{:?}}}", 
                    std::string::String::from_utf8_lossy(input.get_secret_part_bytes()),
                    std::string::String::from_utf8_lossy(stdout),
                    std::string::String::from_utf8_lossy(&hash_val.secret_inputs_full[1]),
                    std::string::String::from_utf8_lossy(&hash_val.public_outputs_full[1].stdout));

                self.prev_pub_in = input.get_public_part_bytes().to_owned();
                self.prev_sec_in = input.get_secret_part_bytes().to_owned();
                self.prev_output = OutputData { stdout: stdout.to_vec(), stderr: stderr.to_vec() };

                return HypertestResult::Failing(
                    I::from_pub_sec_bytes(
                        input.get_public_part_bytes(), 
                        &hash_val.secret_inputs_full[1]       
                    ),
                    I::from_pub_sec_bytes(
                        input.get_public_part_bytes(),
                        input.get_secret_part_bytes()
                    )
                );
            }
        } else {
            self.dict.insert(pub_in_hash, IOHashValue {
                public_input_full: None,
                public_input_hash: pub_in_hash,
                public_output_hashes: vec![pub_out_hash],
                public_outputs_full: Vec::new(),
                secret_input_hashes: vec![sec_in_hash],
                secret_inputs_full: Vec::new()
            });
        }

        self.prev_pub_in = input.get_public_part_bytes().to_owned();
        self.prev_sec_in = input.get_secret_part_bytes().to_owned();
        self.prev_output = OutputData { stdout: stdout.to_vec(), stderr: stderr.to_vec() };
        // if self.prev_output.stdout.len() > 0 || self.prev_output.stderr.len() > 0 {
        //     println!("output: {}", self.prev_output.to_string());
        // }

        HypertestResult::Boring
    }
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
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input, CS::State, OT>,
{
    scheduler: CS,
    feedback: F,
    hypertest_feedback: HTF,
    objective: OF,
    phantom: PhantomData<OT>,
}

impl<CS, F, OF, OT, HTF> UsesState for LeakFuzzer<CS, F, OF, OT, HTF>
where
    CS: Scheduler,
    F: Feedback<CS::State>,
    OF: Feedback<CS::State>,
    CS::State: HasClientPerfMonitor + HasCorpus,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input, CS::State, OT>,
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
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input, CS::State, OT>,
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
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input, CS::State, OT>,
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
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input, CS::State, OT>,
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
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input, CS::State, OT>,
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

        let failing_hypertest = self.hypertest_feedback.exposes_fault(&input, observers);
        match failing_hypertest {
            HypertestResult::Boring => (),
            HypertestResult::NeedsRerun => {
                // let exit_kind = self.execute_input(state, executor, manager, &input)?;
                // let observers = executor.observers();
            },
            HypertestResult::Failing(in1, in2) => {

            },
        };

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
                        Some(manager.serialize_observers::<OT>(observers)?)
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
    CS::State: HasCorpus + HasSolutions + HasClientPerfMonitor + HasExecutions,
    <<CS as UsesState>::State as UsesInput>::Input: Input,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input, CS::State, OT>,
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
        let observers = executor.observers();

        self.scheduler.on_evaluation(state, &input, observers)?;

        self.process_execution(state, manager, input, observers, &exit_kind, send_events)
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
    CS::State: HasCorpus + HasSolutions + HasClientPerfMonitor + HasExecutions,
    <<CS as UsesState>::State as UsesInput>::Input: Input,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input, CS::State, OT>,
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
            Some(manager.serialize_observers::<OT>(observers)?)
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
    CS::State: HasClientPerfMonitor + HasExecutions + HasMetadata + HasCorpus + HasTestcase,
    ST: StagesTuple<E, EM, CS::State, Self>,
    OT: ObserversTuple<CS::State> + Serialize + DeserializeOwned,
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input, CS::State, OT>,
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

        // Get the next index from the scheduler
        let idx = self.scheduler.next(state)?;

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
            let mut testcase = state.testcase_mut(idx)?;
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
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input, CS::State, OT>,
{
    /// Create a new `LeakFuzzer` with standard behavior.
    pub fn new(scheduler: CS, feedback: F, objective: OF) -> Self {
        Self {
            scheduler,
            feedback,
            hypertest_feedback: HTF::new(),
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
    HTF: HypertestFeedback<<CS::State as UsesInput>::Input, CS::State, E::Observers>,
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
