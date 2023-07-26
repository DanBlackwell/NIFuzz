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

/// struct storing associated data for a given public input 
/// (including public outputs and secret inputs that witness a 
/// leak)
pub struct IOHashValue {
    /// The hash of the public input this struct is describing
    pub public_input_hash: u64,
    /// Optional full public input vector; only populated if this 
    /// witnesses a policy violation
    pub public_input_full: Option<Vec<u8>>,
    /// Vector of secret input hashes (only one is stored for each 
    /// different public output)
    pub secret_input_hashes: Vec<u64>,
    /// Vector of public output hashes (note that if more than two
    /// are present then a leak has been witnessed)
    pub public_output_hashes: Vec<u64>,
    /// Mapping from public_output_hashes to a vector of secret_in's
    /// that produce this public output
    public_output_hashes_to_secret_ins: HashMap<u64, Vec<u64>>,

    /// Vector of full byte arrays for secret inputs that can 
    /// witness a leak
    pub secret_inputs_full: Vec<Vec<u8>>,
    /// Vector of full public outputs that witness a leak
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

/// State for the current fuzzing campaign with associated functions
pub struct InfoLeakChecker<I> {
    /// dictionary mapping public_in hashes to IOHashValues (including secret_in and public_out)
    dict: HashMap<u64, IOHashValue>,    
    /// previous secret_in vec, for debug
    prev_sec_in: Vec<u8>,
    /// previous public_in vec, for debug
    prev_pub_in: Vec<u8>,
    /// previous public_out value, for debug
    prev_output: OutputData,
    /// Vector of all public_in hashes that contain a violation (i.e. differing public_out's dependent on secret_in value)
    violation_pub_ins: Vec<u64>,
    phantom: PhantomData<I>
}

impl<I> InfoLeakChecker<I> {
}

pub struct FailingHypertest<'a, I> {
    test_one: (I, &'a OutputData),
    test_two: (I, &'a OutputData),
}

pub trait HypertestFeedback<I, S, OT> 
where 
    I: Input, 
    S: HasCorpus,
    OT: ObserversTuple<S> + Serialize + DeserializeOwned,
{
    /// Create a new empty HypertestFeedback object
    fn new() -> Self;
    /// Read the observers relevant observers and determine whether this input may be interesting
    /// (in which case it should be rerun to confirm that it is deterministic) 
    fn needs_rerun(&mut self, input: &I, observers: &OT) -> (bool, Option<OutputData>);
    /// Called when an interesting input is confirmed to be deterministic; in some cases this may
    /// return a FailingHypertest, or None if this just fixes an entry that was previously stored 
    /// incorrectly (likely due to some oddity in the way the forkserver collects output) 
    fn exposes_fault(&mut self, input: &I, output_data: OutputData) -> Option<FailingHypertest<'_, I>>;
    /// Estimate the quantity of leakage (in bits) that has been witnessed so far
    fn estimate_leakage(&self) -> f64;
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
            violation_pub_ins: vec![],
            phantom: PhantomData
        }
    }

    fn needs_rerun(&mut self, input: &I, observers: &OT) -> (bool, Option<OutputData>) {
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
                let output_data = OutputData { stdout: stdout.to_vec(), stderr: stderr.to_vec() };

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

                    return (true, Some(output_data));
                }

                // let mut matches = false;
                for secret_in in &hash_val.secret_inputs_full {
                    if input.get_secret_part_bytes() == secret_in {
                        // matches = true;
                        panic!("Hash not found in hashes, but full input was?");
                    }
                }

                // if !matches {
                    println!("Likely leak, needs rerun to confirm deterministic");
                    return (true, Some(output_data));
                // }

            // We didn't store the original output the first time so let's do that now!
            } else if hash_val.public_output_hashes.len() > 1 &&
                hash_val.secret_inputs_full.len() < hash_val.public_output_hashes.len() &&
                hash_val.public_output_hashes[0] == pub_out_hash 
            {
                println!("Found an input for which full secret input was not stored, flagged for rerun");
                let output_data = OutputData { stdout: stdout.to_vec(), stderr: stderr.to_vec() };
                return (true, Some(output_data));
            
            // We didn't find a new public_out, but we should update the mapping between public_out and secret_in
            } else {
                if let Some(sec_ins) = hash_val.public_output_hashes_to_secret_ins.get_mut(&pub_out_hash) {
                    sec_ins.push(sec_in_hash);
                } else {
                    panic!("Ow, this was a new public_out after all?");
                }
            }
        } else {
            self.dict.insert(pub_in_hash, IOHashValue {
                public_input_full: None,
                public_output_hashes_to_secret_ins: HashMap::from([(pub_out_hash, vec![sec_in_hash])]),
                public_input_hash: pub_in_hash,
                public_output_hashes: vec![pub_out_hash],
                public_outputs_full: Vec::new(),
                secret_input_hashes: vec![sec_in_hash],
                secret_inputs_full: Vec::new()
            });
        }

        (false, None)
    }

    fn exposes_fault(&mut self, input: &I, output_data: OutputData) -> Option<FailingHypertest<'_, I>> {
        let hash = |val: &[u8]| {
            let mut hasher = DefaultHasher::new();
            val.hash(&mut hasher);
            hasher.finish()
        };

        let pub_in_hash = hash(input.get_public_part_bytes());
        let sec_in_hash = hash(input.get_secret_part_bytes());

        let mut hasher = DefaultHasher::new();
        output_data.stdout.hash(&mut hasher);
        output_data.stderr.hash(&mut hasher);
        let pub_out_hash = hasher.finish();

        if let Some(hash_val) = self.dict.get_mut(&pub_in_hash) {
            if !hash_val.public_output_hashes.contains(&pub_out_hash) {
                if hash_val.secret_input_hashes.contains(&sec_in_hash) {
                    let pos = hash_val.secret_input_hashes
                        .iter()
                        .position(|&h| h == sec_in_hash)
                        .unwrap();
                    let old_pub_out_hash = hash_val.public_output_hashes[pos];
                    hash_val.public_output_hashes[pos] = pub_out_hash;

                    let full_pos = if hash_val.public_output_hashes.len() > hash_val.public_outputs_full.len() {
                        pos - 1
                    } else {
                        pos
                    };

                    if hash_val.public_outputs_full.len() > 0 {
                        hash_val.public_outputs_full[full_pos] = output_data;
                    }

                    // update mappings from output to secret_in
                    let mut members = hash_val.public_output_hashes_to_secret_ins.get_mut(&old_pub_out_hash).unwrap();
                    members.retain(|&x| x != sec_in_hash);
                    if members.len() == 0 { hash_val.public_output_hashes_to_secret_ins.remove(&old_pub_out_hash); }

                    hash_val.public_output_hashes_to_secret_ins.insert(pub_out_hash, vec![sec_in_hash]);
                    print!("public_out: secret_in mapping for {}: [\n", pub_out_hash);
                    for (out, in_vec) in hash_val.public_output_hashes_to_secret_ins.iter() {
                        println!("{}: {:?}", out, in_vec);
                    }
                    println!("]");

                    println!("Replaced incorrect output_hash with correct one");
                    return None;
                }

                if hash_val.public_input_full.is_none() {
                    hash_val.public_input_full = Some(input.get_public_part_bytes().to_vec());
                    self.violation_pub_ins.push(pub_in_hash);
                }

                if let Some(mut members) = hash_val.public_output_hashes_to_secret_ins.get_mut(&pub_out_hash) {
                    panic!("OOH, had a map for {} in {:?}, but not in public_output_hashes: {:?}", pub_out_hash,
                        hash_val.public_output_hashes_to_secret_ins.keys(), hash_val.public_output_hashes);
                } else {
                    hash_val.public_output_hashes_to_secret_ins.insert(pub_out_hash, vec![sec_in_hash]);
                    print!("public_out: secret_in mapping for {}: [\n", pub_out_hash);
                    for (out, in_vec) in hash_val.public_output_hashes_to_secret_ins.iter() {
                        println!("{}: {:?}", out, in_vec);
                    }
                }

                hash_val.secret_inputs_full.push(input.get_secret_part_bytes().to_vec());
                hash_val.public_outputs_full.push(output_data);
                hash_val.public_output_hashes.push(pub_out_hash);

                if hash_val.secret_inputs_full.len() > 2 && hash_val.secret_inputs_full.len() % 2 == 0 {
                    println!("Found a leak!, stdout: {:?}", 
                        std::string::String::from_utf8_lossy(&hash_val.public_outputs_full.last().unwrap().stdout));
                    println!("leak detected: {}", hash_val.extended_info_string());
                    
                    return Some(FailingHypertest {
                        test_one: (
                            I::from_pub_sec_bytes(
                                input.get_public_part_bytes(), 
                                &hash_val.secret_inputs_full[hash_val.secret_inputs_full.len() - 2]       
                            ),
                            &hash_val.public_outputs_full[hash_val.public_outputs_full.len() - 2]
                        ),
                        test_two: (
                            I::from_pub_sec_bytes(
                                input.get_public_part_bytes(),
                                input.get_secret_part_bytes()
                            ),
                            &hash_val.public_outputs_full.last().unwrap()
                        ),
                    });
                }

                println!("Found a likely leak, but don't have the original secret input stored to verify yet");
                return None;

            // We didn't store the original output the first time so let's do that now!
            } else if hash_val.public_output_hashes.len() > 1 &&
                hash_val.secret_inputs_full.len() < hash_val.public_output_hashes.len() &&
                hash_val.public_output_hashes[0] == pub_out_hash 
            {

                println!("Found a leak! stdout: {{{:?}:{:?}}} vs {{{:?}:{:?}}}", 
                    std::string::String::from_utf8_lossy(input.get_secret_part_bytes()),
                    std::string::String::from_utf8_lossy(&output_data.stdout),
                    std::string::String::from_utf8_lossy(&hash_val.secret_inputs_full[0]),
                    std::string::String::from_utf8_lossy(&hash_val.public_outputs_full[0].stdout));

                hash_val.public_outputs_full.insert(0, output_data);
                hash_val.secret_inputs_full.insert(0, input.get_secret_part_bytes().to_vec());

                return Some(FailingHypertest {
                    test_one: (
                        I::from_pub_sec_bytes(
                            input.get_public_part_bytes(), 
                            &hash_val.secret_inputs_full[1]       
                        ),
                        &hash_val.public_outputs_full[1]
                    ),
                    test_two: (
                        I::from_pub_sec_bytes(
                            input.get_public_part_bytes(),
                            input.get_secret_part_bytes()
                        ),
                        &hash_val.public_outputs_full[0]
                    ),
                });
            }
        } else {
            panic!("This should have already been added in needs_rerun!");
        }

        panic!("oops");
    }

    fn estimate_leakage(&self) -> f64 {
        let mut output_violation_entropy_sum = 0.0_f64;
        let mut violation_entropy_sum = 0.0_f64;
        // println!("calculating leakage, probability per pub_in: {}", prob);

        for violation_pub_in_hash in &self.violation_pub_ins {
            let hash_val = self.dict.get(violation_pub_in_hash).unwrap();
            let sample_count = hash_val.public_output_hashes_to_secret_ins
                .values()
                .fold(0, |acc, x| acc + x.len());
            // println!("  {}: ", violation_pub_in_hash);
            for (pub_out, sec_in) in &hash_val.public_output_hashes_to_secret_ins {
                let prob = sec_in.len() as f64 / sample_count as f64;
                output_violation_entropy_sum += prob * prob.log2();
                // println!("    {}: (prob: {}/{}) (entropy_sum: {})", pub_out, sec_in.len(), sample_count, output_violation_entropy_sum);
            }

            let pub_in_prob = 1.0_f64 / self.dict.len() as f64;
            violation_entropy_sum += pub_in_prob * pub_in_prob.log2();
        }

        let leaked_info_bits = - output_violation_entropy_sum + violation_entropy_sum;
        println!("Leaked {} bits", leaked_info_bits);

        leaked_info_bits
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

        let (needs_rerun, output_data) = self.hypertest_feedback.needs_rerun(&input, observers);
        if needs_rerun {
            let failing_hypertest = self.hypertest_feedback.exposes_fault(&input, output_data.unwrap());
            match failing_hypertest {
                Some(failing_hypertest) => { self.hypertest_feedback.estimate_leakage(); },
                _ => ()
            };
        }
        
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
