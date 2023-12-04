use core::time::Duration;
use std::path::PathBuf;

use clap::{self, Parser};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{tuple_list, MatchName},
    AsMutSlice, Truncate,
};
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::HasObservers,
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::Fuzzer,
    monitors::{SimpleMonitor, SimplePrintingMonitor},
    mutators::{StdScheduledMutator, Tokens},
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    state::{HasCorpus, HasMetadata}, prelude::CachedOnDiskCorpus, 
};
use nix::sys::signal::Signal;

pub mod output_observer;
pub mod output_feedback;
pub mod output_forkserver;
pub mod output_leak_fuzzer;
pub mod pub_sec_input;
pub mod pub_sec_mutations;
pub mod hypertest_feedback;
pub mod leak_fuzzer_state;
pub mod leak_fuzzer_scheduler;
pub mod leak_fuzzer_mutational_stage;
#[allow(non_snake_case)]
pub mod STADS;
// use output_feedback::OutputFeedback;
use crate::{
    output_observer::OutputObserver, 
    output_forkserver::{ForkserverWithOutputExecutor, TimeoutForkserverWithOutputExecutor},
    hypertest_feedback::{InfoLeakChecker, HypertestFeedback}, 
    leak_fuzzer_state::LeakFuzzerState, 
    leak_fuzzer_mutational_stage::LeakFuzzerMutationalStage, 
    leak_fuzzer_scheduler::RandLeakScheduler, 
    STADS::StadsMapFeedback
};
use output_leak_fuzzer::LeakFuzzer;
use pub_sec_input::PubSecBytesInput;
use pub_sec_mutations::pub_sec_mutations;



/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "forkserver_libafl_cc",
    about = "This is a simple example fuzzer to fuzz a executable instrumented by libafl_cc.",
    author = "ergrelet <ergrelet@users.noreply.github.com>"
)]
struct Opt {
    #[arg(
        help = "The instrumented binary we want to fuzz",
        name = "EXEC",
        required = true
    )]
    executable: String,

    #[arg(
        help = "The directory to read initial inputs from ('seeds')",
        name = "INPUT_DIR",
        required = true
    )]
    in_dir: PathBuf,

    #[arg(
        help = "Timeout for each individual execution, in milliseconds",
        short = 't',
        long = "timeout",
        default_value = "1200"
    )]
    timeout: u64,

    // #[arg(
    //     help = "If not set, the child's stdout and stderror will be redirected to /dev/null",
    //     short = 'd',
    //     long = "debug-child",
    //     default_value = "false"
    // )]
    // debug_child: bool,

    #[arg(
        help = "Arguments passed to the target",
        name = "arguments",
        num_args(1..),
        allow_hyphen_values = true,
    )]
    arguments: Vec<String>,

    #[arg(
        help = "Signal used to stop child",
        short = 's',
        long = "signal",
        value_parser = str::parse::<Signal>,
        default_value = "SIGKILL"
    )]
    signal: Signal,
}

#[allow(clippy::similar_names)]
pub fn main() {
    const MAP_SIZE: usize = 65536;

    let opt = Opt::parse();

    let corpus_dirs: Vec<PathBuf> = [opt.in_dir].to_vec();

    // The unix shmem provider supported by LibAFL for shared memory
    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    // The coverage map shared between observer and executor
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // let the forkserver know the shmid
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmem_buf = shmem.as_mut_slice();

    // Create an observation channel using the signals map
    let edges_observer =
        unsafe { HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)) };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let output_observer = OutputObserver::new("output".to_string());
    // let output_feedback = OutputFeedback::new(&output_observer);

    // New maximization map feedback linked to the edges observer and the feedback state
    let inner_map = MaxMapFeedback::tracking(&edges_observer, true, false);
    let map_feedback = StadsMapFeedback::new(inner_map);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        map_feedback,
        // Time feedback, this one does not need a feedback state
        TimeFeedback::with_observer(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    // We want to do the same crash deduplication that AFL does
    let mut objective = feedback_and_fast!(
        // Must be a crash
        CrashFeedback::new(),
        // Take it only if trigger new coverage over crashes
        // Uses `with_name` to create a different history from the `MaxMapFeedback` in `feedback` above
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
    );

    // create a State from scratch
    let mut state = LeakFuzzerState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        CachedOnDiskCorpus::<PubSecBytesInput>::new(PathBuf::from("./queue"), 1024 * 1024).unwrap(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // Only store the violations temporarily
        //InMemoryCorpus::<PubSecBytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./violations")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are reported to the user
    // let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let monitor = SimplePrintingMonitor::new();

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // A minimization+queue policy to get testcasess from the corpus
    // let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());
    let scheduler = RandLeakScheduler::new();

    let mut fuzzer = LeakFuzzer::new(scheduler, feedback, objective, InfoLeakChecker::new());

    // If we should debug the child
    // let debug_child = opt.debug_child;

    // Create the executor for the forkserver
    let args = opt.arguments;

    let mut tokens = Tokens::new();
    let mut forkserver = ForkserverWithOutputExecutor::builder()
        .program(opt.executable)
        .debug_child(true)
        // .is_persistent(false)
        .shmem_provider(&mut shmem_provider)
        .autotokens(&mut tokens)
        .parse_afl_cmdline(args)
        .coverage_map_size(MAP_SIZE)
        .build(tuple_list!(time_observer, edges_observer, output_observer))
        .unwrap();

    if let Some(dynamic_map_size) = forkserver.coverage_map_size() {
        forkserver
            .observers_mut()
            .match_name_mut::<HitcountsMapObserver<StdMapObserver<'_, u8, false>>>("shared_mem")
            .unwrap()
            .truncate(dynamic_map_size);
    }

    let mut executor = TimeoutForkserverWithOutputExecutor::with_signal(
        forkserver,
        Duration::from_millis(opt.timeout),
        opt.signal,
    )
    .expect("Failed to create the executor.");

    // In case the corpus is empty (on first run), reset
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &corpus_dirs, err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    state.add_metadata(tokens);

    // Setup a mutational stage with a basic bytes mutator
    let mutator =
        StdScheduledMutator::with_max_stack_pow(pub_sec_mutations(), 6);
        // LeakFuzzerScheduledMutator::with_max_stack_pow(pub_sec_mutations(), 6);
    // let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    let mut stages = tuple_list!(LeakFuzzerMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
