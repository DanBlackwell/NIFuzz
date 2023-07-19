use core::time::Duration;
use std::path::PathBuf;

use clap::{self, Parser};
use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{ShMem, ShMemProvider, UnixShMemProvider},
        tuples::{tuple_list, MatchName, Merge},
        AsMutSlice, Truncate,
    },
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{
        forkserver::ForkserverExecutor,
        HasObservers,
    },
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{scheduled::havoc_mutations, tokens_mutations, StdScheduledMutator, Tokens},
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    prelude::{
        BitFlipMutator, ByteFlipMutator, ByteIncMutator, ByteDecMutator, 
        ByteNegMutator, ByteRandMutator, ByteAddMutator, WordAddMutator, 
        DwordAddMutator, QwordAddMutator, ByteInterestingMutator, WordInterestingMutator, 
        DwordInterestingMutator
    },
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler, MinimizerScheduler, LenTimeMulTestcaseScore},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState}, prelude::{RomuDuoJrRand, MapIndexesMetadata, CombinedFeedback, MapFeedback, DifferentIsNovel, MaxReducer, LogicEagerOr, LogicFastAnd},
};
use nix::sys::signal::Signal;

mod output_observer;
mod output_feedback;
mod output_forkserver;
mod output_leak_fuzzer;
mod pub_sec_input;
// mod pub_sec_mutational;
mod pub_sec_mutations;
// mod pub_sec_scheduled_mutator;
use output_feedback::{OutputFeedback, OutputFeedbackMetadata};
use output_forkserver::TimeoutForkserverExecutorWithOutput;
use crate::{output_observer::OutputObserver, output_forkserver::ForkserverExecutorWithOutput, output_leak_fuzzer::InfoLeakChecker};
use output_leak_fuzzer::LeakFuzzer;
use pub_sec_input::PubSecBytesInput;
// use pub_sec_mutational::StdPubSecMutationalStage;
// use pub_sec_scheduled_mutator::PubSecScheduledMutator;
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
    let output_feedback: OutputFeedback<OutputObserver, StdState<PubSecBytesInput, InMemoryCorpus<PubSecBytesInput>, RomuDuoJrRand, OnDiskCorpus<PubSecBytesInput>>> = OutputFeedback::with_names("output_feedback", "output");

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::tracking(&edges_observer, true, false),
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
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::<PubSecBytesInput>::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer: LeakFuzzer<MinimizerScheduler<QueueScheduler<StdState<PubSecBytesInput, InMemoryCorpus<PubSecBytesInput>, RomuDuoJrRand, OnDiskCorpus<PubSecBytesInput>>>, LenTimeMulTestcaseScore<StdState<PubSecBytesInput, InMemoryCorpus<PubSecBytesInput>, RomuDuoJrRand, OnDiskCorpus<PubSecBytesInput>>>, MapIndexesMetadata>, CombinedFeedback<MapFeedback<DifferentIsNovel, HitcountsMapObserver<StdMapObserver<'_, u8, false>>, MaxReducer, StdState<PubSecBytesInput, InMemoryCorpus<PubSecBytesInput>, RomuDuoJrRand, OnDiskCorpus<PubSecBytesInput>>, u8>, TimeFeedback, LogicEagerOr, StdState<PubSecBytesInput, InMemoryCorpus<PubSecBytesInput>, RomuDuoJrRand, OnDiskCorpus<PubSecBytesInput>>>, CombinedFeedback<CrashFeedback, MapFeedback<DifferentIsNovel, HitcountsMapObserver<StdMapObserver<'_, u8, false>>, MaxReducer, StdState<PubSecBytesInput, InMemoryCorpus<PubSecBytesInput>, RomuDuoJrRand, OnDiskCorpus<PubSecBytesInput>>, u8>, LogicFastAnd, StdState<PubSecBytesInput, InMemoryCorpus<PubSecBytesInput>, RomuDuoJrRand, OnDiskCorpus<PubSecBytesInput>>>, (TimeObserver, (HitcountsMapObserver<StdMapObserver<'_, u8, false>>, (OutputObserver, ()))), InfoLeakChecker<PubSecBytesInput>> = LeakFuzzer::new(scheduler, feedback, objective);

    // If we should debug the child
    // let debug_child = opt.debug_child;

    // Create the executor for the forkserver
    let args = opt.arguments;

    let mut tokens = Tokens::new();
    let mut forkserver = ForkserverExecutorWithOutput::builder()
        .program(opt.executable)
        .debug_child(true)
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

    let mut executor = TimeoutForkserverExecutorWithOutput::with_signal(
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

    // let mutations = tuple_list!(
    //     PubSecBitFlipMutator::new(),
    //     PubSecByteDecMutator::new(),
    //     PubSecByteFlipMutator::new(),
    //     PubSecByteIncMutator::new(),
    //     PubSecByteNegMutator::new(),
    //     PubSecByteRandMutator::new(),
    //     PubSecBytesDeleteMutator::new(),

    //     PubSecByteAddMutator::new(),
    //     PubSecWordAddMutator::new(),
    //     PubSecDwordAddMutator::new(),
    //     PubSecQwordAddMutator::new(),

    //     PubSecByteInterestingMutator::new(),
    //     PubSecWordInterestingMutator::new(),
    //     PubSecDwordInterestingMutator::new(),

    //     PubSecBytesExpandMutator::new(),
    //     PubSecBytesInsertMutator::new(),
    //     PubSecBytesRandInsertMutator::new(),
    //     PubSecBytesSetMutator::new(),
    //     PubSecBytesRandSetMutator::new(),
    //     PubSecBytesCopyMutator::new(),

    //     PubSecCrossoverInsertMutator::new(),
    //     PubSecCrossoverReplaceMutator::new(),
    //     PubSecSpliceMutator::new(),
    // );

    // Setup a mutational stage with a basic bytes mutator
    let mutator =
        StdScheduledMutator::with_max_stack_pow(pub_sec_mutations(), 6);
    // let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

