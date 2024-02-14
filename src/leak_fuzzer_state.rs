//! The fuzzer, and state are the core pieces of every good fuzzer

use core::{
    cell::{Ref, RefMut},
    fmt::Debug,
    marker::PhantomData,
    time::Duration,
};
#[cfg(feature = "std")]
use std::{
    fs,
    path::{Path, PathBuf},
    vec::Vec,
};

use serde::{Deserialize, Serialize};

#[cfg(test)]
use libafl_bolts::rands::StdRand;
use libafl_bolts::{
    rands::Rand,
    serdeany::{NamedSerdeAnyMap, SerdeAnyMap},
};
use libafl::{
    corpus::{Corpus, CorpusId, HasTestcase, Testcase},
    events::{Event, EventFirer, LogSeverity},
    feedbacks::Feedback,
    fuzzer::{Evaluator, ExecuteInputResult},
    generators::Generator,
    inputs::{Input, UsesInput},
    monitors::ClientPerfMonitor,
    state::{State, UsesState, HasCorpus, HasMaxSize, HasSolutions, HasRand, HasClientPerfMonitor, HasMetadata, HasNamedMetadata, HasExecutions, HasStartTime, HasLastReportTime},
    Error,
    prelude::DEFAULT_MAX_SIZE,
};

// // blanket impl which automatically defines UsesInput for anything that implements UsesState
// impl<KS> UsesInput for KS
// where
//     KS: UsesState,
// {
//     type Input = <KS::State as UsesInput>::Input;
// }

/// The state a fuzz run.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "
        C: serde::Serialize + for<'a> serde::Deserialize<'a>,
        SC: serde::Serialize + for<'a> serde::Deserialize<'a>,
        VC: serde::Serialize + for<'a> serde::Deserialize<'a>,
        R: serde::Serialize + for<'a> serde::Deserialize<'a>
    ")]
pub struct LeakFuzzerState<I, C, R, SC, VC> {
    /// RNG instance
    rand: R,
    /// How many times the executor ran the harness/target
    executions: usize,
    /// At what time the fuzzing started
    start_time: Duration,
    /// The corpus
    corpus: C,
    /// Solutions corpus
    solutions: SC,
    /// Violations corpus
    violations: VC,
    /// Are we targeting violations or corpus currently?
    targeting_violations: ViolationsTargetingApproach,
    /// Metadata stored for this state by one of the components
    metadata: SerdeAnyMap,
    /// Metadata stored with names
    named_metadata: NamedSerdeAnyMap,
    /// MaxSize testcase size for mutators that appreciate it
    max_size: usize,
    /// Performance statistics for this fuzzer
    #[cfg(feature = "introspection")]
    introspection_monitor: ClientPerfMonitor,
    #[cfg(feature = "std")]
    /// Remaining initial inputs to load, if any
    remaining_initial_files: Option<Vec<PathBuf>>,
    /// The last time we reported progress (if available/used).
    /// This information is used by fuzzer `maybe_report_progress`.
    last_report_time: Option<Duration>,
    /// Has the estimate CMI mode been enabled? (from CLI)
    estimate_cmi_mode: bool,
    phantom: PhantomData<I>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Copy, PartialEq)]
pub enum ViolationsTargetingApproach {
    None,
    ToBeDecided,
    BitFlips,
    UniformSampling,
}

pub trait HasViolations: UsesInput {
    /// The associated type implementing [`Violations`].
    type Violations: Corpus<Input = <Self as UsesInput>::Input>;

    /// The testcase corpus
    fn violations(&self) -> &Self::Violations;
    /// The testcase corpus (mutable)
    fn violations_mut(&mut self) -> &mut Self::Violations;

    /// Return bool indicating whether we are targeting violations or corpus
    fn targeting_violations(&self) -> ViolationsTargetingApproach;
    /// Set bool indicating whether we are targeting violations or corpus
    fn set_targeting_violations(&mut self, targeting_violations: ViolationsTargetingApproach);

    /// return a bool indicating whether we are in 'estimate CMI' mode (i.e. uniform sampling)
    fn estimate_cmi_mode(&self) -> bool;
}

impl<I, C, R, SC, VC> HasLastReportTime for LeakFuzzerState<I, C, R, SC, VC> {
    /// The last time we reported progress,if available/used.
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time(&self) -> &Option<Duration> {
        &self.last_report_time
    }

    /// The last time we reported progress,if available/used (mutable).
    /// This information is used by fuzzer `maybe_report_progress`.
    fn last_report_time_mut(&mut self) -> &mut Option<Duration> {
        &mut self.last_report_time
    }
}

impl<I, C, R, SC, VC> HasViolations for LeakFuzzerState<I, C, R, SC, VC>
where
    I: Input,
    R: Rand,
    VC: Corpus<Input = <Self as UsesInput>::Input>,
{
    type Violations = VC;

    /// Returns the violations
    #[inline]
    fn violations(&self) -> &Self::Violations {
        &self.violations
    }

    /// Returns the mutable violations
    #[inline]
    fn violations_mut(&mut self) -> &mut Self::Violations {
        &mut self.violations
    }

    fn targeting_violations(&self) -> ViolationsTargetingApproach {
        self.targeting_violations
    }

    fn set_targeting_violations(&mut self, targeting_violations: ViolationsTargetingApproach) {
        self.targeting_violations = targeting_violations;
    }

    fn estimate_cmi_mode(&self) -> bool {
        self.estimate_cmi_mode
    }
}

impl<I, C, R, SC, VC> UsesInput for LeakFuzzerState<I, C, R, SC, VC>
where
    I: Input,
{
    type Input = I;
}

impl<I, C, R, SC, VC> State for LeakFuzzerState<I, C, R, SC, VC>
where
    C: Corpus<Input = Self::Input>,
    R: Rand,
    SC: Corpus<Input = Self::Input>,
    VC: Corpus<Input = Self::Input>,
    Self: UsesInput,
{
}

impl<I, C, R, SC, VC> HasRand for LeakFuzzerState<I, C, R, SC, VC>
where
    R: Rand,
{
    type Rand = R;

    /// The rand instance
    #[inline]
    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    /// The rand instance (mutable)
    #[inline]
    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

impl<I, C, R, SC, VC> HasCorpus for LeakFuzzerState<I, C, R, SC, VC>
where
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
{
    type Corpus = C;

    /// Returns the corpus
    #[inline]
    fn corpus(&self) -> &Self::Corpus {
        &self.corpus
    }

    /// Returns the mutable corpus
    #[inline]
    fn corpus_mut(&mut self) -> &mut Self::Corpus {
        &mut self.corpus
    }
}

impl<I, C, R, SC, VC> HasTestcase for LeakFuzzerState<I, C, R, SC, VC>
where
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
{
    /// To get the testcase
    fn testcase(&self, id: CorpusId) -> Result<Ref<Testcase<<Self as UsesInput>::Input>>, Error> {
        Ok(self.corpus().get(id)?.borrow())
    }

    /// To get mutable testcase
    fn testcase_mut(
        &self,
        id: CorpusId,
    ) -> Result<RefMut<Testcase<<Self as UsesInput>::Input>>, Error> {
        Ok(self.corpus().get(id)?.borrow_mut())
    }
}

impl<I, C, R, SC, VC> HasSolutions for LeakFuzzerState<I, C, R, SC, VC>
where
    I: Input,
    SC: Corpus<Input = <Self as UsesInput>::Input>,
{
    type Solutions = SC;

    /// Returns the solutions corpus
    #[inline]
    fn solutions(&self) -> &SC {
        &self.solutions
    }

    /// Returns the solutions corpus (mutable)
    #[inline]
    fn solutions_mut(&mut self) -> &mut SC {
        &mut self.solutions
    }
}

impl<I, C, R, SC, VC> HasMetadata for LeakFuzzerState<I, C, R, SC, VC> {
    /// Get all the metadata into an [`hashbrown::HashMap`]
    #[inline]
    fn metadata_map(&self) -> &SerdeAnyMap {
        &self.metadata
    }

    /// Get all the metadata into an [`hashbrown::HashMap`] (mutable)
    #[inline]
    fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadata
    }
}

impl<I, C, R, SC, VC> HasNamedMetadata for LeakFuzzerState<I, C, R, SC, VC> {
    /// Get all the metadata into an [`hashbrown::HashMap`]
    #[inline]
    fn named_metadata_map(&self) -> &NamedSerdeAnyMap {
        &self.named_metadata
    }

    /// Get all the metadata into an [`hashbrown::HashMap`] (mutable)
    #[inline]
    fn named_metadata_map_mut(&mut self) -> &mut NamedSerdeAnyMap {
        &mut self.named_metadata
    }
}

impl<I, C, R, SC, VC> HasExecutions for LeakFuzzerState<I, C, R, SC, VC> {
    /// The executions counter
    #[inline]
    fn executions(&self) -> &usize {
        &self.executions
    }

    /// The executions counter (mutable)
    #[inline]
    fn executions_mut(&mut self) -> &mut usize {
        &mut self.executions
    }
}

impl<I, C, R, SC, VC> HasMaxSize for LeakFuzzerState<I, C, R, SC, VC> {
    fn max_size(&self) -> usize {
        self.max_size
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

impl<I, C, R, SC, VC> HasStartTime for LeakFuzzerState<I, C, R, SC, VC> {
    /// The starting time
    #[inline]
    fn start_time(&self) -> &Duration {
        &self.start_time
    }

    /// The starting time (mutable)
    #[inline]
    fn start_time_mut(&mut self) -> &mut Duration {
        &mut self.start_time
    }
}

#[cfg(feature = "std")]
impl<C, I, R, SC, VC> LeakFuzzerState<I, C, R, SC, VC>
where
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
    SC: Corpus<Input = <Self as UsesInput>::Input>,
{
    /// Decide if the state nust load the inputs
    pub fn must_load_initial_inputs(&self) -> bool {
        self.corpus().count() == 0
            || (self.remaining_initial_files.is_some()
                && !self.remaining_initial_files.as_ref().unwrap().is_empty())
    }

    /// List initial inputs from a directory.
    fn visit_initial_directory(files: &mut Vec<PathBuf>, in_dir: &Path) -> Result<(), Error> {
        for entry in fs::read_dir(in_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.file_name().unwrap().to_string_lossy().starts_with('.') {
                continue;
            }

            let attributes = fs::metadata(&path);

            if attributes.is_err() {
                continue;
            }

            let attr = attributes?;

            if attr.is_file() && attr.len() > 0 {
                files.push(path);
            } else if attr.is_dir() {
                Self::visit_initial_directory(files, &path)?;
            }
        }

        Ok(())
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    fn load_initial_inputs_custom<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
        forced: bool,
        loader: &mut dyn FnMut(&mut Z, &mut Self, &Path) -> Result<I, Error>,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        if let Some(remaining) = self.remaining_initial_files.as_ref() {
            // everything was loaded
            if remaining.is_empty() {
                return Ok(());
            }
        } else {
            let mut files = vec![];
            for in_dir in in_dirs {
                Self::visit_initial_directory(&mut files, in_dir)?;
            }

            self.remaining_initial_files = Some(files);
        }

        self.continue_loading_initial_inputs_custom(fuzzer, executor, manager, forced, loader)
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    /// This method takes a list of files.
    fn load_initial_inputs_custom_by_filenames<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
        forced: bool,
        loader: &mut dyn FnMut(&mut Z, &mut Self, &Path) -> Result<I, Error>,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        if let Some(remaining) = self.remaining_initial_files.as_ref() {
            // everything was loaded
            if remaining.is_empty() {
                return Ok(());
            }
        } else {
            self.remaining_initial_files = Some(file_list.to_vec());
        }

        self.continue_loading_initial_inputs_custom(fuzzer, executor, manager, forced, loader)
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    /// This method takes a list of files.
    fn continue_loading_initial_inputs_custom<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        forced: bool,
        loader: &mut dyn FnMut(&mut Z, &mut Self, &Path) -> Result<I, Error>,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        if self.remaining_initial_files.is_none() {
            return Err(Error::illegal_state("No initial files were loaded, cannot continue loading. Call a `load_initial_input` fn first!"));
        }

        while let Some(path) = self.remaining_initial_files.as_mut().unwrap().pop() {
            log::info!("Loading file {:?} ...", &path);
            let input = loader(fuzzer, self, &path)?;
            if forced {
                let _: CorpusId = fuzzer.add_input(self, executor, manager, input).unwrap();
            } else {
                let (res, _) = fuzzer.evaluate_input(self, executor, manager, input).unwrap();
                if res == ExecuteInputResult::None {
                    log::warn!("File {:?} was not interesting, skipped.", &path);
                }
            }
        }

        manager.fire(
            self,
            Event::Log {
                severity_level: LogSeverity::Debug,
                message: format!("Loaded {} initial testcases.", self.corpus().count()), // get corpus count
                phantom: PhantomData::<I>,
            },
        )?;
        Ok(())
    }

    /// Loads all intial inputs, even if they are not considered `interesting`.
    /// This is rarely the right method, use `load_initial_inputs`,
    /// and potentially fix your `Feedback`, instead.
    /// This method takes a list of files, instead of folders.
    pub fn load_initial_inputs_by_filenames<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.load_initial_inputs_custom_by_filenames(
            fuzzer,
            executor,
            manager,
            file_list,
            false,
            &mut |_, _, path| I::from_file(path),
        )
    }

    /// Loads all intial inputs, even if they are not considered `interesting`.
    /// This is rarely the right method, use `load_initial_inputs`,
    /// and potentially fix your `Feedback`, instead.
    pub fn load_initial_inputs_forced<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.load_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            in_dirs,
            true,
            &mut |_, _, path| I::from_file(path),
        )
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    /// If `forced` is true, will add all testcases, no matter what.
    /// This method takes a list of files, instead of folders.
    pub fn load_initial_inputs_by_filenames_forced<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        file_list: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.load_initial_inputs_custom_by_filenames(
            fuzzer,
            executor,
            manager,
            file_list,
            true,
            &mut |_, _, path| I::from_file(path),
        )
    }

    /// Loads initial inputs from the passed-in `in_dirs`.
    pub fn load_initial_inputs<E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.load_initial_inputs_custom(
            fuzzer,
            executor,
            manager,
            in_dirs,
            false,
            &mut |_, _, path| I::from_file(path),
        )
    }
}

impl<C, I, R, SC, VC> LeakFuzzerState<I, C, R, SC, VC>
where
    I: Input,
    C: Corpus<Input = <Self as UsesInput>::Input>,
    R: Rand,
    SC: Corpus<Input = <Self as UsesInput>::Input>,
    VC: Corpus<Input = <Self as UsesInput>::Input>,
{
    fn generate_initial_internal<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
        forced: bool,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        G: Generator<<Self as UsesInput>::Input, Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        let mut added = 0;
        for _ in 0..num {
            let input = generator.generate(self)?;
            if forced {
                let _: CorpusId = fuzzer.add_input(self, executor, manager, input)?;
                added += 1;
            } else {
                let (res, _) = fuzzer.evaluate_input(self, executor, manager, input)?;
                if res != ExecuteInputResult::None {
                    added += 1;
                }
            }
        }
        manager.fire(
            self,
            Event::Log {
                severity_level: LogSeverity::Debug,
                message: format!("Loaded {added} over {num} initial testcases"),
                phantom: PhantomData,
            },
        )?;
        Ok(())
    }

    /// Generate `num` initial inputs, using the passed-in generator and force the addition to corpus.
    pub fn generate_initial_inputs_forced<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        G: Generator<<Self as UsesInput>::Input, Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.generate_initial_internal(fuzzer, executor, generator, manager, num, true)
    }

    /// Generate `num` initial inputs, using the passed-in generator.
    pub fn generate_initial_inputs<G, E, EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), Error>
    where
        E: UsesState<State = Self>,
        EM: EventFirer<State = Self>,
        G: Generator<<Self as UsesInput>::Input, Self>,
        Z: Evaluator<E, EM, State = Self>,
    {
        self.generate_initial_internal(fuzzer, executor, generator, manager, num, false)
    }

    /// Creates a new `State`, taking ownership of all of the individual components during fuzzing.
    pub fn new<F, O>(
        rand: R,
        corpus: C,
        solutions: SC,
        violations: VC,
        feedback: &mut F,
        objective: &mut O,
        estimate_cmi_mode: bool,
    ) -> Result<Self, Error>
    where
        F: Feedback<Self>,
        O: Feedback<Self>,
    {
        let mut state = Self {
            rand,
            executions: 0,
            start_time: Duration::from_millis(0),
            metadata: SerdeAnyMap::default(),
            named_metadata: NamedSerdeAnyMap::default(),
            corpus,
            solutions,
            violations,
            targeting_violations: ViolationsTargetingApproach::None,
            max_size: DEFAULT_MAX_SIZE,
            #[cfg(feature = "introspection")]
            introspection_monitor: ClientPerfMonitor::new(),
            #[cfg(feature = "std")]
            remaining_initial_files: None,
            last_report_time: None,
            estimate_cmi_mode,
            phantom: PhantomData,
        };
        feedback.init_state(&mut state)?;
        objective.init_state(&mut state)?;
        Ok(state)
    }
}

#[cfg(feature = "introspection")]
impl<I, C, R, SC, VC> HasClientPerfMonitor for LeakFuzzerState<I, C, R, SC, VC> {
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        &self.introspection_monitor
    }

    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        &mut self.introspection_monitor
    }
}

#[cfg(not(feature = "introspection"))]
impl<I, C, R, SC, VC> HasClientPerfMonitor for LeakFuzzerState<I, C, R, SC, VC> {
    fn introspection_monitor(&self) -> &ClientPerfMonitor {
        unimplemented!()
    }

    fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
        unimplemented!()
    }
}

// #[cfg(test)]
// /// A very simple state without any bells or whistles, for testing.
// #[derive(Debug, Serialize, Deserialize, Default)]
// pub struct NopState<I> {
//     metadata: SerdeAnyMap,
//     rand: StdRand,
//     phantom: PhantomData<I>,
// }

// #[cfg(test)]
// impl<I> NopState<I> {
//     /// Create a new State that does nothing (for tests)
//     #[must_use]
//     pub fn new() -> Self {
//         NopState {
//             metadata: SerdeAnyMap::new(),
//             rand: StdRand::default(),
//             phantom: PhantomData,
//         }
//     }
// }

// #[cfg(test)]
// impl<I> UsesInput for NopState<I>
// where
//     I: Input,
// {
//     type Input = I;
// }

// #[cfg(test)]
// impl<I> HasExecutions for NopState<I> {
//     fn executions(&self) -> &usize {
//         unimplemented!()
//     }

//     fn executions_mut(&mut self) -> &mut usize {
//         unimplemented!()
//     }
// }

// #[cfg(test)]
// impl<I> HasMetadata for NopState<I> {
//     fn metadata_map(&self) -> &SerdeAnyMap {
//         &self.metadata
//     }

//     fn metadata_map_mut(&mut self) -> &mut SerdeAnyMap {
//         &mut self.metadata
//     }
// }

// #[cfg(test)]
// impl<I> HasRand for NopState<I> {
//     type Rand = StdRand;

//     fn rand(&self) -> &Self::Rand {
//         &self.rand
//     }

//     fn rand_mut(&mut self) -> &mut Self::Rand {
//         &mut self.rand
//     }
// }

// #[cfg(test)]
// impl<I> HasClientPerfMonitor for NopState<I> {
//     fn introspection_monitor(&self) -> &ClientPerfMonitor {
//         unimplemented!()
//     }

//     fn introspection_monitor_mut(&mut self) -> &mut ClientPerfMonitor {
//         unimplemented!()
//     }
// }

// #[cfg(test)]
// impl<I> State for NopState<I> where I: Input {}
