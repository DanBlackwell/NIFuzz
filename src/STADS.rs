use std::fmt::Debug;
use ahash::{HashMap, HashMapExt};
use libafl::{prelude::{MapFeedback, UsesObserver, UsesInput, Observer, Feedback, IsNovel, MapObserver, AsIter, Reducer, ObserversTuple, Testcase, ExitKind, EventFirer, Named, HasObserverName}, state::{HasClientPerfMonitor, HasNamedMetadata}, Error};
use serde::{Serialize, Deserialize, de::DeserializeOwned};

pub struct STADSstatistics {
    expected_finds: usize,
    correctness: f64
}

pub trait STADSfeedback {
    fn stads_calc(&self) -> STADSstatistics;
}


/// The most common AFL-like feedback type
#[derive(Clone, Debug)]
pub struct StadsMapFeedback<N, O, R, S, T> {
    /// Child `MapFeedback` object to handle all of the functionality
    map_feedback: MapFeedback<N, O, R, S, T>,
    /// Number of times we have seen each path in the queue
    path_hash_frequencies: HashMap<u64, usize>,
    /// Number of samples
    count: usize,
}

impl<N, O, R, S, T> UsesObserver<S> for StadsMapFeedback<N, O, R, S, T>
where
    S: UsesInput,
    O: Observer<S>,
{
    type Observer = O;
}

impl<N, O, R, S, T> Feedback<S> for StadsMapFeedback<N, O, R, S, T>
where
    N: IsNovel<T> + Debug,
    O: MapObserver<Entry = T> + for<'it> AsIter<'it, Item = T>,
    R: Reducer<T> + Debug,
    S: UsesInput + HasClientPerfMonitor + HasNamedMetadata + Debug,
    T: Default + Copy + Serialize + for<'de> Deserialize<'de> + PartialEq + Debug + 'static,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.map_feedback.init_state(state)
    }

    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &<S as UsesInput>::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let res = self.map_feedback.is_interesting(state, manager, input, observers, exit_kind);
        if res.is_ok() {
            let observer = observers.match_name::<O>(&self.map_feedback.observer_name()).unwrap();
            let hash = observer.hash();

            if *res.as_ref().unwrap() {
                self.path_hash_frequencies.insert(hash, 1);
            } else {
                // println!("map size: {}, num set bytes: {:?}", observer.len(), observer.count_bytes());
                if let Some(count) = self.path_hash_frequencies.get_mut(&hash) {
                    *count += 1;
                }
            }
        }

        self.count += 1;
        if self.count % 10_000 == 0 { 
            let info = self.stads_calc(); 
            println!("Queue STADS: current_finds: {}, expected_finds: {}, correctness: {}", self.path_hash_frequencies.len(), info.expected_finds, info.correctness);
        }

        res
    }

    fn append_metadata<OT>(
        &mut self,
        state: &mut S,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
    {
        self.map_feedback.append_metadata(state, observers, testcase)
    }
}

impl<N, O, R, S, T> Named for StadsMapFeedback<N, O, R, S, T> {
    #[inline]
    fn name(&self) -> &str {
        self.map_feedback.name()
    }
}

impl<N, O, R, S, T> HasObserverName for StadsMapFeedback<N, O, R, S, T>
where
    T: PartialEq + Default + Copy + 'static + Serialize + DeserializeOwned + Debug,
    R: Reducer<T>,
    N: IsNovel<T>,
    O: MapObserver<Entry = T>,
    for<'it> O: AsIter<'it, Item = T>,
    S: HasNamedMetadata,
{
    #[inline]
    fn observer_name(&self) -> &str {
        self.map_feedback.observer_name()
    }
}

#[allow(dead_code)]
fn create_stats_name(name: &str) -> String {
    name.to_lowercase()
}

impl<N, O, R, S, T> StadsMapFeedback<N, O, R, S, T>
where
    T: PartialEq + Default + Copy + 'static + Serialize + DeserializeOwned + Debug,
    R: Reducer<T>,
    O: MapObserver<Entry = T>,
    for<'it> O: AsIter<'it, Item = T>,
    N: IsNovel<T>,
    S: UsesInput + HasNamedMetadata + HasClientPerfMonitor + Debug,
{
    /// Create new `MapFeedback`
    #[must_use]
    pub fn new(map_feedback: MapFeedback<N, O, R, S, T>) -> Self {
        Self {
            map_feedback,
            path_hash_frequencies: HashMap::new(),
            count: 0,
        }
    }

    /// For tracking, enable `always_track` mode, that also adds `novelties` or `indexes`,
    /// even if the map is not novel for this feedback.
    /// This is useful in combination with `load_initial_inputs_forced`, or other feedbacks.
    #[allow(dead_code)]
    pub fn set_always_track(&mut self, always_track: bool) {
        self.map_feedback.set_always_track(always_track)
    }
}

impl<N, O, R, S, T> STADSfeedback for StadsMapFeedback<N, O ,R, S, T> {
    fn stads_calc(&self) -> STADSstatistics {
        let mut singletons = 0; 
        let mut doubletons = 0;
        let mut total_samples = 0;

        for freq in self.path_hash_frequencies.values() {
            total_samples += *freq;
            match *freq {
                1 => singletons += 1,
                2 => doubletons += 1,
                _ => ()
            };
        }

        let expected_finds = self.path_hash_frequencies.len() +
            if doubletons > 0 {
                (singletons * singletons) / (2 * doubletons)
            } else {
                singletons * (singletons - 1) / 2
            };

        let correctness = singletons as f64 / total_samples as f64;

        STADSstatistics { expected_finds, correctness }
    }
}