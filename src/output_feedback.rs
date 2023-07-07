//! The ``OutputFeedback`` uses the program output

use core::fmt;
use std::{fmt::Debug, marker::PhantomData, cmp::{min, max}, io::{self, BufReader, Read}, fs::File};

use crate::{OutputObserver, output_observer::ObserverWithOutput};

use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

use libafl::{
    prelude::{Rand, Observer},
    bolts::tuples::Named,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, HasObserverName},
    inputs::UsesInput,
    observers::{ObserversTuple},
    state::{HasClientPerfMonitor, HasNamedMetadata, HasRand},
    Error,
};

/// The prefix of the metadata names
pub const OUTPUT_FEEDBACK_METADATA_PREFIX: &str = "output_feedback_metadata_";

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct OutputData {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>
}

/// The state of [`OutputFeedback`]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct OutputFeedbackMetadata {
    /// Contains information about untouched entries
    pub outputs_data: Vec<OutputData>
}

#[rustfmt::skip]
libafl::impl_serdeany!(OutputFeedbackMetadata);

impl OutputFeedbackMetadata {
    /// Create a new [`OutputFeedbackMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the internal state
    pub fn reset(&mut self) -> Result<(), Error> {
        self.outputs_data = Vec::new();
        Ok(())
    }
}

// impl HashSetState<u64> for NewHashFeedbackMetadata {
//     /// Create new [`NewHashFeedbackMetadata`] using a name and a hash set.
//     #[must_use]
//     fn with_hash_set(hash_set: HashSet<u64>) -> Self {
//         Self { hash_set }
//     }

//     fn update_hash_set(&mut self, value: u64) -> Result<bool, Error> {
//         let r = self.hash_set.insert(value);
//         // log::trace!("Got r={}, the hashset is {:?}", r, &self.hash_set);
//         Ok(r)
//     }
// }

/// A [`OutputFeedback`] maintains a hashset of already seen outputs and considers interesting new ones
#[derive(Serialize, Deserialize)]
pub struct OutputFeedback<O, S> {
    name: String,
    observer_name: String,
    /// Initial capacity of hash set
    capacity: usize,
    o_type: PhantomData<(O, S)>,
}

impl<O, S> fmt::Debug for OutputFeedback<O, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "name: {}, observer_name: {}, capacity: {}, o_type: {:?}",
            self.name, self.observer_name, self.capacity, self.o_type)
    }
}

impl<O, S> OutputFeedback<O, S>
where 
    S: HasNamedMetadata
{
}

impl<O, S> Feedback<S> for OutputFeedback<O, S>
where
    O: ObserverWithOutput + Named + Debug,
    S: UsesInput + Debug + HasNamedMetadata + HasClientPerfMonitor + HasRand,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        state.add_named_metadata(
            OutputFeedbackMetadata::new(),
            &self.name
        );
        Ok(())
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let observer = observers.match_name::<O>(&self.observer_name).unwrap();

        let output_data = OutputData {
            stdout: match observer.stdout().to_owned() {
                None => Vec::new(),
                Some(o) => o
            },
            stderr: match observer.stderr().to_owned() {
                None => Vec::new(),
                Some(o) => o
            }
        };

        if observer.stdout().as_ref().unwrap().len() > 0 {
            // eprintln!("stdout: {:?}, stderr: {:?}", observer.stdout(), observer.stderr());
        }

        let output_meta = state
            .named_metadata_map_mut()
            .get_mut::<OutputFeedbackMetadata>(&self.name)
            .unwrap();

        // let compressor = match &mut self.compressor {
        //     Some(comp) => comp,
        //     None => {
        //         let mut buf = Vec::new();
        //         let mut lens = Vec::new();
        //         for out in &output_meta.outputs_data {
        //             buf.append(&mut out.stdout.to_owned());
        //             lens.push(out.stdout.len());
        //         }

        //         let compressor = if buf.len() > 128 {
        //             println!("Creating compressor with buf {}", buf.len());
        //             let dict = zstd::dict::from_continuous(&buf, &lens, 100_000_000).unwrap();
        //             Compressor::with_dictionary(0, &dict).unwrap()
        //         } else {
        //             Compressor::new(0).unwrap()
        //         };
        //         self.compressor = Some(compressor);
        //         self.compressor.as_mut().unwrap()
        //     }
        // };

        // let comp_len_new = compressor.compress(&output_data.stdout).unwrap().len();
        // println!("Comparing {:?} with {:?}", output_data.stdout, output_meta.outputs_data.iter().map(|x| x.stdout.to_owned()).collect::<Vec<Vec<u8>>>());

        // for out in &output_meta.outputs_data {
        //     let comp_len_in2 = compressor.compress(&out.stdout).unwrap().len();

        //     let mut concat = output_data.stdout.to_owned();
        //     concat.append(&mut out.stdout.to_owned());
        //     let comp_len_concat = compressor.compress(&concat).unwrap().len();

        //     let ncd = (comp_len_concat - min(comp_len_new, comp_len_in2)) as f64 / 
        //         max(comp_len_new, comp_len_in2) as f64;
            
        //     println!("NCD for input: {ncd}");
        //     if ncd < 0.6 { rough_match = true; break; }
        // }

        // let backtrace_state = state
        //     .named_metadata_map_mut()
        //     .get_mut::<NewHashFeedbackMetadata>(&self.name)
        //     .unwrap();

        // match observer.hash() {
        //     Some(hash) => {
        //         let res = backtrace_state
        //             .update_hash_set(hash)
        //             .expect("Failed to update the hash state");
        //         Ok(res)
        //     }
        //     None => {
        //         // We get here if the hash was not updated, i.e the first run or if no crash happens
        //         Ok(false)
        //     }
        // }

        Ok(false)
    }
}

impl<O, S> Named for OutputFeedback<O, S> {
    #[inline]
    fn name(&self) -> &str {
        &self.name
    }
}

impl<O, S> HasObserverName for OutputFeedback<O, S> {
    #[inline]
    fn observer_name(&self) -> &str {
        &self.observer_name
    }
}

/// Default capacity for the [`HashSet`] in [`NewHashFeedback`].
///
/// This is reasonably large on the assumption that you expect there to be many
/// runs of the target, producing many different feedbacks.
const DEFAULT_CAPACITY: usize = 4096;

impl<O, S> OutputFeedback<O, S>
where
    O: ObserverWithOutput + Named + Debug,
{
    /// Returns a new [`OutputFeedback`].
    /// Setting an observer name that doesn't exist would eventually trigger a panic.
    #[must_use]
    pub fn with_names(name: &str, observer_name: &str) -> Self {
        Self {
            name: name.to_string(),
            observer_name: observer_name.to_string(),
            capacity: DEFAULT_CAPACITY,
            o_type: PhantomData,
        }
    }

    /// Returns a new [`OutputFeedback`].
    #[must_use]
    pub fn new(observer: &O) -> Self {
        Self::with_capacity(observer, DEFAULT_CAPACITY)
    }

    /// Returns a new [`OutputFeedback`] that will create a hash set with the
    /// given initial capacity.
    #[must_use]
    pub fn with_capacity(observer: &O, capacity: usize) -> Self {
        Self {
            name: OUTPUT_FEEDBACK_METADATA_PREFIX.to_string() + observer.name(),
            observer_name: observer.name().to_string(),
            capacity,
            o_type: PhantomData,
        }
    }
}
