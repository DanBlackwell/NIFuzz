//! The ``OutputFeedback`` uses the program output

use core::fmt;
use std::{fmt::Debug, marker::PhantomData, io::Error};

use crate::output_observer::ObserverWithOutput;

use serde::{Deserialize, Serialize};

use libafl_bolts::Named;
use libafl::feedbacks::HasObserverName;

/// The prefix of the metadata names
pub const OUTPUT_FEEDBACK_METADATA_PREFIX: &str = "output_feedback_metadata_";

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct OutputData {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>
}

impl OutputData {
    pub fn to_string(&self) -> String {
        format!("stdout: {:?}, stderr: {:?}", 
            std::string::String::from_utf8_lossy(&self.stdout),
            std::string::String::from_utf8_lossy(&self.stderr))
    }
}

/// The state of [`OutputFeedback`]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct OutputFeedbackMetadata {
    /// Contains information about untouched entries
    pub outputs_data: Vec<OutputData>
}

#[rustfmt::skip]
libafl_bolts::impl_serdeany!(OutputFeedbackMetadata);

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
pub struct OutputFeedback<O> {
    name: String,
    observer_name: String,
    /// Initial capacity of hash set
    capacity: usize,
    o_type: PhantomData<O>,
}

impl<O> fmt::Debug for OutputFeedback<O> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "name: {}, observer_name: {}, capacity: {}, o_type: {:?}",
            self.name, self.observer_name, self.capacity, self.o_type)
    }
}

impl<O> Named for OutputFeedback<O> {
    #[inline]
    fn name(&self) -> &str {
        &self.name
    }
}

impl<O> HasObserverName for OutputFeedback<O> {
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

impl<O> OutputFeedback<O>
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
