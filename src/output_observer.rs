use std::vec::Vec;

use serde::{Deserialize, Serialize};

use libafl::{bolts::tuples::Named, inputs::UsesInput, observers::Observer};

/// An observer that captures output of a target.
/// Only works for supported executors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutputObserver {
    /// The name of the observer.
    pub name: String,
    /// The stdout of the target during its last execution.
    pub stdout: Option<Vec<u8>>,
    /// The stderr of the target during its last execution.
    pub stderr: Option<Vec<u8>>,
}

/// An observer that captures stdout of a target.
impl OutputObserver {
    /// Create a new [`OutputObserver`] with the given name.
    #[must_use]
    pub fn new(name: String) -> Self {
        Self { name, stdout: None, stderr: None }
    }
}

impl<S> Observer<S> for OutputObserver
where
    S: UsesInput,
{
    #[inline]
    fn observes_stdout(&self) -> bool {
        true
    }

    #[inline]
    fn observes_stderr(&self) -> bool {
        true
    }

    /// React to new `stdout`
    fn observe_stdout(&mut self, stdout: &[u8]) {
        self.stdout = Some(stdout.into());
    }

    /// React to new `stderr`
    fn observe_stderr(&mut self, stderr: &[u8]) {
        self.stderr = Some(stderr.into());
    }
}

impl Named for OutputObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

pub trait ObserverWithOutput {
    fn stdout(&self) -> &Option<Vec<u8>>;
    fn stderr(&self) -> &Option<Vec<u8>>;
}

impl ObserverWithOutput for OutputObserver {
    fn stdout(&self) -> &Option<Vec<u8>> {
        &self.stdout
    }

    fn stderr(&self) -> &Option<Vec<u8>> {
        &self.stderr
    }
}