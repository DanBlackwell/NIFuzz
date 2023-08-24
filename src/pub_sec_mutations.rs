//! A wide variety of mutations used during fuzzing.

extern crate alloc;
use alloc::{borrow::ToOwned, vec::Vec};
use core::{cmp::min, mem::size_of, ops::Range};

use libafl::{
    bolts::{rands::Rand, tuples::Named},
    corpus::{Corpus, CorpusId},
    inputs::HasBytesVec,
    mutators::{
        mutations::{
            rand_range,
            buffer_set
        },
        MutationResult, 
        Mutator
    },
    prelude::{
        ARITH_MAX,
        INTERESTING_8, INTERESTING_16, INTERESTING_32,
        tuple_list, tuple_list_type, BytesInput,
    },
    random_corpus_id,
    stages::mutational::MutatedTransform,
    state::{HasCorpus, HasMaxSize, HasRand},
    Error,
};

use crate::pub_sec_input::{PubSecInput, CurrentMutateTarget};

/// Bitflip mutation for inputs with a bytes vector
#[derive(Default, Debug, Clone)]
pub struct SecretUniformMutator;

impl<I, S> Mutator<I, S> for SecretUniformMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        input.set_current_mutate_target(CurrentMutateTarget::Secret);

        match input.get_current_mutate_target() {
            CurrentMutateTarget::Secret => (),
            _ => panic!("Should have current mutate target set to secret")
        };

        let sample = state.rand_mut().next();
        input.set_secret_part_bytes(&sample.to_ne_bytes());
        println!("set value {sample}, buf now: {:?}", input.get_current_buf_seg());
        Ok(MutationResult::Mutated)
    }
}

impl Named for SecretUniformMutator {
    fn name(&self) -> &str {
        "SecretUniformMutator"
    }
}

impl SecretUniformMutator {
    /// Creates a new [`SecretUniformMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}


/// Tuple type of the mutations that compose the Havoc mutator
pub type PubSecMutationsType = tuple_list_type!(
    PubSecBitFlipMutator,
    PubSecByteFlipMutator,
    PubSecByteIncMutator,
    PubSecByteDecMutator,
    PubSecByteNegMutator,
    PubSecByteRandMutator,
    PubSecByteAddMutator,
    PubSecWordAddMutator,
    PubSecDwordAddMutator,
    PubSecQwordAddMutator,
    PubSecByteInterestingMutator,
    PubSecWordInterestingMutator,
    PubSecDwordInterestingMutator,
    PubSecBytesDeleteMutator,
    PubSecBytesDeleteMutator,
    PubSecBytesDeleteMutator,
    PubSecBytesDeleteMutator,
    PubSecBytesExpandMutator,
    PubSecBytesInsertMutator,
    PubSecBytesRandInsertMutator,
    PubSecBytesSetMutator,
    PubSecBytesRandSetMutator,
    PubSecBytesCopyMutator,
    PubSecBytesInsertCopyMutator,
    PubSecBytesSwapMutator,
    PubSecCrossoverInsertMutator,
    PubSecCrossoverReplaceMutator,
    PubSecSpliceMutator,
);

/// Get the mutations that compose the Havoc mutator
#[must_use]
pub fn pub_sec_mutations() -> PubSecMutationsType {
    tuple_list!(
        PubSecBitFlipMutator::new(),
        PubSecByteFlipMutator::new(),
        PubSecByteIncMutator::new(),
        PubSecByteDecMutator::new(),
        PubSecByteNegMutator::new(),
        PubSecByteRandMutator::new(),
        PubSecByteAddMutator::new(),
        PubSecWordAddMutator::new(),
        PubSecDwordAddMutator::new(),
        PubSecQwordAddMutator::new(),
        PubSecByteInterestingMutator::new(),
        PubSecWordInterestingMutator::new(),
        PubSecDwordInterestingMutator::new(),
        PubSecBytesDeleteMutator::new(),
        PubSecBytesDeleteMutator::new(),
        PubSecBytesDeleteMutator::new(),
        PubSecBytesDeleteMutator::new(),
        PubSecBytesExpandMutator::new(),
        PubSecBytesInsertMutator::new(),
        PubSecBytesRandInsertMutator::new(),
        PubSecBytesSetMutator::new(),
        PubSecBytesRandSetMutator::new(),
        PubSecBytesCopyMutator::new(),
        PubSecBytesInsertCopyMutator::new(),
        PubSecBytesSwapMutator::new(),
        PubSecCrossoverInsertMutator::new(),
        PubSecCrossoverReplaceMutator::new(),
        PubSecSpliceMutator::new(),
    )
}

/// Mem move in the own vec
#[inline]
unsafe fn buffer_self_copy<T>(data: &mut [T], from: usize, to: usize, len: usize) {
    debug_assert!(!data.is_empty());
    debug_assert!(from + len <= data.len());
    debug_assert!(to + len <= data.len());
    if len != 0 && from != to {
        let ptr = data.as_mut_ptr();
        unsafe {
            core::ptr::copy(ptr.add(from), ptr.add(to), len);
        }
    }
}


/// Bitflip mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecBitFlipMutator;

impl<I, S> Mutator<I, S> for PubSecBitFlipMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let bit = 1 << state.rand_mut().choose(0..8);
            let byte = state.rand_mut().choose(input.get_mutable_current_buf_seg());
            *byte ^= bit;
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for PubSecBitFlipMutator {
    fn name(&self) -> &str {
        "PubSecBitFlipMutator"
    }
}

impl PubSecBitFlipMutator {
    /// Creates a new [`PubSecBitFlipMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}


/// Byteflip mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecByteFlipMutator;

impl<I, S> Mutator<I, S> for PubSecByteFlipMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            *state.rand_mut().choose(input.get_mutable_current_buf_seg()) ^= 0xff;
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for PubSecByteFlipMutator {
    fn name(&self) -> &str {
        "PubSecByteFlipMutator"
    }
}

impl PubSecByteFlipMutator {
    /// Creates a new [`PubSecByteFlipMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Byte increment mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecByteIncMutator;

impl<I, S> Mutator<I, S> for PubSecByteIncMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.get_mutable_current_buf_seg());
            *byte = byte.wrapping_add(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for PubSecByteIncMutator {
    fn name(&self) -> &str {
        "PubSecByteIncMutator"
    }
}

impl PubSecByteIncMutator {
    /// Creates a new [`PubSecByteIncMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Byte decrement mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecByteDecMutator;

impl<I, S> Mutator<I, S> for PubSecByteDecMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.get_mutable_current_buf_seg());
            *byte = byte.wrapping_sub(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for PubSecByteDecMutator {
    fn name(&self) -> &str {
        "PubSecByteDecMutator"
    }
}

impl PubSecByteDecMutator {
    /// Creates a a new [`PubSecByteDecMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Byte negate mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecByteNegMutator;

impl<I, S> Mutator<I, S> for PubSecByteNegMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.get_mutable_current_buf_seg());
            *byte = (!(*byte)).wrapping_add(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for PubSecByteNegMutator {
    fn name(&self) -> &str {
        "PubSecByteNegMutator"
    }
}

impl PubSecByteNegMutator {
    /// Creates a new [`PubSecByteNegMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Byte random mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecByteRandMutator;

impl<I, S> Mutator<I, S> for PubSecByteRandMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.get_mutable_current_buf_seg());
            *byte ^= 1 + state.rand_mut().below(254) as u8;
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for PubSecByteRandMutator {
    fn name(&self) -> &str {
        "PubSecByteRandMutator"
    }
}

impl PubSecByteRandMutator {
    /// Creates a new [`PubSecByteRandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

// Helper macro that defines the arithmetic addition/subtraction mutations where random slices
// within the input are treated as u8, u16, u32, or u64, then mutated in place.
macro_rules! add_mutator_impl {
    ($name: ident, $size: ty) => {
        /// Adds or subtracts a random value up to `ARITH_MAX` to a [`<$size>`] at a random place in the [`Vec`], in random byte order.
        #[derive(Default, Debug)]
        pub struct $name;

        #[allow(trivial_numeric_casts)]
        impl<I, S> Mutator<I, S> for $name
        where
            S: HasRand,
            I: PubSecInput,
        {
            fn mutate(
                &mut self,
                state: &mut S,
                input: &mut I,
                _stage_idx: i32,
            ) -> Result<MutationResult, Error> {
                if input.get_current_buf_seg().len() < size_of::<$size>() {
                    Ok(MutationResult::Skipped)
                } else {
                    // choose a random window of bytes (windows overlap) and convert to $size
                    let (index, bytes) = state
                        .rand_mut()
                        .choose(input.get_current_buf_seg().windows(size_of::<$size>()).enumerate());
                    let val = <$size>::from_ne_bytes(bytes.try_into().unwrap());

                    // mutate
                    let num = 1 + state.rand_mut().below(ARITH_MAX) as $size;
                    let new_val = match state.rand_mut().below(4) {
                        0 => val.wrapping_add(num),
                        1 => val.wrapping_sub(num),
                        2 => val.swap_bytes().wrapping_add(num).swap_bytes(),
                        _ => val.swap_bytes().wrapping_sub(num).swap_bytes(),
                    };

                    // set bytes to mutated value
                    let new_bytes = &mut input.get_mutable_current_buf_seg()[index..index + size_of::<$size>()];
                    new_bytes.copy_from_slice(&new_val.to_ne_bytes());
                    Ok(MutationResult::Mutated)
                }
            }
        }

        impl Named for $name {
            fn name(&self) -> &str {
                stringify!($name)
            }
        }

        impl $name {
            /// Creates a new [`$name`].
            #[must_use]
            pub fn new() -> Self {
                Self
            }
        }
    };
}

add_mutator_impl!(PubSecByteAddMutator, u8);
add_mutator_impl!(PubSecWordAddMutator, u16);
add_mutator_impl!(PubSecDwordAddMutator, u32);
add_mutator_impl!(PubSecQwordAddMutator, u64);

///////////////////////////

macro_rules! interesting_mutator_impl {
    ($name: ident, $size: ty, $interesting: ident) => {
        /// Inserts an interesting value at a random place in the input vector
        #[derive(Default, Debug)]
        pub struct $name;

        impl<I, S> Mutator<I, S> for $name
        where
            S: HasRand,
            I: PubSecInput,
        {
            #[allow(clippy::cast_sign_loss)]
            fn mutate(
                &mut self,
                state: &mut S,
                input: &mut I,
                _stage_idx: i32,
            ) -> Result<MutationResult, Error> {
                if input.get_current_buf_seg().len() < size_of::<$size>() {
                    Ok(MutationResult::Skipped)
                } else {
                    let bytes = input.get_mutable_current_buf_seg();
                    let upper_bound = (bytes.len() + 1 - size_of::<$size>()) as u64;
                    let idx = state.rand_mut().below(upper_bound) as usize;
                    let val = *state.rand_mut().choose(&$interesting) as $size;
                    let new_bytes = match state.rand_mut().choose(&[0, 1]) {
                        0 => val.to_be_bytes(),
                        _ => val.to_le_bytes(),
                    };
                    bytes[idx..idx + size_of::<$size>()].copy_from_slice(&new_bytes);
                    Ok(MutationResult::Mutated)
                }
            }
        }

        impl Named for $name {
            fn name(&self) -> &str {
                stringify!($name)
            }
        }

        impl $name {
            /// Creates a new [`$name`].
            #[must_use]
            pub fn new() -> Self {
                Self
            }
        }
    };
}

interesting_mutator_impl!(PubSecByteInterestingMutator, u8, INTERESTING_8);
interesting_mutator_impl!(PubSecWordInterestingMutator, u16, INTERESTING_16);
interesting_mutator_impl!(PubSecDwordInterestingMutator, u32, INTERESTING_32);

/// Bytes delete mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecBytesDeleteMutator;

impl<I, S> Mutator<I, S> for PubSecBytesDeleteMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.get_current_buf_seg().len();
        if size <= 2 {
            return Ok(MutationResult::Skipped);
        }

        let range = rand_range(state, size, size);

        input.remove_bytes_in_range(range);

        Ok(MutationResult::Mutated)
    }
}

impl Named for PubSecBytesDeleteMutator {
    fn name(&self) -> &str {
        "PubSecBytesDeleteMutator"
    }
}

impl PubSecBytesDeleteMutator {
    /// Creates a new [`PubSecBytesDeleteMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes expand mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecBytesExpandMutator;

impl<I, S> Mutator<I, S> for PubSecBytesExpandMutator
where
    S: HasRand + HasMaxSize,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let size = input.get_current_buf_seg().len();
        // Divide max len by 2 for now so that public + secret don't add up to over that
        if size == 0 || input.get_total_len() >= max_size {
            return Ok(MutationResult::Skipped);
        }

        let range = rand_range(state, size, min(16, max_size - size));
        let to_copy = input.get_mutable_current_buf_seg()[range.start..range.end].to_owned();
        input.insert_bytes_at_pos(&to_copy, range.start);

        Ok(MutationResult::Mutated)
    }
}

impl Named for PubSecBytesExpandMutator {
    fn name(&self) -> &str {
        "PubSecBytesExpandMutator"
    }
}

impl PubSecBytesExpandMutator {
    /// Creates a new [`PubSecBytesExpandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes insert mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecBytesInsertMutator;

impl<I, S> Mutator<I, S> for PubSecBytesInsertMutator
where
    S: HasRand + HasMaxSize,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let size = input.get_current_buf_seg().len();
        if size == 0 || input.get_total_len() >= max_size {
            return Ok(MutationResult::Skipped);
        }

        let mut amount = 1 + state.rand_mut().below(16) as usize;
        let offset = state.rand_mut().below(size as u64 + 1) as usize;

        if input.get_total_len() + amount > max_size {
            if max_size > input.get_total_len() {
                amount = max_size - input.get_total_len();
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        let val = input.get_mutable_current_buf_seg()[state.rand_mut().below(size as u64) as usize];
        let buf = vec![val; amount];
        input.insert_bytes_at_pos(&buf, offset);

        Ok(MutationResult::Mutated)
    }
}

impl Named for PubSecBytesInsertMutator {
    fn name(&self) -> &str {
        "PubSecBytesInsertMutator"
    }
}

impl PubSecBytesInsertMutator {
    /// Creates a new [`PubSecBytesInsertMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes random insert mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecBytesRandInsertMutator;

impl<I, S> Mutator<I, S> for PubSecBytesRandInsertMutator
where
    S: HasRand + HasMaxSize,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let size = input.get_current_buf_seg().len();
        if input.get_total_len() >= max_size {
            return Ok(MutationResult::Skipped);
        }

        let mut amount = 1 + state.rand_mut().below(16) as usize;
        let offset = state.rand_mut().below(size as u64 + 1) as usize;

        if input.get_total_len() + amount > max_size {
            if max_size > input.get_total_len() {
                amount = max_size - input.get_total_len();
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        let val = state.rand_mut().next() as u8;
        let buf = vec![val; amount];

        input.insert_bytes_at_pos(&buf, offset);

        Ok(MutationResult::Mutated)
    }
}

impl Named for PubSecBytesRandInsertMutator {
    fn name(&self) -> &str {
        "PubSecBytesRandInsertMutator"
    }
}

impl PubSecBytesRandInsertMutator {
    /// Create a new [`PubSecBytesRandInsertMutator`]
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes set mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecBytesSetMutator;

impl<I, S> Mutator<I, S> for PubSecBytesSetMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.get_current_buf_seg().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }
        let range = rand_range(state, size, min(size, 16));

        let val = *state.rand_mut().choose(input.get_current_buf_seg());
        let quantity = range.len();
        buffer_set(input.get_mutable_current_buf_seg(), range.start, quantity, val);

        Ok(MutationResult::Mutated)
    }
}

impl Named for PubSecBytesSetMutator {
    fn name(&self) -> &str {
        "PubSecBytesSetMutator"
    }
}

impl PubSecBytesSetMutator {
    /// Creates a new [`PubSecBytesSetMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes random set mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecBytesRandSetMutator;

impl<I, S> Mutator<I, S> for PubSecBytesRandSetMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.get_current_buf_seg().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }
        let range = rand_range(state, size, min(size, 16));

        let val = state.rand_mut().next() as u8;
        let quantity = range.len();
        buffer_set(input.get_mutable_current_buf_seg(), range.start, quantity, val);

        Ok(MutationResult::Mutated)
    }
}

impl Named for PubSecBytesRandSetMutator {
    fn name(&self) -> &str {
        "PubSecBytesRandSetMutator"
    }
}

impl PubSecBytesRandSetMutator {
    /// Creates a new [`PubSecBytesRandSetMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes copy mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct PubSecBytesCopyMutator;

impl<I, S> Mutator<I, S> for PubSecBytesCopyMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.get_current_buf_seg().len();
        if size <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let target = state.rand_mut().below(size as u64) as usize;
        let range = rand_range(state, size, size - target);

        unsafe {
            buffer_self_copy(input.get_mutable_current_buf_seg(), range.start, target, range.len());
        }

        Ok(MutationResult::Mutated)
    }
}

impl Named for PubSecBytesCopyMutator {
    fn name(&self) -> &str {
        "PubSecBytesCopyMutator"
    }
}

impl PubSecBytesCopyMutator {
    /// Creates a new [`PubSecBytesCopyMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes insert and self copy mutation for inputs with a bytes vector
#[derive(Debug, Default)]
pub struct PubSecBytesInsertCopyMutator {
    tmp_buf: Vec<u8>,
}

impl<I, S> Mutator<I, S> for PubSecBytesInsertCopyMutator
where
    S: HasRand + HasMaxSize,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.get_current_buf_seg().len();
        if size <= 1 || input.get_total_len() >= state.max_size() {
            return Ok(MutationResult::Skipped);
        }

        let target = state.rand_mut().below(size as u64) as usize;
        // make sure that the sampled range is both in bounds and of an acceptable size
        let max_insert_len = min(size - target, state.max_size() - size);
        let range = rand_range(state, size, min(16, max_insert_len));

        self.tmp_buf = input.get_current_buf_seg()[range].to_vec();
        input.insert_bytes_at_pos(&self.tmp_buf, target);

        Ok(MutationResult::Mutated)
    }
}

impl Named for PubSecBytesInsertCopyMutator {
    fn name(&self) -> &str {
        "PubSecBytesInsertCopyMutator"
    }
}

impl PubSecBytesInsertCopyMutator {
    /// Creates a new [`PubSecBytesInsertCopyMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Bytes swap mutation for inputs with a bytes vector
#[derive(Debug, Default)]
pub struct PubSecBytesSwapMutator {}

#[allow(clippy::too_many_lines)]
impl<I, S> Mutator<I, S> for PubSecBytesSwapMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.get_current_buf_seg().len();
        if size <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let first = rand_range(state, size, size);
        if state.rand_mut().next() & 1 == 0 && first.start != 0 {
            // The second range comes before first.
            let second = rand_range(state, first.start, first.start);
            input.swap_bytes_in_ranges(first, second);
            
            Ok(MutationResult::Mutated)
        } else if first.end != size {
            // The first range comes before the second range
            let mut second = rand_range(state, size - first.end, size - first.end);
            second.start += first.end;
            second.end += first.end;
            input.swap_bytes_in_ranges(first, second);

            Ok(MutationResult::Mutated)
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

impl Named for PubSecBytesSwapMutator {
    fn name(&self) -> &str {
        "PubSecBytesSwapMutator"
    }
}

impl PubSecBytesSwapMutator {
    /// Creates a new [`PubSecBytesSwapMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Crossover insert mutation for inputs with a bytes vector
#[derive(Debug, Default)]
pub struct PubSecCrossoverInsertMutator;

impl<S> Mutator<S::Input, S> for PubSecCrossoverInsertMutator
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.get_current_buf_seg().len();
        let max_size = state.max_size();
        if input.get_total_len() >= max_size {
            return Ok(MutationResult::Skipped);
        }

        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());

        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_size = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            other_testcase.load_input(state.corpus())?;
            let mut alt_input = other_testcase.input_mut().as_mut().unwrap();
            alt_input.set_current_mutate_target(input.get_current_mutate_target());
            alt_input.get_current_buf_seg().len()
        };

        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let range = rand_range(state, other_size, min(other_size, max_size - size));
        let target = state.rand_mut().below(size as u64) as usize;

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        // No need to load the input again, it'll still be cached.
        let other = other_testcase.input_mut().as_ref().unwrap();
        let other_bytes = &other.get_current_buf_seg()[range];

        input.insert_bytes_at_pos(&other_bytes, target);

        Ok(MutationResult::Mutated)
    }
}

impl Named for PubSecCrossoverInsertMutator {
    fn name(&self) -> &str {
        "PubSecCrossoverInsertMutator"
    }
}

impl PubSecCrossoverInsertMutator {
    /// Creates a new [`PubSecCrossoverInsertMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Crossover replace mutation for inputs with a bytes vector
#[derive(Debug, Default)]
pub struct PubSecCrossoverReplaceMutator;

impl<S> Mutator<S::Input, S> for PubSecCrossoverReplaceMutator
where
    S: HasCorpus + HasRand,
    S::Input: PubSecInput,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.get_current_buf_seg().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }

        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_size = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            other_testcase.load_input(state.corpus())?;
            let mut alt_input = other_testcase.input_mut().as_mut().unwrap();
            alt_input.set_current_mutate_target(input.get_current_mutate_target());
            alt_input.get_current_buf_seg().len()
        };

        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let target = state.rand_mut().below(size as u64) as usize;
        let range = rand_range(state, other_size, min(other_size, size - target));

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        // No need to load the input again, it'll still be cached.
        let other = other_testcase.input_mut().as_ref().unwrap();
        let other_bytes = &other.get_current_buf_seg()[range];

        input.get_mutable_current_buf_seg()[target..(target + other_bytes.len())]
            .copy_from_slice(&other_bytes);

        Ok(MutationResult::Mutated)
    }
}

impl Named for PubSecCrossoverReplaceMutator {
    fn name(&self) -> &str {
        "PubSecCrossoverReplaceMutator"
    }
}

impl PubSecCrossoverReplaceMutator {
    /// Creates a new [`PubSecCrossoverReplaceMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Returns the first and last diff position between the given vectors, stopping at the min len
fn locate_diffs(this: &[u8], other: &[u8]) -> (i64, i64) {
    let mut first_diff: i64 = -1;
    let mut last_diff: i64 = -1;
    for (i, (this_el, other_el)) in this.iter().zip(other.iter()).enumerate() {
        if this_el != other_el {
            if first_diff < 0 {
                first_diff = i as i64;
            }
            last_diff = i as i64;
        }
    }

    (first_diff, last_diff)
}

/// Splice mutation for inputs with a bytes vector
#[derive(Debug, Default)]
pub struct PubSecSpliceMutator;

impl<S> Mutator<S::Input, S> for PubSecSpliceMutator
where
    S: HasCorpus + HasRand,
    S::Input: PubSecInput,
{
    #[allow(clippy::cast_sign_loss)]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let (first_diff, last_diff) = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            let other = other_testcase.load_input(state.corpus())?;

            let mut counter: u32 = 0;
            loop {
                let (f, l) = locate_diffs(input.get_current_buf_seg(), other.get_current_buf_seg());

                if f != l && f >= 0 && l >= 2 {
                    break (f as u64, l as u64);
                }
                if counter == 3 {
                    return Ok(MutationResult::Skipped);
                }
                counter += 1;
            }
        };

        let split_at = state.rand_mut().between(first_diff, last_diff) as usize;

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        // No need to load the input again, it'll still be cached.
        let other = other_testcase.input_mut().as_ref().unwrap();
        let other_bytes = &other.get_current_buf_seg()[split_at..];

        let split_end = if split_at + other_bytes.len() > input.get_current_buf_seg().len() {
            input.get_current_buf_seg().len()
        } else {
            split_at + other_bytes.len()
        };

        input.remove_bytes_in_range(split_at..split_end);
        input.insert_bytes_at_pos(other_bytes, split_at);

        Ok(MutationResult::Mutated)
    }
}

impl Named for PubSecSpliceMutator {
    fn name(&self) -> &str {
        "PubSecSpliceMutator"
    }
}

impl PubSecSpliceMutator {
    /// Creates a new [`PubSecSpliceMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}