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
            BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator, 
            ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator, BytesDeleteMutator,
            BytesExpandMutator, BytesInsertCopyMutator, BytesInsertMutator, BytesRandInsertMutator, 
            BytesRandSetMutator, BytesSetMutator, BytesSwapMutator, CrossoverInsertMutator, 
            CrossoverReplaceMutator, DwordAddMutator, DwordInterestingMutator, QwordAddMutator,
            SpliceMutator, WordAddMutator, WordInterestingMutator    
        },
        MutationResult, 
        Mutator
    },
    prelude::{
        ARITH_MAX,
        INTERESTING_8, INTERESTING_16, INTERESTING_32
    },
    random_corpus_id,
    stages::mutational::MutatedTransform,
    state::{HasCorpus, HasMaxSize, HasRand},
    Error,
};

use crate::pub_sec_input::PubSecInput;

pub trait PubSecMutator<I, S> {
    /// Mutate a given input
    fn mutate_pub_sec(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error>;

    // /// Post-process given the outcome of the execution
    // fn post_exec(
    //     &mut self,
    //     _state: &mut S,
    //     _stage_idx: i32,
    //     _corpus_idx: Option<CorpusId>,
    // ) -> Result<(), Error> {
    //     Ok(())
    // }
}

impl<I, S> PubSecMutator<I, S> for BitFlipMutator 
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate_pub_sec(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_mutable_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let bit = 1 << state.rand_mut().choose(0..8);
            let byte = state.rand_mut().choose(input.get_mutable_current_buf_seg());
            *byte ^= bit;
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, S> PubSecMutator<I, S> for ByteFlipMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate_pub_sec(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_mutable_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            *state.rand_mut().choose(input.get_mutable_current_buf_seg()) ^= 0xff;
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, S> PubSecMutator<I, S> for ByteIncMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate_pub_sec(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_mutable_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.get_mutable_current_buf_seg());
            *byte = byte.wrapping_add(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, S> PubSecMutator<I, S> for ByteDecMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate_pub_sec(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_mutable_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.get_mutable_current_buf_seg());
            *byte = byte.wrapping_sub(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, S> PubSecMutator<I, S> for ByteNegMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate_pub_sec(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_mutable_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.get_mutable_current_buf_seg());
            *byte = (!(*byte)).wrapping_add(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, S> PubSecMutator<I, S> for ByteRandMutator
where
    S: HasRand,
    I: PubSecInput,
{
    fn mutate_pub_sec(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.get_mutable_current_buf_seg().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.get_mutable_current_buf_seg());
            *byte ^= 1 + state.rand_mut().below(254) as u8;
            Ok(MutationResult::Mutated)
        }
    }
}

// Helper macro that defines the arithmetic addition/subtraction mutations where random slices
// within the input are treated as u8, u16, u32, or u64, then mutated in place.
macro_rules! add_mutator_impl {
    ($name: ident, $size: ty) => {
        /// Adds or subtracts a random value up to `ARITH_MAX` to a [`<$size>`] at a random place in the [`Vec`], in random byte order.
        #[allow(trivial_numeric_casts)]
        impl<I, S> PubSecMutator<I, S> for $name
        where
            S: HasRand,
            I: PubSecInput,
        {
            fn mutate_pub_sec(
                &mut self,
                state: &mut S,
                input: &mut I,
                _stage_idx: i32,
            ) -> Result<MutationResult, Error> {
                if input.get_mutable_current_buf_seg().len() < size_of::<$size>() {
                    Ok(MutationResult::Skipped)
                } else {
                    // choose a random window of bytes (windows overlap) and convert to $size
                    let (index, bytes) = state
                        .rand_mut()
                        .choose(input.get_mutable_current_buf_seg().windows(size_of::<$size>()).enumerate());
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
    }
}

add_mutator_impl!(ByteAddMutator, u8);
add_mutator_impl!(WordAddMutator, u16);
add_mutator_impl!(DwordAddMutator, u32);
add_mutator_impl!(QwordAddMutator, u64);

///////////////////////////

macro_rules! interesting_mutator_impl {
    ($name: ident, $size: ty, $interesting: ident) => {
        /// Inserts an interesting value at a random place in the input vector
        impl<I, S> PubSecMutator<I, S> for $name
        where
            S: HasRand,
            I: PubSecInput,
        {
            #[allow(clippy::cast_sign_loss)]
            fn mutate_pub_sec(
                &mut self,
                state: &mut S,
                input: &mut I,
                _stage_idx: i32,
            ) -> Result<MutationResult, Error> {
                if input.get_mutable_current_buf_seg().len() < size_of::<$size>() {
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
    };
}

interesting_mutator_impl!(ByteInterestingMutator, u8, INTERESTING_8);
interesting_mutator_impl!(WordInterestingMutator, u16, INTERESTING_16);
interesting_mutator_impl!(DwordInterestingMutator, u32, INTERESTING_32);

// /// Bytes delete mutation for inputs with a bytes vector
// #[derive(Default, Debug)]
// pub struct BytesDeleteMutator;

// impl<I, S> Mutator<I, S> for BytesDeleteMutator
// where
//     S: HasRand,
//     I: HasBytesVec,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut I,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let size = input.bytes().len();
//         if size <= 2 {
//             return Ok(MutationResult::Skipped);
//         }

//         let range = rand_range(state, size, size);

//         input.bytes_mut().drain(range);

//         Ok(MutationResult::Mutated)
//     }
// }

// impl Named for BytesDeleteMutator {
//     fn name(&self) -> &str {
//         "BytesDeleteMutator"
//     }
// }

// impl BytesDeleteMutator {
//     /// Creates a new [`BytesDeleteMutator`].
//     #[must_use]
//     pub fn new() -> Self {
//         Self
//     }
// }

// /// Bytes expand mutation for inputs with a bytes vector
// #[derive(Default, Debug)]
// pub struct BytesExpandMutator;

// impl<I, S> Mutator<I, S> for BytesExpandMutator
// where
//     S: HasRand + HasMaxSize,
//     I: HasBytesVec,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut I,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let max_size = state.max_size();
//         let size = input.bytes().len();
//         if size == 0 || size >= max_size {
//             return Ok(MutationResult::Skipped);
//         }

//         let range = rand_range(state, size, min(16, max_size - size));

//         input.bytes_mut().resize(size + range.len(), 0);
//         unsafe {
//             buffer_self_copy(
//                 input.bytes_mut(),
//                 range.start,
//                 range.start + range.len(),
//                 size - range.start,
//             );
//         }

//         Ok(MutationResult::Mutated)
//     }
// }

// impl Named for BytesExpandMutator {
//     fn name(&self) -> &str {
//         "BytesExpandMutator"
//     }
// }

// impl BytesExpandMutator {
//     /// Creates a new [`BytesExpandMutator`].
//     #[must_use]
//     pub fn new() -> Self {
//         Self
//     }
// }

// /// Bytes insert mutation for inputs with a bytes vector
// #[derive(Default, Debug)]
// pub struct BytesInsertMutator;

// impl<I, S> Mutator<I, S> for BytesInsertMutator
// where
//     S: HasRand + HasMaxSize,
//     I: HasBytesVec,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut I,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let max_size = state.max_size();
//         let size = input.bytes().len();
//         if size == 0 || size >= max_size {
//             return Ok(MutationResult::Skipped);
//         }

//         let mut amount = 1 + state.rand_mut().below(16) as usize;
//         let offset = state.rand_mut().below(size as u64 + 1) as usize;

//         if size + amount > max_size {
//             if max_size > size {
//                 amount = max_size - size;
//             } else {
//                 return Ok(MutationResult::Skipped);
//             }
//         }

//         let val = input.bytes()[state.rand_mut().below(size as u64) as usize];

//         input.bytes_mut().resize(size + amount, 0);
//         unsafe {
//             buffer_self_copy(input.bytes_mut(), offset, offset + amount, size - offset);
//         }
//         buffer_set(input.bytes_mut(), offset, amount, val);

//         Ok(MutationResult::Mutated)
//     }
// }

// impl Named for BytesInsertMutator {
//     fn name(&self) -> &str {
//         "BytesInsertMutator"
//     }
// }

// impl BytesInsertMutator {
//     /// Creates a new [`BytesInsertMutator`].
//     #[must_use]
//     pub fn new() -> Self {
//         Self
//     }
// }

// /// Bytes random insert mutation for inputs with a bytes vector
// #[derive(Default, Debug)]
// pub struct BytesRandInsertMutator;

// impl<I, S> Mutator<I, S> for BytesRandInsertMutator
// where
//     S: HasRand + HasMaxSize,
//     I: HasBytesVec,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut I,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let max_size = state.max_size();
//         let size = input.bytes().len();
//         if size >= max_size {
//             return Ok(MutationResult::Skipped);
//         }

//         let mut amount = 1 + state.rand_mut().below(16) as usize;
//         let offset = state.rand_mut().below(size as u64 + 1) as usize;

//         if size + amount > max_size {
//             if max_size > size {
//                 amount = max_size - size;
//             } else {
//                 return Ok(MutationResult::Skipped);
//             }
//         }

//         let val = state.rand_mut().next() as u8;

//         input.bytes_mut().resize(size + amount, 0);
//         unsafe {
//             buffer_self_copy(input.bytes_mut(), offset, offset + amount, size - offset);
//         }
//         buffer_set(input.bytes_mut(), offset, amount, val);

//         Ok(MutationResult::Mutated)
//     }
// }

// impl Named for BytesRandInsertMutator {
//     fn name(&self) -> &str {
//         "BytesRandInsertMutator"
//     }
// }

// impl BytesRandInsertMutator {
//     /// Create a new [`BytesRandInsertMutator`]
//     #[must_use]
//     pub fn new() -> Self {
//         Self
//     }
// }

// /// Bytes set mutation for inputs with a bytes vector
// #[derive(Default, Debug)]
// pub struct BytesSetMutator;

// impl<I, S> Mutator<I, S> for BytesSetMutator
// where
//     S: HasRand,
//     I: HasBytesVec,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut I,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let size = input.bytes().len();
//         if size == 0 {
//             return Ok(MutationResult::Skipped);
//         }
//         let range = rand_range(state, size, min(size, 16));

//         let val = *state.rand_mut().choose(input.bytes());
//         let quantity = range.len();
//         buffer_set(input.bytes_mut(), range.start, quantity, val);

//         Ok(MutationResult::Mutated)
//     }
// }

// impl Named for BytesSetMutator {
//     fn name(&self) -> &str {
//         "BytesSetMutator"
//     }
// }

// impl BytesSetMutator {
//     /// Creates a new [`BytesSetMutator`].
//     #[must_use]
//     pub fn new() -> Self {
//         Self
//     }
// }

// /// Bytes random set mutation for inputs with a bytes vector
// #[derive(Default, Debug)]
// pub struct BytesRandSetMutator;

// impl<I, S> Mutator<I, S> for BytesRandSetMutator
// where
//     S: HasRand,
//     I: HasBytesVec,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut I,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let size = input.bytes().len();
//         if size == 0 {
//             return Ok(MutationResult::Skipped);
//         }
//         let range = rand_range(state, size, min(size, 16));

//         let val = state.rand_mut().next() as u8;
//         let quantity = range.len();
//         buffer_set(input.bytes_mut(), range.start, quantity, val);

//         Ok(MutationResult::Mutated)
//     }
// }

// impl Named for BytesRandSetMutator {
//     fn name(&self) -> &str {
//         "BytesRandSetMutator"
//     }
// }

// impl BytesRandSetMutator {
//     /// Creates a new [`BytesRandSetMutator`].
//     #[must_use]
//     pub fn new() -> Self {
//         Self
//     }
// }

// /// Bytes copy mutation for inputs with a bytes vector
// #[derive(Default, Debug)]
// pub struct BytesCopyMutator;

// impl<I, S> Mutator<I, S> for BytesCopyMutator
// where
//     S: HasRand,
//     I: HasBytesVec,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut I,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let size = input.bytes().len();
//         if size <= 1 {
//             return Ok(MutationResult::Skipped);
//         }

//         let target = state.rand_mut().below(size as u64) as usize;
//         let range = rand_range(state, size, size - target);

//         unsafe {
//             buffer_self_copy(input.bytes_mut(), range.start, target, range.len());
//         }

//         Ok(MutationResult::Mutated)
//     }
// }

// impl Named for BytesCopyMutator {
//     fn name(&self) -> &str {
//         "BytesCopyMutator"
//     }
// }

// impl BytesCopyMutator {
//     /// Creates a new [`BytesCopyMutator`].
//     #[must_use]
//     pub fn new() -> Self {
//         Self
//     }
// }

// /// Bytes insert and self copy mutation for inputs with a bytes vector
// #[derive(Debug, Default)]
// pub struct BytesInsertCopyMutator {
//     tmp_buf: Vec<u8>,
// }

// impl<I, S> Mutator<I, S> for BytesInsertCopyMutator
// where
//     S: HasRand + HasMaxSize,
//     I: HasBytesVec,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut I,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let size = input.bytes().len();
//         if size <= 1 || size >= state.max_size() {
//             return Ok(MutationResult::Skipped);
//         }

//         let target = state.rand_mut().below(size as u64) as usize;
//         // make sure that the sampled range is both in bounds and of an acceptable size
//         let max_insert_len = min(size - target, state.max_size() - size);
//         let range = rand_range(state, size, min(16, max_insert_len));

//         input.bytes_mut().resize(size + range.len(), 0);
//         self.tmp_buf.resize(range.len(), 0);
//         unsafe {
//             buffer_copy(
//                 &mut self.tmp_buf,
//                 input.bytes(),
//                 range.start,
//                 0,
//                 range.len(),
//             );

//             buffer_self_copy(
//                 input.bytes_mut(),
//                 target,
//                 target + range.len(),
//                 size - target,
//             );
//             buffer_copy(input.bytes_mut(), &self.tmp_buf, 0, target, range.len());
//         }
//         Ok(MutationResult::Mutated)
//     }
// }

// impl Named for BytesInsertCopyMutator {
//     fn name(&self) -> &str {
//         "BytesInsertCopyMutator"
//     }
// }

// impl BytesInsertCopyMutator {
//     /// Creates a new [`BytesInsertCopyMutator`].
//     #[must_use]
//     pub fn new() -> Self {
//         Self::default()
//     }
// }

// /// Bytes swap mutation for inputs with a bytes vector
// #[derive(Debug, Default)]
// pub struct BytesSwapMutator {
//     tmp_buf: Vec<u8>,
// }

// #[allow(clippy::too_many_lines)]
// impl<I, S> Mutator<I, S> for BytesSwapMutator
// where
//     S: HasRand,
//     I: HasBytesVec,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut I,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let size = input.bytes().len();
//         if size <= 1 {
//             return Ok(MutationResult::Skipped);
//         }

//         let first = rand_range(state, size, size);
//         if state.rand_mut().next() & 1 == 0 && first.start != 0 {
//             // The second range comes before first.

//             let second = rand_range(state, first.start, first.start);
//             self.tmp_buf.resize(first.len(), 0);
//             unsafe {
//                 // If range first is larger
//                 if first.len() >= second.len() {
//                     let diff_in_size = first.len() - second.len();

//                     // copy first range to tmp
//                     buffer_copy(
//                         &mut self.tmp_buf,
//                         input.bytes(),
//                         first.start,
//                         0,
//                         first.len(),
//                     );

//                     // adjust second.end..first.start, move them by diff_in_size to the right
//                     buffer_self_copy(
//                         input.bytes_mut(),
//                         second.end,
//                         second.end + diff_in_size,
//                         first.start - second.end,
//                     );

//                     // copy second to where first was
//                     buffer_self_copy(
//                         input.bytes_mut(),
//                         second.start,
//                         first.start + diff_in_size,
//                         second.len(),
//                     );

//                     // copy first back
//                     buffer_copy(
//                         input.bytes_mut(),
//                         &self.tmp_buf,
//                         0,
//                         second.start,
//                         first.len(),
//                     );
//                 } else {
//                     let diff_in_size = second.len() - first.len();

//                     // copy first range to tmp
//                     buffer_copy(
//                         &mut self.tmp_buf,
//                         input.bytes(),
//                         first.start,
//                         0,
//                         first.len(),
//                     );

//                     // adjust second.end..first.start, move them by diff_in_size to the left
//                     buffer_self_copy(
//                         input.bytes_mut(),
//                         second.end,
//                         second.end - diff_in_size,
//                         first.start - second.end,
//                     );

//                     // copy second to where first was
//                     buffer_self_copy(
//                         input.bytes_mut(),
//                         second.start,
//                         first.start - diff_in_size,
//                         second.len(),
//                     );

//                     // copy first back
//                     buffer_copy(
//                         input.bytes_mut(),
//                         &self.tmp_buf,
//                         0,
//                         second.start,
//                         first.len(),
//                     );
//                 }
//             }
//             Ok(MutationResult::Mutated)
//         } else if first.end != size {
//             // The first range comes before the second range
//             let mut second = rand_range(state, size - first.end, size - first.end);
//             second.start += first.end;
//             second.end += first.end;

//             self.tmp_buf.resize(second.len(), 0);
//             unsafe {
//                 if second.len() >= first.len() {
//                     let diff_in_size = second.len() - first.len();
//                     // copy second range to tmp
//                     buffer_copy(
//                         &mut self.tmp_buf,
//                         input.bytes(),
//                         second.start,
//                         0,
//                         second.len(),
//                     );

//                     // adjust first.end..second.start, move them by diff_in_size to the right
//                     buffer_self_copy(
//                         input.bytes_mut(),
//                         first.end,
//                         first.end + diff_in_size,
//                         second.start - first.end,
//                     );

//                     // copy first to where second was
//                     buffer_self_copy(
//                         input.bytes_mut(),
//                         first.start,
//                         second.start + diff_in_size,
//                         first.len(),
//                     );

//                     // copy second back
//                     buffer_copy(
//                         input.bytes_mut(),
//                         &self.tmp_buf,
//                         0,
//                         first.start,
//                         second.len(),
//                     );
//                 } else {
//                     let diff_in_size = first.len() - second.len();
//                     // copy second range to tmp
//                     buffer_copy(
//                         &mut self.tmp_buf,
//                         input.bytes(),
//                         second.start,
//                         0,
//                         second.len(),
//                     );

//                     // adjust first.end..second.start, move them by diff_in_size to the left
//                     buffer_self_copy(
//                         input.bytes_mut(),
//                         first.end,
//                         first.end - diff_in_size,
//                         second.start - first.end,
//                     );

//                     // copy first to where second was
//                     buffer_self_copy(
//                         input.bytes_mut(),
//                         first.start,
//                         second.start - diff_in_size,
//                         first.len(),
//                     );

//                     // copy second back
//                     buffer_copy(
//                         input.bytes_mut(),
//                         &self.tmp_buf,
//                         0,
//                         first.start,
//                         second.len(),
//                     );
//                 }
//             }

//             Ok(MutationResult::Mutated)
//         } else {
//             Ok(MutationResult::Skipped)
//         }
//     }
// }

// impl Named for BytesSwapMutator {
//     fn name(&self) -> &str {
//         "BytesSwapMutator"
//     }
// }

// impl BytesSwapMutator {
//     /// Creates a new [`BytesSwapMutator`].
//     #[must_use]
//     pub fn new() -> Self {
//         Self::default()
//     }
// }

// /// Crossover insert mutation for inputs with a bytes vector
// #[derive(Debug, Default)]
// pub struct CrossoverInsertMutator;

// impl<S> Mutator<S::Input, S> for CrossoverInsertMutator
// where
//     S: HasCorpus + HasRand + HasMaxSize,
//     S::Input: HasBytesVec,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut S::Input,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let size = input.bytes().len();
//         let max_size = state.max_size();
//         if size >= max_size {
//             return Ok(MutationResult::Skipped);
//         }

//         // We don't want to use the testcase we're already using for splicing
//         let idx = random_corpus_id!(state.corpus(), state.rand_mut());

//         if let Some(cur) = state.corpus().current() {
//             if idx == *cur {
//                 return Ok(MutationResult::Skipped);
//             }
//         }

//         let other_size = {
//             let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
//             other_testcase.load_input(state.corpus())?.bytes().len()
//         };

//         if other_size < 2 {
//             return Ok(MutationResult::Skipped);
//         }

//         let range = rand_range(state, other_size, min(other_size, max_size - size));
//         let target = state.rand_mut().below(size as u64) as usize;

//         input.bytes_mut().resize(size + range.len(), 0);
//         unsafe {
//             buffer_self_copy(
//                 input.bytes_mut(),
//                 target,
//                 target + range.len(),
//                 size - target,
//             );
//         }

//         let other_testcase = state.corpus().get(idx)?.borrow_mut();
//         // No need to load the input again, it'll still be cached.
//         let other = other_testcase.input().as_ref().unwrap();

//         unsafe {
//             buffer_copy(
//                 input.bytes_mut(),
//                 other.bytes(),
//                 range.start,
//                 target,
//                 range.len(),
//             );
//         }
//         Ok(MutationResult::Mutated)
//     }
// }

// impl Named for CrossoverInsertMutator {
//     fn name(&self) -> &str {
//         "CrossoverInsertMutator"
//     }
// }

// impl CrossoverInsertMutator {
//     /// Creates a new [`CrossoverInsertMutator`].
//     #[must_use]
//     pub fn new() -> Self {
//         Self
//     }
// }

// /// Crossover replace mutation for inputs with a bytes vector
// #[derive(Debug, Default)]
// pub struct CrossoverReplaceMutator;

// impl<S> Mutator<S::Input, S> for CrossoverReplaceMutator
// where
//     S: HasCorpus + HasRand,
//     S::Input: HasBytesVec,
// {
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut S::Input,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         let size = input.bytes().len();
//         if size == 0 {
//             return Ok(MutationResult::Skipped);
//         }

//         // We don't want to use the testcase we're already using for splicing
//         let idx = random_corpus_id!(state.corpus(), state.rand_mut());
//         if let Some(cur) = state.corpus().current() {
//             if idx == *cur {
//                 return Ok(MutationResult::Skipped);
//             }
//         }

//         let other_size = {
//             let mut testcase = state.corpus().get(idx)?.borrow_mut();
//             testcase.load_input(state.corpus())?.bytes().len()
//         };

//         if other_size < 2 {
//             return Ok(MutationResult::Skipped);
//         }

//         let target = state.rand_mut().below(size as u64) as usize;
//         let range = rand_range(state, other_size, min(other_size, size - target));

//         let other_testcase = state.corpus().get(idx)?.borrow_mut();
//         // No need to load the input again, it'll still be cached.
//         let other = other_testcase.input().as_ref().unwrap();

//         unsafe {
//             buffer_copy(
//                 input.bytes_mut(),
//                 other.bytes(),
//                 range.start,
//                 target,
//                 range.len(),
//             );
//         }
//         Ok(MutationResult::Mutated)
//     }
// }

// impl Named for CrossoverReplaceMutator {
//     fn name(&self) -> &str {
//         "CrossoverReplaceMutator"
//     }
// }

// impl CrossoverReplaceMutator {
//     /// Creates a new [`CrossoverReplaceMutator`].
//     #[must_use]
//     pub fn new() -> Self {
//         Self
//     }
// }

// /// Returns the first and last diff position between the given vectors, stopping at the min len
// fn locate_diffs(this: &[u8], other: &[u8]) -> (i64, i64) {
//     let mut first_diff: i64 = -1;
//     let mut last_diff: i64 = -1;
//     for (i, (this_el, other_el)) in this.iter().zip(other.iter()).enumerate() {
//         if this_el != other_el {
//             if first_diff < 0 {
//                 first_diff = i as i64;
//             }
//             last_diff = i as i64;
//         }
//     }

//     (first_diff, last_diff)
// }

// /// Splice mutation for inputs with a bytes vector
// #[derive(Debug, Default)]
// pub struct SpliceMutator;

// impl<S> Mutator<S::Input, S> for SpliceMutator
// where
//     S: HasCorpus + HasRand,
//     S::Input: HasBytesVec,
// {
//     #[allow(clippy::cast_sign_loss)]
//     fn mutate(
//         &mut self,
//         state: &mut S,
//         input: &mut S::Input,
//         _stage_idx: i32,
//     ) -> Result<MutationResult, Error> {
//         // We don't want to use the testcase we're already using for splicing
//         let idx = random_corpus_id!(state.corpus(), state.rand_mut());
//         if let Some(cur) = state.corpus().current() {
//             if idx == *cur {
//                 return Ok(MutationResult::Skipped);
//             }
//         }

//         let (first_diff, last_diff) = {
//             let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
//             let other = other_testcase.load_input(state.corpus())?;

//             let mut counter: u32 = 0;
//             loop {
//                 let (f, l) = locate_diffs(input.bytes(), other.bytes());

//                 if f != l && f >= 0 && l >= 2 {
//                     break (f as u64, l as u64);
//                 }
//                 if counter == 3 {
//                     return Ok(MutationResult::Skipped);
//                 }
//                 counter += 1;
//             }
//         };

//         let split_at = state.rand_mut().between(first_diff, last_diff) as usize;

//         let other_testcase = state.corpus().get(idx)?.borrow_mut();
//         // Input will already be loaded.
//         let other = other_testcase.input().as_ref().unwrap();

//         input
//             .bytes_mut()
//             .splice(split_at.., other.bytes()[split_at..].iter().copied());

//         Ok(MutationResult::Mutated)
//     }
// }

// impl Named for SpliceMutator {
//     fn name(&self) -> &str {
//         "SpliceMutator"
//     }
// }

// impl SpliceMutator {
//     /// Creates a new [`SpliceMutator`].
//     #[must_use]
//     pub fn new() -> Self {
//         Self
//     }
// }

// // Converts a hex u8 to its u8 value: 'A' -> 10 etc.
// fn from_hex(hex: u8) -> Result<u8, Error> {
//     match hex {
//         48..=57 => Ok(hex - 48),
//         65..=70 => Ok(hex - 55),
//         97..=102 => Ok(hex - 87),
//         _ => Err(Error::illegal_argument("Invalid hex character".to_owned())),
//     }
// }

// /// Decodes a dictionary token: 'foo\x41\\and\"bar' -> 'fooA\and"bar'
// pub fn str_decode(item: &str) -> Result<Vec<u8>, Error> {
//     let mut token: Vec<u8> = Vec::new();
//     let item: Vec<u8> = item.as_bytes().to_vec();
//     let backslash: u8 = 92; // '\\'
//     let mut take_next: bool = false;
//     let mut take_next_two: u32 = 0;
//     let mut decoded: u8 = 0;

//     for c in item {
//         if take_next_two == 1 {
//             decoded = from_hex(c)? << 4;
//             take_next_two = 2;
//         } else if take_next_two == 2 {
//             decoded += from_hex(c)?;
//             token.push(decoded);
//             take_next_two = 0;
//         } else if c != backslash || take_next {
//             if take_next && (c == 120 || c == 88) {
//                 take_next_two = 1;
//             } else {
//                 token.push(c);
//             }
//             take_next = false;
//         } else {
//             take_next = true;
//         }
//     }

//     Ok(token)
// }