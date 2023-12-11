extern crate alloc;
use alloc::{borrow::ToOwned, rc::Rc, string::String, vec::Vec};
use core::{
    cell::RefCell,
    convert::{From, AsRef},
    hash::{BuildHasher, Hasher},
    ops::Range,
};
use std::{collections::hash_map::DefaultHasher, hash::Hash};
#[cfg(feature = "std")]
use std::{fs::File, io::Read, path::Path};

use ahash::RandomState;
use serde::{Deserialize, Serialize};
use serde_json::{
    Map,
    Value,
    Value::Object
};
use base64::{Engine, engine::general_purpose};

#[cfg(feature = "std")]
use libafl_bolts::{fs::write_file_atomic, Error};
use libafl_bolts::{ownedref::OwnedSlice, HasLen};
use libafl::inputs::{HasTargetBytes, Input};

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum MutateTarget {
    PublicExplicitInput,
    SecretExplicitInput,
    SecretStackMemory,
    SecretHeapMemory,
    All,
}

#[derive(Clone, Copy, PartialEq)]
pub enum InputContentsFlags {
    PublicExplicitInput = 0b1000_0000,
    SecretExplicitInput = 0b0100_0000,
    SecretStackMemory   = 0b0010_0000,
    SecretHeapMemory    = 0b0001_0000,
}


pub fn swap_bytes_in_ranges(buf: &mut Vec<u8>, range_1: Range<usize>, range_2: Range<usize>) {
    if (range_2.start >= range_1.start && range_2.start < range_1.end) ||
        (range_2.end > range_1.start && range_2.end < range_1.end) ||
        (range_1.start >= range_2.start && range_1.start < range_2.end) ||
        (range_1.end > range_2.start && range_1.end < range_2.end) {
            panic!("overlapping ranges {:?}, {:?}", range_1, range_2);
        }

    let (mut first, mut second) = if range_1.start < range_2.start {
        (range_1, range_2)
    } else {
        (range_2, range_1)
    };

    let mut temp = Vec::new();
    temp.resize(buf.len(), 0);
    temp[0..first.start].copy_from_slice(&buf[0..first.start]);

    let mut start_pos = first.start;
    let mut end_pos = first.start + second.len();
    temp[start_pos..end_pos].copy_from_slice(&buf[second.clone()]);

    start_pos = end_pos;
    end_pos = start_pos + second.start - first.end;
    temp[start_pos..end_pos].copy_from_slice(&buf[first.end..second.start]);

    start_pos = end_pos;
    end_pos = start_pos + first.len();
    temp[start_pos..end_pos].copy_from_slice(&buf[first.clone()]);

    start_pos = end_pos;
    temp[start_pos..buf.len()].copy_from_slice(&buf[second.end..]);

    buf.clear();
    buf.append(&mut temp);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubSecBytesInput {
    raw_bytes: Vec<u8>,
    explicit_public_len: Option<usize>,
    explicit_secret_len: Option<usize>,
    stack_mem_secret_len: Option<usize>,
    heap_mem_secret_len: Option<usize>,
    current_mutate_target: MutateTarget,
}

pub trait PubSecInput: Input + HasTargetBytes {
    fn from_bufs(
        explicit_public: Option<&[u8]>,
        explicit_secret: Option<&[u8]>,
        stack_mem_secret: Option<&[u8]>,
        heap_mem_secret: Option<&[u8]>
    ) -> Self;
    // fn from_pub_sec_bytes(public: &[u8], secret: &[u8]) -> Self;

    fn get_part_bytes(&self, part: InputContentsFlags) -> Option<&[u8]>;
    fn set_part_bytes(&mut self, part: InputContentsFlags, new_buf: &[u8]);

    // fn get_public_part_bytes(&self) -> Option<&[u8]>;
    // fn get_secret_part_bytes(&self) -> &[u8];
    // fn set_secret_part_bytes(&mut self, new_buf: &[u8]);

    fn get_public_input_hash(&self) -> u64;
    fn get_secret_input_hash(&self) -> u64;

    fn get_current_mutate_target(&self) -> MutateTarget;
    fn set_current_mutate_target(&mut self, new_target: MutateTarget);

    // fn get_current_bytesinput(&self) -> BytesInput;
    fn update_current_buf_seg_from_bytes(&mut self, mutated_input: &[u8]);

    fn get_current_buf_seg(&self) -> &[u8];
    // fn get_mutable_current_buf_seg(&mut self) -> &mut [u8];

    fn get_total_len(&self) -> usize;
    fn get_raw_bytes(&self) -> &[u8];
}

impl PubSecInput for PubSecBytesInput {
    fn from_bufs(
        explicit_public: Option<&[u8]>,
        explicit_secret: Option<&[u8]>,
        stack_mem_secret: Option<&[u8]>,
        heap_mem_secret: Option<&[u8]>
    ) -> Self {
        let mut flags_byte = 0u8;
        let mut raw_bytes = vec![];
        macro_rules! append_to_raw {
            ($buf:ident, $flag:expr) => {
                if let Some($buf) = $buf {
                    flags_byte |= $flag as u8;
                    raw_bytes.append(&mut ($buf.len() as u32).to_ne_bytes().to_vec());
                    raw_bytes.append(&mut $buf.to_vec());
                }
            };
        }

        append_to_raw!(explicit_public, InputContentsFlags::PublicExplicitInput);
        append_to_raw!(explicit_secret, InputContentsFlags::SecretExplicitInput);
        append_to_raw!(stack_mem_secret, InputContentsFlags::SecretStackMemory);
        append_to_raw!(heap_mem_secret, InputContentsFlags::SecretHeapMemory);
        raw_bytes.insert(0, flags_byte);

        let maybe_len = |buf: Option<&[u8]>| {
            if let Some(buf) = buf { Some(buf.len()) } else { None }
        };

        Self {
            raw_bytes,
            explicit_public_len: maybe_len(explicit_public),
            explicit_secret_len: maybe_len(explicit_secret),
            stack_mem_secret_len: maybe_len(stack_mem_secret),
            heap_mem_secret_len: maybe_len(heap_mem_secret),
            current_mutate_target: MutateTarget::All,
        }
    }

    // fn get_public_part_bytes(&self) -> &[u8] {
    //     assert!(u32::from_ne_bytes(self.raw_bytes[0..4].try_into().unwrap()) == self.explicit_public_len as u32);
    //     let len_indicator = std::mem::size_of::<u32>();
    //     let end = len_indicator + self.explicit_public_len;
    //     &self.raw_bytes[len_indicator..end]
    // }

    // fn get_secret_part_bytes(&self) -> &[u8] {
    //     assert!(u32::from_ne_bytes(self.raw_bytes[0..4].try_into().unwrap()) == self.explicit_public_len as u32);
    //     let len_indicator = std::mem::size_of::<u32>();
    //     let start = len_indicator + self.explicit_public_len;
    //     &self.raw_bytes[start..]
    // }

    // fn set_secret_part_bytes(&mut self, new_buf: &[u8]) {
    //     assert!(u32::from_ne_bytes(self.raw_bytes[0..4].try_into().unwrap()) == self.explicit_public_len as u32);
    //     assert!(self.raw_bytes.len() == 4 + self.explicit_public_len + self.explicit_secret_len);
    //     let len_indicator = std::mem::size_of::<u32>();
    //     let start = len_indicator + self.explicit_public_len;
    //     self.raw_bytes.drain(start..);
    //     self.explicit_secret_len = new_buf.len();
    //     assert!(u32::from_ne_bytes(self.raw_bytes[0..4].try_into().unwrap()) == self.explicit_public_len as u32);
    //     assert!(self.raw_bytes.len() == 4 + self.explicit_public_len + self.explicit_secret_len);
    // }

    fn get_part_bytes(&self, part: InputContentsFlags) -> Option<&[u8]> {
        if let Some(len) = match part {
            InputContentsFlags::PublicExplicitInput => self.explicit_public_len,
            InputContentsFlags::SecretExplicitInput => self.explicit_secret_len,
            InputContentsFlags::SecretStackMemory => self.stack_mem_secret_len,
            InputContentsFlags::SecretHeapMemory => self.heap_mem_secret_len,
        } {
            let start_offset = self.get_start_offset_for_part(part);
            let end = start_offset + len;
            Some(&self.raw_bytes[start_offset..end])
        } else {
            None
        }
    }

    fn set_part_bytes(&mut self, part: InputContentsFlags, new_buf: &[u8]) {
        let mut header_len_pos = 1;
        if part != InputContentsFlags::PublicExplicitInput {
            if self.explicit_public_len.is_some() { header_len_pos += 4; }
            if part != InputContentsFlags::SecretExplicitInput {
                if self.explicit_secret_len.is_some() { header_len_pos += 4; }
                if part != InputContentsFlags::SecretStackMemory {
                    if self.stack_mem_secret_len.is_some() { header_len_pos += 4; }
                    if part != InputContentsFlags::SecretHeapMemory {
                        panic!("Unhandled");
                    }
                }
            }
        }

        let len_array = (new_buf.len() as u32).to_ne_bytes().to_vec();
        self.raw_bytes[header_len_pos..(header_len_pos + 4)].copy_from_slice(&len_array);

        let start_offset = self.get_start_offset_for_part(part);
        let mut new_raw = Vec::from_iter(self.raw_bytes[0..start_offset].iter().copied());
        new_raw.append(&mut new_buf.to_vec());

        let end_offset = start_offset + match part {
            InputContentsFlags::PublicExplicitInput => self.explicit_public_len.unwrap(),
            InputContentsFlags::SecretExplicitInput => self.explicit_secret_len.unwrap(),
            InputContentsFlags::SecretStackMemory => self.stack_mem_secret_len.unwrap(),
            InputContentsFlags::SecretHeapMemory => self.heap_mem_secret_len.unwrap(),
        };
        new_raw.append(&mut self.raw_bytes[end_offset..].to_vec());
        
        self.raw_bytes = new_raw;
        match part {
            InputContentsFlags::PublicExplicitInput => self.explicit_public_len = Some(new_buf.len()),
            InputContentsFlags::SecretExplicitInput => self.explicit_secret_len = Some(new_buf.len()),
            InputContentsFlags::SecretStackMemory => self.stack_mem_secret_len = Some(new_buf.len()),
            InputContentsFlags::SecretHeapMemory => self.heap_mem_secret_len = Some(new_buf.len()),
        };

        let expected_len = 1 + 
            if let Some(len) = self.explicit_public_len { 4 + len } else { 0 } +
            if let Some(len) = self.explicit_secret_len { 4 + len } else { 0 } +
            if let Some(len) = self.stack_mem_secret_len { 4 + len } else { 0 } +
            if let Some(len) = self.heap_mem_secret_len { 4 + len } else { 0 };

        if self.raw_bytes.len() != expected_len {
            panic!("expected len: {expected_len}, but actual len was: {} in {:?}", self.raw_bytes.len(), self.raw_bytes);
        }
    }

    fn get_public_input_hash(&self) -> u64 {
        if self.explicit_public_len.is_none() { return 0; }

        let mut hasher = DefaultHasher::new();
        self.get_part_bytes(InputContentsFlags::PublicExplicitInput).unwrap().hash(&mut hasher);
        hasher.finish()
    }

    fn get_secret_input_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        if self.explicit_secret_len.is_some() {
            self.get_part_bytes(InputContentsFlags::SecretExplicitInput).unwrap().hash(&mut hasher);
        }
        if self.stack_mem_secret_len.is_some() {
            self.get_part_bytes(InputContentsFlags::SecretStackMemory).unwrap().hash(&mut hasher);
        }
        if self.heap_mem_secret_len.is_some() {
            self.get_part_bytes(InputContentsFlags::SecretHeapMemory).unwrap().hash(&mut hasher);
        }
        hasher.finish()
    }

    fn get_current_mutate_target(&self) -> MutateTarget {
        self.current_mutate_target
    }

    fn set_current_mutate_target(&mut self, new_target: MutateTarget) {
        self.current_mutate_target = new_target;
    }

    // fn get_current_bytesinput(&self) -> BytesInput {
    //     BytesInput::new(
    //         match self.current_mutate_target {
    //             MutateTarget::PublicExplicitInput => self.get_public_part_bytes().to_vec(),
    //             MutateTarget::SecretExplicitInput => self.get_secret_part_bytes().to_vec(),
    //             MutateTarget::All => self.raw_bytes[std::mem::size_of::<u32>()..].to_vec(),
    //             _ => panic!("PubSecInput does not implement {:?}", self.current_mutate_target)
    //         }
    //     )
    // }

    fn update_current_buf_seg_from_bytes(&mut self, mutated_input: &[u8]) {
        match self.current_mutate_target {
            MutateTarget::PublicExplicitInput => 
                self.set_part_bytes(InputContentsFlags::PublicExplicitInput, mutated_input),
            MutateTarget::SecretExplicitInput =>
                self.set_part_bytes(InputContentsFlags::SecretExplicitInput, mutated_input),
            MutateTarget::SecretStackMemory =>
                self.set_part_bytes(InputContentsFlags::SecretStackMemory, mutated_input),
            MutateTarget::SecretHeapMemory =>
                self.set_part_bytes(InputContentsFlags::SecretHeapMemory, mutated_input),
            MutateTarget::All => {
                let body_len = 
                    if let Some(len) = self.explicit_public_len { len } else { 0 } +
                    if let Some(len) = self.explicit_secret_len { len } else { 0 } +
                    if let Some(len) = self.stack_mem_secret_len { len } else { 0 } +
                    if let Some(len) = self.heap_mem_secret_len { len } else { 0 };
                if mutated_input.len() != body_len {
                    panic!("Expected len: {body_len}, but was actually {}", mutated_input.len());
                }

                let header_len = 1 +
                    if let Some(len) = self.explicit_public_len { 4 } else { 0 } +
                    if let Some(len) = self.explicit_secret_len { 4 } else { 0 } +
                    if let Some(len) = self.stack_mem_secret_len { 4 } else { 0 } +
                    if let Some(len) = self.heap_mem_secret_len { 4 } else { 0 };

                self.raw_bytes[header_len..].copy_from_slice(mutated_input); 
            }
        };

        self.check_len();
    }

    fn get_current_buf_seg(&self) -> &[u8] {
        let range = match self.current_mutate_target {
            MutateTarget::PublicExplicitInput => 
                self.get_start_offset_for_part(
                    InputContentsFlags::PublicExplicitInput
                )..self.explicit_public_len.unwrap(),
            MutateTarget::SecretExplicitInput => 
                self.get_start_offset_for_part(
                    InputContentsFlags::SecretExplicitInput
                )..self.explicit_secret_len.unwrap(),
            MutateTarget::SecretStackMemory =>
                self.get_start_offset_for_part(
                    InputContentsFlags::SecretStackMemory
                )..self.stack_mem_secret_len.unwrap(),
            MutateTarget::SecretHeapMemory =>
                self.get_start_offset_for_part(
                    InputContentsFlags::SecretHeapMemory
                )..self.heap_mem_secret_len.unwrap(),
            MutateTarget::All => {
                let start_offset = if self.explicit_public_len.is_some() {
                    self.get_start_offset_for_part(InputContentsFlags::PublicExplicitInput)
                } else if self.explicit_secret_len.is_some() {
                    self.get_start_offset_for_part(InputContentsFlags::SecretExplicitInput)
                } else if self.stack_mem_secret_len.is_some() {
                    self.get_start_offset_for_part(InputContentsFlags::SecretStackMemory)
                } else if self.heap_mem_secret_len.is_some() {
                    self.get_start_offset_for_part(InputContentsFlags::SecretHeapMemory)
                } else {
                    panic!()
                };

                start_offset..self.raw_bytes.len()
            }
        };

        &self.raw_bytes[range]
    }

    fn get_total_len(&self) -> usize {
        self.raw_bytes.len() - std::mem::size_of::<u32>()
    }

    fn get_raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }
}

impl Input for PubSecBytesInput {
    #[cfg(feature = "std")]
    /// Write this input to the file
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let mut json = "{{\n".to_string();
        macro_rules! try_encode_and_append {
            ($len: expr, $flag: expr, $field: literal) => {
                if $len.is_some() {
                    let b64 = general_purpose::STANDARD.encode(self.get_part_bytes($flag).unwrap());
                    json.push_str(format!(concat!("  \"", $field, "\": \"{}\",\n"), b64).as_str());
                }
            };
        }

        try_encode_and_append!(self.explicit_public_len, InputContentsFlags::PublicExplicitInput, "EXPLICIT_PUBLIC");
        try_encode_and_append!(self.explicit_secret_len, InputContentsFlags::SecretExplicitInput, "EXPLICIT_SECRET");
        try_encode_and_append!(self.stack_mem_secret_len, InputContentsFlags::SecretStackMemory, "STACK_MEM_SECRET");
        try_encode_and_append!(self.heap_mem_secret_len, InputContentsFlags::SecretHeapMemory, "HEAP_MEM_SECRET");

        write_file_atomic(path, &json.as_bytes())
    }

    /// Load the content of this input from a file
    #[cfg(feature = "std")]
    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        // panic!("Haven't implemented this yet");
        let mut file = File::open(path)?;
        let mut bytes: Vec<u8> = vec![];
        file.read_to_end(&mut bytes)?;

        let str = std::str::from_utf8(&bytes).unwrap();
        let obj = serde_json::from_str(str)?;

        match obj {
            Object(map) => {
                let parse_field = |map: &Map<String, Value>, key| {
                    let val = map.get(key).expect(&format!("missing \"{}\" field", key));
                    match val {
                        Value::String(string) => Ok(string.to_owned()),
                        _ => Err(format!("{} was not a string (was {:?})", key, val))
                    }
                };
                macro_rules! parse {
                    ($field: literal) => {
                        if let Ok(buf) = parse_field(&map, $field) {
                            Some(&general_purpose::STANDARD.decode(buf).unwrap())
                        } else {
                            None
                        }
                    };
                }

                Ok(PubSecBytesInput::from_bufs(
                    parse!("EXPLICIT_PUBLIC"),
                    parse!("EXPLICIT_SECRET"),
                    parse!("STACK_MEM_SECRET"),
                    parse!("HEAP_MEM_SECRET")
                ))
            },
            _ => panic!("is not a JSON object!")
        }
    }

    /// Generate a name for this input
    fn generate_name(&self, _idx: usize) -> String {
        let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
        hasher.write(&self.raw_bytes);
        format!("{:016x}", hasher.finish())
    }
}

/// Rc Ref-cell from Input
impl From<PubSecBytesInput> for Rc<RefCell<PubSecBytesInput>> {
    fn from(input: PubSecBytesInput) -> Self {
        Rc::new(RefCell::new(input))
    }
}

// impl HasBytesVec for PubSecBytesInput {
//     #[inline]
//     fn bytes(&self) -> &[u8] {
//         &self.raw_bytes
//     }

//     /// this is only used for mutations, if this changes we need to be more careful here...
//     #[inline]
//     fn bytes_mut(&mut self) -> &mut Vec<u8> {
//         &mut self.raw_bytes
//     }
// }

impl HasTargetBytes for PubSecBytesInput {
    /// Note that this is what gets passed to the SUT, so format needs to be SUT readable
    #[inline]
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(&self.raw_bytes)
    }
}

impl HasLen for PubSecBytesInput {
    #[inline]
    fn len(&self) -> usize {
        self.raw_bytes.len()
    }
}

// impl From<Vec<u8>> for PubSecBytesInput {
//     fn from(bytes: Vec<u8>) -> Self {
//         Self::new(bytes)
//     }
// }

// impl From<&[u8]> for PubSecBytesInput {
//     fn from(bytes: &[u8]) -> Self {
//         Self::new(bytes.to_owned())
//     }
// }

// impl From<PubSecBytesInput> for Vec<u8> {
//     fn from(value: PubSecBytesInput) -> Vec<u8> {
//         value.bytes
//     }
// }

impl PubSecBytesInput {
    // /// Creates a new bytes input using the given bytes
    // #[must_use]
    // pub fn new(public_bytes: Vec<u8>, secret_bytes: Vec<u8>) -> Self {
    //     Self { 
    //         raw_bytes: Self::new_from_raw_bytes(&public_bytes, &secret_bytes), 
    //         explicit_public_len: public_bytes.len(), 
    //         explicit_secret_len: secret_bytes.len(),
    //         current_mutate_target: MutateTarget::AllExplicitInputs,
    //         stack_mem_secret_len: None,
    //         heap_mem_secret_len: None,
    //     }
    // }

    // pub fn new_from_raw_bytes(public_bytes: &[u8], secret_bytes: &[u8]) -> Vec<u8> {
    //     let mut comb = Vec::new();
    //     comb.append(&mut (public_bytes.len() as u32).to_ne_bytes().to_vec());
    //     comb.append(&mut public_bytes.to_owned());
    //     comb.append(&mut secret_bytes.to_owned());
    //     comb
    // }

    // fn set_public_len(&mut self, new_len: usize) {
    //     let offset = std::mem::size_of::<u32>();

    //     self.explicit_public_len = new_len;
    //     let len_array = (self.explicit_public_len as u32).to_ne_bytes().to_vec(); 
    //     self.raw_bytes[0..offset].copy_from_slice(&len_array);
    //     self.explicit_secret_len = self.raw_bytes.len() - self.explicit_public_len - offset;
    // }

    fn get_start_offset_for_part(&self, part: InputContentsFlags) -> usize {
        let mut offset = 1 +
            if self.explicit_public_len.is_some() { 4 } else { 0 } +
            if self.explicit_secret_len.is_some() { 4 } else { 0 } +
            if self.stack_mem_secret_len.is_some() { 4 } else { 0 } +
            if self.heap_mem_secret_len.is_some() { 4 } else { 0 };

        if part == InputContentsFlags::PublicExplicitInput {
            assert!(self.explicit_public_len.is_some());
            return offset;
        } else if let Some(len) = self.explicit_public_len {
            offset += len;
        }

        if part == InputContentsFlags::SecretExplicitInput {
            assert!(self.explicit_secret_len.is_some());
            return offset;
        } else if let Some(len) = self.explicit_secret_len {
            offset += len;
        }

        if part == InputContentsFlags::SecretStackMemory {
            assert!(self.stack_mem_secret_len.is_some());
            return offset;
        } else if let Some(len) = self.stack_mem_secret_len {
            offset += len;
        }

        if part == InputContentsFlags::SecretHeapMemory {
            assert!(self.heap_mem_secret_len.is_some());
            return offset;
        }

        panic!("this is unexpected...");
    }

    fn set_explicit_public_len(&mut self, new_len: usize) {
        assert!(self.explicit_public_len.is_some());

        self.explicit_public_len = Some(new_len);
        let len_array = (new_len as u32).to_ne_bytes().to_vec();
        self.raw_bytes[1..5].copy_from_slice(&len_array);
    }

    fn set_explicit_secret_len(&mut self, new_len: usize) {
        assert!(self.explicit_secret_len.is_some());

        self.explicit_secret_len = Some(new_len);
        let len_array = (new_len as u32).to_ne_bytes().to_vec();
        let start_offset = if self.explicit_public_len.is_some() { 1 + 4 } else { 1 };
        self.raw_bytes[start_offset..(start_offset + 4)].copy_from_slice(&len_array);
    }

    fn set_stack_mem_secret_len(&mut self, new_len: usize) {
        assert!(self.stack_mem_secret_len.is_some());

        self.stack_mem_secret_len = Some(new_len);
        let len_array = (new_len as u32).to_ne_bytes().to_vec();
        let start_offset = 1 +
            if self.explicit_public_len.is_some() { 4 } else { 0 } +
            if self.explicit_secret_len.is_some() { 4 } else { 0 };
        self.raw_bytes[start_offset..(start_offset + 4)].copy_from_slice(&len_array);
    }

    fn set_heap_mem_secret_len(&mut self, new_len: usize) {
        assert!(self.heap_mem_secret_len.is_some());

        self.heap_mem_secret_len = Some(new_len);
        let len_array = (new_len as u32).to_ne_bytes().to_vec();
        let start_offset = 1 +
            if self.explicit_public_len.is_some() { 4 } else { 0 } +
            if self.explicit_secret_len.is_some() { 4 } else { 0 } +
            if self.stack_mem_secret_len.is_some() { 4 } else { 0 };
        self.raw_bytes[start_offset..(start_offset + 4)].copy_from_slice(&len_array);
    }

    fn check_len(&self) {
        let total_len = 1 + 
            if let Some(len) = self.explicit_public_len { 4 + len } else { 0 } +
            if let Some(len) = self.explicit_secret_len { 4 + len } else { 0 } +
            if let Some(len) = self.stack_mem_secret_len { 4 + len } else { 0 } +
            if let Some(len) = self.heap_mem_secret_len { 4 + len } else { 0 };

        if total_len != self.raw_bytes.len() {
            panic!("Expected total len of {total_len} (made up of {{ pub: {:?}, sec_exp: {:?}, stack: {:?}, heap: {:?} }}), got {} ({:?})",
                self.explicit_public_len, self.explicit_secret_len, self.stack_mem_secret_len, self.heap_mem_secret_len, 
                self.raw_bytes.len(), self.raw_bytes);
        }
    }
}
