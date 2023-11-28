extern crate alloc;
use alloc::{borrow::ToOwned, rc::Rc, string::String, vec::Vec};
use core::{
    cell::RefCell,
    convert::{From, AsRef},
    hash::{BuildHasher, Hasher},
    ops::Range,
};
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
use libafl::inputs::{BytesInput, HasTargetBytes, Input};

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum CurrentMutateTarget {
    Public,
    Secret,
    All
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubSecBytesInput {
    raw_bytes: Vec<u8>,
    public_len: usize,
    secret_len: usize,
    current_mutate_target: CurrentMutateTarget
}

pub trait PubSecInput: HasTargetBytes { // : HasBytesVec {
    fn from_pub_sec_bytes(public: &[u8], secret: &[u8]) -> Self;

    fn get_public_part_bytes(&self) -> &[u8];
    fn get_secret_part_bytes(&self) -> &[u8];
    fn set_secret_part_bytes(&mut self, new_buf: &[u8]);

    fn get_current_mutate_target(&self) -> CurrentMutateTarget;
    fn set_current_mutate_target(&mut self, new_target: CurrentMutateTarget);

    fn get_current_bytesinput(&self) -> BytesInput;
    fn update_current_from_bytes(&mut self, mutated_input: &[u8]);

    fn get_current_buf_seg(&self) -> &[u8];
    fn get_mutable_current_buf_seg(&mut self) -> &mut [u8];

    fn remove_bytes_in_range(&mut self, range: Range<usize>);
    fn insert_bytes_at_pos(&mut self, bytes: &[u8], start_pos: usize);
    fn swap_bytes_in_ranges(&mut self, range_1: Range<usize>, range_2: Range<usize>);

    fn get_total_len(&self) -> usize;
    fn get_raw_bytes(&self) -> &[u8];
}

impl PubSecInput for PubSecBytesInput {
    fn from_pub_sec_bytes(public: &[u8], secret: &[u8]) -> Self {
        Self::new(public.to_owned(), secret.to_owned())
    }

    fn get_public_part_bytes(&self) -> &[u8] {
        debug_assert!(u32::from_ne_bytes(self.raw_bytes[0..4].try_into().unwrap()) == self.public_len as u32);
        let len_indicator = std::mem::size_of::<u32>();
        let end = len_indicator + self.public_len;
        &self.raw_bytes[len_indicator..end]
    }

    fn get_secret_part_bytes(&self) -> &[u8] {
        let len_indicator = std::mem::size_of::<u32>();
        let start = len_indicator + self.public_len;
        &self.raw_bytes[start..]
    }

    fn set_secret_part_bytes(&mut self, new_buf: &[u8]) {
        assert!(u32::from_ne_bytes(self.raw_bytes[0..4].try_into().unwrap()) == self.public_len as u32);
        assert!(self.raw_bytes.len() == 4 + self.public_len + self.secret_len);
        let len_indicator = std::mem::size_of::<u32>();
        let start = len_indicator + self.public_len;
        self.raw_bytes.drain(start..);
        self.raw_bytes.append(&mut new_buf.to_owned());
        self.secret_len = new_buf.len();
        assert!(u32::from_ne_bytes(self.raw_bytes[0..4].try_into().unwrap()) == self.public_len as u32);
        assert!(self.raw_bytes.len() == 4 + self.public_len + self.secret_len);
    }

    fn get_current_mutate_target(&self) -> CurrentMutateTarget {
        self.current_mutate_target
    }

    fn set_current_mutate_target(&mut self, new_target: CurrentMutateTarget) {
        self.current_mutate_target = new_target;
    }

    fn get_current_bytesinput(&self) -> BytesInput {
        BytesInput::new(
            match self.current_mutate_target {
                CurrentMutateTarget::Public => self.get_public_part_bytes().to_vec(),
                CurrentMutateTarget::Secret => self.get_secret_part_bytes().to_vec(),
                CurrentMutateTarget::All => self.raw_bytes[std::mem::size_of::<u32>()..].to_vec()
            }
        )
    }

    fn update_current_from_bytes(&mut self, mutated_input: &[u8]) {
        debug_assert!(self.raw_bytes.len() == 4 + self.public_len + self.secret_len);
        match self.current_mutate_target {
            CurrentMutateTarget::Public => {
                if self.public_len == mutated_input.len() {
                    let len_indicator = std::mem::size_of::<u32>();
                    let end = len_indicator + self.public_len;
                    for idx in len_indicator..end {
                        self.raw_bytes[idx] = mutated_input[idx - len_indicator];
                    }
                } else {
                    self.raw_bytes = Self::new_raw_bytes(mutated_input, self.get_secret_part_bytes());
                    self.set_public_len(mutated_input.len());
                }
            },
            CurrentMutateTarget::Secret => {
                if self.secret_len == mutated_input.len() {
                    let len_indicator = std::mem::size_of::<u32>();
                    let start = len_indicator + self.public_len;
                    for idx in start..self.raw_bytes.len() {
                        if self.raw_bytes.len() == 0 { panic!(); }
                        if mutated_input.len() == 0 { panic!("raw_bytes: {:?}, pub_len: {}, sec_len: {}, mutated: {:?}", self.raw_bytes, self.public_len, self.secret_len, mutated_input); }
                        if idx - start >= mutated_input.len() { panic!("raw_bytes: {:?}, pub_len: {}, sec_len: {}, mutated: {:?}", self.raw_bytes, self.public_len, self.secret_len, mutated_input); }
                        self.raw_bytes[idx] = mutated_input[idx - start];
                    }
                } else {
                    self.raw_bytes = Self::new_raw_bytes(self.get_public_part_bytes(), mutated_input);
                    self.secret_len = mutated_input.len();
                }
            },
            CurrentMutateTarget::All => { 
                if self.secret_len + self.public_len != mutated_input.len() {
                    panic!();
                } else {
                    let len_indicator = std::mem::size_of::<u32>();
                    for idx in len_indicator..self.raw_bytes.len() {
                        self.raw_bytes[idx] = mutated_input[idx - len_indicator];
                    }
                }
            }
        }
        debug_assert!(self.raw_bytes.len() == 4 + self.public_len + self.secret_len);
    }

    fn get_current_buf_seg(&self) -> &[u8] {
        let len_indicator = std::mem::size_of::<u32>();
        let public_end = len_indicator + self.public_len;
        match self.current_mutate_target {
            CurrentMutateTarget::Public => &self.raw_bytes[len_indicator..public_end],
            CurrentMutateTarget::Secret => &self.raw_bytes[public_end..],
            CurrentMutateTarget::All => &self.raw_bytes[len_indicator..]
        }
    }

    fn get_mutable_current_buf_seg(&mut self) -> &mut [u8] {
        debug_assert!(u32::from_ne_bytes(self.raw_bytes[0..4].try_into().unwrap()) == self.public_len as u32);
        let len_indicator = std::mem::size_of::<u32>();
        let public_end = len_indicator + self.public_len;
        match self.current_mutate_target {
            CurrentMutateTarget::Public => &mut self.raw_bytes[len_indicator..public_end],
            CurrentMutateTarget::Secret => &mut self.raw_bytes[public_end..],
            CurrentMutateTarget::All => &mut self.raw_bytes[len_indicator..]
        }
    }

    fn remove_bytes_in_range(&mut self, range: Range<usize>) {
        if range.is_empty() { return; }
        debug_assert!(self.raw_bytes.len() == 4 + self.public_len + self.secret_len);

        let len_indicator = std::mem::size_of::<u32>();
        match self.current_mutate_target {
            CurrentMutateTarget::Public => {
                let adjusted = (range.start + len_indicator)..(range.end + len_indicator);
                self.raw_bytes.drain(adjusted);
                self.set_public_len(self.public_len - range.end + range.start);
            },
            CurrentMutateTarget::Secret => {
                let offset = len_indicator + self.public_len;
                let adjusted = (range.start + offset)..(range.end + offset);
                self.raw_bytes.drain(adjusted);
                self.secret_len = self.raw_bytes.len() - offset;
            },
            CurrentMutateTarget::All => {
                let adjusted = (range.start + len_indicator)..(range.end + len_indicator);
                self.raw_bytes.drain(adjusted);

                if range.start < self.public_len {
                    if range.end > self.public_len {
                        // println!("removing range {:?}, lens before: public {}, total {}; after: public {}",
                        //     range, self.public_len, self.raw_bytes.len() - 4, range.start);
                        self.set_public_len(range.start);
                    } else {
                        self.set_public_len(self.public_len - range.end + range.start);
                    }
                }
            }
        }    
        debug_assert!(self.raw_bytes.len() == 4 + self.public_len + self.secret_len);
    }

    fn insert_bytes_at_pos(&mut self, bytes: &[u8], start_pos: usize) {
        if bytes.is_empty() { return; }
        debug_assert!(self.raw_bytes.len() == 4 + self.public_len + self.secret_len);

        let len_indicator = std::mem::size_of::<u32>();
        let adjusted_start = start_pos + len_indicator;
        let adjusted_end = adjusted_start + bytes.len();
        let old_len = self.raw_bytes.len();

        match self.current_mutate_target {
            CurrentMutateTarget::Public => {
                self.raw_bytes.resize(self.raw_bytes.len() + bytes.len(), 0);

                self.raw_bytes.copy_within(adjusted_start..old_len, adjusted_start + bytes.len());
                self.raw_bytes[adjusted_start..adjusted_end].copy_from_slice(bytes);

                self.set_public_len(self.public_len + bytes.len());
            },
            CurrentMutateTarget::Secret => {
                self.raw_bytes.resize(self.raw_bytes.len() + bytes.len(), 0);

                self.raw_bytes.copy_within(adjusted_start..old_len, adjusted_start + bytes.len());
                self.raw_bytes[adjusted_start..adjusted_end].copy_from_slice(bytes);
                self.secret_len = self.raw_bytes.len() - len_indicator - self.public_len;
            },
            CurrentMutateTarget::All => {
                self.raw_bytes.resize(self.raw_bytes.len() + bytes.len(), 0);
                self.raw_bytes.copy_within(adjusted_start..old_len, adjusted_start + bytes.len());
                self.raw_bytes[adjusted_start..adjusted_end].copy_from_slice(bytes);

                if adjusted_start < len_indicator + self.public_len {
                    self.set_public_len(self.public_len + bytes.len());
                }
            }
        }    
        debug_assert!(self.raw_bytes.len() == 4 + self.public_len + self.secret_len);
    }

    fn swap_bytes_in_ranges(&mut self, range_1: Range<usize>, range_2: Range<usize>) {
        debug_assert!(self.raw_bytes.len() == 4 + self.public_len + self.secret_len);

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

        let offset = std::mem::size_of::<u32>() + match self.current_mutate_target {
            CurrentMutateTarget::Secret => self.public_len,
            _ => 0
        };

        first = (first.start + offset)..(first.end + offset);
        second = (second.start + offset)..(second.end + offset);

        // println!("Swapping ranges {:?} and {:?} ({:?} and {:?} in \n{:?}", first, second, &self.raw_bytes[first.clone()], &self.raw_bytes[second.clone()], self.raw_bytes);

        let mut temp = Vec::new();
        temp.resize(self.raw_bytes.len(), 0);
        temp[0..first.start].copy_from_slice(&self.raw_bytes[0..first.start]);

        let mut start_pos = first.start;
        let mut end_pos = first.start + second.len();
        temp[start_pos..end_pos].copy_from_slice(&self.raw_bytes[second.clone()]);

        start_pos = end_pos;
        end_pos = start_pos + second.start - first.end;
        temp[start_pos..end_pos].copy_from_slice(&self.raw_bytes[first.end..second.start]);

        start_pos = end_pos;
        end_pos = start_pos + first.len();
        temp[start_pos..end_pos].copy_from_slice(&self.raw_bytes[first.clone()]);

        start_pos = end_pos;
        temp[start_pos..self.raw_bytes.len()].copy_from_slice(&self.raw_bytes[second.end..]);

        self.raw_bytes = temp;

        match self.current_mutate_target {
            CurrentMutateTarget::All => if first.end <= self.public_len + offset && second.start >= self.public_len + offset {
                self.set_public_len(self.public_len + second.len() - first.len());
            },
            _ => ()
        };

        debug_assert!(self.raw_bytes.len() == 4 + self.public_len + self.secret_len);
        // println!("After swap:\n{:?}\npub: {}, sec: {}", temp, self.public_len, self.secret_len);
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
        let pub_b64 = general_purpose::STANDARD.encode(self.get_public_part_bytes());
        let sec_b64 = general_purpose::STANDARD.encode(self.get_secret_part_bytes());

        let json = format!("{{ \"PUBLIC\": \"{pub_b64}\", \"SECRET\": \"{sec_b64}\" }}");

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

        let (public, secret) = match obj {
            Object(map) => {
                let parse_field = |map: &Map<String, Value>, key| {
                    let val = map.get(key).expect(&format!("missing \"{}\" field", key));
                    match val {
                        Value::String(string) => Ok(string.to_owned()),
                        _ => Err(format!("{} was not a string (was {:?})", key, val))
                    }
                };
                let public = parse_field(&map, "PUBLIC").unwrap();
                let secret = parse_field(&map, "SECRET").unwrap();
                
                let public_decoded = general_purpose::STANDARD.decode(public).unwrap();
                let secret_decoded = general_purpose::STANDARD.decode(secret).unwrap();
                (public_decoded, secret_decoded)
            },
            _ => panic!("is not a JSON object!")
        };

        Ok(PubSecBytesInput::from_pub_sec_bytes(&public, &secret))
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
    /// Creates a new bytes input using the given bytes
    #[must_use]
    pub fn new(public_bytes: Vec<u8>, secret_bytes: Vec<u8>) -> Self {
        Self { 
            raw_bytes: Self::new_raw_bytes(&public_bytes, &secret_bytes), 
            public_len: public_bytes.len(), 
            secret_len: secret_bytes.len(),
            current_mutate_target: CurrentMutateTarget::All
        }
    }

    pub fn new_raw_bytes(public_bytes: &[u8], secret_bytes: &[u8]) -> Vec<u8> {
        let mut comb = Vec::new();
        comb.append(&mut (public_bytes.len() as u32).to_ne_bytes().to_vec());
        comb.append(&mut public_bytes.to_owned());
        comb.append(&mut secret_bytes.to_owned());
        comb
    }

    fn set_public_len(&mut self, new_len: usize) {
        let offset = std::mem::size_of::<u32>();

        self.public_len = new_len;
        let len_array = (self.public_len as u32).to_ne_bytes().to_vec(); 
        self.raw_bytes[0..offset].copy_from_slice(&len_array);
        self.secret_len = self.raw_bytes.len() - self.public_len - offset;
    }
}
