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
    Value::{Object}
};
use base64::{Engine, engine::general_purpose};

#[cfg(feature = "std")]
use libafl::{bolts::fs::write_file_atomic, Error};
use libafl::{
    bolts::{ownedref::OwnedSlice, HasLen},
    inputs::{BytesInput, HasBytesVec, HasTargetBytes, Input},
};

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
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

pub trait PubSecInput { // : HasBytesVec {
    fn from_pub_sec_bytes(public: &[u8], secret: &[u8]) -> Self;

    fn get_public_part_bytes(&self) -> &[u8];
    fn get_secret_part_bytes(&self) -> &[u8];

    fn get_current_mutate_target(&self) -> CurrentMutateTarget;
    fn set_current_mutate_target(&mut self, new_target: CurrentMutateTarget);

    fn get_current_bytesinput(&self) -> BytesInput;
    fn update_current_from_bytesinput(&mut self, mutated_input: &BytesInput);

    fn get_current_buf_seg(&self) -> &[u8];
    fn get_mutable_current_buf_seg(&mut self) -> &mut [u8];

    fn remove_bytes_in_range(&mut self, range: Range<usize>);
    fn insert_bytes_at_pos(&mut self, bytes: &[u8], start_pos: usize);
}

impl PubSecInput for PubSecBytesInput {
    fn from_pub_sec_bytes(public: &[u8], secret: &[u8]) -> Self {
        Self::new(public.to_owned(), secret.to_owned())
    }

    fn get_public_part_bytes(&self) -> &[u8] {
        let len_indicator = std::mem::size_of::<u32>();
        let end = len_indicator + self.public_len;
        &self.raw_bytes[len_indicator..end]
    }

    fn get_secret_part_bytes(&self) -> &[u8] {
        let len_indicator = std::mem::size_of::<u32>();
        let start = len_indicator + self.public_len;
        &self.raw_bytes[start..]
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

    fn update_current_from_bytesinput(&mut self, mutated_input: &BytesInput) {
        match self.current_mutate_target {
            CurrentMutateTarget::Public => {
                if self.public_len == mutated_input.bytes().len() {
                    let len_indicator = std::mem::size_of::<u32>();
                    let end = len_indicator + self.public_len;
                    for idx in len_indicator..end {
                        self.raw_bytes[idx] = mutated_input.bytes()[idx - len_indicator];
                    }
                } else {
                    self.raw_bytes = Self::new_raw_bytes(mutated_input.bytes(), self.get_secret_part_bytes());
                }
            },
            CurrentMutateTarget::Secret => {
                if self.secret_len == mutated_input.bytes().len() {
                    let len_indicator = std::mem::size_of::<u32>();
                    let start = len_indicator + self.public_len;
                    for idx in start..self.raw_bytes.len() {
                        self.raw_bytes[idx] = mutated_input.bytes()[idx - start];
                    }
                } else {
                    self.raw_bytes = Self::new_raw_bytes(self.get_public_part_bytes(), mutated_input.bytes());
                }
            },
            CurrentMutateTarget::All => { 
                if self.secret_len + self.public_len != mutated_input.bytes().len() {
                    panic!();
                } else {
                    let len_indicator = std::mem::size_of::<u32>();
                    for idx in len_indicator..self.raw_bytes.len() {
                        self.raw_bytes[idx] = mutated_input.bytes()[idx - len_indicator];
                    }
                }
            }
        }
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

        let len_indicator = std::mem::size_of::<u32>();
        match self.current_mutate_target {
            CurrentMutateTarget::Public => {
                let adjusted = (range.start + len_indicator)..(range.end + len_indicator);
                self.raw_bytes.drain(adjusted);
                self.public_len -= range.end - range.start;
            },
            CurrentMutateTarget::Secret => {
                let offset = len_indicator + self.public_len;
                let adjusted = (range.start + offset)..(range.end + offset);
                self.raw_bytes.drain(adjusted);
            },
            CurrentMutateTarget::All => {
                if range.start < self.public_len {
                    if range.end > self.public_len {
                        // println!("removing range {:?}, lens before: public {}, total {}; after: public {}",
                        //     range, self.public_len, self.raw_bytes.len() - 4, range.start);
                        self.public_len = range.start;
                    } else {
                        self.public_len -= range.end - range.start;
                    }
                }

                let adjusted = (range.start + len_indicator)..(range.end + len_indicator);
                self.raw_bytes.drain(adjusted);
            }
        }    

        let len_array = (self.public_len as u32).to_ne_bytes().to_vec(); 
        self.raw_bytes[0..len_indicator].copy_from_slice(&len_array);
    }

    fn insert_bytes_at_pos(&mut self, bytes: &[u8], start_pos: usize) {
        if bytes.is_empty() { return; }

        let len_indicator = std::mem::size_of::<u32>();
        let adjusted_start = start_pos + len_indicator;
        let adjusted_end = adjusted_start + bytes.len();
        let old_len = self.raw_bytes.len();

        match self.current_mutate_target {
            CurrentMutateTarget::Public => {
                self.public_len += bytes.len();

                self.raw_bytes.resize(self.raw_bytes.len() + bytes.len(), 0);

                self.raw_bytes.copy_within(adjusted_start..old_len, adjusted_start + bytes.len());
                self.raw_bytes[adjusted_start..adjusted_end].copy_from_slice(bytes);
            },
            CurrentMutateTarget::Secret => {
                self.raw_bytes.resize(self.raw_bytes.len() + bytes.len(), 0);

                self.raw_bytes.copy_within(adjusted_start..old_len, adjusted_start + bytes.len());
                self.raw_bytes[adjusted_start..adjusted_end].copy_from_slice(bytes);
            },
            CurrentMutateTarget::All => {
                if adjusted_start < len_indicator + self.public_len {
                    self.public_len += bytes.len();
                }

                self.raw_bytes.resize(self.raw_bytes.len() + bytes.len(), 0);
                self.raw_bytes.copy_within(adjusted_start..old_len, adjusted_start + bytes.len());
                self.raw_bytes[adjusted_start..adjusted_end].copy_from_slice(bytes);
            }
        }    

        let len_array = (self.public_len as u32).to_ne_bytes().to_vec(); 
        self.raw_bytes[0..len_indicator].copy_from_slice(&len_array);
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

        println!("pub: {:?}, sec: {:?}", public, secret);
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
}
