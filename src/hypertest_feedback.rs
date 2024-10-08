use hashbrown::{HashMap, HashSet};
use core::marker::PhantomData;
use std::{hash::{Hash, Hasher}, collections::hash_map::DefaultHasher};
use libafl_bolts::{ErrorBacktrace, Error};
use libafl::prelude::Input;
use crate::{output_feedback::{OutputData, OutputSource}, leak_fuzzer_state::ViolationsTargetingApproach, pub_sec_input::InputContentsFlags};
use crate::pub_sec_input::PubSecInput;
use crate::OutputObserver;
use crate::output_observer::ObserverWithOutput;

/// State for the current fuzzing campaign with associated functions
pub struct InfoLeakChecker<I> {
    /// dictionary mapping public_in hashes to IOHashValues (including secret_in and public_out)
    pub dict: HashMap<u64, IOHashValue>,    
    /// previous secret_in vec, for debug
    pub prev_sec_in: Vec<u8>,
    /// previous public_in vec, for debug
    pub prev_pub_in: Vec<u8>,
    /// previous public_out value, for debug
    pub prev_output: OutputData,
    /// Vector of all public_in hashes that contain a violation (i.e. differing public_out's dependent on secret_in value)
    pub violation_pub_ins: Vec<u64>,
    phantom: PhantomData<I>
}

impl<I> InfoLeakChecker<I> {}

// #[derive(Serialize, Deserialize, SerdeAny, Debug, Clone)]
pub struct LeakQuantifyMetadata {
    /// Copy of the output when no bits have been flipped
    pub original_output: OutputData,
    /// Flipping the bit at [index] causes 1 bit flip at the output
    pub bitflip_flips_output_bits: BitflipMap,
    /// Have we completed the deterministic bit flipping stage
    pub completed_deterministic_bitflips: bool,
    /// set to true if we find that bitflips in input don't map directly to output
    pub bitflips_do_not_map: bool,
    // /// The set of output bitflips that are affected by more than one input bits, or a combination of input bits
    // pub ignored_output_bitflips: HashMap<OutputSource, HashSet<usize>>,
}

/// enum describing the location of a bit from the secret input (enum parameter indicates bit number)
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct InputBitLocation {
    pub part: InputContentsFlags,
    pub bit_num: usize,
}

/// enum describing the location of a bit from the public input (enum parameter indicates bit number)
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct OutputBitLocation {
    pub source: OutputSource,
    pub bit_num: usize,
}

#[derive(Clone, Debug)]
pub struct BitflipMap {
    map: HashMap<InputBitLocation, HashSet<OutputBitLocation>>,
    seen_output_flips: HashSet<OutputBitLocation>,
    dupes: HashSet<OutputBitLocation>,
}

impl BitflipMap {
    pub fn new() -> Self { 
        Self { 
            map: HashMap::new(),
            seen_output_flips: HashSet::new(),
            dupes: HashSet::new(),
        } 
    }

    pub fn len(&self) -> usize { self.map.len() }

    pub fn mapped_inputs_counts(&self) -> HashMap<InputContentsFlags, usize> {
        let mut out = HashMap::new();
        for (in_loc, out_locs) in self.map.iter() {
            if out_locs.is_empty() { continue; }
            if let Some(count) = out.get_mut(&in_loc.part) {
                *count += 1;
            } else {
                out.insert(in_loc.part, 1);
            }
        }

        out
    }

    pub fn iterate_map(&self) -> hashbrown::hash_map::Iter<'_, InputBitLocation, HashSet<OutputBitLocation>> {
        self.map.iter()
    }

    pub fn full_map(&self) -> &HashMap<InputBitLocation, HashSet<OutputBitLocation>> {
        &self.map
    }

    /// Insert the mapping from input_bit to output_bits, returning a Vec containing the list of
    /// new output_bits that were added (after filtering any duplicates)
    pub fn insert_entry(
        &mut self,
        input_bit: InputBitLocation, 
        output_bits: Vec<OutputBitLocation>
    ) -> Vec<OutputBitLocation> {
        let mut filtered = vec![];
        let mut new_dupes = HashSet::new();

        for out_bit in &output_bits {
            if self.dupes.contains(out_bit) { continue; }
            if !self.seen_output_flips.insert(*out_bit) {
                self.dupes.insert(*out_bit);
                new_dupes.insert(*out_bit);
            } else {
                filtered.push(*out_bit);
            }
        }

        // filter out new dupes from the existing map
        self.map.values_mut().for_each(|out_bits| out_bits.retain(|e|!new_dupes.contains(e)));

        // add this mapping
        self.map.insert(input_bit, HashSet::from_iter(filtered.iter().copied()));

        filtered
    }

    /// Feed a set of input and output bits and update the map accordingly 
    /// return a bool indicating whether the check passed (i.e. no map updates occurred)
    pub fn check_multibit_flip_result(
        &mut self,
        input_bits_flipped: &[InputBitLocation],
        output_bits_flipped: &HashSet<OutputBitLocation>
    ) -> bool {
        let expected = input_bits_flipped.iter()
            .fold(HashSet::new(), |mut set, b| { 
                self.map.get(b).unwrap().iter().for_each(|o| { set.insert(o.to_owned()); }); 
                set
            }
        );

        let mut update_occurred = false;

        let unexpected = output_bits_flipped.difference(&expected);
        for out_bit in unexpected {
            println!("Found unexpected bitflip at {:?}", out_bit);
            // Try add this unexpected bit to seen flips
            if self.seen_output_flips.insert(*out_bit) {
                // If it was already seen, then filter this out from the expected flips
                for (_in_bit, out_flips) in self.map.iter_mut() {
                    let start_len = out_flips.len();
                    out_flips.retain(|e| *e != *out_bit );
                    if out_flips.len() < start_len { update_occurred = true; }
                }
            }
        }

        let failed = expected.difference(&output_bits_flipped);
        for out_bit in failed {
            for in_bit in input_bits_flipped {
                let out_flips = self.map.get_mut(in_bit).unwrap();
                let start_len = out_flips.len();
                out_flips.retain(|e| *e != *out_bit );
                if out_flips.len() < start_len { update_occurred = true; }
            }
            if !update_occurred {
                panic!("We would expect to have filtred this bit out of at least one, as it was in the expected set");
            }
        }

        !update_occurred
    }

    pub fn get_output_flips_for_input_bit(&self, input_bit_location: InputBitLocation) -> Option<&HashSet<OutputBitLocation>> {
        self.map.get(&input_bit_location)
    }
}

#[derive(Clone, Debug)]
pub struct SecretInputParts {
    explicit_secret_input: Option<Vec<u8>>,
    stack_mem_input: Option<Vec<u8>>,
    heap_mem_input: Option<Vec<u8>>,
}

impl SecretInputParts {
    fn get_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        macro_rules! update_hash {
            ($field: expr) => {
                if let Some(ref buf) = $field { buf.hash(&mut hasher); }
            }
        }
        update_hash!(self.explicit_secret_input);
        update_hash!(self.stack_mem_input);
        update_hash!(self.heap_mem_input);
        hasher.finish()
    }

    fn to_string(&self) -> String {
        let dump = |buf: &Option<Vec<u8>>| {
            if let Some(buf) = buf.as_ref() {
                format!("{:?}", if buf.len() > 60 { buf[0..60].to_vec() } else { buf.to_vec() })
            } else {
                "N/A".to_string()
            }
        };

        format!("{{ explicit: {:?}, stack: {:?}, heap: {:?} }}",
            dump(&self.explicit_secret_input),
            dump(&self.stack_mem_input),
            dump(&self.heap_mem_input)).to_string()
    }

    fn matches_secret_part_of_input<I>(&self, input: &I) -> bool 
        where I: PubSecInput 
    {
        macro_rules! check_equal {
            ($field: expr, $flag: expr) => {
                {
                    let buf2 = input.get_part_bytes($flag);
                    if $field.is_some() != buf2.is_some() {
                        false // one is an empty optional, and the other not
                    } else if $field.is_some() {
                        $field.as_ref().unwrap() == buf2.unwrap()
                    } else {
                        true // both are None
                    }
                }
            };
        }

        check_equal!(self.explicit_secret_input, InputContentsFlags::SecretExplicitInput) &&
        check_equal!(self.stack_mem_input, InputContentsFlags::SecretStackMemory) &&
        check_equal!(self.heap_mem_input, InputContentsFlags::SecretHeapMemory)
    }

    fn from_input<I>(input: &I) -> Self
        where I: PubSecInput 
    {
        Self {
            explicit_secret_input: if let Some(buf) = input.get_part_bytes(InputContentsFlags::SecretExplicitInput) {
                Some(buf.to_owned())
            } else { None },
            stack_mem_input: if let Some(buf) = input.get_part_bytes(InputContentsFlags::SecretStackMemory) {
                Some(buf.to_owned())
            } else { None },
            heap_mem_input: if let Some(buf) = input.get_part_bytes(InputContentsFlags::SecretHeapMemory) {
                Some(buf.to_owned())
            } else { None },
        }
    }
}

/// struct storing associated data for a given public input 
/// (including public outputs and secret inputs that witness a 
/// leak)
pub struct IOHashValue {
    /// Number of samples for this public_input_hash
    pub hits: usize,
    /// The hash of the public input this struct is describing
    pub public_input_hash: u64,
    /// Optional full public input vector; only populated if this 
    /// witnesses a policy violation
    pub public_input_full: Option<Vec<u8>>,
    /// Vector of secret input hashes (only one is stored for each 
    /// different public output)
    pub secret_input_hashes: Vec<u64>,
    /// Vector of public output hashes (note that if more than two
    /// are present then a leak has been witnessed)
    pub public_output_hashes: Vec<u64>,
    /// Mapping from public_output_hashes to a vector of secret_in's
    /// that produce this public output
    pub public_output_hashes_to_secret_ins: HashMap<u64, HashSet<u64>>,

    /// Metadata about all the leak quantification testing we have 
    /// done for this input
    pub leak_quantify_metadata: Option<LeakQuantifyMetadata>,

    /// Map from public output hashes to selected secret in hashes, 
    /// generated by sampling secret ins from uniform
    pub uniform_pub_outs_to_sec_ins: HashMap<u64, Vec<u64>>,

    /// Vector of full byte arrays for secret inputs that can 
    /// witness a leak
    pub secret_inputs_full: Vec<SecretInputParts>,
    /// Vector of full public outputs that witness a leak
    pub public_outputs_full: Vec<OutputData>,
}

impl IOHashValue {
    pub fn info_string(&self) -> String {
        format!("[pub_in: {:20}, (sec_in, pub_out)s: {:?}]", 
            self.public_input_hash, 
            self.secret_input_hashes.iter().zip(self.public_output_hashes.iter())
            .collect::<Vec<(&u64, &u64)>>()
        )
    }

    pub fn extended_info_string(&self) -> String {
        if self.public_input_full.is_none() { return self.info_string(); }

        format!("[pub_in: {:20}, (sec_in, pub_out)s: {:?}]", 
            std::string::String::from_utf8_lossy(&self.public_input_full.as_ref().unwrap()).into_owned(), 
            self.secret_inputs_full
                .iter()
                .zip(self.public_outputs_full.iter())
                .map(|(si, po)| (si.to_string(), std::string::String::from_utf8_lossy(&po.stdout).into_owned()))
                .collect::<Vec<(String, String)>>()
        )
    }
}

#[derive(Clone)]
pub struct FailingHypertest<'a, I> {
    pub test_one: (I, &'a OutputData),
    pub test_two: (I, &'a OutputData),
}

pub trait HypertestFeedback<I>
where 
    I: Input, 
{
    /// Create a new empty HypertestFeedback object
    fn new() -> Self;

    /// Read the observers relevant observers and determine whether this input may be interesting
    /// (in which case it should be rerun to confirm that it is deterministic) 
    fn needs_rerun(&mut self, input: &I, output_observer: &OutputObserver) -> (bool, Option<OutputData>);

    // fn needs_rerun(&mut self, input: &I, observers: &OT) -> (bool, Option<OutputData>);
    /// Called when an interesting input is confirmed to be deterministic; in some cases this may
    /// return a tuple (FailingHypertest, isNewViolation), or None if this just fixes an entry that was previously stored 
    /// incorrectly (likely due to some oddity in the way the forkserver collects output) 
    fn exposes_fault(&mut self, input: &I, output_data: &OutputData) -> Option<(FailingHypertest<'_, I>, bool)>;

    /// Upon rerunning we found an incorrectly mapped secret_input, fix the map!
    fn fix_misstored_output(&mut self, input: &I, output_data: &OutputData);

    /// We already know that this input public part witnesses a violation, here is a uniform sampled secret
    /// input that we can use to calculate the probability of witnessing a particular output
    fn store_uniform_sampled_secret_output(&mut self, input: &I, output_data: &OutputData, estimate_cmi_mode: bool);

    /// Retrieve the number of unique outputs found by uniform sampling for a given public input
    fn get_uniform_sampled_output_count(&self, input: &I) -> usize;

    /// Estimate the quantity of leakage (in bits) that has been witnessed so far
    fn estimate_leakage(&self) -> f64;

    /// Decide what the next leak searching approach is for a given input
    fn get_next_violation_targeting_approach(&self, input: &I) -> ViolationsTargetingApproach;

    /// Get immutable reference to the LeakQuantifyMetadata for a given input
    fn get_leak_quantify_metadata(&self, input: &I) -> Result<&LeakQuantifyMetadata, Error>;
    /// Get mutable reference to the LeakQuantifyMetadata for a given input
    fn get_leak_quantify_metadata_mut(&mut self, input: &I) -> Result<&mut LeakQuantifyMetadata, Error>;

    /// When adding a violation, call this to create LeakQuantifyMetadata for the given input
    fn create_leak_quantify_metadata_for(&mut self, input: &I, output_data: &OutputData);
}
pub struct STADSstatistics {
    current_finds: usize,
    expected_finds: usize,
    correctness: f64
}

pub trait STADSfeedback {
    fn stads_uniform_secrets_leakage(&self) -> STADSstatistics;
}

impl<I> HypertestFeedback<I> for InfoLeakChecker<I>
where
    I: Input + PubSecInput,
{
    fn new() -> Self {
        Self {
            dict: HashMap::new(),
            prev_pub_in: Vec::new(),
            prev_sec_in: Vec::new(),
            prev_output: OutputData { stdout: Vec::new(), stderr: Vec::new() },
            violation_pub_ins: vec![],
            phantom: PhantomData
        }
    }

    fn needs_rerun(&mut self, input: &I, output_observer: &OutputObserver) -> (bool, Option<OutputData>) {
        // let observer = observers.match_name::<OutputObserver>("output").unwrap();
        let observer = output_observer;

        let empty = Vec::new();
        let stdout = match observer.stdout() { None => &empty, Some(o) => o }.to_owned();
        let stderr = match observer.stderr() { None => &empty, Some(o) => o }.to_owned();
        if stdout.len() > 0 {
            // println!("stdout: {:?}", String::from_utf8_lossy(stdout));
        }
        let output_data = OutputData { stdout, stderr };

        let pub_in_hash = input.get_public_input_hash();
        let sec_in_hash = input.get_secret_input_hash();
        let pub_out_hash = output_data.get_hash();

        if let Some(hash_val) = self.dict.get_mut(&pub_in_hash) {
            if let Some(full) = hash_val.public_input_full.as_ref() {
                debug_assert!(
                    input.get_part_bytes(InputContentsFlags::PublicExplicitInput).unwrap_or_else(|| &[]) == full
                );
            }

            hash_val.hits += 1;
            if !hash_val.public_output_hashes.contains(&pub_out_hash) {
                if hash_val.secret_input_hashes.contains(&sec_in_hash) {
                    return (true, Some(output_data));
                }

                for secret_in in &hash_val.secret_inputs_full {
                    if secret_in.matches_secret_part_of_input(input) {
                        println!("Compared secrets and found them equal: secret_in: \
                                    {{ exp: {:?}, stack: {:?}, heap: {:?} }}, \n\
                                    cur_input: {{ exp: {:?}, stack: {:?}, heap: {:?} }}",
                                secret_in.explicit_secret_input, secret_in.stack_mem_input, secret_in.heap_mem_input,
                                input.get_part_bytes(InputContentsFlags::SecretExplicitInput), 
                                input.get_part_bytes(InputContentsFlags::SecretStackMemory),
                                input.get_part_bytes(InputContentsFlags::SecretHeapMemory));
                        panic!("Hash not found in hashes, but full input was?");
                    }
                }

                return (true, Some(output_data));

            // We didn't store the original output the first time so let's do that now!
            } else if hash_val.public_output_hashes.len() > 1 && 
                hash_val.secret_inputs_full.len() < hash_val.secret_input_hashes.len() 
            {
                let mut already_stored = false;
                for out_full in &hash_val.public_outputs_full {
                    let mut hasher = DefaultHasher::new();
                    out_full.stdout.hash(&mut hasher);
                    out_full.stderr.hash(&mut hasher);

                    if hasher.finish() == pub_out_hash {
                        already_stored = true;
                        break;
                    }
                }

                if !already_stored {
                    return (true, Some(output_data));
                }
            
            // We didn't find a new public_out, but we should update the mapping between public_out and secret_in
            } else {
                if let Some(sec_ins) = hash_val.public_output_hashes_to_secret_ins.get_mut(&pub_out_hash) {
                    sec_ins.insert(sec_in_hash);
                } else {
                    panic!("Ow, this was a new public_out after all?");
                }

                if !hash_val.public_output_hashes.contains(&pub_out_hash) {
                    panic!();
                }
            }
        } else {
            self.dict.insert(pub_in_hash, IOHashValue {
                hits: 1,
                public_input_full: None,
                uniform_pub_outs_to_sec_ins: HashMap::new(),
                public_output_hashes_to_secret_ins: HashMap::from([(pub_out_hash, [sec_in_hash].into_iter().collect::<HashSet<u64>>())]),
                public_input_hash: pub_in_hash,
                public_output_hashes: vec![pub_out_hash],
                public_outputs_full: Vec::new(),
                secret_input_hashes: vec![sec_in_hash],
                secret_inputs_full: Vec::new(),
                leak_quantify_metadata: None
            });
        }

        (false, None)
    }

    fn exposes_fault(&mut self, input: &I, output_data: &OutputData) -> Option<(FailingHypertest<'_, I>, bool)> {
        let pub_in_hash = input.get_public_input_hash();
        let sec_in_hash = input.get_secret_input_hash();
        let pub_out_hash = output_data.get_hash();

        if let Some(hash_val) = self.dict.get_mut(&pub_in_hash) {
            if !hash_val.public_output_hashes.contains(&pub_out_hash) {
                // We already have this secret hash (but new output - probably old output was incorrect)
                if hash_val.secret_input_hashes.contains(&sec_in_hash) {
                    let pos = hash_val.secret_input_hashes
                        .iter()
                        .position(|&h| h == sec_in_hash)
                        .unwrap();
                    let old_pub_out_hash = hash_val.public_output_hashes[pos];
                    let sec_ins = hash_val.public_output_hashes_to_secret_ins.get(&old_pub_out_hash).unwrap();
                    hash_val.public_output_hashes[pos] = pub_out_hash;
                    if let Some(replacement) = sec_ins.iter().find(|&&x| x != sec_in_hash) {
                        hash_val.secret_input_hashes.push(*replacement);
                        hash_val.public_output_hashes.push(old_pub_out_hash);
                    }

                    if let Some(full_pos) = hash_val.public_outputs_full.iter().position(|buf| {
                        let mut hasher = DefaultHasher::new();
                        buf.stdout.hash(&mut hasher);
                        buf.stderr.hash(&mut hasher);
                        hasher.finish() == old_pub_out_hash
                    }) {
                        hash_val.public_outputs_full[full_pos] = output_data.clone();
                    } else {
                        hash_val.public_outputs_full.push(output_data.clone());
                    }

                    if let Some(sec_full_pos) = hash_val.secret_inputs_full.iter()
                        .position(|buf| buf.get_hash() == sec_in_hash) 
                    {
                        if !hash_val.secret_inputs_full[sec_full_pos].matches_secret_part_of_input(input) {
                            panic!("somehow hashes matched????");
                        }
                    } else {
                        hash_val.secret_inputs_full.push(SecretInputParts::from_input(input));
                    }

                    // update mappings from output to secret_in
                    let members = hash_val.public_output_hashes_to_secret_ins.get_mut(&old_pub_out_hash).unwrap();
                    members.retain(|&x| x != sec_in_hash);
                    if members.is_empty() { 
                        hash_val.public_output_hashes_to_secret_ins.remove(&old_pub_out_hash); 
                    }

                    hash_val.public_output_hashes_to_secret_ins.insert(pub_out_hash, [sec_in_hash].into_iter().collect::<HashSet<u64>>());

                    return None;
                }

                if hash_val.public_input_full.is_none() {
                    hash_val.public_input_full = Some(
                        input.get_part_bytes(InputContentsFlags::PublicExplicitInput)
                            .unwrap_or_else(|| &[])
                            .to_vec()
                    );
                    self.violation_pub_ins.push(pub_in_hash);
                }

                if let Some(_members) = hash_val.public_output_hashes_to_secret_ins.get_mut(&pub_out_hash) {
                    panic!("OOH, (pub_in: {}) had a map for {} in {:?} ({:?}), but not in public_output_hashes: {:?}, sec_in_hashes: {:?}", 
                        pub_in_hash,
                        pub_out_hash,
                        hash_val.public_output_hashes_to_secret_ins.keys(),
                        hash_val.public_output_hashes_to_secret_ins.get(&pub_out_hash).unwrap(),
                        hash_val.public_output_hashes,
                        hash_val.secret_input_hashes
                    );
                } else {
                    hash_val.public_output_hashes_to_secret_ins.insert(pub_out_hash, [sec_in_hash].into_iter().collect::<HashSet<u64>>());
                }

                hash_val.secret_input_hashes.push(sec_in_hash);
                hash_val.secret_inputs_full.push(SecretInputParts::from_input(input));
                hash_val.public_outputs_full.push(output_data.clone());
                hash_val.public_output_hashes.push(pub_out_hash);

                if !hash_val.public_output_hashes.contains(&pub_out_hash) {
                    panic!("oof, missing {} from public out hashes: {:?}", pub_out_hash, hash_val.public_output_hashes);
                }

                if hash_val.secret_inputs_full.len() > 2 && hash_val.secret_inputs_full.len() % 2 == 0 {
                    return Some((
                        FailingHypertest {
                            test_one: (
                                I::from_bufs(
                                    input.get_part_bytes(InputContentsFlags::PublicExplicitInput),
                                    hash_val.secret_inputs_full[hash_val.secret_inputs_full.len() - 2].explicit_secret_input.as_deref(),
                                    hash_val.secret_inputs_full[hash_val.secret_inputs_full.len() - 2].stack_mem_input.as_deref(), 
                                    hash_val.secret_inputs_full[hash_val.secret_inputs_full.len() - 2].heap_mem_input.as_deref(), 
                                ),
                                &hash_val.public_outputs_full[hash_val.public_outputs_full.len() - 2]
                            ),
                            test_two: (
                                input.clone(),
                                &hash_val.public_outputs_full.last().unwrap()
                            ),
                        },
                        hash_val.secret_inputs_full.len() == 4 && hash_val.secret_input_hashes.len() > 4
                    ));
                }

                // println!("Found a likely leak, but don't have the original secret input stored to verify yet");
                return None;

            // We didn't store the original output the first time so let's do that now!
            } else if hash_val.public_output_hashes.len() > 1 &&
                hash_val.secret_inputs_full.len() < hash_val.secret_input_hashes.len()
            {
                let pos = hash_val.public_output_hashes.iter().position(|&x| x == pub_out_hash).unwrap();
                if pos < hash_val.public_outputs_full.len() {
                    hash_val.public_outputs_full.insert(pos, output_data.clone());
                    hash_val.secret_inputs_full.insert(pos, SecretInputParts::from_input(input));
                } else {
                    hash_val.public_outputs_full.push(output_data.clone());
                    hash_val.secret_inputs_full.push(SecretInputParts::from_input(input));
                }
                hash_val.secret_input_hashes[pos] = sec_in_hash;

                return Some((
                    FailingHypertest {
                        test_one: (
                            I::from_bufs(
                                input.get_part_bytes(InputContentsFlags::PublicExplicitInput),
                                hash_val.secret_inputs_full[1].explicit_secret_input.as_deref(),
                                hash_val.secret_inputs_full[1].stack_mem_input.as_deref(), 
                                hash_val.secret_inputs_full[1].heap_mem_input.as_deref(), 
                            ),
                            &hash_val.public_outputs_full[1]
                        ),
                        test_two: (
                            input.clone(),
                            &hash_val.public_outputs_full[0]
                        ),
                    },
                    hash_val.secret_inputs_full.len() <= 4
                ));
            }
        } else {
            panic!("This should have already been added in needs_rerun!");
        }

        panic!("oops");
    }

    fn fix_misstored_output(&mut self, input: &I, output_data: &OutputData) {
        let pub_in_hash = input.get_public_input_hash();
        let sec_in_hash = input.get_secret_input_hash();

        // let mut hasher = DefaultHasher::new();
        // output_data.stdout.hash(&mut hasher);
        // output_data.stderr.hash(&mut hasher);
        // let pub_out_hash = hasher.finish();

        let hash_val = self.dict.get_mut(&pub_in_hash).unwrap();
        hash_val.public_output_hashes_to_secret_ins.retain(|_pub_out, sec_in| {
            sec_in.retain(|e| *e != sec_in_hash);
            !sec_in.is_empty()
        });

        let mut removed_count = 0;
        for (idx, hash) in hash_val.secret_input_hashes.clone().into_iter().enumerate() {
            if hash == sec_in_hash {
                let adjusted_idx = idx - removed_count;
                let removed_pub_out = hash_val.public_output_hashes.remove(adjusted_idx);
                hash_val.secret_input_hashes.remove(adjusted_idx);
                removed_count += 1;

                for (idx, sec_full) in hash_val.secret_inputs_full.clone().iter().enumerate() {
                    if sec_full.get_hash() == sec_in_hash {
                        assert!(hash_val.secret_inputs_full.len() == hash_val.public_outputs_full.len());
                        if hash_val.public_outputs_full[idx].get_hash() != removed_pub_out {
                            println!("expected public_outputs_full[{idx}].get_hash() to be {}, but was {} (all: {:?})",
                                removed_pub_out, hash_val.public_outputs_full[idx].get_hash(),
                                hash_val.public_outputs_full.clone().into_iter().map(|o| o.get_hash()).collect::<Vec<u64>>());
                            panic!();
                        }
                        hash_val.secret_inputs_full.remove(idx);
                        hash_val.public_outputs_full.remove(idx);
                        hash_val.public_output_hashes_to_secret_ins.remove(&removed_pub_out);
                        break;
                    }
                }
            }
        }

        // if let Some(sec_ins) = hash_val.public_output_hashes_to_secret_ins.get_mut(&pub_out_hash) {
        //     sec_ins.push(sec_in_hash);
        // } else {
        //     hash_val.public_output_hashes_to_secret_ins.insert(pub_out_hash, vec![sec_in_hash]);
        // }

        println!("Fixed incorrectly stored sec_in pub_out mapping");
    }

    fn store_uniform_sampled_secret_output(&mut self, input: &I, output_data: &OutputData, estimate_cmi_mode: bool) {
        let pub_in_hash = input.get_public_input_hash();
        let sec_in_hash = input.get_secret_input_hash();
        let pub_out_hash = output_data.get_hash();

        if let Some(hash_val) = self.dict.get_mut(&pub_in_hash) {
            if estimate_cmi_mode {
                hash_val.hits += 1;
            }

            if let Some(existing) = hash_val.uniform_pub_outs_to_sec_ins.get_mut(&pub_out_hash) {
                existing.push(sec_in_hash);
                // println!("tested: (pub in len: {}) {:?}, got {:?} out", input.get_public_part_bytes().len(), input.get_secret_part_bytes(), String::from_utf8_lossy(stdout));
            } else {
                hash_val.uniform_pub_outs_to_sec_ins.insert(pub_out_hash, vec![sec_in_hash]);

                if estimate_cmi_mode && hash_val.uniform_pub_outs_to_sec_ins.len() == 2 {
                    self.violation_pub_ins.push(pub_in_hash);
                }
            }
        } else {
            // this path will only run in cmi_estimate_mode
            self.dict.insert(pub_in_hash, IOHashValue {
                hits: 1,
                public_input_full: None,
                uniform_pub_outs_to_sec_ins: HashMap::from([(pub_out_hash, vec![sec_in_hash])]),
                public_output_hashes_to_secret_ins: HashMap::from([(pub_out_hash, [sec_in_hash].into_iter().collect::<HashSet<u64>>())]),
                public_input_hash: pub_in_hash,
                public_output_hashes: vec![pub_out_hash],
                public_outputs_full: Vec::new(),
                secret_input_hashes: vec![sec_in_hash],
                secret_inputs_full: Vec::new(),
                leak_quantify_metadata: None
            });
        }
    }

    fn get_uniform_sampled_output_count(&self, input: &I) -> usize {
        let pub_in_hash = input.get_public_input_hash();
        let hash_val = self.dict.get(&pub_in_hash).unwrap();
        hash_val.uniform_pub_outs_to_sec_ins.len()
    }

    fn estimate_leakage(&self) -> f64 {
        let mut most_output_distinctions = 0;
        let mut most_bitflips_locations = None;
        let mut most_bitflips_leaked = 0;
        const MIN_HITS: usize = 4;

        let mut output_violation_entropy_sum = 0f64;
        let mut violation_entropy_sum = 0f64;

        let well_sampled_pub_ins_count = self.dict.iter()
            .fold(0usize, |acc, (_pub_in_hash, hash_val)| {
                acc + if hash_val.hits >= MIN_HITS { 1 } else { 0 }
            });

        let pub_in_prob = 1.0f64 / (well_sampled_pub_ins_count as f64);

        let mut well_sampled = 0;
        for violation_pub_in_hash in &self.violation_pub_ins {
            let hash_val = self.dict.get(violation_pub_in_hash).unwrap();
            if let Some(metadata) = &hash_val.leak_quantify_metadata {
                if !metadata.bitflips_do_not_map && metadata.completed_deterministic_bitflips {
                    let bitflips_leaked = metadata.bitflip_flips_output_bits.mapped_inputs_counts();
                    let count = bitflips_leaked.values().fold(0, |acc, &x| acc + x);
                    if count > most_bitflips_leaked {
                        most_bitflips_leaked = count;
                        most_bitflips_locations = Some(bitflips_leaked);
                    }
                }
            }

            if hash_val.uniform_pub_outs_to_sec_ins.is_empty() {
                continue;
            }

            well_sampled += 1;

            violation_entropy_sum += pub_in_prob * pub_in_prob.log2();

            let sample_count = hash_val.uniform_pub_outs_to_sec_ins
                .values()
                .fold(0, |acc, x| acc + x.len());

            let mut entropy = 0f64;
            for (_pub_out, sec_in) in &hash_val.uniform_pub_outs_to_sec_ins {
                let prob = pub_in_prob * (sec_in.len() as f64 / sample_count as f64);
                entropy += prob * prob.log2();
            }

            let non_uniform_set: HashSet<&u64> = HashSet::from_iter(hash_val.public_output_hashes_to_secret_ins.keys());
            let uniform_set = HashSet::from_iter(hash_val.uniform_pub_outs_to_sec_ins.keys());
            let diff = non_uniform_set.difference(&uniform_set);

            for &&_pub_out in diff.clone() {
                let prob = pub_in_prob * (1f64 / sample_count as f64);
                entropy += prob * prob.log2();
            }

            let total_distinctions = hash_val.uniform_pub_outs_to_sec_ins.len() + diff.count();
            if total_distinctions > most_output_distinctions {
                most_output_distinctions = total_distinctions;
            }

            output_violation_entropy_sum += entropy; 
        }

        let leaked_info_bits = -output_violation_entropy_sum + violation_entropy_sum;
        println!("Leakage statistics:");
        println!("    CMI:             {leaked_info_bits} bits from {well_sampled} well sampled violations");
        print!(  "    Bitflips:        {most_bitflips_leaked} is the most bits leaked directly from input to output.");
        if let Some(bitflip_locations) = most_bitflips_locations {
            print!(" From: {{");
            for (source, count) in bitflip_locations {
                print!("{:?}: {}, ", source, count);
            }
            print!("}}");
        }
        println!("");
        println!("    Maximal Leakage: {:.02} bits channel capacity; max distinctions on output: {most_output_distinctions}", (most_output_distinctions as f64).log2());
        let stats = self.stads_uniform_secrets_leakage();
        println!("    violation STADS: {{ current_finds: {}, expected_finds: {}, correctness: {} }}", stats.current_finds, stats.expected_finds, stats.correctness);

        // leaked_info_bits
        0.0
    }

    fn get_next_violation_targeting_approach(&self, input: &I) -> ViolationsTargetingApproach {
        let metadata = self.get_leak_quantify_metadata(input).unwrap();
        if metadata.bitflip_flips_output_bits.len() == 0 {
            ViolationsTargetingApproach::BitFlips
        } else {
            ViolationsTargetingApproach::UniformSampling
        }
    }

    fn get_leak_quantify_metadata(&self, input: &I) -> Result<&LeakQuantifyMetadata, Error> {
        let pub_in_hash = input.get_public_input_hash();
        if let Some(deets) = self.dict.get(&pub_in_hash) {
            if let Some(meta) = &deets.leak_quantify_metadata {
                Ok(meta)
            } else {
                Err(Error::EmptyOptional(
                    "self.dict.get_mut(&pub_in_hash)?.leak_quantify_metadata".to_string(), 
                    ErrorBacktrace::new()
                ))
            }
        } else {
            Err(Error::EmptyOptional(
                "self.dict.get_mut(&pub_in_hash)?".to_string(), 
                ErrorBacktrace::new()
            ))
        }
    }

    fn get_leak_quantify_metadata_mut(&mut self, input: &I) -> Result<&mut LeakQuantifyMetadata, Error> {
        let pub_in_hash = input.get_public_input_hash();
        if let Some(deets) = self.dict.get_mut(&pub_in_hash) {
            if let Some(meta) = &mut deets.leak_quantify_metadata {
                Ok(meta)
            } else {
                Err(Error::EmptyOptional(
                    "self.dict.get_mut(&pub_in_hash)?".to_string(), 
                    ErrorBacktrace::new()
                ))
            }
        } else {
            Err(Error::EmptyOptional(
                "self.dict.get_mut(&pub_in_hash)?".to_string(), 
                ErrorBacktrace::new()
            ))
        }
    }

    fn create_leak_quantify_metadata_for(&mut self, input: &I, output_data: &OutputData) {
        let pub_in_hash = input.get_public_input_hash();
        let deets = self.dict.get_mut(&pub_in_hash).unwrap();
        if deets.leak_quantify_metadata.is_some() {
            // It already exists, this can happen when the original input that we only had the 
            // hash for gets discovered
            return;
        }

        deets.leak_quantify_metadata = Some(LeakQuantifyMetadata {
            bitflip_flips_output_bits: BitflipMap::new(),
            original_output: output_data.to_owned(),
            completed_deterministic_bitflips: false,
            bitflips_do_not_map: false,
        });
    }
}

impl<I> STADSfeedback for InfoLeakChecker<I> {
    fn stads_uniform_secrets_leakage(&self) -> STADSstatistics {
        let mut singletons = 0; 
        let mut doubletons = 0;
        let mut total_samples = 0;
        let mut current_finds = 0;

        for pub_in in &self.violation_pub_ins {
            if let Ok(info) = self.get_sample_info_for_pub_in(*pub_in) {
                singletons += info.singletons;
                doubletons += info.doubletons;
                total_samples += info.sample_count;
                current_finds += info.species_count;
            }
        }

        let expected_finds = current_finds +
            if doubletons > 0 {
                (singletons * singletons) / (2 * doubletons)
            } else if singletons > 0 {
                singletons * (singletons - 1) / 2
            } else {
                0
            };

        let correctness = singletons as f64 / total_samples as f64;
        // let correctness = 1f64 - singletons as f64 / current_finds as f64;

        STADSstatistics { current_finds, expected_finds, correctness }
    }
}

struct SamplesInfo {
    singletons: usize,
    doubletons: usize,
    species_count: usize,
    sample_count: usize
}

impl<I> InfoLeakChecker<I> {
    fn get_sample_info_for_pub_in(&self, pub_in: u64) -> Result<SamplesInfo, libafl::Error> {
        let mut singletons = 0;
        let mut doubletons = 0;
        let mut species_count = 0;

        let hash_val = self.dict.get(&pub_in)
            .ok_or(libafl::Error::KeyNotFound(pub_in.to_string(), ErrorBacktrace::new()))?;

        let mut sample_count = 0;
        for (_pub_out, sec_ins) in &hash_val.uniform_pub_outs_to_sec_ins {
            species_count += 1; 
            match sec_ins.len() {
                1 => singletons += 1,
                2 => doubletons += 1,
                _ => ()
            };
            sample_count += sec_ins.len();
        }

        if hash_val.uniform_pub_outs_to_sec_ins.len() > 0 {
            let _expected_finds = self.violation_pub_ins.len() +
                if doubletons > 0 {
                    (singletons * singletons) / (2 * doubletons)
                } else if singletons > 0 {
                    singletons * (singletons - 1) / 2
                } else {
                    0
                };

            let _correctness = singletons as f64 / sample_count as f64;
            // println!("violation: {pub_in}, actual_finds: {}, expected: {expected_finds}, correctness: {correctness}", hash_val.uniform_pub_outs_to_sec_ins.len());
        }

        Ok(SamplesInfo { singletons, doubletons, species_count, sample_count })
    }
}
