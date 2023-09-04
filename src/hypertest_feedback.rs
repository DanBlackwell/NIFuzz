use hashbrown::HashMap;
use core::{fmt::Debug, marker::PhantomData, time::Duration};
use serde::{Serialize, de::DeserializeOwned};
use std::{hash::{Hash, Hasher}, collections::{hash_map::DefaultHasher, HashSet}};
use libafl::{
    observers::ObserversTuple,
    prelude::{Input, HasCorpus}
};
use crate::output_leak_fuzzer::{IOHashValue, OutputData};
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

impl<I> InfoLeakChecker<I> {
}

pub struct FailingHypertest<'a, I> {
    test_one: (I, &'a OutputData),
    test_two: (I, &'a OutputData),
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
    fn exposes_fault(&mut self, input: &I, output_data: OutputData) -> Option<(FailingHypertest<'_, I>, bool)>;

    /// We already know that this input public part witnesses a violation, here is a uniform sampled secret
    /// input that we can use to calculate the probability of witnessing a particular output
    fn store_uniform_sampled_secret_output(&mut self, input: &I, output_observer: &OutputObserver);

    /// Estimate the quantity of leakage (in bits) that has been witnessed so far
    fn estimate_leakage(&self) -> f64;
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
        let stdout = match observer.stdout() { None => &empty, Some(o) => o };
        let stderr = match observer.stderr() { None => &empty, Some(o) => o };

        let hash = |val: &[u8]| {
            let mut hasher = DefaultHasher::new();
            val.hash(&mut hasher);
            hasher.finish()
        };

        let pub_in_hash = hash(input.get_public_part_bytes());
        let sec_in_hash = hash(input.get_secret_part_bytes());

        let mut hasher = DefaultHasher::new();
        stdout.hash(&mut hasher);
        stderr.hash(&mut hasher);
        let pub_out_hash = hasher.finish();

        if let Some(hash_val) = self.dict.get_mut(&pub_in_hash) {
            if let Some(full) = hash_val.public_input_full.as_ref() {
                debug_assert!(input.get_public_part_bytes() == full);
            }

            hash_val.hits += 1;
            if !hash_val.public_output_hashes.contains(&pub_out_hash) {
                let output_data = OutputData { stdout: stdout.to_vec(), stderr: stderr.to_vec() };

                if hash_val.secret_input_hashes.contains(&sec_in_hash) {
                    // println!("Made the following observations (secret_in: public_out) for public_in: {:?}:", 
                    //     std::string::String::from_utf8_lossy(input.get_public_part_bytes()));

                    // if hash_val.public_outputs_full.len() == 0 {
                    //     println!("For public in: {:?} and secret_in: {:?} found two different outputs: (hash only) {:?} and {:?}",
                    //         std::string::String::from_utf8_lossy(input.get_public_part_bytes()),
                    //         std::string::String::from_utf8_lossy(input.get_secret_part_bytes()),
                    //         hash_val.public_output_hashes[0],
                    //         output_data.to_string());

                    // } else if hash_val.secret_inputs_full.len() < hash_val.public_outputs_full.len() {
                    //     println!("(hash only) {}: {:?}",
                    //         hash_val.secret_input_hashes[0],
                    //         std::string::String::from_utf8_lossy(&hash_val.public_outputs_full[0].stdout));
                    //     for i in 0..hash_val.secret_inputs_full.len() {
                    //         println!("{:?}: {:?}",
                    //             std::string::String::from_utf8_lossy(&hash_val.secret_inputs_full[i]),
                    //             std::string::String::from_utf8_lossy(&hash_val.public_outputs_full[i + 1].stdout));
                    //     }

                    // } else {
                    //     for i in 0..hash_val.secret_inputs_full.len() {
                    //         println!("{:?}: {:?}",
                    //             std::string::String::from_utf8_lossy(&hash_val.secret_inputs_full[i]),
                    //             std::string::String::from_utf8_lossy(&hash_val.public_outputs_full[i].stdout));
                    //     }

                    // }

                    // println!("Note: prev pub_in: {:?},\nsec_in: {:?},\npub_stdout: {:?},\npub_stderr: {:?}",
                    //     std::string::String::from_utf8_lossy(&self.prev_pub_in),
                    //     std::string::String::from_utf8_lossy(&self.prev_sec_in),
                    //     std::string::String::from_utf8_lossy(&self.prev_output.stdout),
                    //     std::string::String::from_utf8_lossy(&self.prev_output.stderr),
                    // );

                    return (true, Some(output_data));
                }

                for secret_in in &hash_val.secret_inputs_full {
                    if input.get_secret_part_bytes() == secret_in {
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
                    let output_data = OutputData { stdout: stdout.to_vec(), stderr: stderr.to_vec() };
                    return (true, Some(output_data));
                }
            
            // We didn't find a new public_out, but we should update the mapping between public_out and secret_in
            } else {
                if let Some(sec_ins) = hash_val.public_output_hashes_to_secret_ins.get_mut(&pub_out_hash) {
                    sec_ins.push(sec_in_hash);
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
                public_output_hashes_to_secret_ins: HashMap::from([(pub_out_hash, vec![sec_in_hash])]),
                public_input_hash: pub_in_hash,
                public_output_hashes: vec![pub_out_hash],
                public_outputs_full: Vec::new(),
                secret_input_hashes: vec![sec_in_hash],
                secret_inputs_full: Vec::new()
            });
        }

        (false, None)
    }

    fn exposes_fault(&mut self, input: &I, output_data: OutputData) -> Option<(FailingHypertest<'_, I>, bool)> {
        let hash = |val: &[u8]| {
            let mut hasher = DefaultHasher::new();
            val.hash(&mut hasher);
            hasher.finish()
        };

        let pub_in_hash = hash(input.get_public_part_bytes());
        let sec_in_hash = hash(input.get_secret_part_bytes());

        let mut hasher = DefaultHasher::new();
        output_data.stdout.hash(&mut hasher);
        output_data.stderr.hash(&mut hasher);
        let pub_out_hash = hasher.finish();

        if let Some(hash_val) = self.dict.get_mut(&pub_in_hash) {
            if !hash_val.public_output_hashes.contains(&pub_out_hash) {
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
                        hash_val.public_outputs_full[full_pos] = output_data;
                    } else {
                        hash_val.public_outputs_full.push(output_data);
                    }

                    if let Some(sec_full_pos) = hash_val.secret_inputs_full.iter()
                        .position(|buf| hash(buf) == sec_in_hash) 
                    {
                        if hash_val.secret_inputs_full[sec_full_pos] != input.get_secret_part_bytes() {
                            panic!("somehow hashes matched????");
                        }
                    } else {
                        hash_val.secret_inputs_full.push(input.get_secret_part_bytes().to_vec());
                    }

                    // update mappings from output to secret_in
                    let members = hash_val.public_output_hashes_to_secret_ins.get_mut(&old_pub_out_hash).unwrap();
                    members.retain(|&x| x != sec_in_hash);
                    if members.is_empty() { 
                        hash_val.public_output_hashes_to_secret_ins.remove(&old_pub_out_hash); 
                    }

                    hash_val.public_output_hashes_to_secret_ins.insert(pub_out_hash, vec![sec_in_hash]);

                    return None;
                }

                if hash_val.public_input_full.is_none() {
                    hash_val.public_input_full = Some(input.get_public_part_bytes().to_vec());
                    self.violation_pub_ins.push(pub_in_hash);
                }

                if let Some(members) = hash_val.public_output_hashes_to_secret_ins.get_mut(&pub_out_hash) {
                    panic!("OOH, (pub_in: {}) had a map for {} in {:?} ({:?}), but not in public_output_hashes: {:?}, sec_in_hashes: {:?}", 
                        pub_in_hash,
                        pub_out_hash,
                        hash_val.public_output_hashes_to_secret_ins.keys(),
                        hash_val.public_output_hashes_to_secret_ins.get(&pub_out_hash).unwrap(),
                        hash_val.public_output_hashes,
                        hash_val.secret_input_hashes
                    );
                } else {
                    hash_val.public_output_hashes_to_secret_ins.insert(pub_out_hash, vec![sec_in_hash]);
                }

                hash_val.secret_input_hashes.push(sec_in_hash);
                hash_val.secret_inputs_full.push(input.get_secret_part_bytes().to_vec());
                hash_val.public_outputs_full.push(output_data);
                hash_val.public_output_hashes.push(pub_out_hash);

                if !hash_val.public_output_hashes.contains(&pub_out_hash) {
                    panic!("oof, missing {} from public out hashes: {:?}", pub_out_hash, hash_val.public_output_hashes);
                }

                if hash_val.secret_inputs_full.len() > 2 && hash_val.secret_inputs_full.len() % 2 == 0 {
                    return Some((
                        FailingHypertest {
                            test_one: (
                                I::from_pub_sec_bytes(
                                    input.get_public_part_bytes(), 
                                    &hash_val.secret_inputs_full[hash_val.secret_inputs_full.len() - 2]       
                                ),
                                &hash_val.public_outputs_full[hash_val.public_outputs_full.len() - 2]
                            ),
                            test_two: (
                                I::from_pub_sec_bytes(
                                    input.get_public_part_bytes(),
                                    input.get_secret_part_bytes()
                                ),
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
                    hash_val.public_outputs_full.insert(pos, output_data);
                    hash_val.secret_inputs_full.insert(pos, input.get_secret_part_bytes().to_vec());
                } else {
                    hash_val.public_outputs_full.push(output_data);
                    hash_val.secret_inputs_full.push(input.get_secret_part_bytes().to_vec());
                }
                hash_val.secret_input_hashes[pos] = sec_in_hash;

                return Some((
                    FailingHypertest {
                        test_one: (
                            I::from_pub_sec_bytes(
                                input.get_public_part_bytes(), 
                                &hash_val.secret_inputs_full[1]       
                            ),
                            &hash_val.public_outputs_full[1]
                        ),
                        test_two: (
                            I::from_pub_sec_bytes(
                                input.get_public_part_bytes(),
                                input.get_secret_part_bytes()
                            ),
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

    fn store_uniform_sampled_secret_output(&mut self, input: &I, output_observer: &OutputObserver) {
        let observer = output_observer;

        let empty = Vec::new();
        let stdout = match observer.stdout() { None => &empty, Some(o) => o };
        let stderr = match observer.stderr() { None => &empty, Some(o) => o };

        let hash = |val: &[u8]| {
            let mut hasher = DefaultHasher::new();
            val.hash(&mut hasher);
            hasher.finish()
        };

        let pub_in_hash = hash(input.get_public_part_bytes());
        let sec_in_hash = hash(input.get_secret_part_bytes());

        let mut hasher = DefaultHasher::new();
        stdout.hash(&mut hasher);
        stderr.hash(&mut hasher);
        let pub_out_hash = hasher.finish();

        let hash_val = self.dict.get_mut(&pub_in_hash).unwrap();
        if let Some(existing) = hash_val.uniform_pub_outs_to_sec_ins.get_mut(&pub_out_hash) {
            existing.push(sec_in_hash);
        } else {
            hash_val.uniform_pub_outs_to_sec_ins.insert(pub_out_hash, vec![sec_in_hash]);
        }
    }

    fn estimate_leakage(&self) -> f64 {
        let mut output_violation_entropy_sum = 0.0_f64;
        let mut violation_entropy_sum = 0.0_f64;
        const MIN_HITS: usize = 1_000;

        let filtered = self.violation_pub_ins.iter()
            .map(|x| self.dict.get(x).unwrap())
            .filter(|x| x.hits >= MIN_HITS);
        let (sum, well_sampled_pubs) = filtered.fold((0, 0), |(sum, len), x| (sum + x.hits, len + if x.hits > 10 { 1 } else { 0 }));
        let pub_in_prob = 1.0f64 / (well_sampled_pubs as f64);

        let valid_count = self.violation_pub_ins.iter().fold(0, |cnt, x| cnt + if self.dict.get(x).unwrap().uniform_pub_outs_to_sec_ins.len() > 1 {1} else {0});

        let mut well_sampled = 0;
        for violation_pub_in_hash in &self.violation_pub_ins {
            let hash_val = self.dict.get(violation_pub_in_hash).unwrap();
            if hash_val.uniform_pub_outs_to_sec_ins.len() == 0 {
                continue;
            }

            well_sampled += 1;

            violation_entropy_sum += pub_in_prob * pub_in_prob.log2();

            let sample_count = hash_val.uniform_pub_outs_to_sec_ins
                .values()
                .fold(0, |acc, x| acc + x.len());

            let mut entropy = 0_f64;
            print!("Probability of outputs: [");
            for (pub_out, sec_in) in &hash_val.uniform_pub_outs_to_sec_ins {
                let prob = pub_in_prob * (sec_in.len() as f64 / sample_count as f64);
                print!("{}: {} (raw {} / {}), ", pub_out, prob, sec_in.len(), sample_count);
                entropy += prob * prob.log2();
            }

            let non_uniform_set: HashSet<&u64> = HashSet::from_iter(hash_val.public_output_hashes_to_secret_ins.keys());
            let uniform_set = HashSet::from_iter(hash_val.uniform_pub_outs_to_sec_ins.keys());
            let diff = non_uniform_set.difference(&uniform_set);

            for &&pub_out in diff {
                let prob = pub_in_prob * (1f64 / sample_count as f64);
                print!("[non_uniform] {}: {} (raw {} / {}), ", pub_out, prob, 1, sample_count);
                entropy += prob * prob.log2();
            }

            println!("]");
            output_violation_entropy_sum += entropy; 

            // if hash_val.secret_inputs_full.len() > 2 {
            //     println!("{{ pub: {:?}, sec1: {:?}, sec2: {:?}, sec3: {:?} }} => {{ out1: {}, out2: {}, out3: {} }}",
            //         hash_val.public_input_full, hash_val.secret_inputs_full[0], hash_val.secret_inputs_full[1], hash_val.secret_inputs_full[2],
            //         hash_val.public_outputs_full[0].to_string(), hash_val.public_outputs_full[1].to_string(), hash_val.public_outputs_full[2].to_string());
            // }

        }

        let leaked_info_bits = -output_violation_entropy_sum + violation_entropy_sum;
        println!("Leaked {} bits from {} well sampled violations (violation entropy sum: {violation_entropy_sum}, sample_count: {well_sampled_pubs}), valid_count: {valid_count}", leaked_info_bits, well_sampled);

        leaked_info_bits
    }
}
