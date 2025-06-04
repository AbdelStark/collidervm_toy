use crate::utils::{encode_scriptnum, NonceSearchProgress};
use bitcoin::{
    Amount, PublicKey, XOnlyPublicKey,
    blockdata::script::{Builder, ScriptBuf},
    opcodes::{self, OP_TRUE},
};
use bitcoin_hashes::{HashEngine, sha256};
pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;
use bitcoin_script_stack::optimizer;
use bitvm::{
    execute_script_buf,
    hash::blake3::{
        blake3_compute_script_with_limb, blake3_push_message_script_with_limb,
    },
};
use blake3::Hasher;
use indicatif::{ProgressBar, ProgressStyle};
use secp256k1::Message;
use std::time::{Duration, Instant};

/// F1 threshold: x must be > 100
pub const F1_THRESHOLD: u32 = 100;
/// F2 threshold: x must be < 200
pub const F2_THRESHOLD: u32 = 200;

/// Create a minimal sighash for demonstration
pub fn create_toy_sighash_message(
    locking_script: &ScriptBuf,
    value: Amount,
) -> Message {
    let mut engine = sha256::HashEngine::default();
    engine.input(&locking_script.to_bytes());
    engine.input(&value.to_sat().to_le_bytes());
    let digest = sha256::Hash::from_engine(engine);
    Message::from_digest(digest.to_byte_array())
}

/// Calculate H(x||nonce)|_B => flow_id
pub fn calculate_flow_id(input: u32, nonce: u64) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(&input.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    let hash = hasher.finalize();

    let mut fourb = [0u8; 4];
    fourb.copy_from_slice(&hash.as_bytes()[0..4]);

    u32::from_le_bytes(fourb)
}

/// Finds a valid nonce `r` for a given input `x` such that `H(x, r)|_B` falls within the set `D`. (Off-chain logic)
///
/// This simulates the work performed by an Operator during the online phase.
/// The expected number of hash attempts is `2^(B-L)`.
///
/// # Arguments
/// * `input` - The input value `x`.
/// * `b_bits` - The hash prefix length `B`.
/// * `l_bits` - The parameter `L` defining the size of set `D`.
///
/// # Returns
/// * `Ok((u64, u32))` - A tuple containing the found nonce `r` and the corresponding flow ID `d`.
/// * `Err(String)` - An error if a nonce cannot be found (e.g., due to overflow or excessive attempts).
pub fn find_valid_nonce(
    input: u32,
    b_bits: usize,
    l_bits: usize,
) -> Result<(u64, u32), String> {
    let mut nonce: u64 = 0;

    // Calculate expected number of attempts (2^(B-L)) for progress reporting
    let expected_attempts: u64 = 1u64
        .checked_shl((b_bits.saturating_sub(l_bits)) as u32) // Calculate 2^(B-L)
        .unwrap_or(u64::MAX);

    println!(
        "Finding valid nonce (L={}, B={})... (Expected work: ~2^{} = {} hashes)",
        l_bits,
        b_bits,
        b_bits.saturating_sub(l_bits),
        expected_attempts
    );

    let mut progress = NonceSearchProgress::new(expected_attempts);

    let max_flow_id = (1u64 << l_bits) as u32;
    let mask_b = if b_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << b_bits) - 1
    };

    loop {
        // Always get the prefix and hash
        let hash = calculate_flow_id(input, nonce);
        let prefix_b = hash & mask_b;
        if prefix_b < max_flow_id {
            // Found a nonce `r` such that H(x, r)|_B = d ∈ D
            progress.success(prefix_b, nonce);
            return Ok((nonce, prefix_b));
        } else {
            // Hash prefix was outside the valid range [0, 2^L - 1], try next nonce
            progress.update(nonce);

            // Increment nonce, checking for overflow
            nonce = nonce.checked_add(1).ok_or_else(|| {
                "Nonce overflowed u64::MAX while searching".to_string()
            })?;

            // Safety break after excessive attempts (e.g., 100x expected work)
            // This prevents infinite loops in case of configuration errors.
            if nonce > expected_attempts.saturating_mul(100) {
                progress.failure();
                return Err(format!(
                    "Could not find a valid nonce after {nonce} attempts (expected ~{expected_attempts})",
                ));
            }
        }
    }
}

/// Convert flow_id => little-endian prefix of length B/8
pub fn flow_id_to_prefix_bytes(flow_id: u32, b_bits: usize) -> Vec<u8> {
    assert!(b_bits <= 32);
    assert_eq!(b_bits % 8, 0, "b_bits must be multiple of 8");
    let prefix_len = b_bits / 8;
    let le4 = flow_id.to_le_bytes();
    let flow_id_prefix_bytes = le4[..prefix_len].to_vec();
    // Transform to nibbles
    // For example: [0x12, 0x34] => [0x1, 0x2, 0x3, 0x4]
    // Or: [0x0d, 0x00] => [0x0, 0xd, 0x0, 0x0]
    let mut nibbles = Vec::with_capacity(flow_id_prefix_bytes.len() * 2);
    for &byte in &flow_id_prefix_bytes {
        // Extract high nibble (first 4 bits)
        nibbles.push((byte >> 4) & 0x0F);
        // Extract low nibble (last 4 bits)
        nibbles.push(byte & 0x0F);
    }
    nibbles
}

/// Helper: combine scripts (by just concatenating the raw bytes).
pub fn combine_scripts(fragments: &[ScriptBuf]) -> ScriptBuf {
    let mut combined = Vec::new();
    for frag in fragments {
        combined.extend(frag.to_bytes());
    }
    ScriptBuf::from_bytes(combined)
}

/// A small helper script that pushes `prefix_data` and does OP_EQUALVERIFY
/// This is used to check if the top of the stack matches the prefix
/// For example, if the content of the stack is:
/// [0x00, 0x0d, 0x00, 0x00]
/// Then the script needs to check equality of each byte.
/// We need to take care of the fact that the prefix is now in nibbles.
/// Also the ordering of elements on the stack.
/// We need to push the prefix in reverse order to the stack.
pub fn build_prefix_equalverify(prefix_data: &[u8]) -> ScriptBuf {
    let mut b = Builder::new();

    // Check each nibble individually, pushing in reverse order to match stack evaluation
    for &nibble in prefix_data.iter().rev() {
        // For the nibble value, use push_int for accurate stack comparison
        b = b.push_int(nibble as i64);
        b = b.push_opcode(opcodes::all::OP_EQUALVERIFY);
    }

    b.into_script()
}

pub fn build_drop(items: usize) -> ScriptBuf {
    let mut b = Builder::new();
    for _ in 0..items {
        b = b.push_opcode(opcodes::all::OP_DROP);
    }
    b.into_script()
}

// Reconstructs a 32-bit value `x` from limbs of `limb_len` size.
// Only supports power-of-2 limb lengths for Bitcoin Script efficiency.
fn build_script_reconstruct_x(limb_len: u8) -> ScriptBuf {
    // Validate that limb_len_bits is a power of 2
    assert!(limb_len > 0 && (limb_len & (limb_len - 1)) == 0, 
            "limb_len_bits must be a power of 2");
    
    let limbs_needed = (32 + limb_len - 1) / limb_len; // Ceiling division
    
    println!("limb_len: {limb_len}, limbs_needed: {limbs_needed}");

    let mut b = Builder::new().push_int(0); // acc = 0
    
    for i in 0..limbs_needed {
        for _ in 0..limb_len {
            b = b.push_opcode(opcodes::all::OP_DUP)
                 .push_opcode(opcodes::all::OP_ADD);
        }
        
        // Pick the i-th limb from bottom of stack and add to accumulator
        b = b.push_opcode(opcodes::all::OP_DEPTH)
             .push_opcode(opcodes::all::OP_1SUB)      // depth - 1 (bottom index)
             .push_int(i as i64)                      // limb index
             .push_opcode(opcodes::all::OP_SUB)       // (depth-1) - i
             .push_opcode(opcodes::all::OP_PICK)      // copy limb to top
             .push_opcode(opcodes::all::OP_ADD);      // acc += limb
    }
    
    b.into_script()
}

// limb length for blake3 in bits, 
// blake3 accepts any limb length [4, 32) but due to the way how build_script_reconstruct_x
// it must be a power of 2 between 1 and 16
// Valid values: 1, 2, 4, 8, 16
const LIMB_LEN: u8 = 16;

/// Build an F1 script with onchain BLAKE3, checking x>F1_THRESHOLD and the top (b_bits/8) bytes match flow_id_prefix.
pub fn build_script_f1_blake3_locked(
    signer_pubkey: &PublicKey,
    flow_id_prefix: &[u8],
    _b_bits: usize,
) -> ScriptBuf {
    let prefix_len = flow_id_prefix.len();
    let total_msg_len = 12; // x_4b + r_4b0 + r_4b1

    // 1) Script to check signature
    let verify_signature_script = {
        let mut b = Builder::new();
        b = b.push_x_only_key(&XOnlyPublicKey::from(signer_pubkey.inner));
        b.push_opcode(opcodes::all::OP_CHECKSIGVERIFY).into_script()
    };

    // 2) Reconstruct x from first 8 nibbles
    let reconstruct_x_script = build_script_reconstruct_x(LIMB_LEN);

    // 3) Check x_num > 100
    let x_greater_check_script = Builder::new()
        .push_int(F1_THRESHOLD as i64)
        .push_opcode(opcodes::all::OP_GREATERTHAN)
        .push_opcode(opcodes::all::OP_VERIFY)
        .into_script();

    // 4) BLAKE3 compute snippet - OPTIMIZED
    let compute_compiled =
        blake3_compute_script_with_limb(total_msg_len, LIMB_LEN).compile();
    let compute_optimized = optimizer::optimize(compute_compiled);
    let compute_blake3_script =
        ScriptBuf::from_bytes(compute_optimized.to_bytes());

    // 5) drop limbs we don't need for prefix check
    // Needed nibbles: prefix_len (because now represented as nibbles) or B / 4
    let needed_nibbles = prefix_len;
    let blake3_script_hash_len_nibbles = 64;

    let drop_script =
        build_drop(blake3_script_hash_len_nibbles - needed_nibbles);

    // 6) compare prefix => OP_EQUALVERIFY
    let prefix_cmp_script = build_prefix_equalverify(flow_id_prefix);

    // 7) push OP_TRUE
    let success_script = Builder::new().push_opcode(OP_TRUE).into_script();

    // Combine the locking script parts
    combine_scripts(&[
        verify_signature_script,
        reconstruct_x_script,
        x_greater_check_script,
        compute_blake3_script,
        drop_script,
        prefix_cmp_script,
        success_script,
    ])
}

/// Build an F2 script with onchain BLAKE3, checking x<F2_THRESHOLD and prefix
pub fn build_script_f2_blake3_locked(
    signer_pubkey: &PublicKey,
    flow_id_prefix: &[u8],
    _b_bits: usize,
) -> ScriptBuf {
    let prefix_len = flow_id_prefix.len();
    let total_msg_len = 12;

    // 1) Script to check signature
    let verify_signature_script = {
        let mut b = Builder::new();
        b = b.push_x_only_key(&XOnlyPublicKey::from(signer_pubkey.inner));
        b.push_opcode(opcodes::all::OP_CHECKSIGVERIFY).into_script()
    };

    // 2) Reconstruct x from first 8 nibbles
    let reconstruct_x_script = build_script_reconstruct_x(LIMB_LEN);

    // 3) Check x_num < 200
    let x_less_check_script = Builder::new()
        .push_int(F2_THRESHOLD as i64)
        .push_opcode(opcodes::all::OP_LESSTHAN)
        .push_opcode(opcodes::all::OP_VERIFY)
        .into_script();

    // 4) BLAKE3 compute snippet - OPTIMIZED
    let compute_blake3_script = {
        let compiled =
            blake3_compute_script_with_limb(total_msg_len, LIMB_LEN).compile();
        // Important: Optimize the compute script
        let optimized = optimizer::optimize(compiled);
        ScriptBuf::from_bytes(optimized.to_bytes())
    };

    // 5) drop limbs we don't need for prefix check
    // Needed nibbles: prefix_len (because now represented as nibbles) or B / 4
    let needed_nibbles = prefix_len;
    let blake3_script_hash_len_nibbles = 64;

    let drop_script =
        build_drop(blake3_script_hash_len_nibbles - needed_nibbles);

    // 6) compare prefix => OP_EQUALVERIFY
    let prefix_cmp_script = build_prefix_equalverify(flow_id_prefix);

    let success_script = Builder::new().push_opcode(OP_TRUE).into_script();

    combine_scripts(&[
        verify_signature_script,
        reconstruct_x_script,
        x_less_check_script,
        compute_blake3_script,
        drop_script,
        prefix_cmp_script,
        success_script,
    ])
}


pub fn message_to_witness_limbs(x: u32, nonce: u64) -> Vec<Vec<u8>> {
    
    let message = [
        x.to_le_bytes(),
        nonce.to_le_bytes()[0..4].try_into().unwrap(),
        nonce.to_le_bytes()[4..8].try_into().unwrap(),
    ]
    .concat();

    blake3_message_to_limbs(&message, LIMB_LEN)
        .into_iter()
        .map(|limb| encode_scriptnum(limb.into()))
        .collect()
}
/// A basic "hash rate" calibration
pub fn benchmark_hash_rate(duration_secs: u64) -> u64 {
    println!("Calibrating for {duration_secs} seconds...");
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner} [{elapsed_precise}] [{bar:40.green/black}] {percent}% {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    let start = Instant::now();
    let end = start + Duration::from_secs(duration_secs);

    let mut count = 0u64;
    let mut nonce = 0u64;
    let input = 123u32;

    while Instant::now() < end {
        let mut hasher = Hasher::new();
        hasher.update(&input.to_le_bytes());
        hasher.update(&nonce.to_le_bytes());
        hasher.finalize();
        nonce += 1;
        count += 1;
    }

    let dt = start.elapsed().as_secs_f64();
    let rate = if dt > 0.0 { count as f64 / dt } else { 0.0 };
    pb.finish_with_message(format!("~{rate:.2} H/s"));
    rate as u64
}

// for off-chain use
pub fn blake3_message_to_limbs(message_bytes: &[u8], limb_len: u8) -> Vec<u32> {
    let script =
        blake3_push_message_script_with_limb(message_bytes, limb_len).compile();
    let res = execute_script_buf(script);

    res.final_stack
        .0
        .iter_str()
        .map(|v| {
            let mut arr = [0u8; 4];
            arr[..v.len()].copy_from_slice(&v);
            u32::from_le_bytes(arr)
        })
        .collect()
}

pub fn build_script_hash_to_limbs() -> ScriptBuf {
    let mut builder = Builder::new();

    for _ in 0..56 {
        builder = builder.push_opcode(opcodes::all::OP_TOALTSTACK);
    }
    for i in 0..8 {
        for j in (0..8).step_by(2) {
            builder = builder
                .push_int(j)
                .push_opcode(opcodes::all::OP_ROLL)
                .push_int(j + 1)
                .push_opcode(opcodes::all::OP_ROLL)
                .push_opcode(opcodes::all::OP_SWAP);
        }
        if i != 7 {
            for _ in 0..8 {
                builder = builder.push_opcode(opcodes::all::OP_FROMALTSTACK);
            }
        }
    }

    for _ in 0..64 {
        builder = builder.push_int(0);
    }

    builder.into_script()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_script::script;
    use bitvm::{
        execute_script_buf,
        hash::blake3::{
            blake3_push_message_script_with_limb, blake3_verify_output_script,
        },
    };

    #[test]
    fn test_f1_witness_script() {
        // Create an input value that will fill the 4 bytes
        let input_value = u32::from_be_bytes([0x12, 0x34, 0x56, 0x78]);
        let nonce = u64::from_be_bytes([
            0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x21, 0x43,
        ]);
        let limb_len: u8 = 16;

        let message = [
            input_value.to_le_bytes(),
            nonce.to_le_bytes()[0..4].try_into().unwrap(),
            nonce.to_le_bytes()[4..8].try_into().unwrap(),
        ]
        .concat();
        println!("input_value: {input_value}");
        println!("nonce: {nonce}");
        println!("message: {}", hex::encode(message.clone()));
        let msg_push_script_f1 =
            blake3_push_message_script_with_limb(&message, limb_len).compile();
        //println!("msg_push_script_f1: {}", msg_push_script_f1);

        let witness_script =
            ScriptBuf::from_bytes(msg_push_script_f1.to_bytes());
        let f1_res = execute_script_buf(witness_script);
        println!("F1 => success={}", f1_res.success);
        println!("F1 => exec_stats={:?}", f1_res.stats);
        println!("F1 => final_stack={:?}", f1_res.final_stack);
        println!("F1 => error={:?}", f1_res.error);
        println!("F1 => last_opcode={:?}", f1_res.last_opcode);
        assert!(f1_res.error.is_none());
    }

    #[test]
    fn test_blake3_script_generation() {
        let message = [0u8; 32];
        let limb_len: u8 = 16;
        let expected_hash = *blake3::hash(message.as_ref()).as_bytes();

        println!("Expected hash: {}", hex::encode(expected_hash));

        // Test push message script generation (requires message argument)
        let push_bytes =
            blake3_push_message_script_with_limb(&message, limb_len)
                .compile()
                .to_bytes();

        // Test compute script generation
        let optimized_compute = optimizer::optimize(
            blake3_compute_script_with_limb(message.len(), limb_len).compile(),
        );

        // Test verify output script generation
        let verify_bytes = blake3_verify_output_script(expected_hash)
            .compile()
            .to_bytes();

        // Combine scripts for execution (assuming message is pushed first)
        let mut combined_script_bytes = push_bytes;
        combined_script_bytes.extend(optimized_compute.to_bytes());
        combined_script_bytes.extend(verify_bytes);

        let script = ScriptBuf::from_bytes(combined_script_bytes);

        let result = execute_script_buf(script);

        println!("Result: {result:?}");
        assert!(result.success, "Blake3 script execution failed");

        // Create an invalid hash by copying the expected hash and modifying one byte
        let mut invalid_hash = expected_hash;
        invalid_hash[0] ^= 0x01; // Change one byte to create an invalid hash

        // Test push message script generation (requires message argument)
        let push_bytes =
            blake3_push_message_script_with_limb(&message, limb_len)
                .compile()
                .to_bytes();

        // Test compute script generation
        let optimized_compute = optimizer::optimize(
            blake3_compute_script_with_limb(message.len(), limb_len).compile(),
        );

        // Test verify output script generation
        let verify_bytes = blake3_verify_output_script(invalid_hash)
            .compile()
            .to_bytes();

        // Combine scripts for execution (assuming message is pushed first)
        let mut combined_script_bytes = push_bytes;
        combined_script_bytes.extend(optimized_compute.to_bytes());
        combined_script_bytes.extend(verify_bytes);

        let script = ScriptBuf::from_bytes(combined_script_bytes);

        let result = execute_script_buf(script);

        println!("Result: {result:?}");
        assert!(!result.success, "Blake3 script execution failed");
    }

    #[test]
    fn test_encoding() {
        let x_sig_script = {
            let mut b = Builder::new();
            b = b.push_int(0x00_i64);
            b = b.push_int(0x0d_i64);
            b = b.push_int(0x00_i64);
            b = b.push_int(0x00_i64);
            b.into_script()
        };
        println!("x_sig_script: {x_sig_script}");

        // flow id prefix: 000d0000
        let flow_id_prefix = vec![0x00, 0x0d, 0x00, 0x00];
        let script_part_1 = build_prefix_equalverify(&flow_id_prefix);

        let locking_script =
            combine_scripts(&[script_part_1, script! {OP_TRUE}.compile()]);

        let mut full_f1 = x_sig_script.to_bytes();
        full_f1.extend(locking_script.to_bytes());
        let exec_f1_script = ScriptBuf::from_bytes(full_f1);
        println!("exec_f1_script: {exec_f1_script}");

        let f1_res = execute_script_buf(exec_f1_script);
        println!("F1 => success={}", f1_res.success);
        println!("F1 => exec_stats={:?}", f1_res.stats);
        println!("F1 => final_stack={:?}", f1_res.final_stack);
        println!("F1 => error={:?}", f1_res.error);
        println!("F1 => last_opcode={:?}", f1_res.last_opcode);
        assert!(f1_res.success);
    }

    #[test]
    fn test_blake3_input_from_witness() {
        let limb_len = 16;
        let message = [
            0x7b, 0x00, 0x00, 0x00, 0xd9, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let msg_push_script =
            blake3_push_message_script_with_limb(&message, limb_len).compile();
        let push_script = ScriptBuf::from_bytes(msg_push_script.to_bytes());

        let total_msg_len = 12;
        
        let compute_compiled =
            blake3_compute_script_with_limb(total_msg_len, limb_len).compile();
        let compute_optimized = optimizer::optimize(compute_compiled);
        let compute_script =
            ScriptBuf::from_bytes(compute_optimized.to_bytes());

        let expected_hash = *blake3::hash(message.as_ref()).as_bytes();
        let verify_script = ScriptBuf::from_bytes(
            blake3_verify_output_script(expected_hash)
                .compile()
                .to_bytes(),
        );

        let locking_script = combine_scripts(&[compute_script, verify_script]);

        let witness = push_script;

        let mut full_f1 = witness.to_bytes();
        full_f1.extend(locking_script.to_bytes());
        let exec_f1_script = ScriptBuf::from_bytes(full_f1);
        let f1_res = execute_script_buf(exec_f1_script);
        println!("F1 => success={}", f1_res.success);
        println!("F1 => exec_stats={:?}", f1_res.stats);
        println!("F1 => final_stack={:?}", f1_res.final_stack);
        println!("F1 => error={:?}", f1_res.error);
        println!("F1 => last_opcode={:?}", f1_res.last_opcode);
        assert!(f1_res.success);
    }
}
