// src/bin/mock_pool.rs
// Rust port of mock_pool.py: Alephium mock pool for gpu-miner connectivity tests
// Usage: cargo run --bin mock_pool -- --host 0.0.0.0 --port 10973 --difficulty 1

use bitcoin::opcodes::OP_TRUE;
use bitcoin::script::Builder;
use bitcoin::ScriptBuf;

use bitcoin_script_stack::optimizer;
use bitvm::hash::blake3::blake3_push_message_script_with_limb;
use bitvm::{
    ExecuteInfo,
    execute_script_buf,
    hash::blake3::blake3_compute_script_with_limb,
};

use clap::Parser;

use collidervm_toy::core::{
    blake3_message_to_limbs, build_drop, build_prefix_equalverify,
    build_script_hash_to_limbs, combine_scripts,
};

use num_bigint::BigUint;
use num_traits::One;
use rand::RngCore;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

const PROTO_VERSION: u8 = 1;
const MSG_JOBS: u8 = 0;
const MSG_SUBMIT_BLOCK: u8 = 0;
const HEADER_LEN: usize = 208;
const NONCE_LEN: usize = 24;
const BLAKE3_BUF_LEN: usize = 326;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(long, default_value_t = 10973)]
    port: u16,
    #[arg(long, default_value_t = 1)]
    difficulty: u64,
}

fn u32be(i: u32) -> [u8; 4] {
    i.to_be_bytes()
}

fn blob(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + data.len());
    v.extend(&(data.len() as u32).to_be_bytes());
    v.extend(data);
    v
}

fn build_job(
    from_group: u32,
    to_group: u32,
    header_blob: &[u8],
    txs_blob: &[u8],
    target_blob: &[u8],
    height: u32,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend(&u32be(from_group));
    v.extend(&u32be(to_group));
    v.extend(blob(header_blob));
    v.extend(blob(txs_blob));
    v.extend(blob(target_blob));
    v.extend(&u32be(height));
    v
}

fn build_jobs_message(jobs: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![PROTO_VERSION, MSG_JOBS];
    body.extend(&u32be(jobs.len() as u32));
    for job in jobs {
        body.extend(job);
    }
    let mut msg = Vec::new();
    msg.extend(&u32be(body.len() as u32));
    msg.extend(body);
    msg
}

pub fn target_from_difficulty(diff: u64) -> [u8; 32] {
    if diff == 0 {
        panic!("difficulty must be ≥ 1");
    }

    // max_target = 2^256 − 1
    let max_target = (BigUint::one() << 256) - BigUint::one();

    let target: BigUint = max_target / BigUint::from(diff);

    // Convert to big-endian bytes and left-pad to 32 bytes
    let raw = target.to_bytes_be();

    if raw.len() > 32 {
        panic!("target doesn’t fit in 32 bytes");
    }

    let mut bytes = [0u8; 32];

    bytes[32 - raw.len()..].copy_from_slice(&raw);
    bytes
}

fn make_jobs(batch_id: u64, diff: u64) -> Vec<Vec<u8>> {
    let mut jobs = Vec::new();
    let mut header_seed = [0u8; 32];
    let mut hasher = blake3::Hasher::new();
    hasher.update(&batch_id.to_le_bytes());
    header_seed.copy_from_slice(&hasher.finalize().as_bytes()[..32]);
    for fg in 0..4 {
        for tg in 0..4 {
            let mut header = vec![0u8; HEADER_LEN];
            rand::thread_rng().fill_bytes(&mut header);
            header[..header_seed.len()].copy_from_slice(&header_seed);
            jobs.push(build_job(
                fg,
                tg,
                &header,
                &[],
                &target_from_difficulty(diff),
                0,
            ));
        }
    }
    jobs
}

fn recv_exact(stream: &mut TcpStream, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut read = 0;
    while read < n {
        let r = stream.read(&mut buf[read..])?;
        if r == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "socket closed",
            ));
        }
        read += r;
    }
    Ok(buf)
}

fn alephium_block_hash(nonce: &[u8], header: &[u8]) -> [u8; 32] {
    if nonce.len() != NONCE_LEN || header.len() != HEADER_LEN {
        panic!(
            "Invalid nonce or header length: nonce={} bytes, header={} bytes",
            nonce.len(),
            header.len()
        );
    }
    let mut full_header = Vec::with_capacity(BLAKE3_BUF_LEN);
    full_header.extend(nonce);
    full_header.extend(header);
    full_header.resize(BLAKE3_BUF_LEN, 0);

    let h1 = blake3::hash(&full_header);
    let h2 = blake3::hash(h1.as_bytes());

    // let h1_int = BigUint::from_bytes_be(h1.as_bytes());
    // let h2_int = BigUint::from_bytes_be(h2.as_bytes());
    // println!("    h1: {:0>64x}", h1_int);
    // println!("    h2: {:0>64x}", h2_int);

    *h2.as_bytes()
}

fn is_ok(nonce: &[u8], header: &[u8], target: &[u8]) -> bool {
    let h2 = alephium_block_hash(nonce, header);

    let h2_int = BigUint::from_bytes_be(&h2);
    let target_int = BigUint::from_bytes_be(target);

    h2_int < target_int
}

// For debugging purposes, reconstruct the hash from the stack
#[allow(dead_code)]
fn reconstruct_hash_from_stack(result: &ExecuteInfo) -> BigUint {
    // Reconstruct hash from nibbles on stack
    let stack: Vec<u32> = result
        .final_stack
        .0
        .iter_str()
        .map(|v| {
            if v.len() > 4 {
                panic!("Stack element too large to fit in u32: {:?}", v);
            }
            let mut arr = [0u8; 4];
            arr[4 - v.len()..].copy_from_slice(&v);
            u32::from_be_bytes(arr)
        })
        .collect();

    let mut hash: Vec<u8> = Vec::with_capacity(32);
    for i in 0..32 {
        let hi = stack
            .get(2 * i)
            .copied()
            .expect("Not enough stack elements for hi nibble");
        let lo = stack
            .get(2 * i + 1)
            .copied()
            .expect("Not enough stack elements for lo nibble");
        if hi > 0xF || lo > 0xF {
            panic!("Nibble value out of range: hi={}, lo={}", hi, lo);
        }
        let byte = ((hi as u8) << 4) | (lo as u8);
        hash.push(byte);
    }
    BigUint::from_bytes_be(&hash)
}

fn build_check_alephium_block_hash(
    block: &[u8],
    expected_block_hash: &[u8],
) -> ScriptBuf {
    let limb_len = 16;

    // let message_limbs = blake3_message_to_limbs(&block, limb_len)
    //     .iter()
    //     .map(|&limb| limb as i64)
    //     .fold(Builder::new(), |b, limb| b.push_int(limb))
    //     .into_script();

    let message_limbs = blake3_push_message_script_with_limb(block, limb_len).compile();

    let h1 = optimizer::optimize(
        blake3_compute_script_with_limb(BLAKE3_BUF_LEN, limb_len).compile(),
    );

    let hash_to_limbs = build_script_hash_to_limbs();

    let h2 =
        optimizer::optimize(blake3_compute_script_with_limb(32, 4).compile());

    let expected_nibbles = expected_block_hash
        .iter()
        .flat_map(|&byte| vec![(byte >> 4) & 0xF, byte & 0xF])
        .collect::<Vec<_>>();

    let to_drop = 64 - expected_nibbles.len();

    let drop_tail = build_drop(to_drop);

    let prefix_cmp = build_prefix_equalverify(&expected_nibbles);

    let success_script = Builder::new().push_opcode(OP_TRUE).into_script();

    combine_scripts(&[
        message_limbs,
        h1,
        hash_to_limbs,
        h2,
        drop_tail,
        prefix_cmp,
        success_script,
    ])
}

pub fn verify_alephium_block_hash_with_script(
    nonce: &[u8],
    header: &[u8],
    block_hash: &[u8],
) -> bool {
    assert_eq!(nonce.len(), NONCE_LEN, "nonce must be 24 bytes");
    assert_eq!(header.len(), HEADER_LEN, "header must be 208 bytes");
    assert_eq!(block_hash.len(), 32, "block_hash must be 32 bytes");

    let mut message = Vec::default();
    message.extend_from_slice(&nonce);
    message.extend_from_slice(&header);
    message.resize(BLAKE3_BUF_LEN, 0);

    let script = build_check_alephium_block_hash(&message, block_hash);

    let res = execute_script_buf(script);

    println!(
        "Script executed with success: {}",
        res.success
    );
    println!("stack: {:?}", res.final_stack);

    return res.success;
}

fn decode_submit_block(frame: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if frame.len() < 10 {
        return None;
    }
    let total_len =
        u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
    let _ver = frame[4];
    let kind = frame[5];
    let block_size =
        u32::from_be_bytes(frame[6..10].try_into().unwrap()) as usize;
    if kind != MSG_SUBMIT_BLOCK
        || total_len != frame.len() - 4
        || block_size != frame.len() - 10
    {
        return None;
    }
    let mut pos = 10;
    let nonce = frame[pos..pos + NONCE_LEN].to_vec();
    pos += NONCE_LEN;
    let header = frame[pos..pos + HEADER_LEN].to_vec();
    pos += HEADER_LEN;
    let txs = frame[pos..].to_vec();
    Some((nonce, header, txs))
}

fn handle_miner(mut stream: TcpStream, diff: u64) -> io::Result<()> {
    println!("[+] Miner connected from {}", stream.peer_addr()?);
    let batch_ctr = 0u64;
    let target = target_from_difficulty(diff);

    // Send initial job set
    let jobs_msg = build_jobs_message(&make_jobs(batch_ctr, diff));
    stream.write_all(&jobs_msg)?;
    println!("[>] Pushed 16 templates");

    loop {
        let prefix = match recv_exact(&mut stream, 4) {
            Ok(p) => p,
            Err(_) => {
                println!("[*] Miner disconnected");
                break Ok(());
            }
        };
        let pay_len =
            u32::from_be_bytes(prefix[..4].try_into().unwrap()) as usize;
        let payload = match recv_exact(&mut stream, pay_len) {
            Ok(p) => p,
            Err(_) => {
                println!("[*] Miner disconnected");
                break Ok(());
            }
        };

        let mut frame = prefix.clone();
        frame.extend(payload);

        if let Some((nonce, header, txs)) = decode_submit_block(&frame) {
            let pow_ok = is_ok(&nonce, &header, &target);

            let block_hash = alephium_block_hash(&nonce, &header);

            let hash_ok = verify_alephium_block_hash_with_script(
                &nonce,
                &header,
                &block_hash,
            );
            println!(
                "[{}] nonce {}  txs {}",
                if pow_ok && hash_ok { "✓" } else { "✗" },
                hex::encode(&nonce),
                txs.len(),
            );
            return Ok(());
        } else {
            println!("[!] Bad frame");
        }
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr)?;
    println!("[+] Listening on {}  diff={}", addr, args.difficulty);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let diff = args.difficulty;
                thread::spawn(move || {
                    if let Err(e) = handle_miner(stream, diff) {
                        eprintln!("[!] Error handling miner: {}", e);
                    }
                    std::process::exit(0);
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn hex_to_array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex::decode(hex).expect("Invalid hex string");
        assert_eq!(bytes.len(), N, "Length mismatch");
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        arr
    }

    const NONCE_HEX: &str = "bd193b24440aca7894a1edea53fc7bf0cc52c06e7b970562";
    const HEADER_HEX: &str = "71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cbfbd480ea895758fa18cb534cd1a8f2617a299636d8b77e186fa09b7e369036edadf5d00d823b299d67b91384bcfe977e1efdaf56575410bb59c9ef4dced5df13304357f20c8f8958499833c9d9385534929515b30aea4e19e8dabd1890d970e206d5088ec1125b2d2c9b15c008bff7e0e23cebe0a26fc2fdfc16d13443465828337e4e43ef84b0aee9a348a3baab8d3002e2de9b7adc6ccf3ac6b6d0d881a214914d16e6fcb595768e273e606379fd0e";
    const TARGET_HEX: &str =
        "000000068db8bac710cb295e9e1b089a027525460aa64c2f837b4a2339c0ebed";

    fn fixtures() -> ([u8; NONCE_LEN], [u8; HEADER_LEN], [u8; 32]) {
        (
            hex_to_array::<NONCE_LEN>(NONCE_HEX),
            hex_to_array::<HEADER_LEN>(HEADER_HEX),
            hex_to_array::<32>(TARGET_HEX),
        )
    }

    #[rstest]
    #[case::valid(fixtures())]
    fn test_verify_alephium_pow_with_script_valid(
        #[case] (nonce, header, target): (
            [u8; NONCE_LEN],
            [u8; HEADER_LEN],
            [u8; 32],
        ),
    ) {
        assert!(is_ok(&nonce, &header, &target));

        let block_hash = alephium_block_hash(&nonce, &header);

        let res = verify_alephium_block_hash_with_script(
            &nonce,
            &header,
            &block_hash,
        );

        assert!(res, "Expected success for valid PoW");
    }

    #[rstest]
    #[case::invalid(fixtures())]
    fn test_verify_alephium_pow_with_script_invalid(
        #[case] (nonce, header, _): (
            [u8; NONCE_LEN],
            [u8; HEADER_LEN],
            [u8; 32],
        ),
    ) {
        let mut block_hash = alephium_block_hash(&nonce, &header);
        block_hash[0] ^= 0xFF;

        let res = verify_alephium_block_hash_with_script(
            &nonce,
            &header,
            &block_hash,
        );
        assert!(!res, "Expected failure for invalid PoW");
    }
}
