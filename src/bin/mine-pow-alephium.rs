// src/bin/mock_pool.rs
// Rust port of mock_pool.py: Alephium mock pool for gpu-miner connectivity tests
// Usage: cargo run --bin mock_pool -- --host 0.0.0.0 --port 10973 --difficulty 1

use clap::Parser;
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

fn is_good_solution(nonce: &[u8], header: &[u8], target: &[u8]) -> bool {
    if nonce.len() != NONCE_LEN || header.len() != HEADER_LEN {
        return false;
    }
    let mut full_header = Vec::with_capacity(BLAKE3_BUF_LEN);
    full_header.extend(nonce);
    full_header.extend(header);
    full_header.resize(BLAKE3_BUF_LEN, 0);
    let h1 = blake3::hash(&full_header);
    let h2 = blake3::hash(h1.as_bytes());
    let h2_int = u128::from_be_bytes(h2.as_bytes()[..16].try_into().unwrap());
    let target_int = u128::from_be_bytes(target[..16].try_into().unwrap());
    h2_int < target_int
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
                break;
            }
        };
        let pay_len =
            u32::from_be_bytes(prefix[..4].try_into().unwrap()) as usize;
        let payload = match recv_exact(&mut stream, pay_len) {
            Ok(p) => p,
            Err(_) => {
                println!("[*] Miner disconnected");
                break;
            }
        };

        let mut frame = prefix.clone();
        frame.extend(payload);

        if let Some((nonce, header, txs)) = decode_submit_block(&frame) {
            let good = is_good_solution(&nonce, &header, &target);
            println!(
                "[{}] nonce {}  txs {}  valid={}",
                if good { "✓" } else { "✗" },
                hex::encode(&nonce),
                txs.len(),
                good
            );
        } else {
            println!("[!] Bad frame");
        }
    }
    Ok(())
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
                    let _ = handle_miner(stream, diff);
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
    Ok(())
}
