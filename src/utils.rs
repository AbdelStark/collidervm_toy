use indicatif::{ProgressBar, ProgressStyle};
use std::cmp::max;
use std::time::Duration;
use std::time::Instant;

use bitcoin::{Network, Txid, secp256k1::SecretKey};
use bitcoincore_rpc::{Client, RpcApi};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Encode an i64 as a minimally‑encoded script number (little‑endian)
pub fn encode_scriptnum(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let mut abs = n.unsigned_abs();
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    // If the most‑significant bit is set, add a sign byte
    if out.last().unwrap() & 0x80 != 0 {
        out.push(if n < 0 { 0x80 } else { 0x00 });
    } else if n < 0 {
        *out.last_mut().unwrap() |= 0x80;
    }
    out
}

/// Quick & dirty fee estimator (vbytes × sat/vB)
pub fn estimate_fee_vbytes(vbytes: usize, rate: u64) -> u64 {
    (vbytes as u64) * rate
}

/// Convert a SecretKey to WIF (signet/testnet)
pub fn sk_to_wif(sk: &SecretKey, network: Network) -> String {
    let priv_key = bitcoin::PrivateKey::new(*sk, network);
    priv_key.to_wif()
}

pub fn wif_to_sk(wif: &str) -> SecretKey {
    bitcoin::PrivateKey::from_wif(wif)
        .expect("Invalid WIF")
        .inner
}

/// Serialize a Schnorr signature to Vec<u8>
pub fn serialize_schnorr_sig(sig: &secp256k1::schnorr::Signature) -> Vec<u8> {
    sig.serialize().to_vec()
}

pub fn wait_for_confirmation(
    rpc_client: &Client,
    txid: &Txid,
    confirmations: u32,
    block_time: u64,
) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    let timeout = 2 * block_time;
    let sleep = Duration::from_secs(max(2, timeout / 5));
    loop {
        match rpc_client.get_raw_transaction_info(txid, None) {
            Ok(tx_info) => {
                let elapsed_secs = start.elapsed().as_secs_f64();
                let (unit, elapsed_disp) = if block_time >= 60 {
                    ("minutes", elapsed_secs / 60.0)
                } else {
                    ("seconds", elapsed_secs)
                };
                if let Some(c) = tx_info.confirmations {
                    if c >= confirmations {
                        println!(
                            "✅ Transaction confirmed (×{c}) in {elapsed_disp:.1} {unit}!"
                        );
                        return Ok(());
                    } else {
                        println!(
                            "⏳ Confirmations: {c}. Elapsed: {elapsed_disp:.1} {unit}...",
                        );
                    }
                } else {
                    println!(
                        "⏳ Transaction in the mempool. Elapsed: {elapsed_disp:.1} {unit}...",
                    );
                }
            }
            Err(e) => {
                anyhow::bail!(e);
            }
        }
        if start.elapsed().as_secs() > timeout {
            anyhow::bail!("timed out waiting for confirmation");
        }
        std::thread::sleep(sleep);
    }
}

pub fn write_transaction_to_file(
    tx: &bitcoin::Transaction,
    output_dir: &str,
    file_name: &str,
) -> anyhow::Result<String> {
    std::fs::create_dir_all(output_dir)?;
    let path = format!("{output_dir}/{file_name}.tx");
    std::fs::write(&path, bitcoin::consensus::encode::serialize_hex(tx))?;
    Ok(path)
}

pub fn wrap_network(network: &str) -> Network {
    match network {
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        "testnet" => Network::Testnet,
        "mainnet" => Network::Bitcoin,
        _ => todo!(),
    }
}

pub struct NonceSearchProgress {
    progress_bar: Option<ProgressBar>,
    expected_attempts: u64,
    last_update: u64,
    hash_rates: Vec<f64>,
    start_time: Instant,
    report_interval: u64,
}

impl NonceSearchProgress {
    pub fn new(expected_attempts: u64) -> Self {
        let progress_bar = if expected_attempts > 100 {
            let pb = ProgressBar::new(expected_attempts);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:50.cyan/blue}] {pos}/{len} ({percent}%) [{per_sec}] {msg}")
                    .unwrap()
                    .progress_chars("■□·")
            );
            pb.set_message("Finding nonce for valid flow...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));
            Some(pb)
        } else {
            None
        };
        Self {
            progress_bar,
            expected_attempts,
            last_update: 0,
            hash_rates: Vec::with_capacity(10),
            start_time: Instant::now(),
            report_interval: 50_000,
        }
    }

    pub fn update(&mut self, nonce: u64) {
        if nonce > self.last_update + self.report_interval {
            let elapsed = self.start_time.elapsed();
            let hash_rate = if elapsed.as_secs() > 0 {
                nonce as f64 / elapsed.as_secs_f64()
            } else {
                nonce as f64
            };
            self.hash_rates.push(hash_rate);
            if self.hash_rates.len() > 10 {
                self.hash_rates.remove(0);
            }
            let avg_hash_rate: f64 = self.hash_rates.iter().sum::<f64>()
                / self.hash_rates.len() as f64;
            if let Some(pb) = &self.progress_bar {
                pb.set_position(nonce);
                let eta_secs = if nonce >= self.expected_attempts {
                    0.0
                } else {
                    (self.expected_attempts - nonce) as f64 / avg_hash_rate
                };
                let eta_str = if eta_secs < 60.0 {
                    format!("{eta_secs:.1}s")
                } else if eta_secs < 3600.0 {
                    format!("{:.1}m {:.0}s", eta_secs / 60.0, eta_secs % 60.0)
                } else {
                    format!(
                        "{:.1}h {:.0}m",
                        eta_secs / 3600.0,
                        (eta_secs % 3600.0) / 60.0
                    )
                };
                pb.set_message(format!(
                    "ETA: {eta_str} @ {:.2} KH/s, {:.1}% done",
                    avg_hash_rate / 1000.0,
                    (nonce as f64 / self.expected_attempts as f64) * 100.0
                ));
            } else {
                println!(
                    "  Tried {nonce} hashes... ({avg_hash_rate:.2} hash/s)"
                );
            }
            self.last_update = nonce;
        }
        if let Some(pb) = &self.progress_bar {
            let update_frequency = if self.expected_attempts > 1_000_000 {
                5_000
            } else if self.expected_attempts > 100_000 {
                1_000
            } else {
                100
            };
            if nonce % update_frequency == 0 {
                pb.set_position(nonce);
            }
        }
    }

    pub fn success(&self, flow_id: u32, nonce: u64) {
        let elapsed = self.start_time.elapsed();
        let hash_rate = if elapsed.as_secs() > 0 {
            nonce as f64 / elapsed.as_secs_f64()
        } else {
            nonce as f64
        };
        if let Some(pb) = &self.progress_bar {
            pb.finish_with_message(format!(
                "Found flow_id {flow_id} after {nonce} hashes!"
            ));
        } else {
            println!(
                "  Found valid nonce {nonce} -> flow_id {flow_id} after {nonce} hashes."
            );
        }
        println!("  Average hash rate: {hash_rate:.2} hashes/sec");
    }

    pub fn failure(&self) {
        if let Some(pb) = &self.progress_bar {
            pb.finish_with_message("Exceeded maximum attempts");
        }
    }
}

/// This is special for conversion of SecretKey and PublicKey between ::musig2::secp256k and ::secp256k1
pub fn inner_from<F: Serialize, T: DeserializeOwned>(from: F) -> T {
    let value = serde_json::to_value(&from).unwrap();
    serde_json::from_value(value).unwrap()
}
