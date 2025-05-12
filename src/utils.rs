use std::time::Duration;

use bitcoin::{Network, Txid, secp256k1::SecretKey};
use bitcoincore_rpc::{Client, RpcApi};

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
    timeout_sec: u64,
) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    loop {
        match rpc_client.get_raw_transaction_info(txid, None) {
            Ok(tx_info) => {
                if let Some(c) = tx_info.confirmations {
                    println!("⏳ Confirmations: {c}"); // Changed from {confirmations} to {c}
                    if c >= confirmations {
                        println!("✅ Transaction is confirmed!");
                        break;
                    }
                } else {
                    println!(
                        "⏳ Transaction in mempool, no confirmations yet."
                    );
                }
            }
            Err(e) => {
                anyhow::bail!(e);
            }
        }
        if start.elapsed().as_secs() > timeout_sec {
            anyhow::bail!("timed out waiting for confirmation");
        }
        std::thread::sleep(Duration::from_secs(1)); // wait and poll again
    }
    Ok(())
}

pub fn write_transaction_to_file(
    tx: &bitcoin::Transaction,
    output_dir: &str,
    file_name: &str,
) -> anyhow::Result<String> {
    std::fs::create_dir_all(output_dir)?;
    let path = format!("{}/{}.tx", output_dir, file_name);
    std::fs::write(&path, bitcoin::consensus::encode::serialize_hex(tx))?;
    Ok(path)
}

pub fn wrap_network(network: &str) -> Network {
    match network {
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        "testnet" => Network::Testnet,
        _ => todo!(),
    }
}
