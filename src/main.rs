//! ColliderVM Signet Demo Binary
//!
//! This binary generates **real Bitcoin Signet transactions** that execute the
//! two‑step `F1/F2` ColliderVM toy program on‑chain.  It bridges the gap
//! between the purely in‑memory simulation (`src/simulation.rs`) and an actual
//! end‑to‑end flow that users can broadcast on Signet.
//!
//! # High‑level flow
//! 1.  **Key generation** – by default the program creates one Signer key and
//!     one Operator key and prints them (WIF + address).
//! 2.  **Funding phase** – if the user has _not_ supplied a `funding_txid`, the
//!     program prints clear CLI instructions telling the user how to fund the
//!     demo address on Signet and exits.
//! 3.  **Offline phase** – given a funding UTXO, the program
//!     * finds a nonce `r` such that `H(x‖r)|_B ∈ D` (using
//!       `collidervm_toy::core::find_valid_nonce`).
//!     * chooses the corresponding flow `d` and builds the **locking script**
//!       for `F1` (and `F2`) using the existing helpers.
//!     * constructs and signs **tx_f1** (spends the funding UTXO → P2WSH locked
//!       by the `F1` program).
//! 4.  **Online phase** – it then builds and signs **tx_f2**, spending the F1
//!     output with the witness `[sig, flow_id, x, script]`, paying the remaining
//!     funds to an Operator address.
//! 5.  Both transactions are written to `f1.tx` and `f2.tx` (raw hex), and all relevant IDs / next steps are printed.
//!
//! ## Build & run
//! ```bash
//! cargo run --bin demo -- -i 150 --network regtest  # builds f1.tx + f2.tx
//! ```

#![allow(clippy::too_many_arguments)]

use bitcoin::sighash::Prevouts;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness,
    absolute,
};
use bitcoin::{CompressedPublicKey, TapLeafHash, TapSighashType};
use bitcoin::{EcdsaSighashType, hashes::Hash};
use bitcoin::{
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::SighashCache,
};
use bitcoincore_rpc::{Auth, Client, RawTx, RpcApi};
use clap::Parser;
use collidervm_toy::core::{
    blake3_message_to_limbs, build_script_f1_blake3_locked, build_script_f2_blake3_locked,
    find_valid_nonce, flow_id_to_prefix_bytes,
};
use collidervm_toy::utils::{encode_scriptnum, estimate_fee_vbytes, sk_to_wif, wait_for_confirmation, wif_to_sk};
use serde::Serialize;
use std::{fs, str::FromStr};

/// Minimal amount we ask the user to deposit (10 000 sat ≈ 0.0001 BTC)
const REQUIRED_AMOUNT_SAT: u64 = 200_000;
/// Hard‑coded ColliderVM parameters (match the toy simulation)
const L_PARAM: usize = 4;
const B_PARAM: usize = 16; // multiple of 8 ≤ 32

const OUTPUT_DIR: &str = "target/demo";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input value x (checked by F1 > 100 and F2 < 200)
    #[arg(short, long, default_value_t = 114)]
    x: u32,

    /// Dry run mode doesn't interact with Bitcoin network
    #[arg(long)]
    dry_run: bool,

    /// Fee‑rate in sat/vB (default = 1 sat/vB, plenty for Signet)
    #[arg(long, default_value_t = 1)]
    fee_rate: u64,

    /// Write JSON output to a file instead of stdout
    #[arg(long)]
    json_output_file: Option<String>,

    /// receiver of the spending tx
    #[arg(long)]
    receiver: String,

    /// Network name
    #[arg(short, long, default_value = "regtest")]
    network: String,

    /// Network RRC URL
    #[arg(short, long, default_value = "http://127.0.0.1:18443")]
    rpc_url: String,

    /// RPC user
    #[arg(long, default_value = "user")]
    rpc_user: String,

    /// RPC password
    #[arg(long, default_value = "PaSsWoRd")]
    rpc_password: String,

    /// bitcoin wallet name
    #[arg(long, default_value = "alice")]
    wallet_name: String,
    /// bitcoin wallet passphrase
    #[arg(long, default_value = "alicePsWd")]
    wallet_passphrase: String,
}

/// Structure for serializing key details to JSON
#[derive(Serialize)]
struct KeyInfo {
    pub signer: KeyPair,
    pub operator: KeyPair,
}

/// Structure for serializing individual key pairs to JSON
#[derive(Serialize)]
struct KeyPair {
    pub address: String,
    pub wif: String,
}

/// Structure for serializing transaction details to JSON
#[derive(Serialize)]
struct TransactionInfo {
    f1: TxInfo,
    f2: TxInfo,
    nonce: u64,
    flow_id: u32,
}

/// Structure for serializing individual transaction information
#[derive(Serialize)]
struct TxInfo {
    txid: String,
    file_path: String,
}

/// Complete demo output for JSON serialization
#[derive(Serialize)]
struct DemoOutput {
    pub keys: KeyInfo,
    transactions: Option<TransactionInfo>,
    input_x: u32,
    parameters: DemoParameters,
}

/// Parameters used in the demo for JSON serialization
#[derive(Serialize)]
struct DemoParameters {
    required_amount_sat: u64,
    l_param: usize,
    b_param: usize,
}

fn wrap_network(network: &str) -> Network {
    match network {
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        "testnet" => Network::Testnet,
        _ => todo!(),
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let rpc_client = Client::new(
        &format!("{}/wallet/{}", args.rpc_url, args.wallet_name),
        Auth::UserPass(args.rpc_user.clone(), args.rpc_password.clone()),
    )
    .expect(
        "Failed to connect to bitcoind, check out scripts/README.md to launch a Bitcoin testnet",
    );

    let network = wrap_network(args.network.as_str());

    // 0. Generate Signer & Operator keys (for demo we use 1‑of‑1)
    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();

    let (sk_signer, pk_signer) = secp.generate_keypair(&mut rand::thread_rng());
    let (sk_operator, pk_operator) = secp.generate_keypair(&mut rand::thread_rng());

    let signer_compressed_pk = CompressedPublicKey::try_from(bitcoin::PublicKey::new(pk_signer))?;
    let signer_addr = Address::p2wpkh(&signer_compressed_pk, network);

    let operator_compressed_pk = CompressedPublicKey::try_from(PublicKey::new(pk_operator))?;
    let operator_addr = Address::p2wpkh(&operator_compressed_pk, network);

    // // Prepare key information for output
    // let key_info = KeyInfo {
    //     signer: KeyPair {
    //         address: signer_addr.to_string(),
    //         wif: sk_to_wif(&sk_signer, network),
    //     },
    //     operator: KeyPair {
    //         address: operator_addr.to_string(),
    //         wif: sk_to_wif(&sk_operator, network),
    //     },
    // };

    // // For debug
    // let sk_expected = wif_to_sk(&key_info.signer.wif);
    // assert_eq!(sk_expected, sk_signer);

    // // Prepare demo output structure for JSON output
    // let mut demo_output = DemoOutput {
    //     keys: key_info,
    //     transactions: None,
    //     input_x: args.x,
    //     parameters: DemoParameters {
    //         required_amount_sat: REQUIRED_AMOUNT_SAT,
    //         l_param: L_PARAM,
    //         b_param: B_PARAM,
    //     },
    // };

    // // If dry-run mode, print key information in formatted text
    // if args.dry_run {
    //     println!(
    //         "{}\n  Signer  → {} (WIF {})\n  Operator→ {} (WIF {})\n{}",
    //         "Generated demo keys:".bold().blue(),
    //         signer_addr,
    //         sk_to_wif(&sk_signer, network),
    //         operator_addr,
    //         sk_to_wif(&sk_operator, network),
    //         "---------------------------------------------".dimmed()
    //     );
    // }

    // Output JSON without transaction info
    // let json_output = serde_json::to_string_pretty(&demo_output)?;

    // If a JSON output file is specified, write to it
    // if let Some(file_path) = &args.json_output_file {
    //     fs::create_dir_all(
    //         std::path::Path::new(file_path)
    //             .parent()
    //             .unwrap_or(std::path::Path::new("./")),
    //     )?;
    //     fs::write(file_path, &json_output)?;
    // } else {
    //     // Otherwise print to stdout
    //     println!("{json_output}");
    // }

    // --------------------------------------------------------------------
    // 1. Parse CLI funding UTXO
    // --------------------------------------------------------------------
    let (funding_txid, funding_vout) = if args.dry_run {
        // In dry run mode, use a placeholder txid
        (Txid::all_zeros(), 0)
    } else {
        // In normal mode
        let funding_tx = rpc_client.send_to_address(
            &signer_addr,
            Amount::from_sat(REQUIRED_AMOUNT_SAT),
            None,
            None,
            None,
            None,
            None,
            None,
        ).map_err(|err| {
            panic!(
                "Error: {}, please run:\n
docker exec -it bitcoind-regtest bitcoin-cli -{} --rpcuser={} --rpcpassword={} walletpassphrase {} 600\n",
                err, args.network, args.rpc_user, args.rpc_password, args.wallet_passphrase
            );
        }).unwrap();

        let confirmed_funding_tx = rpc_client.get_raw_transaction(&funding_tx, None)?;
        let tx_out_sp_0 = &confirmed_funding_tx.output[0].script_pubkey;
        let vout = if *tx_out_sp_0 == signer_addr.script_pubkey() {
            0
        } else {
            1
        };

        (funding_tx, vout)
    };
    let funding_outpoint = OutPoint {
        txid: funding_txid,
        vout: funding_vout,
    };

    // In a production‑ready tool we would RPC‑query the node to retrieve the
    // exact amount & pkScript of the funding UTXO.  To keep the demo
    // self‑contained we *assume* the UTXO pays `REQUIRED_AMOUNT_SAT` to the
    // Signer's P2WPKH address.  The instructions ensured the user sends that.
    let funding_value_sat = REQUIRED_AMOUNT_SAT;

    // --------------------------------------------------------------------
    // 2. Find nonce r & flow‑id d  (operator work)
    // --------------------------------------------------------------------
    let (nonce, flow_id, _hash) =
        find_valid_nonce(args.x, B_PARAM, L_PARAM).expect("nonce search should succeed quickly");

    println!(
        "Found nonce r = {nonce} selecting flow d = {flow_id} (B={B_PARAM} bits, L={L_PARAM})"
    );

    // --------------------------------------------------------------------
    // 3. Build locking scripts for F1 & F2 (for the chosen flow)
    // --------------------------------------------------------------------
    let flow_id_prefix = flow_id_to_prefix_bytes(flow_id, B_PARAM);

    // let f1_lock =
    //     build_script_f1_blake3_locked(&PublicKey::new(pk_signer), &flow_id_prefix, B_PARAM);

    let sk_keypair = Keypair::from_secret_key(&secp, &sk_signer);
    // let x_only_pk = secp256k1::XOnlyPublicKey::from_keypair(&sk_keypair).0;
    // let f2_lock =
    //     build_script_f2_blake3_locked(&PublicKey::new(pk_signer), &flow_id_prefix, B_PARAM);


    fs::create_dir_all(OUTPUT_DIR)?;

    // 4. Construct tx_f1

    let (tx_f1, f1_lock, f1_spend_info) = create_and_sign_tx_f1(
         &secp,
         &sk_keypair,
         network,
         funding_outpoint,
         funding_value_sat,
        &flow_id_prefix,
         args.fee_rate,
     )?;

     let (tx_f2, f2_lock, f2_spend_info) = create_and_sign_tx_f2(
        &secp,
        &sk_keypair,
        &tx_f1,
        tx_f1.output[0].value.to_sat(),
        &f1_lock,
        &f1_spend_info,
        network,
        &flow_id_prefix,
        args.fee_rate,
        args.x,
        nonce,
    )?;

    let receiver_addr = Address::from_str(&args.receiver)?.require_network(network)?;
    let (spending_tx, _) = create_and_sign_spending_tx(
        &secp,
        &sk_keypair,
        &tx_f2,
        tx_f2.output[0].value.to_sat(),
        receiver_addr,
        &f2_lock,
        &f2_spend_info,
        args.fee_rate,
        args.x,
        nonce,
    )?;

    // // Update transaction information for JSON output
    // demo_output.transactions = Some(TransactionInfo {
    //     f1: TxInfo {
    //         txid: tx_f1_id.to_string(),
    //         file_path: f1_file_path,
    //     },
    //     f2: TxInfo {
    //         txid: tx_f2_id.to_string(),
    //         file_path: f2_file_path,
    //     },
    //     nonce,
    //     flow_id,
    // });

    // // If JSON output is requested, print the full JSON structure
    // let json_output = serde_json::to_string_pretty(&demo_output)?;

    // // If a JSON output file is specified, write to it
    // if let Some(file_path) = &args.json_output_file {
    //     fs::create_dir_all(
    //         std::path::Path::new(file_path)
    //             .parent()
    //             .unwrap_or(std::path::Path::new("./")),
    //     )?;
    //     fs::write(file_path, &json_output)?;
    // } else {
    //     // Otherwise print to stdout
    //     println!("{json_output}");
    // }

    if !args.dry_run {
        println!("▶️  Pushed f1, txid: {}", tx_f1.compute_txid());
        let f1_txid = rpc_client.send_raw_transaction(&tx_f1)?;
        wait_for_confirmation(&rpc_client, &f1_txid, 1, 60)?;

        println!("▶️  Pushed f2, txid: {}", tx_f2.compute_txid());
        let f2_txid = rpc_client.send_raw_transaction(&tx_f2)?;
        wait_for_confirmation(&rpc_client, &f2_txid, 1, 60)?;

        println!(
            "▶️  Pushed spending tx, txid: {}",
            spending_tx.compute_txid()
        );
        let spending_tx_txid = rpc_client.send_raw_transaction(&spending_tx)?;
        wait_for_confirmation(&rpc_client, &spending_tx_txid, 1, 60)?;
    }

    Ok(())
}

// --------------------------------------------------------------------
// Transaction Creation Functions
// --------------------------------------------------------------------

/// Creates and signs tx_f1, spending the funding UTXO to the F1 Taproot address.
fn create_and_sign_tx_f1(
    secp: &Secp256k1<secp256k1::All>,
    sk_keypair: &Keypair,
    network: Network,
    funding_outpoint: OutPoint,
    funding_value_sat: u64,
    flow_id_prefix: &[u8],
    fee_rate: u64,
) -> anyhow::Result<(bitcoin::Transaction, ScriptBuf, TaprootSpendInfo)> {

    // ── build F1 locking script ─────────────────────────────────────────
    let pk_signer   = sk_keypair.public_key();
    let lock = build_script_f1_blake3_locked(
        &bitcoin::PublicKey::new(pk_signer),
        flow_id_prefix,
        B_PARAM,
    );

    // ── wrap in a Taproot tree & derive its address ─────────────────────
    let x_only_pk   = secp256k1::XOnlyPublicKey::from_keypair(sk_keypair).0;
    let spend_info  = TaprootBuilder::new()
        .add_leaf(0, lock.clone())
        .expect("valid leaf")
        .finalize(secp, x_only_pk).unwrap();

    let tr_addr     = Address::p2tr_tweaked(spend_info.output_key(), network);

    let fee_f1 = estimate_fee_vbytes(155, fee_rate); // ~1 input + 1 output
    let f1_output_value = funding_value_sat
        .checked_sub(fee_f1)
        .expect("funding not sufficient for fee");

    let mut tx_f1 = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(f1_output_value),
            script_pubkey: tr_addr.script_pubkey(),
        }],
    };

    // Sign the funding input (P2WPKH)
    let signer_addr = Address::p2wpkh(
        &CompressedPublicKey::try_from(bitcoin::PublicKey::new(sk_keypair.public_key()))?,
        network,
    );
    let signer_pkh = signer_addr
        .witness_program()
        .expect("addr")
        .program() // 20 bytes = hash160(pubkey)
        .to_owned();
    let script_code =
        ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_slice(signer_pkh.as_bytes())?);
    let mut sighash_cache = SighashCache::new(&mut tx_f1);
    let sighash = sighash_cache.p2wsh_signature_hash(
        0,
        &script_code,
        Amount::from_sat(funding_value_sat),
        EcdsaSighashType::All,
    )?;
    let sig = secp.sign_ecdsa(&Message::from_digest_slice(&sighash[..])?, &sk_keypair.secret_key());
    let mut sig_ser = sig.serialize_der().to_vec();
    sig_ser.push(EcdsaSighashType::All as u8);
    tx_f1.input[0].witness = Witness::from_slice(&[sig_ser, sk_keypair.public_key().serialize().to_vec()]);

    Ok((tx_f1, lock, spend_info))
}

/// Creates and signs tx_f2, spending the F1 output to the F2 Taproot address.
fn create_and_sign_tx_f2(
    secp: &Secp256k1<secp256k1::All>,
    sk_keypair: &Keypair,
    tx_f1: &bitcoin::Transaction,
    f1_output_value: u64,
    f1_lock: &ScriptBuf,
    f1_spend_info: &TaprootSpendInfo,
    network: Network,
    flow_id_prefix: &[u8],
    fee_rate: u64,
    x_val: u32,
    nonce: u64,
) -> anyhow::Result<(bitcoin::Transaction, ScriptBuf, TaprootSpendInfo)> {

     // ── build F2 locking script & Taproot branch ────────────────────────
    let pk_signer   = sk_keypair.public_key();
    let f2_lock = build_script_f2_blake3_locked(
        &bitcoin::PublicKey::new(pk_signer),
        flow_id_prefix,
        B_PARAM,
    );
    let x_only_pk   = secp256k1::XOnlyPublicKey::from_keypair(sk_keypair).0;
    let spend_info  = TaprootBuilder::new()
        .add_leaf(0, f2_lock.clone())
        .expect("valid leaf")
        .finalize(secp, x_only_pk).unwrap();
    let tr_addr     = Address::p2tr_tweaked(spend_info.output_key(), network);

    // Now the tx vsize is about 17093.
    let fee_f2 = estimate_fee_vbytes(17093, fee_rate); // 1 input P2TR + 1 output
    let f2_output_value = f1_output_value
        .checked_sub(fee_f2)
        .expect("f1 output too small for f2 fee");

    let mut tx_f2 = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx_f1.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(f2_output_value),
            script_pubkey: tr_addr.script_pubkey(),
        }],
    };

    // Build the witness stack for the P2TR spend
    let leaf_hash = TapLeafHash::from_script(f1_lock, LeafVersion::TapScript);

    let mut cache = SighashCache::new(&mut tx_f2);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[tx_f1.output[0].clone()]),
            leaf_hash,
            TapSighashType::Default,
        )
        .unwrap();

    let msg = Message::from_digest_slice(&sighash[..])?;
    let sig = secp.sign_schnorr(&msg, sk_keypair);
    let sig_f2_ser = sig.serialize().to_vec();

    // Assemble witness
    let control_block = f1_spend_info
        .control_block(&(f1_lock.clone(), LeafVersion::TapScript))
        .unwrap();

    // Encode input_value || nonce
    let message = [
        x_val.to_le_bytes(),
        nonce.to_le_bytes()[0..4].try_into()?,
        nonce.to_le_bytes()[4..8].try_into()?,
    ]
    .concat();

    let mut witness = Witness::new();
    for limb in blake3_message_to_limbs(&message, 4) {
        witness.push(encode_scriptnum(limb.into()));
    }

    witness.push(sig_f2_ser);
    witness.push(f1_lock.to_bytes());
    witness.push(control_block.serialize());

    tx_f2.input[0].witness = witness;

    // let f2_file_path = format!("{OUTPUT_DIR}/f2.tx");
    Ok((tx_f2, f2_lock, spend_info))
}

/// Creates and signs the spending transaction, spending the F2 output to the receiver.
fn create_and_sign_spending_tx(
    secp: &Secp256k1<secp256k1::All>,
    sk_keypair: &Keypair,
    tx_f2: &bitcoin::Transaction,
    f2_output_value: u64,
    receiver_addr: Address,
    f2_lock: &ScriptBuf,
    f2_spend_info: &TaprootSpendInfo,
    fee_rate: u64,
    x_val: u32,
    nonce: u64,
) -> anyhow::Result<(bitcoin::Transaction, String)> {
    let fee_spending_tx = estimate_fee_vbytes(17082, fee_rate); // 1 input P2TR + 1 output
    let spending_output_value = f2_output_value
        .checked_sub(fee_spending_tx)
        .expect("f2 output too small for spending tx");

    let mut spending_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx_f2.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(spending_output_value),
            script_pubkey: receiver_addr.script_pubkey(),
        }],
    };

    // Build the witness stack for the P2TR spend
    let leaf_hash = TapLeafHash::from_script(f2_lock, LeafVersion::TapScript);

    let mut cache = SighashCache::new(&mut spending_tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[tx_f2.output[0].clone()]),
            leaf_hash,
            TapSighashType::Default,
        )
        .unwrap();

    let msg = Message::from_digest_slice(&sighash[..])?;
    let sig = secp.sign_schnorr(&msg, sk_keypair);
    let sig_spending_ser = sig.serialize().to_vec();

    // Assemble witness
    let control_block = f2_spend_info
        .control_block(&(f2_lock.clone(), LeafVersion::TapScript))
        .unwrap();

    // Encode input_value || nonce
    let message = [
        x_val.to_le_bytes(),
        nonce.to_le_bytes()[0..4].try_into()?,
        nonce.to_le_bytes()[4..8].try_into()?,
    ]
    .concat();

    let mut witness = Witness::new();
    for limb in blake3_message_to_limbs(&message, 4) {
        witness.push(encode_scriptnum(limb.into()));
    }

    witness.push(sig_spending_ser);
    witness.push(f2_lock.to_bytes());
    witness.push(control_block.serialize());

    spending_tx.input[0].witness = witness;

    let spending_tx_file_path = format!("{OUTPUT_DIR}/spending.tx"); // Optional, but consistent
    Ok((spending_tx, spending_tx_file_path))
}



