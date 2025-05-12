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

use bitcoin::CompressedPublicKey;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::{Address, Amount, Network, OutPoint, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use clap::Parser;
use collidervm_toy::core::{find_valid_nonce, flow_id_to_prefix_bytes};
use collidervm_toy::transactions::{
    create_and_sign_spending_tx, create_and_sign_tx_f1, create_and_sign_tx_f2,
};
use collidervm_toy::utils::wait_for_confirmation;
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
// #[derive(Serialize)]
// struct KeyInfo {
//     pub signer: KeyPair,
//     pub operator: KeyPair,
// }

/// Structure for serializing individual key pairs to JSON
#[derive(Serialize)]
struct KeyPair {
    pub address: String,
    pub wif: String,
}

// /// Structure for serializing transaction details to JSON
// #[derive(Serialize)]
// struct TransactionInfo {
//     f1: TxInfo,
//     f2: TxInfo,
//     nonce: u64,
//     flow_id: u32,
// }

// /// Structure for serializing individual transaction information
// #[derive(Serialize)]
// struct TxInfo {
//     txid: String,
//     file_path: String,
// }

// /// Complete demo output for JSON serialization
// #[derive(Serialize)]
// struct DemoOutput {
//     pub keys: KeyInfo,
//     transactions: Option<TransactionInfo>,
//     input_x: u32,
//     parameters: DemoParameters,
// }

// /// Parameters used in the demo for JSON serialization
// #[derive(Serialize)]
// struct DemoParameters {
//     required_amount_sat: u64,
//     l_param: usize,
//     b_param: usize,
// }


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

    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();

    let (sk_signer, pk_signer) = secp.generate_keypair(&mut rand::thread_rng());
    // let (sk_operator, pk_operator) =
    //     secp.generate_keypair(&mut rand::thread_rng());

    let signer_compressed_pk =
        CompressedPublicKey::try_from(bitcoin::PublicKey::new(pk_signer))?;
    let signer_addr = Address::p2wpkh(&signer_compressed_pk, network);

    // let operator_compressed_pk =
    //     CompressedPublicKey::try_from(PublicKey::new(pk_operator))?;
    // let operator_addr = Address::p2wpkh(&operator_compressed_pk, network);

    let funding_outpoint = if args.dry_run {
        OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        }
    } else {
        // In normal mode
        get_funding_outpoint(
            &rpc_client,
            &signer_addr,
            REQUIRED_AMOUNT_SAT,
        )
    };

    // In a production‑ready tool we would RPC‑query the node to retrieve the
    // exact amount & pkScript of the funding UTXO.  To keep the demo
    // self‑contained we *assume* the UTXO pays `REQUIRED_AMOUNT_SAT` to the
    // Signer's P2WPKH address.  The instructions ensured the user sends that.
    let funding_value_sat = REQUIRED_AMOUNT_SAT;

    // --------------------------------------------------------------------
    // 2. Find nonce r & flow‑id d  (operator work)
    // --------------------------------------------------------------------
    let (nonce, flow_id, _hash) = find_valid_nonce(args.x, B_PARAM, L_PARAM)
        .expect("nonce search should succeed quickly");

    println!(
        "Found nonce r = {nonce} selecting flow d = {flow_id} (B={B_PARAM} bits, L={L_PARAM})"
    );

    // --------------------------------------------------------------------
    // 3. Build locking scripts for F1 & F2 (for the chosen flow)
    // --------------------------------------------------------------------
    let flow_id_prefix = flow_id_to_prefix_bytes(flow_id, B_PARAM);

    let sk_keypair = Keypair::from_secret_key(&secp, &sk_signer);

    let (tx_f1, f1_lock, f1_spend_info) = create_and_sign_tx_f1(
        B_PARAM,
        &secp,
        &sk_keypair,
        network,
        funding_outpoint,
        funding_value_sat,
        &flow_id_prefix,
        args.fee_rate,
    )?;

    let (tx_f2, f2_lock, f2_spend_info) = create_and_sign_tx_f2(
        B_PARAM,
        &secp,
        &sk_keypair,
        network,
        &tx_f1,
        tx_f1.output[0].value.to_sat(),
        &f1_lock,
        &f1_spend_info,
        &flow_id_prefix,
        args.fee_rate,
        args.x,
        nonce,
    )?;

    let receiver_addr =
        Address::from_str(&args.receiver)?.require_network(network)?;

    let spending_tx = create_and_sign_spending_tx(
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

fn wrap_network(network: &str) -> Network {
    match network {
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        "testnet" => Network::Testnet,
        _ => todo!(),
    }
}

fn get_funding_outpoint(
    rpc_client: &bitcoincore_rpc::Client,
    signer_addr: &bitcoin::Address,
    required_amount_sat: u64,
) -> bitcoin::OutPoint {
    let txid = rpc_client.send_to_address(
        signer_addr,
        bitcoin::Amount::from_sat(required_amount_sat),
        None,
        None,
        None,
        None,
        None,
        None,
    ).map_err(|err| {
        panic!("Error: {}", err)
    }).unwrap();

    let confirmed_funding_tx = rpc_client.get_raw_transaction(&txid, None).unwrap();
    let tx_out_sp_0 = &confirmed_funding_tx.output[0].script_pubkey;
    let vout = if *tx_out_sp_0 == signer_addr.script_pubkey() {
        0
    } else {
        1
    };

    bitcoin::OutPoint {
        txid,
        vout,
    }
}
