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
//! cargo run -- --receiver bcrt1qz3fps2lxvrp5rqj8ucsqrzjx2c3md9gawqr3l6
//! ```

#![allow(clippy::too_many_arguments)]

use bitcoin::Network;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, OutPoint, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use clap::Parser;
use collidervm_toy::core::{find_valid_nonce, flow_id_to_prefix_bytes};
use collidervm_toy::musig2::{re_export, simulate_musig};
use collidervm_toy::transactions::{
    create_and_sign_spending_tx, create_and_sign_spending_tx_finish,
    create_and_sign_tx_f1, create_and_sign_tx_f1_finish, create_and_sign_tx_f2,
    create_and_sign_tx_f2_finish,
};
use collidervm_toy::utils::{
    wait_for_confirmation, wrap_network, write_transaction_to_file,
};
use std::str::FromStr;

mod output;
use output::{
    DemoOutput, DemoParameters, KeyInfo, KeyPair, TransactionInfo, TxInfo,
    write_demo_output_to_file,
};

/// Minimal amount we ask the user to deposit (10 000 sat ≈ 0.0001 BTC)
const REQUIRED_AMOUNT_SAT: u64 = 200_000;
/// Hard‑coded ColliderVM parameters (match the toy simulation)
const L_PARAM: usize = 4;
const B_PARAM: usize = 16; // multiple of 8 ≤ 32

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
    #[arg(long, default_value = "target/demo")]
    output_dir: String,

    /// Write JSON output to a file instead of stdout
    #[arg(long, default_value = "demo.json")]
    output_file: String,

    /// receiver of the spending tx
    #[arg(
        long,
        default_value = "bcrt1qz3fps2lxvrp5rqj8ucsqrzjx2c3md9gawqr3l6"
    )]
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

    let secp: Secp256k1<bitcoin::secp256k1::All> = Secp256k1::new();

    //let (sk_signer, pk_signer) = secp.generate_keypair(&mut rand::thread_rng());

    let sk_signers = collidervm_toy::musig2::generate_keys::<3>();
    let pk_signers = sk_signers.iter().map(|key| key.1).collect::<Vec<_>>();
    let agg_ctx = musig2::KeyAggContext::new(pk_signers)?;
    let pk_signer: musig2::secp256k1::PublicKey = agg_ctx.aggregated_pubkey();

    // let (sk_operator, pk_operator) =
    //     secp.generate_keypair(&mut rand::thread_rng());

    //let signer_compressed_pk =
    //    CompressedPublicKey::try_from(bitcoin::PublicKey::new(pk_signer))?;
    //let signer_addr = Address::p2wpkh(&signer_compressed_pk, network);

    // let operator_compressed_pk =
    //     CompressedPublicKey::try_from(PublicKey::new(pk_operator))?;
    // let operator_addr = Address::p2wpkh(&operator_compressed_pk, network);

    let funding_outpoint = if args.dry_run {
        OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        }
    } else {
        get_funding_outpoint(
            &rpc_client,
            network,
            &re_export(pk_signer),
            REQUIRED_AMOUNT_SAT,
        )
    };

    // In a production‑ready tool we would RPC‑query the node to retrieve the
    // exact amount & pkScript of the funding UTXO.  To keep the demo
    // self‑contained we *assume* the UTXO pays `REQUIRED_AMOUNT_SAT` to the
    // Signer's P2WPKH address.  The instructions ensured the user sends that.
    let funding_value_sat = REQUIRED_AMOUNT_SAT;

    let (nonce, flow_id) = find_valid_nonce(args.x, B_PARAM, L_PARAM)
        .expect("nonce search should succeed quickly");

    println!(
        "Found nonce r = {nonce} selecting flow d = {flow_id} (B={B_PARAM} bits, L={L_PARAM})"
    );

    let flow_id_prefix = flow_id_to_prefix_bytes(flow_id, B_PARAM);

    //let sk_keypair = Keypair::from_secret_key(&secp, &sk_signer);
    //let pk_keypair = sk_keypair.public_key();

    let (
        mut f1_tx,
        f1_lock,
        f1_spend_info,
        funding_script,
        funding_spend_info,
        message,
    ) = create_and_sign_tx_f1(
        B_PARAM,
        &secp,
        &re_export(pk_signer),
        &network,
        &funding_outpoint,
        &funding_value_sat,
        &flow_id_prefix,
        &args.fee_rate,
    )?;
    let final_signature = simulate_musig(&sk_signers, &message);
    create_and_sign_tx_f1_finish(
        final_signature,
        &funding_spend_info,
        &funding_script,
        &mut f1_tx,
    );

    let (mut f2_tx, f2_lock, f2_spend_info, message) = create_and_sign_tx_f2(
        B_PARAM,
        &secp,
        &re_export(pk_signer),
        &network,
        &f1_tx,
        &f1_output_value,
        &f1_lock,
        &flow_id_prefix,
        &args.fee_rate,
    )?;
    let final_signature = simulate_musig(&sk_signers, &message);
    create_and_sign_tx_f2_finish(
        final_signature,
        &f1_spend_info,
        &f1_lock,
        &mut f2_tx,
        &args.x,
        &nonce,
    );

    let receiver_addr =
        Address::from_str(&args.receiver)?.require_network(network)?;

    let (mut spending_tx, message) = create_and_sign_spending_tx(
        &f2_tx,
        &f2_output_value,
        &receiver_addr,
        &f2_lock,
        &args.fee_rate,
    )?;
    let final_signature = simulate_musig(&sk_signers, &message);
    create_and_sign_spending_tx_finish(
        final_signature,
        &f2_spend_info,
        &f2_lock,
        &mut spending_tx,
        &args.x,
        &nonce,
    );

    let f1_tx_path = write_transaction_to_file(&f1_tx, &args.output_dir, "f1")?;
    let f2_tx_path = write_transaction_to_file(&f2_tx, &args.output_dir, "f2")?;
    let spending_tx_path =
        write_transaction_to_file(&spending_tx, &args.output_dir, "spending")?;

    let signers = sk_signers
        .iter()
        .map(|key| KeyPair {
            wif: bitcoin::PrivateKey::new(re_export(key.0), network).to_wif(),
        })
        .collect::<Vec<_>>();
    let demo_output = DemoOutput {
        keys: KeyInfo {
            signers,
            //KeyPair {
            //    //address: signer_addr.to_string(),
            //    //wif: bitcoin::PrivateKey::new(re_export(sk_signers[0]), network).to_wif(),
            //},
            // operator: KeyPair {
            //     address: receiver_addr.to_string(),
            //     wif: "".to_string(), // TODO
            // },
        },
        transactions: Some(TransactionInfo {
            f1: TxInfo {
                txid: f1_tx.compute_txid().to_string(),
                file_path: f1_tx_path,
            },
            f2: TxInfo {
                txid: f2_tx.compute_txid().to_string(),
                file_path: f2_tx_path,
            },
            spending: TxInfo {
                txid: spending_tx.compute_txid().to_string(),
                file_path: spending_tx_path,
            },
            nonce,
            flow_id,
        }),
        input_x: args.x,
        parameters: DemoParameters {
            required_amount_sat: REQUIRED_AMOUNT_SAT,
            l_param: L_PARAM,
            b_param: B_PARAM,
        },
    };

    write_demo_output_to_file(
        &demo_output,
        &args.output_dir,
        &args.output_file,
    )?;

    if !args.dry_run {
        println!("▶️  Pushed f1, txid: {}", f1_tx.compute_txid());
        let f1_txid = rpc_client.send_raw_transaction(&f1_tx)?;
        wait_for_confirmation(&rpc_client, &f1_txid, 1, 60)?;

        println!("▶️  Pushed f2, txid: {}", f2_tx.compute_txid());
        let f2_txid = rpc_client.send_raw_transaction(&f2_tx)?;
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

/// create a funding taproot address, and demo the spending tx with musig2
fn create_funding_taproot_address(
    pubkey: &PublicKey,
    network: Network,
) -> Address {
    let secp = Secp256k1::new();
    let xonly_pk = XOnlyPublicKey::from(*pubkey);
    let leaf_script = bitcoin::script::Builder::new()
        .push_x_only_key(&xonly_pk)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script();

    let spend_info = TaprootBuilder::new()
        .add_leaf(0, leaf_script.clone())
        .unwrap()
        .finalize(&secp, xonly_pk)
        .unwrap();

    // The scriptPubKey for this Taproot output and the address (for funding):
    Address::p2tr_tweaked(spend_info.output_key(), network)
}

fn get_funding_outpoint(
    rpc_client: &bitcoincore_rpc::Client,
    network: Network,
    signer_pubkey: &PublicKey,
    required_amount_sat: u64,
) -> bitcoin::OutPoint {
    let funding_address =
        create_funding_taproot_address(signer_pubkey, network);
    let txid = rpc_client
        .send_to_address(
            &funding_address,
            bitcoin::Amount::from_sat(required_amount_sat),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .map_err(|err| panic!("Error: {err}"))
        .unwrap();
    println!("Funding tx: {txid}");
    wait_for_confirmation(rpc_client, &txid, 1, 60).unwrap();

    let confirmed_funding_tx =
        rpc_client.get_raw_transaction(&txid, None).unwrap();
    let tx_out_sp_0 = &confirmed_funding_tx.output[0].script_pubkey;
    let vout = if *tx_out_sp_0 == funding_address.script_pubkey() {
        0
    } else {
        1
    };

    bitcoin::OutPoint { txid, vout }
}
