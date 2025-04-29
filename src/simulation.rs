// src/simulation.rs

use colored::*;
use std::{collections::HashMap, error::Error, thread, time::Duration};

use bitcoin::{
    Amount, OutPoint, PublicKey, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    blockdata::script::{Builder, ScriptBuf},
    script::PushBytesBuf,
};
use bitvm::{execute_script_buf, hash::blake3::blake3_push_message_script_with_limb};
use secp256k1::{Keypair, Secp256k1};

use crate::core::{
    ColliderVmConfig, F1_THRESHOLD, F2_THRESHOLD, OperatorInfo, PresignedFlow, PresignedStep,
    SignerInfo, build_script_f1_blake3_locked, build_script_f2_blake3_locked,
    create_toy_sighash_message, find_valid_nonce, flow_id_to_prefix_bytes,
};

/// Stores the results of a ColliderVM simulation run.
#[allow(dead_code)]
pub struct SimulationResult {
    /// Did the entire simulation succeed (F1 & F2 both pass)?
    pub success: bool,
    /// F1 script outcome
    pub f1_result: bool,
    /// F2 script outcome
    pub f2_result: bool,
    /// Summary message
    pub message: String,
}

/// Type alias: the output of offline_setup => (signers, operators, map_of_flows)
type SetupResult = (
    Vec<SignerInfo>,
    Vec<OperatorInfo>,
    HashMap<u32, PresignedFlow>,
);

/// Creates a placeholder transaction for demonstration.
fn create_placeholder_tx(
    locking_script: ScriptBuf,
    value: Amount,
    input_txid: Txid,
    input_vout: u32,
) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: input_txid,
                vout: input_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: locking_script,
        }],
    }
}

/// Offline Setup: generate signers, operators, presigned flows, etc.
pub fn offline_setup(config: &ColliderVmConfig) -> Result<SetupResult, Box<dyn Error>> {
    println!("\n{}", "--- Phase 1: Offline Setup ---".bold().yellow());
    println!(
        "{}",
        "(Signers generate keys and presign all transaction flows)".dimmed()
    );
    thread::sleep(Duration::from_millis(500)); // Small pause

    println!(
        "\nGenerating {} signers and {} operators...",
        config.n.to_string().cyan(),
        config.m.to_string().cyan()
    );
    thread::sleep(Duration::from_millis(200));

    // Initialize Secp256k1 context for key operations
    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
    let mut signers = Vec::with_capacity(config.n);
    let mut operators = Vec::with_capacity(config.m);

    // Generate signers
    println!("Generating Signer keys...");
    for i in 0..config.n {
        let (sk, pk) = secp.generate_keypair(&mut rand::thread_rng());
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = keypair.x_only_public_key();
        let si = SignerInfo {
            id: i,
            pubkey: PublicKey::new(pk),
            privkey: sk,
            keypair,
            xonly,
        };
        println!(
            "  {} {}: {}",
            "Generated Signer".dimmed(),
            i,
            si.pubkey.to_string().green()
        );
        signers.push(si);
        thread::sleep(Duration::from_millis(50)); // Tiny pause per key
    }

    // Generate operators
    println!("\nGenerating Operator keys...");
    for j in 0..config.m {
        let (sk, pk) = secp.generate_keypair(&mut rand::thread_rng());
        let op = OperatorInfo {
            id: j,
            pubkey: PublicKey::new(pk),
            privkey: sk,
        };
        println!(
            "  {} {}: {}",
            "Generated Operator".dimmed(),
            j,
            op.pubkey.to_string().blue()
        );
        operators.push(op);
        thread::sleep(Duration::from_millis(50)); // Tiny pause per key
    }

    // We'll create up to 2^L flows, but cap at 16 in this toy.
    let num_flows = std::cmp::min(1u64 << config.l, 16) as u32;
    println!(
        "\n{} {} flows (Transaction Templates + Signatures)...",
        "Generating".yellow(),
        num_flows.to_string().cyan()
    );
    thread::sleep(Duration::from_millis(300));
    println!(
        "  {}",
        format!(
            "(Targeting {} flows for this demo, L={}, B={}, max 16)",
            num_flows, config.l, config.b
        )
        .dimmed()
    );

    let mut flows_map = HashMap::new();

    // A dummy funding TXID
    let funding_txid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        .parse::<Txid>()
        .unwrap();
    let funding_vout = 0;
    let funding_amount = Amount::from_sat(10_000);

    // We'll have just one signer sign everything (signer[0]) for simplicity
    let signer0 = &signers[0];
    let secp_sign = Secp256k1::signing_only();

    for flow_id in 0..num_flows {
        // Convert the flow_id to a prefix (now returns nibbles)
        let prefix_nibbles: Vec<u8> = flow_id_to_prefix_bytes(flow_id, config.b);

        // Build the F1 script
        let f1_script = build_script_f1_blake3_locked(&signer0.pubkey, &prefix_nibbles, config.b);
        // Tx template
        let tx_f1 = create_placeholder_tx(
            f1_script.clone(),
            funding_amount,
            funding_txid,
            funding_vout,
        );
        // Create sighash
        let sighash_f1 = create_toy_sighash_message(&f1_script, tx_f1.output[0].value);
        // sign
        let mut sigs_f1 = HashMap::new();
        let sig_f1 = secp_sign.sign_schnorr(&sighash_f1, &signer0.keypair);
        sigs_f1.insert(signer0.pubkey.to_bytes(), sig_f1);

        let step_f1 = PresignedStep {
            tx_template: tx_f1.clone(),
            sighash_message: sighash_f1,
            signatures: sigs_f1,
            locking_script: f1_script,
        };

        // Build the F2 script
        let f2_script = build_script_f2_blake3_locked(&signer0.pubkey, &prefix_nibbles, config.b);
        // Tx template F2 depends on TxF1
        let tx_f2 =
            create_placeholder_tx(f2_script.clone(), funding_amount, tx_f1.compute_txid(), 0);
        let sighash_f2 = create_toy_sighash_message(&f2_script, tx_f2.output[0].value);
        let mut sigs_f2 = HashMap::new();
        let sig_f2 = secp_sign.sign_schnorr(&sighash_f2, &signer0.keypair);
        sigs_f2.insert(signer0.pubkey.to_bytes(), sig_f2);

        let step_f2 = PresignedStep {
            tx_template: tx_f2,
            sighash_message: sighash_f2,
            signatures: sigs_f2,
            locking_script: f2_script,
        };

        flows_map.insert(
            flow_id,
            PresignedFlow {
                flow_id,
                steps: vec![step_f1, step_f2],
            },
        );
        // Progress indicator
        if flow_id % (num_flows / 4).max(1) == (num_flows / 4).max(1) - 1
            || flow_id == num_flows - 1
        {
            println!(
                "  {} flow d={}...",
                "Created and presigned".dimmed(),
                flow_id
            );
            thread::sleep(Duration::from_millis(100));
        }
    }

    println!(
        "\n{} {} flows presigned by {} signers.",
        "Offline setup complete.".bold().green(),
        flows_map.len().to_string().cyan(),
        config.n.to_string().cyan()
    );
    println!(
        "{}",
        "-----------------------------------------------------".yellow()
    );
    Ok((signers, operators, flows_map))
}

/// Online execution: Operator picks x, finds nonce, picks flow, builds script/witness, runs it.
pub fn online_execution(
    signers: &[SignerInfo],
    _operators: &[OperatorInfo],
    flows_map: &HashMap<u32, PresignedFlow>,
    config: &ColliderVmConfig,
    input_value: u32,
) -> Result<SimulationResult, Box<dyn Error>> {
    println!("\n{}", "--- Phase 2: Online Execution ---".bold().yellow());
    println!(
        "{}",
        "(Operator finds nonce, selects flow, executes scripts)".dimmed()
    );
    thread::sleep(Duration::from_millis(500));

    println!("\nConfiguration:");
    println!(
        "  L={}, B={}, k={}, n={}, m={}",
        config.l.to_string().cyan(),
        config.b.to_string().cyan(),
        config.k.to_string().cyan(),
        config.n.to_string().cyan(),
        config.m.to_string().cyan()
    );
    println!("Input value (x): {}", input_value.to_string().cyan());
    thread::sleep(Duration::from_millis(300));

    // 1) find a valid nonce => flow_id
    println!(
        "\n{}: Finding Nonce (r) and Flow ID (d) for input x={}...",
        "Operator Action".bold().blue(),
        input_value
    );
    let (nonce, flow_id, _hash) = find_valid_nonce(input_value, config.b, config.l)?;
    println!(
        "  {} Nonce (r): {}, Required Flow ID (d): {}",
        "Found!".bold().green(),
        nonce.to_string().cyan(),
        flow_id.to_string().cyan()
    );
    thread::sleep(Duration::from_millis(300));

    // retrieve that presigned flow
    println!(
        "\n{}: Retrieving presigned flow d={}...",
        "Operator Action".bold().blue(),
        flow_id
    );
    let flow = flows_map
        .get(&flow_id)
        .ok_or_else(|| format!("No presigned flow for flow_id={flow_id}"))?;
    println!(
        "  {} Retrieved presigned flow d={}",
        "Success:".green(),
        flow_id
    );
    thread::sleep(Duration::from_millis(300));

    // We'll do a basic off-chain check of the signature from Signer0
    println!(
        "\n{}",
        "--- Off-Chain Check Results (Informational) ---".dimmed()
    );
    let secp_verify = Secp256k1::verification_only();
    let signer0 = &signers[0];

    let step_f1 = &flow.steps[0];
    let sig_f1 = step_f1
        .signatures
        .get(&signer0.pubkey.to_bytes())
        .ok_or("Signer0 sig missing for F1")?;
    let step_f2 = &flow.steps[1];
    let sig_f2 = step_f2
        .signatures
        .get(&signer0.pubkey.to_bytes())
        .ok_or("Signer0 sig missing for F2")?;

    let sig_ok_f1 = secp_verify
        .verify_schnorr(sig_f1, &step_f1.sighash_message, &signer0.xonly)
        .is_ok();
    let sig_ok_f2 = secp_verify
        .verify_schnorr(sig_f2, &step_f2.sighash_message, &signer0.xonly)
        .is_ok();

    println!(
        "  {} F1 Signature Valid (Signer 0): {}",
        "Check:".dimmed(),
        sig_ok_f1
            .to_string()
            .color(if sig_ok_f1 { Color::Green } else { Color::Red })
    );
    println!(
        "  {} F2 Signature Valid (Signer 0): {}",
        "Check:".dimmed(),
        sig_ok_f2
            .to_string()
            .color(if sig_ok_f2 { Color::Green } else { Color::Red })
    );
    println!(
        "{}",
        "---------------------------------------------".dimmed()
    );
    thread::sleep(Duration::from_millis(500));

    // Create PushBytesBuf for all raw bytes for F1
    let sig_f1_buf =
        PushBytesBuf::try_from(sig_f1.as_ref().to_vec()).expect("sig_f1 conversion failed");

    // Now let's construct the message dynamically
    // Message is input_value, nonce[0..4], nonce[4..8]
    let message = [
        input_value.to_le_bytes(),
        nonce.to_le_bytes()[0..4].try_into().unwrap(),
        nonce.to_le_bytes()[4..8].try_into().unwrap(),
    ]
    .concat();
    let msg_push_script_f1 = blake3_push_message_script_with_limb(&message, 4).compile();

    // -- Step F1 script
    println!(
        "\n{}: Executing Full Script Step F1 (Flow d={})...",
        "Operator Action".bold().blue(),
        flow_id
    );
    thread::sleep(Duration::from_millis(300));
    let sig_script_f1 = {
        let mut b = Builder::new();
        b = b.push_slice(sig_f1_buf);
        b.into_script()
    };

    let mut full_f1 = msg_push_script_f1.to_bytes();
    full_f1.extend(sig_script_f1.to_bytes());
    full_f1.extend(step_f1.locking_script.to_bytes());
    let exec_f1_script = ScriptBuf::from_bytes(full_f1);

    let f1_res = execute_script_buf(exec_f1_script);
    let script_f1_success = f1_res.success;
    println!(
        "    => {}: {} (Log: {:?})",
        "Execution Result".bold(),
        if script_f1_success {
            "PASSED ✅".bold().green()
        } else {
            "FAILED ❌".bold().red()
        },
        f1_res
    );
    thread::sleep(Duration::from_millis(500));

    // Create PushBytesBuf for F2 values - new instances
    let sig_f2_buf =
        PushBytesBuf::try_from(sig_f2.as_ref().to_vec()).expect("sig_f2 conversion failed");

    // -- Step F2 script
    println!(
        "\n{}: Executing Full Script Step F2 (Flow d={})...",
        "Operator Action".bold().blue(),
        flow_id
    );
    thread::sleep(Duration::from_millis(300));
    let message = [
        input_value.to_le_bytes(),
        nonce.to_le_bytes()[0..4].try_into().unwrap(),
        nonce.to_le_bytes()[4..8].try_into().unwrap(),
    ]
    .concat();
    let msg_push_script_f2 = blake3_push_message_script_with_limb(&message, 4).compile();

    let x_sig_script_f2 = {
        let mut b = Builder::new();
        b = b.push_int(input_value as i64);
        b = b.push_slice(sig_f2_buf);
        b.into_script()
    };

    let mut full_f2 = msg_push_script_f2.to_bytes();
    full_f2.extend(x_sig_script_f2.to_bytes());
    full_f2.extend(step_f2.locking_script.to_bytes());
    let exec_f2_script = ScriptBuf::from_bytes(full_f2);

    let f2_res = execute_script_buf(exec_f2_script);
    let script_f2_success = f2_res.success;
    println!(
        "    => {}: {} (Log: {:?})",
        "Execution Result".bold(),
        if script_f2_success {
            "PASSED ✅".bold().green()
        } else {
            "FAILED ❌".bold().red()
        },
        f2_res
    );
    thread::sleep(Duration::from_millis(500));

    let overall = script_f1_success && script_f2_success;
    println!("\n{}", "--- Online Execution Complete ---".yellow());

    let msg = if overall {
        format!(
            "Success: Both F1(x>{F1_THRESHOLD}) and F2(x<{F2_THRESHOLD}) checks + BLAKE3 prefix match (flow_id={flow_id})"
        )
    } else {
        format!(
            "FAIL: F1={}, F2={} for x={} flow_id={}",
            f1_res.success, f2_res.success, input_value, flow_id
        )
    };

    Ok(SimulationResult {
        success: overall,
        f1_result: script_f1_success,
        f2_result: script_f2_success,
        message: msg,
    })
}

/// Orchestrates both offline setup + online execution.
pub fn run_simulation(
    config: ColliderVmConfig,
    input_value: u32,
) -> Result<SimulationResult, Box<dyn Error>> {
    let (signers, operators, flows_map) = offline_setup(&config)?;
    let res = online_execution(&signers, &operators, &flows_map, &config, input_value)?;
    Ok(res)
}
