use anyhow;
use bitcoin::sighash::Prevouts;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf,
    Sequence, TapLeafHash, TapSighashType, TxIn, TxOut, Witness, absolute,
};
use bitcoin::{EcdsaSighashType, hashes::Hash};
use bitcoin::{
    secp256k1::{Keypair, Message, Secp256k1},
    sighash::SighashCache,
};

use crate::core::{
    blake3_message_to_limbs, build_script_f1_blake3_locked,
    build_script_f2_blake3_locked,
};
use crate::utils::{encode_scriptnum, estimate_fee_vbytes};

// --------------------------------------------------------------------
// Transaction Creation Functions
// --------------------------------------------------------------------

/// Creates and signs tx_f1, spending the funding UTXO to the F1 Taproot address.
#[allow(clippy::too_many_arguments)]
pub fn create_and_sign_tx_f1(
    b_bits: usize,
    secp: &Secp256k1<secp256k1::All>,
    sk_keypair: &Keypair,
    network: Network,
    funding_outpoint: OutPoint,
    funding_value_sat: u64,
    flow_id_prefix: &[u8],
    fee_rate: u64,
) -> anyhow::Result<(bitcoin::Transaction, ScriptBuf, TaprootSpendInfo)> {
    // ── build F1 locking script ─────────────────────────────────────────
    let pk_signer = sk_keypair.public_key();
    let lock = build_script_f1_blake3_locked(
        &bitcoin::PublicKey::new(pk_signer),
        flow_id_prefix,
        b_bits,
    );

    // ── wrap in a Taproot tree & derive its address ─────────────────────
    let x_only_pk = secp256k1::XOnlyPublicKey::from_keypair(sk_keypair).0;
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, lock.clone())
        .expect("valid leaf")
        .finalize(secp, x_only_pk)
        .unwrap();

    let tr_addr = Address::p2tr_tweaked(spend_info.output_key(), network);

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
        &CompressedPublicKey::try_from(bitcoin::PublicKey::new(
            sk_keypair.public_key(),
        ))?,
        network,
    );
    let signer_pkh = signer_addr
        .witness_program()
        .expect("addr")
        .program() // 20 bytes = hash160(pubkey)
        .to_owned();
    let script_code = ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_slice(
        signer_pkh.as_bytes(),
    )?);
    let mut sighash_cache = SighashCache::new(&mut tx_f1);
    let sighash = sighash_cache.p2wsh_signature_hash(
        0,
        &script_code,
        Amount::from_sat(funding_value_sat),
        EcdsaSighashType::All,
    )?;
    let sig = secp.sign_ecdsa(
        &Message::from_digest_slice(&sighash[..])?,
        &sk_keypair.secret_key(),
    );
    let mut sig_ser = sig.serialize_der().to_vec();
    sig_ser.push(EcdsaSighashType::All as u8);
    tx_f1.input[0].witness = Witness::from_slice(&[
        sig_ser,
        sk_keypair.public_key().serialize().to_vec(),
    ]);

    Ok((tx_f1, lock, spend_info))
}

/// Creates and signs tx_f2, spending the F1 output to the F2 Taproot address.
#[allow(clippy::too_many_arguments)]
pub fn create_and_sign_tx_f2(
    b_bits: usize,
    secp: &Secp256k1<secp256k1::All>,
    sk_keypair: &Keypair,
    network: Network,
    tx_f1: &bitcoin::Transaction,
    f1_output_value: u64,
    f1_lock: &ScriptBuf,
    f1_spend_info: &TaprootSpendInfo,
    flow_id_prefix: &[u8],
    fee_rate: u64,
    x: u32,
    nonce: u64,
) -> anyhow::Result<(bitcoin::Transaction, ScriptBuf, TaprootSpendInfo)> {
    // ── build F2 locking script & Taproot branch ────────────────────────
    let pk_signer = sk_keypair.public_key();
    let f2_lock = build_script_f2_blake3_locked(
        &bitcoin::PublicKey::new(pk_signer),
        flow_id_prefix,
        b_bits,
    );
    let x_only_pk = secp256k1::XOnlyPublicKey::from_keypair(sk_keypair).0;
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, f2_lock.clone())
        .expect("valid leaf")
        .finalize(secp, x_only_pk)
        .unwrap();
    let tr_addr = Address::p2tr_tweaked(spend_info.output_key(), network);

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
        x.to_le_bytes(),
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

    Ok((tx_f2, f2_lock, spend_info))
}

/// Creates and signs the spending transaction, spending the F2 output to the receiver.
#[allow(clippy::too_many_arguments)]
pub fn create_and_sign_spending_tx(
    secp: &Secp256k1<secp256k1::All>,
    sk_keypair: &Keypair,
    tx_f2: &bitcoin::Transaction,
    f2_output_value: u64,
    receiver_addr: &Address,
    f2_lock: &ScriptBuf,
    f2_spend_info: &TaprootSpendInfo,
    fee_rate: u64,
    x: u32,
    nonce: u64,
) -> anyhow::Result<bitcoin::Transaction> {
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
        x.to_le_bytes(),
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

    Ok(spending_tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::OutPoint;
    use bitcoin::Txid;
    use bitcoin::secp256k1::Keypair;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::secp256k1::rand::thread_rng;
    use bitvm::dry_run_taproot_input;
    use rstest::*;
    use std::str::FromStr;

    use crate::core::find_valid_nonce;
    use crate::core::flow_id_to_prefix_bytes;

    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    struct TxContext {
        secp: Secp256k1<secp256k1::All>,
        sk_keypair: Keypair,
        network: Network,
        funding_outpoint: OutPoint,
        funding_value_sat: u64,
        fee_rate: u64,
        l: usize,
        b: usize,
        x: u32,
        nonce: u64,
        flow_id_prefix: Vec<u8>,
        receiver_addr: Address,
    }

    #[fixture]
    fn tx_context() -> TxContext {
        let secp = Secp256k1::new();
        let sk_keypair = Keypair::new(&secp, &mut thread_rng());

        let network = Network::Regtest;

        let funding_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };

        let funding_value_sat = 100_000;
        let fee_rate = 1;

        const L: usize = 4;
        const B: usize = 16;
        let x = 123;

        let (nonce, flow_id, _hash) = find_valid_nonce(x, B, L).unwrap();
        let flow_id_prefix = flow_id_to_prefix_bytes(flow_id, B);
        let receiver_addr =
            Address::from_str("bcrt1qz3fps2lxvrp5rqj8ucsqrzjx2c3md9gawqr3l6")
                .unwrap()
                .require_network(network)
                .unwrap();

        TxContext {
            secp,
            sk_keypair,
            network,
            funding_outpoint,
            funding_value_sat,
            fee_rate,
            l: L,
            b: B,
            x,
            nonce,
            flow_id_prefix,
            receiver_addr,
        }
    }

    #[rstest]
    fn test_e2e_valid_input(tx_context: TxContext) -> anyhow::Result<()> {
        let TxContext {
            secp,
            sk_keypair,
            network,
            funding_outpoint,
            funding_value_sat,
            fee_rate,
            l: _,
            b,
            x,
            nonce,
            flow_id_prefix,
            receiver_addr,
        } = tx_context;
        // F1 tx
        let (tx_f1, f1_lock, f1_spend_info) = create_and_sign_tx_f1(
            b,
            &secp,
            &sk_keypair,
            network,
            funding_outpoint,
            funding_value_sat,
            &flow_id_prefix,
            fee_rate,
        )?;
        // F2 tx
        let (tx_f2, f2_lock, f2_spend_info) = create_and_sign_tx_f2(
            b,
            &secp,
            &sk_keypair,
            network,
            &tx_f1,
            tx_f1.output[0].value.to_sat(),
            &f1_lock,
            &f1_spend_info,
            &flow_id_prefix,
            fee_rate,
            x,
            nonce,
        )?;
        // Spending tx
        let spending_tx = create_and_sign_spending_tx(
            &secp,
            &sk_keypair,
            &tx_f2,
            tx_f2.output[0].value.to_sat(),
            &receiver_addr,
            &f2_lock,
            &f2_spend_info,
            fee_rate,
            x,
            nonce,
        )?;

        // --- Dry run F2 script logic ---
        let exec_info_f2 = dry_run_taproot_input(&tx_f2, 0, &tx_f1.output);
        assert!(
            exec_info_f2.success,
            "F2 script dry run failed: {:?}",
            exec_info_f2.last_opcode
        );

        // --- Dry run spending script logic ---
        let exec_info_spending =
            dry_run_taproot_input(&spending_tx, 0, &tx_f2.output);
        assert!(
            exec_info_spending.success,
            "Spending script dry run failed: {:?}",
            exec_info_f2.last_opcode
        );
        Ok(())
    }

    #[rstest]
    fn test_e2e_invalid_input(tx_context: TxContext) -> anyhow::Result<()> {
        let TxContext {
            secp,
            sk_keypair,
            network,
            funding_outpoint,
            funding_value_sat,
            fee_rate,
            l: _,
            b,
            x,
            nonce,
            flow_id_prefix,
            receiver_addr,
        } = tx_context;
        // F1 tx
        let (tx_f1, f1_lock, f1_spend_info) = create_and_sign_tx_f1(
            b,
            &secp,
            &sk_keypair,
            network,
            funding_outpoint,
            funding_value_sat,
            &flow_id_prefix,
            fee_rate,
        )?;
        // F2 tx
        let (tx_f2, f2_lock, f2_spend_info) = create_and_sign_tx_f2(
            b,
            &secp,
            &sk_keypair,
            network,
            &tx_f1,
            tx_f1.output[0].value.to_sat(),
            &f1_lock,
            &f1_spend_info,
            &flow_id_prefix,
            fee_rate,
            x,
            nonce,
        )?;
        // Spending tx
        let spending_tx = create_and_sign_spending_tx(
            &secp,
            &sk_keypair,
            &tx_f2,
            tx_f2.output[0].value.to_sat(),
            &receiver_addr,
            &f2_lock,
            &f2_spend_info,
            fee_rate,
            x + 1, // Invalid x
            nonce,
        )?;

        // --- Dry run F2 script logic ---
        let exec_info_f2 = dry_run_taproot_input(&tx_f2, 0, &tx_f1.output);
        assert!(
            exec_info_f2.success,
            "F2 script dry run failed: {:?}",
            exec_info_f2.last_opcode
        );

        // --- Dry run spending script logic ---
        let exec_info_spending =
            dry_run_taproot_input(&spending_tx, 0, &tx_f2.output);
        assert!(
            !exec_info_spending.success,
            "Spending script dry run succeeded: {:?}",
            exec_info_f2.last_opcode
        );
        Ok(())
    }
}
