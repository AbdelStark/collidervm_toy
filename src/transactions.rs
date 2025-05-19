use crate::core::{
    blake3_message_to_limbs, build_script_f1_blake3_locked,
    build_script_f2_blake3_locked,
};
use crate::utils::{encode_scriptnum, estimate_fee_vbytes};
use anyhow;
use bitcoin::sighash::Prevouts;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash,
    TapSighashType, Transaction, TxIn, TxOut, Witness, absolute,
};
use bitcoin::{
    secp256k1::{Message, Secp256k1},
    sighash::SighashCache,
};
use musig2::LiftedSignature;
use secp256k1::{PublicKey, XOnlyPublicKey};
// --------------------------------------------------------------------
// Transaction Creation Functions
// --------------------------------------------------------------------

/// Creates and signs tx_f1, spending the funding UTXO to the F1 Taproot address.
#[allow(clippy::too_many_arguments)]
pub fn create_f1_tx(
    b_bits: usize,
    secp: &Secp256k1<secp256k1::All>,
    pk_signer: &PublicKey,
    network: &Network,
    funding_outpoint: &OutPoint,
    funding_value_sat: &u64,
    flow_id_prefix: &[u8],
    fee_rate: &u64,
) -> anyhow::Result<(
    Transaction,
    ScriptBuf,
    TaprootSpendInfo,
    ScriptBuf,
    TaprootSpendInfo,
    Message,
)> {
    // ── build F1 locking script ─────────────────────────────────────────
    let lock = build_script_f1_blake3_locked(
        &bitcoin::PublicKey::new(*pk_signer),
        flow_id_prefix,
        b_bits,
    );

    // ── wrap in a Taproot tree & derive its address ─────────────────────
    let x_only_pk = secp256k1::XOnlyPublicKey::from(*pk_signer);
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, lock.clone())
        .expect("valid leaf")
        .finalize(secp, x_only_pk)
        .unwrap();

    let tr_addr = Address::p2tr_tweaked(spend_info.output_key(), *network);

    let fee_f1 = estimate_fee_vbytes(155, *fee_rate); // ~1 input + 1 output
    let f1_output_value = funding_value_sat
        .checked_sub(fee_f1)
        .expect("funding not sufficient for fee");

    let mut tx_f1 = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: *funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(f1_output_value),
            script_pubkey: tr_addr.script_pubkey(),
        }],
    };

    let xonly_pk = XOnlyPublicKey::from(*pk_signer);
    let funding_script = get_funding_script(&x_only_pk);

    let leaf_hash =
        TapLeafHash::from_script(&funding_script, LeafVersion::TapScript);

    // Build the tree with a single leaf
    let funding_spend_info = TaprootBuilder::new()
        .add_leaf(0, funding_script.clone())?
        .finalize(secp, xonly_pk)
        .unwrap();

    // The scriptPubKey for this Taproot output and the address (for funding):
    let funding_address =
        Address::p2tr_tweaked(funding_spend_info.output_key(), *network);

    let mut cache = SighashCache::new(&mut tx_f1);
    let sighash = cache.taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[TxOut {
            value: Amount::from_sat(*funding_value_sat),
            script_pubkey: funding_address.script_pubkey(),
        }]),
        leaf_hash,
        TapSighashType::Default,
    )?;

    let msg = Message::from_digest_slice(&sighash[..])?;

    Ok((
        tx_f1,
        lock,
        spend_info,
        funding_script,
        funding_spend_info,
        msg,
    ))
}

pub fn get_funding_script(xonly_pk: &XOnlyPublicKey) -> ScriptBuf {
    bitcoin::script::Builder::new()
        .push_x_only_key(xonly_pk)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script()
}
pub fn finalize_f1_tx(
    tx: &mut Transaction,
    sig: LiftedSignature,
    spend_info: &TaprootSpendInfo,
    funding_script: &ScriptBuf,
) {
    let control_block = spend_info
        .control_block(&(funding_script.clone(), LeafVersion::TapScript))
        .unwrap();

    tx.input[0].witness = Witness::from_slice(&[
        sig.serialize().to_vec(),
        funding_script.to_bytes(),
        control_block.serialize(),
    ]);
}

/// Creates and signs tx_f2, spending the F1 output to the F2 Taproot address.
#[allow(clippy::too_many_arguments)]
pub fn create_f2_tx(
    b_bits: usize,
    secp: &Secp256k1<secp256k1::All>,
    pk_signer: &PublicKey,
    network: &Network,
    f1_tx: &Transaction,
    f1_output_value: &u64,
    f1_lock: &ScriptBuf,
    flow_id_prefix: &[u8],
    fee_rate: &u64,
) -> anyhow::Result<(Transaction, ScriptBuf, TaprootSpendInfo, Message)> {
    // ── build F2 locking script & Taproot branch ────────────────────────
    let f2_lock = build_script_f2_blake3_locked(
        &bitcoin::PublicKey::new(*pk_signer),
        flow_id_prefix,
        b_bits,
    );
    let x_only_pk = secp256k1::XOnlyPublicKey::from(*pk_signer);
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, f2_lock.clone())
        .expect("valid leaf")
        .finalize(secp, x_only_pk)
        .unwrap();
    let tr_addr = Address::p2tr_tweaked(spend_info.output_key(), *network);

    // Now the tx vsize is about 17093.
    let fee_f2 = estimate_fee_vbytes(17093, *fee_rate); // 1 input P2TR + 1 output
    let f2_output_value = f1_output_value
        .checked_sub(fee_f2)
        .expect("f1 output too small for f2 fee");

    let mut tx_f2 = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: f1_tx.compute_txid(),
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
    let sighash = cache.taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[f1_tx.output[0].clone()]),
        leaf_hash,
        TapSighashType::Default,
    )?;

    let msg = Message::from_digest_slice(&sighash[..])?;
    Ok((tx_f2, f2_lock, spend_info, msg))
}

pub fn finalize_lock_tx(
    tx: &mut Transaction,
    sig: LiftedSignature,
    spend_info: &TaprootSpendInfo,
    lock: &ScriptBuf,
    x: &u32,
    nonce: &u64,
) -> anyhow::Result<()> {
    // Assemble witness
    let control_block = spend_info
        .control_block(&(lock.clone(), LeafVersion::TapScript))
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

    witness.push(sig.serialize());
    witness.push(lock.to_bytes());
    witness.push(control_block.serialize());

    tx.input[0].witness = witness;
    Ok(())
}

/// Creates and signs the spending transaction, spending the F2 output to the receiver.
#[allow(clippy::too_many_arguments)]
pub fn create_spending_tx(
    f2_tx: &Transaction,
    f2_output_value: &u64,
    receiver_addr: &Address,
    f2_lock: &ScriptBuf,
    fee_rate: &u64,
) -> anyhow::Result<(Transaction, Message)> {
    let fee_spending_tx = estimate_fee_vbytes(17082, *fee_rate); // 1 input P2TR + 1 output
    let spending_output_value = f2_output_value
        .checked_sub(fee_spending_tx)
        .expect("f2 output too small for spending tx");

    let mut spending_tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: f2_tx.compute_txid(),
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
            &Prevouts::All(&[f2_tx.output[0].clone()]),
            leaf_hash,
            TapSighashType::Default,
        )
        .unwrap();

    let msg = Message::from_digest_slice(&sighash[..])?;
    Ok((spending_tx, msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::find_valid_nonce;
    use crate::core::flow_id_to_prefix_bytes;
    use crate::musig2::{generate_keys, simulate_musig2};
    use crate::utils::inner_from;
    use Transaction;
    use bitcoin::Network;
    use bitcoin::OutPoint;
    use bitcoin::Txid;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Secp256k1;
    use bitvm::dry_run_taproot_input;
    use rstest::*;
    use std::str::FromStr;

    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    struct TxContext {
        secp: Secp256k1<secp256k1::All>,
        sk_signers:
            [(musig2::secp256k1::SecretKey, musig2::secp256k1::PublicKey); 2],
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
    #[once]
    fn tx_context() -> TxContext {
        let secp = Secp256k1::new();
        let sk_signers = generate_keys::<2>();

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

        let (nonce, flow_id) = find_valid_nonce(x, B, L).unwrap();
        let flow_id_prefix = flow_id_to_prefix_bytes(flow_id, B);
        let receiver_addr =
            Address::from_str("bcrt1qz3fps2lxvrp5rqj8ucsqrzjx2c3md9gawqr3l6")
                .unwrap()
                .require_network(network)
                .unwrap();

        TxContext {
            secp,
            sk_signers,
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

    #[derive(Debug, Clone)]
    struct TxFixture {
        tx: Transaction,
        prev_lock: ScriptBuf,
        prev_spend_info: TaprootSpendInfo,
    }

    #[fixture]
    fn f1_tx_fixture(tx_context: &TxContext) -> TxFixture {
        let TxContext {
            secp,
            sk_signers,
            network,
            funding_outpoint,
            funding_value_sat,
            fee_rate,
            b,
            flow_id_prefix,
            ..
        } = tx_context;

        let pk_signers = sk_signers.iter().map(|key| key.1).collect::<Vec<_>>();
        let agg_ctx = musig2::KeyAggContext::new(pk_signers).unwrap();
        let pk_signer: musig2::secp256k1::PublicKey =
            agg_ctx.aggregated_pubkey();

        let (
            mut tx,
            prev_lock,
            prev_spend_info,
            funding_script,
            funding_spend_info,
            message,
        ) = create_f1_tx(
            *b,
            secp,
            &inner_from(pk_signer),
            network,
            funding_outpoint,
            funding_value_sat,
            flow_id_prefix,
            fee_rate,
        )
        .unwrap();

        let final_sig = simulate_musig2(sk_signers, &message).unwrap();
        finalize_f1_tx(
            &mut tx,
            final_sig,
            &funding_spend_info,
            &funding_script,
        );

        TxFixture {
            tx,
            prev_lock,
            prev_spend_info,
        }
    }

    #[fixture]
    fn f2_tx_fixture(
        tx_context: &TxContext,
        f1_tx_fixture: TxFixture,
    ) -> TxFixture {
        let TxContext {
            secp,
            sk_signers,
            network,
            fee_rate,
            b,
            x,
            nonce,
            flow_id_prefix,
            ..
        } = tx_context;

        let pk_signers = sk_signers.iter().map(|key| key.1).collect::<Vec<_>>();
        let agg_ctx = musig2::KeyAggContext::new(pk_signers).unwrap();
        let pk_signer: musig2::secp256k1::PublicKey =
            agg_ctx.aggregated_pubkey();

        let TxFixture {
            tx: tx_f1,
            prev_lock: f1_lock,
            prev_spend_info: f1_spend_info,
            ..
        } = &f1_tx_fixture;

        let (mut tx, prev_lock, prev_spend_info, message) = create_f2_tx(
            *b,
            secp,
            &inner_from(pk_signer),
            network,
            tx_f1,
            &tx_f1.output[0].value.to_sat(),
            f1_lock,
            flow_id_prefix,
            fee_rate,
        )
        .unwrap();
        let final_sig = simulate_musig2(sk_signers, &message).unwrap();
        finalize_lock_tx(&mut tx, final_sig, f1_spend_info, f1_lock, x, nonce)
            .unwrap();

        TxFixture {
            tx,
            prev_lock,
            prev_spend_info,
        }
    }

    #[fixture]
    fn spending_tx(
        tx_context: &TxContext,
        f2_tx_fixture: TxFixture,
    ) -> Transaction {
        let TxContext {
            sk_signers,
            fee_rate,
            x,
            nonce,
            receiver_addr,
            ..
        } = tx_context;

        let TxFixture {
            tx: tx_f2,
            prev_lock: f2_lock,
            prev_spend_info: f2_spend_info,
            ..
        } = &f2_tx_fixture;

        let (mut tx, message) = create_spending_tx(
            tx_f2,
            &tx_f2.output[0].value.to_sat(),
            receiver_addr,
            f2_lock,
            fee_rate,
        )
        .unwrap();
        let final_sig = simulate_musig2(sk_signers, &message).unwrap();
        finalize_lock_tx(&mut tx, final_sig, f2_spend_info, f2_lock, x, nonce)
            .unwrap();
        tx
    }

    #[rstest]
    fn test_e2e_valid_input(
        f1_tx_fixture: TxFixture,
        f2_tx_fixture: TxFixture,
        spending_tx: Transaction,
    ) -> anyhow::Result<()> {
        let TxFixture { tx: tx_f1, .. } = f1_tx_fixture;
        let TxFixture { tx: tx_f2, .. } = f2_tx_fixture;

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
    fn test_e2e_invalid_input(
        tx_context: &TxContext,
        f1_tx_fixture: TxFixture,
        f2_tx_fixture: TxFixture,
    ) -> anyhow::Result<()> {
        let TxContext {
            sk_signers,
            fee_rate,
            x,
            nonce,
            receiver_addr,
            ..
        } = tx_context;

        let TxFixture { tx: tx_f1, .. } = f1_tx_fixture;
        let TxFixture {
            tx: tx_f2,
            prev_lock: f2_lock,
            prev_spend_info: f2_spend_info,
            ..
        } = f2_tx_fixture;

        // Spending tx with invalid x
        let (mut spending_tx, message) = create_spending_tx(
            &tx_f2,
            &tx_f2.output[0].value.to_sat(),
            receiver_addr,
            &f2_lock,
            fee_rate,
        )?;
        let final_sig = simulate_musig2(sk_signers, &message).unwrap();
        // invalid input value: x+1
        finalize_lock_tx(
            &mut spending_tx,
            final_sig,
            &f2_spend_info,
            &f2_lock,
            &(x + 1),
            nonce,
        )
        .unwrap();

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
