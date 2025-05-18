use musig2::{
    AggNonce, KeyAggContext, LiftedSignature, PartialSignature, PubNonce,
    SecNonce, aggregate_partial_signatures,
    secp::{MaybeScalar, Point},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    sign_partial,
};
use rand::RngCore;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub fn generate_keys<const N: usize>() -> [(SecretKey, PublicKey); N] {
    let secp = Secp256k1::new();
    (0..N)
        .map(|_| secp.generate_keypair(&mut rand::thread_rng()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn generate_nonce(
    key: &(SecretKey, PublicKey),
    aggregated_pubkey: impl Into<Point>,
    message: impl AsRef<[u8]>,
    signer_index: usize,
) -> (SecNonce, PubNonce) {
    // TODO: add signature for the nonce
    let mut nonce_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce_seed);

    let secnonce = SecNonce::build(nonce_seed)
        .with_seckey(key.0)
        .with_message(&message)
        .with_aggregated_pubkey(aggregated_pubkey)
        .with_extra_input(&(signer_index as u32).to_be_bytes())
        .build();

    let our_public_nonce = secnonce.public_nonce();
    (secnonce, our_public_nonce)
}

pub fn gen_partial_signature(
    secret_key: &SecretKey,
    n_of_n_public_keys: Vec<musig2::secp256k1::PublicKey>,
    sighash: impl AsRef<[u8]>,
    secret_nonce: &SecNonce,
    aggregated_nonce: &AggNonce,
) -> anyhow::Result<MaybeScalar> {
    let pubkeys: Vec<Point> = Vec::from_iter(
        n_of_n_public_keys
            .iter()
            .map(|&public_key| public_key.into()),
    );
    let key_agg_ctx = KeyAggContext::new(pubkeys)?;

    Ok(sign_partial(
        &key_agg_ctx,
        *secret_key,
        secret_nonce.clone(),
        aggregated_nonce,
        sighash,
    )?)
}

pub fn gen_aggregated_signature(
    n_of_n_public_keys: Vec<musig2::secp256k1::PublicKey>,
    sighash: impl AsRef<[u8]>,
    aggregated_nonce: &AggNonce,
    partial_signatures: Vec<PartialSignature>,
) -> anyhow::Result<LiftedSignature> {
    let pubkeys: Vec<Point> = Vec::from_iter(
        n_of_n_public_keys
            .iter()
            .map(|&public_key| public_key.into()),
    );
    let key_agg_ctx = KeyAggContext::new(pubkeys)?;

    Ok(aggregate_partial_signatures(
        &key_agg_ctx,
        aggregated_nonce,
        partial_signatures,
        sighash,
    )?)
}

pub fn inner_from<F: Serialize, T: DeserializeOwned>(from: F) -> T {
    let value = serde_json::to_value(&from).unwrap();
    serde_json::from_value(value).unwrap()
}

pub fn simulate_musig2(
    keys: &[(SecretKey, PublicKey)],
    message: &bitcoin::secp256k1::Message,
) -> anyhow::Result<LiftedSignature> {
    let message = message.as_ref();
    let public_keys: Vec<_> = keys.iter().map(|key| key.1).collect();

    let ctx = musig2::KeyAggContext::new(public_keys.clone())?;
    let agg_public_keys: musig2::secp256k1::PublicKey = ctx.aggregated_pubkey();

    let nonces = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            generate_nonce(key, agg_public_keys, message, index)
        })
        .collect::<Vec<_>>();

    let agg_nonce = nonces
        .iter()
        .map(|nonce| nonce.1.clone())
        .collect::<Vec<PubNonce>>()
        .iter()
        .sum();

    let partial_sigs = keys
        .iter()
        .zip(nonces.iter())
        .map(|(key, nonce)| {
            gen_partial_signature(
                &key.0,
                public_keys.clone(),
                message,
                &nonce.0,
                &agg_nonce,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    gen_aggregated_signature(
        public_keys.clone(),
        message,
        &agg_nonce,
        partial_sigs,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    #[test]
    fn test_musig2_functional_api() {
        let digest = sha2::Sha256::digest(b"hello world").to_vec();
        let message =
            bitcoin::secp256k1::Message::from_digest_slice(&digest).unwrap();
        let keys = generate_keys::<5>();

        let public_keys: Vec<_> = keys.into_iter().map(|key| key.1).collect();

        let ctx = musig2::KeyAggContext::new(public_keys.clone()).unwrap();
        let agg_public_keys: musig2::secp256k1::PublicKey =
            ctx.aggregated_pubkey();

        let final_signature = simulate_musig2(&keys, &message).unwrap();

        musig2::verify_single(
            agg_public_keys,
            final_signature,
            message.as_ref(),
        )
        .expect("aggregated signature must be valid");
    }

    #[test]
    fn test_wrap_value() {
        let secp = Secp256k1::new();
        let keypair = secp.generate_keypair(&mut rand::thread_rng());
        let keypair_sk: bitcoin::secp256k1::SecretKey = inner_from(keypair.0);
        let keypair_sk_sk: SecretKey = inner_from(keypair_sk);
        assert_eq!(keypair_sk_sk, keypair.0);
    }
}
