use crate::hash::Hash;

pub fn derive_participation_pubkey(hash: &Hash, secret_key: &[u8], nullifier: &[u8]) -> Vec<u8> {
    let aux_sk = hash.h2(&secret_key, &nullifier);
    hash.h1(&aux_sk)
}

pub fn sign_choice_tx(
    hash: &Hash,
    secret_key: &[u8],
    nullifier: &[u8],
    choice: &[u8],
    dh_pub_key: &[u8],
) -> Vec<u8> {
    let aux_sk = hash.h2(&secret_key, &nullifier);
    let penultimate_signature = hash.h2(&aux_sk, &choice);
    hash.h2(&penultimate_signature, &dh_pub_key)
}

pub fn sign_reveal_tx(
    hash: &Hash,
    secret_key: &[u8],
    nullifier: &[u8],
    ciphertext_hash: &[u8],
    dh_pub_key: &[u8],
) -> Vec<u8> {
    let aux_sk = hash.h2(secret_key, nullifier);
    let penultimate_signature = hash.h2(&aux_sk, ciphertext_hash);
    hash.h2(&penultimate_signature, dh_pub_key)
}
