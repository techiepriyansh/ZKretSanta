use santazk::crypto::*;
use santazk::hash::Hash;
use santazk::merkle::MerkleTree;
use santazk::proofs::{ChoiceAuthProver, ChoiceAuthVerifier};

const MERKLE_TREE_DEPTH: usize = 7;
pub fn test_proof_and_verification() {
    let secret_key = vec![1u8; 64];
    let nullifier = vec![5u8; 64];
    let choice = vec![3u8; 64];
    let dh_pub_key = vec![9u8; 64];

    let hasher = Hash::new();
    let pub_key = derive_participation_pubkey(&hasher, &secret_key, &nullifier);
    let signature = sign_choice_tx(&hasher, &secret_key, &nullifier, &choice, &dh_pub_key);

    println!("Building merkle tree...");
    let mt = MerkleTree::new(MERKLE_TREE_DEPTH, &[pub_key]);
    let root = mt.root();
    let merkle_path = mt.generate_proof(0).unwrap();

    println!("Proving...");
    let prover = ChoiceAuthProver::new();
    let proof = prover.prove(
        &secret_key,
        &nullifier,
        &root,
        &merkle_path,
        &choice,
        &dh_pub_key,
        &signature,
    );
    println!("Proof len {}...", proof.len());

    println!("Verifying...");
    let verifier = ChoiceAuthVerifier::new();
    let check = verifier.verify(&proof, &nullifier, &root, &choice, &dh_pub_key, &signature);

    assert!(check);

    println!("Verification successful!");
}
