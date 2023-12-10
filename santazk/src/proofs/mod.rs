use ark_bls12_381::{Bls12_381, Config as Bls12_381Config, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::bls12::Bls12;
use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use rand_core::OsRng;

use crate::{
    circuits::{ChoiceAuthCircuit, RevealAuthCircuit},
    merkle::MerkleTree,
    serialization::deserialize_jub_jub_affine_point,
};

const CHOICE_AUTH_PROVER_PARAMS: &[u8; 48603984] =
    include_bytes!("../../params/choice_auth.groth16.pk");
const CHOICE_AUTH_VERIFIER_PARAMS: &[u8; 1064] =
    include_bytes!("../../params/choice_auth.groth16.vk");
const REVEAL_AUTH_PROVER_PARAMS: &[u8; 15463440] =
    include_bytes!("../../params/reveal_auth.groth16.pk");
const REVEAL_AUTH_VERIFIER_PARAMS: &[u8; 968] =
    include_bytes!("../../params/reveal_auth.groth16.vk");

pub struct ChoiceAuthProver {
    pk: ProvingKey<Bls12<Bls12_381Config>>,
}

impl ChoiceAuthProver {
    pub fn new() -> Self {
        let pk = load_proving_key(CHOICE_AUTH_PROVER_PARAMS);
        Self { pk }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        &self,
        secret_key: &[u8],
        nullifier: &[u8],
        root: &[u8],
        merkle_path: &[u8],
        choice: &[u8],
        dh_pub_key: &[u8],
        signature: &[u8],
    ) -> Vec<u8> {
        let root = deserialize_jub_jub_affine_point(root);
        let ckt = ChoiceAuthCircuit {
            secret_key: secret_key.to_vec(),
            nullifier: nullifier.to_vec(),
            root,
            merkle_path: MerkleTree::deserialize_path(merkle_path),
            choice: choice.to_vec(),
            dh_pub_key: dh_pub_key.to_vec(),
            signature: signature.to_vec(),
        };

        let mut rng = &mut OsRng;
        let proof = Groth16::<Bls12_381>::prove(&self.pk, ckt, &mut rng).unwrap();
        serialize_proof(&proof)
    }
}

pub struct ChoiceAuthVerifier {
    pvk: PreparedVerifyingKey<Bls12<Bls12_381Config>>,
}

impl ChoiceAuthVerifier {
    pub fn new() -> Self {
        let vk = load_verifying_key(CHOICE_AUTH_VERIFIER_PARAMS);
        let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();
        Self { pvk }
    }

    pub fn verify(
        &self,
        proof: &[u8],
        nullifier: &[u8],
        root: &[u8],
        choice: &[u8],
        dh_pub_key: &[u8],
        signature: &[u8],
    ) -> bool {
        let proof = deserialize_proof(proof);
        let root = deserialize_jub_jub_affine_point(root);

        let nullifier_pub = ToConstraintField::<Fr>::to_field_elements(nullifier).unwrap();
        let root_pub = vec![root.x, root.y];
        let choice_pub = ToConstraintField::<Fr>::to_field_elements(choice).unwrap();
        let dh_pub_key_pub = ToConstraintField::<Fr>::to_field_elements(dh_pub_key).unwrap();
        let signature_pub = ToConstraintField::<Fr>::to_field_elements(signature).unwrap();

        let mut pub_inp = Vec::new();
        pub_inp.extend(nullifier_pub);
        pub_inp.extend(root_pub);
        pub_inp.extend(choice_pub);
        pub_inp.extend(dh_pub_key_pub);
        pub_inp.extend(signature_pub);

        Groth16::<Bls12_381>::verify_with_processed_vk(&self.pvk, &pub_inp, &proof).is_ok()
    }
}

pub struct RevealAuthProver {
    pk: ProvingKey<Bls12<Bls12_381Config>>,
}

impl RevealAuthProver {
    pub fn new() -> Self {
        let pk = load_proving_key(REVEAL_AUTH_PROVER_PARAMS);
        Self { pk }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        &self,
        secret_key: &[u8],
        nullifier: &[u8],
        pub_key: &[u8],
        ciphertext_hash: &[u8],
        dh_pub_key: &[u8],
        signature: &[u8],
    ) -> Vec<u8> {
        let ckt = RevealAuthCircuit {
            secret_key: secret_key.to_vec(),
            nullifier: nullifier.to_vec(),
            pub_key: pub_key.to_vec(),
            ciphertext_hash: ciphertext_hash.to_vec(),
            dh_pub_key: dh_pub_key.to_vec(),
            signature: signature.to_vec(),
        };

        let mut rng = &mut OsRng;
        let proof = Groth16::<Bls12_381>::prove(&self.pk, ckt, &mut rng).unwrap();
        serialize_proof(&proof)
    }
}

pub struct RevealAuthVerifier {
    pvk: PreparedVerifyingKey<Bls12<Bls12_381Config>>,
}

impl RevealAuthVerifier {
    pub fn new() -> Self {
        let vk = load_verifying_key(REVEAL_AUTH_VERIFIER_PARAMS);
        let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();
        Self { pvk }
    }

    pub fn verify(
        &self,
        proof: &[u8],
        pub_key: &[u8],
        ciphertext_hash: &[u8],
        dh_pub_key: &[u8],
        signature: &[u8],
    ) -> bool {
        let proof = deserialize_proof(proof);

        let pub_key_pub = ToConstraintField::<Fr>::to_field_elements(pub_key).unwrap();
        let ciphertext_hash_pub =
            ToConstraintField::<Fr>::to_field_elements(ciphertext_hash).unwrap();
        let dh_pub_key_pub = ToConstraintField::<Fr>::to_field_elements(dh_pub_key).unwrap();
        let signature_pub = ToConstraintField::<Fr>::to_field_elements(signature).unwrap();

        let mut pub_inp = Vec::new();
        pub_inp.extend(pub_key_pub);
        pub_inp.extend(ciphertext_hash_pub);
        pub_inp.extend(dh_pub_key_pub);
        pub_inp.extend(signature_pub);

        Groth16::<Bls12_381>::verify_with_processed_vk(&self.pvk, &pub_inp, &proof).is_ok()
    }
}

fn load_proving_key(bytes: &[u8]) -> ProvingKey<Bls12<Bls12_381Config>> {
    let bytes = bytes.to_vec();
    ProvingKey::deserialize_compressed(&mut bytes.as_slice()).unwrap()
}

fn load_verifying_key(bytes: &[u8]) -> VerifyingKey<Bls12<Bls12_381Config>> {
    let bytes = bytes.to_vec();
    VerifyingKey::deserialize_compressed(&mut bytes.as_slice()).unwrap()
}

fn serialize_proof(proof: &Proof<Bls12<Bls12_381Config>>) -> Vec<u8> {
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes).unwrap();
    bytes
}

fn deserialize_proof(bytes: &[u8]) -> Proof<Bls12<Bls12_381Config>> {
    let bytes = bytes.to_vec();
    Proof::deserialize_compressed(&mut bytes.as_slice()).unwrap()
}
