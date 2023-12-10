use ark_crypto_primitives::crh::{
    pedersen::{self, constraints::CRHParametersVar},
    TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};

use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::merkle_tree::constraints::{BytesVarDigestConverter, ConfigGadget};
use ark_crypto_primitives::merkle_tree::{
    constraints::PathVar, ByteDigestConverter, Config, MerkleTree as ArkMerkleTree, Path,
};
use ark_ed_on_bls12_381::{
    constraints::EdwardsVar, EdwardsAffine as JubJubAffine, EdwardsProjective as JubJub, Fq as Fr,
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[allow(unused)]
use ark_r1cs_std::prelude::*;
#[allow(unused)]
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};

use ark_bls12_381::Bls12_381;

use ark_std::rand::{Rng, RngCore, SeedableRng};
use ark_std::test_rng;
use rand_core::OsRng;

use ark_ff::ToConstraintField;

use crate::{
    hash::{common::*, pedersen_params::*, serialization::load_pedersen_params},
    merkle::{JubJubMerkleTreeParams, JubJubMerkleTreeParamsVar, MerkleTree},
    serialization::*,
};

type ConstraintF = Fr;

#[derive(Clone)]
pub struct ChoiceAuthCircuit {
    pub secret_key: Vec<u8>,
    pub nullifier: Vec<u8>,
    pub root: JubJubAffine,
    pub merkle_path: Path<JubJubMerkleTreeParams>,
    pub choice: Vec<u8>,
    pub dh_pub_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ConstraintSynthesizer<ConstraintF> for ChoiceAuthCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let h1_crh_params_value = load_pedersen_params(&H1_PEDERSEN_PARAMS_BYTES);
        let h2_crh_params_value = load_pedersen_params(&H2_PEDERSEN_PARAMS_BYTES);

        let h1_crh_params_var = CRHParametersVar::<JubJub, EdwardsVar>::new_constant(
            ark_relations::ns!(cs, "h1_crh_params"),
            h1_crh_params_value,
        )?;
        let h2_crh_params_var = CRHParametersVar::<JubJub, EdwardsVar>::new_constant(
            ark_relations::ns!(cs, "h2_crh_params"),
            h2_crh_params_value,
        )?;

        let secret_key_var =
            UInt8::new_witness_vec(ark_relations::ns!(cs, "secret_key"), &self.secret_key)?; // cs.clone vs ns?

        let nullifier_var =
            UInt8::new_input_vec(ark_relations::ns!(cs, "nullifier"), &self.nullifier)?;

        let aux_secret_key_var = hash_two_to_one_constrained(
            &h1_crh_params_var,
            &h2_crh_params_var,
            &secret_key_var,
            &nullifier_var,
        )?;

        let pub_key_var = hash_one_constrained(&h1_crh_params_var, &aux_secret_key_var)?;

        let root_var = EdwardsVar::new_input(ark_relations::ns!(cs, "root"), || Ok(self.root))?;

        let merkle_path_var: PathVar<
            JubJubMerkleTreeParams,
            ConstraintF,
            JubJubMerkleTreeParamsVar,
        > = PathVar::new_witness(ark_relations::ns!(cs, "path"), || Ok(self.merkle_path))?;

        let _ = merkle_path_var.verify_membership(
            &h1_crh_params_var,
            &h2_crh_params_var,
            &root_var,
            &pub_key_var,
        )?;

        let choice_var = UInt8::new_input_vec(ark_relations::ns!(cs, "choice"), &self.choice)?;

        let penultimate_signature_var = hash_two_to_one_constrained(
            &h1_crh_params_var,
            &h2_crh_params_var,
            &aux_secret_key_var,
            &choice_var,
        )?;

        let dh_pub_key_var =
            UInt8::new_input_vec(ark_relations::ns!(cs, "dh_pub_key"), &self.dh_pub_key)?;

        let expected_signature_var = hash_two_to_one_constrained(
            &h1_crh_params_var,
            &h2_crh_params_var,
            &penultimate_signature_var,
            &dh_pub_key_var,
        )?;

        let signature_var =
            UInt8::new_input_vec(ark_relations::ns!(cs, "signature"), &self.signature)?;

        let _ = expected_signature_var.is_eq(&signature_var)?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct RevealAuthCircuit {
    pub secret_key: Vec<u8>,
    pub nullifier: Vec<u8>,
    pub pub_key: Vec<u8>,
    pub ciphertext_hash: Vec<u8>,
    pub dh_pub_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ConstraintSynthesizer<ConstraintF> for RevealAuthCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let h1_crh_params_value = load_pedersen_params(&H1_PEDERSEN_PARAMS_BYTES);
        let h2_crh_params_value = load_pedersen_params(&H2_PEDERSEN_PARAMS_BYTES);

        let h1_crh_params_var = CRHParametersVar::<JubJub, EdwardsVar>::new_constant(
            ark_relations::ns!(cs, "h1_crh_params"),
            h1_crh_params_value,
        )?;
        let h2_crh_params_var = CRHParametersVar::<JubJub, EdwardsVar>::new_constant(
            ark_relations::ns!(cs, "h2_crh_params"),
            h2_crh_params_value,
        )?;

        let secret_key_var =
            UInt8::new_witness_vec(ark_relations::ns!(cs, "secret_key"), &self.secret_key)?; // cs.clone vs ns?

        let nullifier_var =
            UInt8::new_witness_vec(ark_relations::ns!(cs, "nullifier"), &self.nullifier)?;

        let aux_secret_key_var = hash_two_to_one_constrained(
            &h1_crh_params_var,
            &h2_crh_params_var,
            &secret_key_var,
            &nullifier_var,
        )?;

        let expected_pub_key_var = hash_one_constrained(&h1_crh_params_var, &aux_secret_key_var)?;

        let pub_key_var = UInt8::new_input_vec(ark_relations::ns!(cs, "pub_key"), &self.pub_key)?;

        let _ = expected_pub_key_var.is_eq(&pub_key_var)?;

        let ciphertext_hash_var = UInt8::new_input_vec(
            ark_relations::ns!(cs, "ciphertext_hash"),
            &self.ciphertext_hash,
        )?;

        let penultimate_signature_var = hash_two_to_one_constrained(
            &h1_crh_params_var,
            &h2_crh_params_var,
            &aux_secret_key_var,
            &ciphertext_hash_var,
        )?;

        let dh_pub_key_var =
            UInt8::new_input_vec(ark_relations::ns!(cs, "dh_pub_key"), &self.dh_pub_key)?;
        
        let expected_signature_var = hash_two_to_one_constrained(
            &h1_crh_params_var,
            &h2_crh_params_var,
            &penultimate_signature_var,
            &dh_pub_key_var,
        )?;

        let signature_var =
            UInt8::new_input_vec(ark_relations::ns!(cs, "signature"), &self.signature)?;

        let _ = expected_signature_var.is_eq(&signature_var)?;

        Ok(())
    }
}

fn hash_one_constrained(
    h1_crh_params_var: &CRHParametersVar<JubJub, EdwardsVar>,
    input: &[UInt8<ConstraintF>],
) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
    let h = CRHGadget::evaluate(h1_crh_params_var, input)?;
    convert_edwards_var_to_uint8_vec(h)
}

fn hash_two_to_one_constrained(
    h1_crh_params_var: &CRHParametersVar<JubJub, EdwardsVar>,
    h2_crh_params_var: &CRHParametersVar<JubJub, EdwardsVar>,
    input1: &[UInt8<ConstraintF>],
    input2: &[UInt8<ConstraintF>],
) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
    let l = CRHGadget::evaluate(h1_crh_params_var, input1)?;
    let r = CRHGadget::evaluate(h1_crh_params_var, input2)?;

    let h = TwoToOneCRHGadget::compress(h2_crh_params_var, &l, &r)?;
    convert_edwards_var_to_uint8_vec(h)
}

fn convert_edwards_var_to_uint8_vec(
    edwards_var: EdwardsVar,
) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
    let mut bits: Vec<Boolean<ConstraintF>> = edwards_var.to_bits_le()?;
    // Size of bits is currently 510, pad by 2 bits to be a multiple of 8.
    for _ in 0..2 {
        bits.push(Boolean::<ConstraintF>::Constant(false));
    }

    Ok(bits.chunks(8).map(UInt8::from_bits_le).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::*;
    use crate::hash::Hash;

    #[test]
    fn choice_auth_circuit_test() {
        let secret_key = vec![1u8; 32];
        let nullifier = vec![2u8; 32];
        let choice = vec![3u8; 32];
        let dh_pub_key = vec![4u8; 32];

        let hasher = Hash::new();
        let pub_key = derive_participation_pubkey(&hasher, &secret_key, &nullifier);
        let signature = sign_choice_tx(&hasher, &secret_key, &nullifier, &choice, &dh_pub_key);

        let mt = MerkleTree::new(2,&[pub_key, vec![0u8; 64]]);
        let merkle_path = MerkleTree::deserialize_path(&mt.generate_proof(0).unwrap());

        let ckt = ChoiceAuthCircuit {
            secret_key: vec![1u8; 32],
            nullifier: vec![2u8; 32],
            root: deserialize_jub_jub_affine_point(&mt.root()),
            merkle_path,
            choice,
            dh_pub_key,
            signature,
        };
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        ckt.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn reveal_auth_circuit_test() {
        let secret_key = vec![1u8; 32];
        let nullifier = vec![2u8; 32];
        let ciphertext = vec![3u8; 32];
        let dh_pub_key = vec![4u8; 32];

        let hasher = Hash::new();
        let pub_key = derive_participation_pubkey(&hasher, &secret_key, &nullifier);
        let ciphertext_hash = hasher.h1(&ciphertext);
        let signature = sign_reveal_tx(
            &hasher,
            &secret_key,
            &nullifier,
            &ciphertext_hash,
            &dh_pub_key,
        );

        let ckt = RevealAuthCircuit {
            secret_key,
            nullifier,
            pub_key,
            ciphertext_hash,
            dh_pub_key,
            signature,
        };
        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        ckt.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }
}
