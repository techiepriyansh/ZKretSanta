use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_ff::BigInteger;
use ark_ff::PrimeField;

use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, Fq as Fr};

pub mod common;
use common::*;

pub mod pedersen_params;
use pedersen_params::*;

pub mod serialization;
use serialization::load_pedersen_params;

use crate::serialization::*;

pub struct Hash {
    h1_crh_params: PedersenParameters,
    h2_crh_params: PedersenParameters,
}

impl Hash {
    pub fn new() -> Self {
        let h1_crh_params = load_pedersen_params(&H1_PEDERSEN_PARAMS_BYTES);
        let h2_crh_params = load_pedersen_params(&H2_PEDERSEN_PARAMS_BYTES);
        Hash {
            h1_crh_params,
            h2_crh_params,
        }
    }

    pub fn h1(&self, input: &[u8]) -> Vec<u8> {
        let h = CRH::evaluate(&self.h1_crh_params, input).unwrap();
        serialize_jub_jub_affine_point(&h)
    }

    pub fn h2(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
        let l = CRH::evaluate(&self.h1_crh_params, left).unwrap();
        let r = CRH::evaluate(&self.h1_crh_params, right).unwrap();
        let h = TwoToOneCRH::compress(&self.h2_crh_params, l, r).unwrap();
        serialize_jub_jub_affine_point(&h)
    }

    pub fn h2c(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
        let l = deserialize_jub_jub_affine_point(left);
        let r = deserialize_jub_jub_affine_point(right);
        let h = TwoToOneCRH::compress(&self.h2_crh_params, l, r).unwrap();
        serialize_jub_jub_affine_point(&h)
    }
}

mod tests {
    use super::*;

    #[test]
    fn naive_test() {
        let hash = Hash::new();
        let secret_key = vec![1u8; 32];
        let nullifier = vec![2u8; 32];
        let aux_sk = hash.h2(&secret_key, &nullifier);
        let pub_key = hash.h1(&aux_sk);
        println!("pub_key: {:?}", pub_key);
        println!("pub_key.len(): {:?}", pub_key.len());
    }
}
