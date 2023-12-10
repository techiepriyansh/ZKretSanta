#![allow(unused)]

use ark_crypto_primitives::crh::{pedersen::Parameters, CRHScheme, TwoToOneCRHScheme};
use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, EdwardsProjective as JubJub};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use rand_core::OsRng;

use super::common::*;

pub fn efficient_serialize_jub_jub_affine_point(el: &JubJubAffine) -> Vec<u8> {
    let mut bytes = Vec::new();
    el.serialize_compressed(&mut bytes).unwrap();
    bytes
}

pub fn efficient_deserialize_jub_jub_affine_point(bytes: &[u8]) -> JubJubAffine {
    JubJubAffine::deserialize_compressed(bytes).unwrap()
}

pub fn serialize_pedersen_params(params: &Parameters<JubJub>) -> Vec<Vec<Vec<u8>>> {
    let mut serialized = Vec::new();
    for el in params.generators.iter() {
        let mut curr = Vec::new();
        for sub_el in el.iter() {
            let affine_el: JubJubAffine = (*sub_el).into();
            curr.push(efficient_serialize_jub_jub_affine_point(&affine_el));
        }
        serialized.push(curr);
    }
    serialized
}

pub fn generate_pedersen_params(name_prefix: &str, two_to_one: bool) {
    let rng = &mut OsRng;

    let params = if two_to_one {
        TwoToOneCRH::setup(rng).unwrap()
    } else {
        CRH::setup(rng).unwrap()
    };

    let serialized = serialize_pedersen_params(&params);

    let n1 = serialized.len();
    let n2 = serialized[0].len();
    let n3 = serialized[0][0].len();

    println!(
        "pub const {}_PEDERSEN_PARAMS_BYTES: [[[u8; {}]; {}]; {}] =\n[",
        name_prefix, n3, n2, n1
    );
    for a in serialized.iter() {
        println!("\t[");
        for b in a.iter() {
            println!("\t\t{:?},", b);
        }
        println!("\t],");
    }
    println!("];");
}

pub fn load_pedersen_params<const A: usize, const B: usize, const C: usize>(
    params_bytes: &[[[u8; A]; B]; C],
) -> Parameters<JubJub> {
    let mut generators = Vec::new();
    for a in params_bytes.iter() {
        let mut curr = Vec::new();
        for b in a.iter() {
            let el: JubJub = efficient_deserialize_jub_jub_affine_point(b).into();
            curr.push(el);
        }
        generators.push(curr);
    }
    Parameters::<JubJub> { generators }
}
