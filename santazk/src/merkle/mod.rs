use ark_crypto_primitives::crh::{pedersen, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};

use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::merkle_tree::constraints::{BytesVarDigestConverter, ConfigGadget};
use ark_crypto_primitives::merkle_tree::{
    constraints::PathVar, ByteDigestConverter, Config, MerkleTree as ArkMerkleTree, Path,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq as Fr};

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
    serialization::*,
};

type LeafH = CRH;
type LeafHG = CRHGadget;

type CompressH = TwoToOneCRH;
type CompressHG = TwoToOneCRHGadget;

type LeafVar<ConstraintF> = [UInt8<ConstraintF>];

pub struct JubJubMerkleTreeParams;
impl Config for JubJubMerkleTreeParams {
    type Leaf = [u8];
    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;

    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;
    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}

type ConstraintF = Fr;
pub(crate) struct JubJubMerkleTreeParamsVar;
impl ConfigGadget<JubJubMerkleTreeParams, ConstraintF> for JubJubMerkleTreeParamsVar {
    type Leaf = LeafVar<ConstraintF>;
    type LeafDigest = <LeafHG as CRHSchemeGadget<LeafH, ConstraintF>>::OutputVar;
    type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF>;
    type InnerDigest = <CompressHG as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::OutputVar;
    type LeafHash = LeafHG;
    type TwoToOneHash = CompressHG;
}

type JubJubMerkleTree = ArkMerkleTree<JubJubMerkleTreeParams>;

pub struct MerkleTree(JubJubMerkleTree);
impl MerkleTree {
    pub fn new(depth: usize, leaves: &[Vec<u8>]) -> Self {
        let leaf_crh_params = load_pedersen_params(&H1_PEDERSEN_PARAMS_BYTES);
        let two_to_one_crh_params = load_pedersen_params(&H2_PEDERSEN_PARAMS_BYTES);
        let mut complete_leaves = Vec::from(leaves);
        for _ in 0..((1 << depth) - leaves.len()) {
            complete_leaves.push(vec![0u8; 64]);
        }
        let tree = JubJubMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            complete_leaves.iter().map(|v| v.as_slice()),
        )
        .unwrap();
        Self(tree)
    }

    pub fn root(&self) -> Vec<u8> {
        serialize_jub_jub_affine_point(&self.0.root())
    }

    pub fn update(&mut self, leaf_index: usize, leaf: &[u8]) {
        self.0.update(leaf_index, leaf).unwrap();
    }

    pub fn generate_proof(&self, leaf_index: usize) -> Option<Vec<u8>> {
        let proof = self.0.generate_proof(leaf_index).ok()?;
        Some(MerkleTree::serialize_path(&proof))
    }

    pub(crate) fn serialize_path(path: &Path<JubJubMerkleTreeParams>) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&serialize_jub_jub_affine_point(&path.leaf_sibling_hash));
        for node in path.auth_path.iter() {
            bytes.extend_from_slice(&serialize_jub_jub_affine_point(node));
        }
        bytes.extend_from_slice(&(path.leaf_index as u32).to_le_bytes());
        bytes
    }

    pub(crate) fn deserialize_path(bytes: &[u8]) -> Path<JubJubMerkleTreeParams> {
        let mut i: usize = 0;

        let leaf_sibling_hash =
            deserialize_jub_jub_affine_point(&bytes[i..i + JUBJUB_AFFINE_POINT_SIZE]);
        i += JUBJUB_AFFINE_POINT_SIZE;

        let mut auth_path = Vec::new();
        while i < bytes.len() - 4 {
            auth_path.push(deserialize_jub_jub_affine_point(
                &bytes[i..i + JUBJUB_AFFINE_POINT_SIZE],
            ));
            i += JUBJUB_AFFINE_POINT_SIZE;
        }

        let leaf_index: usize = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap())
            .try_into()
            .unwrap();
        Path {
            leaf_sibling_hash,
            auth_path,
            leaf_index,
        }
    }
}
