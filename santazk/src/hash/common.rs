#![allow(unused)]

use ark_crypto_primitives::crh::pedersen;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub};

#[derive(Clone)]
pub struct Window4x256;
impl pedersen::Window for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

pub(crate) type CRH = pedersen::CRH<JubJub, Window4x256>;
pub(crate) type CRHGadget = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window4x256>;

pub(crate) type TwoToOneCRH = pedersen::TwoToOneCRH<JubJub, Window4x256>;
pub(crate) type TwoToOneCRHGadget = pedersen::constraints::TwoToOneCRHGadget<JubJub, EdwardsVar, Window4x256>;

pub(crate) type PedersenParameters = pedersen::Parameters<JubJub>;
pub(crate) type PedersenParametersVar = pedersen::constraints::CRHParametersVar<JubJub, EdwardsVar>;