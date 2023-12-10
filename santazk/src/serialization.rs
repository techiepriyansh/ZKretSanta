use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, Fq as Fr};
use ark_ff::BigInteger;
use ark_ff::PrimeField;

pub const JUBJUB_AFFINE_POINT_SIZE: usize = 64;

pub fn serialize_jub_jub_affine_point(el: &JubJubAffine) -> Vec<u8> {
    let mut bits: Vec<bool> = el.x.into_bigint().to_bits_le(); bits.pop();
    bits.extend(el.y.into_bigint().to_bits_le()); bits.pop();

    // Size of bits is currently 510, pad by 2 bits to be a multiple of 8.
    bits.extend([false; 2]);

    bits.chunks(8)
        .map(|chunk| {
            let mut byte = 0u8;
            for (i, bit) in chunk.iter().enumerate() {
                if *bit {
                    byte |= 1 << i;
                }
            }
            byte
        })
        .collect()
}

pub fn deserialize_jub_jub_affine_point(bytes: &[u8]) -> JubJubAffine {
    let mut bits = Vec::new();
    for byte in bytes.iter() {
        for i in 0..8 {
            bits.push(byte & (1 << i) != 0);
        }
    }
    bits.pop();
    bits.pop(); // remove padding

    let x = Fr::from_bigint(BigInteger::from_bits_le(&bits[..255])).unwrap();
    let y = Fr::from_bigint(BigInteger::from_bits_le(&bits[255..])).unwrap();

    JubJubAffine { x, y }
}
