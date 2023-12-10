use std::collections::HashSet;

use derivative::{self, Derivative};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use santazk::{
    hash::Hash,
    merkle::MerkleTree,
    proofs::{ChoiceAuthVerifier, RevealAuthVerifier},
};

const MERKLE_TREE_DEPTH: usize = 7;

pub(crate) type Bytes64 = [u8; 64];

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Derivative, Default)]
#[derivative(Debug, PartialEq, Eq)]
pub struct SBytes64(pub [u8; 32], pub [u8; 32]); // serde-serializable Bytes64

#[allow(clippy::module_name_repetitions)]
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Derivative, Default)]
#[derivative(Debug, PartialEq, Eq)]
pub struct TransactionData(
    pub SBytes64,
    pub SBytes64,
    pub SBytes64,
    pub SBytes64,
    pub Vec<u8>,
    pub Vec<u8>,
);

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Derivative, Default)]
#[derivative(Debug, PartialEq, Eq)]
pub struct Transaction {
    pub transaction_type: u8,
    pub data: TransactionData,
}

impl Transaction {
    pub(crate) fn genesis(genesis_data: Vec<u8>) -> Self {
        let mut transaction = Transaction {
            transaction_type: 0,
            ..Default::default()
        };
        transaction.data.4 = genesis_data;
        transaction
    }

    pub(crate) fn enter(pub_key: &[u8]) -> Self {
        let mut transaction = Transaction {
            transaction_type: 1,
            ..Default::default()
        };
        transaction.data.0 = SBytes64::from_bytes(pub_key);
        transaction
    }

    pub(crate) fn verify(
        &self,
        merkle_leaves: &[Bytes64],
        nullifiers: &[Bytes64],
        unclaimed_pub_keys: &[Bytes64],
        revealed_pub_keys: &[Bytes64],
    ) -> bool {
        let entered_pub_keys_set = merkle_leaves.iter().copied().collect::<HashSet<_>>();
        let nullifiers_set = nullifiers.iter().copied().collect::<HashSet<_>>();
        let unclaimed_pub_keys_set = unclaimed_pub_keys.iter().copied().collect::<HashSet<_>>();
        let revealed_pub_keys_set = revealed_pub_keys.iter().copied().collect::<HashSet<_>>();

        match self.transaction_type {
            0 => true,
            1 => {
                let pub_key = self.data.0.to_u8_64();
                if entered_pub_keys_set.contains(&pub_key) {
                    return false;
                }
                true
            }
            2 => {
                let nullifier = self.data.1.to_u8_64();
                if nullifiers_set.contains(&nullifier) {
                    return false;
                }

                let choice = self.data.0.to_u8_64();
                if !unclaimed_pub_keys_set.contains(&choice) {
                    return false;
                }

                let dh_pub_key = self.data.2.to_u8_64();
                let signature = self.data.3.to_u8_64();

                let root = MerkleTree::new(
                    MERKLE_TREE_DEPTH,
                    &merkle_leaves.iter().map(|b| b.to_vec()).collect::<Vec<_>>(),
                )
                .root();

                let ca_verifier = ChoiceAuthVerifier::new();
                ca_verifier.verify(
                    &self.data.4, // proof
                    &nullifier,
                    &root,
                    &choice,
                    &dh_pub_key,
                    &signature,
                )
            }
            3 => {
                let pk = self.data.0.to_u8_64();
                if !entered_pub_keys_set.contains(&pk) {
                    return false;
                }
                if revealed_pub_keys_set.contains(&pk) {
                    return false;
                }

                let hasher = Hash::new();
                let expected_ct_hash = hasher.h1(&self.data.4); // hash the ciphertext;

                let ct_hash = self.data.1.to_u8_64().to_vec();

                if ct_hash != expected_ct_hash {
                    return false;
                }

                let dh_pub_key = self.data.2.to_u8_64();
                let signature = self.data.3.to_u8_64();

                let ra_verifier = RevealAuthVerifier::new();
                ra_verifier.verify(
                    &self.data.5, // proof
                    &pk,
                    &ct_hash,
                    &dh_pub_key,
                    &signature,
                )
            }
            _ => false,
        }
    }

    pub(crate) fn update_state(
        &self,
        merkle_leaves: &mut Vec<Bytes64>,
        nullifiers: &mut Vec<Bytes64>,
        unclaimed_pub_keys: &mut Vec<Bytes64>,
        revealed_pub_keys: &mut Vec<Bytes64>,
    ) {
        match self.transaction_type {
            1 => {
                let pub_key = self.data.0.to_u8_64();
                merkle_leaves.push(pub_key);
                unclaimed_pub_keys.push(pub_key);
            }
            2 => {
                let nullifier = self.data.1.to_u8_64();
                nullifiers.push(nullifier);

                let choice = self.data.0.to_u8_64();
                unclaimed_pub_keys.retain(|pk| pk != &choice);
            }
            3 => {
                let pk = self.data.0.to_u8_64();
                revealed_pub_keys.push(pk);
            }
            _ => {}
        };
    }
}

impl SBytes64 {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let mut sbytes64 = SBytes64::default();
        sbytes64.0.copy_from_slice(&bytes[0..32]);
        sbytes64.1.copy_from_slice(&bytes[32..64]);
        sbytes64
    }

    pub(crate) fn to_u8_64(&self) -> [u8; 64] {
        let mut res = [0u8; 64];
        res[0..32].copy_from_slice(&self.0);
        res[32..64].copy_from_slice(&self.1);
        res
    }
}
