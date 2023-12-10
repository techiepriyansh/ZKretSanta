use derivative::{self, Derivative};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Derivative, Default)]
#[derivative(Debug, PartialEq, Eq)]
pub struct Bytes64([u8; 32], [u8; 32]);

#[allow(clippy::module_name_repetitions)]
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Derivative, Default)]
#[derivative(Debug, PartialEq, Eq)]
pub struct TransactionData(
    pub Bytes64,
    pub Bytes64,
    pub Bytes64,
    pub Bytes64,
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
        transaction.data.0 = Bytes64::new(pub_key);
        transaction
    }
}

impl Bytes64 {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        let mut bytes64 = Bytes64::default();
        bytes64.0.copy_from_slice(&bytes[0..32]);
        bytes64.1.copy_from_slice(&bytes[32..64]);
        bytes64
    }
}
