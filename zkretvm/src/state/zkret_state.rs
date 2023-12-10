#![allow(clippy::missing_errors_doc)]

use std::io::{self, Error, ErrorKind};

use crate::block::transaction::Bytes64;

use super::State;

const MERKLE_LEAVES_KEY: &[u8] = b"merkle_leaves";
const NULLIFIERS_KEY: &[u8] = b"nullifiers";
const ENTERED_PUB_KEYS_KEY: &[u8] = b"entered_pub_keys";

fn encode(v: &Vec<Bytes64>) -> Vec<u8> {
    let mut res = Vec::new();
    for b in v {
        res.extend_from_slice(&b.0);
        res.extend_from_slice(&b.1);
    }
    res
}

fn decode(d: impl AsRef<[u8]>) -> Vec<Bytes64> {
    let mut res = Vec::new();
    let dd = d.as_ref();
    for i in 0..dd.len() / 64 {
        let mut b = Bytes64::default();
        b.0.copy_from_slice(&dd[i * 64..i * 64 + 32]);
        b.1.copy_from_slice(&dd[i * 64 + 32..i * 64 + 64]);
        res.push(b);
    }
    res
}

impl State {
    async fn set_bytes64_vec(&self, key: &[u8], list: &Vec<Bytes64>) -> io::Result<()> {
        let mut db = self.db.write().await;
        db.put(key, &encode(list)).await.map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to put list leaves: {e:?}"),
            )
        })
    }

    async fn get_bytes64_vec(&self, key: &[u8]) -> io::Result<Vec<Bytes64>> {
        let db = self.db.read().await;
        db.get(key).await.map(decode).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to get list leaves: {e:?}"),
            )
        })
    }

    pub async fn set_merkle_leaves(&self, leaves: &Vec<Bytes64>) -> io::Result<()> {
        self.set_bytes64_vec(MERKLE_LEAVES_KEY, leaves).await
    }

    pub async fn get_merkle_leaves(&self) -> io::Result<Vec<Bytes64>> {
        self.get_bytes64_vec(MERKLE_LEAVES_KEY).await
    }

    pub async fn set_nullifiers(&self, nullifiers: &Vec<Bytes64>) -> io::Result<()> {
        self.set_bytes64_vec(NULLIFIERS_KEY, nullifiers).await
    }

    pub async fn get_nullifiers(&self) -> io::Result<Vec<Bytes64>> {
        self.get_bytes64_vec(NULLIFIERS_KEY).await
    }

    pub async fn set_entered_pub_keys(&self, entered_pub_keys: &Vec<Bytes64>) -> io::Result<()> {
        self.set_bytes64_vec(ENTERED_PUB_KEYS_KEY, entered_pub_keys)
            .await
    }

    pub async fn get_entered_pub_keys(&self) -> io::Result<Vec<Bytes64>> {
        self.get_bytes64_vec(ENTERED_PUB_KEYS_KEY).await
    }
}
