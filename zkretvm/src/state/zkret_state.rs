#![allow(clippy::missing_errors_doc)]

use std::io::{self, Error, ErrorKind};

use avalanche_types::subnet;

use super::State;
use crate::block::transaction::Bytes64;

const MERKLE_LEAVES_KEY: &[u8] = b"merkle_leaves";
const NULLIFIERS_KEY: &[u8] = b"nullifiers";
const UNCLAIMED_PUB_KEYS_KEY: &[u8] = b"unclaimed_pub_keys";
const REVEALED_PUB_KEYS_KEY: &[u8] = b"revealed_pub_keys";

fn encode(v: &Vec<Bytes64>) -> Vec<u8> {
    let mut res = Vec::new();
    for b in v {
        res.extend_from_slice(b);
    }
    res
}

fn decode(d: impl AsRef<[u8]>) -> Vec<Bytes64> {
    let mut res = Vec::new();
    let dd = d.as_ref();
    dd.chunks(64).for_each(|b| {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(b);
        res.push(bytes);
    });
    res
}

impl State {
    async fn set_bytes64_vec(&self, key: &[u8], list: &Vec<Bytes64>) -> io::Result<()> {
        let mut db = self.db.write().await;
        db.put(key, &encode(list)).await.map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to put bytes64 list: {e:?}"),
            )
        })
    }

    async fn get_bytes64_vec(&self, key: &[u8]) -> io::Result<Vec<Bytes64>> {
        let db = self.db.read().await;
        match db.get(key).await.map(decode) {
            Ok(d) => Ok(d),
            Err(e) => {
                if subnet::rpc::errors::is_not_found(&e) {
                    Ok(Vec::new())
                } else {
                    Err(Error::new(
                        ErrorKind::Other,
                        format!("failed to get bytes64 list: {e:?}"),
                    ))
                }
            }
        }
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

    pub async fn set_unclaimed_pub_keys(&self, pub_keys: &Vec<Bytes64>) -> io::Result<()> {
        self.set_bytes64_vec(UNCLAIMED_PUB_KEYS_KEY, pub_keys).await
    }

    pub async fn get_unclaimed_pub_keys(&self) -> io::Result<Vec<Bytes64>> {
        self.get_bytes64_vec(UNCLAIMED_PUB_KEYS_KEY).await
    }

    pub async fn set_revealed_pub_keys(&self, pub_keys: &Vec<Bytes64>) -> io::Result<()> {
        self.set_bytes64_vec(REVEALED_PUB_KEYS_KEY, pub_keys).await
    }

    pub async fn get_revealed_pub_keys(&self) -> io::Result<Vec<Bytes64>> {
        self.get_bytes64_vec(REVEALED_PUB_KEYS_KEY).await
    }
}
