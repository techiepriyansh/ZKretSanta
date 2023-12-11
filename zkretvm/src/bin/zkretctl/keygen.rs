use santazk::hash::Hash;

use clap::{arg, Command};
use serde::{Deserialize, Serialize};

use crate::utils::generate_key_tuple;

pub const NAME: &str = "keygen";

#[must_use]
pub fn command() -> Command {
    Command::new(NAME)
        .about("Generate a new zkret key")
        .arg(arg!(-k [KEY_PATH] "Output zkret key path"))
        .arg(arg!(<CHAIN_ID> "Chain ID"))
        .arg_required_else_help(true)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ZkretKey {
    pub secret_key: Vec<u8>,
    pub nullifier: Vec<u8>,
    pub pub_key: Vec<u8>,
    pub dh_pub_key: Vec<u8>,

    pub chain_id: String,

    pub chosen_pub_key: Vec<u8>,
}

pub fn gen_key(key_path: &str, chain_id: &str) {
    let hasher = Hash::new();

    let (secret_key, nullifier, pub_key, dh_pub_key) = generate_key_tuple(&hasher);
    let zkret_key = ZkretKey {
        secret_key,
        nullifier,
        pub_key,
        dh_pub_key,
        chain_id: chain_id.to_string(),
        chosen_pub_key: Vec::new(),
    };

    std::fs::write(key_path, serde_json::to_string(&zkret_key).unwrap()).unwrap();
}

pub fn read_key(key_path: &str) -> ZkretKey {
    let zkret_key = std::fs::read_to_string(key_path).unwrap();
    serde_json::from_str(&zkret_key).unwrap()
}
