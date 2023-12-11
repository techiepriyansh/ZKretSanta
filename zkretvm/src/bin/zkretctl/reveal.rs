use std::io;

use clap::{arg, Command};
use santazk::{crypto::sign_reveal_tx, hash::Hash, proofs::RevealAuthProver};
use zkretvm::block::transaction::{SBytes64, Transaction, TransactionData};

use crate::{
    keygen::read_key,
    utils::{RpcClient},
};

pub const NAME: &str = "reveal";

#[must_use]
pub fn command() -> Command {
    Command::new(NAME)
        .about("Reveal your information to your santa")
        .arg(arg!(-k [KEY_PATH] "zkret key path"))
        .arg(arg!(<INFO> "Your information to reveal"))
}

pub async fn do_reveal(key_path: &str, info: &str) -> io::Result<()> {
    let key = read_key(key_path);
    let client = RpcClient::new(key.chain_id.as_str());

    let hasher = Hash::new();

    let ct = info.as_bytes();
    let ct_hash = hasher.h1(ct);
    let signature = sign_reveal_tx(
        &hasher,
        &key.secret_key,
        &key.nullifier,
        &ct_hash,
        &key.dh_pub_key,
    );

    println!("Generating ZK proof...");
    let ra_prover = RevealAuthProver::new();
    let proof = ra_prover.prove(
        &key.secret_key,
        &key.nullifier,
        &key.pub_key,
        &ct_hash,
        &key.dh_pub_key,
        &signature,
    );

    let tx = Transaction {
        transaction_type: 3,
        data: TransactionData (
            SBytes64::from_bytes(&key.pub_key),
            SBytes64::from_bytes(&ct_hash),
            SBytes64::from_bytes(&key.dh_pub_key),
            SBytes64::from_bytes(&signature),
            ct.to_vec(),
            proof,
        ),
    };

    println!("Sending REVEAL transaction...");
    client.push_tx(tx).await?;
    println!("Done.");

    Ok(())
}
