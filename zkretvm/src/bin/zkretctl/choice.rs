use std::io;

use clap::{arg, Command};
use santazk::{crypto::sign_choice_tx, hash::Hash, merkle::MerkleTree, proofs::ChoiceAuthProver};
use zkretvm::block::transaction::{SBytes64, Transaction, TransactionData};

use crate::{
    keygen::read_key,
    utils::{printable_to_pub_key, pub_key_to_printable, RpcClient},
};

pub const NAME: &str = "choice";
pub const CHOICE_LIST: &str = "list";
pub const CHOICE_MAKE: &str = "make";

#[must_use]
pub fn list_command() -> Command {
    Command::new(CHOICE_LIST)
        .about("List unclaimed public keys")
        .arg(arg!(-k [KEY_PATH] "zkret key path"))
}

#[must_use]
pub fn make_command() -> Command {
    Command::new(CHOICE_MAKE)
        .about("Make a choice for a public key")
        .arg(arg!(-k [KEY_PATH] "zkret key path"))
        .arg(arg!(<CHOICE> "Chosen public key"))
}

#[must_use]
pub fn command() -> Command {
    Command::new(NAME)
        .about("Generate a new zkret key")
        .subcommands(vec![list_command(), make_command()])
}

pub async fn list_choices(key_path: &str) -> io::Result<()> {
    let key = read_key(key_path);
    let client = RpcClient::new(key.chain_id.as_str());

    let mut upks = client.get_current_unclaimed_pub_keys().await?;
    upks.retain(|upk| *upk != SBytes64::from_bytes(&key.pub_key));

    for upk in upks {
        println!("- {}", pub_key_to_printable(&upk));
    }

    Ok(())
}

pub async fn do_choice_make(key_path: &str, choice: &str) -> io::Result<()> {
    let mut key = read_key(key_path);
    let choice = printable_to_pub_key(choice).to_vec();

    let client = RpcClient::new(key.chain_id.as_str());

    let merkle_leaves = client.get_current_merkle_leaves().await?;
    let leaves = merkle_leaves
        .iter()
        .map(SBytes64::to_vec)
        .collect::<Vec<Vec<u8>>>();

    let mt = MerkleTree::new(7, &leaves);
    let merkle_path = mt
        .generate_proof(leaves.iter().position(|r| *r == key.pub_key).unwrap())
        .unwrap();
    let root = mt.root();

    let hasher = Hash::new();
    let signature = sign_choice_tx(
        &hasher,
        &key.secret_key,
        &key.nullifier,
        &choice,
        &key.dh_pub_key,
    );

    println!("Generating ZK proof...");
    let ca_prover = ChoiceAuthProver::new();
    let proof = ca_prover.prove(
        &key.secret_key,
        &key.nullifier,
        &root,
        &merkle_path,
        &choice,
        &key.dh_pub_key,
        &signature,
    );

    let tx = Transaction {
        transaction_type: 2,
        data: TransactionData(
            SBytes64::from_bytes(choice.as_slice()),
            SBytes64::from_bytes(key.nullifier.as_slice()),
            SBytes64::from_bytes(key.dh_pub_key.as_slice()),
            SBytes64::from_bytes(signature.as_slice()),
            proof,
            Vec::new(),
        ),
    };

    println!("Sending CHOICE transaction...");
    client.push_tx(tx).await?;
    println!("Done.");

    key.chosen_pub_key = choice;
    std::fs::write(key_path, serde_json::to_string(&key).unwrap()).unwrap();

    Ok(())
}
