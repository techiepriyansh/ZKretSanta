use http_manager;
use santazk::proofs::RevealAuthProver;
use serde_json;
use std::io;
use tokio::time::sleep;
use tokio::time::Duration;
use zkretvm::block::transaction::TransactionData;
use zkretvm::block::transaction::{SBytes64, Transaction};

use santazk::crypto::*;
use santazk::hash::Hash;
use santazk::merkle::MerkleTree;
use santazk::proofs::ChoiceAuthProver;

use clap::{arg, crate_version, Command};

pub const APP_NAME: &str = "zkretctl";

const HTTP_RPC: &str = "http://127.0.0.1:9650";

#[tokio::main]
async fn main() -> io::Result<()> {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("ZKretSanta Client CLI")
        .arg(arg!(<URL_PATH> "RPC URL path"))
        .get_matches();

    let url_path = matches.get_one::<String>("URL_PATH").expect("required");

    let hasher = Hash::new();

    let (sA, nA, pA, dA) = generate_key_tuple(&hasher);
    let (sB, nB, pB, dB) = generate_key_tuple(&hasher);
    let (sC, nC, pC, dC) = generate_key_tuple(&hasher);

    let txA_enter = create_enter_tx(&pA);
    push_tx(txA_enter, url_path).await?;
    let _ = sleep(Duration::from_secs(10)).await;

    let txB_enter = create_enter_tx(&pB);
    push_tx(txB_enter, url_path).await?;
    let _ = sleep(Duration::from_secs(10)).await;

    let txC_enter = create_enter_tx(&pC);
    push_tx(txC_enter, url_path).await?;
    let _ = sleep(Duration::from_secs(10)).await;

    // A chooses B
    let mt = MerkleTree::new(7, &[pA.clone(), pB.clone(), pC.clone()]);
    let rpA = mt.generate_proof(0).unwrap();
    let root = mt.root();
    let sig_txA_choose = sign_choice_tx(&hasher, &sA, &nA, &pB, &dA);

    // generate ZK proof for A choosing B without revealing his pubkey
    let ca_prover = ChoiceAuthProver::new();
    let proof = ca_prover.prove(&sA, &nA, &root, &rpA, &pB, &dA, &sig_txA_choose);

    // finally generate the tx and make the transaction
    let txA_choose = Transaction {
        transaction_type: 2,
        data: TransactionData(
            SBytes64::from_bytes(&pB),
            SBytes64::from_bytes(&nA),
            SBytes64::from_bytes(&dA),
            SBytes64::from_bytes(&sig_txA_choose),
            proof,
            Vec::new(),
        ),
    };
    push_tx(txA_choose, url_path).await?;

    // B reveal their pubkey. The ciphertext message can only be seen by A.
    let ct = b"Hi, I am B. Send me ZCash!".to_vec();
    let ct_hash = hasher.h1(&ct);
    let sig_txB_reveal = sign_reveal_tx(&hasher, &sB, &nB, &ct_hash, &dB);

    let ra_prover = RevealAuthProver::new();
    let proof = ra_prover.prove(&sB, &nB, &pB, &ct_hash, &dB, &sig_txB_reveal);

    let txB_reveal = Transaction {
        transaction_type: 3,
        data: TransactionData(
            SBytes64::from_bytes(&pB),
            SBytes64::from_bytes(&ct_hash),
            SBytes64::from_bytes(&dB),
            SBytes64::from_bytes(&sig_txB_reveal),
            ct,
            proof,
        ),
    };
    push_tx(txB_reveal, url_path).await?;

    Ok(())
}

fn generate_key_tuple(hasher: &Hash) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let secret_key = random_manager::secure_bytes(64).unwrap();
    let nullifier = random_manager::secure_bytes(64).unwrap();
    let dh_key = random_manager::secure_bytes(64).unwrap();

    let pub_key = derive_participation_pubkey(&hasher, &secret_key, &nullifier);

    (secret_key, nullifier, pub_key, dh_key)
}

fn create_enter_tx(pub_key: &[u8]) -> Transaction {
    let mut tx = Transaction {
        transaction_type: 1,
        ..Default::default()
    };
    tx.data.0 = SBytes64::from_bytes(&pub_key);

    tx
}

async fn push_tx(tx: Transaction, url_path: &str) -> io::Result<()> {
    let s = serde_json::to_string(&tx).unwrap();
    let s1 = r#"{
    "jsonrpc": "2.0",
    "id"     : 1,
    "method" : "zkretvm.proposeBlock",
    "params" : [{"transaction": "#;
    let s2 = r#"}]
}
    "#;

    let fin = format!("{}{}{}", s1, s, s2);
    println!("{}", fin.clone());
    let res = http_manager::post_non_tls(HTTP_RPC, url_path, &fin).await?;
    println!("{}", String::from_utf8(res).unwrap());
    println!("");
    println!("");

    Ok(())
}
