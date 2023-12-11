use santazk::proofs::{ChoiceAuthProver, RevealAuthProver};
use std::io;
use tokio::time::sleep;
use tokio::time::Duration;
use zkretvm::block::transaction::TransactionData;
use zkretvm::block::transaction::{SBytes64, Transaction};

use santazk::crypto::*;
use santazk::hash::Hash;
use santazk::merkle::MerkleTree;

use clap::{arg, Command};
use colored::Colorize;

use crate::utils::generate_key_tuple;
use crate::utils::{self};

pub const NAME: &str = "demo";

#[must_use]
pub fn command() -> Command {
    Command::new(NAME)
        .about("Run a sample protocol round")
        .arg(arg!(<CHAIN_ID> "Chain ID"))
        .arg_required_else_help(true)
}

pub async fn run_demo(client: &utils::RpcClient) -> io::Result<()> {
    let hasher = Hash::new();

    let (sA, nA, pA, dA) = generate_key_tuple(&hasher);
    let (sB, nB, pB, dB) = generate_key_tuple(&hasher);
    let (sC, nC, pC, dC) = generate_key_tuple(&hasher);

    let txA_enter = create_enter_tx(&pA);
    println!("{}", "ENTER".green());
    println!(
        "{}{}",
        "PubKey: ".green(),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pA)[..20].green()
    );
    println!("{}\n", serde_json::to_string(&txA_enter).unwrap());
    client.push_tx(txA_enter).await?;
    let _ = sleep(Duration::from_secs(10)).await;

    let txB_enter = create_enter_tx(&pB);
    println!("{}", "ENTER".red());
    println!(
        "{}{}",
        "PubKey: ".red(),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pB[..20]).red()
    );
    println!("{}\n", serde_json::to_string(&txB_enter).unwrap());
    client.push_tx(txB_enter).await?;
    let _ = sleep(Duration::from_secs(10)).await;

    let txC_enter = create_enter_tx(&pC);
    println!("{}", "ENTER".yellow());
    println!(
        "{}{}",
        "PubKey: ".yellow(),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pC)[..20].yellow()
    );
    println!("{}\n", serde_json::to_string(&txC_enter).unwrap());
    client.push_tx(txC_enter).await?;

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
    println!("{}", "CHOOSE".green());
    println!(
        "{}{}",
        "Choice: ".green(),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pB)[..20].green()
    );
    println!(
        "{}{}",
        "DHPubKey: ".green(),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &dA)[..20].green()
    );
    println!("{}\n", serde_json::to_string(&txA_choose).unwrap());
    client.push_tx(txA_choose).await?;

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
            ct.clone(),
            proof,
        ),
    };
    println!("{}", "REVEAL".red());
    println!(
        "{}{}",
        "PubKey: ".red(),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pB)[..20].red()
    );
    println!(
        "{}{}",
        "DHPubKey: ".red(),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &dB)[..20].red()
    );
    println!(
        "{}{}",
        "Ciphertext: ".red(),
        String::from_utf8(ct).unwrap().purple().italic()
    );
    println!("{}\n", serde_json::to_string(&txB_reveal).unwrap());
    client.push_tx(txB_reveal).await?;

    Ok(())
}

fn create_enter_tx(pub_key: &[u8]) -> Transaction {
    let mut tx = Transaction {
        transaction_type: 1,
        ..Default::default()
    };
    tx.data.0 = SBytes64::from_bytes(pub_key);

    tx
}
