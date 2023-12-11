use std::io;

use clap::{arg, Command};
use zkretvm::block::transaction::{SBytes64, Transaction};

use crate::{keygen::read_key, utils::RpcClient};

pub const NAME: &str = "enter";

#[must_use]
pub fn command() -> Command {
    Command::new(NAME)
        .about("Publish your public key")
        .arg(arg!(-k [KEY_PATH] "zkret key path"))
}

pub async fn do_enter(key_path: &str) -> io::Result<()> {
    let key = read_key(key_path);
    let client = RpcClient::new(key.chain_id.as_str());

    let mut tx = Transaction {
        transaction_type: 1,
        ..Default::default()
    };
    tx.data.0 = SBytes64::from_bytes(key.pub_key.as_slice());

    println!("Sending ENTER transaction...");
    client.push_tx(tx).await?;
    println!("Done.");

    Ok(())
}
