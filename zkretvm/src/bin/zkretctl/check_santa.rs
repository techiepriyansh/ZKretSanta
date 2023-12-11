use clap::{arg, Command};
use std::io;
use zkretvm::block::transaction::SBytes64;

use crate::keygen::read_key;
use crate::utils::RpcClient;

pub const NAME: &str = "checkmysanta";

#[must_use]
pub fn command() -> Command {
    Command::new(NAME)
        .about("Check if someone chose to be your santa")
        .arg(arg!(-k [KEY_PATH] "zkret key path"))
}

pub async fn check_santa(key_path: &str) -> io::Result<()> {
    let key = read_key(key_path);
    let client = RpcClient::new(key.chain_id.as_str());

    let upks = client.get_current_unclaimed_pub_keys().await?;
    upks.iter().position(|upk| *upk == SBytes64::from_bytes(&key.pub_key))
        .map(|_| println!("You don't have a santa yet!"))
        .unwrap_or_else(|| println!("You have a santa! You should complete the REVEAL phase to let them know your information."));

    Ok(())
}
