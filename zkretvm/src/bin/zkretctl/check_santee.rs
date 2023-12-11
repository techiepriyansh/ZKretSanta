use clap::{arg, Command};
use std::io;
use zkretvm::block::transaction::SBytes64;

use crate::keygen::read_key;
use crate::utils::RpcClient;

pub const NAME: &str = "checkmysantee";

#[must_use]
pub fn command() -> Command {
    Command::new(NAME)
        .about("Check if your santee has revealed their information")
        .arg(arg!(-k [KEY_PATH] "zkret key path"))
}

pub async fn check_santee(key_path: &str) -> io::Result<()> {
    let key = read_key(key_path);
    let client = RpcClient::new(key.chain_id.as_str());

    let rpks = client.get_current_revealed_pub_keys().await?;
    let rcts = client.get_current_revealed_cts().await?;
    rpks.iter()
        .position(|rpk| *rpk == SBytes64::from_bytes(&key.chosen_pub_key))
        .map(|i| {
            println!(
                "Your santee has revealed their information. This is what they said:\n{}",
                String::from_utf8(rcts[i].clone()).unwrap()
            )
        })
        .unwrap_or_else(|| println!("Your santee has not revealed their information yet."));

    Ok(())
}
