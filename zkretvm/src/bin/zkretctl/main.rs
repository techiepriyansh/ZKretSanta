mod check_santa;
mod check_santee;
mod choice;
mod demo;
mod enter;
mod keygen;
mod reveal;
mod utils;

use std::io;

use clap::{arg, crate_version, Command};

pub const APP_NAME: &str = "zkretctl";

#[tokio::main]
async fn main() -> io::Result<()> {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("ZKretSanta Client CLI")
        .subcommands(vec![
            keygen::command(),
            enter::command(),
            choice::command(),
            check_santa::command(),
            reveal::command(),
            check_santee::command(),
            demo::command(),
        ])
        .get_matches();

    let default_key_path = "key.zkret".to_string();

    match matches.subcommand() {
        Some((keygen::NAME, sub_matches)) => {
            let key_path = sub_matches
                .get_one::<String>("KEY_PATH")
                .unwrap_or(&default_key_path);
            let chain_id = sub_matches.get_one::<String>("CHAIN_ID").expect("required");

            keygen::gen_key(key_path, chain_id);
        }
        Some((enter::NAME, sub_matches)) => {
            let key_path = sub_matches
                .get_one::<String>("KEY_PATH")
                .unwrap_or(&default_key_path);

            enter::do_enter(key_path).await?;
        }
        Some((choice::NAME, sub_matches)) => match sub_matches.subcommand() {
            Some((choice::CHOICE_LIST, sub_sub_matches)) => {
                let key_path = sub_sub_matches
                    .get_one::<String>("KEY_PATH")
                    .unwrap_or(&default_key_path);

                choice::list_choices(key_path).await?;
            }
            Some((choice::CHOICE_MAKE, sub_sub_matches)) => {
                let key_path = sub_sub_matches
                    .get_one::<String>("KEY_PATH")
                    .unwrap_or(&default_key_path);
                let choice = sub_sub_matches
                    .get_one::<String>("CHOICE")
                    .expect("required");

                choice::do_choice_make(key_path, choice).await?;
            }
            _ => {}
        },
        Some((check_santa::NAME, sub_matches)) => {
            let key_path = sub_matches
                .get_one::<String>("KEY_PATH")
                .unwrap_or(&default_key_path);

            check_santa::check_santa(key_path).await?;
        }
        Some((reveal::NAME, sub_matches)) => {
            let key_path = sub_matches
                .get_one::<String>("KEY_PATH")
                .unwrap_or(&default_key_path);
            let info = sub_matches
                .get_one::<String>("INFO")
                .expect("required");

            reveal::do_reveal(key_path, info).await?;
        }
        Some((check_santee::NAME, sub_matches)) => {
            let key_path = sub_matches
                .get_one::<String>("KEY_PATH")
                .unwrap_or(&default_key_path);

            check_santee::check_santee(key_path).await?;
        }
        Some((demo::NAME, sub_matches)) => {
            let chain_id = sub_matches.get_one::<String>("CHAIN_ID").expect("required");
            let client = utils::RpcClient::new(chain_id);

            demo::run_demo(&client).await?
        }
        _ => {}
    }

    Ok(())
}
