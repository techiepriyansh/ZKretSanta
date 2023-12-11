use std::io;

use santazk::{crypto::derive_participation_pubkey, hash::Hash};
use zkretvm::block::transaction::{SBytes64, Transaction};

const HTTP_RPC: &str = "http://127.0.0.1:9650";
pub struct RpcClient {
    pub url_path: String,
}

impl RpcClient {
    pub fn new(chain_id: &str) -> Self {
        Self {
            url_path: format!("/ext/bc/{}/rpc", chain_id),
        }
    }

    pub async fn push_tx(&self, tx: Transaction) -> io::Result<()> {
        let s = serde_json::to_string(&tx).unwrap();
        let params_str = format!(r#"[{{"transaction": {}}}]"#, s);
        let _ = self.make_request("proposeBlock", &params_str).await?;
        Ok(())
    }

    pub async fn get_current_block_state(&self) -> io::Result<String> {
        let params_str = r#"[]"#;
        let resp = self.make_request("lastAccepted", params_str).await?;
        let id = serde_json::from_str::<serde_json::Value>(&resp)
            .unwrap()
            .get("result")
            .unwrap()
            .get("id")
            .unwrap()
            .to_string();

        let params_str = format!(r#"[{{"id": {}}}]"#, id);
        let resp = self.make_request("getBlock", &params_str).await?;
        let resp = serde_json::from_str::<serde_json::Value>(&resp)
            .unwrap()
            .get("result")
            .unwrap()
            .get("block")
            .unwrap()
            .get("block_state")
            .unwrap()
            .to_string();
        Ok(resp)
    }

    pub async fn get_current_merkle_leaves(&self) -> io::Result<Vec<SBytes64>> {
        let state = self.get_current_block_state().await?;
        let res = serde_json::from_str::<serde_json::Value>(&state)
            .unwrap()
            .get("merkle_leaves")
            .unwrap()
            .to_string();

        let res = serde_json::from_str::<Vec<SBytes64>>(&res).unwrap();
        Ok(res)
    }

    pub async fn get_current_unclaimed_pub_keys(&self) -> io::Result<Vec<SBytes64>> {
        let state = self.get_current_block_state().await?;
        let res = serde_json::from_str::<serde_json::Value>(&state)
            .unwrap()
            .get("unclaimed_pub_keys")
            .unwrap()
            .to_string();

        let res = serde_json::from_str::<Vec<SBytes64>>(&res).unwrap();
        Ok(res)
    }

    pub async fn get_current_revealed_pub_keys(&self) -> io::Result<Vec<SBytes64>> {
        let state = self.get_current_block_state().await?;
        let res = serde_json::from_str::<serde_json::Value>(&state)
            .unwrap()
            .get("revealed_pub_keys")
            .unwrap()
            .to_string();

        let res = serde_json::from_str::<Vec<SBytes64>>(&res).unwrap();
        Ok(res)
    }

    pub async fn get_current_revealed_cts(&self) -> io::Result<Vec<Vec<u8>>> {
        let state = self.get_current_block_state().await?;
        let res = serde_json::from_str::<serde_json::Value>(&state)
            .unwrap()
            .get("revealed_cts")
            .unwrap()
            .to_string();

        let res = serde_json::from_str::<Vec<Vec<u8>>>(&res).unwrap();
        Ok(res)
    }

    pub async fn make_request(&self, method: &str, params: &str) -> io::Result<String> {
        let req_str = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"zkretvm.{}","params":{}}}"#,
            method, params
        );
        let res = http_manager::post_non_tls(HTTP_RPC, &self.url_path, &req_str).await?;
        Ok(String::from_utf8(res).unwrap())
    }
}

pub fn generate_key_tuple(hasher: &Hash) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let secret_key = random_manager::secure_bytes(64).unwrap();
    let nullifier = random_manager::secure_bytes(64).unwrap();
    let dh_key = random_manager::secure_bytes(64).unwrap();

    let pub_key = derive_participation_pubkey(hasher, &secret_key, &nullifier);

    (secret_key, nullifier, pub_key, dh_key)
}

pub fn pub_key_to_printable(pub_key: &SBytes64) -> String {
    let mut s = String::new();
    for i in 0..pub_key.0.len() {
        s.push_str(&format!("{:02x}", pub_key.0[i]));
    }
    for i in 0..pub_key.1.len() {
        s.push_str(&format!("{:02x}", pub_key.1[i]));
    }
    s
}

pub fn printable_to_pub_key(s: &str) -> SBytes64 {
    let mut pub_key = SBytes64::default();
    let mut i = 0;
    while i < 32 {
        pub_key.0[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        i += 1;
    }
    while i < 64 {
        pub_key.1[i - 32] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        i += 1;
    }
    pub_key
}
