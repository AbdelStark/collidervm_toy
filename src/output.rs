use anyhow::Result;
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Serialize)]
pub struct KeyInfo {
    pub signers: Vec<KeyPair>,
    // pub operator: KeyPair,
}

#[derive(Serialize)]
pub struct KeyPair {
    //pub address: String,
    pub wif: String,
}

#[derive(Serialize)]
pub struct TransactionInfo {
    pub f1: TxInfo,
    pub f2: TxInfo,
    pub spending: TxInfo,
    pub nonce: u64,
    pub flow_id: u32,
}

#[derive(Serialize)]
pub struct TxInfo {
    pub txid: String,
    pub file_path: String,
}

#[derive(Serialize)]
pub struct DemoOutput {
    pub keys: KeyInfo,
    pub transactions: Option<TransactionInfo>,
    pub input_x: u32,
    pub parameters: DemoParameters,
}

#[derive(Serialize)]
pub struct DemoParameters {
    pub required_amount_sat: u64,
    pub l_param: usize,
    pub b_param: usize,
}

pub fn write_demo_output_to_file(
    output: &crate::DemoOutput,
    output_dir: &str,
    path: &str,
) -> Result<()> {
    let dir = Path::new(output_dir);
    fs::create_dir_all(dir)?;
    let file_path = dir.join(path);
    println!("Writing demo output to file: {file_path:?}");
    fs::write(file_path, serde_json::to_string_pretty(output)?)?;
    Ok(())
}
