use std::str::FromStr;

use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, Response};

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);
}

#[derive(Serialize, Deserialize)]
struct Output {
    amount: u64,
    address: String,
}

#[derive(Serialize, Deserialize)]
struct Input {
    tx_id: String,
    vout: u32,
    private_key: String,
}

#[derive(Deserialize)]
struct Tx {
    vout: Vec<TxVout>,
}

#[derive(Deserialize)]
struct TxVout {
    scriptpubkey: String,
    value: u32,
}

#[wasm_bindgen]
pub async fn create_raw_tx(inputs_js: JsValue, outputs_js: JsValue) -> String {
    let secp = Secp256k1::new();

    let version_hex = "02000000";
    let marker_hex = "00";
    let flag_hex = "01";

    let inputs_param: Vec<Input> = serde_wasm_bindgen::from_value(inputs_js).unwrap();
    let outputs_param: Vec<Output> = serde_wasm_bindgen::from_value(outputs_js).unwrap();

    let sequence = "fdffffff"; // locktime + RBF
    let script_sig_size = "00"; // we're dealing with segwit only
    let locktime = "00000000";

    let input_count = inputs_param.len();
    let input_count_bytes = input_count.to_le_bytes();
    let input_count_last_non_zero = input_count_bytes.iter().rposition(|&x| x != 0).unwrap_or(0);
    let input_count_trimmed_bytes = &input_count_bytes[..=input_count_last_non_zero];
    let input_count_hex = hex::encode(input_count_trimmed_bytes);

    let output_count = outputs_param.len();
    let output_count_bytes = output_count.to_le_bytes();
    let output_count_last_non_zero = output_count_bytes
        .iter()
        .rposition(|&x| x != 0)
        .unwrap_or(0);
    let output_count_trimmed_bytes = &output_count_bytes[..=output_count_last_non_zero];
    let output_count_hex = hex::encode(output_count_trimmed_bytes);

    let tx_ids_vouts = inputs_param
        .iter()
        .map(|input| reverse_byte_order(&input.tx_id) + &hex::encode(input.vout.to_le_bytes()))
        .collect::<String>();

    let mut outputs_hex = String::new();

    for output in outputs_param {
        let (_hrp, _data, program) =
            bech32::segwit::decode(&output.address).expect("Failed to decode segwit address");

        let amount_hex = hex::encode(output.amount.to_le_bytes());

        let mut script_pub_key = vec![];

        script_pub_key.push(0x00);
        script_pub_key.push(program.len() as u8);
        script_pub_key.extend_from_slice(&program);

        let script_pub_key_hex = hex::encode(&script_pub_key);

        let script_pub_key_size_hex =
            hex::encode(&((script_pub_key_hex.len() / 2) as u8).to_le_bytes());

        outputs_hex.push_str(&amount_hex);
        outputs_hex.push_str(&script_pub_key_size_hex);
        outputs_hex.push_str(&script_pub_key_hex);
    }

    let outputs_hash256 = double_sha256(&outputs_hex);

    let mut inputs_hex = String::new();

    let mut complete_witness_sig = String::new();

    for input in inputs_param {
        let tx_id = reverse_byte_order(&input.tx_id);
        let vout = hex::encode(&input.vout.to_le_bytes());
        let sequence = sequence;

        inputs_hex.push_str(&tx_id);
        inputs_hex.push_str(&vout);
        inputs_hex.push_str(script_sig_size);
        inputs_hex.push_str(sequence);

        let tx_id_vout = String::from(&tx_id) + &vout;

        let request =
            Request::new_with_str(&format!("https://mempool.space/api/tx/{}", &input.tx_id))
                .expect("Failed to init request");

        let window = web_sys::window().unwrap();
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .expect("Failed to query tx");

        assert!(resp_value.is_instance_of::<Response>());
        let resp: Response = resp_value.dyn_into().unwrap();

        let json = JsFuture::from(resp.json().expect("Failed converting to json"))
            .await
            .expect("Request promise rejected");

        let tx: Tx = serde_wasm_bindgen::from_value(json).unwrap();

        let script_pub_key = &tx.vout[input.vout as usize].scriptpubkey;

        let pub_key_hash = &script_pub_key[4..];

        let script_code = String::from("1976a914") + pub_key_hash + "88ac";

        let value = hex::encode(&(tx.vout[input.vout as usize].value as u64).to_le_bytes());

        let preimage = version_hex.to_owned()
            + &double_sha256(&tx_ids_vouts)
            + &double_sha256(sequence)
            + &tx_id_vout
            + &script_code
            + &value
            + sequence
            + &outputs_hash256
            + locktime;

        let preimage_with_sig_hash = preimage.to_owned() + &hex::encode((1 as u32).to_le_bytes());

        let preimage_hash = double_sha256(&preimage_with_sig_hash);

        let private_key = if input.private_key.len() == 52 {
            hex::encode(
                &bs58::decode(input.private_key)
                    .into_vec()
                    .expect("Invalid base58")[1..33],
            )
        } else {
            input.private_key
        };

        let secret_key = SecretKey::from_str(&private_key).expect("32 bytes, within curve order");

        let public_key = secret_key.public_key(&secp);

        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hex::decode(&preimage_hash).expect("Failed to decode"));

        let signature = secp.sign_ecdsa(&Message::from_digest(hash_array), &secret_key);

        let signature_with_sig_hash_all = signature.to_string() + "01";

        complete_witness_sig =
            "0248".to_string() + &signature_with_sig_hash_all + "21" + &public_key.to_string();
    }

    let full_tx = String::new()
        + version_hex
        + marker_hex
        + flag_hex
        + &input_count_hex
        + &inputs_hex
        + &output_count_hex
        + &outputs_hex
        + &complete_witness_sig
        + locktime;

    full_tx
}

fn reverse_byte_order(hex: &str) -> String {
    let bytes = hex::decode(hex).expect("Failed to decode");

    let reversed_bytes: Vec<u8> = bytes.into_iter().rev().collect();

    hex::encode(reversed_bytes)
}

fn double_sha256(data: &str) -> String {
    let hash = sha2::Sha256::digest(hex::decode(data).expect("Failed to decode"));

    let double_hash = sha2::Sha256::digest(hash);

    hex::encode(double_hash)
}
