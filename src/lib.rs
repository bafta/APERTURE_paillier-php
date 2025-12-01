/// Thin wrapper over Paillier-rs to make it a PHP module
/// Install the dev environment following the instructions here... https://ext-php.rs/getting-started/installation.html
/// Paillier-rs docs https://crates.io/crates/libpaillier
use std::collections::HashMap;
use ext_php_rs::{info_table_end, info_table_row, info_table_start, prelude::*, zend::ModuleEntry, binary::Binary};
use libpaillier::{Ciphertext, DecryptionKey, EncryptionKey};

#[derive(ZvalConvert)]
pub enum MsgType {
    Int(i64),
    Str(String),
    None
}

#[derive(ZvalConvert)]
pub enum ResultType {
    Int(i64),
    Str(String),
    None
}

/// Returns a randomly generated keypair
/// @return array [0 => encryption_key, 1 => decryption_key, 'encryption_key' -> ..., 'decryption_key' => ...]
#[php_function]
pub fn generate_keys() -> Result<HashMap<String, Binary<u8>>, &'static str> {
    let Some(dk) = DecryptionKey::random() else { return Err("Failed to generate decryption key") };
    let ek = EncryptionKey::from(&dk);
    let mut keys = HashMap::new();
    keys.insert("0".to_string(), ek.to_bytes().into_iter().collect::<Binary<_>>());
    keys.insert("1".to_string(), dk.to_bytes().into_iter().collect::<Binary<_>>());
    keys.insert("encryption_key".to_string(), ek.to_bytes().into_iter().collect::<Binary<_>>());
    keys.insert("decryption_key".to_string(), dk.to_bytes().into_iter().collect::<Binary<_>>());
    Ok(keys)
}

/// Encrypt a message
/// @param string $encryption_key Binary string containing the encryption key
/// @param string $msg The int or string to be encrypted
/// @return string The encrypted ciphertext
#[php_function]
pub fn encrypt(encryption_key: Binary<u8>, msg: MsgType) -> Result<Binary<u8>, String> {
    let ek = EncryptionKey::from_bytes(encryption_key.to_vec())?;
    encrypt_msg(&ek, &msg)
}

/// Encrypt an array of messages
/// @param string $encryption_key Binary string containing the encryption key
/// @param string|int[] $msgs Array of ints or strings to be encrypted
/// @return string[] The encrypted ciphertext, keys are preserved
#[php_function]
pub fn encrypt_array(encryption_key: Binary<u8>, msgs: HashMap<String, MsgType>) -> Result<HashMap<String, Binary<u8>>, String> {
    let ek = EncryptionKey::from_bytes(encryption_key.to_vec())?;
    let mut encrypted: HashMap<String, Binary<u8>> = HashMap::new();
    for (key, msg) in msgs.iter() {
        encrypted.insert(key.clone(), encrypt_msg(&ek, msg)?);
    }

    Ok(encrypted)
}

fn encrypt_msg(ek: &EncryptionKey, msg: &MsgType) -> Result<Binary<u8>, String> {
    let msg_data = match msg {
        MsgType::Int(int_val) => &(int_val.to_ne_bytes()),
        MsgType::Str(str_val) => str_val.as_bytes(),
        MsgType::None => return Err("Bad type".to_string()),
    };
    let Some((ciphertext, _)) = ek.encrypt(msg_data, None) else { return Err("Failed to encrypt".to_string()) };
    Ok(ciphertext.to_bytes().into_iter().collect::<Binary<_>>())
}

/// Decrypt a ciphertext
/// @param string $decryption_key Binary string containing the decryption key
/// @param string $ct_data Binary ciphertext string to be decrypted
/// @param string $return_as Indicates what type to cast the returned data as, "INT" or "STRING", default "INT"
/// @return string The decrypted plaintext
#[php_function]
pub fn decrypt(decryption_key: Binary<u8>, ct_data: Binary<u8>, return_as: Option<String>) -> Result<ResultType, String> {
    let dk = DecryptionKey::from_bytes(decryption_key.to_vec())?;
    decrypt_ciphertext(&dk, &ct_data, return_as)
}

/// Decrypt an array of ciphertexts
/// @param string $encryption_key Binary string containing the encryption key
/// @param string[] $ciphertext_data Array of binary strings to be decrypted
/// @param string[] Indicates what type to cast the returned data with the same key, each value "INT" or "STRING", defaults to "INT" for any missing items
#[php_function]
pub fn decrypt_array(decryption_key: Binary<u8>, ciphertext_data: HashMap<String, Binary<u8>>, return_as: Option<HashMap<String, String>>) -> Result<HashMap<String, ResultType>, String> {
    let dk = DecryptionKey::from_bytes(decryption_key.to_vec())?;
    let return_types = return_as.unwrap_or_default();
    let mut decrypted: HashMap<String, ResultType> = HashMap::new();
    for (key, ct_data) in ciphertext_data.iter() {
        decrypted.insert(key.clone(), decrypt_ciphertext(&dk, ct_data, return_types.get(key).cloned())?);
    }

    Ok(decrypted)
}

fn decrypt_ciphertext(dk: &DecryptionKey, ct_data: &Binary<u8>, return_as: Option<String>) -> Result<ResultType, String> {
    let ciphertext = Ciphertext::from_slice(ct_data.to_vec());
    let Some(mut plaintext) = dk.decrypt(&ciphertext) else { return Err("Failed to decrypt".to_string()) };
    let return_type = return_as.unwrap_or("INT".to_string()).to_uppercase();
    match return_type.as_str() {
        "INT" => {
            plaintext.truncate(8);
            let Ok(byte_array) = <[u8; 8]>::try_from(plaintext.as_slice()) else { return Err("Could not convert value to int".to_string()) };
            Ok(ResultType::Int(i64::from_ne_bytes(byte_array)))
        },
        "STRING" => {
            let Ok(plaintext_str) = String::from_utf8(plaintext) else { return Err("Could not convert value to string".to_string()) };
            Ok(ResultType::Str(plaintext_str))
        },
        _ => Err("Bad return type".to_string())
    }
}

/// Paillier add two ciphertexts
/// @param string $encryption_key Binary string containing the encryption key
/// @param string $ct1_data Binary string of the first operand
/// @param string $ct2_data Binary string of the second operand
/// @return string The encrypted result of the addition
#[php_function]
pub fn add(encryption_key: Binary<u8>, ct1_data: Binary<u8>, ct2_data: Binary<u8>) -> Result<Binary<u8>, &'static str> {
    let Ok(ek) = EncryptionKey::from_bytes(encryption_key.to_vec()) else { return Err("Bad encryption key") };
    let ciphertext1 = Ciphertext::from_slice(ct1_data.to_vec());
    let ciphertext2 = Ciphertext::from_slice(ct2_data.to_vec());
    let sum = add_ciphertexts(&ek, &ciphertext1, &ciphertext2)?;
    Ok(sum.to_bytes().into_iter().collect::<Binary<_>>())
}

/// Paillier add all ciphertexts in an array
/// @param string $encryption_key Binary string containing the encryption key
/// @param string[] $ciphertext_data Array of ciphertexts to add
/// @return string The encrypted result of the addition
#[php_function]
pub fn add_array(encryption_key: Binary<u8>, ciphertext_data: HashMap<String, Binary<u8>>) -> Result<Binary<u8>, &'static str> {
    let Ok(ek) = EncryptionKey::from_bytes(encryption_key.to_vec()) else { return Err("Bad encryption key") };
    let Some((mut enc_total, _)) = ek.encrypt(&(0_i32.to_ne_bytes()), None) else { return Err("Failed to encrypt starting value") };
    for (_, ct_data) in ciphertext_data.iter() {
        let ciphertext = Ciphertext::from_slice(ct_data.to_vec());
        enc_total = add_ciphertexts(&ek, &enc_total, &ciphertext)?;
    }

    Ok(enc_total.to_bytes().into_iter().collect::<Binary<_>>())
}

fn add_ciphertexts(ek: &EncryptionKey, ciphertext1: &Ciphertext, ciphertext2: &Ciphertext) -> Result<Ciphertext, &'static str> {
    let Some(sum) = ek.add(&ciphertext1, &ciphertext2) else { return Err("Add failed") };
    Ok(sum)
}

pub extern "C" fn php_module_info(_module: *mut ModuleEntry) {
    info_table_start!();
    info_table_row!("Paillier PHP", "enabled");
    info_table_row!("Version", env!("CARGO_PKG_VERSION"));
    info_table_end!();
}

#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    module
        .function(wrap_function!(generate_keys))
        .function(wrap_function!(encrypt))
        .function(wrap_function!(encrypt_array))
        .function(wrap_function!(add))
        .function(wrap_function!(decrypt))
        .function(wrap_function!(decrypt_array))
        .info_function(php_module_info)
}
