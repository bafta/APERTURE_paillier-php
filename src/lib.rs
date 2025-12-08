/// Thin wrapper over Paillier-rs to make it a PHP module
/// Install the dev environment following the instructions here... https://ext-php.rs/getting-started/installation.html
/// Paillier-rs docs https://crates.io/crates/libpaillier
use std::collections::HashMap;
use ext_php_rs::{info_table_end, info_table_row, info_table_start, prelude::*, zend::ModuleEntry, binary::Binary};
use libpaillier::{Ciphertext, DecryptionKey, EncryptionKey};

#[derive(ZvalConvert, PartialEq, Debug)]
pub enum MsgResultType {
    Int(i64),
    Str(String),
    None
}

//#[derive(ZvalConvert, PartialEq, Debug)]
//pub enum ResultType {
//    Int(i64),
//    Str(String),
//    None
//}

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
pub fn encrypt(encryption_key: Binary<u8>, msg: MsgResultType) -> Result<Binary<u8>, String> {
    let ek = EncryptionKey::from_bytes(encryption_key.to_vec())?;
    Ok((encrypt_msg(&ek, &msg)?).to_bytes().into_iter().collect::<Binary<_>>())
}

/// Encrypt an array of messages
/// @param string $encryption_key Binary string containing the encryption key
/// @param string|int[] $msgs Array of ints or strings to be encrypted
/// @return string[] The encrypted ciphertext, keys are preserved
#[php_function]
pub fn encrypt_array(encryption_key: Binary<u8>, msgs: HashMap<String, MsgResultType>) -> Result<HashMap<String, Binary<u8>>, String> {
    let ek = EncryptionKey::from_bytes(encryption_key.to_vec())?;
    let mut encrypted: HashMap<String, Binary<u8>> = HashMap::new();
    for (key, msg) in msgs.iter() {
        encrypted.insert(key.clone(), (encrypt_msg(&ek, msg)?).to_bytes().into_iter().collect::<Binary<_>>());
    }

    Ok(encrypted)
}

fn encrypt_msg(ek: &EncryptionKey, msg: &MsgResultType) -> Result<Ciphertext, String> {
    let msg_data = match msg {
        MsgResultType::Int(int_val) => &(int_val.to_be_bytes()), // MUST be big-endian for paillier addition to work
        MsgResultType::Str(str_val) => str_val.as_bytes(),
        MsgResultType::None => return Err("Bad type".to_string()),
    };
    let Some((ciphertext, _)) = ek.encrypt(msg_data, None) else { return Err("Failed to encrypt".to_string()) };
    Ok(ciphertext)
}

/// Decrypt a ciphertext
/// @param string $decryption_key Binary string containing the decryption key
/// @param string $ct_data Binary ciphertext string to be decrypted
/// @param string $return_as Indicates what type to cast the returned data as, "INT" or "STRING", default "INT"
/// @return string The decrypted plaintext
#[php_function]
pub fn decrypt(decryption_key: Binary<u8>, ct_data: Binary<u8>, return_as: Option<String>) -> Result<MsgResultType, String> {
    let dk = DecryptionKey::from_bytes(decryption_key.to_vec())?;
    decrypt_ciphertext(&dk, &Ciphertext::from_slice(ct_data.to_vec()), return_as)
}

/// Decrypt an array of ciphertexts
/// @param string $encryption_key Binary string containing the encryption key
/// @param string[] $ciphertext_data Array of binary strings to be decrypted
/// @param string[] Indicates what type to cast the returned data with the same key, each value "INT" or "STRING", defaults to "INT" for any missing items
#[php_function]
pub fn decrypt_array(decryption_key: Binary<u8>, ciphertext_data: HashMap<String, Binary<u8>>, return_as: Option<HashMap<String, String>>) -> Result<HashMap<String, MsgResultType>, String> {
    let dk = DecryptionKey::from_bytes(decryption_key.to_vec())?;
    let return_types = return_as.unwrap_or_default();
    let mut decrypted: HashMap<String, MsgResultType> = HashMap::new();
    for (key, ct_data) in ciphertext_data.iter() {
        decrypted.insert(key.clone(), decrypt_ciphertext(&dk, &Ciphertext::from_slice(ct_data.to_vec()), return_types.get(key).cloned())?);
    }

    Ok(decrypted)
}

fn decrypt_ciphertext(dk: &DecryptionKey, ciphertext: &Ciphertext, return_as: Option<String>) -> Result<MsgResultType, String> {
    let Some(mut plaintext) = dk.decrypt(ciphertext) else { return Err("Failed to decrypt".to_string()) };
    let return_type = return_as.unwrap_or("INT".to_string()).to_uppercase();
    match return_type.as_str() {
        "INT" => {
            plaintext.truncate(8);
            // plaintext may be fewer than 8 long due to leading 0's being trimmed -- add them back in
            for _ in 0..(8 - plaintext.len()) {
                plaintext.insert(0, 0);
            }
            let Ok(byte_array) = <[u8; 8]>::try_from(plaintext.as_slice()) else { return Err("Could not convert value to int".to_string()) };
            Ok(MsgResultType::Int(i64::from_be_bytes(byte_array)))
        },
        "STRING" => {
            let Ok(plaintext_str) = String::from_utf8(plaintext) else { return Err("Could not convert value to string".to_string()) };
            Ok(MsgResultType::Str(plaintext_str))
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
    let Some((mut enc_total, _)) = ek.encrypt(0_i32.to_ne_bytes(), None) else { return Err("Failed to encrypt starting value") };
    for (_, ct_data) in ciphertext_data.iter() {
        let ciphertext = Ciphertext::from_slice(ct_data.to_vec());
        enc_total = add_ciphertexts(&ek, &enc_total, &ciphertext)?;
    }

    Ok(enc_total.to_bytes().into_iter().collect::<Binary<_>>())
}

fn add_ciphertexts(ek: &EncryptionKey, ciphertext1: &Ciphertext, ciphertext2: &Ciphertext) -> Result<Ciphertext, &'static str> {
    let Some(sum) = ek.add(ciphertext1, ciphertext2) else { return Err("Add failed") };
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
        .function(wrap_function!(add_array))
        .function(wrap_function!(decrypt))
        .function(wrap_function!(decrypt_array))
        .info_function(php_module_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn keys() -> Result<(), &'static str> {
        let keys = generate_keys()?;
        let Some(_) = keys.get("0") else { return Err("Missing key 0") };
        let Some(_) = keys.get("1") else { return Err("Missing key 1") };
        let Some(_) = keys.get("encryption_key") else { return Err("Missing key encryption_key") };
        let Some(_) = keys.get("decryption_key") else { return Err("Missing key decryption_key") };
        Ok(())
    }

    #[test]
    fn encrypt_decrypt() -> Result<(), String> {
        let keys = generate_keys()?;
        let Some(ek_data) = keys.get("encryption_key") else { return Err("No encryption key".to_string()) };
        let Ok(ek) = EncryptionKey::from_bytes(ek_data.to_vec()) else { return Err("Bad encryption key data".to_string()) };
        let Some(dk_data) = keys.get("decryption_key") else { return Err("No deryption key".to_string()) };
        let Ok(dk) = DecryptionKey::from_bytes(dk_data.to_vec()) else { return Err("Bad encryption key data".to_string()) };

        let mut rng = rand::rng();
        let plain_val = rng.random::<u32>() as i64;
        let enc_val = encrypt_msg(&ek, &MsgResultType::Int(plain_val))?;
        let dec_val = decrypt_ciphertext(&dk, &enc_val, None)?;
        assert_eq!(MsgResultType::Int(plain_val), dec_val);
        Ok(())
    }

    #[test]
    fn enc_add() -> Result<(), String> {
        let keys = generate_keys()?;
        let Some(ek_data) = keys.get("encryption_key") else { return Err("No encryption key".to_string()) };
        let Ok(ek) = EncryptionKey::from_bytes(ek_data.to_vec()) else { return Err("Bad encryption key data".to_string()) };
        let Some(dk_data) = keys.get("decryption_key") else { return Err("No deryption key".to_string()) };
        let Ok(dk) = DecryptionKey::from_bytes(dk_data.to_vec()) else { return Err("Bad encryption key data".to_string()) };

        let mut rng = rand::rng();
        let plain1 = rng.random::<u32>() as i64;
        let plain2 = rng.random::<u32>() as i64;
        let plain_sum = plain1 + plain2;

        let enc1 = encrypt_msg(&ek, &MsgResultType::Int(plain1))?;
        let enc2 = encrypt_msg(&ek, &MsgResultType::Int(plain2))?;
        let enc_sum = add_ciphertexts(&ek, &enc1, &enc2)?;
        let sum = decrypt_ciphertext(&dk, &enc_sum, None)?;

        assert_eq!(sum, MsgResultType::Int(plain_sum), "p1 {plain1} p2 {plain2} psum {plain_sum} sum {sum:?}");
        Ok(())
    }
}
