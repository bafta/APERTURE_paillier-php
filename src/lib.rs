/**
 * Thin wrapper over Paillier-rs to make it a PHP module
 * Install the dev environment following the instrictions here... https://ext-php.rs/getting-started/installation.html
 * Paillier-rs docs https://crates.io/crates/libpaillier
 */
use std::collections::HashMap;
use ext_php_rs::{info_table_end, info_table_row, info_table_start, prelude::*, zend::ModuleEntry, binary::Binary};
use libpaillier::{Ciphertext, DecryptionKey, EncryptionKey};

/// Returns a randomly generated keypair
/// @return Array [0 => encryption_key, 1 => decryption_key, 'encryption_key' -> ..., 'decryption_key' => ...]
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
/// @param string $msg The binary string to be encrypted
/// @return string The encrypted ciphertext
#[php_function]
pub fn encrypt(encryption_key: Binary<u8>, msg: Binary<u8>) -> Result<Binary<u8>, &'static str> {
    let Ok(ek) = EncryptionKey::from_bytes(encryption_key.to_vec()) else { return Err("Bad encryption key") };
    let Some((ciphertext, _)) = ek.encrypt(msg.to_vec(), None) else { return Err("Failed to encrypt") };
    Ok(ciphertext.to_bytes().into_iter().collect::<Binary<_>>())
}

/// Decrypt a message
/// @param string $decryption_key Binary string containing the decryption key
/// @param string $ct_data The binary ciphertext string to be decrypted
/// @return string The decrypted plaintext
#[php_function]
pub fn decrypt(decryption_key: Binary<u8>, ct_data: Binary<u8>) -> Result<Binary<u8>, &'static str> {
    let Ok(dk) = DecryptionKey::from_bytes(decryption_key.to_vec()) else { return Err("Bad decryption key") };
    let ciphertext = Ciphertext::from_slice(ct_data.to_vec());
    let Some(plaintext) = dk.decrypt(&ciphertext) else { return Err("Failed to decrypt") };
    Ok(plaintext.into_iter().collect::<Binary<_>>())
}

/// Paillier add two ciphertexts
/// @param string $encryption_key Binary string containing the encryption key
/// @param string ct1_data Binary string of the first operand
/// @param string ct2_data Binary string of the second operand
/// @return string The encrypted result of the addition
#[php_function]
pub fn add(encryption_key: Binary<u8>, ct_data1: Binary<u8>, ct_data2: Binary<u8>) -> Result<Binary<u8>, &'static str> {
    let Ok(ek) = EncryptionKey::from_bytes(encryption_key.to_vec()) else { return Err("Bad encryption key") };
    let ciphertext1 = Ciphertext::from_slice(ct_data1.to_vec());
    let ciphertext2 = Ciphertext::from_slice(ct_data2.to_vec());
    let Some(sum) = ek.add(&ciphertext1, &ciphertext2) else { return Err("Add failed") };
    Ok(sum.to_bytes().into_iter().collect::<Binary<_>>())
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
        .function(wrap_function!(decrypt))
        .function(wrap_function!(add))
        .info_function(php_module_info)
}
