/// Thin wrapper over Paillier-rs to make it a PHP module
/// Install the dev environment following the instructions here... https://ext-php.rs/getting-started/installation.html
/// Paillier-rs docs https://crates.io/crates/libpaillier
use std::collections::HashMap;
use ext_php_rs::{info_table_end, info_table_row, info_table_start, prelude::*, zend::ModuleEntry};
use fast_paillier::*;
use fast_paillier::backend::Integer;

#[derive(ZvalConvert, PartialEq, Debug)]
pub enum MsgType {
    Int(i64),
    Str(String),
    None
}

/// Returns a randomly generated keypair
/// @return array [0 => encryption_key, 1 => decryption_key, 'encryption_key' -> ..., 'decryption_key' => ...]
#[php_function]
pub fn pal_generate_keys() -> Result<HashMap<String, String>, &'static str> {
    let Ok(dk) = DecryptionKey::generate(&mut rand_core::OsRng) else { return Err("Failed to generate decryption key") };
    let ek = EncryptionKey::from_n(dk.n().clone());
    let mut keys = HashMap::new();
    keys.insert("0".to_string(), ek.n().to_str_radix(36));
    keys.insert("1".to_string(), format!("{}||{}", dk.p().to_str_radix(36), dk.q().to_str_radix(36)));
    keys.insert("encryption_key".to_string(), ek.n().to_str_radix(36));
    keys.insert("decryption_key".to_string(), format!("{}||{}", dk.p().to_str_radix(36), dk.q().to_str_radix(36)));
    Ok(keys)
}

/// Returns g & n for an encryption key so it can be used with other Paillier libraries
/// @param string $encryption_key Binary string containing the encryption key
/// @return array [0 => g, 1 => n, 'g' -> g, 'n' => n]
#[php_function]
pub fn pal_get_encryption_key_numbers(encryption_key: String) -> Result<HashMap<String, String>, String> {
    let Some(n) = Integer::from_str_radix(&encryption_key, 36) else { return Err("Bad encryption key data".to_string()) };
    let g: Integer = n.clone() + 1; // As best I can tell this is a standard optimisation that fast_paillier uses
    let mut numbers = HashMap::new();
    numbers.insert("0".to_string(), n.to_str_radix(36));
    numbers.insert("1".to_string(), g.to_str_radix(36));
    numbers.insert("n".to_string(), n.to_str_radix(36));
    numbers.insert("g".to_string(), g.to_str_radix(36));
    Ok(numbers)
}

/// Encrypt a message
/// @param string $encryption_key Binary string containing the encryption key
/// @param string $msg The int or string to be encrypted
/// @return string The encrypted ciphertext
#[php_function]
pub fn pal_encrypt(encryption_key: String, msg: MsgType) -> Result<String, String> {
    let ek = validate_encryption_key(encryption_key)?;
    Ok((encrypt_msg(&ek, &msg)?).to_str_radix(36))
}

/// Encrypt an array of messages
/// @param string $encryption_key Binary string containing the encryption key
/// @param string|int[] $msgs Array of ints or strings to be encrypted
/// @return string[] The encrypted ciphertext, keys are preserved
#[php_function]
pub fn pal_encrypt_array(encryption_key: String, msgs: HashMap<String, MsgType>) -> Result<HashMap<String, String>, String> {
    let ek = validate_encryption_key(encryption_key)?;
    let mut encrypted: HashMap<String, String> = HashMap::new();
    for (key, msg) in msgs.iter() {
        encrypted.insert(key.clone(), (encrypt_msg(&ek, msg)?).to_str_radix(36));
    }

    Ok(encrypted)
}

fn validate_encryption_key(encryption_key_data: String) -> Result<EncryptionKey, String> {
    let Some(n) = Integer::from_str_radix(&encryption_key_data, 36) else { return Err("Bad encryption key data".to_string()) };
    Ok(EncryptionKey::from_n(n))
}

fn encrypt_msg(ek: &EncryptionKey, msg: &MsgType) -> Result<Ciphertext, String> {
    let msg_data = match msg {
        MsgType::Int(int_val) => Integer::from(*int_val as u32),
        // TODO vvv Which string format do we want? vvv
        //MsgResultType::Str(str_val) => Integer::parse(str_val.as_bytes()).unwrap().complete(),
        MsgType::Str(str_val) => match Integer::from_str_radix(str_val, 36) {
            Some(int) => int,
            None => return Err("Bad message data".to_string()),
        },
        MsgType::None => return Err("Bad type".to_string()),
    };
    let Ok((ciphertext, _)) = ek.encrypt_with_random(&mut rand_core::OsRng, &msg_data) else { return Err("Failed to encrypt".to_string()) };
    Ok(ciphertext)
}

/// Decrypt a ciphertext
/// @param string $decryption_key Binary string containing the decryption key
/// @param string $ct_data Binary ciphertext string to be decrypted
/// @return string The decrypted plaintext
#[php_function]
pub fn pal_decrypt(decryption_key_data: String, ct_data: String) -> Result<String, String> {
    let dk = validate_decryption_key(decryption_key_data)?;
    let Some(ciphertext) = Ciphertext::from_str_radix(&ct_data, 36) else { return Err("Bad ciphertext data".to_string()) };
    decrypt_ciphertext(&dk, &ciphertext)
}

/// Decrypt an array of ciphertexts
/// @param string $encryption_key Binary string containing the encryption key
/// @param string[] $ciphertext_data Array of binary strings to be decrypted
/// @return string[] Array of decrypted plaintexts (base36 encoded)
#[php_function]
pub fn pal_decrypt_array(decryption_key_data: String, ciphertext_data: HashMap<String, String>) -> Result<HashMap<String, String>, String> {
    let dk = validate_decryption_key(decryption_key_data)?;
    let mut decrypted: HashMap<String, String> = HashMap::new();
    for (key, ct_data) in ciphertext_data.iter() {
        let Some(ciphertext) = Ciphertext::from_str_radix(ct_data, 36) else { return Err(format!("Bad ciphertext_data[{}]", key)) };
        decrypted.insert(key.clone(), decrypt_ciphertext(&dk, &ciphertext)?);
    }

    Ok(decrypted)
}

fn validate_decryption_key(decryption_key_data: String) -> Result<DecryptionKey, String> {
    let pq: Vec<&str> = decryption_key_data.split("||").collect();
    if pq.len() != 2 {
        return Err("Bad decryption key data".to_string());
    }
    let Some(p) = Integer::from_str_radix(pq[0], 36) else { return Err("Bad decryption key data (p)".to_string()) };
    let Some(q) = Integer::from_str_radix(pq[1], 36) else { return Err("Bad decryption key data (q)".to_string()) };
    let Ok(dk) = DecryptionKey::from_primes(p, q) else { return Err("Failed to recreate decryption key".to_string()) };
    Ok(dk)
}

fn decrypt_ciphertext(dk: &DecryptionKey, ciphertext: &Ciphertext) -> Result<String, String> {
    let Ok(plaintext) = dk.decrypt(ciphertext) else { return Err("Failed to decrypt".to_string()) };
    Ok(plaintext.to_str_radix(36))
}

/// Paillier add two ciphertexts
/// @param string $encryption_key Binary string containing the encryption key
/// @param string $ct1_data Binary string of the first operand
/// @param string $ct2_data Binary string of the second operand
/// @return string The encrypted result of the addition
#[php_function]
pub fn pal_add(encryption_key: String, ct1_data: String, ct2_data: String) -> Result<String, String> {
    let ek = validate_encryption_key(encryption_key)?;
    let Some(ciphertext1) = Ciphertext::from_str_radix(&ct1_data, 36) else { return Err("Bad ct1_data".to_string()) };
    let Some(ciphertext2) = Ciphertext::from_str_radix(&ct2_data, 36) else { return Err("Bad ct2_data".to_string()) };
    let sum = add_ciphertexts(&ek, &ciphertext1, &ciphertext2)?;
    Ok(sum.to_str_radix(36))
}

/// Paillier add all ciphertexts in an array
/// @param string $encryption_key Binary string containing the encryption key
/// @param string[] $ciphertext_data Array of ciphertexts to add
/// @return string The encrypted result of the addition
#[php_function]
pub fn pal_add_array(encryption_key: String, ciphertext_data: HashMap<String, String>) -> Result<String, String> {
    let ek = validate_encryption_key(encryption_key)?;
    if ciphertext_data.is_empty() {
        return Err("Nothing to add".to_string());
    }

    let mut enc_total: Option<Ciphertext> = None;
    for (_, ct_data) in ciphertext_data.iter() {
        let Some(ciphertext) = Ciphertext::from_str_radix(ct_data, 36) else { return Err("Bad ciphertext data".to_string()) };
        match enc_total {
            Some(curr_total) => enc_total = Some(add_ciphertexts(&ek, &curr_total, &ciphertext)?),
            None => enc_total = Some(ciphertext),
        }
    }

    match enc_total {
        Some(final_total) => Ok(final_total.to_str_radix(36)),
        None => Err("Error adding array".to_string()),
    }
}

fn add_ciphertexts(ek: &EncryptionKey, ciphertext1: &Ciphertext, ciphertext2: &Ciphertext) -> Result<Ciphertext, String> {
    let Ok(sum) = ek.oadd(ciphertext1, ciphertext2) else { return Err("Add failed".to_string()) };
    Ok(sum)
}

/// Paillier multiply a ciphertext by a number
/// @param string $encryption_key Binary string containing the encryption key
/// @param string $ct_data Binary string of the ciphertext
/// @param int $factor number by which to multiply the cipertext
/// @return string The encrypted result of the multiplication
#[php_function]
pub fn pal_multiply(encryption_key: String, ct_data: String, factor: i64) -> Result<String, String> {
    let ek = validate_encryption_key(encryption_key)?;
    let Some(ciphertext) = Ciphertext::from_str_radix(&ct_data, 36) else { return Err("Bad ciphertext data".to_string()) };
    let fac = Integer::zero() + factor; // can't create from<i64> but can add it to zero
    let mult_ciphertext = multiply_ciphertext(&ek, &ciphertext, fac)?;
    Ok(mult_ciphertext.to_str_radix(36))
}

fn multiply_ciphertext(ek: &EncryptionKey, ciphertext: &Ciphertext, factor: Integer) -> Result<Ciphertext, String> {
    let Ok(mult_ciphertext) = ek.omul(&factor, ciphertext) else { return Err("Failed to multipy".to_string()) };
    Ok(mult_ciphertext)
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
        .function(wrap_function!(pal_generate_keys))
        .function(wrap_function!(pal_get_encryption_key_numbers))
        .function(wrap_function!(pal_encrypt))
        .function(wrap_function!(pal_encrypt_array))
        .function(wrap_function!(pal_add))
        .function(wrap_function!(pal_add_array))
        .function(wrap_function!(pal_multiply))
        .function(wrap_function!(pal_decrypt))
        .function(wrap_function!(pal_decrypt_array))
        .info_function(php_module_info)
}

#[cfg(test)]
mod tests {
    use rand_core::RngCore;

    use super::*;

    #[test]
    fn keys() -> Result<(), String> {
        let keys = pal_generate_keys()?;
        let Some(_) = keys.get("0") else { return Err("Missing key 0".to_string()) };
        let Some(_) = keys.get("1") else { return Err("Missing key 1".to_string()) };
        let Some(_) = keys.get("encryption_key") else { return Err("Missing key encryption_key".to_string()) };
        let Some(_) = keys.get("decryption_key") else { return Err("Missing key decryption_key".to_string()) };
        Ok(())
    }

    #[test]
    #[ignore]
    fn show_keys() -> Result<(), String> {
        let keys = pal_generate_keys()?;
        return Err(format!("{:?}", keys));
    }

    #[test]
    fn encrypt_decrypt() -> Result<(), String> {
        let keys = pal_generate_keys()?;
        let Some(ek_data) = keys.get("encryption_key") else { return Err("No encryption key".to_string()) };
        let ek = validate_encryption_key(ek_data.to_string())?;
        let Some(dk_data) = keys.get("decryption_key") else { return Err("No decryption key".to_string()) };
        let dk = validate_decryption_key(dk_data.to_string())?;

        let mut rng = rand_core::OsRng;
        let plain_val = rng.next_u32() as i64;
        let plain_str = (Integer::zero() + plain_val).to_str_radix(36);
        let enc_val = encrypt_msg(&ek, &MsgType::Int(plain_val))?;
        let dec_val = decrypt_ciphertext(&dk, &enc_val)?;
        assert_eq!(plain_str, dec_val);
        Ok(())
    }

    #[test]
    fn enc_add() -> Result<(), String> {
        let keys = pal_generate_keys()?;
        let Some(ek_data) = keys.get("encryption_key") else { return Err("No encryption key".to_string()) };
        let ek = validate_encryption_key(ek_data.to_string())?;
        let Some(dk_data) = keys.get("decryption_key") else { return Err("No decryption key".to_string()) };
        let dk = validate_decryption_key(dk_data.to_string())?;

        let mut rng = rand_core::OsRng;
        let plain1 = rng.next_u32() as i64;
        let plain2 = rng.next_u32() as i64;
        let plain_sum = plain1 + plain2;
        let plain_str = (Integer::zero() + plain_sum).to_str_radix(36);

        let enc1 = encrypt_msg(&ek, &MsgType::Int(plain1))?;
        let enc2 = encrypt_msg(&ek, &MsgType::Int(plain2))?;
        let enc_sum = add_ciphertexts(&ek, &enc1, &enc2)?;
        let sum = decrypt_ciphertext(&dk, &enc_sum)?;

        assert_eq!(sum, plain_str, "p1 {plain1} p2 {plain2} psum {plain_sum} sum {sum:?}");
        Ok(())
    }

    #[test]
    fn enc_add_array() -> Result<(), String> {
        let keys = pal_generate_keys()?;
        let Some(ek_data) = keys.get("encryption_key") else { return Err("No encryption key".to_string()) };
        let ek = validate_encryption_key(ek_data.to_string())?;
        let Some(dk_data) = keys.get("decryption_key") else { return Err("No decryption key".to_string()) };
        let dk = validate_decryption_key(dk_data.to_string())?;

        let mut rng = rand_core::OsRng;
        let plain1 = rng.next_u32() as i64;
        let enc1 = (encrypt_msg(&ek, &MsgType::Int(plain1))?).to_str_radix(36);
        let plain2 = rng.next_u32() as i64;
        let enc2 = (encrypt_msg(&ek, &MsgType::Int(plain2))?).to_str_radix(36);
        let plain3 = rng.next_u32() as i64;
        let enc3 = (encrypt_msg(&ek, &MsgType::Int(plain3))?).to_str_radix(36);
        let plain_sum = plain1 + plain2 + plain3;
        let plain_str = (Integer::zero() + plain_sum).to_str_radix(36);

        let mut ary = HashMap::new();
        ary.insert("1".to_string(), enc1);
        ary.insert("2".to_string(), enc2);
        ary.insert("3".to_string(), enc3);
        let array_sum_data = pal_add_array(ek_data.to_string(), ary)?;
        let Some(array_sum) = Integer::from_str_radix(&array_sum_data, 36) else { return Err("Bad array sum data".to_string()) };
        let dec_sum = decrypt_ciphertext(&dk, &array_sum)?;
        assert_eq!(plain_str, dec_sum);
        Ok(())
    }

    #[test]
    fn multiply() -> Result<(), String> {
        let keys = pal_generate_keys()?;
        let Some(ek_data) = keys.get("encryption_key") else { return Err("No encryption key".to_string()) };
        let ek = validate_encryption_key(ek_data.to_string())?;
        let Some(dk_data) = keys.get("decryption_key") else { return Err("No decryption key".to_string()) };
        let dk = validate_decryption_key(dk_data.to_string())?;

        let mut rng = rand_core::OsRng;
        let plain_val = rng.next_u32() as i64;
        let enc_val = encrypt_msg(&ek, &MsgType::Int(plain_val))?;
        let factor = (rng.next_u32() as u16) as i64;
        let fac = Integer::zero() + factor;
        let plain_str = (fac.clone() * plain_val).to_str_radix(36);
        let mult_val = multiply_ciphertext(&ek, &enc_val, fac)?;
        let dec_val = decrypt_ciphertext(&dk, &mult_val)?;
        assert_eq!(plain_str, dec_val);
        Ok(())
    }

    #[test]
    pub fn enc_dec_zero() -> Result<(), String> {
        let keys = pal_generate_keys()?;
        let Some(ek_data) = keys.get("encryption_key") else { return Err("No encryption key".to_string()) };
        let ek = validate_encryption_key(ek_data.to_string())?;
        let Some(dk_data) = keys.get("decryption_key") else { return Err("No decryption key".to_string()) };
        let dk = validate_decryption_key(dk_data.to_string())?;

        let plain_zero = 0_i64;
        let plain_str = (Integer::zero() + plain_zero).to_str_radix(36);
        let enc_zero = encrypt_msg(&ek, &MsgType::Int(plain_zero))?;
        let dec_zero = decrypt_ciphertext(&dk, &enc_zero)?;
        assert_eq!(plain_str, dec_zero);
        Ok(())
    }
}
