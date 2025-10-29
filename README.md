# PHP Paillier encryption library and PHP extension
[Wraps libpaillier](https://crates.io/crates/libpaillier)
## Usage
```php
<?php
/**
 * Returns a randomly generated keypair
 * @return array [0 => encryption_key, 1 => decryption_key, 'encryption_key' -> ..., 'decryption_key' => ...]
 */
function generate_keys(): array

/**
 * Encrypt a message
 * @param string $encryption_key Binary string containing the encryption key
 * @param string $msg The int or string to be encrypted
 * @return string The encrypted ciphertext
 */
function encrypt(string $encryption_key, mixed $msg): string

/**
 * Encrypt an array of messages
 * @param string $encryption_key Binary string containing the encryption key
 * @param string|int[] $msgs Array of ints or strings to be encrypted
 * @return string[] The encrypted ciphertext, keys are preserved
 */
function encrypt_array(string $encryption_key, array $msgs): array

/**
 * Paillier add two ciphertexts
 * @param string $encryption_key Binary string containing the encryption key
 * @param string ct1_data Binary string of the first operand
 * @param string ct2_data Binary string of the second operand
 * @return string The encrypted result of the addition
 */
function add(string $encryption_key, string $ct1_data, string $ct2_data): string

/**
 * Decrypt a ciphertext
 * @param string $decryption_key Binary string containing the decryption key
 * @param string $ct_data Binary ciphertext string to be decrypted
 * @param string $return_as Indicates what type to cast the returned data as, "INT" or "STRING", default "INT"
 * @return int|string The decrypted plaintext
 */
function decrypt(string $decryption_key, string $ct_data, ?string $return_as): int|string

/**
 * Decrypt an array of ciphertexts
 * @param string $encryption_key Binary string containing the encryption key
 * @param string[] $ciphertext_data Array of binary strings to be decrypted
 * @param string[] Indicates what type to cast the returned data with the same key, each value "INT" or "STRING", defaults to "INT" for any missing items
 */
function decrypt_array(string $decryption_key, array $ciphertext_data, ?array $return_as): array
```
## Installation
Install the dev environment following [these instructions](https://ext-php.rs/getting-started/installation.html) then
```bash
$ cargo install
$ cargo build
$ sudo -E path/to/cargo php install
```
