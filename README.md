# paillier-php

A PHP extension providing [Paillier homomorphic encryption](https://en.wikipedia.org/wiki/Paillier_cryptosystem), built in Rust using [ext-php-rs](https://ext-php.rs/).

Paillier is a partially homomorphic encryption scheme, meaning you can perform arithmetic on encrypted data without decrypting it first. Specifically, given ciphertexts you can:

- **Add** two encrypted values to get an encrypted sum
- **Multiply** an encrypted value by a plaintext scalar

This is useful for privacy-preserving computation -- for example, a server can compute totals over encrypted data without ever seeing the underlying values.

The cryptographic implementation is provided by the [fast-paillier](https://crates.io/crates/fast-paillier) Rust crate (currently using [a fork](https://github.com/bafta/fast-paillier) at v0.3.2 due to an upstream build issue).

## Prerequisites

- **Rust** toolchain (install via [rustup](https://rustup.rs/))
- **PHP 8.4+** with development headers
- **ext-php-rs** dev environment -- follow the [installation instructions](https://ext-php.rs/getting-started/installation.html)

## Installation

Build and install the extension:

```bash
cargo build
sudo -E path/to/cargo php install
```

Or copy the pre-built shared object directly:

```bash
cp ./target/debug/libpaillier_php.so /usr/lib/php/20240924/libpaillier_php.so
```

You may also need to add `extension=libpaillier_php.so` to your php.ini although `cargo php install` should have done this.

## Data format

All keys, ciphertexts, and large numeric return values are represented as **base-36 encoded strings**.

## API

### Key management

```php
/**
 * Generate a random Paillier keypair.
 * @return array [0 => encryption_key, 1 => decryption_key, 'encryption_key' -> encryption_key, 'decryption_key' => decryption_key]
 */
function pal_generate_keys(): array

/**
 * Extract the public parameters (n, g) from an encryption key for interop with other Paillier libraries.
 * @param string $encryption_key The encryption key (base-36 encoded)
 * @return array [0 => g, 1 => n, 'g' -> g, 'n' => n]
 */
function pal_get_encryption_key_numbers(string $encryption_key): array
```

### Encryption

```php
/**
 * Encrypt a single message.
 * @param string $encryption_key The encryption key (base-36 encoded)
 * @param int|string $msg An integer or base-36 encoded string to encrypt
 * @return string The ciphertext (base-36 encoded)
 */
function pal_encrypt(string $encryption_key, int|string $msg): string

/**
 * Encrypt an array of messages. Array keys are preserved.
 * @param string $encryption_key The encryption key (base-36 encoded)
 * @param (int|string)[] $msgs Messages to encrypt
 * @return (int|string)[] Ciphertexts (base-36 encoded)
 */
function pal_encrypt_array(string $encryption_key, array $msgs): array
```

### Homomorphic operations

```php
/**
 * Add two ciphertexts (homomorphic addition).
 * @param string $encryption_key The encryption key (base-36 encoded)
 * @param string $ct1_data First ciphertext (base-36 encoded)
 * @param string $ct2_data Second ciphertext (base-36 encoded)
 * @return string The encrypted sum (base-36 encoded)
 */
function pal_add(string $encryption_key, string $ct1_data, string $ct2_data): string

/**
 * Sum all ciphertexts in an array (homomorphic addition).
 * @param string $encryption_key The encryption key (base-36 encoded)
 * @param string[] $ciphertext_data Ciphertexts to sum (base-36 encoded)
 * @return string The encrypted total (base-36 encoded)
 */
function pal_add_array(string $encryption_key, array $ciphertext_data): string

/**
 * Multiply a ciphertext by a plaintext scalar (homomorphic scalar multiplication).
 * @param string $encryption_key The encryption key (base-36 encoded)
 * @param string $ct_data The ciphertext (base-36 encoded)
 * @param int $factor The scalar to multiply by
 * @return string The encrypted product (base-36 encoded)
 */
function pal_multiply(string $encryption_key, string $ct_data, int $factor): string
```

### Decryption

```php
/**
 * Decrypt a ciphertext.
 * @param string $decryption_key The decryption key (base-36 encoded)
 * @param string $ct_data The ciphertext (base-36 encoded)
 * @return string The decrypted plaintext (base-36 encoded)
 */
function pal_decrypt(string $decryption_key, string $ct_data): string

/**
 * Decrypt an array of ciphertexts. Array keys are preserved.
 * @param string $decryption_key The decryption key (base-36 encoded)
 * @param string[] $ciphertext_data Ciphertexts to decrypt (base-36 encoded)
 * @return string[] Decrypted plaintexts (base-36 encoded)
 */
function pal_decrypt_array(string $decryption_key, array $ciphertext_data): array
```

## Example

```php
// Generate a keypair
$keys = pal_generate_keys();
$ek = $keys['encryption_key'];
$dk = $keys['decryption_key'];

// Encrypt two values
$enc_a = pal_encrypt($ek, 42);
$enc_b = pal_encrypt($ek, 8);

// Add them while still encrypted
$enc_sum = pal_add($ek, $enc_a, $enc_b);

// Decrypt the result
$sum = pal_decrypt($dk, $enc_sum); // "1e" (50 in base-36)

// Scalar multiplication
$enc_doubled = pal_multiply($ek, $enc_a, 2);
$doubled = pal_decrypt($dk, $enc_doubled); // "2a" (84 in base-36)
```

## Running tests

```bash
cargo test -- --test-threads=1
```
