# Rusty Crystals

A Rust implementation of the ML-DSA (CRYSTALS-Dilithium) post-quantum digital signature scheme with hierarchical deterministic (HD) wallet support.

This workspace provides post-quantum cryptographic primitives and HD wallet functionality compatible with BIP-32, BIP-39, and BIP-44 standards.

## Security Features

This implementation provides enterprise-grade memory security through `SensitiveBytes*` wrapper types that:

- **Prevent accidental copying** - Compile-time enforcement ensures sensitive data can only be moved, never copied
- **Automatic memory zeroization** - Both source arrays and wrapper contents are automatically cleared when dropped
- **Explicit sensitive data handling** - API requires `(&mut entropy).into()` syntax, making sensitive operations obvious
- **Move-only semantics** - Functions take `SensitiveBytes32`/`SensitiveBytes64` directly, preventing silent reference copying

```rust
// Secure by design - entropy is zeroized after conversion
let mut entropy = [0u8; 32];
getrandom::getrandom(&mut entropy).unwrap();
let keypair = ml_dsa_87::Keypair::generate((&mut entropy).into());
// entropy is now [0,0,0,...] - no sensitive data left in memory
```

This eliminates entire classes of security vulnerabilities related to sensitive data handling in cryptographic applications.

## Overview

This workspace contains two independent crates:

- **`qp-rusty-crystals-dilithium`** - ML-DSA digital signature implementation
- **`qp-rusty-crystals-hdwallet`** - HD wallet for post-quantum keys

## Usage

### ML-DSA Digital Signatures

```toml
[dependencies]
qp-rusty-crystals-dilithium = "2.0.0"
getrandom = "0.2"  # For secure entropy generation if needed
```

**Security Note**: When generating entropy for cryptographic operations, always use cryptographically secure random sources. Never use predictable strings, timestamps, or user input as entropy.

```rust
use qp_rusty_crystals_dilithium::ml_dsa_87;

// Generate secure entropy
let mut entropy = [0u8; 32];
getrandom::getrandom(&mut entropy).expect("Failed to generate entropy");

// Generate keypair
let keypair = ml_dsa_87::Keypair::generate((&mut entropy).into()).expect("Failed to generate keypair");

// Sign message
let message = b"Hello, post-quantum world!";
let signature = keypair.sign(message, None, None);

// Verify signature
let is_valid = keypair.verify(message, &signature, None);
```

### HD Wallet

```toml
[dependencies]
qp-rusty-crystals-hdwallet = "1.0.0"
```

```rust
use qp_rusty_crystals_hdwallet::{generate_mnemonic, HDLattice};

// Generate secure seed for mnemonic
let mut seed = [0u8; 32];
getrandom::getrandom(&mut seed).expect("Failed to generate seed");

// Generate mnemonic
let mnemonic = generate_mnemonic((&mut seed).into())?;

// Create HD wallet
let hd_wallet = HDLattice::from_mnemonic(&mnemonic, None)?;

// Derive keys using BIP-44 path
let keys = hd_wallet.generate_derived_keys("44'/0'/0'/0'/0'")?;
```

## Crates

### qp-rusty-crystals-dilithium
ML-DSA digital signature implementation:
- **ML-DSA-44, ML-DSA-65, ML-DSA-87** - All security levels
- **NIST Compliant** - Verified against official test vectors  
- **Pure Rust** - Memory-safe, no unsafe code
- **High Performance** - Optimized implementation

### qp-rusty-crystals-hdwallet
Post-quantum HD wallet:
- **BIP-39 Compatible** - Mnemonic phrase generation/restoration
- **BIP-32 Derivation** - Hierarchical deterministic keys
- **BIP-44 Paths** - Standard derivation paths
- **Hardened Keys Only** - Secure post-quantum derivation


## Testing

Run all tests with:

```bash
cargo test --workspace
```

For test coverage:

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --workspace
```

### NIST KAT tests

test_nist_kat test case in 'verify_integration_tests.rs' covers the NIST KAT test cases generated from the PQCrystals 
for ML-DSA-87. We exported the test file from PQ-Crystals c code, and are importing and testing against it here. 

To regenerate this file...
```
git clone https://github.com/pq-crystals/dilithium
cd dilithium/ref
make nistkat
./nistkat/PQCgenKAT_sign5 
cp ./nistkat/PQCsignKAT_Dilithium5.rsp ???
```

## Code Coverage
This repository has 100% code coverage for all critical logic and functionality. 
```./coverage.sh```

## License

[GPL-3.0](LICENSE) - See LICENSE file for details.

## Acknowledgements

The ml-dsa code was lifted with minimal changes from [Quantum Blockchain's port](https://github.com/Quantum-Blockchains/dilithium)
of [pq-crystals](https://github.com/pq-crystals/dilithium) to Rust.
