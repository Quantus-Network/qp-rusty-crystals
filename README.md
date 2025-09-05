# AL Rusty Crystals

A Rust implementation of the ML-DSA (CRYSTALS-Dilithium) post-quantum digital signature scheme with hierarchical deterministic (HD) wallet support.

This workspace provides post-quantum cryptographic primitives and HD wallet functionality compatible with BIP-32, BIP-39, and BIP-44 standards.

## Overview

This workspace contains two independent crates:

- **`al-rusty-crystals-dilithium`** - ML-DSA digital signature implementation
- **`al-rusty-crystals-hdwallet`** - HD wallet for post-quantum keys

## Usage

### ML-DSA Digital Signatures

```toml
[dependencies]
al-rusty-crystals-dilithium = "0.0.2"
```

```rust
use al_rusty_crystals_dilithium::{ml_dsa_44, Keypair};

// Generate keypair
let keypair = ml_dsa_44::Keypair::generate(None);

// Sign message
let message = b"Hello, post-quantum world!";
let signature = keypair.sign(message);

// Verify signature
let is_valid = keypair.public_key.verify(message, &signature);
```

### HD Wallet

```toml
[dependencies]
al-rusty-crystals-hdwallet = "0.0.2"
```

```rust
use al_rusty_crystals_hdwallet::{generate_mnemonic, HDLattice};

// Generate mnemonic
let mnemonic = generate_mnemonic(24)?;

// Create HD wallet
let hd_wallet = HDLattice::from_mnemonic(&mnemonic, None)?;

// Derive keys using BIP-44 path
let keys = hd_wallet.generate_derived_keys("44'/0'/0'/0'/0'")?;
```

## Crates

### al-rusty-crystals-dilithium
ML-DSA digital signature implementation:
- **ML-DSA-44, ML-DSA-65, ML-DSA-87** - All security levels
- **NIST Compliant** - Verified against official test vectors  
- **Pure Rust** - Memory-safe, no unsafe code
- **High Performance** - Optimized implementation

### al-rusty-crystals-hdwallet
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
