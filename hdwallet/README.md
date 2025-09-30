# qp-rusty-crystals-hdwallet

Hierarchical Deterministic (HD) wallet implementation for post-quantum ML-DSA keys, compatible with BIP-32, BIP-39, and BIP-44 standards.

## Features

- **BIP-39 Mnemonic** - Generate and restore from mnemonic phrases
- **BIP-32 HD Derivation** - Hierarchical deterministic key derivation
- **BIP-44 Compatible** - Standard derivation paths
- **Post-Quantum** - Uses ML-DSA (Dilithium) signatures
- **Hardened First 3 Levels** - Require hardened `purpose'`, `coin_type'`, `account'`; later levels optional

## Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
qp-rusty-crystals-hdwallet = "0.0.2"
qp-rusty-crystals-dilithium = "0.0.2"
```

### Basic Example

```rust
use qp_rusty_crystals_hdwallet::{generate_mnemonic, HDLattice};

// Generate a new mnemonic
let mnemonic = generate_mnemonic(24)?;
println!("Mnemonic: {}", mnemonic);

// Create HD wallet from mnemonic
let hd_wallet = HDLattice::from_mnemonic(&mnemonic, None)?;

// Generate master keys
let master_keys = hd_wallet.generate_keys();

// Derive child keys using BIP-44 path
let child_keys = hd_wallet.generate_derived_keys("44'/0'/0'/0'/0'")?;

// Sign with derived keys
let message = b"Hello, quantum-safe wallet!";
let signature = child_keys.sign(message);
```

### Derivation Paths

Standard BIP-44 derivation paths are supported:
```
m / purpose' / coin_type' / account' / change / address_index
```

Example paths:
- `m/44'/0'/0'/0'/0'` - First address of first account
- `m/44'/0'/1'/0'/0'` - First address of second account
- `m/44'/0'/0'/1'/0'` - First change address

**Note**: For security, the first three indices must be hardened (`purpose'`, `coin_type'`, `account'`). Subsequent indices (`change`, `address_index`) may be unhardened.

## Why Hardened Keys Only?

Non-hardened key derivation relies on elliptic curve properties not present in lattice-based cryptography. For security, this implementation requires hardened derivation for the first three indices and permits flexibility for deeper levels.

## Testing

```bash
cargo test
```

## License

GPL-3.0 - See [LICENSE](../LICENSE) for details.
