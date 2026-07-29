# qp-rusty-crystals-hdwallet

Hierarchical Deterministic (HD) wallet implementation for post-quantum ML-DSA keys, compatible with BIP-32, BIP-39, and BIP-44 standards.

## Features

- **BIP-39 Mnemonic** - Generate and restore from mnemonic phrases
- **BIP-32 HD Derivation** - Hierarchical deterministic key derivation
- **BIP-44 Compatible** - Standard derivation paths
- **Post-Quantum** - Uses ML-DSA (Dilithium) signatures
- **Hardened First 3 Levels** - Require hardened `purpose'`, `coin_type'`, `account'`; later levels optional

## Parameter sets

ML-DSA parameter sets are selected with additive cargo features (default: `ml-dsa-87`):

```toml
# ML-DSA-87 only (default)
qp-rusty-crystals-hdwallet = "3.1"

# Multiple parameter sets side by side
qp-rusty-crystals-hdwallet = { version = "3.0", features = ["ml-dsa-44", "ml-dsa-65"] }
```

Each enabled feature exposes a key-derivation module (`ml_dsa_44`, `ml_dsa_65`,
`ml_dsa_87`) with `derive_key_from_seed` / `derive_key_from_mnemonic` returning
that variant's `Keypair`. The top-level `derive_key_from_seed` /
`derive_key_from_mnemonic` functions are the original ML-DSA-87 API and require
the `ml-dsa-87` feature.

Deriving keys for different parameter sets from the same path is safe: FIPS 204
key generation absorbs the parameter set's `(k, ℓ)` into the seed expansion, so
the same derived entropy yields independent keys per variant. Mnemonic handling
and the wormhole module work regardless of which ML-DSA features are enabled.

## Standard expected derivation path
We use 44 for purpose, 189189 for coin type (Quantus), and account index for account
Example: "m/44'/189189'/{account_index}'/0/0"

## Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
qp-rusty-crystals-hdwallet = "3.1"
```

### Basic Example

```rust
use qp_rusty_crystals_hdwallet::{derive_key_from_mnemonic, generate_mnemonic};

// Generate secure entropy for a new mnemonic
let mut entropy = [0u8; 32];
getrandom::getrandom(&mut entropy).expect("Failed to generate entropy");
let mnemonic = generate_mnemonic((&mut entropy).into())?;
println!("Mnemonic: {}", mnemonic);

// Derive an ML-DSA-87 keypair at a BIP-44 path
let keypair = derive_key_from_mnemonic(&mnemonic, None, "m/44'/189189'/0'/0'/0'")?;

// Sign and verify with the derived keypair
let message = b"Hello, quantum-safe wallet!";
let signature = keypair.sign(message, None, None).expect("signing failed");
assert!(keypair.verify(message, &signature, None));
```

Other parameter sets use the per-variant modules (see "Parameter sets" above),
e.g. `ml_dsa_44::derive_key_from_mnemonic` with the `ml-dsa-44` feature.

### Seed-based API

If you already hold a BIP-39 seed (or want to stretch the mnemonic once and
derive many keys), use the seed entrypoints. Seeds are passed by move as
self-zeroizing types:

```rust
use qp_rusty_crystals_hdwallet::{derive_key_from_seed, mnemonic_to_seed};

let mut seed = mnemonic_to_seed(mnemonic, None)?; // consumes the mnemonic
let keypair = derive_key_from_seed((&mut seed).into(), "m/44'/189189'/0'/0'/0'")?;
```

### Wormhole pairs

Wormhole address derivation is Poseidon-based and independent of the ML-DSA
parameter set. It requires the wormhole coin type (`189189189'`) in the path:

```rust
use qp_rusty_crystals_hdwallet::derive_wormhole_from_mnemonic;

let pair = derive_wormhole_from_mnemonic(&mnemonic, None, "m/44'/189189189'/0'/0'/0'")?;
println!("Address: {}", hex::encode(pair.address));
```

### Derivation Paths

Standard BIP-44 derivation paths are supported:
```
m / purpose' / coin_type' / account' / change / address_index
```

Example paths:
- `m/44'/189189'/0'/0'/0'` - First address of first account
- `m/44'/189189'/1'/0'/0'` - First address of second account
- `m/44'/189189'/0'/1'/0'` - First change address

**Note**: For security, the first three indices must be hardened (`purpose'`, `coin_type'`, `account'`). Subsequent indices (`change`, `address_index`) may be unhardened.

## Why Hardened Keys Only?

Non-hardened key derivation relies on elliptic curve properties not present in lattice-based cryptography. For security, this implementation requires hardened derivation for the first three indices and permits flexibility for deeper levels.

## Testing

```bash
cargo test                                                  # std + ml-dsa-87 (default)
cargo test --no-default-features --features std,ml-dsa-44  # single-variant build
cargo test --features ml-dsa-44,ml-dsa-65                   # all three variants
```

The historical test-vector suite is ML-DSA-87 and runs only when that feature
is enabled; the multi-variant suite runs for whichever features are active.

## License

GPL-3.0 - See [LICENSE](../LICENSE) for details.
