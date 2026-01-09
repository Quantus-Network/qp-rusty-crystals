# Threshold ML-DSA-87 Signature Scheme

A Rust implementation of threshold ML-DSA-87 (Dilithium) signatures, allowing multiple parties to collectively sign messages without any single party having access to the complete signing key.

## ⚠️ Warning

**This implementation is for research and experimentation purposes only. It has not undergone security review and should not be used in production.**

## Overview

In a (t, n) threshold scheme:
- There are **n** total parties
- Any **t** or more parties can cooperate to produce a valid signature
- Fewer than **t** parties cannot produce a signature or learn the secret key

This implementation supports configurations up to (6, 6) and produces signatures compatible with standard ML-DSA-87 verification.

### Features

- **ML-DSA-87 Support**: 256-bit security level (NIST Level 5)
- **Flexible Thresholds**: Any (t, n) configuration where 2 ≤ t ≤ n ≤ 6
- **3-Round Protocol**: Commitment, reveal, and response phases
- **Network Ready**: Clear separation of broadcast messages for distributed signing
- **Memory Safety**: Automatic zeroization of sensitive data
- **Serde Support**: Optional serialization for network transport

## Usage

### Key Generation

```rust
use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig};

// Create a 2-of-3 threshold configuration
let config = ThresholdConfig::new(2, 3)?;
let seed = [0u8; 32]; // Use a cryptographically secure random seed!

// Generate keys with a trusted dealer
let (public_key, shares) = generate_with_dealer(&seed, config)?;

// Distribute shares securely to each party:
// - shares[0] goes to party 0
// - shares[1] goes to party 1
// - shares[2] goes to party 2
```

### Threshold Signing

Each party creates a `ThresholdSigner` and participates in three rounds:

```rust
use qp_rusty_crystals_threshold::{ThresholdSigner, ThresholdConfig};

// Each party creates their signer (on their own machine)
let mut signer = ThresholdSigner::new(my_share, public_key, config)?;

// Round 1: Generate commitment
let r1_broadcast = signer.round1_commit(&mut rng)?;
// --> Send r1_broadcast to all other parties
// --> Receive other parties' Round1Broadcasts

// Round 2: Reveal commitment  
let r2_broadcast = signer.round2_reveal(message, context, &other_r1_broadcasts)?;
// --> Send r2_broadcast to all other parties
// --> Receive other parties' Round2Broadcasts

// Round 3: Compute response
let r3_broadcast = signer.round3_respond(&other_r2_broadcasts)?;
// --> Send r3_broadcast to all other parties
// --> Receive other parties' Round3Broadcasts

// Combine into final signature (any party can do this)
let signature = signer.combine_with_message(
    message, context, &all_r2_broadcasts, &all_r3_broadcasts
)?;
```

### Verification

Signatures are compatible with standard ML-DSA-87:

```rust
use qp_rusty_crystals_threshold::verify_signature;

let is_valid = verify_signature(&public_key, message, context, &signature);
```

## API Reference

### Types

| Type | Description |
|------|-------------|
| `ThresholdConfig` | Configuration for (t, n) threshold scheme |
| `PublicKey` | Threshold public key (can be freely shared) |
| `PrivateKeyShare` | Secret key share for one party (keep confidential!) |
| `ThresholdSigner` | Main signing interface for each party |
| `Round1Broadcast` | Message to broadcast in Round 1 |
| `Round2Broadcast` | Message to broadcast in Round 2 |
| `Round3Broadcast` | Message to broadcast in Round 3 |
| `Signature` | Final signature (standard ML-DSA-87 format) |

### Functions

| Function | Description |
|----------|-------------|
| `generate_with_dealer` | Generate keys using a trusted dealer |
| `verify_signature` | Verify a threshold signature |

## Architecture

```
threshold/src/
├── lib.rs              # Public API exports
├── config.rs           # ThresholdConfig
├── keys.rs             # PublicKey, PrivateKeyShare
├── broadcast.rs        # Round1/2/3Broadcast, Signature
├── signer.rs           # ThresholdSigner
├── error.rs            # Error types
├── keygen/
│   └── dealer.rs       # Trusted dealer key generation
└── protocol/
    ├── primitives.rs   # Internal crypto operations
    └── signing.rs      # Protocol implementation
```

## Testing

```bash
# Run all tests
cargo test --package qp-rusty-crystals-threshold

# Run new API tests
cargo test --test test_new_api

# Run integration tests (old API)
cargo test --test integration_tests
```

## Security Parameters

| Parameter | Value |
|-----------|-------|
| Ring Dimension (N) | 256 |
| Matrix Dimensions | k=8, l=7 |
| Security Level | ~256-bit (NIST Level 5) |
| Max Parties | 6 |
| Supported Thresholds | 2 ≤ t ≤ n ≤ 6 |

## Features

- `std` (default): Standard library support
- `serde`: Serialization/deserialization for broadcast types

## Dependencies

- `qp-rusty-crystals-dilithium`: ML-DSA implementation
- `zeroize`: Secure memory clearing
- `rand_core`: Randomness traits
- `serde` (optional): Serialization

## Future Work

- **Distributed Key Generation (DKG)**: Generate shares without a trusted dealer
- **Performance**: SIMD optimizations, constant-time operations
- **Security Audit**: Professional cryptographic review

## License

Licensed under the same terms as the parent qp-rusty-crystals project.

## References

- "Efficient Threshold ML-DSA up to 6 parties" research paper
- FIPS 204: ML-DSA Standard
- CIRCL cryptographic library (Go reference implementation)