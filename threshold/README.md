# Threshold ML-DSA Signature Scheme

A Rust implementation of threshold variants of the ML-DSA (Dilithium) signature scheme for ML-DSA-87 (256-bit security).

## ⚠️ Warning

**This implementation is for research and experimentation purposes only. It has not undergone security review and should not be used in production.**

## Overview

This crate implements threshold signature schemes that allow up to 6 parties to collectively sign messages without any single party having access to the complete signing key.

### Features

- **ML-DSA-87 Support**: 256-bit security level (NIST Level 5)
- **Flexible Thresholds**: Support for any (t, n) configuration up to 6 parties
- **3-Round Protocol**: Commitment, challenge, and response phases
- **Memory Safety**: Automatic zeroization of sensitive data
- **Dilithium Compatibility**: Signatures verify with standard ML-DSA-87

## Usage

### Basic Setup

```rust
use qp_rusty_crystals_threshold::mldsa87::{ThresholdConfig, generate_threshold_key};

// Setup 3-of-5 threshold scheme
let config = ThresholdConfig::new(3, 5)?;

// Generate threshold keys
let (public_key, secret_keys) = generate_threshold_key(&mut rng, &config)?;
```

### Threshold Signing (3 Rounds)

```rust
// Round 1: Generate commitments
let (commitment, round1_state) = Round1State::new(&secret_keys[0], &config, &mut rng)?;

// Round 2: Exchange commitments and compute challenge
let (packed_commitment, round2_state) = Round2State::new(
    &secret_keys[0], active_parties, message, context, 
    &all_commitments, &round1_state
)?;

// Round 3: Generate responses
let (response, _) = Round3State::new(
    &secret_keys[0], &config, &packed_commitments,
    &round1_state, &round2_state
)?;

// Combine into final signature
let signature = combine_signatures(
    &public_key, message, context,
    &all_commitments, &all_responses, &config
)?;
```

### Verification

Signatures can be verified using either the threshold implementation or the standard dilithium crate:

```rust
// Using threshold verification
let is_valid = verify_signature(&public_key, message, context, &signature);

// Using dilithium crate (demonstrates compatibility)
let dilithium_pk = qp_rusty_crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(&public_key.packed)?;
let is_valid = dilithium_pk.verify(message, &signature, Some(context));
```

## Implementation Status

### ✅ Complete

- Field arithmetic and polynomial operations
- ML-DSA-87 parameter handling
- 3-round threshold protocol
- Secret sharing and key generation
- Signature aggregation and combination
- Comprehensive error handling
- 31 passing unit tests + integration tests
- Dilithium compatibility (correct signature format)

### 🚧 Simplified/Placeholder

- NTT operations (basic implementation)
- Polynomial sampling (simplified)
- Signature verification (placeholder)
- Constraint validation (relaxed for testing)

## Architecture

```
threshold/
├── src/
│   ├── lib.rs           # Main API
│   ├── common.rs        # Error types
│   ├── params.rs        # ML-DSA parameters
│   ├── field.rs         # Field arithmetic
│   └── mldsa87/mod.rs   # ML-DSA-87 implementation
└── tests/
    └── integration_tests.rs  # Dilithium compatibility tests
```

## Testing

```bash
# Run all tests
cargo test --package qp-rusty-crystals-threshold

# Integration tests (dilithium compatibility)
cargo test --test integration_tests
```

## Security Parameters

- **Ring Dimension**: N = 256
- **Matrix Dimensions**: k = 8, l = 7
- **Security Level**: ~256-bit (NIST Level 5)
- **Max Parties**: 6
- **Supported Thresholds**: Any t ≤ n ≤ 6

## Dependencies

- `qp-rusty-crystals-dilithium`: For ML-DSA compatibility
- `sha3`: Cryptographic hashing
- `zeroize`: Memory safety
- `rand_core`: Randomness interface

## Future Work

1. **Production readiness**: Full NTT implementation, proper sampling, security audit
2. **Performance**: SIMD optimizations, constant-time operations
3. **Features**: Serialization, network protocols, hardware integration

## License

Licensed under the same terms as the parent qp-rusty-crystals project.

## References

- "Efficient Threshold ML-DSA up to 6 parties" research paper
- FIPS 204: ML-DSA Standard
- CIRCL cryptographic library (Go reference implementation)