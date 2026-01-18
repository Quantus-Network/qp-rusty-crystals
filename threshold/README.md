# Threshold ML-DSA-87 Signature Scheme

A Rust implementation of threshold ML-DSA-87 (Dilithium) signatures for the NEAR MPC network, allowing multiple parties to collectively sign messages without any single party having access to the complete signing key.

## ⚠️ Warning

**This implementation is for research and experimentation purposes only. It has not undergone a security audit and should not be used in production without thorough review.**

## Overview

In a (t, n) threshold scheme:
- **n** total parties hold key shares
- Any **t** or more parties can cooperate to produce a valid signature
- Fewer than **t** parties cannot sign or learn the secret key

Signatures are fully compatible with standard ML-DSA-87 verification.

## Key Concepts for Dilithium Users

If you're familiar with standard ML-DSA/Dilithium but new to threshold signatures, here are the key concepts:

### Secret Sharing

In standard Dilithium, one party holds the complete secret key `(s1, s2)`. In threshold Dilithium, the secret is split into **shares** so that no single party knows the full secret. We use **Replicated Secret Sharing (RSS)** where each party holds shares for multiple subsets of signers, enabling any `t` parties to reconstruct enough information to sign.

### Hyperball Sampling

Standard Dilithium uses rejection sampling on the response vector `z` to ensure signatures don't leak information about the secret key. In threshold signing, each party independently samples randomness, which could cause the combined result to fail rejection bounds more often. **Hyperball sampling** addresses this by having parties sample from a carefully sized hypersphere, ensuring that when contributions are combined, the result stays within acceptable bounds with high probability.

### Distributed Key Generation (DKG)

Instead of a trusted dealer generating and distributing key shares, **DKG** lets parties collaboratively generate shares without any party learning the full secret. Our 4-round DKG protocol uses commitments to prevent parties from biasing the key based on others' contributions.

### Resharing (Committee Handoff)

When the set of parties needs to change (nodes joining, leaving, or being replaced), **resharing** transfers the secret to a new committee while preserving the same public key. The old committee collectively "re-deals" shares to the new committee without ever reconstructing the secret in the clear.

### K Iterations

Due to rejection sampling in threshold signing, any single signing attempt may fail. The protocol runs **K parallel iterations** simultaneously, increasing the probability that at least one succeeds. The K values are tuned per configuration to achieve low retry rates.

### Leader-Based Retry

When all K iterations fail rejection sampling, a **leader** (lowest-ID participant) decides to retry with fresh randomness. This ensures all parties stay synchronized during retries.

## Features

- **ML-DSA-87**: NIST Level 5 post-quantum security (~256-bit)
- **Flexible Thresholds**: Supports (t, n) configurations where 2 ≤ t ≤ n ≤ 7
- **4-Round Protocol**: Commitment, reveal, response, and leader decision phases
- **Leader-Based Retry**: Automatic retry on rejection sampling failures
- **Distributed Key Generation (DKG)**: Generate keys without a trusted dealer
- **Key Resharing**: Transfer keys to a new committee
- **Key Derivation**: HD-wallet style derived keys for NEAR MPC
- **Message Buffering**: Handles out-of-order network messages
- **NEAR MPC Integration**: Ready for use with the NEAR MPC network

## Quick Start

### Key Generation (Dealer)

```rust
use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig};

let config = ThresholdConfig::new(2, 3)?; // 2-of-3 threshold
let seed = [0u8; 32]; // Use secure randomness!
let (public_key, shares) = generate_with_dealer(&seed, config)?;
// Distribute shares[i] to party i
```

### Key Generation (DKG)

```rust
use qp_rusty_crystals_threshold::keygen::dkg::run_local_dkg;

let outputs = run_local_dkg(2, 3, seed)?; // 2-of-3 threshold
// Each output contains: public_key, private_share
```

### Signing (4-Round Protocol)

```rust
use qp_rusty_crystals_threshold::signing_protocol::{DilithiumSignProtocol, run_local_signing};

// For local testing:
let signature = run_local_signing(signers, message, context)?;

// For distributed signing, use DilithiumSignProtocol with poke/message pattern
```

### Verification

```rust
use qp_rusty_crystals_threshold::verify_signature;

let valid = verify_signature(&public_key, message, context, &signature);
```

## Supported Configurations

| Parties (n) | Thresholds (t) |
|-------------|----------------|
| 2 | 2 |
| 3 | 2, 3 |
| 4 | 2, 3, 4 |
| 5 | 2, 3, 4, 5 |
| 6 | 2, 3, 4, 5, 6 |
| 7 | 2, 3, 4, 5, 6, 7 |

Note: n=7 configurations are experimental.

## Testing

```bash
# Run all tests
cargo test

# Run integration tests
cargo test --test integration_tests -- --nocapture

# Run benchmarks
cargo bench
```

## Benchmarks

```bash
# Compare threshold vs standard Dilithium
cargo bench -- comparison

# Benchmark all configurations
cargo bench -- signing_4round
```

## Documentation

- [NEAR Integration Plan](./NEAR_INTEGRATION_PLAN.md) - Integration with NEAR MPC
- [Key Derivation](./DILITHIUM_KEY_DERIVATION.md) - HD-wallet style derivation
- [Resharing](./RESHARING_PLAN.md) - Committee handoff protocol
- [Benchmarks](./BENCHMARK_PLAN.md) - Performance testing

## License

GPL-3.0 License - see the parent qp-rusty-crystals project.

## References

- [Threshold ML-DSA Research](https://mithril-th.org/)
- [FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)