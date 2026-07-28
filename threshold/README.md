# Threshold ML-DSA Signature Scheme

A Rust implementation of threshold ML-DSA (Dilithium) signatures for the NEAR MPC network, allowing multiple parties to collectively sign messages without any single party having access to the complete signing key.

## Parameter Sets

Build for **exactly one** FIPS 204 parameter set via Cargo feature (default `ml-dsa-87`):

| Feature | NIST category | Notes |
|---------|---------------|-------|
| `ml-dsa-87` | 5 (~256-bit) | Default; audited production calibration (hyperball / `k_iterations`) |
| `ml-dsa-65` | 3 (~192-bit) | Calibrated tables (2k-sample grid, 8k-sample K refine); reshares at κ=1 everywhere (measured overshoots 0.62–0.92) |
| `ml-dsa-44` | 2 (~128-bit) | Calibrated tables (2k-sample grid, 8k-sample K refine); reshare κ-enlarged for (2,4)/(3,5); reshare into (4,6) fails closed |

```bash
cargo test -p qp-rusty-crystals-threshold --features ml-dsa-87
cargo test -p qp-rusty-crystals-threshold --no-default-features --features 'ml-dsa-65,std'
cargo test -p qp-rusty-crystals-threshold --no-default-features --features 'ml-dsa-44,std'
```

If multiple features are enabled (e.g. workspace `--all-features`), priority is **87 > 65 > 44**.

Suite IDs (SSID / resharing): `1` = ML-DSA-87, `2` = ML-DSA-44, `3` = ML-DSA-65. Protocol SSID version is `THRESHOLD_SSID_VERSION = 3`.

## Security Status

| Component | Audit Status |
|-----------|--------------|
| Threshold signing protocol | ✅ Audited (ML-DSA-87 calibration) |
| Distributed Key Generation (DKG) | ✅ Audited |
| Resharing protocol | ⚠️ Not audited |
| ML-DSA-44 / ML-DSA-65 tables | ⚠️ Not audited (calibrated: 2,000-sample MC grid search for radii, 8,000-sample K refine with 2× margin; resharing overshoots measured, κ per variant — see `src/resharing/SECURITY_PROOF.md` "Parameter-Set Scope") |

The threshold signing and DKG protocols have undergone security review for the ML-DSA-87 parameter set. The resharing (committee handoff) protocol has not been audited. See `src/resharing/README.md` for security analysis and empirical verification of the resharing protocol's safety properties.

## Overview

In a (t, n) threshold scheme:
- **n** total parties hold key shares
- Any **t** or more parties can cooperate to produce a valid signature
- Fewer than **t** parties cannot sign or learn the secret key

Signatures are fully compatible with standard ML-DSA verification for the selected parameter set.

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

- **ML-DSA-44 / 65 / 87**: selectable FIPS 204 parameter sets
- **Flexible Thresholds**: Supports (t, n) configurations where 2 ≤ t ≤ n ≤ 6
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

## Testing

```bash
# Default (ML-DSA-87)
cargo test -p qp-rusty-crystals-threshold

# Other parameter sets
cargo test -p qp-rusty-crystals-threshold --no-default-features --features 'ml-dsa-44,std'
cargo test -p qp-rusty-crystals-threshold --no-default-features --features 'ml-dsa-65,std'

# Integration tests
cargo test -p qp-rusty-crystals-threshold --test integration_tests -- --nocapture

# Benchmarks
cargo bench -p qp-rusty-crystals-threshold
```

## Benchmarks

```bash
# Compare threshold vs standard Dilithium
cargo bench -p qp-rusty-crystals-threshold -- comparison

# Benchmark all configurations
cargo bench -p qp-rusty-crystals-threshold -- signing_4round
```

## License

GPL-3.0 License - see the parent qp-rusty-crystals project.

## References

- [Threshold ML-DSA Research](https://mithril-th.org/)
- [FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
