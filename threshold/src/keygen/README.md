# Threshold ML-DSA-87 Key Generation

This module provides two methods for generating threshold Dilithium (ML-DSA-87) key shares:

1. **Trusted Dealer** (`dealer.rs`) - A single trusted party generates and distributes shares
2. **Distributed Key Generation** (`dkg/`) - Parties collaboratively generate shares without a trusted dealer

## Trusted Dealer

The trusted dealer approach is simpler but requires trusting one party with the complete secret key during generation. See `dealer.rs` for implementation.

```rust
use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig};

let config = ThresholdConfig::new(2, 3)?;  // 2-of-3
let seed = [42u8; 32];
let (public_key, shares) = generate_with_dealer(&seed, config)?;
```

## Distributed Key Generation (DKG)

The DKG protocol allows parties to collaboratively generate key shares without any single party ever knowing the complete secret. This is the recommended approach for production use.

### Protocol Overview (Mithril 4-Round DKG)

The protocol follows the Mithril paper (Appendix D) with 4 rounds plus aggregation:

```
Round 1: Shared secret establishment + commitment
    - Leaders (min(S) for each subset S) generate K_S and distribute via secure P2P
    - All parties commit to random r_i: broadcast c_i = H(i, r_i)

Round 2: Reveal randomness
    - All parties reveal r_i
    - Verify commitments: c_j = H(j, r_j)

Round 3: Derive secrets + commit to partial PKs
    - Compute global randomness R = r_1 || ... || r_N
    - Leaders derive s_S = H_keygen(S, K_S, R) and compute t_S = A·s_S
    - Leaders broadcast commitment to partial PK

Round 4: Reveal partial PKs + transcript signing
    - Leaders reveal t_S
    - Non-leaders verify: recompute s_S from K_S and R, verify commitment
    - All parties sign transcript with long-term key

Aggregate: Verify signatures + combine PKs
    - Verify all transcript signatures
    - Compute final public key: t = Σ t_S
```

### Leader Selection

Each subset S has a deterministic leader: the party with the smallest index in S.
The leader is responsible for:
- Sampling the shared secret K_S for the group
- Computing the partial public key t_S
- Distributing K_S to other members via secure P2P channels

### Key Insight: η-Bounded Secrets

The critical innovation is how secrets are derived. In a naive approach where k parties each contribute η-bounded values that get summed, the result would have coefficients in [-k·η, k·η], violating the Dilithium security requirements.

The Mithril approach solves this:

1. The leader generates a **shared secret** K_S (random bytes)
2. All parties in subset S receive K_S via secure P2P
3. All parties derive the **same** η-bounded secret: `s_S = H_keygen(S, K_S, R)`

This ensures:
- All parties in a subset compute identical shares
- The final secret coefficients are in [-η, η], not [-k·η, k·η]
- The distribution matches what a trusted dealer would produce

### Subset Structure

For a (t, n) threshold scheme:
- Subset size k = n - t + 1
- Each subset S corresponds to a set of k parties
- Total number of subsets = C(n, k) = n! / (k! · (n-k)!)

Example for (2, 3):
- k = 3 - 2 + 1 = 2
- Subsets: {0,1}, {0,2}, {1,2}
- Each party belongs to 2 subsets

### Security Properties

1. **Threshold Security**: Any t parties can sign, but t-1 parties learn nothing about the secret
2. **No Trusted Dealer**: No single party ever knows the complete secret key
3. **Commitment Scheme**: Parties commit before revealing, preventing adaptive attacks
4. **Transcript Signing**: Provides non-repudiation and detects tampering
5. **PK Commitment Verification**: Non-leaders verify partial PKs before signing

### Supported Configurations

- **MAX_PARTIES = 6**: n=7 is not supported due to impractical K values for middle thresholds
- All (t, n) configurations where 2 ≤ t ≤ n ≤ 6 are supported

### Files

- `dkg/mod.rs` - Module exports and documentation
- `dkg/types.rs` - Message types, configuration, TranscriptSigner trait
- `dkg/state.rs` - Protocol state structures
- `dkg/protocol.rs` - Main protocol implementation (`MithrilDkg`)

### Usage

```rust
use qp_rusty_crystals_threshold::keygen::dkg::{
    MithrilDkg, MithrilDkgConfig, MithrilAction, run_local_mithril_dkg,
};

// For testing/local use with a simple signer:
let signers: Vec<MySigner> = (0..3).map(|id| MySigner::new(id)).collect();
let public_keys: Vec<_> = signers.iter().map(|s| s.public_key()).collect();
let seed = [42u8; 32]; // Caller provides randomness as 32-byte seed

let outputs = run_local_mithril_dkg(2, 3, signers, public_keys, seed)?;

// For distributed use, create MithrilDkg instances and drive with poke()/message():
let config = MithrilDkgConfig::new(
    threshold_config,
    my_party_id,
    all_participants,
    my_signer,
    participant_public_keys,
)?;

let mut dkg = MithrilDkg::new(config, seed);

loop {
    match dkg.poke()? {
        MithrilAction::Wait => { /* wait for messages */ }
        MithrilAction::SendMany(data) => { /* broadcast to all parties */ }
        MithrilAction::SendPrivate(to, data) => { /* send via secure P2P */ }
        MithrilAction::Return(output) => {
            // DKG complete!
            let public_key = output.public_key;
            let private_share = output.private_share;
            break;
        }
    }
}
```

### TranscriptSigner Trait

The DKG requires a `TranscriptSigner` implementation for signing transcripts:

```rust
pub trait TranscriptSigner {
    type Signature: Clone + AsRef<[u8]>;
    type PublicKey: Clone + PartialEq;

    fn sign(&self, hash: &[u8; 32]) -> Self::Signature;
    fn verify(pk: &Self::PublicKey, hash: &[u8; 32], sig: &Self::Signature) -> bool;
    fn verify_bytes(pk: &Self::PublicKey, hash: &[u8; 32], sig: &[u8]) -> bool;
    fn public_key(&self) -> Self::PublicKey;
}
```

For NEAR MPC, this would typically be Ed25519 or ML-DSA-87 for long-term keys.

### NEAR MPC Compatibility

The `MithrilDkg` struct follows the poke/message pattern used by NEAR's
`threshold-signatures` crate, making it compatible with NEAR MPC's
`run_protocol` infrastructure.

### References

- [Mithril Paper](https://iohk.io/en/research/library/papers/mithril-stake-based-threshold-multisignatures/) - IOG's threshold signature scheme
- [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final) - The underlying signature scheme
