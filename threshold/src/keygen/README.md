# Threshold ML-DSA-87 Key Generation

This module provides two methods for generating threshold Dilithium (ML-DSA-87) key shares:

1. **Trusted Dealer** (`dealer.rs`) - A single trusted party generates and distributes shares
2. **Distributed Key Generation** (`dkg/`) - Parties collaboratively generate shares without a trusted dealer

## Trusted Dealer

The trusted dealer approach is simpler but requires trusting one party with the complete secret key during generation. See `dealer.rs` for implementation.

## Distributed Key Generation (DKG)

The DKG protocol allows parties to collaboratively generate key shares without any single party ever knowing the complete secret. This is the recommended approach for production use.

### Protocol Overview

The DKG uses a **seed-based** approach to ensure shares have properly bounded coefficients (within [-η, η] for ML-DSA-87 where η=2).

#### Round Structure

```
Round 1: Session ID (broadcast)
    Each party contributes random bytes to form a unique session ID.
    This prevents replay attacks across DKG runs.

Round 2: Commit to Seeds (broadcast)
    Each party:
    1. Generates random seeds for each subset they belong to
    2. Computes seed hashes H(seed) for each subset
    3. Broadcasts commitment_hash and public_contributions (seed hashes)
    
    Note: The combined session_id from Round 1 is used as rho (the seed for 
    expanding the public matrix A). This eliminates the need for separate 
    rho contributions.

Round 3: P2P Seed Exchange
    Each party sends their actual seeds to other parties in the same subsets.
    Seeds are only shared within subsets to preserve the threshold property.

Round 4: Partial Public Keys (broadcast)
    Each party:
    1. Combines received seeds: combined_seed = H(seed_0 || seed_1 || ... || seed_{k-1})
    2. Derives η-bounded secret: s_I = DeriveUniformLeqEta(combined_seed)
    3. Computes partial public key: t_I = A·s1_I + s2_I
    4. Broadcasts partial public keys for all their subsets

Round 5: Confirmation (broadcast)
    Each party:
    1. Sums partial public keys to get final t = Σ t_I
    2. Computes public key hash for consensus verification
    3. Broadcasts success/failure and public key hash
```

### Key Insight: η-Bounded Secrets

The critical innovation is how secrets are derived. In a naive approach where k parties each contribute η-bounded values that get summed, the result would have coefficients in [-k·η, k·η], violating the Dilithium security requirements.

The seed-based approach solves this:

1. Each party contributes a **seed** (random bytes), not a polynomial
2. All parties in a subset combine seeds deterministically: `combined_seed = H(seed_0 || ... || seed_{k-1})`
3. The **same** η-bounded secret is derived by all parties: `s_I = DeriveUniformLeqEta(combined_seed)`

This ensures:
- All parties in a subset compute identical shares
- The final secret coefficients are in [-η, η], not [-k·η, k·η]
- The distribution matches what a trusted dealer would produce (Mithril compatibility)

### Subset Structure

For a (t, n) threshold scheme:
- Subset size k = n - t + 1
- Each subset I corresponds to a set of k parties
- Total number of subsets = C(n, k) = n! / (k! · (n-k)!)

Example for (2, 3):
- k = 3 - 2 + 1 = 2
- Subsets: {0,1}, {0,2}, {1,2}
- Each party belongs to 2 subsets

### Security Properties

1. **Threshold Security**: Any t parties can sign, but t-1 parties learn nothing about the secret
2. **No Trusted Dealer**: No single party ever knows the complete secret key
3. **HQ1 Fix**: Secrets are never broadcast; only seed hashes and partial public keys are public
4. **Commitment Scheme**: Parties commit before revealing, preventing adaptive attacks

### Files

- `dkg/mod.rs` - Module exports and `run_local_dkg` helper
- `dkg/types.rs` - Message types, seed derivation functions
- `dkg/state.rs` - Protocol state machine and round data
- `dkg/protocol.rs` - Main protocol implementation (`DilithiumDkg`)

### Usage

```rust
use qp_rusty_crystals_threshold::keygen::dkg::{run_local_dkg, DkgOutput};

// For testing/local use:
let outputs: Vec<DkgOutput> = run_local_dkg(2, 3, seed)?;

// For distributed use, create DilithiumDkg instances and drive with poke()/message():
let mut dkg = DilithiumDkg::new(config, seed);
loop {
    match dkg.poke()? {
        Action::Wait => { /* wait for messages */ },
        Action::SendMany(data) => { /* broadcast to all parties */ },
        Action::SendPrivate(to, data) => { /* send to specific party */ },
        Action::Return(output) => { break; /* DKG complete */ },
    }
}
```

### References

- Mithril (IOG): Reference threshold Dilithium implementation
- ML-DSA (FIPS 204): The underlying signature scheme
- RSS (Replicated Secret Sharing): The sharing scheme used for subsets
