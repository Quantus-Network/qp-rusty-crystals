# Resharing (Committee Handoff) Protocol

This module implements resharing for threshold ML-DSA-87, allowing the participant set to change while preserving the same public key.

## Why Resharing?

In production deployments, nodes may need to:
- **Join**: New nodes added to increase availability
- **Leave**: Nodes retired or decommissioned  
- **Replace**: Compromised or failed nodes swapped out
- **Rebalance**: Change threshold (e.g., 2-of-3 → 3-of-5)

Without resharing, any change would require generating a new key and migrating all assets/contracts to the new public key.

## Protocol Overview

### Participants

- **Old Committee**: Parties holding current shares (threshold `t_old` of `n_old`)
- **New Committee**: Parties that will hold new shares (threshold `t_new` of `n_new`)
- **Overlap**: Parties may be in both committees

### Protocol Rounds (5-round forward-secrecy protocol)

This module uses **distributed per-subset re-sharing** with **forward secrecy** — at no point does any party ever assemble the full secret `s`, and at no point is any individual share exposed in clear on the wire.

```
Round 1: Entropy Commitment (Forward Secrecy)
├── Each old committee member generates fresh entropy and broadcasts H(entropy).
└── Commit-reveal prevents any party from biasing the session seed.

Round 2: Entropy Reveal (Forward Secrecy)
├── Old committee members reveal their entropy.
├── All parties verify reveals against Round 1 commitments.
└── Session seed = SHAKE256("resharing-session-seed-v1" || party_1 || entropy_1 || ...)
    computed deterministically from all contributions in sorted party ID order.

Round 3: Per-Subset Commitments
├── For each old subset I, the designated dealer D_I (lowest-ID old participant in I)
│   deterministically derives sub-shares r_{I→J} for every new subset J such that
│   Σ_J r_{I→J} = s_I^old. The derivation incorporates the session seed for forward secrecy.
└── D_I broadcasts H(r_{I→J}) for each (I, J). Members of I can independently
    recompute the same r_{I→J} from s_I^old and verify D_I's commitments.

Round 4: Private Sub-Share Reveal (⚠️ REQUIRES SECURE CHANNEL)
├── D_I privately delivers r_{I→J} to each member of new subset J.
└── No public traffic carries any share material.

Round 5: Verification + Accusations + Public-Key Invariant
├── Each new party verifies received r_{I→J} against the Round 3 commitment, then
│   sums s_J^new = Σ_I r_{I→J} for each new subset J they're in, and broadcasts
│   a commitment to s_J^new so that the membership of J can cross-verify.
├── Each new party also broadcasts t_J^new = A·s1_J^new + s2_J^new (mod Q) for
│   every J they hold. After Round 5, anyone can sum these and confirm
│   Σ_J t_J^new = T (the original public key). This catches a malicious dealer
│   that owns a *size-1* old subset (e.g. t = n configurations), where there is
│   no other I-member to cross-verify the dealer's commitments.
└── Old subset members file DealerAccusation if any dealer's broadcast commitment
    doesn't match their independent recomputation.
```

Because `Σ_J s_J^new = Σ_J Σ_I r_{I→J} = Σ_I s_I^old = s`, the secret — and hence the public key `t = A·s1 + s2` — is preserved.

## Forward Secrecy

The 5-round protocol provides **forward secrecy**: even if old shares are later compromised, an attacker cannot reconstruct the randomness used to derive new shares.

### How It Works

1. **Entropy Generation**: Each old committee member generates fresh random entropy from their provided seed.

2. **Commit-Reveal**: Round 1-2 use a commit-reveal scheme to ensure no party can bias the session seed based on others' contributions.

3. **Session Seed Derivation**: The session seed is computed as:
   ```
   session_seed = SHAKE256("resharing-session-seed-v1" || party_id_1 || entropy_1 || party_id_2 || entropy_2 || ...)
   ```
   where parties are processed in sorted order by ID.

4. **PRF Mixing**: The session seed is mixed into the PRF that derives sub-shares:
   ```
   prf_seed = SHAKE256("resharing-subset-prf-v3" || session_seed || i_mask || s_I^old)
   ```

### Security Guarantee

Even if an attacker:
- Compromises all old shares after resharing
- Observes all protocol messages
- Knows n-1 parties' entropy contributions

They still cannot reconstruct the session seed (and thus the new shares) because the honest party's entropy contribution is unknown.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Secrecy of `s`** | No party — not even any dealer — ever holds `s` in clear. Each `D_I` only handles `s_I^old`, which they already had. |
| **Forward Secrecy** | Session seed incorporates fresh entropy from all old committee members via commit-reveal. Even if old shares are later compromised, the randomness used to derive new shares cannot be reconstructed. |
| **Confidentiality of contributions** | Rounds 1-3, 5 broadcast only hash commitments; Round 4 sub-shares travel privately. Even an unbounded eavesdropper learns nothing about any `s_I^old` from the public transcript. |
| **Cheating-dealer detection** | Other members of `I` independently recompute `r_{I→J}` from `s_I^old` and accuse `D_I` if the broadcast commitment differs; new-subset members cross-verify computed `s_J^new`; and a final partial-public-key sum check reconstructs `T` from `Σ_J t_J^new`, catching any dealer that lied about a residual even when their old subset has size 1. |
| **PK Preservation** | Public key `t = A·s1 + s2` unchanged, verified at the end of Round 5 via a deterministic byte-equality check against the original PK. |

## Why Custom Protocol?

Standard resharing protocols (CHURP, MPSS) assume Shamir polynomial secret sharing where shares are points on a polynomial. Our implementation uses **Replicated Secret Sharing (RSS)** with subset-indexed additive shares:

```
secret = Σ share[S]  for all subsets S of size n - t + 1
```

The custom design lets each old RSS subset re-share *its own* η-bounded share to the new committee independently, without anyone ever combining the sub-shares back into `s`.

## Usage

```rust
use qp_rusty_crystals_threshold::resharing::{
    ResharingConfig, ResharingProtocol, Action,
};
use rand::RngCore;

// Generate fresh entropy for this party (CRITICAL for forward secrecy)
let mut seed = [0u8; 32];
rand::rngs::OsRng.fill_bytes(&mut seed);

// Configure resharing
let config = ResharingConfig::new(
    old_threshold,      // e.g., 2
    old_participants,   // e.g., vec![0, 1, 2]
    new_threshold,      // e.g., 3
    new_participants,   // e.g., vec![1, 2, 3, 4]
    my_party_id,
    my_existing_share,  // Some(share) if in old committee, None if joining
    public_key,
)?;

// Create protocol with fresh entropy seed
let mut protocol = ResharingProtocol::new(config, seed);

// Run protocol loop
loop {
    match protocol.poke()? {
        Action::Wait => { /* wait for network messages */ }
        Action::SendMany(data) => { /* broadcast to all parties */ }
        // ⚠️ CRITICAL: Use authenticated-encrypted channel!
        Action::SendPrivate(to, data) => { /* send to specific party over secure channel */ }
        Action::Return(output) => {
            // Resharing complete
            let new_share = output.private_share;
            break;
        }
    }
    
    // Process incoming messages
    for (from, data) in incoming_messages {
        protocol.message(from, data)?;
    }
}
```

## ⚠️ Transport Security Requirements

**CRITICAL**: Round 4 messages (`Action::SendPrivate`) contain secret share material in plaintext
and **MUST** be transmitted over an authenticated-encrypted channel. The protocol does not
provide its own encryption layer.

| Message Type | Transport Requirement |
|--------------|----------------------|
| `Action::SendMany` (Rounds 1, 2, 3, 5) | Authenticated broadcast (integrity only) |
| `Action::SendPrivate` (Round 4) | **Authenticated encryption required** (confidentiality + integrity) |

If `SendPrivate` messages are sent over an unencrypted channel, an eavesdropper can recover
the sub-shares `r_{I→J}` and potentially reconstruct secret key material.

**For NEAR MPC**: The existing authenticated-encryption transport satisfies this requirement.

**For other integrations**: Ensure your transport layer provides:
- Confidentiality (e.g., TLS, Noise Protocol, or application-layer encryption)
- Authentication (recipient can verify the sender's identity)
- Integrity (messages cannot be modified in transit)

## ⚠️ Entropy Requirements

**CRITICAL**: Each party must provide cryptographically random entropy via the `seed` parameter
to `ResharingProtocol::new()`. Using predictable, weak, or reused entropy compromises forward secrecy.

| Requirement | Why |
|-------------|-----|
| **Cryptographically random** | Use `OsRng` or equivalent CSPRNG, not PRNG or timestamps |
| **Independent per party** | Each party must generate their own entropy; don't share seeds |
| **Fresh per session** | Generate new entropy for each resharing; don't reuse across sessions |

If all parties use the same seed, or if seeds are predictable, an attacker who later compromises
old shares can reconstruct the session seed and derive the new shares.

## Roles

Each party has a role determined by committee membership:

| Role | Old Committee | New Committee | Actions |
|------|--------------|---------------|---------|
| `OldOnly` | ✓ | ✗ | Generate entropy; deal sub-shares for old subsets they own; file dealer accusations |
| `NewOnly` | ✗ | ✓ | Receive sub-shares; verify against commitments; aggregate `s_J^new` |
| `Both`    | ✓ | ✓ | Generate entropy; deal + receive + verify |

## Message Types

- `Round1EntropyCommitment`: Hash commitment to entropy `H(entropy)` for forward secrecy
- `Round2EntropyReveal`: Revealed entropy (32 bytes) — verified against Round 1 commitment
- `Round3Broadcast`: Per-subset commitment hashes `H(r_{I→J})` (no plaintext shares)
- `Round4Message`: Private sub-share reveal (**requires secure channel**) — one message per (dealer, recipient) carrying every `r_{I→J}` the dealer owes that recipient. Dealers handle self-deals locally and never emit `SendPrivate(self, _)`.
- `Round5Broadcast`: Commitments to computed `s_J^new`, partial public-key contributions `t_J^new`, and any `DealerAccusation`s

## State Machine

```
Round1Generate -> Round1Waiting -> Round2Generate -> Round2Waiting
    -> Round3Generate -> Round3Waiting -> Round4Generate -> Round4Waiting
    -> Round5Generate -> Round5Waiting -> Combining -> Done
```

NewOnly parties skip Rounds 1-2 (entropy commit-reveal) and go directly to `Round2Waiting`.

## Limitations

- Maximum 16 parties (due to u16 subset masks)
- Requires every designated dealer to be online; if a dealer is offline or cheats, the protocol aborts (no recovery / re-deal in this implementation)
- **Secure channels required for Round 4 private messages** (see Transport Security section above)
- **Cryptographically random entropy required from each old committee member** (see Entropy Requirements section above)

## Coefficient Growth and η-Bounds

### Background

In ML-DSA (Dilithium), the secret key polynomials `s1` and `s2` have coefficients bounded by the parameter η (eta). For ML-DSA-87, η = 2, meaning original secret coefficients are in the range `[-2, 2]`.

A natural concern with resharing is whether the share coefficients remain η-bounded after multiple resharings. If coefficients grew unboundedly, it could potentially affect:
1. Security proofs that assume small coefficients
2. Rejection sampling rates during signing

### Why η-Bounded Shares Are Not Required

The TALUS paper ("TALUS: Threshold ML-DSA with One-Round Online Signing via Boundary Clearance and Carry Elimination", arXiv:2603.22109) provides key insight here. In their Proactive Key Refresh protocol (Appendix C), they explicitly sample refresh updates from the **full ring `R_q`**, not from η-bounded values:

> "Sample degree-(T-1) polynomial f_i(X) with a_{i,0} = 0 and a_{i,k} ← R_q^{nℓ} for k ≥ 1"

The shares can have arbitrarily large coefficients (mod q), but **the reconstructed secret remains the original η-bounded secret**. This is because:

1. The updates sum to zero at the secret point: `Σ f_h(0) = 0`
2. Therefore `s' = s` (the original η-bounded secret is preserved)
3. During signing, what matters is `z = y + c·s` where `s = Σ s_i` is η-bounded

### Empirical Validation

We validated this with extensive testing of consecutive resharings:

| Resharings | Avg Retries | Max Retries | Success Rate |
|------------|-------------|-------------|--------------|
| 0 (DKG)    | 0.46        | 5           | 100%         |
| 10x        | 0.48        | 5           | 100%         |
| 100x       | 0.54        | 4           | 100%         |
| 250x       | 3.24        | 13          | 100%         |
| 500x       | 7.60        | 39          | 100%         |
| 1000x      | 34.00       | 67          | 30%          |

Key findings:
- **Up to 100 resharings**: No measurable impact on signing retry rates
- **250-500 resharings**: Gradual increase in retries, but 100% success rate
- **1000 resharings**: Significant degradation begins

For any practical deployment, even 100 consecutive resharings far exceeds operational needs. A typical system might reshare annually for key rotation, meaning 100 resharings would span a century of operation.

### Why This Works

The hyperball rejection sampling in our threshold signing protocol operates on the **combined response** `z = Σ z_i = y + c·s`, where `s` is the reconstructed secret. Since the individual shares sum to the original η-bounded secret, the combined response has the correct distribution regardless of individual share coefficient magnitudes.

The gradual degradation at extreme resharing counts (500+) is due to numerical precision effects in the floating-point hyperball calculations as intermediate values grow, not a fundamental protocol limitation.

### References

- TALUS paper: https://arxiv.org/abs/2603.22109 (Section C.2: Refresh Protocol)
- Test: `test_measure_retry_rate_dkg_vs_reshared_shares` in `tests/resharing_tests.rs`
