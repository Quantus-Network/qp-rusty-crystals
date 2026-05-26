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
│   deterministically derives bounded sub-shares r_{I→J} for every new subset J such that
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
| **Cheating-dealer detection** | Other members of `I` independently recompute `r_{I→J}` from `s_I^old` and accuse `D_I` if the broadcast commitment differs; new-subset members cross-verify computed `s_J^new`; and a final partial-public-key sum check reconstructs `T` from `Σ_J t_J^new`, catching a malicious dealer even when their old subset has size 1. |
| **PK Preservation** | Public key `t = A·s1 + s2` unchanged, verified at the end of Round 5 via a deterministic byte-equality check against the original PK. |

## Why Custom Protocol?

Standard resharing protocols (CHURP, MPSS) assume Shamir polynomial secret sharing where shares are points on a polynomial. Our implementation uses **Replicated Secret Sharing (RSS)** with subset-indexed additive shares:

```
secret = Σ share[S]  for all subsets S of size n - t + 1
```

The custom design lets each old RSS subset re-share *its own* share to the new committee independently, without anyone ever combining the sub-shares back into `s`.

## Bounded Conditional Splitting

Earlier versions of this module sampled all but one `r_{I→J}` as `η`-bounded values and let one residual sub-share absorb the equation

```text
r_{I→J_residual} = s_I^old - Σ_{J≠J_residual} r_{I→J} mod Q.
```

That preserves the secret, but the residual can become a full-ring coefficient. After repeated handoffs, those large coefficients can appear in the recovered partial secrets used by Mithril-style hyperball rejection sampling, which moves signing outside the original proof regime.

The current protocol instead uses a bounded conditional splitter. For each coefficient of `s_I^old` and for `m = |new_subsets|`, the dealer:

1. Converts the coefficient to its centered representative in `(-Q/2, Q/2]`.
2. Splits it as evenly as possible across all `m` new subsets, so the deterministic base values sum exactly to the centered coefficient.
3. Adds deterministic PRF-derived pairwise zero-sum noise: for every pair `(J_a, J_b)`, sample a small `δ ∈ [-η, η]`, add `δ` to `J_a`, and subtract `δ` from `J_b`.

The output satisfies the exact integer equation

```text
Σ_J r_{I→J} = centered(s_I^old)
```

and therefore also the required modular equation. No single sub-share absorbs a full residual. Each sub-share coefficient is bounded by roughly

```text
ceil(|centered(s_I^old)| / m) + (m - 1)η.
```

This is a practical bounded conditional sampler over the sum constraint. It is not an `η`-bounded sharing and it is not claimed to be a discrete Gaussian sampler. The security proof obligation is instead the same one used by Mithril's hyperball rejection analysis: every recovered signing partial must remain within the norm bound used to choose the hyperball parameters.

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

## Coefficient Growth and Signing Security

ML-DSA's base secret has `η`-bounded coefficients, but Mithril-style RSS key generation and a posteriori sharing do not require each stored RSS subset share to be `η`-bounded forever. The relevant proof condition is on the recovered partial secret used by signing.

For a signing set `A` and party `i`, let `p_i(A) = (p_{i,1}, p_{i,2})` be the result of RSS recovery. The hyperball rejection proof assumes the shift

```text
v_i(c) = ((c · p_{i,1}) / ν, c · p_{i,2})
```

is within the configured norm bound for all challenges `c` sampled by `SampleInBall`. A conservative deterministic sufficient condition is

```text
τ · sqrt(||p_{i,1}||² / ν² + ||p_{i,2}||²) ≤ B.
```

The bounded conditional splitter is designed to prevent the random-walk growth caused by residual sub-shares, so this recovered-partial norm remains stable across repeated committee handoffs.

### Empirical Results

Testing with a 2-of-3 configuration shows coefficients stabilize after the first resharing:

| Resharings | Max |coeff| |
|------------|-----|
| 0 (DKG)    | 2   |
| 1          | 13-14 |
| 10         | 12-13 |
| 100        | 12-14 |
| 1000       | 12-13 |

The first resharing increases coefficients from η=2 to ~14 due to the balanced split plus pairwise noise across 3 subsets. After that, coefficients stay bounded because we're splitting already-bounded values and the noise terms cancel on average. Signing success rate remains 100% with ~0.5 average retries (same as fresh DKG shares) even after 1000 consecutive resharings.

With the old residual-based approach, coefficients grew as ~√n and signing would fail around 250-500 resharings.

A complete deployment should still enforce or audit the recovered-partial norm invariant for every supported `(T, N)` configuration, because that is the condition needed by the signing proof.
