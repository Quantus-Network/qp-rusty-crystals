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

### Protocol Rounds (5-round session-randomized protocol)

This module uses **distributed per-subset re-sharing** with SSID-based replay protection and public session randomization. At no point does any party ever assemble the full secret `s`, and no individual share is exposed on public broadcast traffic. Round 4 private traffic does contain secret share material and requires an authenticated-encrypted channel.

```
Round 1: Entropy Commitment (Session Randomization)
├── Each old committee member generates fresh entropy and broadcasts H(entropy).
└── Commit-reveal prevents any party from biasing the session seed.

Round 2: Entropy Reveal (Public Session Seed)
├── Old committee members reveal their entropy.
├── All parties verify reveals against Round 1 commitments.
└── Session seed = SHAKE256("resharing-session-seed-v1" || party_1 || entropy_1 || ...)
    computed deterministically from all contributions in sorted party ID order.

Round 3: Per-Subset Commitments
├── For each old subset I, the designated dealer D_I (lowest-ID old participant in I)
│   deterministically derives bounded sub-shares r_{I→J} for every new subset J such that
│   Σ_J r_{I→J} = s_I^old. The derivation incorporates the public session seed for
│   per-session randomization.
├── D_I broadcasts H(r_{I→J}) for each (I, J).
└── Every other old member of I recomputes the same r_{I→J} values and verifies
    D_I's commitments before any Round 4 private delivery occurs.

Round 4: Private Sub-Share Reveal (⚠️ REQUIRES SECURE CHANNEL)
├── D_I privately delivers r_{I→J} to each member of new subset J.
└── No public traffic carries any share material.

Round 5: Verification + Public-Key Invariant
├── Each new party verifies received r_{I→J} against the Round 3 commitment, then
│   sums s_J^new = Σ_I r_{I→J} for each new subset J they're in, and broadcasts
│   a commitment to s_J^new so that other members of J can cross-verify.
├── Each new party also broadcasts t_J^new = A·s1_J^new + s2_J^new (mod Q) for
│   every J they hold. After Round 5, anyone can sum these and confirm
│   Σ_J t_J^new = T (the original public key). This catches a malicious dealer
│   even when their old subset has size 1.
└── If any verification fails, the protocol aborts. (No blame attribution is
    attempted since it's not always possible to identify the misbehaving party.)
```

Because `Σ_J s_J^new = Σ_J Σ_I r_{I→J} = Σ_I s_I^old = s`, the secret — and hence the public key `t = A·s1 + s2` — is preserved.

## Session Randomization and Threat Model

The 5-round protocol provides public session randomization, replay protection, and anti-bias commit-reveal. It does **not** provide post-compromise forward secrecy.

Round 2 entropy reveals are part of the public transcript. After Round 2, the `session_seed` is public transcript material. Because sub-shares are derived deterministically from `session_seed`, `i_mask`, and `s_I^old`, an attacker who records the transcript and later compromises old subset shares can recompute the resharing randomness and derive the corresponding new shares.

### How It Works

1. **Entropy Generation**: Each old committee member generates fresh random entropy from their provided seed.

2. **Commit-Reveal**: Round 1-2 use a commit-reveal scheme to make the session seed unpredictable before reveals and prevent parties from choosing entropy after seeing others' revealed values.

3. **Public Session Seed Derivation**: The session seed is computed as:
   ```
   session_seed = SHAKE256("resharing-session-seed-v1" || ssid || party_id_1 || entropy_1 || party_id_2 || entropy_2 || ...)
   ```
   where parties are processed in sorted order by ID. The SSID is included so that even if parties accidentally reuse entropy seeds across different resharing sessions, the session seed (and thus sub-share derivation) will differ.

4. **PRF Mixing**: The public session seed is mixed into the PRF that derives sub-shares:
   ```
   prf_seed = SHAKE256("resharing-subset-prf-v3" || session_seed || i_mask || s_I^old)
   ```

### Security Boundary

Before Round 2 reveals are known, an attacker cannot predict the session seed unless they know every old committee member's entropy contribution. After Round 2, the seed is public. The protocol's replay protection comes from the SSID, which binds messages to the old committee, new committee, public key, and session nonce. The protocol's confidentiality depends on keeping Round 4 private messages encrypted and authenticated.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Secrecy of `s`** | No party — not even any dealer — ever holds `s` in clear. Each `D_I` only handles `s_I^old`, which they already had. |
| **Replay protection** | Every message carries an SSID derived from the old/new committees, public key, and session nonce. Messages with a mismatched SSID are ignored. |
| **Session randomization** | Session seed incorporates the SSID and fresh entropy from all old committee members via commit-reveal, so different sessions produce different deterministic sub-share splits even if entropy is accidentally reused. This does not provide post-compromise forward secrecy once the transcript is recorded. |
| **Confidentiality of contributions** | Rounds 1-3, 5 broadcast only hash commitments; Round 4 sub-shares travel privately. Even an unbounded eavesdropper learns nothing about any `s_I^old` from the public transcript. |
| **Cheating-dealer detection** | Old-subset peers recompute and verify Round 3 commitments before Round 4 whenever the old subset has another member. New-subset members verify delivered sub-shares against Round 3 commitments, reject over-large sub-share coefficients, and reject recovered signing partials that exceed the existing hyperball safety envelope. A final partial-public-key sum check reconstructs `T` from `Σ_J t_J^new`, catching aggregate-secret corruption even when an old subset has size 1. If any verification fails, the protocol aborts. |
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

That preserves the secret, but the residual can become a full-ring coefficient. After repeated handoffs, those large coefficients can appear in the recovered partial secrets used by hyperball rejection sampling, which moves signing outside the original proof regime.

The current protocol instead uses a bounded conditional splitter. For each coefficient of `s_I^old` and for `m = |new_subsets|`, the dealer:

1. Converts the coefficient to its centered representative in `(-Q/2, Q/2]`.
2. Splits it as evenly as possible across all `m` new subsets, so the deterministic base values sum exactly to the centered coefficient.
3. Adds deterministic PRF-derived zero-sum noise using an `O(m)` telescoping cycle: for each coefficient, sample one centered-binomial delta `δ_i` per new subset and assign the difference `δ_i − δ_{(i−1) mod m}` to subset `i`. The assignment is zero-sum (`Σ_i (δ_i − δ_{i−1}) = 0`), so each subset receives exactly two noise terms regardless of `m` (per-coefficient noise variance is `O(1)` in `m`, versus `O(m)` for the earlier all-pairs pattern). The deltas are drawn from the centered binomial distribution (CBD_η, as used by ML-KEM), the standard bounded approximation to a discrete Gaussian; this makes the joint share distribution approximately multivariate Gaussian, which the key-hiding analysis in `SECURITY_PROOF.md` relies on.

The output satisfies the exact integer equation

```text
Σ_J r_{I→J} = centered(s_I^old)
```

and therefore also the required modular equation. No single sub-share absorbs a full residual. Each sub-share coefficient is bounded by roughly

```text
ceil(|centered(s_I^old)| / m) + (m - 1)η.
```

This is a practical bounded conditional sampler over the sum constraint. It is not an `η`-bounded sharing and it is not claimed to be a discrete Gaussian sampler. The security proof obligation is instead the same one used by the hyperball rejection analysis: every recovered signing partial must remain within the norm envelope assumed by the existing hyperball parameters.

Round 5 now enforces that condition directly. After a new party aggregates its `s_J^new` values, it enumerates every threshold signing set containing itself, recovers the same partial secret that signing would use, and aborts unless

```text
τ · sqrt(||p_{i,1}||² / ν² + ||p_{i,2}||²) ≤ r'
```

for the existing `(t_new, n_new)` hyperball parameters. This catches bounded, public-key-preserving zero-sum reshaping attacks that would pass the per-subshare coefficient bound but push later signing outside the intended proof regime.

## Usage

```rust
use qp_rusty_crystals_threshold::resharing::{
    ResharingConfig, ResharingProtocol, Action,
};
use rand::RngCore;

// Generate fresh entropy for this party's session-randomization contribution.
let mut seed = [0u8; 32];
rand::rngs::OsRng.fill_bytes(&mut seed);

// Generate or receive a unique nonce shared by all parties in this resharing session.
let mut session_nonce = [0u8; 32];
rand::rngs::OsRng.fill_bytes(&mut session_nonce);

// Configure resharing
let config = ResharingConfig::new(
    old_threshold,      // e.g., 2
    old_participants,   // e.g., vec![0, 1, 2]
    new_threshold,      // e.g., 3
    new_participants,   // e.g., vec![1, 2, 3, 4]
    my_party_id,
    public_key,
)?;

// Old committee members pass Some(existing_share); new-only parties pass None.
let mut protocol = ResharingProtocol::new(config, my_existing_share, seed, &session_nonce)?;

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

**CRITICAL**: Each old committee member must provide cryptographically random entropy via the `seed` parameter to `ResharingProtocol::new()`. Fresh entropy makes the public session seed unpredictable before Round 2 and avoids repeated deterministic sub-share splits. It does not provide post-compromise secrecy once the transcript has been recorded.

| Requirement | Why |
|-------------|-----|
| **Cryptographically random** | Use `OsRng` or equivalent CSPRNG, not PRNG or timestamps |
| **Independent per party** | Each party must generate their own entropy; don't share seeds |
| **Fresh per session** | Generate new entropy for each resharing; don't reuse across sessions |

If all parties reuse the same seeds with the same inputs, the protocol can repeat the same deterministic split. If seeds are predictable, the session seed can be predicted before Round 2.

## Roles

Each party has a role determined by committee membership:

| Role | Old Committee | New Committee | Actions |
|------|--------------|---------------|---------|
| `OldOnly` | ✓ | ✗ | Generate entropy; deal sub-shares for old subsets they own |
| `NewOnly` | ✗ | ✓ | Receive sub-shares; verify against commitments; aggregate `s_J^new` |
| `Both`    | ✓ | ✓ | Generate entropy; deal + receive + verify |

## Message Types

- `Round1EntropyCommitment`: Hash commitment to entropy `H(entropy)` for session randomization
- `Round2EntropyReveal`: Revealed entropy (32 bytes) — verified against Round 1 commitment
- `Round3Broadcast`: Per-subset commitment hashes `H(r_{I→J})` (no plaintext shares)
- `Round4Message`: Private sub-share reveal (**requires secure channel**) — one message per (dealer, recipient) carrying every `r_{I→J}` the dealer owes that recipient. Dealers handle self-deals locally and never emit `SendPrivate(self, _)`.
- `Round5Broadcast`: Commitments to computed `s_J^new`, partial public-key contributions `t_J^new`

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

ML-DSA's base secret has `η`-bounded coefficients, but RSS key generation and a posteriori sharing do not require each stored RSS subset share to be `η`-bounded forever. The relevant proof condition is on the recovered partial secret used by signing.

For a signing set `A` and party `i`, let `p_i(A) = (p_{i,1}, p_{i,2})` be the result of RSS recovery. The hyperball rejection proof assumes the shift

```text
v_i(c) = ((c · p_{i,1}) / ν, c · p_{i,2})
```

is within the configured norm bound for all challenges `c` sampled by `SampleInBall`. A conservative deterministic sufficient condition is

```text
τ · sqrt(||p_{i,1}||² / ν² + ||p_{i,2}||²) ≤ B.
```

The bounded conditional splitter is designed to prevent the random-walk growth caused by residual sub-shares, so this recovered-partial norm remains stable across repeated committee handoffs.

### Post-Resharing Coefficient Distribution

For honest executions of the bounded splitter, coefficients follow an **approximately Gaussian distribution** that is stable across further resharings. This is a consequence of the Central Limit Theorem: each new subset share is a sum of contributions from multiple old subsets, and the sum of many bounded random variables converges to a Gaussian. This distributional analysis is useful for parameter sanity checks; the runtime security guard is the recovered-partial norm check above.

#### Variance Scaling

For a (t, n) threshold scheme with **m = C(n, t-1)** subsets, each new subset
share sums one fragment from each of the `m` old subsets, where each fragment is
a balanced-split piece plus two CBD noise terms (from the `O(m)` telescoping
cycle). Variance therefore adds across the `m` old-subset contributions, giving a
roughly linear-in-`m` variance and `√m` standard deviation:

```
σ² ≈ 2.1 · m        (empirical fit, η = 2, CBD noise)
σ  ≈ √(2.1 · m)
```

This is a dramatic improvement over the original `O(m²)` all-pairs uniform noise,
whose variance grew as `≈ 2(m² − m)` (e.g. σ ≈ 27.6 for 4-of-6 versus ≈ 6.6
now). The `√m` scaling keeps recovered partials far closer to the keygen
envelope as the committee grows.

#### Empirical Measurements

Measured with the current `O(m)` telescoping CBD splitter (per-coefficient
statistics over all shares; values are the stabilized post-resharing fixed
point). For comparison, the final column shows the original all-pairs uniform σ.

| Config | Subsets (m) | Empirical σ | Observed range | √(2.1m) | Old all-pairs σ |
|--------|-------------|-------------|----------------|---------|-----------------|
| 2-of-3 | 3           | 2.65        | [-10, 10]      | 2.51    | 3.6             |
| 2-of-4 | 4           | 3.02        | [-13, 14]      | 2.90    | 5.0             |
| 3-of-5 | 10          | 4.67        | [-22, 21]      | 4.58    | 13.4            |
| 4-of-6 | 20          | 6.57        | [-31, 29]      | 6.48    | 27.6            |

Numbers are reproduced by `test_coefficient_distribution_*` in
`tests/resharing_tests.rs`. The DKG baseline is uniform over `[-2, 2]`
(σ ≈ 1.41, excess kurtosis ≈ −1.3); after the first resharing the distribution
becomes approximately Gaussian (excess kurtosis ≈ 0, see Key Properties).

#### Key Properties

1. **Symmetric**: Skewness ≈ 0 (measured `|skew| < 0.04` across all configs).
2. **Approximately Gaussian**: Excess kurtosis ≈ 0 after the first resharing
   (measured within `±0.08`), versus ≈ −1.3 for the uniform DKG baseline. The CBD
   noise shaping is what pulls the post-resharing distribution toward a Gaussian.
3. **Idempotent**: The distribution is a fixed point of resharing — variance
   changes by < 5% from the first resharing through 10–100 subsequent resharings.
4. **Bounded**: Coefficients stay within ≈ 4.5σ in the measured ranges.

#### Empirical Verification

The variance stabilizes after the first resharing and remains constant (within
< 5% variation) across subsequent resharings. This idempotence occurs because
subset shares become correlated after resharing, preventing further variance
growth.

#### Security Implications

For honest-resharing analysis, the post-resharing distribution can be characterized as **sub-Gaussian with parameter σ** where σ is given by the formula above. This provides:

- **Tail bounds**: P(|X| > t) ≤ 2·exp(-t²/2σ²)
- **Composability**: Sub-Gaussian distributions compose well under addition
- **Stability**: The bound holds for any number of resharings

### Hyperball Parameter Verification

The hyperball rejection sampling proof requires recovered partials to be small after challenge multiplication. The implementation enforces the following deterministic sufficient check for each new party and each threshold signing set containing that party:

```
τ · sqrt(||p_{i,1}||² / ν² + ||p_{i,2}||²) ≤ r'
```

Where:
- `p_{i,1}`, `p_{i,2}` are the s1/s2 components of the recovered partial
- `τ = 60` is the challenge weight (number of ±1 in the challenge polynomial)
- `ν = 7` is the s1 scaling factor for ML-DSA-87
- `r'` is the existing hyperball sampling radius for `(t_new, n_new)`

This does **not** change hyperball parameters. It rejects resharing outputs that would require larger parameters.

#### Empirical Verification

Testing shows that honest post-resharing recovered partials have comfortable margin relative to this enforced bound:

| Config | Max Combined Norm | τ·Max Norm | r' | Guard Margin | Coeff σ Ratio |
|--------|------------------|------------|-----|--------------|---------------|
| 2-of-3 | 179              | 10,740     | 631,703 | 98.3% | 2.7x |
| 2-of-4 | 251              | 15,060     | 633,006 | 97.6% | 3.7x |
| 3-of-5 | 1,037            | 62,220     | 577,546 | 89.2% | 13.5x |
| 4-of-6 | 2,894            | 173,640    | 517,853 | 66.5% | 36x |

Where:
- **Combined Norm** = `sqrt(||s1||² / ν² + ||s2||²)` for the recovered partial
- **τ·Max Norm** is the conservative challenge-amplified bound checked by Round 5
- **Guard Margin** = `(r' - τ·max_norm) / r'`
- **Coeff σ Ratio** = post-resharing coefficient std dev / original η-bounded std dev

Even in the worst observed honest case (4-of-6 after resharing), the challenge-amplified bound is ~174,000 vs an r' limit of ~518,000, leaving about **66%** margin.

#### Long-Term Stability (100+ Resharings)

Extended testing over 100 resharings confirms the distribution is a **stable fixed point**:

| Config | Resharings | Max Norm | τ·Max Norm | Guard Margin |
|--------|------------|----------|------------|--------------|
| 2-of-3 | 100        | 179      | 10,740     | 98.3% |
| 2-of-4 | 100        | 251      | 15,060     | 97.6% |

The recovered partial norm remains stable across honest resharings. The margin depends only on the configuration `(t, n)`, not on the number of resharings performed. This confirms the idempotence property observed for honest executions: the post-resharing distribution is a fixed point of the resharing operator.

#### Why Such Large Margins?

The hyperball parameters are computed to handle:
1. Sum of `t` parties' random hyperball contributions
2. Challenge multiplication `c · s` which amplifies by factor `τ`
3. Rejection sampling overhead

The key insight is that the coefficient variance (which grows ~36x for 4-of-6) affects individual coefficients, but the **L2 norm** of the full polynomial vector grows much more slowly because:
- Most coefficients remain small (Gaussian distribution is concentrated near 0)
- The L2 norm averages over all ~3,840 coefficients (L×N + K×N = 7×256 + 8×256)
- The hyperball parameters already include 1.3x safety factors

#### Safety Analysis

For a recovered partial with coefficient std dev `σ`, the expected L2 norm is:

```
E[||p||] ≈ σ · sqrt(dimension) = σ · sqrt(3840) ≈ 62·σ
```

For 4-of-6 with σ ≈ 51:
- Expected L2 norm ≈ 62 × 51 ≈ 3,100
- Observed max combined norm ≈ 2,894
- Conservative challenge-amplified bound ≈ 60 × 2,894 ≈ 174,000, still below r' = 517,853

The Round 5 guard rejects any resharing output whose challenge-amplified recovered partial exceeds the existing `r'` radius. This ensures malicious bounded zero-sum reshaping cannot silently move the key outside the checked signing regime.

#### Conclusion

**Accepted resharings remain inside the existing signing regime.** The coefficient variance growth after honest resharing is controlled by:
1. The L2 norm averaging effect across thousands of coefficients
2. The bounded conditional splitter preventing unbounded residual growth
3. The idempotent distribution that stabilizes after the first resharing
4. The Round 5 recovered-partial guard, which rejects adversarial outputs that exceed the current hyperball envelope

Within the supported `(t, n)` configurations, honest repeated resharing remains stable in testing, and adversarial resharing outputs are accepted only if every recovered signing partial passes the same norm guard used to justify signing with the existing parameters.
