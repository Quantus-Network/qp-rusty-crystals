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

### Protocol Rounds (session-randomized protocol with active-set liveness)

This module uses **distributed per-subset re-sharing** with SSID-based replay protection, public session randomization, and active-set liveness (resharing succeeds when up to `n_old − t_old` old members are offline). At no point does any party ever assemble the full secret `s`, and no individual share is exposed on public broadcast traffic. Round 4 private traffic does contain secret share material and requires an authenticated-encrypted channel.

```
Round 1: Entropy Commitment / Ready (Session Randomization)
├── Each old committee member generates fresh entropy and broadcasts H(entropy).
├── The commitment doubles as that member's Ready signal.
└── Commit-reveal prevents any party from biasing the session seed.

Act Proposal (Active-Set Selection)
├── The session leader (lowest-ID new committee member) proposes the active set Act:
│   all old members once everyone has committed (fast path), the committed subset
│   once every *expected* member has committed (set_expected_active_set(), for
│   transports where some old members are structurally unreachable), or the
│   committed subset after the caller closes the ready window
│   (close_ready_window(), e.g. on a transport timeout).
├── Every party verifies: sender is the leader, Act ⊆ old committee, |Act| ≥ t_old.
│   |Act| ≥ t_old guarantees every old subset I (size n_old − t_old + 1) intersects
│   Act, so a live dealer exists for every subset.
├── No party broadcasts its Round 2 reveal until it holds a Round 1 commitment from
│   every Act member: every contributor's entropy is fixed before any reveal is
│   sent, so a colluding member listed in Act cannot choose its entropy after
│   seeing honest reveals to bias the session seed.
└── If fewer than t_old old members are ready, the protocol aborts
    (InsufficientParties).

Round 2: Entropy Reveal (Public Session Seed)
├── Active old committee members reveal their entropy.
├── All parties verify reveals against Round 1 commitments.
└── Session seed = SHAKE256("resharing-session-seed-v1" || ssid || party_1 || entropy_1 || ...)
    computed deterministically from the active set's contributions in sorted party ID order.

Round 3: Per-Subset Commitments
├── For each old subset I, the designated dealer D_I = min(I ∩ Act) (lowest-ID active
│   old participant in I) deterministically derives bounded sub-shares r_{I→J} for every
│   new subset J such that Σ_J r_{I→J} = s_I^old. The derivation incorporates the public
│   session seed for per-session randomization. All members of I hold the same s_I^old
│   and the derivation is deterministic, so dealer identity does not affect the values.
├── D_I broadcasts H(r_{I→J}) for each (I, J).
└── Every other active member of I recomputes the same r_{I→J} values and verifies
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

Round 6: Signed Transcript Acceptance (Certificate)
├── After all Round 5 checks pass, each party computes the transcript hash:
│   SHAKE256("resharing-transcript-v1" || ssid || Act || session_seed ||
│   Round 3 broadcasts (Act, sorted) || Round 5 broadcasts (Act ∪ new, sorted)).
├── Each new committee member signs
│   SHAKE256("resharing-accept-v3" || ssid || transcript_hash || Act ||
│   new committee) with its long-term key (TranscriptSigner) and broadcasts
│   the signature.
├── Every party verifies every acceptance against its *own* transcript hash.
│   A dealer that equivocated (sent different broadcasts to different parties)
│   causes verification to fail on at least one honest party, which aborts.
└── The output includes a ResharingCertificate (ssid, Act, new committee,
    transcript hash, acceptance signatures) verifiable by any third party
    holding exactly the new committee's verifying keys; the required signer
    set comes from the certificate's own signed new-committee field.
```

Because `Σ_J s_J^new = Σ_J Σ_I r_{I→J} = Σ_I s_I^old = s`, the secret — and hence the public key `t = A·s1 + s2` — is preserved.

## Session Randomization and Threat Model

The protocol provides public session randomization, replay protection, and anti-bias commit-reveal. It does **not** provide post-compromise forward secrecy.

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

Before Round 2 reveals are known, an attacker cannot predict the session seed unless they know every old committee member's entropy contribution. After Round 2, the seed is public. The protocol's replay protection comes from the SSID, which binds messages to the protocol version, cryptographic suite, handoff epoch, old committee, new committee, public key, and session nonce. The protocol's confidentiality depends on keeping Round 4 private messages encrypted and authenticated.

### Mandatory Erasure at Finalize

Because sub-share derivation is deterministic from the (public, post-Round-2) session seed and the old subset shares, erasure of pre-handoff state is the compensating control for forward secrecy: an attacker must compromise a machine **while it still holds old material** to recompute the handoff.

On successful completion (`Action::Return`), the protocol zeroizes, in place: the caller-provided seed, this party's entropy, the session seed, all derived sub-shares `r_{I→J}`, all received Round 4 messages, the aggregated new-share working set, and — for old committee members — **the old share held in the config**. `old_share_erased()` reports whether the config's share is gone. The same erasure runs again on `Drop` (covering abort paths). Callers must still erase their own copies: the original share file/keystore entry and anything cloned before `ResharingConfig::new`.

**Abort recovery**: a session that fails or stalls before Round 6 certification has produced no replacement share, and dropping the failed protocol erases the old share held in the config. Old committee members that moved their only live copy of the share into `ResharingConfig` must recover it with `take_existing_share()` before dropping the protocol, then retry with a fresh session. Recovering the share marks an in-flight session as failed (it cannot continue without the share).

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Secrecy of `s`** | No party — not even any dealer — ever holds `s` in clear. Each `D_I` only handles `s_I^old`, which they already had. |
| **Replay protection** | Every message carries an SSID derived from the protocol version, suite ID, handoff epoch, old/new committees, public key, and session nonce (`RESHARING_SSID_V2`). Messages with a mismatched SSID are ignored; transcripts from other protocol versions, suites, or epochs cannot be replayed. |
| **Session randomization** | Session seed incorporates the SSID and fresh entropy from all active old committee members via commit-reveal, so different sessions produce different deterministic sub-share splits even if entropy is accidentally reused. This does not provide post-compromise forward secrecy once the transcript is recorded. |
| **Liveness with offline old members** | Round 1 commitments double as Ready signals. The session leader (lowest-ID new committee member) proposes the active set `Act` of ready members (`|Act| ≥ t_old`); dealers are assigned as `min(I ∩ Act)`, so resharing completes with up to `n_old − t_old` old members offline. Transports where some old members are structurally unreachable (e.g. a mesh spanning only the new committee) can use `set_expected_active_set` on the leader for a deterministic proposal without waiting for a timeout. The leader cannot break safety: parties verify `Act` against the Ready signals they received themselves, no party reveals entropy until it holds commitments from all of `Act` (so every contributor's entropy is fixed before any reveal), sub-share derivation is deterministic (dealer identity doesn't change values), and the seed stays unbiased because `Act` contains at least one honest member. A malicious leader can at most deny service or select among ready members; equivocating proposals lead to mismatched deterministic commitments and an abort. |
| **Confidentiality of contributions** | Rounds 1-3, 5 broadcast only hash commitments; Round 4 sub-shares travel privately. Even an unbounded eavesdropper learns nothing about any `s_I^old` from the public transcript. |
| **Cheating-dealer detection** | Old-subset peers recompute and verify Round 3 commitments before Round 4 whenever the old subset has another member. New-subset members verify delivered sub-shares against Round 3 commitments, reject over-large sub-share coefficients, and reject recovered signing partials that exceed the existing hyperball safety envelope. A final partial-public-key sum check reconstructs `T` from `Σ_J t_J^new`, catching aggregate-secret corruption even when an old subset has size 1. If any verification fails, the protocol aborts. |
| **PK Preservation** | Public key `t = A·s1 + s2` unchanged, verified at the end of Round 5 via a deterministic byte-equality check against the original PK. |
| **Transcript agreement + attestation** | Round 6: every new committee member signs the transcript hash with its long-term key; every party verifies all acceptances against its own transcript hash, so completion implies all parties observed identical broadcasts (equivocation ⇒ abort). The resulting `ResharingCertificate` lets a third party holding the new committee's verifying keys confirm the whole new committee attested to the handoff. It attests process integrity and PK preservation, not share-distribution properties (that would require ZK proofs). |

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
3. Adds deterministic PRF-derived zero-sum noise via **balanced mean subtraction** (`add_mean_subtracted_noise`): for each coefficient, sample `m` i.i.d. deltas `δ_0..δ_{m−1}` and assign `N_j = δ_j − balanced(Σδ)_j` to subset `j`. The assignment is integer zero-sum (`Σ_j N_j = 0`), and reproduces the a-posteriori coset Gaussian's **uniform** negative correlation `Cov(N_j,N_k) = −σ²/m`, so `Var(Σ_{J∈pattern} N) = σ²·|pattern|·(1 − |pattern|/m)` matches the keygen conditional partial variance for *every* recovery pattern. The deltas are **sparse-ternary** in `{−1, 0, +1}` with intensity `P(±1) ≈ 0.49 / S_old`, where `S_old = C(n_old, n_old−t_old+1)` is the number of old subsets. This `1/S_old` scaling is the key: because each new share `s_J^new = Σ_I r_{I→J}` aggregates contributions from all `S_old` old subsets, injecting only `≈ 1/S_old` of the keygen noise per dealer makes the aggregated new-share noise land at the keygen level — the new shares are distributed like a *fresh* keygen sharing (a discrete Gaussian over the sum-`s` coset, i.e. Mithril §3.3 a-posteriori sharing), so the recovered-partial norm no longer grows with the committee size. (The `v4` splitter used an `O(m)` telescoping cycle `δ_i − δ_{i−1}`, whose *banded* correlation overshot for non-contiguous patterns; the earlier `v3` used a fixed `CBD_η` delta independent of `S_old`, over-injecting noise.) See `SECURITY_PROOF.md`.

The output satisfies the exact integer equation

```text
Σ_J r_{I→J} = centered(s_I^old)
```

and therefore also the required modular equation. No single sub-share absorbs a full residual. Each sub-share coefficient is bounded by roughly

```text
ceil(|centered(s_I^old)| / m) + (m - 1)η.
```

This is a practical bounded conditional sampler over the sum constraint. It is not an `η`-bounded sharing and it is not claimed to be a discrete Gaussian sampler. The security proof obligation is instead the same one used by the hyperball rejection analysis: every recovered signing partial must remain within the partial-secret norm bound `B'` that the configuration's hyperball parameters are derived from.

Round 5 now enforces that condition directly. After a new party aggregates its `s_J^new` values, it enumerates every threshold signing set containing itself, recovers the same partial secret that signing would use, and aborts unless

```text
sqrt(τ) · sqrt(||p_{i,1}||² / ν² + ||p_{i,2}||²) ≤ B'
```

for the existing `(t_new, n_new)` hyperball parameters. This catches bounded, public-key-preserving zero-sum reshaping attacks that would pass the per-subshare coefficient bound but push later signing outside the intended proof regime.

Round 5 additionally enforces a per-subset **stored-share norm guard** (`B_G` analog): each aggregated `s_J^new` individually must satisfy the same weighted-norm bound with `num_secrets = 1` (a single base secret's envelope, versus the `⌈C(N,T−1)/T⌉` shares summed at recovery time). This is defense in depth against inflating an individual stored share while arranging cancellation in the specific combinations the recovered-partial check sums.

## Usage

```rust
use qp_rusty_crystals_threshold::resharing::{
    ResharingConfig, ResharingProtocol, ResharingSignerConfig, Action,
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

// Long-term-key signer for Round 6 transcript acceptance (e.g. Ed25519),
// plus the verifying keys of every new committee member.
let signer_config = ResharingSignerConfig::new(
    my_signer,          // implements TranscriptSigner
    verifying_keys,     // BTreeMap<ParticipantId, PublicKey>, covers new committee
    &new_participants,
)?;

// Old committee members pass Some(existing_share); new-only parties pass None.
// `epoch` is a monotonic handoff counter for this public key (0 for the first
// resharing after keygen), bound into the SSID against cross-epoch replay.
let mut protocol = ResharingProtocol::new(config, signer_config, seed, &session_nonce, epoch)?;

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
            // Publicly verifiable proof of the handoff:
            let certificate = output.certificate;
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
| `Action::SendMany` (Rounds 1, 2, 3, 5, 6) | Authenticated broadcast (integrity only) |
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

- `Round1EntropyCommitment`: Hash commitment to entropy `H(entropy)` for session randomization; doubles as the sender's Ready signal
- `ActProposal`: The leader's proposed active set `Act` (sorted, `⊆` old committee, `|Act| ≥ t_old`)
- `Round2EntropyReveal`: Revealed entropy (32 bytes) — verified against Round 1 commitment
- `Round3Broadcast`: Per-subset commitment hashes `H(r_{I→J})` (no plaintext shares)
- `Round4Message`: Private sub-share reveal (**requires secure channel**) — one message per (dealer, recipient) carrying every `r_{I→J}` the dealer owes that recipient. Dealers handle self-deals locally and never emit `SendPrivate(self, _)`.
- `Round5Broadcast`: Commitments to computed `s_J^new`, partial public-key contributions `t_J^new`
- `Accept`: Signed acceptance of the transcript hash by a new committee member (Round 6); the collected signatures form the `ResharingCertificate`

## State Machine

```
Round1Generate -> Round1Waiting -> Round2Generate -> Round2Waiting
    -> Round3Generate -> Round3Waiting -> Round4Generate -> Round4Waiting
    -> Round5Generate -> Round5Waiting -> Combining
    -> AcceptGenerate -> AcceptWaiting -> Done
```

NewOnly parties skip Rounds 1-2 (entropy commit-reveal) and go directly to `Round2Waiting`. The Act proposal is emitted and consumed within the `Round1Waiting`/`Round2Waiting` states; parties do not advance past them until `Act` is agreed. Old members outside `Act` observe (they verify and, if in the new committee, receive shares) but do not contribute entropy or deal.

## Limitations

- Maximum 16 parties (due to u16 subset masks)
- Requires at least `t_old` old committee members (and every new committee member) to be online. Offline old members are excluded from the active set after the caller closes the ready window (`close_ready_window()` on the leader, e.g. after a transport timeout), or deterministically via `set_expected_active_set()` on the leader when the transport makes some old members structurally unreachable; dealers fail over to `min(I ∩ Act)`. If an *active* dealer goes offline mid-session or cheats, the protocol still aborts (no mid-session re-deal in this implementation) — restart the session and the dead dealer will be excluded from the next active set.
- **Secure channels required for Round 4 private messages** (see Transport Security section above)
- **Cryptographically random entropy required from each active old committee member** (see Entropy Requirements section above)

## Coefficient Growth and Signing Security

ML-DSA's base secret has `η`-bounded coefficients, but RSS key generation and a posteriori sharing do not require each stored RSS subset share to be `η`-bounded forever. The relevant proof condition is on the recovered partial secret used by signing.

For a signing set `A` and party `i`, let `p_i(A) = (p_{i,1}, p_{i,2})` be the result of RSS recovery. The hyperball rejection proof assumes the shift

```text
v_i(c) = ((c · p_{i,1}) / ν, c · p_{i,2})
```

is within the configured norm bound for all challenges `c` sampled by `SampleInBall`. A conservative deterministic sufficient condition is

```text
sqrt(τ) · sqrt(||p_{i,1}||² / ν² + ||p_{i,2}||²) ≤ B'
```

The bounded conditional splitter is designed to prevent the random-walk growth caused by residual sub-shares, so this recovered-partial norm remains stable across repeated committee handoffs.

### Post-Resharing Coefficient Distribution

For honest executions of the bounded splitter, coefficients follow an **approximately Gaussian distribution** that is stable across further resharings. This is a consequence of the Central Limit Theorem: each new subset share is a sum of contributions from multiple old subsets, and the sum of many bounded random variables converges to a Gaussian. This distributional analysis is useful for parameter sanity checks; the runtime security guard is the recovered-partial norm check above.

#### Variance Scaling

For a (t, n) threshold scheme with **m = C(n, t-1)** subsets, each new subset
share sums one fragment from each of the `S_old` old subsets, where each fragment
is a balanced-split piece plus a mean-subtracted noise term. The coset splitter
scales each dealer's noise intensity as `1/S_old`, so the aggregated noise variance
is **independent of the committee size** and matches the keygen level:

```
σ_aggregated_noise ≈ σ_keygen = √2     (by design; intensity ∝ 1/S_old)
σ_stored_share     ≈ 1.7–1.85          (balanced-split spread + keygen-level noise)
```

This is the key difference from the earlier fixed-`CBD_η` splitter, whose
stored-share σ grew as `√(2.1·m)` (e.g. σ ≈ 6.6 for 4-of-6). Holding σ ≈
keygen-level keeps recovered partials inside the keygen envelope `B` regardless of
how large the committee is.

#### Empirical Measurements

Measured with the fresh re-sharing splitter (per-coefficient statistics over all
stored shares; values are the stabilized post-resharing fixed point). For
comparison, the final column shows the earlier fixed-`CBD_η` splitter's σ.

| Config | Subsets (m) | Empirical σ | Observed range | DKG σ | Old `√(2.1m)` σ |
|--------|-------------|-------------|----------------|-------|-----------------|
| 2-of-3 | 3           | 1.76        | [-6, 8]        | 1.41  | 2.65            |
| 2-of-4 | 4           | 1.74        | [-8, 7]        | 1.41  | 3.02            |
| 3-of-5 | 10          | 1.81        | [-8, 8]        | 1.41  | 4.67            |
| 4-of-6 | 20          | ~1.85       | —              | 1.41  | 6.57            |

Numbers are reproduced by `test_coefficient_distribution_*` in
`tests/resharing_tests.rs` (4-of-6 is the projected value). The DKG baseline is uniform over `[-2, 2]`
(σ ≈ 1.41, excess kurtosis ≈ −1.3); after the first resharing the distribution
becomes approximately Gaussian (excess kurtosis ≈ 0, see Key Properties). Note the
σ is now roughly **constant in `m`** rather than growing.

#### Key Properties

1. **Symmetric**: Skewness ≈ 0 (measured `|skew| < 0.04` across all configs).
2. **Approximately Gaussian**: Excess kurtosis ≈ 0 after the first resharing
   (measured within `±0.1`), versus ≈ −1.3 for the uniform DKG baseline. The
   aggregated (CLT) sum over old subsets pulls the distribution toward a Gaussian.
3. **Idempotent**: The distribution is a fixed point of resharing — variance
   changes by < 5% from the first resharing through 10–100 subsequent resharings.
4. **Keygen-matched width**: σ ≈ 1.25× the keygen σ and constant in committee
   size, the a-posteriori target that keeps recovered partials under `B`.

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
sqrt(τ) · sqrt(||p_{i,1}||² / ν² + ||p_{i,2}||²) ≤ B'
```

Where:
- `p_{i,1}`, `p_{i,2}` are the s1/s2 components of the recovered partial
- `τ = 60` is the challenge weight; the `sqrt(τ)` amplification matches the Gaussian-heuristic convention used to define `B` in Mithril §3.4 / footnote 3
- `ν = 7` is the s1 scaling factor for ML-DSA-87
- `B'` is the configured partial-secret norm bound for `(t_new, n_new)` — see below

> **Note.** Earlier revisions of this document compared `τ · ||p||_ν` against the
> sampling radius `r'`. That was incorrect: `r'` (~500k–665k) is the radius the
> signing nonce is sampled from, **not** the bound on the secret-dependent shift.
> The correct quantity is Mithril's partial-secret bound `B` (~650–1450), and the
> amplification factor is `sqrt(τ)`, not `τ`.

#### Bound `B` and the enlargement `B' = κ·B`

`B` is the keygen-calibrated Mithril §3.4 bound that the hyperball radii are derived from (`r = slack·B`, `r' = slackradius2·r`; in `scripts/compute_hyperball_params.py`, `B` is the script's `beta`).

Honest resharing inflates the recovered-partial norm relative to the keygen `B`. With the v5 mean-subtracted coset splitter (noise intensity `∝ 1/S_old`) the steady-state overshoot is ~0.78–1.16× across committees `2 ≤ T ≤ N ≤ 6`, instead of the `~√S_old` growth of the earlier fixed-noise splitter. Where the overshoot exceeds 1, the config enlarges the bound to `B' = κ·B` **and** the hyperball radii to `(κ·r, κ·r')` by the same factor. Scaling `(B, r, r')` by a common `κ` is *scale-invariant* in the radius condition `r'² = r² + B² + 2rB/φ`, so the **per-sample** rejection distribution `ε` is unchanged. The **signing-query budget `Q_s = 1/(K·ε)` is not** preserved when `κ > 1`: enlarging the ball lowers per-iteration acceptance (the enlarged radius nears ML-DSA-87's fixed verification ceilings), so `K` grows — and since `ε` is fixed, `Q_s` falls by exactly that `K` factor (`(3,5)`: −0.78 bits, K 35→60; `(2,2)`/`(2,3)` stay at κ=1 so pay nothing). See `SECURITY_PROOF.md` for the table.

This enlargement only works while `κ·r` stays under ML-DSA-87's fixed `‖z₁‖∞ < γ1 − β` verification ceiling, which caps `κ` at ≈1.5×. With the small v5 overshoot this is no longer the binding constraint for the supported committees (see table).

#### Empirical Verification

Measured honest post-resharing overshoot (`sqrt(τ)·‖p‖_ν / B`) with the **v5 mean-subtracted coset splitter** (`add_mean_subtracted_noise`; Rust `test_recovered_partial_variance_*`, fixed point over all signing sets: 100 reshares for `(2,*)`, 20 for `(3,5)`, 10 for `(4,6)`), the re-derived enlargement `κ`, and the resulting `K`:

| Config | Base `B` | Overshoot (v4 → v5) | `κ` | `B' = κ·B` | `K` (prev) | Supported? |
|--------|---------|---------------------|------|-----------|-----------|------------|
| 2-of-2 | 650  | 0.975 → **0.780** | 1.00 | 650   | 4 (was 6/14) | ✅ (base params) |
| 2-of-3 | 920  | 0.897 → **0.810** | 1.00 | 920   | 5 (was 6/23) | ✅ (base params) |
| 2-of-4 | 920  | 1.018 → **0.961** | 1.10 | 1,011 | 10 | ✅ |
| 3-of-5 | 1,300 | 1.107 → **1.012** | 1.15 | 1,495 | 60 (was 227) | ✅ |
| 4-of-6 | 1,454 | 1.286 → **1.163** | 1.25 | 1,818 | 1,600 (was 350 base) | ✅ (per-sig tax) |

The **v5 mean-subtracted noise** (`δ_j − balanced(Σδ)_j`) reproduces the a-posteriori coset Gaussian's uniform negative correlation, dropping every overshoot vs the v4 telescoping cycle. `(2,2)`/`(2,3)` now sit far enough below the base bound to reshare at **κ=1** — a reshared committee signs with exactly the same params as a fresh keygen one, at no `Q_s` cost. `(3,5)` dropped `K` 227→60 (~1.9 bits of `Q_s` recovered). The base `B` itself is sampler-independent (keygen §3.4) and unchanged; only `κ` depends on the splitter.

`(4,6)` is **enabled** by enlargement (`κ = 1.25`, `K = 1600`) because the `near-mpc` integration requires the 4-of-6 committee shape. Its honest overshoot ~1.163× is extremely stable (1.153–1.163 across 8 seeds, the recovered-partial norm concentrates), so κ=1.25 carries a ~7.5% margin. The cost is a per-signature tax: every `(4,6)` signature uses `K = 1600` (~15 MB/session, `Q_s ≈ 2^28.2 ≈ 300M` queries). The path to `κ=1 / K=350` (removing the tax) is future work: budget the per-reshare noise intensity down for a bounded reshare count, or draw a single collaborative coset-Gaussian sample (one extra MPC round) for keygen-level hiding at `κ=1`.

These numbers are reproduced by `scripts/compute_hyperball_params.py` (`compute_resharing_params`) and the `test_recovered_partial_variance_*` tests.

#### Long-Term Stability (100+ Resharings)

For the supported configs, the recovered-partial norm is a **stable fixed point** — it stabilizes after the first resharing and stays within <5% across 100 consecutive resharings, so the guard margin depends only on `(t, n)`, not on the number of resharings. This is verified by `test_recovered_partial_variance_2_of_3`, `test_recovered_partial_variance_2_of_4`, and `test_recovered_partial_variance_3_of_5`.

#### Safety Analysis

The guard rejects any resharing output (honest or adversarial) whose challenge-amplified recovered partial `sqrt(τ)·‖p‖_ν` exceeds the configured bound `B'`. Because the enlarged radii `(κ·r, κ·r')` were derived from the same `B'`, every accepted partial provably sits inside the hyperball regime that the signing security proof requires for that configuration — at the cost of a larger `K` and the corresponding `Q_s = 1/(K·ε)` reduction (see above). This ensures malicious bounded zero-sum reshaping cannot silently move the key outside the checked signing regime.

#### Conclusion

**Accepted resharings remain inside the signing regime that `(r, r', K, B')` were jointly derived for.** For the supported committees (`(2,2)`, `(2,3)`, `(2,4)`, `(3,5)`):
1. honest repeated resharing is a stable fixed point (verified over 100 resharings);
2. the v5 mean-subtracted coset splitter holds the recovered-partial overshoot at ~0.78–1.01× (independent of committee size);
3. where overshoot > 1, the enlarged bound `B' = κ·B` covers it and the matching enlarged radii keep the per-sample `ε` invariant (scale-invariant radius condition) at the cost of a larger `K` — which reduces `Q_s = 1/(K·ε)` by that `K` factor (`(3,5)`: ~0.78 bits; `(2,2)`/`(2,3)` use κ=1 and pay nothing);
4. the recovered-partial guard rejects adversarial outputs exceeding `B'`.

`(4,6)` is **enabled** by enlargement under the v5 coset splitter (overshoot ~1.163× at keygen-level hiding, κ = 1.25, `K = 1600`) for the `near-mpc` 4-of-6 committee shape — at the cost of a per-signature tax (~15 MB/session, `Q_s ≈ 2^28.2`). The path to `κ=1 / K=350` (removing the tax) is future work: budget the per-reshare noise intensity down for a bounded reshare count, or draw a single collaborative coset-Gaussian sample (one extra MPC round) for keygen-level hiding at `κ=1`. A separate one-time hiding (hint-MLWE) loss applies to a-posteriori-style sharing in general, per Mithril §3.3 (≤12 bits heuristic); see `SECURITY_PROOF.md`.
