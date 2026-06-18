# Resharing Security Proof Notes

This note gives a proof outline for the resharing protocol implemented in this
module. It is meant to justify why an accepted resharing can be used by the
existing Threshold ML-DSA signing protocol without changing the public key or the
hyperball parameters.

The proof is conditional on the same assumptions used by the Threshold ML-DSA
paper, plus the transport and erasure assumptions stated below. It is not an
independent audit.

## Protocol Summary

Let the old committee have threshold `t_old` and size `n_old`. Let the new
committee have threshold `t_new` and size `n_new`.

The old RSS subset size is:

```text
k_old = n_old - t_old + 1
```

The new RSS subset size is:

```text
k_new = n_new - t_new + 1
```

Old subset shares are indexed by old subsets `I` of size `k_old`. New subset
shares are indexed by new subsets `J` of size `k_new`.

Before resharing, the secret is represented as:

```text
s = sum_I s_I^old
```

For every old subset `I`, the designated dealer `D_I` is the lowest-ID old
participant in `I`. The dealer computes sub-shares `r_{I->J}` for every new
subset `J`, such that:

```text
sum_J r_{I->J} = s_I^old
```

The new subset share is:

```text
s_J^new = sum_I r_{I->J}
```

The implementation uses a bounded conditional splitter, not an exact discrete
Gaussian sampler. Each coefficient is split evenly across new subsets and then
masked by deterministic zero-sum noise derived from the public session seed and
the old subset share. The noise (splitter `v5`, `add_mean_subtracted_noise`) uses
**balanced mean subtraction**: for each coefficient `m` i.i.d. deltas `δ_0..δ_{m−1}`
are drawn and `N_j = δ_j − balanced(Σδ)_j` is assigned to subset `j`. This is
integer zero-sum and reproduces the a-posteriori coset Gaussian's *uniform*
negative correlation `Cov(N_j,N_k) = −σ²/m` (the earlier `v4` telescoping cycle
`δ_i − δ_{i−1}` had only banded correlation, which overshot for non-contiguous
recovery patterns).

### Fresh re-sharing (noise intensity scaling)

The deltas are **sparse-ternary** in `{-1, 0, +1}` with per-coefficient intensity
`P(±1) ≈ 0.49 / S_old` each, where `S_old = C(n_old, n_old−T_old+1)` is the number
of old RSS subsets (`split_noise_threshold` in `protocol.rs`). The scaling is the
crux of the construction. Each new subset share is

```text
s_J^new = sum_I r_{I->J}
```

a sum over all `S_old` old subsets, so injecting only `≈ 1/S_old` of the keygen
noise per dealer makes the **aggregated** new-share noise variance reach the
keygen level `σ²_keygen`. The new shares are therefore distributed like a *fresh*
keygen short secret sharing — a discrete Gaussian over the sum-`s` coset, i.e.
Mithril's a-posteriori sharing (Sec. 3.3) reproduced in a distributed way. This
keeps the recovered signing partials under the keygen norm envelope `B` instead
of letting their variance grow linearly in the committee size.

The `v3` splitter used a **fixed** centered-binomial delta (`CBD_η`, independent of
`S_old`), which over-injected noise: the recovered-partial overshoot grew as
`~√S_old` (2-of-3: 1.22×, 3-of-5: 2.61×, 4-of-6: 4.50×). With the `1/S_old` scaling
*and* the v5 mean subtraction the steady-state overshoot is held at `~0.78–1.16×`
across all committees `2 ≤ T ≤ N ≤ 6` (Rust fixed-point measurement over repeated
reshares), while the aggregated hiding standard deviation stays `≈ σ_keygen = √2`.
Sparse-ternary at this small intensity is an integer,
PRF-deterministic stand-in for a coset discrete Gaussian (its `±2` Gaussian tail
is negligible), so every old-subset peer derives identical sub-shares.

## Threat Model

The protocol provides a committee handoff under the following assumptions.

1. Private Round 4 messages are sent over authenticated encryption.
2. Broadcast messages have integrity and are sender-authenticated.
3. Hash functions and domain-separated SHAKE invocations are modeled as random
   oracles, or at least collision/preimage resistant where used as commitments.
4. The adversary corrupts fewer than the relevant threshold in any single epoch.
5. Old share material is erased after a successful handoff when proactive
   security is desired.
6. The underlying Threshold ML-DSA signing proof applies to any accepted new
   sharing whose recovered signing partials satisfy the configured hyperball
   norm condition.

The protocol is abort-only. It detects invalid behavior and aborts, but it does
not provide blame attribution or identifiable aborts.

The protocol does not provide post-compromise forward secrecy. The session seed
is public after Round 2. If an attacker records the transcript and later obtains
old subset shares, it can recompute the deterministic sub-share split for those
old subset shares.

## Accepted-State Invariants

If an honest party accepts the resharing output, the implementation has checked
the following invariants.

1. All messages are bound to the same resharing SSID.
2. All Round 2 entropy reveals match Round 1 commitments.
3. Every old-subset peer that knows `s_I^old` and is not `D_I` recomputes all
   `r_{I->J}` commitments and rejects any mismatch before Round 4.
4. Every new recipient verifies every delivered `r_{I->J}` against the Round 3
   commitment.
5. Every delivered `r_{I->J}` has all coefficients within
   `SUBSHARE_COEFF_BOUND`.
6. Every new party enumerates all threshold signing sets containing itself,
   recovers the corresponding signing partial, and rejects if the configured
   challenge-amplified weighted norm bound is exceeded.
7. Members of each new subset `J` broadcast commitments to `s_J^new`; honest
   parties reject if members of the same `J` disagree.
8. Members of each new subset `J` broadcast partial public keys
   `t_J^new = A * s_{J,1}^new + s_{J,2}^new`; honest parties reject if members
   of the same `J` disagree.
9. The sum of canonical `t_J^new` values packs to the original public key.

## Honest Correctness

Assume all parties follow the protocol.

For each old subset `I`, the bounded splitter satisfies the exact integer
identity:

```text
sum_J r_{I->J} = centered(s_I^old)
```

Therefore it also satisfies the required identity modulo `Q`.

Summing over all new subsets:

```text
sum_J s_J^new
  = sum_J sum_I r_{I->J}
  = sum_I sum_J r_{I->J}
  = sum_I s_I^old
  = s
```

Thus the secret represented by the new RSS sharing is the same secret as before
resharing.

Because the public key relation is linear,

```text
sum_J (A * s_{J,1}^new + s_{J,2}^new)
  = A * sum_J s_{J,1}^new + sum_J s_{J,2}^new
  = A * s_1 + s_2
```

So the packed public key remains unchanged. Honest parties therefore pass the
Round 5 public-key invariant.

The bounded splitter keeps honest sub-shares small, and the recovered-partial
guard checks the exact signing partials that the signing implementation later
uses. Honest resharing passes this guard for the supported configurations in the
test suite.

## Dealer-Commitment Integrity

Fix an old subset `I` and its designated dealer `D_I`.

If there is an honest old party `P in I` with `P != D_I`, then `P` knows the same
old subset share `s_I^old` as the dealer. Since the session seed, old subset
mask, new subset order, and splitting algorithm are public and deterministic
given `s_I^old`, `P` can recompute every expected `r_{I->J}` and every expected
commitment:

```text
H("resharing-commit-v3" || I || J || r_{I->J})
```

Before Round 4, `P` compares these values with `D_I`'s Round 3 broadcast.

Therefore, except with commitment collision probability, a malicious `D_I` cannot
commit to any value different from the deterministic split for `s_I^old` when an
honest non-dealer peer exists in `I`. Any missing or mismatched commitment causes
abort before private sub-shares are sent.

If all members of `I` are corrupted, or if `I` is a singleton and its only member
is corrupted, there is no honest old peer who can enforce the deterministic
split for that `I`. In that case the protocol relies on the later checks:

1. new recipients verify Round 4 payloads against Round 3 commitments;
2. sub-share coefficients are bounded;
3. recovered signing partials must pass the hyperball guard;
4. the final public key must match the original public key.

This is exactly the remaining case the extra Round 5 checks are intended to
cover.

## Round 4 Payload Integrity

Each new recipient receives private messages containing `r_{I->J}` values. The
recipient recomputes the Round 3 commitment for each received value and rejects a
mismatch.

Assuming the commitment hash is collision resistant, all honest recipients who
accept a value for the same pair `(I, J)` accept the same value. A dealer cannot
send two different accepted sub-shares for the same `(I, J)` unless it finds a
hash collision.

Round 4 must be authenticated and encrypted. Authentication prevents an attacker
from injecting a value under another dealer's identity. Encryption prevents
eavesdroppers from learning sub-shares intended for other new parties.

## New-Subset Consistency

For every new subset `J`, all honest members of `J` receive the same accepted
`r_{I->J}` values for every old subset `I`, except with hash collision or
transport-authentication failure.

Thus every honest member of `J` computes the same:

```text
s_J^new = sum_I r_{I->J}
```

The Round 5 share commitment check enforces this. If members of `J` disagree,
honest parties abort.

For singleton new subsets, there is no peer to compare with. This is handled by
the public-key invariant and the recovered-partial guard.

## Public-Key Preservation For Accepted Outputs

Every new subset member broadcasts:

```text
t_J^new = A * s_{J,1}^new + s_{J,2}^new
```

For each `J`, honest parties select one canonical `t_J^new` after checking that
members of `J` agree. They then pack:

```text
sum_J t_J^new
```

and compare it byte-for-byte with the original public key.

Therefore, any accepted resharing preserves the verification key. A corrupted
old subset can only change the represented secret in a way that still maps to
the same public key, passes the sub-share coefficient bound, and passes the
recovered-partial norm guard. Finding a different short secret representation
for the same public key is an MLWE/SIS-type relation problem, and in any case
accepted outputs remain within the signing norm envelope checked by the guard.

## Recovered-Partial Norm Guard

The Threshold ML-DSA signing proof uses rejection sampling over hyperballs. Its
security analysis requires that each party's secret-dependent shift be small.

For a signing set `A` of size `t_new`, signer `i in A`, and recovered partial
secret:

```text
p_i(A) = (p_{i,1}(A), p_{i,2}(A))
```

the relevant weighted norm is:

```text
||p_i(A)||_nu = sqrt(||p_{i,1}(A)||_2^2 / nu^2 + ||p_{i,2}(A)||_2^2)
```

The implementation checks the challenge-amplified sufficient bound:

```text
sqrt(TAU) * ||p_i(A)||_nu <= B'
```

using the `sqrt(TAU)` amplification (matching the Gaussian-heuristic convention
that defines `B` in Mithril §3.4 / footnote 3), where `B'` is the configured
partial-secret norm bound for `(t_new, n_new)`.

**Assumption (√τ convention — explicit auditor sign-off).** The guard amplifies by
the *expected* challenge factor `√τ` (`E_c‖c·u‖₂ ≈ √τ·‖u‖₂` for a `SampleInBall`
challenge with `τ` nonzero `±1` coefficients), not the worst-case `‖c‖₁ = τ`. This
is deliberate: it is the same expected-norm convention used to *define* the keygen
bound `B` (Mithril §3.4 / footnote 3) and the one signing's own hyperball
rejection sampling is calibrated against, so the quantity the guard bounds and the
bound `B` it is compared to are expressed in identical units. Its soundness
therefore inherits from — and is **conditional on** — the Threshold ML-DSA proof
using this `√τ` expected-norm convention throughout its rejection-sampling
analysis (rather than a worst-case `τ` bound). We flag this as an explicit
dependency for the cryptographic auditor. It does not change the guard's
structure: a worst-case `τ` convention would simply re-scale `B`, `(r, r')` and the
per-config `κ` by the `√τ ≈ 7.75×` substitution (a larger bound that shrinks `Q_s`
accordingly), with the same acceptance test.

The check is deterministic and local to each new party. Each new party enumerates
all threshold signing sets containing itself and uses the same RSS recovery logic
as signing. Therefore, every later signing partial that this party can produce
has already passed the guard during resharing.

### Bound `B`, the enlargement `B' = κ·B`, and `Q_s`

The base bound `B` is the keygen-calibrated Mithril §3.4 quantity

```text
B = 1.3 · sqrt(TAU) · sqrt(n·(k + ℓ/ν²)) · sqrt(Var(U(−η,η))) · sqrt(⌈C(N, T−1)/T⌉),
```

the value the reference hyperball radii `(r, r')` are derived from
(`r = slack·B`, `r' = slackradius2·r`; see `scripts/compute_hyperball_params.py`,
where `B` is the script's `beta`).

Honest resharing inflates the recovered-partial norm relative to the keygen `B`
by a factor that depends on the splitter. With the **v5 mean-subtracted coset**
splitter (the `1/S_old` noise scaling above plus balanced mean subtraction) the
steady-state overshoot is `~0.78–1.16×` for every committee `2 ≤ T ≤ N ≤ 6`,
instead of the `~√S_old` growth (2-of-3: 1.22×, 3-of-5: 2.61×, 4-of-6: 4.50×) of
the old fixed-noise splitter.

To accept honest reshares the implementation enlarges the bound to `B' = κ·B`
*and* enlarges the hyperball radii to `(κ·r, κ·r')` for the same configuration
(`get_hyperball_params`).

**What the enlargement preserves, and what it costs.** The per-sample rejection
distribution is governed by `φ` through the radius condition
`r'² = r² + B² + 2rB/φ`, which is *scale-invariant*: scaling `(B, r, r')` by a
common `κ` leaves `φ` — and hence the per-sample leakage `ε` — exactly unchanged
(verified numerically: `(3,5)` `φ = 8.9931` before and after; `(4,6)`
`φ = 8.9762` before and after). So the simulated and real transcript
distributions stand in exactly the same relation *per sample* as in the unscaled
scheme.

The signing-query budget, however, is **not** preserved. By Theorem 3.2 the
budget is

```text
Q_s = 1 / (K · ε),
```

so it is inversely proportional to the parallel-attempt count `K`. Enlarging the
ball lowers per-iteration acceptance — because `κ·r` moves toward ML-DSA-87's
*fixed* verification ceilings (`‖z₁‖∞ < γ1 − β`, `‖v‖∞ ≤ γ2`, hint weight `≤ ω`),
and clearing all ~4000 nonce coordinates simultaneously is a high-dimensional
joint event that collapses super-linearly in the radius — so `K` grows. Because
`ε` is unchanged, that same `K` growth reduces `Q_s` by exactly the factor `K`
grows, i.e. the `Q_s` cost is `log₂(K_enlarged / K_base)` bits.

The `κ` were re-derived for the **v5 mean-subtracted coset splitter**
(`add_mean_subtracted_noise`) from the **measured** honest overshoot
(`sqrt(τ)·‖p‖_ν / B_base`; Rust `test_recovered_partial_variance_*`, fixed point
over all signing sets). v5's uniform negative correlation lowered every overshoot
vs the v4 telescoping cycle:

| Config | overshoot (v4 → v5) | κ | K (base → enlarged) | `Q_s` cost |
|--------|---------------------|---|---------------------|-----------|
| 2-of-2 | 0.975 → 0.780 | 1.00 | 4 → 4   | 0 (base params) |
| 2-of-3 | 0.897 → 0.810 | 1.00 | 5 → 5   | 0 (base params) |
| 2-of-4 | 1.018 → 0.961 | 1.10 | 7 → 10  | 0.51 bits |
| 3-of-5 | 1.107 → 1.012 | 1.15 | 35 → 60 | 0.78 bits |
| 4-of-6 | 1.286 → 1.163 | 1.25 | 350 → 1600 | ~2.2 bits (→ ~2^28.2) |

v5 pushes `(2,2)` and `(2,3)` far enough below the base bound that they reshare at
**κ = 1**: a reshared committee signs with the exact base params of a fresh keygen
committee, at *zero* `Q_s` cost. `(3,5)` drops `K` from 227 (v4) to 60. The cost
where κ > 1 is real and is *not* merely a completeness/`K` overhead — the `K`
overhead and the `Q_s` reduction are the **same** effect (each signing query
reveals all `K` aggregated responses, so the security game accumulates
`Q_s · K · ε` leakage, bounding `Q_s ≤ 1/(K·ε)`).

Note `B_base` itself (the keygen §3.4 quantity above) is **sampler-independent** —
it is the keygen reference, not re-derived from the resharing distribution. Only
`κ` (hence `B' = κ·B`, the radii, and `K`) depends on the splitter.

This enlargement is only possible while `κ·r` stays under ML-DSA-87's fixed
verification ceiling on `‖z₁‖∞ < γ1 − β`, which caps `κ` at ≈1.5×:

- `(2,2)`, `(2,3)`, `(2,4)`, `(3,5)`, `(4,6)` are **supported** (κ = 1.00 / 1.00 /
  1.10 / 1.15 / 1.25; `(2,2)`/`(2,3)` need no enlargement at all).
- `(4,6)` is **enabled** by enlargement (κ = 1.25, K = 1600) because the `near-mpc`
  integration requires the 4-of-6 committee shape. v5's honest overshoot is
  `~1.163×` and extremely stable (1.153–1.163 across 8 seeds, the recovered-partial
  norm concentrates), so κ = 1.25 carries a ~7.5% margin. The cost is a
  per-signature tax: every `(4,6)` signature uses `K = 1600` (~15 MB/session,
  `Q_s ≈ 2^28.2 ≈ 300M` queries). Reaching `κ = 1 / K = 350` for `(4,6)` (removing
  this tax) is future work: either budget the per-reshare noise intensity down for a
  bounded reshare count, or draw a single collaborative coset-Gaussian sample (one
  extra MPC round) for keygen-level hiding at `κ = 1`.

## Confidentiality

The public transcript consists of entropy commitments, entropy reveals, sub-share
commitments, new-share commitments, and partial public keys. No plaintext old or
new subset share appears on the public broadcast channel.

Round 3 commitments hide the committed sub-shares under the random-oracle or
preimage-resistance model. In honest executions, the committed values are derived
from high-entropy old subset shares and PRF output. In malicious executions,
revealing only a hash commitment does not reveal the committed value beyond what
is brute-forceable from its entropy.

Round 4 messages contain plaintext sub-shares and therefore require
authenticated encryption. Under that transport assumption, parties learn only the
sub-shares for new subsets they belong to.

Publishing `t_J^new = A * s_{J,1}^new + s_{J,2}^new` is treated as an MLWE sample.
Recovering `s_J^new` from `t_J^new` is as hard as the corresponding MLWE problem
for the accepted short-share distribution.

Thus resharing leaks no additional secret information beyond:

1. shares held by corrupted old parties before the handoff;
2. shares delivered to corrupted new parties after the handoff;
3. public MLWE samples and hash commitments.

This is the same leakage structure as the underlying RSS threshold scheme, plus
the public verification data needed to make the handoff verifiable.

## Key Hiding Under Resharing (Heuristic Parity)

This section addresses the gap between what the Threshold ML-DSA (Mithril) proof
formally requires of a share distribution and what the bounded conditional
splitter actually produces. The claim here is parity with base keygen hiding —
not a fresh closed-form MLWE reduction, but a parity that is now **measured**
(conditional covariance + a validated core-SVP estimate; see *Quantitative
confirmation*) rather than merely asserted.

### Leakage structure

Fix a single resharing epoch. An adversary corrupting at most `t_new - 1` new
parties learns at most `t_new - 1` of the new subset shares `{s_J^new}` (the new
RSS subset shares it is entitled to), the public transcript, and every per-subset
partial key `t_J^new`. Key hiding requires that the secret `s` (equivalently the
unseen subset shares) stays pseudorandom given this view, with the public key
`t = A*s_1 + s_2` fixed.

This is exactly the leakage structure that Mithril analyzes for key generation
and a-posteriori resharing (Mithril Sec. 3.3): the adversary's view is a
hint-MLWE instance, where the "hints" are the leaked subset shares (which are
correlated with the unseen shares through the `sum_J s_J^new = s` constraint and
the zero-sum splitting noise).

### Why this is heuristic, not a fresh reduction

Mithril's formal hint-MLWE -> MLWE reduction (Mithril Thm. for a-posteriori
sharing, App. E.3) requires each share coordinate to be discrete Gaussian with
standard deviation above the lattice smoothing parameter (sigma on the order of a
few thousand for these dimensions). That regime is incompatible with the small
secret-dependent shifts that signing's hyperball rejection sampling needs, so
Mithril does not instantiate the reduction at those parameters either. Instead it
falls back to a heuristic estimate (conditional entropy of the hidden share fed
to the lattice estimator, with a reported ~7-12 bit security loss versus plain
ML-DSA for its *a-posteriori* keygen). Resharing inherits the same wall — no
closed-form reduction — so the realistic target is the same lattice-estimator
methodology. Note this codebase's *keygen* shares are sampled **independently**
(`uniform_eta`, a priori), so its hidden keygen share is an independent `U(−2,2)`
with no a-posteriori loss; the *Quantitative confirmation* below shows resharing
preserves that (hidden-share hardness `≥` base ML-DSA-87), rather than merely
matching Mithril's a-posteriori heuristic.

### Distribution produced by the splitter

After the fresh re-sharing noise change (see `protocol.rs`), each new subset-share
coordinate is

```text
s_J^new[x] = sum_I ( balanced_split(s_I^old)[x]_J + N_{I,J} ),
  N_{I,J} = delta_{I,J} - balanced(sum_{J'} delta_{I,J'})_J
```

where the `delta_{I,J}` are independent sparse-ternary draws in `{-1, 0, +1}` with
intensity `P(±1) ≈ 0.49 / S_old`, and `N_{I,J}` is the integer zero-sum
mean-subtracted noise (`add_mean_subtracted_noise`) with the uniform negative
correlation `Cov(N_{I,J}, N_{I,J'}) = −σ²/m` for `J ≠ J'`. Two facts make the joint
distribution tractable:

1. Each coordinate is a sum over the `S_old = C(n_old, k_old)` old subsets of
   bounded, symmetric, independent terms, so by the central limit theorem each
   marginal is approximately a discrete Gaussian centered at the balanced-split
   mean. The `1/S_old` intensity scaling is chosen so that this aggregated marginal
   has standard deviation `≈ σ_keygen = √2` — i.e. the post-reshare share matches
   the *fresh keygen* share width rather than exceeding it (the small-σ sparse
   ternary is an integer stand-in for the coset discrete Gaussian of Mithril §3.3).
2. With (approximately) Gaussian noise the joint law of `(s_J^new)_J` is
   approximately a degenerate multivariate Gaussian, degenerate because the
   shares are constrained to sum to `s`. This is the same object Mithril's
   heuristic reasons about, which lets the conditional distribution of an unseen
   share given the leaked shares be described by a Gaussian conditional covariance
   rather than an ad hoc bounded distribution.

### Parity argument

Let `chi_s = U([-eta, eta])` be the base ML-DSA secret coordinate distribution,
with variance `Var(chi_s) = eta*(eta+1)/3` (sigma ~ 1.41 for eta=2). The base
scheme's hidden keygen subset share has coordinate variance `Var(chi_s)`.

1. Marginal width. The v5 coset splitter is tuned so the honest post-reshare
   hidden subset share has per-coordinate standard deviation `≈ σ_keygen` (measured
   aggregated hiding σ ≈ 1.37–1.43 across supported committees), matching the base
   keygen share rather than the old splitter's inflated `σ ≈ 3.6`. This is exactly
   the a-posteriori target of Mithril §3.3: the hidden share is distributed like a
   fresh keygen share, so its per-coordinate conditional entropy is on par with
   base keygen.
2. Correlation with leaked shares. Unlike independent keygen shares, the leaked
   `t_new - 1` shares are correlated with the hidden share via the sum constraint
   and the mean-subtracted noise. Because the joint law is approximately
   multivariate Gaussian, the residual uncertainty in the hidden share given the
   leaked shares is governed by the Schur-complement conditional covariance. The
   mean-subtracted noise gives the uniform negative correlation `−σ²/m` of the coset
   Gaussian, so no leaked share fixes the hidden share; the conditional covariance
   retains the structural balanced-split spread plus a non-degenerate noise
   contribution.
   This step is now **measured** rather than assumed (see *Quantitative
   confirmation* below): the per-coordinate conditional variance of the hidden share
   given the other `t_new − 1` shares is `≥` the base keygen value `Var(χ_s) = 2`
   for every supported `(t,n)`, so the hidden share carries at least as much
   conditional entropy as a fresh keygen share.
3. Published partial keys. Resharing additionally publishes `{t_J^new}`, which the
   base keygen does not. Each `t_J^new = A*s_{J,1}^new + s_{J,2}^new` is an MLWE
   sample for the post-reshare short-share distribution, and they sum to the fixed
   public key. Treating each as an MLWE sample, publishing them leaks nothing
   beyond MLWE hardness for that distribution. This is an extra assumption beyond
   base keygen, flagged in Limitations.

Combining the three points, the hint-MLWE instance an adversary faces after an
honest resharing is heuristically no easier than the one Mithril already accepts
for a-posteriori sharing: the hidden share is at least as wide (strictly wider for
`m_new ≥ 3`; within `0.4 %` of keygen width for `(2,2)` — both marginal and
conditional variance `≈ 1.992`, see *Quantitative confirmation*), the
Gaussian-shaped noise keeps the conditional covariance non-degenerate, and the only
genuinely new public data is a set of MLWE samples. Hence the lattice estimator
security level (and Mithril's reported heuristic loss) is expected to carry over.

### Repeated resharing

Each epoch republishes `{t_J^new}` and introduces a fresh hint. Under the
single-epoch bounded-corruption and erasure assumptions in the Threat Model, the
adversary's view in any one epoch is one hint-MLWE instance as above; it does not
accumulate hidden-share information across epochs because honest parties erase old
shares and the per-epoch noise is independently keyed to a fresh session seed.
There is no post-compromise forward secrecy: an adversary that records all
transcripts and later compromises old shares can recompute the deterministic
splits, exactly as stated in Limitations.

### Quantitative confirmation (measured)

The two supporting computations the parity argument depends on have been carried
out for every supported `(t,n)` (scripts `keyhiding_conditional.py` and
`keyhiding_estimator.py`).

**Reduction to one MLWE secret.** A `t_new − 1` coalition is the worst case for
hiding (maximal leakage). It learns all new subset shares except exactly one — the
hidden share `X_{J*}` indexed by the honest set `J* = ` complement of the coalition
(`|J*| = k_new`). Knowing the other `m_new − 1` shares and the public key `t`, the
coalition can subtract their contribution, leaving

```text
t' = t − Σ_{J≠J*}(A·s_{J,1} + s_{J,2}) = A·s_{J*,1} + s_{J*,2},
```

a single MLWE sample with secret the hidden share. The published per-subset key
`t_{J*}` equals this same `t'` (the `t_J` sum to `t`), so for the worst-case
coalition the published partial keys add **no** MLWE sample beyond base keygen.
Hence key hiding is exactly: is `X_{J*}`, given the other `m_new − 1` shares, at
least as hard an MLWE secret as base ML-DSA-87's `U(−2,2)`?

**(i) Conditional covariance.** Reproducing the exact v5 splitter
(`balanced_split_coeff` + `add_mean_subtracted_noise`, `1/S_old` intensity) per
coordinate and measuring the Schur-complement conditional variance of the hidden
share at the repeated-reshare fixed point (`keyhiding_conditional.py`, 4×10⁵
samples). Keygen samples subset shares i.i.d. `U(−2,2)`, so its hidden share is
independent with conditional variance `= Var(χ_s) = 2`; the variance-parity
criterion is that resharing match or exceed it (the security-relevant criterion —
core-SVP hardness — is analysed in (ii)):

| Config | keygen cond. var. | reshared cond. var. (fixed pt) | σ_cond |
|--------|-------------------|--------------------------------|--------|
| 2-of-2 | 2.00 | 1.992 | 1.411 |
| 2-of-3 | 2.00 | 2.14  | 1.464 |
| 2-of-4 | 2.00 | 2.24  | 1.496 |
| 3-of-5 | 2.00 | 2.50  | 1.582 |
| 4-of-6 | 2.00 | 2.48  | 1.575 |

The conditional variance is stable across `R = 1..20` reshares (no drift). Four of
the five configs are strictly wider than the keygen baseline (`> 2`); `(2,2)` is
the sole exception, sitting reproducibly just below it at `1.992`. This is **not**
Monte-Carlo noise: over 64 independent seeds (`N = 4·10⁵` each) the `(2,2)` fixed
point is `1.992 ± 0.004` (per-run std), with the keygen value `2.000` lying `+2.1`
per-run σ above the mean (`≈16` standard errors above the mean-of-means). It is a
genuine `~0.4 %` variance deficit — `σ_cond = √1.992 = 1.4114` vs the keygen
`√2 = 1.4142`, a `0.2 %` reduction in secret width. Crucially this sits **below the
resolution of the core-SVP estimator**: at `σ_cond = 1.411` the induced instance
still yields `β = 863` / classical `252`-bit / quantum `229`-bit, **identical** to
base ML-DSA-87 (see (ii)). So `(2,2)` misses *exact variance* parity by a
cryptographically negligible margin while retaining full *key-recovery-hardness*
parity, and the other four configs are strictly harder.

**(ii) Lattice estimate.** The induced key-recovery instance has the *identical*
module shape, modulus and sample count as base ML-DSA-87; only the secret/error
width changes from `√2` to `σ_cond`. The standard primal-uSVP core-SVP estimate
(`keyhiding_estimator.py`) — validated by reproducing Dilithium-5's published
key-recovery hardness exactly (β = 863, **classical 252-bit / quantum 229-bit**) —
gives:

| Config | σ_cond | BKZ β | classical core-SVP | vs base |
|--------|--------|-------|--------------------|---------|
| base ML-DSA-87 | 1.414 | 863 | 252 bits | — |
| 2-of-2 | 1.411 | 863 | 252 bits | +0.0 |
| 2-of-3 | 1.464 | 868 | 253 bits | +1.5 |
| 2-of-4 | 1.496 | 871 | 254 bits | +2.3 |
| 3-of-5 | 1.582 | 878 | 256 bits | +4.4 |
| 4-of-6 | 1.575 | 878 | 256 bits | +4.4 |

Core-SVP β is monotone non-decreasing in the secret/error width. The four configs
with `σ_cond > √2` are therefore key-recovery hardness strictly `≥` base ML-DSA-87
(a few bits *harder*). For `(2,2)`, `σ_cond = 1.411` is a hair *below* `√2 = 1.414`,
but the gap is below the estimator's integer-β resolution: it yields the same
`β = 863` and the same classical `252`-bit / quantum `229`-bit hardness as base. So
key-recovery hardness is `≥` base ML-DSA-87 (NIST Category 5) for every supported
config. The heuristic-parity claim is therefore confirmed quantitatively at the
security-relevant level: an honest resharing leaves the hidden share at least as
hard to recover as in base ML-DSA-87 — for `(2,2)` at parity, for the rest strictly
harder — even though `(2,2)` falls `0.4 %` short of exact *variance* parity.

**Residual caveats.** (a) The covariance is the exact second moment, but the
variance→core-SVP step uses the same Gaussian core-SVP model as ML-DSA's own
security claim; the hidden share is Gaussian by CLT over `m_new` subset
contributions, weakest at `m_new = 2` (`(2,2)`), where `σ_cond ≈ 1.411` — `0.2 %`
below `√2`, which the core-SVP estimate resolves as identical β / bit-security to
base (above).
(b) The analysis is per-coordinate i.i.d. (the splitter treats coordinates
independently), so the scalar result lifts to the full `256·(k+ℓ)` dimension.
(c) Smaller coalitions leak fewer shares (strictly easier to hide), so the
`t_new − 1` case bounds them.

## Proactive Security

Assume a mobile or snapshot adversary that corrupts fewer than the threshold in
each epoch, and assume old shares are erased after successful resharing.

Before resharing, fewer than `t_old` old shares are insufficient to sign or to
recover the represented secret under the Threshold ML-DSA security assumptions.

After resharing, old shares are no longer used by the signing protocol. The new
committee signs only with `s_J^new` shares. Fewer than `t_new` current shares are
insufficient to sign or recover the represented secret.

Therefore an attacker who temporarily obtained fewer than threshold old shares
must compromise the new epoch again. This is the standard proactive-security
benefit. It does not hold if the attacker keeps persistent control of enough
devices across epochs, or if old share material is not erased.

## Reduction To Threshold ML-DSA Signing Security

Consider an adversary that first interacts with resharing and then attempts to
forge a Threshold ML-DSA signature under the unchanged public key.

If resharing aborts, the adversary obtains no accepted new signing key.

If resharing succeeds, the accepted-state invariants imply:

1. all honest new parties agree on the subset shares they jointly hold;
2. the packed public key is unchanged;
3. delivered sub-shares are coefficient-bounded;
4. every recovered signing partial that an honest new party can later use passes
   the configured hyperball guard.

Now build a reduction that uses the successful resharing output as the key state
for the existing Threshold ML-DSA signing game. The signing transcript and
signature distribution are exactly those of the existing signing implementation
on an accepted key state. Since all recovered partials pass the guard, the
Mithril rejection-sampling hybrid can be applied with the configured bound for
accepted states.

Hence, for any adversary `A`, its advantage after accepted resharing is bounded
by the advantage of an adversary `B` against the underlying Threshold ML-DSA
scheme, plus the probability of breaking one of the resharing checks:

```text
Adv_reshare+sign(A)
  <= Adv_Threshold-ML-DSA(B)
   + Adv_hash_collision/preimage
   + Adv_AE
   + Adv_MLWE/SIS_for_public_verification_data
```

The recovered-partial guard contributes no statistical failure term in an
accepted execution, because it is checked deterministically. Honest resharing
passes the guard with the empirically tested margins documented in `README.md`.

## Honest Distribution Analysis

For honest resharing, each new subset share is a sum of bounded terms. Each
coefficient is therefore sub-Gaussian by standard bounded-difference bounds. For
large enough numbers of old subsets, the central limit theorem gives the observed
approximately Gaussian shape.

The README variance formula is an honest-execution parameter sanity check, not a
standalone security assumption. Malicious resharing is handled by verification:
old-subset peer commitment checks, per-subshare coefficient bounds,
recovered-partial norm checks, and public-key preservation.

## Limitations

The protocol does not provide identifiable aborts. Any verification failure
aborts the session without blaming a unique party.

The protocol does not provide post-compromise forward secrecy for old shares.
Recorded transcripts plus later compromise of old subset shares allow
recomputation of deterministic sub-shares for those old subset shares.

If an old subset is entirely corrupted, honest old-subset peer verification is
not available for that subset. Such deviations are constrained by recipient
commitment checks, coefficient bounds, recovered-partial norm checks, and public
key preservation.

The exact quantitative security reduction inherits the parameter-selection
requirements of the Threshold ML-DSA proof. If hyperball parameters or the guard
radius change, the guard must be checked against the corresponding proof bound.
