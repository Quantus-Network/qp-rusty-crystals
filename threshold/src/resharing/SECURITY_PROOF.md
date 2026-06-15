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
the old subset share. The noise uses an `O(m)` telescoping cycle: for each
coefficient one centered-binomial delta `delta_i` is drawn per new subset and the
difference `delta_i - delta_{(i-1) mod m}` is assigned to subset `i`. The
centered binomial distribution (CBD, as used by ML-KEM) is the standard bounded
approximation to a discrete Gaussian; it makes the joint law of the new subset
shares approximately a (degenerate, sum-preserving) multivariate Gaussian, which
is what the key-hiding argument below relies on.

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

The implementation checks the conservative challenge-amplified sufficient bound:

```text
TAU * ||p_i(A)||_nu <= R_guard
```

where `R_guard` is the configured guard radius derived from the current
Threshold ML-DSA-87 hyperball parameters for `(t_new, n_new)`.

The check is deterministic and local to each new party. Each new party enumerates
all threshold signing sets containing itself and uses the same RSS recovery logic
as signing. Therefore, every later signing partial that this party can produce
has already passed the guard during resharing.

For a paper-style instantiation against the exact Mithril theorem, instantiate
`R_guard` with a bound `B` satisfying the hyperball parameter-selection condition
from the Threshold ML-DSA proof. Operationally, the implementation rejects any
resharing output that exceeds its configured guard for the existing parameters;
it does not enlarge or retune hyperball parameters during resharing.

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
splitter actually produces. The claim here is heuristic parity with Mithril's own
a-posteriori sharing, not a fresh MLWE reduction.

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
ML-DSA). Resharing inherits the same wall, so the realistic target is parity with
Mithril's heuristic, not a stronger statement.

### Distribution produced by the splitter

After the CBD noise change (see `protocol.rs`), each new subset-share coordinate
is

```text
s_J^new[x] = sum_I ( balanced_split(s_I^old)[x] + (delta_{I,J} - delta_{I,J-1}) )
```

where the `delta` are independent CBD_eta draws (symmetric, sub-Gaussian,
variance `eta/2`). Two facts make the joint distribution tractable:

1. Each coordinate is a sum over the `C(n_old, k_old)` old subsets of bounded,
   symmetric, independent terms, so by the central limit theorem each marginal is
   approximately a discrete Gaussian centered at the balanced-split mean. This
   matches the empirically observed shape in `README.md`.
2. With (approximately) Gaussian noise the joint law of `(s_J^new)_J` is
   approximately a degenerate multivariate Gaussian, degenerate because the
   shares are constrained to sum to `s`. This is the same object Mithril's
   heuristic reasons about, which is why the CBD shaping (rather than uniform
   noise) matters: it lets the conditional distribution of an unseen share given
   the leaked shares be described by a Gaussian conditional covariance instead of
   an ad hoc bounded distribution.

### Parity argument

Let `chi_s = U([-eta, eta])` be the base ML-DSA secret coordinate distribution,
with variance `Var(chi_s) = eta*(eta+1)/3` (sigma ~ 1.41 for eta=2). The base
scheme's hidden keygen subset share has coordinate variance `Var(chi_s)`.

1. Marginal width. The honest post-reshare hidden subset share has per-coordinate
   standard deviation at least that of the base keygen share, and empirically
   strictly larger (sigma >= ~3.6 even for the smallest 2-of-3 configuration; see
   `README.md`). A wider symmetric marginal has at least as much per-coordinate
   conditional entropy, so on the marginal axis resharing is no worse than base
   keygen.
2. Correlation with leaked shares. Unlike independent keygen shares, the leaked
   `t_new - 1` shares are correlated with the hidden share via the sum constraint
   and the telescoping noise. Because the joint law is approximately multivariate
   Gaussian, the residual uncertainty in the hidden share given the leaked shares
   is governed by the Schur-complement conditional covariance. The telescoping
   cycle gives each subset exactly two noise terms (variance `O(1)` in `m`) and
   spreads them around a cycle, so no leaked share fixes the hidden share; the
   conditional covariance retains the structural balanced-split spread plus a
   non-degenerate noise contribution. We therefore claim the conditional entropy
   of the hidden share is at least that of the base scheme's hidden keygen share.
   This is the step that should be confirmed numerically by feeding the actual
   conditional covariance into the lattice estimator (see Open Items).
3. Published partial keys. Resharing additionally publishes `{t_J^new}`, which the
   base keygen does not. Each `t_J^new = A*s_{J,1}^new + s_{J,2}^new` is an MLWE
   sample for the post-reshare short-share distribution, and they sum to the fixed
   public key. Treating each as an MLWE sample, publishing them leaks nothing
   beyond MLWE hardness for that distribution. This is an extra assumption beyond
   base keygen, flagged in Limitations.

Combining the three points, the hint-MLWE instance an adversary faces after an
honest resharing is heuristically no easier than the one Mithril already accepts
for a-posteriori sharing: the hidden share is at least as wide marginally, the
Gaussian-shaped noise keeps the conditional covariance non-degenerate, and the
only genuinely new public data is a set of MLWE samples. Hence the lattice
estimator security level (and Mithril's reported heuristic loss) is expected to
carry over.

### Repeated resharing

Each epoch republishes `{t_J^new}` and introduces a fresh hint. Under the
single-epoch bounded-corruption and erasure assumptions in the Threat Model, the
adversary's view in any one epoch is one hint-MLWE instance as above; it does not
accumulate hidden-share information across epochs because honest parties erase old
shares and the per-epoch noise is independently keyed to a fresh session seed.
There is no post-compromise forward secrecy: an adversary that records all
transcripts and later compromises old shares can recompute the deterministic
splits, exactly as stated in Limitations.

### Open items

This argument is heuristic parity, not a proof. The supporting work needed to make
it quantitative is: (i) compute the exact conditional covariance of one hidden
subset share given any `t_new - 1` leaked shares for each supported `(t,n)`, and
(ii) run the lattice estimator on the induced hint-MLWE instance to confirm the
security level matches Mithril's a-posteriori heuristic within its stated loss.
Items (i)-(ii) are configuration-specific and are tracked separately from this
note.

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
