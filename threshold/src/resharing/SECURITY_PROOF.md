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

The implementation uses a bounded conditional splitter, not a discrete Gaussian
sampler. Each coefficient is split evenly across new subsets and then masked by
deterministic pairwise zero-sum `[-eta, eta]` noise derived from the public
session seed and the old subset share.

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
