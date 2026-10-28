# Lattice reduction challenge for ML-DSA

This crate defines a time-boxed lattice-reduction challenge against the
ML-DSA (Dilithium) key-recovery lattice, and the verifier that scores it. It
is written so that a challenge host (e.g. Yukon) can run submissions and
publish verified scores without needing to trust the submitter or understand
lattice cryptography in depth.

The crate ships three things:

1. A deterministic **instance generator**: a public seed turns into a lattice
   problem shaped exactly like the one an attacker faces when trying to recover
   an ML-DSA secret key from a public key.
2. A **verifier** that, given an instance and a submitted result, decides
   whether the result is legitimate and computes its score.
3. A **harness** that runs a submitted algorithm for a fixed wall-clock budget
   and hands the output to the verifier. A reference BKZ implementation is
   included as an example submission; contestants are free to use any
   algorithm.

## Background in one page

ML-DSA is the NIST post-quantum signature standard. A public key is a matrix
`A` and a vector `t` with `t = A·s1 + s2 (mod q)`, where `s1, s2` are the
secret and have very small entries (between −2 and 2 for the parameter sets we
use). The prime modulus is `q = 8 380 417`. Recovering `(s1, s2)` from
`(A, t)` is the Module-LWE problem, and the best known attacks on it are
lattice reduction algorithms.

A **lattice** is the set of all integer combinations of a given list of
vectors (a **basis**). The same lattice has infinitely many bases. The
cryptanalytic task is to start from the obvious, terrible basis and transform
it into a basis made of short, nearly orthogonal vectors. In the key-recovery
lattice, the shortest vector *is* the secret key, so "find a short enough
basis" and "break the key" are the same task. Nobody can do this for the real
parameter sets; the open question is how close one can get with a given amount
of compute, which is what this challenge measures.

Lattice reduction algorithms (LLL, BKZ, sieving, and whatever contestants
invent) all share one interface: basis in, better basis of the same lattice
out. That is the abstraction this crate is built around.

## Instances

### Why the secret cannot be planted

A challenge host wants instances that nobody, including the host, has a
trapdoor for. We get that by deriving the instance from a public seed in the
Fiat–Shamir style: `A` is expanded from a hash of the seed using ML-DSA's own
`ExpandA` routine, and `t` is sampled uniformly at random from another hash of
the seed. Because `t` is uniform rather than computed from a secret, there is
no secret to leak. Under the Module-LWE assumption such an instance is
indistinguishable from a real public key's lattice, so an algorithm's
performance on it is representative of its performance on a real key. The one
difference is that there is no planted short vector to find, which is why the
score is based on the quality of the whole basis rather than on "did you find
the key".

### Parameters

An instance is identified by:

| field     | meaning                                                                 |
|-----------|-------------------------------------------------------------------------|
| `variant` | `ML-DSA-44`, `ML-DSA-65`, or `ML-DSA-87`. Fixes `q`, the ring dimension (256) and the matrix shape `k × l`. |
| `seed`    | 32 bytes, public. The host chooses it (e.g. a hash of the previous leaderboard entry). |
| `n`       | number of secret coordinates used (columns of `A`), `1 ≤ n ≤ 256·l`.    |
| `m`       | number of equations used (rows of `A`), `1 ≤ m ≤ 256·k`.                |

The lattice has dimension `d = n + m + 1`. With `n = 256·l` and `m = 256·k`
the instance is exactly the full key-recovery lattice of that parameter set
(`d = 2049` for ML-DSA-44). Smaller `n, m` give a ladder of easier instances
with identical structure, which is what a leaderboard will mostly live on. The
instance id is a hash of all four fields.

### Starting basis

Every run starts from the same canonical basis of the lattice

```
L = { (x, y, w) ∈ Z^n × Z^m × Z : y ≡ x·Aᵀ + w·b (mod q) }
```

written as rows

```
[ 0    q·I_m   0 ]      m rows
[ I_n  Aᵀ      0 ]      n rows
[ 0    bᵀ      1 ]      1 row
```

where `b = t1 · 2¹³` mirrors the public-key encoding of `t`. For a real key
the vector `(s1, t0 − s2, −1)` lies in this lattice and is far shorter than
anything else, which is what makes the embedding an attack. The construction
is tested against real ML-DSA keypairs for all three parameter sets.

## Scoring

The verifier scores a basis `B` by its **log-potential**

```
P(B) = Σ_{i=1..d} (d − i) · ln ‖b*_i‖
```

where `b*_1, …, b*_d` are the Gram–Schmidt vectors of `B` (each basis vector
with its components along the previous ones removed). The reported score is
the improvement over the starting basis, in bits:

```
score(B) = (P(B₀) − P(B)) / ln 2
```

Why this metric:

- **It uses the whole basis.** The product of all Gram–Schmidt lengths is the
  lattice volume, which no algorithm can change; reduction can only move
  length from the front of the basis to the back. The decreasing weights
  `(d − i)` make that movement visible. The first vector contributes a weight
  of `d` out of a total of roughly `d²/2`, so one lucky short vector cannot
  dominate. A single-vector metric such as the Hermite factor would.
- **It tracks reduction.** Every LLL swap strictly decreases it (that is the
  classical argument that LLL terminates). A BKZ block insertion lowers the
  front of its block but only leaves the rest of the block LLL-reduced, so a
  single tour can give back a few bits; over a run the score climbs steadily,
  which the tests check.
- **It is model-free.** It is defined for any basis, including the very uneven
  starting one, without assuming the basis profile has a particular shape.
- **It is computed by the verifier**, from the submitted basis, never
  self-reported.

Orthogonality is not scored directly: the parts of a basis vector that point
along earlier vectors ("size reduction") can be removed cheaply by anyone
after the fact and do not change the Gram–Schmidt lengths. The secondary,
human-facing metrics in the report (length of the first vector relative to
the Gaussian heuristic, shortest row, slope of the log-profile) are therefore
chosen so that they do not depend on it either, or are labelled as taken
from the basis as submitted.

## Verification criteria

Given an instance and a submitted square integer matrix `B` with `d` rows, the
verifier accepts iff all of the following hold:

1. **Well-formed.** `B` is `d × d` and every entry has magnitude below `2⁴⁰`.
   The starting basis has entries of size `q ≈ 2²³`; the bound exists only to
   keep the arithmetic below exact and is far above anything a reduction
   algorithm produces.
2. **Every row lies in the lattice.** For a row `(x, y, w)` this is the
   congruence `y ≡ x·Aᵀ + w·b (mod q)`, checked exactly with integers. No
   matrix inversion is needed because the lattice is defined by that
   congruence.
3. **Same volume.** Rows in the lattice can still span a *sub*lattice (for
   example if a row is doubled, or a row is replaced by a combination of the
   others). A sublattice has volume `k · qᵐ` for an integer `k ≥ 2`, i.e. its
   log-volume differs from the expected `m · ln q` by at least `ln 2`. The
   verifier computes the log-volume as `Σ ln ‖b*_i‖` and requires it to be
   within `0.25` of `m · ln q`. Combined with (2), this proves `B` generates
   exactly the original lattice.
4. **Numerically trustworthy.** The Gram–Schmidt lengths behind (3) and the
   score are computed from the exact integer Gram matrix in double-double
   arithmetic (about 32 significant digits). If a pivot comes out
   non-positive or tiny relative to its row, the basis is rejected as
   "unverifiable" rather than scored. Any honest reduced basis passes; this
   only triggers on inputs engineered to defeat floating point.

If accepted, the verifier returns the score plus the secondary metrics.

## Time rules

The harness owns the clock. A submission implements:

```rust
pub trait Reducer: Send {
	fn name(&self) -> String;
	/// Perform one unit of work on `basis`, in place. Should return promptly
	/// once `ctx.should_stop()` is true.
	fn step(&mut self, basis: &mut Basis, ctx: &StepContext) -> Step; // Continue | Done
}
```

and the harness:

1. Builds the starting basis and records `P(B₀)`.
2. Calls `step` repeatedly. After each call that returns **before the
   deadline**, it snapshots the basis. A call that returns after the deadline
   does not count; the previous snapshot is used. `ctx.should_stop()` turns
   true a small margin before the deadline (`Budget::soft_margin`, default
   50 ms plus 0.5 % of the budget) so that a reducer which stops when asked
   returns inside the window.
3. If a call has not returned by `deadline + grace`, a watchdog ends the run
   on the previous snapshot.
4. A reducer may return `Done` to end the run early (e.g. it has converged).
   An external cancel flag is also honoured, for operators who want to stop a
   run by hand.
5. The final snapshot goes through the verifier. The report records the
   instance id, the reducer name, the budget, a per-step trace of elapsed time
   and (optionally) fast approximate score, how the run terminated
   (`Deadline`, `Overrun`, `Watchdog`, `Done`, `Cancelled`, `MaxSteps`,
   `ReducerPanicked`), the verified score or the rejection reason, and the
   final basis so that anyone can re-run the verifier on it offline.

Contestants therefore cannot gain by ignoring the deadline, and the host does
not need to inspect their code to measure time. Multithreading inside a step
is allowed; the budget is wall-clock.

## Reference reducer

`ProgressiveBkz` is included as a worked example of the trait: LLL to start,
then BKZ tours with Schnorr–Euchner enumeration as the SVP oracle, inserting
the vector found by LLL-reducing the block with it as an extra row, and
increasing the block size every couple of tours or as soon as a tour stalls.
One step is one tour.
It checks the deadline between blocks and every 2¹⁶ enumeration nodes, so it
stops within milliseconds of the budget. It is a baseline, not a target: a
serious entry would use sieving, pruned enumeration, or something new. `Lll`
on its own is also provided as the simplest possible `Reducer`.

## Usage

```rust
use std::time::Duration;
use qp_rusty_crystals_lattice_attack::{
	harness::{run, Budget, StderrObserver},
	reducers::ProgressiveBkz,
	verify::verify,
	Instance, Variant,
};

let instance = Instance::generate(Variant::MlDsa44, [7u8; 32], 60, 60)?;
let report = run(
	&instance,
	ProgressiveBkz::new(10, 60),
	&Budget::new(Duration::from_secs(30)),
	&mut StderrObserver,
);
println!("{:?}", report.score_bits());

// Anyone holding the instance parameters and the basis can re-check it:
let again = verify(&instance, report.basis.as_ref().unwrap())?;
assert_eq!(again.score_bits, report.score_bits().unwrap());
```

The same flow from the command line, including offline re-verification of a
saved report:

```sh
cargo run --release -p qp-rusty-crystals-lattice-attack --example bkz_demo -- \
    --variant 44 --seed 07 --n 60 --m 60 --secs 30 --report report.json --events events.jsonl
cargo run --release -p qp-rusty-crystals-lattice-attack --example bkz_demo -- --verify report.json
```

Costs to plan around: verification is `O(d³)` in double-double arithmetic,
which is instant below `d ≈ 300` and tens of seconds at the full ML-DSA-44
dimension (`d = 2049`); the per-step `f64` trace is also `O(d³)` and should
be disabled (`Budget::trace = false`) for large instances. The reference
reducers recompute Gram–Schmidt rows on change and are not tuned; they are
fine up to a few hundred dimensions.

## What this crate does not do

- No leaderboard, web service, or submission intake. The host provides those.
- No sandboxing of contestant code. The harness measures time and verifies
  output; isolating untrusted code is the host's job.
- No checkpoint/resume or Ctrl-C handling. Runs are bounded by the budget.
- No attempt to be fast enough to threaten real parameters. Full-size
  instances are supported and verified, but the reference reducer is a
  baseline only.

## Layout

| module            | contents                                                      |
|-------------------|---------------------------------------------------------------|
| `instance`        | `Variant`, `Instance`, Fiat–Shamir generation, real-key import, starting basis |
| `basis`           | `Basis` (rows of `i64`) and serialization                     |
| `dd`              | double-double arithmetic for the verifier                     |
| `gso`             | Gram–Schmidt: fast `f64` (for reducers and traces) and double-double from the exact Gram matrix (for the verifier) |
| `verify`          | membership, volume, score, secondary metrics                  |
| `harness`         | `Reducer`, `StepContext`, `Budget`, `Observer`, `Report`, `run` |
| `reducers::workspace` | integer rows plus incrementally maintained `f64` Gram–Schmidt data |
| `reducers::lll`   | floating-point LLL and the `Lll` reducer                      |
| `reducers::bkz`   | enumeration, unimodular insertion, tours, `ProgressiveBkz`    |
| `examples/bkz_demo` | runs the reference reducer on a seeded instance, writes a report, re-verifies one |
| `tests/full_size` | opt-in (`--ignored`) checks at the full ML-DSA-44 dimension   |

## Tests as proof of the criteria

- Generation is deterministic in the seed and different across seeds.
- The starting basis built from a real ML-DSA-44/65/87 keypair contains the
  secret vector `(s1, t0 − s2, −1)`, confirming the embedding matches the
  real scheme (including the NTT-domain convention of `ExpandA`).
- The verifier accepts the starting basis with score 0, accepts row
  permutations and any LLL/BKZ output, and rejects: a scaled row, a row
  replaced by a combination of others, a basis for a different seed, wrong
  dimensions, and oversized entries.
- Enumeration matches brute force on small lattices; LLL output satisfies the
  LLL conditions.
- On a fixed small instance the score is non-decreasing across BKZ steps and a
  larger budget never scores lower.
- A reducer that overruns the deadline is scored on its last in-time
  snapshot; a reducer that never returns is terminated by the watchdog; a
  reducer returning `Done` ends the run early; a reducer that panics or
  returns a non-lattice basis forfeits (scored on the last good snapshot, or
  rejected).
- An ignored (opt-in) test exercises the full ML-DSA-44 dimension end to end:
  `cargo test --release -p qp-rusty-crystals-lattice-attack --test full_size -- --ignored`.
