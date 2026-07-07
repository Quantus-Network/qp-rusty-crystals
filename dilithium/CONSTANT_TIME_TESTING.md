# Constant-Time Testing for qp-rusty-crystals-dilithium

This project uses [dudect-bencher](https://github.com/rozbb/dudect-bencher) to test that the
secret-dependent components of the ML-DSA-87 implementation execute in constant time.

## Quick Start

```bash
cargo run --release -p qp-rusty-crystals-dilithium --example ct_bench
```

Run a single test (with continuous sampling until interrupted):

```bash
cargo run --release -p qp-rusty-crystals-dilithium --example ct_bench -- --continuous sign_norm_check
```

## What we measure — and what we deliberately do not

This is the important part, and it is where a naive test setup goes wrong.

ML-DSA signing is **Fiat-Shamir with aborts**: the signer retries (on average ~4 times for
ML-DSA-87) until a candidate signature passes four rejection checks. The *number of attempts*
is independent of the long-term secret key and is treated as **public information** in the
FIPS 204 security analysis — every mainstream implementation (reference C, PQClean, AWS-LC)
uses a plain early-exit rejection loop. End-to-end signing time therefore varies from call to
call *by design*.

Consequence: timing the whole `sign()` call with dudect (fixed key vs. random key, or fixed
message vs. random message) produces a large t-statistic that looks like a leak but is not —
dudect is simply detecting the public abort count. The same applies to whole
`Keypair::generate()` calls: expanding the matrix A uses rejection sampling on `rho`, and
`rho` is published in the public key.

What must NOT depend on secrets is the work done **inside** each attempt and around it.
The harness (`examples/ct_bench.rs`) therefore isolates each secret-consuming component and
compares a fixed secret input (Class Left) against fresh random secret inputs (Class Right):

| Test                   | Component under test                                        |
|------------------------|-------------------------------------------------------------|
| `keygen_s1s2_sampling` | Sampling secret vectors s1/s2 from rho' (keygen)            |
| `rej_eta_one_block`    | Raw eta rejection sampler over one SHAKE block              |
| `sign_sk_expansion`    | Secret-key unpack + NTT of s1/s2/t0 (per-sign setup)        |
| `sign_mask_expansion`  | Mask vector y expansion from rho' (ExpandMask)              |
| `sign_norm_check`      | Infinity-norm rejection check on z = y + c·s1               |
| `sign_make_hint`       | Hint computation from secret-derived w0/w1                  |
| `ntt_pointwise`        | NTT + pointwise multiplication on secret operands           |

Deliberately excluded:

- **Whole `sign()` / keygen calls** — timing varies with public information (abort count,
  `rho`), see above.
- **`poly::challenge()`** — variable-time by design. Its input `c~ = H(mu, w1)` is a hash
  output: published in the signature for accepted attempts, and unexploitable (a preimage
  of an unpublished hash) for rejected ones. No secret-key material flows into it.
- **`packing::pack_sig()`** — only called for the accepted attempt, so its inputs are
  exactly the published signature bytes. (The hint loop is branchless anyway as
  defense-in-depth, but its hint-weight-dependent store footprint is not a secret channel.)
- **`verify()`** — operates exclusively on public data.

## Understanding Results

Each test prints a line like:

```
bench sign_norm_check ... : n == +0.149M, max t = +1.53271, max tau = +0.00397, (5/tau)^2 = 1587037
```

- **n**: number of measurements used (in millions, after outlier trimming)
- **max t**: worst Welch t-statistic over all measurement crops
- **max tau**: t normalized by sqrt(n) — comparable across sample sizes
- **(5/tau)²**: roughly how many measurements would be needed to confirm a leak

Interpretation:

- **|max t| < 5**: no timing leakage detected — pass
- **|max t| ≥ 5**: potential leak — re-run several times on an idle machine; a real leak
  reproduces and its |max t| *grows* with more samples, noise does not

## Best Practices

- Always run with `--release`.
- Run on an idle machine; close other applications.
- On laptops, pin the CPU governor / disable turbo if results are noisy:

```bash
# Linux
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

- Re-run marginal results several times before drawing conclusions. dudect maximizes t over
  many crops of the data, so |max t| in the 2–4 range is common for perfectly constant-time
  code.

## Implementation notes

The constant-time strategy of the library itself:

- All secret-dependent arithmetic (Keccak, NTT, Montgomery/Barrett-style reductions,
  pack/unpack of secret polynomials) is branchless with data-independent memory access.
- The norm checks (`poly::check_norm`) scan every coefficient with a bitwise-OR accumulator —
  no early exit, since the index of the first failing coefficient of z = y + c·s1 is
  secret-derived.
- `rej_eta` processes every input byte and stores accepted coefficients through a masked,
  clamped (`min`, compiles to conditional move) index — no secret-dependent division
  (KyberSlash class) and no early exit.
- `rounding::make_hint` and the hint loop in `packing::pack_sig` are branchless, because
  hints of *rejected* attempts are never published.
- The rejection loop itself exits as soon as an attempt is accepted. The abort count is
  public (see above), so no batching or dummy work is performed to disguise it.

## Security Implications

This implementation is described as "reasonably constant-time":

- Timing reveals only information that is public under the FIPS 204 security analysis
  (abort count, message length, `rho`).
- All operations on secret-key material are constant-time to the extent the compiler
  preserves the branchless constructs used (standard caveat for any Rust/C implementation).

Anyone wishing to fully protect against side-channel attacks (including power/EM and
microarchitectural attacks) should evaluate on their specific hardware against their
specific threat model.

## Further Reading

- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [dudect: dude, is my code constant time?](https://github.com/oreparaz/dudect)
- [KyberSlash: division timing attacks on Kyber implementations](https://kyberslash.cr.yp.to/)
- [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://www.paulkocher.com/doc/TimingAttacks.pdf)
