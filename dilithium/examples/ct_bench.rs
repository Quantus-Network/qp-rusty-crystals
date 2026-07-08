//! dudect-based constant-time tests for the ML-DSA-87 implementation.
//!
//! Run with:
//!
//! ```bash
//! cargo run --release -p qp-rusty-crystals-dilithium --example ct_bench
//! ```
//!
//! # What we measure — and what we deliberately do not
//!
//! ML-DSA signing is "Fiat-Shamir with aborts": it retries until a candidate signature
//! passes four rejection checks. The *number of attempts* is independent of the long-term
//! secret key and is treated as public information in the FIPS 204 security analysis, so
//! end-to-end signing time is *expected* to vary from call to call. Timing the whole
//! `sign()` call with dudect therefore produces a meaningless "leak" signal: the variance
//! it detects is the public abort count, not the secret key.
//!
//! What must NOT depend on secrets is the work done *inside* each attempt and around it.
//! So each test below isolates one secret-consuming component and compares a fixed secret
//! input (Class Left) against fresh random secret inputs (Class Right):
//!
//! - `keygen_s1s2_sampling`     — sampling the secret vectors s1/s2 from rho' (keygen)
//! - `rej_eta_one_block`        — the raw eta rejection-sampler over one SHAKE block
//! - `sign_sk_expansion`        — unpacking the secret key and NTT-transforming s1/s2/t0
//! - `sign_mask_expansion`      — expanding the secret mask vector y from rho'
//! - `sign_norm_check`          — the infinity-norm rejection check on z = y + c*s1
//! - `sign_make_hint`           — hint computation from secret-derived w0/w1
//! - `ntt_pointwise`            — core polynomial arithmetic on secret operands
//!
//! Intentionally not tested:
//!
//! - whole `sign()` / `Keypair::generate()` calls (their duration varies with public values: the
//!   abort count and rho, which is published in the public key)
//! - `poly::challenge()` (variable-time by design; its input c~ = H(mu, w1) is a hash output that
//!   is published for accepted attempts and unexploitable for rejected ones)
//! - `packing::pack_sig()` (only called for the accepted attempt, so its inputs are exactly the
//!   published signature bytes; the hint loop is branchless anyway as defense-in-depth, but its
//!   weight-dependent store pattern is not a secret channel)
//! - `verify()` (operates exclusively on public data)
//!
//! # Harness design notes
//!
//! To avoid measuring artifacts of the harness itself, both classes perform *identical*
//! preparation before every timed sample: a fresh random input is always generated into a
//! scratch buffer, and then either the fixed input (Left) or the scratch input (Right) is
//! copied into a single reusable working buffer. This keeps RNG work, copy work and cache
//! state of the working buffer the same for both classes; only the *values* differ.
//! Sub-microsecond operations are batched inside the timed closure so each measurement is
//! several microseconds long (the macOS/Apple-Silicon monotonic timer ticks at ~41 ns).
//!
//! # Interpreting results
//!
//! For each test dudect reports a t-statistic; |max t| < 5 is the usual "no leakage
//! detected" threshold. dudect maximizes t over many crops of the data, so values in the
//! 2-4 range are common for perfectly constant-time code. A real leak reproduces across
//! runs and its |max t| grows with more samples.

use core::hint::black_box;
use dudect_bencher::{
	ctbench_main,
	rand::{Rng, RngExt},
	BenchRng, Class, CtRunner,
};

use qp_rusty_crystals_dilithium::{
	ml_dsa_87::Keypair,
	packing, params, poly,
	poly::Poly,
	polyvec,
	polyvec::{Polyveck, Polyvecl},
};

const L: usize = params::L;
const Q: i32 = params::Q;

/// Pick a class uniformly at random so Left/Right samples are interleaved.
fn random_class(rng: &mut BenchRng) -> (bool, Class) {
	let is_left = rng.random::<bool>();
	(is_left, if is_left { Class::Left } else { Class::Right })
}

/// Fill a Poly with uniform coefficients in [-bound, bound].
fn fill_poly(p: &mut Poly, bound: i32, rng: &mut BenchRng) {
	for c in p.coeffs.iter_mut() {
		*c = rng.random_range(-bound..=bound);
	}
}

/// Fill a Polyvecl with uniform coefficients in [-bound, bound].
fn fill_polyvecl(v: &mut Polyvecl, bound: i32, rng: &mut BenchRng) {
	for p in v.vec.iter_mut() {
		fill_poly(p, bound, rng);
	}
}

/// Fill a Polyveck with uniform coefficients in [-bound, bound].
fn fill_polyveck(v: &mut Polyveck, bound: i32, rng: &mut BenchRng) {
	for p in v.vec.iter_mut() {
		fill_poly(p, bound, rng);
	}
}

/// Plain coefficient copy (no allocation, no zeroize-on-drop of the destination).
fn copy_polyvecl(dst: &mut Polyvecl, src: &Polyvecl) {
	for (d, s) in dst.vec.iter_mut().zip(src.vec.iter()) {
		d.coeffs = s.coeffs;
	}
}

/// Plain coefficient copy (no allocation, no zeroize-on-drop of the destination).
fn copy_polyveck(dst: &mut Polyveck, src: &Polyveck) {
	for (d, s) in dst.vec.iter_mut().zip(src.vec.iter()) {
		d.coeffs = s.coeffs;
	}
}

/// Keygen: sampling the secret vectors s1 (length L) and s2 (length K) from rho'.
///
/// This is the secret-dependent part of key generation. (Matrix expansion from rho is
/// public and excluded.) Fixed vs random rho' seed.
fn keygen_s1s2_sampling(runner: &mut CtRunner, rng: &mut BenchRng) {
	const SAMPLES: usize = 100_000;
	let mut fixed = [0u8; params::CRHBYTES];
	rng.fill_bytes(&mut fixed);
	let mut scratch = [0u8; params::CRHBYTES];
	let mut seed = [0u8; params::CRHBYTES];

	for _ in 0..SAMPLES {
		let (is_left, class) = random_class(rng);
		// Identical prep for both classes: RNG fill, then memcpy.
		rng.fill_bytes(&mut scratch);
		seed.copy_from_slice(if is_left { &fixed } else { &scratch });
		runner.run_one(class, || {
			let mut s1 = Polyvecl::default();
			let mut s2 = Polyveck::default();
			polyvec::l_uniform_eta(&mut s1, black_box(&seed), 0);
			polyvec::k_uniform_eta(&mut s2, black_box(&seed), L as u16);
			black_box((&s1, &s2));
		});
	}
}

/// The raw eta rejection sampler over a single SHAKE256 block.
///
/// Called exactly as `uniform_eta` calls it in production: a 1000-slot output buffer, so
/// the counter never saturates the index clamp. (Benching with a tight 256-slot buffer
/// instead makes the clamp pin the store index to the last slot for the tail of the block,
/// and the resulting same-address read-modify-write chain shows up as a large timing
/// signal that production never exhibits.) Fixed vs random block.
fn rej_eta_one_block(runner: &mut CtRunner, rng: &mut BenchRng) {
	const SAMPLES: usize = 300_000;
	const BATCH: usize = 8;

	let mut fixed = [0u8; 136];
	rng.fill_bytes(&mut fixed);
	let mut scratch = [0u8; 136];
	let mut block = [0u8; 136];

	for _ in 0..SAMPLES {
		let (is_left, class) = random_class(rng);
		rng.fill_bytes(&mut scratch);
		block.copy_from_slice(if is_left { &fixed } else { &scratch });
		runner.run_one(class, || {
			for _ in 0..BATCH {
				// Same shape as the call in `uniform_eta`.
				let mut out = [0i32; 1000];
				let accepted = poly::rej_eta(&mut out, black_box(&block));
				black_box((accepted, &out));
			}
		});
	}
}

/// Signing: unpacking the packed secret key and NTT-transforming s1, s2 and t0.
///
/// This is the per-call secret-key setup phase of `sign()`. Fixed key vs random keys
/// (drawn from a pregenerated pool; per-sample keygen would dominate the harness).
fn sign_sk_expansion(runner: &mut CtRunner, rng: &mut BenchRng) {
	const SAMPLES: usize = 50_000;

	let gen_sk = |rng: &mut BenchRng| -> [u8; params::SECRETKEYBYTES] {
		let mut entropy = [0u8; 32];
		rng.fill_bytes(&mut entropy);
		let keypair = Keypair::generate((&mut entropy).into());
		keypair.secret.to_bytes()
	};

	let fixed = gen_sk(rng);
	let pool: Vec<[u8; params::SECRETKEYBYTES]> = (0..256).map(|_| gen_sk(rng)).collect();
	let mut sk = [0u8; params::SECRETKEYBYTES];

	for _ in 0..SAMPLES {
		let (is_left, class) = random_class(rng);
		// Draw the pool index for both classes so RNG work is identical.
		let idx = rng.random_range(0..pool.len());
		sk.copy_from_slice(if is_left { &fixed } else { &pool[idx] });
		runner.run_one(class, || {
			let mut rho = [0u8; params::SEEDBYTES];
			let mut tr = [0u8; params::TR_BYTES];
			let mut key = [0u8; params::SEEDBYTES];
			let mut t0 = Polyveck::default();
			let mut s1 = Polyvecl::default();
			let mut s2 = Polyveck::default();
			packing::unpack_sk(
				&mut rho,
				&mut tr,
				&mut key,
				&mut t0,
				&mut s1,
				&mut s2,
				black_box(&sk),
			);
			polyvec::l_ntt(&mut s1);
			polyvec::k_ntt(&mut s2);
			polyvec::k_ntt(&mut t0);
			black_box((&s1, &s2, &t0));
		});
	}
}

/// Signing: expanding the secret mask vector y from rho' (ExpandMask).
///
/// Uses no rejection sampling, so this should be strictly constant-time.
/// Fixed vs random rho'.
fn sign_mask_expansion(runner: &mut CtRunner, rng: &mut BenchRng) {
	const SAMPLES: usize = 100_000;
	let mut fixed = [0u8; params::CRHBYTES];
	rng.fill_bytes(&mut fixed);
	let mut scratch = [0u8; params::CRHBYTES];
	let mut seed = [0u8; params::CRHBYTES];

	for _ in 0..SAMPLES {
		let (is_left, class) = random_class(rng);
		rng.fill_bytes(&mut scratch);
		seed.copy_from_slice(if is_left { &fixed } else { &scratch });
		runner.run_one(class, || {
			let mut y = Polyvecl::default();
			polyvec::l_uniform_gamma1(&mut y, black_box(&seed), 0);
			black_box(&y);
		});
	}
}

/// Signing: the infinity-norm rejection check on secret-derived z = y + c*s1.
///
/// Must scan every coefficient without early exit; an early exit would leak the index of
/// the first out-of-bound coefficient. Fixed vs random z (coefficients in the post-reduce32
/// range, checked against the gamma1 - beta bound as in signing).
fn sign_norm_check(runner: &mut CtRunner, rng: &mut BenchRng) {
	const SAMPLES: usize = 200_000;
	const BATCH: usize = 4;
	const REDUCE32_RANGE: i32 = 6283008;
	let bound = (params::GAMMA1 - params::BETA) as i32;

	let mut fixed = Polyvecl::default();
	fill_polyvecl(&mut fixed, REDUCE32_RANGE, rng);
	let mut scratch = Polyvecl::default();
	let mut z = Polyvecl::default();

	for _ in 0..SAMPLES {
		let (is_left, class) = random_class(rng);
		fill_polyvecl(&mut scratch, REDUCE32_RANGE, rng);
		copy_polyvecl(&mut z, if is_left { &fixed } else { &scratch });
		runner.run_one(class, || {
			for _ in 0..BATCH {
				let ok = polyvec::polyvecl_is_norm_within_bound(black_box(&z), bound);
				black_box(ok);
			}
		});
	}
}

/// Signing: hint computation from secret-derived low/high parts.
///
/// Runs on rejected attempts whose hints are never published, so the per-coefficient hint
/// decision must be branchless. Inputs span +/- 2*gamma2 so both hint outcomes occur.
fn sign_make_hint(runner: &mut CtRunner, rng: &mut BenchRng) {
	const SAMPLES: usize = 200_000;
	const BATCH: usize = 4;
	let gamma2 = params::GAMMA2 as i32;

	let fill_w1 = |v: &mut Polyveck, rng: &mut BenchRng| {
		for p in v.vec.iter_mut() {
			for c in p.coeffs.iter_mut() {
				*c = rng.random_range(0..16);
			}
		}
	};

	let mut fixed_w0 = Polyveck::default();
	let mut fixed_w1 = Polyveck::default();
	fill_polyveck(&mut fixed_w0, 2 * gamma2, rng);
	fill_w1(&mut fixed_w1, rng);

	let mut scratch_w0 = Polyveck::default();
	let mut scratch_w1 = Polyveck::default();
	let mut w0 = Polyveck::default();
	let mut w1 = Polyveck::default();

	for _ in 0..SAMPLES {
		let (is_left, class) = random_class(rng);
		fill_polyveck(&mut scratch_w0, 2 * gamma2, rng);
		fill_w1(&mut scratch_w1, rng);
		if is_left {
			copy_polyveck(&mut w0, &fixed_w0);
			copy_polyveck(&mut w1, &fixed_w1);
		} else {
			copy_polyveck(&mut w0, &scratch_w0);
			copy_polyveck(&mut w1, &scratch_w1);
		}
		runner.run_one(class, || {
			for _ in 0..BATCH {
				let mut h = Polyveck::default();
				let weight = polyvec::k_make_hint(&mut h, black_box(&w0), black_box(&w1));
				black_box((weight, &h));
			}
		});
	}
}

/// Core polynomial arithmetic on secret operands: forward NTT, pointwise multiply,
/// inverse NTT.
fn ntt_pointwise(runner: &mut CtRunner, rng: &mut BenchRng) {
	const SAMPLES: usize = 200_000;
	const BATCH: usize = 4;

	let mut fixed_a = Poly::default();
	let mut fixed_b = Poly::default();
	fill_poly(&mut fixed_a, Q - 1, rng);
	fill_poly(&mut fixed_b, Q - 1, rng);

	let mut scratch_a = Poly::default();
	let mut scratch_b = Poly::default();
	let mut a = Poly::default();
	let mut b = Poly::default();

	for _ in 0..SAMPLES {
		let (is_left, class) = random_class(rng);
		fill_poly(&mut scratch_a, Q - 1, rng);
		fill_poly(&mut scratch_b, Q - 1, rng);
		if is_left {
			a.coeffs = fixed_a.coeffs;
			b.coeffs = fixed_b.coeffs;
		} else {
			a.coeffs = scratch_a.coeffs;
			b.coeffs = scratch_b.coeffs;
		}
		runner.run_one(class, || {
			for _ in 0..BATCH {
				let mut a_ntt = black_box(&a).clone();
				poly::ntt(&mut a_ntt);
				let mut prod = Poly::default();
				poly::pointwise_montgomery(&mut prod, &a_ntt, black_box(&b));
				poly::invntt_tomont(&mut prod);
				black_box(&prod);
			}
		});
	}
}

ctbench_main!(
	keygen_s1s2_sampling,
	rej_eta_one_block,
	sign_sk_expansion,
	sign_mask_expansion,
	sign_norm_check,
	sign_make_hint,
	ntt_pointwise
);
