//! Regression test (security review): the trusted-dealer keygen must not
//! leave plaintext copies of per-party key seeds in dead stack memory.
//!
//! The companion heap test (`heap_zeroization.rs`) catches secret-bearing
//! heap blocks freed unwiped, but cannot see stack residue. This probe covers
//! the stack side of the same dealer findings: `generate_with_dealer` squeezes
//! each party's 32-byte key seed, holds the set in a `Zeroizing` vector, and
//! copies one seed into each `PrivateKeyShare` — every one of those copies
//! passes through stack temporaries (the squeeze-loop local, the by-value
//! argument to `PrivateKeyShare::new`, compiler spills) that no drop reaches
//! if codegen fails to elide them.
//!
//! Detection uses the same painted-stack technique as dilithium's
//! `import_stack_zeroization` test: run the operation on a dedicated
//! sentinel-painted buffer via `psm::on_stack`, then scan the buffer — which
//! we own, so the read is sound — for party 0's key seed. The seed is
//! high-entropy XOF output and deterministically recomputable through the
//! public fips202 API, so the scan cannot false-positive on unrelated memory
//! (unlike the small-valued share coefficients, which make poor scan targets).
//! The scenario closure captures only the dealer input seed, never the
//! pattern, so the probe machinery itself cannot plant a match.
//!
//! Only compiled for optimized builds (`cargo test --release`): unoptimized
//! codegen materializes additional compiler-generated move temporaries for
//! large by-value structs which no source-level fix can wipe, so a zero-copy
//! assertion is only meaningful once those are elided.
#![cfg(not(debug_assertions))]

#[path = "common/share_patterns.rs"]
mod share_patterns;
#[path = "common/stack_patterns.rs"]
mod stack_patterns;

use std::collections::BTreeMap;

use qp_rusty_crystals_dilithium::{poly, polyvec};
use qp_rusty_crystals_test_utils::{probe_stack_for, probe_stack_for_named};
use qp_rusty_crystals_threshold::{
	generate_with_dealer,
	params::{K, L, Q},
	PrivateKeyShare, PublicKey, ThresholdConfig,
};
use share_patterns::{decode_share, named, poly_pattern, share_patterns, Coeffs};
use stack_patterns::dealer_party0_seed_pattern;
use zeroize::Zeroize;

// 4 MiB: comfortably above the dealer's frame (matrix A alone is K x L
// polynomials, ~57 KiB, plus the polyvec locals).
const STACK_BYTES: usize = 4 * 1024 * 1024;

#[test]
fn dealer_keygen_leaves_no_party_seed_copies_on_the_stack() {
	let dealer_seed = [0x2Du8; 32];
	let pattern = dealer_party0_seed_pattern(&dealer_seed, 2, 3);

	// Sanity: the technique detects an unwiped copy. A closure that
	// deliberately leaves the seed in a dead stack frame must be seen.
	assert!(
		probe_stack_for(STACK_BYTES, &pattern, || {
			let leaked: [u8; 32] = pattern;
			core::hint::black_box(&leaked);
		}),
		"probe self-check: a deliberately leaked stack copy was not detected"
	);

	// Real scenario: full dealer keygen. The returned shares hold the only
	// legitimate copies of the seeds; they live in the Vec's heap buffer and
	// are wiped in place through a reference (so the probe itself never moves
	// a secret and cannot smear its own copies around). Anything left in the
	// painted region afterwards is a stack copy the dealer failed to wipe.
	let leaked = probe_stack_for(STACK_BYTES, &pattern, || {
		let config = ThresholdConfig::new(2, 3).expect("valid config");
		let (_pk, mut shares) =
			generate_with_dealer(&dealer_seed, config).expect("keygen succeeds");
		for share in shares.iter_mut() {
			share.zeroize();
		}
	});
	assert!(!leaked, "generate_with_dealer left a plaintext per-party key seed in stack memory");
}

/// The dealer's aggregate secrets as named scan patterns, recomputed from the
/// shares: the total `s1` in NTT form, as fed to `A*s1`, and the unrounded
/// `t = A*s1 + s2`, whose low bits are the secret `t0`.
fn aggregate_patterns(
	public_key: &PublicKey,
	shares: &[PrivateKeyShare],
) -> Vec<(String, Vec<u8>)> {
	let subsets: BTreeMap<u16, Vec<Coeffs>> =
		shares.iter().flat_map(|share| decode_share(share).1).collect();
	let canonical = |poly: &mut poly::Poly| {
		poly.coeffs_mut().iter_mut().for_each(|c| *c = c.rem_euclid(Q));
	};
	let mut patterns = Vec::new();

	// `t` starts out as the total `s2`.
	let mut s1h = polyvec::Polyvec::<L>::default();
	let mut t = polyvec::Polyvec::<K>::default();
	for polys in subsets.values() {
		for (total, poly) in s1h.vec.iter_mut().chain(t.vec.iter_mut()).zip(polys) {
			total.coeffs_mut().iter_mut().zip(poly).for_each(|(sum, c)| *sum += c);
		}
	}
	for (i, s1h_poly) in s1h.vec.iter_mut().enumerate() {
		poly::ntt(s1h_poly);
		canonical(s1h_poly);
		patterns.push((format!("aggregate s1 (NTT) [{i}]"), poly_pattern(s1h_poly.coeffs())));
	}

	let mut a_matrix: [polyvec::Polyvec<L>; K] =
		core::array::from_fn(|_| polyvec::Polyvec::default());
	polyvec::matrix_expand(&mut a_matrix, public_key.as_bytes()[..32].try_into().expect("rho"));
	for (i, (a_row, t_poly)) in a_matrix.iter().zip(t.vec.iter_mut()).enumerate() {
		let mut a_s1 = poly::Poly::default();
		for (a_poly, s1h_poly) in a_row.vec.iter().zip(&s1h.vec) {
			let mut product = poly::Poly::default();
			poly::pointwise_montgomery(&mut product, a_poly, s1h_poly);
			poly::add_ip(&mut a_s1, &product);
		}
		poly::reduce(&mut a_s1);
		poly::invntt_tomont(&mut a_s1);
		poly::add_ip(t_poly, &a_s1);
		canonical(t_poly);
		patterns.push((format!("unrounded t[{i}]"), poly_pattern(t_poly.coeffs())));
	}
	patterns
}

/// Regression test (security review): the dealer must not leave any party's
/// key seed, any share coefficients or the aggregate secret in dead stack
/// memory.
///
/// The probe above scans party 0's seed only, and every loop in the dealer
/// reuses its stack slots, so whatever it leaves behind belongs to the *last*
/// party and the *last* subset — which that probe never looks at. This one
/// scans every party's key seed, every polynomial of every subset share (the
/// decoded coefficient arrays) and the aggregates the public key is computed
/// from, for the smallest, the default and a larger committee.
#[test]
fn dealer_keygen_leaves_no_share_copies_on_the_stack() {
	for (threshold, parties) in [(2, 2), (2, 3), (2, 5)] {
		let dealer_seed = [0x2Du8; 32];
		let config = ThresholdConfig::new(threshold, parties).expect("valid config");

		// Reference run (unprobed): learn the secrets the probed run must
		// wipe. Keygen is deterministic in the seed, so both runs produce
		// byte-identical shares.
		let (public_key, shares) =
			generate_with_dealer(&dealer_seed, config).expect("keygen succeeds");
		let mut patterns: Vec<_> = shares.iter().flat_map(share_patterns).collect();
		patterns.extend(aggregate_patterns(&public_key, &shares));
		patterns.sort();
		patterns.dedup();
		drop(shares);

		let leaked = probe_stack_for_named(STACK_BYTES, &named(&patterns), || {
			let (_pk, mut shares) =
				generate_with_dealer(&dealer_seed, config).expect("keygen succeeds");
			for share in shares.iter_mut() {
				share.zeroize();
			}
		});
		assert!(
			leaked.is_empty(),
			"{threshold}-of-{parties} generate_with_dealer left secrets in stack memory: {leaked:?}"
		);
	}
}
