//! Regression test (security review): threshold signing must not leave the
//! per-signature mask randomness or the signer's secret share in dead stack
//! memory.
//!
//! Round 1 (`round1_commit_with_seed`) squeezes a SHAKE stream and rejection-
//! samples it into the hyperball mask y. That raw stream is the most
//! dangerous transient in the whole signing flow: y itself never leaves the
//! signer, but the Round 3 response z = y + c*s is published, so anyone who
//! recovers y from process memory recovers the secret share s. The stream's
//! raw bytes exist only during Round 1 sampling, so the first two probes
//! target Round 1. The companion heap test (`heap_zeroization.rs`, scenario
//! 3) covers the same stream's heap-side scratch buffer. Round 3 handles s
//! itself, and the last probe covers it.
//!
//! Detection uses the same painted-stack technique as the dealer and DKG
//! probes: run Round 1 on a sentinel-painted stack via `psm::on_stack`, then
//! scan the buffer — which we own, so the read is sound — for the first 32
//! bytes of the iteration-0 mask stream, recomputed independently through the
//! public fips202 API. The signer is constructed outside the probe and the
//! scenario closure captures only references, so the probe machinery cannot
//! plant the pattern itself.
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

use qp_rusty_crystals_dilithium::poly;
use qp_rusty_crystals_test_utils::{probe_stack_for, probe_stack_for_named};
use qp_rusty_crystals_threshold::{
	generate_with_dealer,
	params::{K, L, Q},
	PrivateKeyShare, ThresholdConfig, ThresholdSigner,
};
use share_patterns::{decode_share, named, poly_pattern, share_patterns, Coeffs};
use stack_patterns::{hyperball_stream_pattern, round1_iteration_seeds};

// 16 MiB: Round 1 drives hyperball rejection sampling across all commitment
// iterations plus the packing of the commitment hash input.
const STACK_BYTES: usize = 16 * 1024 * 1024;

/// Party 0's signer for a dealer-generated key, ready for Round 1.
fn party0_signer(config: ThresholdConfig) -> ThresholdSigner {
	let (pk, shares) = generate_with_dealer(&[7u8; 32], config).expect("keygen succeeds");
	ThresholdSigner::new(shares.into_iter().next().unwrap(), pk, config).expect("signer")
}

#[test]
fn round1_leaves_no_mask_stream_copies_on_the_stack() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let mut signer = party0_signer(config);
	let sign_ssid = [0x5Cu8; 32];
	let round1_seed = [0x33u8; 32];
	let pattern = hyperball_stream_pattern(&sign_ssid, &round1_seed);

	// Sanity: the technique detects an unwiped copy. A closure that
	// deliberately leaves the stream prefix in a dead stack frame must be
	// seen.
	assert!(
		probe_stack_for(STACK_BYTES, &pattern, || {
			let leaked: [u8; 32] = pattern;
			core::hint::black_box(&leaked);
		}),
		"probe self-check: a deliberately leaked stack copy was not detected"
	);

	// Real scenario: Round 1 commitment on the painted stack. The mask y it
	// samples is retained (in zeroizing state) for the later rounds; the raw
	// stream the sampler consumed must not survive anywhere in the frames
	// Round 1 used.
	let leaked = probe_stack_for(STACK_BYTES, &pattern, || {
		signer
			.round1_commit_with_seed(&sign_ssid, &round1_seed)
			.expect("round 1 commit succeeds");
	});
	assert!(!leaked, "round 1 left the raw mask stream in stack memory");
}

/// Regression test (security review): Round 1 must not leave any iteration's
/// nonce seed in dead stack memory.
///
/// Each commitment iteration derives `iter_seed` — the round seed itself up
/// to two known bytes — and from it the `iter_rho_prime` its mask is sampled
/// from. Either one regenerates the mask y, exactly like the raw stream
/// above. The iterations reuse the same stack slots, so what stays behind
/// belongs to the *last* iteration, which the iteration-0 stream probe never
/// looks at; every iteration's pair is scanned here.
#[test]
fn round1_leaves_no_nonce_seed_copies_on_the_stack() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let mut signer = party0_signer(config);
	let sign_ssid = [0x5Cu8; 32];
	let round1_seed = [0x33u8; 32];
	let seeds: Vec<_> = (0..config.k_iterations() as u16)
		.map(|k_iter| round1_iteration_seeds(&sign_ssid, &round1_seed, k_iter))
		.collect();
	let patterns: Vec<(&str, &[u8])> = seeds
		.iter()
		.flat_map(|(iter_seed, iter_rho_prime)| {
			[("iter_seed", &iter_seed[..]), ("iter_rho_prime", &iter_rho_prime[..])]
		})
		.collect();

	let leaked = probe_stack_for_named(STACK_BYTES, &patterns, || {
		signer
			.round1_commit_with_seed(&sign_ssid, &round1_seed)
			.expect("round 1 commit succeeds");
	});
	assert!(leaked.is_empty(), "round 1 left nonce seeds in stack memory: {leaked:?}");
}

/// Party 0's recovered partial secret as named scan patterns.
///
/// Round 3 sums the NTT of the subset shares assigned to the signer's slot in
/// the signing set. Party 0 holds slot 0 whenever it signs, and the sharing
/// patterns give slot 0 every subset that contains it, so the sum runs over
/// all of party 0's subset shares. Each sum is reduced to [0, Q), as the
/// recovery leaves it.
fn party0_recovered_patterns(share: &PrivateKeyShare) -> Vec<(String, Vec<u8>)> {
	let (_, subsets) = decode_share(share);
	(0..L + K)
		.map(|i| {
			let mut sum: Coeffs = [0; 256];
			for (_, polys) in &subsets {
				let mut ntt = poly::Poly::default();
				ntt.coeffs_mut().copy_from_slice(&polys[i]);
				poly::ntt(&mut ntt);
				for (s, c) in sum.iter_mut().zip(ntt.coeffs()) {
					*s = (*s + c.rem_euclid(Q)) % Q;
				}
			}
			(format!("recovered (NTT) [{i}]"), poly_pattern(&sum))
		})
		.collect()
}

/// Regression test (security review): Round 3 must not leave the signer's
/// subset shares or its recovered partial secret in dead stack memory.
///
/// Round 3 recovers the signer's partial secret for the signing set from its
/// subset shares and multiplies it by the challenge. Every polynomial of both
/// is scanned, for the smallest, the default and a larger committee.
#[test]
fn round3_leaves_no_share_copies_on_the_stack() {
	for parties in [2, 3, 5] {
		let config = ThresholdConfig::new(2, parties).expect("valid config");
		let (pk, shares) = generate_with_dealer(&[7u8; 32], config).expect("keygen succeeds");
		let mut patterns = share_patterns(&shares[0]);
		patterns.extend(party0_recovered_patterns(&shares[0]));

		let mut signers = shares
			.into_iter()
			.take(2)
			.map(|share| ThresholdSigner::new(share, pk.clone(), config).expect("signer"));
		let (mut a, mut b) = (signers.next().unwrap(), signers.next().unwrap());
		let ssid = [0x11u8; 32];
		let r1a = a.round1_commit_with_seed(&ssid, &[0x5Au8; 32]).expect("round 1");
		let r1b = b.round1_commit_with_seed(&ssid, &[0x6Bu8; 32]).expect("round 1");
		let r2b = b.round2_reveal(&ssid, b"message", b"ctx", &[r1a]).expect("round 2");
		a.round2_reveal(&ssid, b"message", b"ctx", core::slice::from_ref(&r1b))
			.expect("round 2");

		let leaked = probe_stack_for_named(STACK_BYTES, &named(&patterns), || {
			a.round3_respond(&ssid, core::slice::from_ref(&r1b), core::slice::from_ref(&r2b))
				.expect("round 3");
		});
		assert!(
			leaked.is_empty(),
			"2-of-{parties} round 3 left secrets in stack memory: {leaked:?}"
		);
	}
}
