//! Regression test (security review): threshold signing must not leave the
//! per-signature mask randomness in dead stack memory.
//!
//! Round 1 (`round1_commit_with_seed`) squeezes a SHAKE stream and rejection-
//! samples it into the hyperball mask y. That raw stream is the most
//! dangerous transient in the whole signing flow: y itself never leaves the
//! signer, but the Round 3 response z = y + c*s is published, so anyone who
//! recovers y from process memory recovers the secret share s. The stream's
//! raw bytes exist only during Round 1 sampling — later rounds handle y and s
//! in coefficient form inside `ZeroizeOnDrop` polyvecs — so Round 1 is where
//! stack residue of this secret can occur, and what this probe targets. The
//! companion heap test (`heap_zeroization.rs`, scenario 3) covers the same
//! stream's heap-side scratch buffer.
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

#[path = "common/stack_patterns.rs"]
mod stack_patterns;

use qp_rusty_crystals_test_utils::{probe_stack_for, probe_stack_for_named};
use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig, ThresholdSigner};
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
