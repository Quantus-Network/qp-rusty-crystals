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

use std::alloc::{alloc, dealloc, Layout};

use qp_rusty_crystals_dilithium::fips202;
use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig, ThresholdSigner};

const PAINT: u8 = 0xAA;
// 16 MiB: Round 1 drives hyperball rejection sampling across all commitment
// iterations plus the packing of the commitment hash input.
const STACK_BYTES: usize = 16 * 1024 * 1024;
const ALIGN: usize = 4096;

/// Run `f` on a freshly painted stack buffer, then scan the buffer for
/// `pattern` and return whether it was found.
fn probe_stack_for<F: FnOnce()>(pattern: &[u8; 32], f: F) -> bool {
	let layout = Layout::from_size_align(STACK_BYTES, ALIGN).unwrap();
	unsafe {
		let base = alloc(layout);
		assert!(!base.is_null(), "probe stack allocation failed");
		std::ptr::write_bytes(base, PAINT, STACK_BYTES);

		psm::on_stack(base, STACK_BYTES, f);

		let region = std::slice::from_raw_parts(base, STACK_BYTES);
		let offsets: Vec<usize> = region
			.windows(pattern.len())
			.enumerate()
			.filter(|(_, w)| w == pattern)
			.map(|(i, _)| i)
			.collect();
		eprintln!("probe: {} match(es) at offsets {:?}", offsets.len(), offsets);
		let found = !offsets.is_empty();
		dealloc(base, layout);
		found
	}
}

/// First 32 bytes of the SHAKE256 stream `sample_hyperball` squeezes for
/// iteration 0 of `round1_commit_with_seed(ssid, seed)`. Recomputed here
/// through the public fips202 API, mirroring the derivation in
/// `protocol/signing.rs` (iteration 0 leaves the seed unmodified).
fn hyperball_stream_pattern(ssid: &[u8; 32], seed: &[u8; 32]) -> [u8; 32] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, seed);
	fips202::shake256_absorb(&mut state, ssid);
	fips202::shake256_absorb(&mut state, b"rho_prime");
	fips202::shake256_absorb(&mut state, &[0u8]);
	fips202::shake256_finalize(&mut state);
	let mut iter_rho_prime = [0u8; 64];
	fips202::shake256_squeeze(&mut iter_rho_prime, &mut state);

	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, b"H");
	fips202::shake256_absorb(&mut state, &iter_rho_prime);
	fips202::shake256_absorb(&mut state, &0u16.to_le_bytes());
	fips202::shake256_finalize(&mut state);
	let mut pattern = [0u8; 32];
	fips202::shake256_squeeze(&mut pattern, &mut state);
	pattern
}

#[test]
fn round1_leaves_no_mask_stream_copies_on_the_stack() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let (pk, shares) = generate_with_dealer(&[7u8; 32], config).expect("keygen succeeds");
	let mut signer =
		ThresholdSigner::new(shares.into_iter().next().unwrap(), pk, config).expect("signer");
	let sign_ssid = [0x5Cu8; 32];
	let round1_seed = [0x33u8; 32];
	let pattern = hyperball_stream_pattern(&sign_ssid, &round1_seed);

	// Sanity: the technique detects an unwiped copy. A closure that
	// deliberately leaves the stream prefix in a dead stack frame must be
	// seen.
	assert!(
		probe_stack_for(&pattern, || {
			let leaked: [u8; 32] = pattern;
			core::hint::black_box(&leaked);
		}),
		"probe self-check: a deliberately leaked stack copy was not detected"
	);

	// Real scenario: Round 1 commitment on the painted stack. The mask y it
	// samples is retained (in zeroizing state) for the later rounds; the raw
	// stream the sampler consumed must not survive anywhere in the frames
	// Round 1 used.
	let leaked = probe_stack_for(&pattern, || {
		signer
			.round1_commit_with_seed(&sign_ssid, &round1_seed)
			.expect("round 1 commit succeeds");
	});
	assert!(!leaked, "round 1 left the raw mask stream in stack memory");
}
