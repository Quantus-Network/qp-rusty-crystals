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

use std::alloc::{alloc, dealloc, Layout};

use qp_rusty_crystals_dilithium::fips202;
use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig};
use zeroize::Zeroize;

const PAINT: u8 = 0xAA;
// 4 MiB: comfortably above the dealer's frame (matrix A alone is K x L
// polynomials, ~57 KiB, plus the polyvec locals).
const STACK_BYTES: usize = 4 * 1024 * 1024;
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

/// The 32-byte per-party key seed the dealer squeezes for party 0, recomputed
/// through the public fips202 API in the exact absorb/squeeze order of
/// `generate_with_dealer`: absorb the dealer seed, `[K, L]`, and the `(t, n)`
/// policy binding, then squeeze rho (public matrix seed, discarded) followed
/// by party 0's key seed.
fn dealer_party0_seed_pattern(seed: &[u8; 32], threshold: u32, parties: u32) -> [u8; 32] {
	use qp_rusty_crystals_threshold::params::{K, L};

	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, seed);
	fips202::shake256_absorb(&mut state, &[K as u8, L as u8]);
	fips202::shake256_absorb(&mut state, &threshold.to_le_bytes());
	fips202::shake256_absorb(&mut state, &parties.to_le_bytes());
	fips202::shake256_finalize(&mut state);
	let mut rho = [0u8; 32];
	fips202::shake256_squeeze(&mut rho, &mut state);
	let mut key0 = [0u8; 32];
	fips202::shake256_squeeze(&mut key0, &mut state);
	key0
}

#[test]
fn dealer_keygen_leaves_no_party_seed_copies_on_the_stack() {
	let dealer_seed = [0x2Du8; 32];
	let pattern = dealer_party0_seed_pattern(&dealer_seed, 2, 3);

	// Sanity: the technique detects an unwiped copy. A closure that
	// deliberately leaves the seed in a dead stack frame must be seen.
	assert!(
		probe_stack_for(&pattern, || {
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
	let leaked = probe_stack_for(&pattern, || {
		let config = ThresholdConfig::new(2, 3).expect("valid config");
		let (_pk, mut shares) =
			generate_with_dealer(&dealer_seed, config).expect("keygen succeeds");
		for share in shares.iter_mut() {
			share.zeroize();
		}
	});
	assert!(!leaked, "generate_with_dealer left a plaintext per-party key seed in stack memory");
}
