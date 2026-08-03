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

mod common;

use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig};
use zeroize::Zeroize;

use common::{dealer_party0_seed_pattern, probe_stack_for};

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
