//! Regression test (security review): the 32-byte wormhole secret must not
//! survive in dead stack memory after the `WormholePair` that owns it is
//! dropped.
//!
//! The secret previously crossed several function boundaries by value:
//! `generate_new`'s local wrapper moved into `generate_pair_from_secret`'s
//! parameter, the parameter moved into `SensitiveBytes32::into_bytes(self)`,
//! and the finished pair moved from a named `result` local to the return
//! slot. Rust moves are copies that leave the moved-from stack slot dead but
//! never dropped, so `ZeroizeOnDrop` could not wipe those slots — and
//! `into_bytes` additionally handed back a plain `Copy` array with no
//! erasure obligation at all. The fixed pipeline keeps the secret inside the
//! wrapper (no extraction API), lends it to the derivation by reference, and
//! swaps it into the tail-constructed pair, so every dead slot holds zeros.
//!
//! This test also depends on `qp-poseidon-core >= 3.1.0` (its own
//! `tests/stack_zeroization.rs`): the secret *is* a Poseidon digest, and
//! before that version the hasher's self-consuming finalize chain left dead
//! copies of it in the sponge frames, out of this crate's reach.
//!
//! Detection uses the same painted-stack technique as the other
//! `*_stack_zeroization` tests; see `hderive_stack_zeroization.rs`.
//!
//! The assertion is about codegen (which temporaries get wiped), so it is
//! only compiled for optimized builds (`cargo test --release`).
#![cfg(all(not(debug_assertions), feature = "ml-dsa-87"))]

use qp_rusty_crystals_hdwallet::{SensitiveBytes32, WormholePair};
use qp_rusty_crystals_test_utils::{probe_stack_for, probe_stack_for_named};

// The wormhole path only computes Poseidon hashes; 1 MiB is ample.
const STACK_BYTES: usize = 1024 * 1024;

/// Distinctive ASCII seed so a match can only come from a verbatim copy.
const SEED: [u8; 32] = *b"wormhole-probe-seed-0123456789AB";

fn seed_holder() -> SensitiveBytes32 {
	let mut seed = SensitiveBytes32::zeroed();
	seed.as_mut_bytes().copy_from_slice(&SEED);
	seed
}

/// The wormhole secret and first hash for SEED, computed outside any probed
/// region. Derivation is deterministic, so a second run inside the probe
/// produces the same bytes.
fn reference_pair_bytes() -> ([u8; 32], [u8; 32]) {
	let mut seed = seed_holder();
	let pair = WormholePair::generate_new(&mut seed);
	(*pair.secret().as_bytes(), *pair.first_hash())
}

/// Security review: both the wormhole secret and the `first_hash` reveal
/// value must be gone from dead stack memory after the owning pair drops.
/// `first_hash` is the single hash of the salted preimage — a proving
/// reveal, not public data (the address is the *double* hash) — but it was
/// held as a bare `[u8; 32]`, so the pair's drop wiped only the secret and
/// left the reveal readable in the released frame.
#[test]
fn wormhole_secrets_never_survive_pair_drop() {
	let (secret, first_hash) = reference_pair_bytes();
	let patterns = [("secret", &secret[..]), ("first_hash", &first_hash[..])];

	// Sanity: the technique detects an unwiped copy.
	assert!(
		probe_stack_for(STACK_BYTES, &secret, || {
			let leaked: [u8; 32] = secret;
			core::hint::black_box(&leaked);
		}),
		"probe self-check: a deliberately leaked secret copy was not detected"
	);

	// Generate a pair and drop it inside the probed region. The pair's own
	// wrappers zeroize the live values on drop; nothing else may retain them.
	let leaked = probe_stack_for_named(STACK_BYTES, &patterns, || {
		let mut seed = SensitiveBytes32::zeroed();
		seed.as_mut_bytes().copy_from_slice(&SEED);
		let pair = WormholePair::generate_new(&mut seed);
		core::hint::black_box(&pair);
	});
	assert!(
		leaked.is_empty(),
		"wormhole material survived in dead stack memory after the pair was dropped: {leaked:?} \
		 (the secret alone derives the address; first_hash is the proving reveal)"
	);
}
