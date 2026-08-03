//! Regression test (security review): the 32 bytes of derived keypair
//! entropy must not survive in dead stack memory after key generation.
//!
//! The entropy is the crown jewel of the pipeline: it deterministically
//! yields the entire keypair. It previously crossed three function
//! boundaries by value — `derive_entropy_from_seed`'s return,
//! `Keypair::generate`'s parameter, and `keypair_var`'s parameter (which
//! additionally unwrapped it into a raw array via `into_bytes()`). Rust
//! moves are copies that leave the moved-from stack slot dead but never
//! dropped, so `ZeroizeOnDrop` could not wipe those slots. The fixed
//! pipeline fills a caller-owned `SensitiveBytes32` in place and lends it
//! to key generation by reference, which wipes it in place after use.
//!
//! Detection uses the same painted-stack technique as the other
//! `*_stack_zeroization` tests; see `hderive_stack_zeroization.rs`.
//!
//! The assertion is about codegen (which temporaries get wiped), so it is
//! only compiled for optimized builds (`cargo test --release`).
#![cfg(all(not(debug_assertions), feature = "ml-dsa-87"))]

use qp_rusty_crystals_hdwallet::{
	derive_key_from_seed, generate_wormhole_from_seed, hderive::ExtendedPrivKey, SensitiveBytes64,
};
use qp_rusty_crystals_test_utils::probe_stack_for;

// 4 MiB: comfortably above what ML-DSA-87 key generation needs.
const STACK_BYTES: usize = 4 * 1024 * 1024;

/// Distinctive 64-byte seed (ASCII, so a match cannot come from byte-swapped
/// words inside a hash message schedule — only from a verbatim copy).
const SEED: [u8; 64] = *b"entropy-probe-seed-first-half-0Aentropy-probe-seed-second-half0B";
const PATH: &str = "m/44'/189189'/0'/0'/0'";
const WORMHOLE_PATH: &str = "m/44'/189189189'/0'/0'/0'";

fn seed_holder() -> SensitiveBytes64 {
	let mut seed = SensitiveBytes64::zeroed();
	seed.as_mut_bytes().copy_from_slice(&SEED);
	seed
}

/// Reference entropy at (SEED, path), computed outside any probed region.
fn reference_entropy(path: &str) -> [u8; 32] {
	let mut xpriv = ExtendedPrivKey::zeroed();
	ExtendedPrivKey::derive(&SEED, path, &mut xpriv).unwrap();
	*xpriv.secret().as_bytes()
}

#[test]
fn derived_entropy_never_survives_key_generation() {
	let entropy = reference_entropy(PATH);

	// Sanity: the technique detects an unwiped copy.
	assert!(
		probe_stack_for(STACK_BYTES, &entropy, || {
			let leaked: [u8; 32] = entropy;
			core::hint::black_box(&leaked);
		}),
		"probe self-check: a deliberately leaked entropy copy was not detected"
	);

	// The full pipeline: seed -> HD entropy -> ML-DSA-87 keypair. Once the
	// keypair has been produced and dropped, no copy of the entropy may
	// remain anywhere on the stack.
	let holder = seed_holder();
	let leaked = probe_stack_for(STACK_BYTES, &entropy, move || {
		let keypair = derive_key_from_seed(holder, PATH).unwrap();
		core::hint::black_box(&keypair);
	});
	assert!(
		!leaked,
		"the derived keypair entropy survived in dead stack memory after key \
		 generation; it deterministically yields the entire keypair"
	);
}

// Same property for the wormhole consumer of the derived entropy. This path
// is the sensitive detector for by-value entropy hops: ML-DSA key generation
// uses ~100 KB of stack whose frames happen to overwrite earlier move
// temporaries, but the wormhole pair only computes a Poseidon hash, so an
// unwiped entropy copy in a dead slot survives and the probe sees it.
#[test]
fn derived_entropy_never_survives_wormhole_generation() {
	let entropy = reference_entropy(WORMHOLE_PATH);

	let holder = seed_holder();
	let leaked = probe_stack_for(STACK_BYTES, &entropy, move || {
		let pair = generate_wormhole_from_seed(holder, WORMHOLE_PATH).unwrap();
		core::hint::black_box(&pair);
	});
	assert!(
		!leaked,
		"the derived wormhole entropy survived in dead stack memory; it yields \
		 the wormhole secret (and the keypair at the same path)"
	);
}
