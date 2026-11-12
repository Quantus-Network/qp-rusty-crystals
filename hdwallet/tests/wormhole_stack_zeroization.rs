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

use qp_rusty_crystals_hdwallet::{
	derive_wormhole_from_mnemonic, generate_wormhole_from_seed, SensitiveBytes32, SensitiveBytes64,
	WormholePair,
};
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

const SEED_64: [u8; 64] = *b"wormhole-probe-seed-first-half0Awormhole-probe-seed-second-half0";
/// Derives an unrelated pair: the scan must never report it.
const OTHER_SEED_64: [u8; 64] =
	*b"wormhole-probe-other-seed-half0Awormhole-probe-other-seed-half0B";
const PATH: &str = "m/44'/189189189'/0'/0'/0'";
const MNEMONIC: &str =
	"legal winner thank year wave sausage worth useful legal winner thank yellow";

fn seed_holder_64(seed: &[u8; 64]) -> SensitiveBytes64 {
	let mut holder = SensitiveBytes64::zeroed();
	holder.as_mut_bytes().copy_from_slice(seed);
	holder
}

/// Security review: the derivation entrypoints must uphold the same property
/// as `generate_new`. They used to return `Result<WormholePair, _>` by
/// value; the temporary that value is moved out of is never dropped, so the
/// pair's own zeroizing wrappers could not reach it and both `secret` and
/// `first_hash` stayed in dead stack memory — while the test above, which
/// calls `generate_new` directly, kept passing. The entrypoints now fill a
/// caller-owned pair in place.
///
/// `derive` fills the pair under test and `unrelated` a different one, whose
/// secrets the scan must not report.
fn assert_no_wormhole_residue(
	entrypoint: &str,
	derive: impl Fn(&mut WormholePair),
	unrelated: impl Fn(&mut WormholePair),
) {
	// Reference values, computed outside any probed region.
	let mut pair = WormholePair::zeroed();
	derive(&mut pair);
	let (secret, first_hash) = (*pair.secret().as_bytes(), *pair.first_hash());
	unrelated(&mut pair);
	let (other_secret, other_first_hash) = (*pair.secret().as_bytes(), *pair.first_hash());
	let patterns = [
		("secret", &secret[..]),
		("first_hash", &first_hash[..]),
		("unrelated secret", &other_secret[..]),
		("unrelated first_hash", &other_first_hash[..]),
	];

	// Sanity: the technique detects unwiped copies, and only those planted.
	let planted = probe_stack_for_named(STACK_BYTES, &patterns, || {
		let leaked: [[u8; 32]; 2] = [secret, first_hash];
		core::hint::black_box(&leaked);
	});
	assert_eq!(planted, ["secret", "first_hash"], "probe self-check failed");

	let leaked = probe_stack_for_named(STACK_BYTES, &patterns, || {
		let mut pair = WormholePair::zeroed();
		derive(&mut pair);
		core::hint::black_box(&pair);
	});
	assert!(
		leaked.is_empty(),
		"{entrypoint} left wormhole material in dead stack memory after the pair was dropped: \
		 {leaked:?}"
	);
}

#[test]
fn wormhole_secrets_never_survive_seed_derivation() {
	let derive = |seed: &[u8; 64], out: &mut WormholePair| {
		generate_wormhole_from_seed(&seed_holder_64(seed), PATH, out).unwrap()
	};
	assert_no_wormhole_residue(
		"generate_wormhole_from_seed",
		|out| derive(&SEED_64, out),
		|out| derive(&OTHER_SEED_64, out),
	);
}

#[test]
fn wormhole_secrets_never_survive_mnemonic_derivation() {
	let derive = |passphrase: Option<&str>, out: &mut WormholePair| {
		derive_wormhole_from_mnemonic(MNEMONIC, passphrase, PATH, out).unwrap()
	};
	assert_no_wormhole_residue(
		"derive_wormhole_from_mnemonic",
		|out| derive(None, out),
		|out| derive(Some("other"), out),
	);
}
