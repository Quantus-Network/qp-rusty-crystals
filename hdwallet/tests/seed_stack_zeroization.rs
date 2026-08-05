//! Regression test (security review): the 64-byte BIP39 seed handed to the
//! seed-based derivation entrypoints must not survive in dead stack memory
//! after derivation completes.
//!
//! The entrypoints (`derive_key_from_seed`, the macro-generated per-variant
//! versions, and `generate_wormhole_from_seed`) previously took
//! `SensitiveBytes64` *by value*. `SensitiveBytes64` relies on
//! `ZeroizeOnDrop` and moving it into a callee prevents the destructor from
//! running for the caller's original storage: the callee's parameter is
//! wiped on return, but the moved-from caller slot keeps the seed bytes.
//! The mnemonic-based helpers likewise filled a local `SensitiveBytes64`
//! and moved it into `derive_key_from_seed`, leaving their own stack slot
//! outside the drop-time wipe. The fixed entrypoints borrow the seed, so
//! the only copy lives in the caller's self-zeroizing value and is wiped in
//! place when it drops.
//!
//! The companion `entropy_stack_zeroization.rs` probes the same pipelines
//! but scans for the derived 32-byte entropy; this file scans for the seed
//! itself, which is strictly more powerful (it derives the keys and
//! wormhole identities at *every* path).
//!
//! Detection uses the same painted-stack technique as the other
//! `*_stack_zeroization` tests; see `hderive_stack_zeroization.rs`.
//!
//! The assertion is about codegen (which temporaries get wiped), so it is
//! only compiled for optimized builds (`cargo test --release`).
#![cfg(all(not(debug_assertions), feature = "ml-dsa-87"))]

use qp_rusty_crystals_hdwallet::{
	derive_key_from_mnemonic, derive_key_from_seed, derive_wormhole_from_mnemonic,
	generate_wormhole_from_seed, mnemonic_to_seed, SensitiveBytes64,
};
use qp_rusty_crystals_test_utils::probe_stack_for_named;

// 4 MiB: comfortably above what ML-DSA-87 key generation needs.
const STACK_BYTES: usize = 4 * 1024 * 1024;

/// Distinctive 64-byte seed; each 32-byte half is a scan pattern (a partial
/// leak of either half must still be caught). ASCII, so a match cannot come
/// from byte-swapped words inside a hash message schedule — only from a
/// verbatim byte-level copy of the seed.
const SEED: [u8; 64] = *b"seedprobe-bip39-seed-first-half0seedprobe-bip39-seed-second-half";

const PATH: &str = "m/44'/189189'/0'/0'/0'";
const WORMHOLE_PATH: &str = "m/44'/189189189'/0'/0'/0'";

/// Mnemonic for the mnemonic-based entrypoints; its PBKDF2-stretched seed
/// (computed outside the probed region) is the scan pattern.
const MNEMONIC: &str =
	"legal winner thank year wave sausage worth useful legal winner thank yellow";

fn seed_patterns(seed: &[u8; 64]) -> [(&'static str, &[u8]); 2] {
	[("seed[0..32]", &seed[..32]), ("seed[32..64]", &seed[32..])]
}

/// Self-check: the probe technique must detect a deliberately leaked copy.
fn assert_probe_detects(seed: &[u8; 64]) {
	assert!(
		!probe_stack_for_named(STACK_BYTES, &seed_patterns(seed), || {
			let leaked: [u8; 64] = *seed;
			core::hint::black_box(&leaked);
		})
		.is_empty(),
		"probe self-check: a deliberately leaked stack copy was not detected"
	);
}

#[test]
fn seed_never_survives_key_derivation() {
	assert_probe_detects(&SEED);

	let leaked = probe_stack_for_named(STACK_BYTES, &seed_patterns(&SEED), || {
		let mut seed = SensitiveBytes64::zeroed();
		seed.as_mut_bytes().copy_from_slice(&SEED);
		let keypair = derive_key_from_seed(&seed, PATH).unwrap();
		core::hint::black_box(&keypair);
		// `seed` drops here and wipes its storage in place.
	});
	assert!(
		leaked.is_empty(),
		"derive_key_from_seed left the BIP39 seed in dead stack memory: {leaked:?}"
	);
}

#[test]
fn seed_never_survives_wormhole_generation() {
	assert_probe_detects(&SEED);

	let leaked = probe_stack_for_named(STACK_BYTES, &seed_patterns(&SEED), || {
		let mut seed = SensitiveBytes64::zeroed();
		seed.as_mut_bytes().copy_from_slice(&SEED);
		let pair = generate_wormhole_from_seed(&seed, WORMHOLE_PATH).unwrap();
		core::hint::black_box(&pair);
	});
	assert!(
		leaked.is_empty(),
		"generate_wormhole_from_seed left the BIP39 seed in dead stack memory: {leaked:?}"
	);
}

/// Reference stretched seed for MNEMONIC, computed outside any probed region.
fn stretched_seed() -> [u8; 64] {
	let mut seed = SensitiveBytes64::zeroed();
	mnemonic_to_seed(MNEMONIC.to_string(), None, &mut seed).unwrap();
	*seed.as_bytes()
}

#[test]
fn stretched_seed_never_survives_mnemonic_key_derivation() {
	let reference = stretched_seed();
	assert_probe_detects(&reference);

	let leaked = probe_stack_for_named(STACK_BYTES, &seed_patterns(&reference), || {
		let keypair = derive_key_from_mnemonic(MNEMONIC, None, PATH).unwrap();
		core::hint::black_box(&keypair);
	});
	assert!(
		leaked.is_empty(),
		"derive_key_from_mnemonic left the stretched seed in dead stack memory: {leaked:?}"
	);
}

#[test]
fn stretched_seed_never_survives_mnemonic_wormhole_derivation() {
	let reference = stretched_seed();
	assert_probe_detects(&reference);

	let leaked = probe_stack_for_named(STACK_BYTES, &seed_patterns(&reference), || {
		let pair = derive_wormhole_from_mnemonic(MNEMONIC, None, WORMHOLE_PATH).unwrap();
		core::hint::black_box(&pair);
	});
	assert!(
		leaked.is_empty(),
		"derive_wormhole_from_mnemonic left the stretched seed in dead stack memory: {leaked:?}"
	);
}
