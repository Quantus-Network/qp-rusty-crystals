//! Regression test (security review): the packed ML-DSA secret key must not
//! survive in dead stack memory after the keypair derived by
//! `derive_key_from_seed` / `derive_key_from_mnemonic` is dropped.
//!
//! Both entrypoints used to return `Result<Keypair, _>` by value. A returned
//! value is moved out of the temporary it was built in, and Rust moves are
//! copies that leave the moved-from stack slot dead but never dropped, so
//! `ZeroizeOnDrop` on the `SecretKey` could not wipe it: the complete packed
//! secret key was left behind verbatim. Whether the compiler elides such a
//! move varies by target, so the entrypoints now fill a caller-owned
//! `Keypair` in place and the key only ever exists inside that self-wiping
//! value.
//!
//! The companion `entropy_stack_zeroization.rs` and `seed_stack_zeroization.rs`
//! probe the same pipelines but scan for the derived entropy and the seed;
//! neither can see a copy of the key those produce.
//!
//! Detection uses the same painted-stack technique as the other
//! `*_stack_zeroization` tests; see `hderive_stack_zeroization.rs`.
//!
//! The assertion is about codegen (which temporaries get wiped), so it is
//! only compiled for optimized builds (`cargo test --release`).
#![cfg(all(not(debug_assertions), feature = "ml-dsa-87"))]

use qp_rusty_crystals_dilithium::{
	ml_dsa_87::SECRETKEYBYTES,
	params::{SEEDBYTES, TR_BYTES},
};
use qp_rusty_crystals_hdwallet::{
	derive_key_from_mnemonic, derive_key_from_seed, ml_dsa_87::Keypair, SensitiveBytes64,
};
use qp_rusty_crystals_test_utils::probe_stack_for_named;

// 4 MiB: comfortably above what ML-DSA-87 key generation needs.
const STACK_BYTES: usize = 4 * 1024 * 1024;

const SEED: [u8; 64] = *b"keypair-probe-seed-first-half-0Akeypair-probe-seed-second-half0B";
/// Derives an unrelated key: the scan must never report it.
const OTHER_SEED: [u8; 64] = *b"keypair-probe-other-seed-half-0Akeypair-probe-other-seed-half-0B";
const PATH: &str = "m/44'/189189'/0'/0'/0'";
const MNEMONIC: &str =
	"legal winner thank year wave sausage worth useful legal winner thank yellow";

/// Window length the packed secret key is scanned in: any verbatim copy of
/// at least `2 * WINDOW - 1` contiguous secret bytes contains a whole window.
const WINDOW: usize = 32;

fn seed_holder(seed: &[u8; 64]) -> SensitiveBytes64 {
	let mut holder = SensitiveBytes64::zeroed();
	holder.as_mut_bytes().copy_from_slice(seed);
	holder
}

/// Reference packed secret key at (seed, PATH), computed outside any probed
/// region.
fn key_from_seed(seed: &[u8; 64]) -> Vec<u8> {
	let mut keypair = Keypair::zeroed();
	derive_key_from_seed(&seed_holder(seed), PATH, &mut keypair).unwrap();
	keypair.secret().to_bytes().to_vec()
}

/// Same for (MNEMONIC, passphrase, PATH).
fn key_from_mnemonic(passphrase: Option<&str>) -> Vec<u8> {
	let mut keypair = Keypair::zeroed();
	derive_key_from_mnemonic(MNEMONIC, passphrase, PATH, &mut keypair).unwrap();
	keypair.secret().to_bytes().to_vec()
}

/// The secret parts of a packed key `rho || K || tr || s1 || s2 || t0`: the
/// nonce seed `K` and the packed secret polynomials, as named scan windows.
/// `rho` and `tr` are public (the public key carries `rho`; `tr` is its
/// hash) and legitimately stay behind.
fn secret_windows<'a>(label: &str, secret_key: &'a [u8]) -> Vec<(String, &'a [u8])> {
	let nonce_seed = &secret_key[SEEDBYTES..2 * SEEDBYTES];
	let polys = &secret_key[2 * SEEDBYTES + TR_BYTES..];
	core::iter::once((format!("{label} K"), nonce_seed))
		.chain(
			polys
				.chunks_exact(WINDOW)
				.enumerate()
				.map(|(i, window)| (format!("{label} s1||s2||t0[{}..]", i * WINDOW), window)),
		)
		.collect()
}

/// Run `f` on a painted stack and return which secret windows of `key` and
/// of the unrelated `other` key it left behind.
fn leaked_windows(key: &[u8], other: &[u8], f: impl FnOnce()) -> (Vec<String>, Vec<String>) {
	let key_windows = secret_windows("key", key);
	let other_windows = secret_windows("other", other);
	let patterns: Vec<(&str, &[u8])> = key_windows
		.iter()
		.chain(&other_windows)
		.map(|(name, w)| (name.as_str(), *w))
		.collect();
	probe_stack_for_named(STACK_BYTES, &patterns, f)
		.into_iter()
		.partition(|name| name.starts_with("key "))
}

/// Self-check: a planted copy of `key` is found in full, and nothing of the
/// unrelated `other` key is reported.
fn assert_probe_detects(key: &[u8], other: &[u8]) {
	let (found, spurious) = leaked_windows(key, other, || {
		let leaked: [u8; SECRETKEYBYTES] = key.try_into().unwrap();
		core::hint::black_box(&leaked);
	});
	assert_eq!(
		found.len(),
		secret_windows("key", key).len(),
		"probe self-check: a deliberately leaked secret key was not detected in full"
	);
	assert!(spurious.is_empty(), "probe self-check: an unrelated key was reported");
}

#[test]
fn packed_secret_key_never_survives_seed_derivation() {
	let key = key_from_seed(&SEED);
	let other = key_from_seed(&OTHER_SEED);
	assert_probe_detects(&key, &other);

	let (leaked, spurious) = leaked_windows(&key, &other, || {
		let seed = seed_holder(&SEED);
		let mut keypair = Keypair::zeroed();
		derive_key_from_seed(&seed, PATH, &mut keypair).unwrap();
		core::hint::black_box(&keypair);
		// `keypair` drops here and wipes its secret half in place.
	});
	assert!(spurious.is_empty(), "an unrelated key was reported");
	assert!(
		leaked.is_empty(),
		"derive_key_from_seed left {} windows of the packed secret key in dead stack memory",
		leaked.len()
	);
}

#[test]
fn packed_secret_key_never_survives_mnemonic_derivation() {
	let key = key_from_mnemonic(None);
	let other = key_from_mnemonic(Some("other"));
	assert_probe_detects(&key, &other);

	let (leaked, spurious) = leaked_windows(&key, &other, || {
		let mut keypair = Keypair::zeroed();
		derive_key_from_mnemonic(MNEMONIC, None, PATH, &mut keypair).unwrap();
		core::hint::black_box(&keypair);
	});
	assert!(spurious.is_empty(), "an unrelated key was reported");
	assert!(
		leaked.is_empty(),
		"derive_key_from_mnemonic left {} windows of the packed secret key in dead stack memory",
		leaked.len()
	);
}
