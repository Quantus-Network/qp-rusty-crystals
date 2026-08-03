//! Regression tests (security review): the HMAC-SHA512 derivation steps in
//! `ExtendedPrivKey::derive` and `ExtendedPrivKey::child` must not leave
//! secret material in dead stack memory.
//!
//! The previous implementation drove the derivation through the `hmac` crate's
//! `Hmac<Sha512>`, whose state is dropped without zeroization:
//!
//! - `Hmac::new_from_slice` builds a 128-byte key block, XORs it in place with the ipad/opad
//!   constants and drops it unwiped, leaving `key ^ 0x5c..` (the parent chain code in `child()`) in
//!   a dead stack frame.
//! - The wrapper's block buffer holds the raw message tail — the BIP39 seed in `derive()`, `0x00 ||
//!   parent_secret_key || child_index` in `child()` — verbatim, and `finalize()` consumes the
//!   ~470-byte wrapper by value, so moves smear unwiped copies of that buffer across the stack.
//! - The two inner SHA-512 states that absorbed the secrets are dropped unwiped as well.
//!
//! Detection uses the same painted-stack technique as
//! `dilithium/tests/import_stack_zeroization.rs`: run the derivation on a
//! dedicated sentinel-painted buffer via `psm::on_stack`, then scan the buffer
//! — which we own, so the read is sound — for distinctive secret patterns.
//! The reference values (master secret key and chain code) are computed
//! independently with the `hmac` dev-dependency outside the probed region.
//!
//! The assertion is about codegen (which temporaries get wiped), so it is only
//! compiled for optimized builds (`cargo test --release`): unoptimized codegen
//! materializes additional compiler-generated move temporaries that no
//! source-level fix can wipe.
#![cfg(not(debug_assertions))]

use hmac::{Hmac, Mac};
use qp_rusty_crystals_hdwallet::hderive::{ChildNumber, ExtendedPrivKey};
use qp_rusty_crystals_test_utils::probe_stack_for_named;
use sha2::Sha512;

// 4 MiB: comfortably above what a single HMAC-SHA512 derivation step needs.
const STACK_BYTES: usize = 4 * 1024 * 1024;

/// HMAC ipad/opad constants (RFC 2104). `Hmac::new_from_slice` leaves
/// `key ^ OPAD` in its dropped key-block local, so a scan for these XOR
/// patterns detects chain-code residue even though the raw chain code itself
/// never appears verbatim.
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// Distinctive 64-byte seed; each 32-byte half is a scan pattern. ASCII, so a
/// match cannot come from the byte-swapped u64 words inside the SHA-512
/// message schedule — only from a verbatim byte-level copy of the seed.
const SEED: [u8; 64] = *b"hderive-probe-seed-first-half-0Ahderive-probe-seed-second-half0B";

fn xor_pattern(bytes: &[u8; 32], pad: u8) -> [u8; 32] {
	bytes.map(|b| b ^ pad)
}

#[test]
fn hderive_leaves_no_secret_material_on_the_stack() {
	// Reference master secret_key || chain_code, computed independently of the
	// code under test (and outside the probed region).
	let mut reference: Hmac<Sha512> = Hmac::new_from_slice(b"Dilithium seed").unwrap();
	reference.update(&SEED);
	let reference = reference.finalize().into_bytes();
	let master_secret: [u8; 32] = reference[..32].try_into().unwrap();
	let master_chain: [u8; 32] = reference[32..].try_into().unwrap();

	let mut master = ExtendedPrivKey::zeroed();
	ExtendedPrivKey::derive(&SEED, "m", &mut master).unwrap();
	assert_eq!(
		master.secret().as_bytes(),
		&master_secret,
		"reference HMAC disagrees with derive()"
	);

	// Sanity: the technique detects an unwiped copy. A closure that
	// deliberately leaves the seed in a dead stack frame must be seen.
	let seed_patterns: [(&str, &[u8]); 2] =
		[("seed[0..32]", &SEED[..32]), ("seed[32..64]", &SEED[32..])];
	assert!(
		!probe_stack_for_named(STACK_BYTES, &seed_patterns, || {
			let leaked: [u8; 64] = SEED;
			core::hint::black_box(&leaked);
		})
		.is_empty(),
		"probe self-check: a deliberately leaked stack copy was not detected"
	);

	// Scenario A: master derivation. The seed is fed into the HMAC step and
	// must not survive anywhere on the stack once the derived key (which is
	// self-zeroizing) has been dropped.
	let derive_leaks = probe_stack_for_named(STACK_BYTES, &seed_patterns, || {
		let mut key = ExtendedPrivKey::zeroed();
		ExtendedPrivKey::derive(&SEED, "m", &mut key).unwrap();
		core::hint::black_box(&key);
	});

	// Scenario B: child derivation. The parent secret key is the HMAC message
	// and the parent chain code is the HMAC key; neither the raw values nor
	// their ipad/opad-XORed key blocks may survive on the stack.
	let chain_ipad = xor_pattern(&master_chain, IPAD);
	let chain_opad = xor_pattern(&master_chain, OPAD);
	let child_patterns: [(&str, &[u8]); 4] = [
		("parent secret_key", &master_secret),
		("parent chain_code", &master_chain),
		("parent chain_code ^ ipad", &chain_ipad),
		("parent chain_code ^ opad", &chain_opad),
	];
	let child_number: ChildNumber = "0'".parse().unwrap();
	let child_leaks = probe_stack_for_named(STACK_BYTES, &child_patterns, || {
		let mut key = ExtendedPrivKey::zeroed();
		ExtendedPrivKey::derive(&SEED, "m", &mut key).unwrap();
		key.child_in_place(child_number);
		core::hint::black_box(&key);
	});

	assert!(
		derive_leaks.is_empty(),
		"derive() left secret material in dead stack memory: {derive_leaks:?}"
	);
	assert!(
		child_leaks.is_empty(),
		"child_in_place() left secret material in dead stack memory: {child_leaks:?}"
	);
}

// Regression test (security review): deriving a key, reading its secret
// through `ExtendedPrivKey::secret()`, and dropping everything must leave no
// copy of the derived key material in dead stack memory — with no manual
// wiping on the caller's part.
//
// Two past violations are pinned here. The raw-array accessor
// (`fn secret(&self) -> [u8; 32]`) handed the caller an unguarded duplicate
// with no destruction-time zeroization. And `derive()` returned the key
// struct by value: Rust moves are copies that leave the moved-from stack
// slot dead but never dropped, so the secret key and chain code survived in
// a dead `Result` slot that `ZeroizeOnDrop` could not wipe. The accessor now
// returns a borrow (no copy exists to leak) and `derive()` fills a
// caller-provided key in place, so the material only ever lives inside the
// caller's self-zeroizing value.
#[test]
fn derive_and_secret_access_leave_no_unwiped_copies() {
	// Reference master secret and chain code, computed independently outside
	// the probed region.
	let mut reference: Hmac<Sha512> = Hmac::new_from_slice(b"Dilithium seed").unwrap();
	reference.update(&SEED);
	let reference = reference.finalize().into_bytes();
	let patterns: [(&str, &[u8]); 2] =
		[("master secret_key", &reference[..32]), ("master chain_code", &reference[32..])];

	let leaks = probe_stack_for_named(STACK_BYTES, &patterns, || {
		let mut key = ExtendedPrivKey::zeroed();
		ExtendedPrivKey::derive(&SEED, "m", &mut key).unwrap();
		let secret = key.secret();
		core::hint::black_box(&secret);
		// `key` drops here and wipes its fields in place.
	});
	assert!(leaks.is_empty(), "derived key material survived in dead stack memory: {leaks:?}");
}
