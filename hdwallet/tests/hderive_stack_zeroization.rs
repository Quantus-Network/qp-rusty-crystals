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

use std::alloc::{alloc, dealloc, Layout};

use hmac::{Hmac, Mac};
use qp_rusty_crystals_hdwallet::hderive::{ChildNumber, ExtendedPrivKey};
use sha2::Sha512;

const PAINT: u8 = 0xAA;
// 4 MiB: comfortably above what a single HMAC-SHA512 derivation step needs.
const STACK_BYTES: usize = 4 * 1024 * 1024;
const ALIGN: usize = 4096;

/// HMAC ipad/opad constants (RFC 2104). `Hmac::new_from_slice` leaves
/// `key ^ OPAD` in its dropped key-block local, so a scan for these XOR
/// patterns detects chain-code residue even though the raw chain code itself
/// never appears verbatim.
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// Run `f` on a freshly painted stack buffer, then scan the buffer for each
/// named pattern and return the names of those found.
fn probe_stack_for<F: FnOnce()>(patterns: &[(&str, [u8; 32])], f: F) -> Vec<String> {
	let layout = Layout::from_size_align(STACK_BYTES, ALIGN).unwrap();
	unsafe {
		let base = alloc(layout);
		assert!(!base.is_null(), "probe stack allocation failed");
		std::ptr::write_bytes(base, PAINT, STACK_BYTES);

		psm::on_stack(base, STACK_BYTES, f);

		let region = std::slice::from_raw_parts(base, STACK_BYTES);
		let mut found = Vec::new();
		for (name, pattern) in patterns {
			let offsets: Vec<usize> = region
				.windows(pattern.len())
				.enumerate()
				.filter(|(_, w)| w == pattern)
				.map(|(i, _)| i)
				.collect();
			if !offsets.is_empty() {
				eprintln!("probe: pattern {name:?} found at offsets {offsets:?}");
				found.push(name.to_string());
			}
		}
		dealloc(base, layout);
		found
	}
}

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

	let master = ExtendedPrivKey::derive(&SEED, "m").unwrap();
	assert_eq!(master.secret(), master_secret, "reference HMAC disagrees with derive()");

	// Sanity: the technique detects an unwiped copy. A closure that
	// deliberately leaves the seed in a dead stack frame must be seen.
	let seed_patterns = [
		("seed[0..32]", SEED[..32].try_into().unwrap()),
		("seed[32..64]", SEED[32..].try_into().unwrap()),
	];
	assert!(
		!probe_stack_for(&seed_patterns, || {
			let leaked: [u8; 64] = SEED;
			core::hint::black_box(&leaked);
		})
		.is_empty(),
		"probe self-check: a deliberately leaked stack copy was not detected"
	);

	// Scenario A: master derivation. The seed is fed into the HMAC step and
	// must not survive anywhere on the stack once the derived key (which is
	// self-zeroizing) has been dropped.
	let derive_leaks = probe_stack_for(&seed_patterns, || {
		let key = ExtendedPrivKey::derive(&SEED, "m").unwrap();
		core::hint::black_box(&key);
	});

	// Scenario B: child derivation. The parent secret key is the HMAC message
	// and the parent chain code is the HMAC key; neither the raw values nor
	// their ipad/opad-XORed key blocks may survive on the stack.
	let child_patterns = [
		("parent secret_key", master_secret),
		("parent chain_code", master_chain),
		("parent chain_code ^ ipad", xor_pattern(&master_chain, IPAD)),
		("parent chain_code ^ opad", xor_pattern(&master_chain, OPAD)),
	];
	let child_number: ChildNumber = "0'".parse().unwrap();
	let child_leaks = probe_stack_for(&child_patterns, || {
		let child = master.child(child_number).unwrap();
		core::hint::black_box(&child);
	});

	assert!(
		derive_leaks.is_empty(),
		"derive() left secret material in dead stack memory: {derive_leaks:?}"
	);
	assert!(
		child_leaks.is_empty(),
		"child() left secret material in dead stack memory: {child_leaks:?}"
	);
}
