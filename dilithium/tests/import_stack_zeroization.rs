//! Regression tests (security review): the key import/serialize paths must
//! not leave plaintext copies of the secret key in dead stack memory.
//!
//! `Keypair::from_bytes` and `SecretKey::from_bytes` built a local
//! `[u8; SECRETKEYBYTES]` copy of the secret key and "moved" it into the
//! returned struct — but `[u8; N]` is `Copy`, so the local survived the move
//! and was never zeroized. `Keypair::to_bytes` materialized a
//! `self.secret.to_bytes()` temporary that was dropped unwiped. (Contrast
//! `Keypair::generate`, which explicitly wipes its `sk` local.) Any of these
//! leaves the full secret key readable in stale stack memory after the live
//! `SecretKey` has been dropped and zeroized.
//!
//! Detection uses the same painted-stack technique as the crate's
//! `stack_probe` example: run the operation on a dedicated sentinel-painted
//! buffer via `psm::on_stack`, then scan the buffer — which we own, so the
//! read is sound — for a distinctive window of the packed secret key. The
//! caller-side result is wiped inside the probe, so any surviving match is a
//! copy the library itself failed to clean up.
//!
//! The scan window is taken from the packed s1 region of the secret key:
//! those bytes only ever appear in this packed form in full serialized-key
//! copies (the unpacked polynomial representation is laid out differently),
//! so a match cannot come from the legitimate, separately-zeroized unpacked
//! intermediates.
//!
//! Only compiled for optimized builds (`cargo test --release`): unoptimized
//! codegen materializes additional compiler-generated move temporaries for
//! the large by-value key structs which no source-level fix can wipe, so a
//! zero-copy assertion is only meaningful once those are elided.
#![cfg(not(debug_assertions))]

use qp_rusty_crystals_dilithium::ml_dsa_87::{Keypair, SecretKey, SECRETKEYBYTES};
use std::alloc::{alloc, dealloc, Layout};
use zeroize::Zeroize;

const PAINT: u8 = 0xAA;
// 4 MiB: comfortably above the keygen-scale derivation the import paths run.
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

/// A distinctive 32-byte window from the packed s1 region of the secret key.
/// SK layout: rho (32) || key (32) || tr (64) || s1 || s2 || t0; s1 starts at
/// offset 128 and is high-entropy packed data for a random key.
fn sk_pattern(sk_bytes: &[u8; SECRETKEYBYTES]) -> [u8; 32] {
	let mut pattern = [0u8; 32];
	pattern.copy_from_slice(&sk_bytes[128..160]);
	pattern
}

#[test]
fn key_import_and_serialize_leave_no_secret_copies_on_the_stack() {
	let keypair = Keypair::generate((&mut [0x5Au8; 32]).into());
	let kp_bytes = keypair.to_bytes();
	let sk_bytes = keypair.secret.to_bytes();
	let pattern = sk_pattern(&sk_bytes);

	// Sanity: the technique detects an unwiped copy. A closure that
	// deliberately leaves the secret key in a dead stack frame must be seen.
	assert!(
		probe_stack_for(&pattern, || {
			let leaked: [u8; SECRETKEYBYTES] = sk_bytes;
			core::hint::black_box(&leaked);
		}),
		"probe self-check: a deliberately leaked stack copy was not detected"
	);

	// Scenario A: Keypair::from_bytes. The imported keypair is wiped in place
	// (through a reference, so the probe itself never moves the secret and
	// cannot smear its own copies around); anything left afterwards is a copy
	// the import path failed to wipe.
	let keypair_import_leaked = probe_stack_for(&pattern, || {
		let mut imported = Keypair::from_bytes(&kp_bytes);
		if let Ok(kp) = imported.as_mut() {
			kp.secret.zeroize();
		}
	});

	// Scenario B: SecretKey::from_bytes, same contract.
	let secret_key_import_leaked = probe_stack_for(&pattern, || {
		let mut imported = SecretKey::from_bytes(&sk_bytes);
		if let Ok(sk) = imported.as_mut() {
			sk.zeroize();
		}
	});

	// Scenario C: Keypair::to_bytes. The returned serialization necessarily
	// contains the secret key; the caller wipes it, so any surviving match is
	// an internal temporary the library dropped unwiped.
	let serialize_leaked = probe_stack_for(&pattern, || {
		let mut serialized = keypair.to_bytes();
		serialized.zeroize();
	});

	assert!(
		!keypair_import_leaked,
		"Keypair::from_bytes left a plaintext secret key copy in stack memory"
	);
	assert!(
		!secret_key_import_leaked,
		"SecretKey::from_bytes left a plaintext secret key copy in stack memory"
	);
	assert!(
		!serialize_leaked,
		"Keypair::to_bytes left a plaintext secret key copy in stack memory"
	);
}
