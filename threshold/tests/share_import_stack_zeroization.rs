//! Regression test (security review): a *failed* `PrivateKeyShare` import
//! must not leave plaintext share material in dead stack memory.
//!
//! `PrivateKeyShare::deserialize_reader` reads the secret fields — `key`,
//! `rho`, `tr`, and every subset's `SecretShareData` — before running its
//! validation checks, and `SecretShareData::deserialize_reader` reads the
//! full s1/s2 coefficient arrays before its range check. Those secrets live
//! in plain local arrays, so any validation failure (a malformed or
//! attacker-controlled blob that parses far enough) returns an error while
//! Rust's default `Drop` leaves the secrets intact on the stack. The
//! `Zeroize`/`ZeroizeOnDrop` impls only cover fully constructed values.
//!
//! Detection uses the same painted-stack technique as the crate's other
//! `*_stack_zeroization` tests: run the failing import on a dedicated
//! sentinel-painted buffer via `psm::on_stack`, then scan the buffer — which
//! we own, so the read is sound — for the secret bytes. The patterns are
//! taken from the serialized blob itself (which lives on the heap, outside
//! the painted region), so a match can only be a stack copy the import path
//! failed to wipe. `key`/`rho`/`tr` are high-entropy XOF output; the share
//! coefficient pattern is a 256-byte window (64 serialized coefficients), so
//! neither can false-positive on unrelated memory.
//!
//! Only compiled for optimized builds (`cargo test --release`): unoptimized
//! codegen materializes additional compiler-generated move temporaries for
//! the large by-value arrays which no source-level fix can wipe, so a
//! zero-copy assertion is only meaningful once those are elided.
#![cfg(not(debug_assertions))]

use qp_rusty_crystals_test_utils::probe_stack_for_named;
use qp_rusty_crystals_threshold::{generate_with_dealer, PrivateKeyShare, ThresholdConfig};

// 4 MiB: comfortably above the deserializer's frame (one share entry is
// ~15 KiB of coefficients plus the map and header locals).
const STACK_BYTES: usize = 4 * 1024 * 1024;

/// Serialized `PrivateKeyShare` header layout for a 3-participant share:
/// party_id (4) || total_parties (4) || threshold (4) || participant list
/// (4 + 3*4) || key (32) || rho (32) || tr (64) || shares len (4) || entries.
/// Each entry is mask (2) || s1 || s2 with 4-byte little-endian coefficients.
const KEY_RANGE: core::ops::Range<usize> = 28..60;
const RHO_RANGE: core::ops::Range<usize> = 60..92;
const TR_RANGE: core::ops::Range<usize> = 92..156;
const ENTRIES_OFFSET: usize = 160;

/// Run one failing-import scenario and return the names of leaked patterns.
fn probe_failed_import(blob: &[u8], patterns: &[(&str, &[u8])]) -> Vec<String> {
	probe_stack_for_named(STACK_BYTES, patterns, || {
		let result: Result<PrivateKeyShare, _> = borsh::from_slice(blob);
		assert!(result.is_err(), "tampered blob must be rejected");
	})
}

#[test]
fn failed_share_import_leaves_no_secret_copies_on_the_stack() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let (_pk, shares) =
		generate_with_dealer(&[0x3Cu8; 32], config).expect("dealer keygen succeeds");
	let blob = borsh::to_vec(&shares[0]).expect("share serializes");

	// Pin the layout assumptions behind the pattern offsets: a 2-of-3 share
	// for party 0 holds exactly the two size-2 subsets containing dkg index
	// 0, and the entries follow a 160-byte header.
	let entry_count =
		u32::from_le_bytes(blob[ENTRIES_OFFSET - 4..ENTRIES_OFFSET].try_into().unwrap());
	assert_eq!(entry_count, 2, "layout drift: expected 2 share entries");
	let entry_size = (blob.len() - ENTRIES_OFFSET) / 2;
	assert_eq!(
		ENTRIES_OFFSET + 2 * entry_size,
		blob.len(),
		"layout drift: entries region is not two equal entries"
	);
	assert_eq!((entry_size - 2) % 1024, 0, "layout drift: entry is not mask + whole polynomials");

	// Scan patterns, taken from the heap-resident blob so the probe closure
	// never touches them: the three header secrets, plus the last 64
	// serialized coefficients of the final share's s2 (stopping 4 bytes
	// short of the end, which scenario A tampers with).
	let key_pattern = &blob[KEY_RANGE];
	let rho_pattern = &blob[RHO_RANGE];
	let tr_pattern = &blob[TR_RANGE];
	let coeff_pattern = &blob[blob.len() - 260..blob.len() - 4];
	let patterns: [(&str, &[u8]); 4] = [
		("key", key_pattern),
		("rho", rho_pattern),
		("tr", tr_pattern),
		("share coefficients", coeff_pattern),
	];

	// Sanity: the technique detects an unwiped copy. A closure that
	// deliberately leaves the key seed in a dead stack frame must be seen.
	let mut leaked_key = [0u8; 32];
	leaked_key.copy_from_slice(key_pattern);
	assert_eq!(
		probe_stack_for_named(STACK_BYTES, &patterns, move || {
			core::hint::black_box(&leaked_key);
		}),
		vec!["key".to_string()],
		"probe self-check: a deliberately leaked stack copy was not detected"
	);

	// Scenario A: the blob parses completely — header secrets, both share
	// entries — and is rejected by the very last SecretShareData range
	// check, because the final s2 coefficient is out of range. Everything
	// secret has been read by the time the error propagates.
	let mut out_of_range = blob.clone();
	let n = out_of_range.len();
	out_of_range[n - 4..].copy_from_slice(&i32::MAX.to_le_bytes());
	let leaked = probe_failed_import(&out_of_range, &patterns);
	assert!(
		leaked.is_empty(),
		"rejected share import (out-of-range coefficient) left secrets in stack memory: {leaked:?}"
	);

	// Scenario B: the blob is truncated just before the final coefficient,
	// so the import dies with an EOF error mid-way through the last share's
	// s2 — after the header secrets and all scanned coefficients were read.
	let truncated = &blob[..blob.len() - 4];
	let leaked = probe_failed_import(truncated, &patterns);
	assert!(
		leaked.is_empty(),
		"rejected share import (truncated blob) left secrets in stack memory: {leaked:?}"
	);
}
