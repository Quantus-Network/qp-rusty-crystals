//! Regression test (security review): wormhole address derivation must never
//! free heap memory that still contains the secret.
//!
//! `generate_pair_from_secret` encodes the secret as Goldilocks felts and
//! copies them into a heap-backed `Vec` preimage for Poseidon hashing. That
//! vector used to be `clear()`ed — which resets the length but does not touch
//! the backing allocation — so the felt-encoded secret survived in freed heap
//! memory after the pair's own zeroizing wrappers had done their job.
//!
//! The test installs a global allocator that scans every block for the secret
//! pattern at `dealloc` time (the block is still valid inside the hook, so the
//! scan is sound) and asserts that no secret-bearing block is ever freed while
//! derivation runs. This file contains exactly one test so no unrelated
//! concurrent allocations can race the scanner.

use core::sync::atomic::{AtomicBool, Ordering};
use std::{
	alloc::{GlobalAlloc, Layout, System},
	sync::OnceLock,
};

use qp_rusty_crystals_hdwallet::wormhole::WormholePair;

/// Seed for `generate_new`. The scanned pattern is not the seed itself but
/// the *derived* secret (`hash_bytes(seed)`): that is what the derivation
/// felt-encodes into the heap-backed Poseidon preimage, and its 8-byte
/// little-endian limbs are canonical field elements by construction, so
/// `bytes_to_digest_lossy` stores them verbatim in the felt buffer.
const SEED_PATTERN: [u8; 32] = *b"wormhole-heap-zeroize-pattern-32";

/// The derived secret, learned from a reference run with the scanner off.
/// Derivation is deterministic, so the probed run reproduces these bytes.
static DERIVED_SECRET: OnceLock<[u8; 32]> = OnceLock::new();

static SCANNING: AtomicBool = AtomicBool::new(false);
static SECRET_FREED_UNCLEARED: AtomicBool = AtomicBool::new(false);

struct SecretScanningAllocator;

unsafe impl GlobalAlloc for SecretScanningAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		unsafe { System.alloc(layout) }
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		if SCANNING.load(Ordering::SeqCst) {
			if let Some(pattern) = DERIVED_SECRET.get() {
				if layout.size() >= pattern.len() {
					let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
					if block.windows(pattern.len()).any(|w| w == pattern) {
						SECRET_FREED_UNCLEARED.store(true, Ordering::SeqCst);
					}
				}
			}
		}
		unsafe { System.dealloc(ptr, layout) }
	}
}

#[global_allocator]
static ALLOCATOR: SecretScanningAllocator = SecretScanningAllocator;

#[test]
fn wormhole_derivation_never_frees_heap_memory_containing_the_secret() {
	// Reference run (scanner off) to learn the derived secret bytes.
	let mut seed = SEED_PATTERN;
	let reference = WormholePair::generate_new(&mut (&mut seed).into());
	DERIVED_SECRET.set(*reference.secret.as_bytes()).expect("set once");
	drop(reference);

	let mut seed = SEED_PATTERN;
	SCANNING.store(true, Ordering::SeqCst);
	let pair = WormholePair::generate_new(&mut (&mut seed).into());
	drop(pair);
	SCANNING.store(false, Ordering::SeqCst);

	assert!(
		!SECRET_FREED_UNCLEARED.load(Ordering::SeqCst),
		"wormhole derivation freed a heap block still containing the secret \
		 (felt-encoded preimage); the secret grants control of the derived \
		 address, so it must be zeroized before its memory is released"
	);
}
