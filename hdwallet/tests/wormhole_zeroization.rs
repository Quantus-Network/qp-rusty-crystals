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
use std::alloc::{GlobalAlloc, Layout, System};

use qp_rusty_crystals_hdwallet::wormhole::WormholePair;

/// Distinctive 32-byte secret. Each 8-byte little-endian limb is below the
/// Goldilocks prime (high byte is ASCII < 0x80), so `bytes_to_digest_lossy`
/// stores the limbs verbatim and the felt buffer contains these exact bytes.
const SECRET_PATTERN: [u8; 32] = *b"wormhole-heap-zeroize-pattern-32";

static SCANNING: AtomicBool = AtomicBool::new(false);
static SECRET_FREED_UNCLEARED: AtomicBool = AtomicBool::new(false);

struct SecretScanningAllocator;

unsafe impl GlobalAlloc for SecretScanningAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		unsafe { System.alloc(layout) }
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		if SCANNING.load(Ordering::SeqCst) && layout.size() >= SECRET_PATTERN.len() {
			let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
			if block.windows(SECRET_PATTERN.len()).any(|w| w == SECRET_PATTERN) {
				SECRET_FREED_UNCLEARED.store(true, Ordering::SeqCst);
			}
		}
		unsafe { System.dealloc(ptr, layout) }
	}
}

#[global_allocator]
static ALLOCATOR: SecretScanningAllocator = SecretScanningAllocator;

#[test]
fn wormhole_derivation_never_frees_heap_memory_containing_the_secret() {
	let mut secret = SECRET_PATTERN;

	SCANNING.store(true, Ordering::SeqCst);
	let pair = WormholePair::verify([0u8; 32], (&mut secret).into());
	SCANNING.store(false, Ordering::SeqCst);

	assert!(
		!SECRET_FREED_UNCLEARED.load(Ordering::SeqCst),
		"wormhole derivation freed a heap block still containing the secret \
		 (felt-encoded preimage); the secret grants control of the derived \
		 address, so it must be zeroized before its memory is released"
	);

	// Sanity: the pattern secret does not verify against a zero address.
	assert!(!pair);
}
