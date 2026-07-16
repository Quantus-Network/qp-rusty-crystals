//! Regression test (security review): key generation must never free heap
//! memory that still contains the input seed.
//!
//! `keypair` used to assemble the SHAKE preimage `seed || K || L` in a
//! growable `Vec` starting from `Vec::new()`: `extend_from_slice` allocated
//! exactly 32 bytes of capacity, so the two subsequent `push` calls forced a
//! reallocation that copied the seed to a new block and freed the original
//! without clearing it. The final `preimage.zeroize()` only wiped the
//! surviving allocation, leaving the raw seed — which deterministically
//! derives the entire keypair — recoverable from freed heap memory.
//!
//! The test installs a global allocator that scans every block for the seed
//! pattern at `dealloc` time (the block is still valid inside the hook, so
//! the scan is sound) and asserts that no seed-bearing block is ever freed
//! while key generation runs. This file contains exactly one test so no
//! unrelated concurrent allocations can race the scanner.

use core::sync::atomic::{AtomicBool, Ordering};
use std::alloc::{GlobalAlloc, Layout, System};

use qp_rusty_crystals_dilithium::{ml_dsa_87::Keypair, SensitiveBytes32};

/// Distinctive 32-byte pattern; a repeated single byte could false-positive
/// against unrelated allocator noise.
const SEED_PATTERN: [u8; 32] = *b"zeroize-regression-seed-pattern!";

static SCANNING: AtomicBool = AtomicBool::new(false);
static SEED_FREED_UNCLEARED: AtomicBool = AtomicBool::new(false);

struct SeedScanningAllocator;

unsafe impl GlobalAlloc for SeedScanningAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		unsafe { System.alloc(layout) }
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		if SCANNING.load(Ordering::SeqCst) && layout.size() >= SEED_PATTERN.len() {
			let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
			if block.windows(SEED_PATTERN.len()).any(|w| w == SEED_PATTERN) {
				SEED_FREED_UNCLEARED.store(true, Ordering::SeqCst);
			}
		}
		unsafe { System.dealloc(ptr, layout) }
	}
}

#[global_allocator]
static ALLOCATOR: SeedScanningAllocator = SeedScanningAllocator;

#[test]
fn keypair_never_frees_heap_memory_containing_the_seed() {
	let mut seed = SEED_PATTERN;
	let sensitive = SensitiveBytes32::new(&mut seed);

	SCANNING.store(true, Ordering::SeqCst);
	let keypair = Keypair::generate(sensitive);
	SCANNING.store(false, Ordering::SeqCst);

	assert!(
		!SEED_FREED_UNCLEARED.load(Ordering::SeqCst),
		"key generation freed a heap block still containing the raw seed; \
		 the seed deterministically derives the private key, so it must be \
		 zeroized before its memory is released"
	);

	// Sanity: generation still produces a working keypair.
	let message = b"zeroization regression";
	let signature = keypair.sign(message, None, None).expect("signing succeeds");
	assert!(keypair.public.verify(message, &signature, None));
}
