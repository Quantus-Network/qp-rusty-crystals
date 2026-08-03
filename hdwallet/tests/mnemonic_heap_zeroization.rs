//! Regression test (security review): the mnemonic phrase returned by
//! `generate_mnemonic` must not survive in freed heap memory after the caller
//! drops it.
//!
//! `generate_mnemonic` used to return the recovery phrase as a plain
//! `String`, which does not zeroize its backing allocation on drop. The crate's
//! security model keeps every other secret (entropy, seeds, keys) inside
//! self-zeroizing wrappers, so a caller had no type-level hint that the one
//! secret that yields the *entire* wallet — the 24-word phrase — was their job
//! to erase. Returning `Zeroizing<String>` closes that custody gap: moving the
//! wrapper only copies the (ptr, len, cap) triple, and the heap contents are
//! wiped before the allocation is released.
//!
//! Detection uses the same technique as `wormhole_zeroization.rs`: a global
//! allocator that scans every block for the phrase bytes at `dealloc` time
//! (the block is still valid inside the hook, so the scan is sound). This file
//! contains exactly one test so no unrelated concurrent allocations can race
//! the scanner.

use core::sync::atomic::{AtomicBool, Ordering};
use std::{
	alloc::{GlobalAlloc, Layout, System},
	sync::OnceLock,
};

use qp_rusty_crystals_hdwallet::{generate_mnemonic, SensitiveBytes32};

/// Deterministic entropy: generation is deterministic in the entropy, so a
/// reference run (scanner off) reproduces the exact phrase bytes to scan for.
const ENTROPY: [u8; 32] = *b"mnemonic-heap-zeroize-pattern-32";

/// The generated phrase, learned from the reference run.
static PHRASE_PATTERN: OnceLock<Vec<u8>> = OnceLock::new();

static SCANNING: AtomicBool = AtomicBool::new(false);
static PHRASE_FREED_UNCLEARED: AtomicBool = AtomicBool::new(false);

struct SecretScanningAllocator;

unsafe impl GlobalAlloc for SecretScanningAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		unsafe { System.alloc(layout) }
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		if SCANNING.load(Ordering::SeqCst) {
			if let Some(pattern) = PHRASE_PATTERN.get() {
				if layout.size() >= pattern.len() {
					let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
					if block.windows(pattern.len()).any(|w| w == &pattern[..]) {
						PHRASE_FREED_UNCLEARED.store(true, Ordering::SeqCst);
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
fn generated_mnemonic_never_survives_in_freed_heap_memory() {
	// Reference run (scanner off) to learn the phrase bytes.
	let mut entropy = ENTROPY;
	let reference = generate_mnemonic(SensitiveBytes32::from(&mut entropy)).unwrap();
	assert_eq!(reference.split_whitespace().count(), 24);
	PHRASE_PATTERN.set(reference.as_bytes().to_vec()).expect("set once");
	drop(reference);

	// Probed run: generate the phrase and drop it, as a caller who has
	// finished with it (e.g. displayed it once) would. Every heap block
	// freed in this window — including the phrase's own allocation — must
	// no longer contain the phrase bytes.
	let mut entropy = ENTROPY;
	SCANNING.store(true, Ordering::SeqCst);
	let phrase = generate_mnemonic(SensitiveBytes32::from(&mut entropy)).unwrap();
	core::hint::black_box(&phrase);
	drop(phrase);
	SCANNING.store(false, Ordering::SeqCst);

	assert!(
		!PHRASE_FREED_UNCLEARED.load(Ordering::SeqCst),
		"generate_mnemonic()'s returned phrase survived in freed heap memory \
		 after the caller dropped it; the recovery phrase yields the entire HD \
		 wallet, so it must be zeroized before its allocation is released"
	);
}
