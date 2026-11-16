//! Regression test (security review): `generate_mnemonic` must not leak the
//! phrase through freed buffers of *word pointers* either.
//!
//! The phrase-byte probe (`mnemonic_heap_zeroization.rs`) only catches UTF-8
//! copies of the phrase. But `generate_mnemonic` used to build the phrase via
//! `words.collect::<Vec<&str>>().join(" ")`, which parks 24 fat pointers
//! (address + length, 384 bytes on 64-bit) into the *static* word list in a
//! heap buffer that `join` leaves behind unwiped. The word-list addresses are
//! fixed per process image, so the freed pointer sequence decodes right back
//! to the phrase — an alternate representation of the same secret, invisible
//! to a byte-level phrase scan.
//!
//! This probe learns the exact fat-pointer byte sequence by building the same
//! `Vec` against the library's word-list statics (the word indices come from
//! the reference bip39 implementation), then scans every block freed while
//! `generate_mnemonic` runs. Same dealloc-scanning technique as the phrase
//! probe; one test per file so no unrelated concurrent allocations race the
//! scanner.

use core::sync::atomic::{AtomicBool, Ordering};
use std::{
	alloc::{GlobalAlloc, Layout, System},
	sync::OnceLock,
};

use qp_rusty_crystals_hdwallet::{generate_mnemonic, mnemonic::WORD_LIST, SensitiveBytes32};

/// Deterministic entropy: same entropy => same words => same fat-pointer
/// sequence as inside `generate_mnemonic`.
const ENTROPY: [u8; 32] = *b"mnemonic-word-ptr-zeroize-32-pat";

/// The raw bytes of the 24 fat pointers, learned with the scanner off.
static POINTER_PATTERN: OnceLock<Vec<u8>> = OnceLock::new();

static SCANNING: AtomicBool = AtomicBool::new(false);
static POINTERS_FREED_UNCLEARED: AtomicBool = AtomicBool::new(false);

struct SecretScanningAllocator;

unsafe impl GlobalAlloc for SecretScanningAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		unsafe { System.alloc(layout) }
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		if SCANNING.load(Ordering::SeqCst) {
			if let Some(pattern) = POINTER_PATTERN.get() {
				if layout.size() >= pattern.len() {
					let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
					if block.windows(pattern.len()).any(|w| w == &pattern[..]) {
						POINTERS_FREED_UNCLEARED.store(true, Ordering::SeqCst);
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
fn generated_mnemonic_word_pointers_never_survive_in_freed_heap_memory() {
	// Reference run (scanner off): materialize the same Vec<&'static str>
	// the implementation builds internally and capture its raw bytes.
	let mnemonic = bip39::Mnemonic::from_entropy(&ENTROPY).expect("valid entropy");
	let words: Vec<&'static str> = mnemonic.word_indices().map(|i| WORD_LIST[i]).collect();
	assert_eq!(words.len(), 24);
	let pattern = unsafe {
		core::slice::from_raw_parts(
			words.as_ptr().cast::<u8>(),
			words.len() * core::mem::size_of::<&str>(),
		)
	}
	.to_vec();
	POINTER_PATTERN.set(pattern).expect("set once");
	drop(words); // freed with the scanner off: cannot self-trigger the probe

	// Probed run: every heap block freed while generate_mnemonic runs (and
	// while the caller drops the phrase) must not contain the pointer
	// sequence.
	let mut entropy = ENTROPY;
	SCANNING.store(true, Ordering::SeqCst);
	let phrase = generate_mnemonic(&mut SensitiveBytes32::from(&mut entropy)).unwrap();
	core::hint::black_box(&phrase);
	drop(phrase);
	SCANNING.store(false, Ordering::SeqCst);

	assert!(
		!POINTERS_FREED_UNCLEARED.load(Ordering::SeqCst),
		"generate_mnemonic() freed a buffer still holding the word fat-pointer \
		 sequence; the word-list addresses are fixed statics, so the \
		 pointer sequence decodes back to the full recovery phrase"
	);
}
