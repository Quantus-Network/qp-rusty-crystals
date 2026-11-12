//! Regression test (security review): NFKD-normalizing a secret passphrase or
//! mnemonic must not leave any of the normalized text in freed heap memory.
//!
//! BIP-39 hashes both strings in NFKD form, so an input that is not already
//! normalized (a composed `é`, an ideographic space between words) gets a
//! normalized copy. That copy used to be `collect()`ed into a growing
//! `String`: every time the buffer was outgrown, its contents — a prefix of
//! the normalized secret — were copied into a larger block and the old block
//! was freed as it was. `Zeroizing` only ever wipes the final allocation. The
//! copy is now allocated once, at its final size.
//!
//! The decomposition iterator of `unicode-normalization` leaked the same way:
//! it buffers pending characters as (class, character) pairs, moves that
//! buffer to the heap once more than four are pending, and frees it unwiped.
//! The normalization no longer goes through that iterator.
//!
//! Detection uses the same technique as `wormhole_zeroization.rs`: a global
//! allocator that scans every block at `dealloc` time (the block is still
//! valid inside the hook, so the scan is sound), here for the longest prefix
//! of each watched text and the longest run of the passphrase's characters.
//! This file contains exactly one test so no unrelated concurrent allocations
//! can race the scanner.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::{
	alloc::{GlobalAlloc, Layout, System},
	sync::OnceLock,
};

use qp_rusty_crystals_hdwallet::{mnemonic_to_seed, SensitiveBytes64};
use unicode_normalization::UnicodeNormalization;

/// Already NFKD, so it is also what the phrase below normalizes to.
const MNEMONIC: &str =
	"legal winner thank year wave sausage worth useful legal winner thank yellow";
/// Not NFKD: every composed letter decomposes into a base letter and a
/// combining mark, and U+FDFA into eighteen characters, more than the
/// decomposition iterator keeps outside the heap.
const PASSPHRASE: &str =
	"crème brûlée à la façon d'Ésope, naïveté coöpérative, señor Ångström \u{fdfa}";
/// Normalized the same way but never used: the scan must not report it.
const UNRELATED: &str = "pâté à l'ancienne, garçon, s'il vous plaît; piñata über alles";

/// Shortest prefix of a watched text the scan reports.
const MIN_PREFIX: usize = 8;
/// Shortest run of consecutive passphrase characters the scan reports.
const MIN_CHARS: usize = 4;

const PASSPHRASE_SLOT: usize = 0;
const MNEMONIC_SLOT: usize = 1;
const UNRELATED_SLOT: usize = 2;

/// The watched texts in NFKD form, indexed by slot.
static WATCHED: OnceLock<[Vec<u8>; 3]> = OnceLock::new();
/// The normalized passphrase as characters.
static WATCHED_CHARS: OnceLock<Vec<char>> = OnceLock::new();
/// Longest prefix of each watched text seen in a block freed while scanning.
static LONGEST_FREED_PREFIX: [AtomicUsize; 3] =
	[AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)];
/// Longest run of passphrase characters seen in a block freed while scanning.
static LONGEST_FREED_CHAR_RUN: AtomicUsize = AtomicUsize::new(0);

static SCANNING: AtomicBool = AtomicBool::new(false);

/// Length of the longest prefix of `text` (at least `MIN_PREFIX` bytes)
/// occurring anywhere in `block`, or 0.
fn longest_prefix_in(block: &[u8], text: &[u8]) -> usize {
	block
		.windows(MIN_PREFIX)
		.enumerate()
		.filter(|(_, window)| *window == &text[..MIN_PREFIX])
		.map(|(at, _)| block[at..].iter().zip(text).take_while(|(a, b)| a == b).count())
		.max()
		.unwrap_or(0)
}

/// Length of the longest run of consecutive `chars` (at least `MIN_CHARS`)
/// stored in `block` as 32-bit values `stride` bytes apart, or 0: 4 for a
/// buffer of characters, 8 for one of (class, character) pairs.
fn longest_char_run_in(block: &[u8], chars: &[char], stride: usize) -> usize {
	let stored = |at: usize| {
		block.get(at..at + 4).map(|bytes| u32::from_ne_bytes(bytes.try_into().unwrap()))
	};
	let run_at = |at: usize, first: usize| {
		chars[first..]
			.iter()
			.enumerate()
			.take_while(|(n, c)| stored(at + stride * n) == Some(u32::from(**c)))
			.count()
	};
	(0..block.len())
		.flat_map(|at| (0..chars.len()).map(move |first| (at, first)))
		.map(|(at, first)| run_at(at, first))
		.filter(|run| *run >= MIN_CHARS)
		.max()
		.unwrap_or(0)
}

struct SecretScanningAllocator;

unsafe impl GlobalAlloc for SecretScanningAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		unsafe { System.alloc(layout) }
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		if SCANNING.load(Ordering::SeqCst) {
			let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
			if let Some(watched) = WATCHED.get() {
				for (text, longest) in watched.iter().zip(&LONGEST_FREED_PREFIX) {
					longest.fetch_max(longest_prefix_in(block, text), Ordering::SeqCst);
				}
			}
			if let Some(chars) = WATCHED_CHARS.get() {
				for stride in [4, 8] {
					LONGEST_FREED_CHAR_RUN
						.fetch_max(longest_char_run_in(block, chars, stride), Ordering::SeqCst);
				}
			}
		}
		// Every block is wiped once it has been looked at, so nothing this
		// test frees itself (its own normalized copies, the planted blocks)
		// can show up again in a block the library reuses and frees later.
		unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
		unsafe { System.dealloc(ptr, layout) }
	}
}

#[global_allocator]
static ALLOCATOR: SecretScanningAllocator = SecretScanningAllocator;

/// Run `f` with the scanner on and return the longest prefix of each watched
/// text and the longest run of passphrase characters found in the blocks it
/// freed.
fn longest_freed(f: impl FnOnce()) -> ([usize; 3], usize) {
	SCANNING.store(true, Ordering::SeqCst);
	f();
	SCANNING.store(false, Ordering::SeqCst);
	(
		core::array::from_fn(|slot| LONGEST_FREED_PREFIX[slot].swap(0, Ordering::SeqCst)),
		LONGEST_FREED_CHAR_RUN.swap(0, Ordering::SeqCst),
	)
}

#[test]
fn normalized_secrets_never_survive_in_freed_heap_memory() {
	let normalized_passphrase: String = PASSPHRASE.nfkd().collect();
	assert_ne!(normalized_passphrase, PASSPHRASE, "the test passphrase must not be NFKD");
	// Ideographic spaces normalize to plain ones: a non-NFKD spelling of
	// `MNEMONIC`, sharing no reportable prefix with it.
	let mnemonic = MNEMONIC.replace(' ', "\u{3000}");
	WATCHED_CHARS.set(normalized_passphrase.chars().collect()).expect("set once");
	WATCHED
		.set([
			normalized_passphrase.into_bytes(),
			MNEMONIC.as_bytes().to_vec(),
			UNRELATED.nfkd().collect::<String>().into_bytes(),
		])
		.expect("set once");
	let watched = WATCHED.get().unwrap();
	let chars = WATCHED_CHARS.get().unwrap();

	// Sanity: the scan sees a block freed with part of a watched text in it,
	// in each of the three forms, measures it, and reports nothing else.
	let planted_len = watched[PASSPHRASE_SLOT].len() / 2;
	let planted = watched[PASSPHRASE_SLOT][..planted_len].to_vec();
	let mut expected = [0; 3];
	expected[PASSPHRASE_SLOT] = planted_len;
	assert_eq!(longest_freed(|| drop(planted)), (expected, 0), "probe self-check failed");
	let planted_chars = chars[..chars.len() / 2].to_vec();
	let planted_pairs: Vec<(u8, char)> = chars[..chars.len() / 3].iter().map(|c| (0, *c)).collect();
	assert_eq!(longest_freed(|| drop(planted_chars)), ([0; 3], chars.len() / 2));
	assert_eq!(longest_freed(|| drop(planted_pairs)), ([0; 3], chars.len() / 3));

	// Probed run: both inputs take the normalizing path. Every heap block
	// freed in this window must be free of the normalized texts.
	let (leaked, leaked_chars) = longest_freed(|| {
		let mut seed = SensitiveBytes64::zeroed();
		mnemonic_to_seed(mnemonic, Some(PASSPHRASE), &mut seed).unwrap();
		core::hint::black_box(&seed);
	});
	assert_eq!(leaked[UNRELATED_SLOT], 0, "an unrelated text was reported");
	assert_eq!(
		(leaked[PASSPHRASE_SLOT], leaked[MNEMONIC_SLOT]),
		(0, 0),
		"mnemonic_to_seed() freed heap memory still holding a prefix of the normalized \
		 (passphrase, mnemonic) of this many bytes, out of ({}, {})",
		watched[PASSPHRASE_SLOT].len(),
		watched[MNEMONIC_SLOT].len()
	);
	assert_eq!(
		leaked_chars,
		0,
		"mnemonic_to_seed() freed heap memory still holding this many consecutive characters of \
		 the normalized passphrase, out of {}",
		chars.len()
	);
}
