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
//! Detection uses the same technique as `wormhole_zeroization.rs`: a global
//! allocator that scans every block at `dealloc` time (the block is still
//! valid inside the hook, so the scan is sound), here for the longest prefix
//! of each watched text. This file contains exactly one test so no unrelated
//! concurrent allocations can race the scanner.

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
/// combining mark.
const PASSPHRASE: &str = "crème brûlée à la façon d'Ésope, naïveté coöpérative, señor Ångström";
/// Normalized the same way but never used: the scan must not report it.
const UNRELATED: &str = "pâté à l'ancienne, garçon, s'il vous plaît; piñata über alles";

/// Shortest prefix of a watched text the scan reports.
const MIN_PREFIX: usize = 8;

const PASSPHRASE_SLOT: usize = 0;
const MNEMONIC_SLOT: usize = 1;
const UNRELATED_SLOT: usize = 2;

/// The watched texts in NFKD form, indexed by slot.
static WATCHED: OnceLock<[Vec<u8>; 3]> = OnceLock::new();
/// Longest prefix of each watched text seen in a block freed while scanning.
static LONGEST_FREED_PREFIX: [AtomicUsize; 3] =
	[AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)];

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

struct SecretScanningAllocator;

unsafe impl GlobalAlloc for SecretScanningAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		unsafe { System.alloc(layout) }
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		if SCANNING.load(Ordering::SeqCst) {
			if let Some(watched) = WATCHED.get() {
				let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
				for (text, longest) in watched.iter().zip(&LONGEST_FREED_PREFIX) {
					longest.fetch_max(longest_prefix_in(block, text), Ordering::SeqCst);
				}
			}
		}
		unsafe { System.dealloc(ptr, layout) }
	}
}

#[global_allocator]
static ALLOCATOR: SecretScanningAllocator = SecretScanningAllocator;

/// Run `f` with the scanner on and return the longest prefix of each watched
/// text found in the blocks it freed.
fn longest_freed_prefixes(f: impl FnOnce()) -> [usize; 3] {
	SCANNING.store(true, Ordering::SeqCst);
	f();
	SCANNING.store(false, Ordering::SeqCst);
	core::array::from_fn(|slot| LONGEST_FREED_PREFIX[slot].swap(0, Ordering::SeqCst))
}

#[test]
fn normalized_secrets_never_survive_in_freed_heap_memory() {
	let normalized_passphrase: String = PASSPHRASE.nfkd().collect();
	assert_ne!(normalized_passphrase, PASSPHRASE, "the test passphrase must not be NFKD");
	// Ideographic spaces normalize to plain ones: a non-NFKD spelling of
	// `MNEMONIC`, sharing no reportable prefix with it.
	let mnemonic = MNEMONIC.replace(' ', "\u{3000}");
	WATCHED
		.set([
			normalized_passphrase.into_bytes(),
			MNEMONIC.as_bytes().to_vec(),
			UNRELATED.nfkd().collect::<String>().into_bytes(),
		])
		.expect("set once");
	let watched = WATCHED.get().unwrap();

	// Sanity: the scan sees a block freed with part of a watched text in it,
	// measures it, and reports nothing else.
	let planted_len = watched[PASSPHRASE_SLOT].len() / 2;
	let planted = watched[PASSPHRASE_SLOT][..planted_len].to_vec();
	let mut expected = [0; 3];
	expected[PASSPHRASE_SLOT] = planted_len;
	assert_eq!(longest_freed_prefixes(|| drop(planted)), expected, "probe self-check failed");

	// Probed run: both inputs take the normalizing path. Every heap block
	// freed in this window must be free of the normalized texts.
	let leaked = longest_freed_prefixes(|| {
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
}
