//! Regression test (security review): `NewShareData` values stored in the
//! resharing B-tree maps must not leave sub-share coefficients in freed node
//! memory.
//!
//! The resharing protocol parks sub-shares in `BTreeMap`s — `my_subshares`
//! and the per-recipient Round 4 `contributions` maps. Unlike the DKG's
//! `round1_privates` buffer (where supported committee sizes keep the map
//! under the 11-entry node capacity), these maps blow far past it at
//! supported sizes: in a 3-of-6 → 3-of-6 reshare, `designated_dealer_for`
//! picks the lowest active member of each subset, so party 0 deals for all
//! C(5,2) = 10 old subsets containing it across C(6,4) = 15 new subsets —
//! 150 `my_subshares` entries — and a single recipient's `contributions` map
//! gets 10 × 10 = 100. Node splits are therefore *guaranteed*, and splits
//! move entries byte-wise between nodes: `ZeroizeOnDrop` wipes live values,
//! but the stale copies left behind by node operations are freed unwiped
//! when the nodes are released.
//!
//! This probe mirrors the map shape with the crate's real `NewShareData`
//! (via the `internal-test-helpers` constructor): insert 100 entries with
//! distinctive coefficients, drop the map, and scan every freed block for a
//! window of a mid-map entry's coefficient bytes. With values stored inline
//! it trips; with `Box<NewShareData>` values (the protocol's representation)
//! node operations move only pointers and the box wipes in place on drop.
//! One test per file so unrelated concurrent allocations cannot race the
//! scanner.

use core::sync::atomic::{AtomicBool, Ordering};
use std::{
	alloc::{GlobalAlloc, Layout, System},
	collections::BTreeMap,
	sync::OnceLock,
};

use qp_rusty_crystals_threshold::{
	params::{K, L, N},
	resharing::{NewShareData, SubsetPair},
};

const N_USIZE: usize = N as usize;

/// How many entries the probe inserts: one recipient's Round 4
/// `contributions` map in a 3-of-6 → 3-of-6 reshare holds exactly this many.
const ENTRIES: u16 = 100;

/// The entry whose coefficient bytes the scanner looks for. Mid-map, so it
/// sits in a node that participates in splits as the map grows.
const TARGET: u16 = 57;

/// Distinctive per-entry coefficient: high bytes are a marker, low bytes the
/// entry index, so a match cannot come from unrelated memory noise.
const fn coeff(idx: u16) -> i32 {
	0x11A5_0000_u32 as i32 | idx as i32
}

/// 64 bytes = 16 consecutive coefficients of the target entry.
static COEFF_PATTERN: OnceLock<Vec<u8>> = OnceLock::new();

static SCANNING: AtomicBool = AtomicBool::new(false);
static COEFFS_FREED_UNCLEARED: AtomicBool = AtomicBool::new(false);

struct SecretScanningAllocator;

unsafe impl GlobalAlloc for SecretScanningAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		unsafe { System.alloc(layout) }
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		if SCANNING.load(Ordering::SeqCst) {
			if let Some(pattern) = COEFF_PATTERN.get() {
				if layout.size() >= pattern.len() {
					let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
					if block.windows(pattern.len()).any(|w| w == &pattern[..]) {
						COEFFS_FREED_UNCLEARED.store(true, Ordering::SeqCst);
					}
				}
			}
		}
		unsafe { System.dealloc(ptr, layout) }
	}
}

#[global_allocator]
static ALLOCATOR: SecretScanningAllocator = SecretScanningAllocator;

fn make_share(idx: u16) -> NewShareData {
	let c = coeff(idx);
	NewShareData::testing_from_coefficients([[c; N_USIZE]; L], [[c; N_USIZE]; K])
}

#[test]
fn subshare_btree_nodes_never_free_unwiped_coefficients() {
	let mut pattern = Vec::with_capacity(64);
	for _ in 0..16 {
		pattern.extend_from_slice(&coeff(TARGET).to_le_bytes());
	}
	COEFF_PATTERN.set(pattern).expect("set once");

	// Same shape as the protocol's share maps (`my_subshares`, Round 4
	// `contributions`, `new_shares`): `Box`ed values, so node operations
	// move only pointers. Storing `NewShareData` inline here instead
	// reproduces the leak this test exists to prevent (stale coefficients
	// in freed nodes); a compile-time pin in the protocol's unit tests
	// keeps the real fields boxed. Keys are (old_subset, new_subset)
	// pairs; their exact values are irrelevant to node mechanics.
	SCANNING.store(true, Ordering::SeqCst);
	{
		let mut map: BTreeMap<SubsetPair, Box<NewShareData>> = BTreeMap::new();
		for idx in 0..ENTRIES {
			map.insert((idx, idx), Box::new(make_share(idx)));
		}
		core::hint::black_box(&map);
		// Drop: node blocks are freed; each box wipes its NewShareData in
		// place (ZeroizeOnDrop) before its allocation is released.
	}
	SCANNING.store(false, Ordering::SeqCst);

	assert!(
		!COEFFS_FREED_UNCLEARED.load(Ordering::SeqCst),
		"a freed B-tree node still held NewShareData coefficient bytes; \
		 node splits copy entries byte-wise, so sub-shares stored inline \
		 survive in freed node memory despite ZeroizeOnDrop on live values"
	);
}
