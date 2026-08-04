//! Regression test (security review): growth of the DKG `pending_privates`
//! queue must never free a buffer that still contains subset shared secrets.
//!
//! The queue held `(ParticipantId, Round1Private)` values in a plain `Vec`.
//! `Round1Private` is `ZeroizeOnDrop`, but that only wipes live elements in
//! their final resting place: when a `Vec` grows it copies its elements
//! bytewise into a new buffer and frees the old one without any drop or wipe,
//! so every reallocation stranded a buffer full of K_S values in freed heap
//! memory — past the reach of `pop_pending_private`'s slot wipe and the
//! `Drop`-time sweep, which both only touch the live buffer.
//!
//! The existing `heap_zeroization.rs` DKG scenario could not see this: its
//! 2-of-3 run queues at most 2 privates per party, within the `Vec`'s minimum
//! non-zero capacity of 4 for ~76-byte elements, so no reallocation ever
//! happened. This test runs a deterministic 2-of-5 DKG in which party 0 leads
//! four subsets of size 4 and queues 12 privates, forcing reallocations.
//!
//! Detection follows the established technique: a global allocator scans every
//! freed block — still valid inside the `dealloc` hook, so the read is sound —
//! for any K_S learned from an identical reference run (the protocol's
//! randomness is SHAKE-derived from the fixed seeds, so runs are
//! byte-identical). This file contains exactly one test so no unrelated
//! concurrent allocations can race the scanner.

use core::sync::atomic::{AtomicBool, Ordering};
use std::{
	alloc::{GlobalAlloc, Layout, System},
	collections::BTreeMap,
	sync::Mutex,
};

use qp_rusty_crystals_threshold::{
	keygen::dkg::{Dkg, DkgAction, DkgConfig, TranscriptSigner},
	ThresholdConfig,
};
use zeroize::Zeroizing;

/// All K_S values observed in the reference run (one per (leader, subset)
/// private delivery; 32 bytes each). Only written while scanning is off, so
/// `try_lock` in the hook never contends and never misses.
static PATTERNS: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());
static SCANNING: AtomicBool = AtomicBool::new(false);
static SECRET_FREED_UNCLEARED: AtomicBool = AtomicBool::new(false);
static LEAK_SIZE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

struct SecretScanningAllocator;

unsafe impl GlobalAlloc for SecretScanningAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		unsafe { System.alloc(layout) }
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		if SCANNING.load(Ordering::SeqCst) && layout.size() >= 32 {
			if let Ok(patterns) = PATTERNS.try_lock() {
				let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
				if block.windows(32).any(|w| patterns.iter().any(|p| w == p)) {
					SECRET_FREED_UNCLEARED.store(true, Ordering::SeqCst);
					LEAK_SIZE.store(layout.size(), Ordering::SeqCst);
				}
			}
		}
		unsafe { System.dealloc(ptr, layout) }
	}
}

#[global_allocator]
static ALLOCATOR: SecretScanningAllocator = SecretScanningAllocator;

/// Simple test signer for DKG transcript signing (mirrors the DKG unit-test
/// signer).
#[derive(Clone, Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct TestSigner {
	id: u32,
}

impl TranscriptSigner for TestSigner {
	type Signature = Vec<u8>;
	type PublicKey = u32;

	fn sign(&self, hash: &[u8; 32]) -> Self::Signature {
		let mut sig = vec![0u8; 36];
		sig[..4].copy_from_slice(&self.id.to_le_bytes());
		sig[4..36].copy_from_slice(hash);
		sig
	}

	fn verify(pk: &Self::PublicKey, hash: &[u8; 32], sig: &Self::Signature) -> bool {
		Self::verify_bytes(pk, hash, sig)
	}

	fn verify_bytes(pk: &Self::PublicKey, hash: &[u8; 32], sig: &[u8]) -> bool {
		if sig.len() < 36 {
			return false;
		}
		let sig_id = u32::from_le_bytes(sig[..4].try_into().unwrap());
		sig_id == *pk && &sig[4..36] == hash
	}

	fn public_key(&self) -> Self::PublicKey {
		self.id
	}
}

/// Run a deterministic 2-of-5 DKG locally, returning every K_S observed on
/// the wire (the last 32 bytes of each Round 1 private frame). With n=5 and
/// t=2, subsets have size n-t+1 = 4; party 0 is the leader (lowest id) of all
/// C(4,3) = 4 subsets containing it and queues 4 x 3 = 12 privates, driving
/// the queue through at least one reallocation.
///
/// The collected secrets are themselves kept leak-free so the scanner only
/// sees the protocol's behavior: the collection Vec is allocated at its exact
/// final size (its own growth would free unwiped intermediate buffers) and
/// wrapped in `Zeroizing` (its drop in the scanned run must wipe the copies).
fn run_local_dkg_2of5() -> Zeroizing<Vec<[u8; 32]>> {
	let threshold_config = ThresholdConfig::new(2, 5).expect("valid config");
	let participants: Vec<u32> = vec![0, 1, 2, 3, 4];
	let pk_map: BTreeMap<u32, u32> = participants.iter().map(|&p| (p, p)).collect();
	let session_nonce = [0x4Du8; 32];

	let mut dkgs: Vec<_> = participants
		.iter()
		.map(|&party_id| {
			let config = DkgConfig::new(
				threshold_config,
				party_id,
				participants.clone(),
				TestSigner { id: party_id },
				pk_map.clone(),
			)
			.expect("valid DKG config");
			let mut seed = [0xB2u8; 32];
			seed[0] = party_id as u8;
			Dkg::new(config, seed, &session_nonce)
		})
		.collect();

	let mut queues: Vec<Vec<(u32, Vec<u8>)>> = vec![Vec::new(); participants.len()];
	// Exactly 15 private deliveries occur (see the assertion below).
	let mut ks_values: Zeroizing<Vec<[u8; 32]>> = Zeroizing::new(Vec::with_capacity(15));
	let mut done = vec![false; participants.len()];
	for _ in 0..1000 {
		if done.iter().all(|&d| d) {
			break;
		}
		for i in 0..dkgs.len() {
			if done[i] {
				continue;
			}
			for (from, data) in std::mem::take(&mut queues[i]) {
				dkgs[i].message(from, data).expect("message is processed");
			}
			match dkgs[i].poke().expect("poke succeeds") {
				DkgAction::Wait => {},
				DkgAction::SendMany(data) =>
					for (j, queue) in queues.iter_mut().enumerate() {
						if j != i {
							queue.push((i as u32, data.clone()));
						}
					},
				DkgAction::SendPrivate(to, mut data) => {
					// Round 1 private frames carry K_S; the serialized tail
					// is the secret itself.
					if data.len() >= 32 {
						ks_values.push(data[data.len() - 32..].try_into().unwrap());
					}
					queues[to as usize].push((i as u32, std::mem::take(&mut *data)));
				},
				DkgAction::Return(_output) => {
					done[i] = true;
				},
			}
		}
	}
	assert!(done.iter().all(|&d| d), "DKG must complete");
	// 5 subsets x 3 recipients = 15 private deliveries, 12 of them queued by
	// party 0 — well past the queue's initial capacity of 4.
	assert_eq!(
		ks_values.len(),
		15,
		"test setup: expected party 0 to queue 12 of 15 private deliveries"
	);
	ks_values
}

#[test]
fn pending_privates_queue_growth_never_frees_unwiped_ks() {
	// Reference run (scanner off) to learn every K_S this deterministic
	// session produces. The static keeps plain copies, but it is never
	// deallocated, so the scanner cannot be tripped by it.
	let patterns = run_local_dkg_2of5();
	*PATTERNS.lock().unwrap() = patterns.to_vec();
	drop(patterns);

	SECRET_FREED_UNCLEARED.store(false, Ordering::SeqCst);
	SCANNING.store(true, Ordering::SeqCst);
	let _ = run_local_dkg_2of5();
	SCANNING.store(false, Ordering::SeqCst);

	assert!(
		!SECRET_FREED_UNCLEARED.load(Ordering::SeqCst),
		"a heap block ({} bytes) still containing a subset shared secret K_S was \
		 freed without being zeroized; growth of the pending_privates queue must \
		 not strand secrets in freed buffers",
		LEAK_SIZE.load(Ordering::SeqCst)
	);
}
