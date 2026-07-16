//! Audit regression test: `round2_reveal` must validate the caller-controlled
//! message and context bounds *before* packing Round 1 commitment data.
//!
//! Packing allocates and serializes `k_iterations * SINGLE_COMMITMENT_SIZE`
//! bytes (about 9.4 MB for the 4-of-6 configuration). If the ML-DSA size
//! bounds are only enforced afterwards (inside `process_round2`), an attacker
//! can force that CPU and memory cost with a guaranteed-to-fail request, e.g.
//! a 256-byte context. This test observes the wasted work directly: it tracks
//! the largest single heap allocation made during the failing call and
//! requires it to stay below one packed commitment (5888 bytes).
//!
//! This test lives in its own integration-test binary because it installs a
//! tracking global allocator; sharing the binary with unrelated tests would
//! add allocation noise from parallel test threads.

use std::{
	alloc::{GlobalAlloc, Layout, System},
	sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use qp_rusty_crystals_threshold::{
	generate_with_dealer, ThresholdConfig, ThresholdError, ThresholdSigner,
};

/// Packed size of one commitment: K (8) polynomials of 736 bytes each.
/// Round 2 packing allocates `k_iterations` of these in a single buffer
/// (29,440 bytes for the 2-of-3 configuration used here).
const SINGLE_COMMITMENT_SIZE: usize = 8 * 736;

static TRACKING: AtomicBool = AtomicBool::new(false);
static MAX_ALLOC: AtomicUsize = AtomicUsize::new(0);

/// Wraps the system allocator, recording the largest single allocation made
/// while `TRACKING` is enabled.
struct MaxAllocTracker;

unsafe impl GlobalAlloc for MaxAllocTracker {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		if TRACKING.load(Ordering::Relaxed) {
			MAX_ALLOC.fetch_max(layout.size(), Ordering::Relaxed);
		}
		System.alloc(layout)
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		System.dealloc(ptr, layout)
	}
}

#[global_allocator]
static ALLOCATOR: MaxAllocTracker = MaxAllocTracker;

/// Run `f` with allocation tracking enabled and return the largest single
/// allocation observed during the call.
fn max_alloc_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
	MAX_ALLOC.store(0, Ordering::Relaxed);
	TRACKING.store(true, Ordering::Relaxed);
	let result = f();
	TRACKING.store(false, Ordering::Relaxed);
	(result, MAX_ALLOC.load(Ordering::Relaxed))
}

#[test]
fn round2_reveal_rejects_bad_inputs_before_commitment_packing() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let (public_key, shares) = generate_with_dealer(&[3u8; 32], config).expect("keygen");

	let mut s0 = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config).unwrap();
	let mut s1 = ThresholdSigner::new(shares[1].clone(), public_key.clone(), config).unwrap();

	let ssid = [0xA5u8; 32];
	let _r1_0 = s0.round1_commit_with_seed(&ssid, &[1u8; 32]).unwrap();
	let r1_1 = s1.round1_commit_with_seed(&ssid, &[2u8; 32]).unwrap();
	let others = core::slice::from_ref(&r1_1);

	// A context one byte over the 255-byte ML-DSA limit must be rejected
	// before the k * SINGLE_COMMITMENT_SIZE packing buffer is allocated.
	let oversized_context = vec![0u8; 256];
	let (result, max_alloc) =
		max_alloc_during(|| s0.round2_reveal(&ssid, b"message", &oversized_context, others));
	assert!(
		matches!(result, Err(ThresholdError::ContextTooLong { length: 256 })),
		"expected ContextTooLong, got {result:?}"
	);
	assert!(
		max_alloc < SINGLE_COMMITMENT_SIZE,
		"oversized context still triggered commitment packing: \
		 largest allocation during the rejected call was {max_alloc} bytes \
		 (>= one packed commitment of {SINGLE_COMMITMENT_SIZE} bytes)"
	);

	// Same for an oversized message.
	let oversized_message =
		vec![0u8; qp_rusty_crystals_dilithium::ml_dsa_87::MAX_MESSAGE_SIZE + 1];
	let (result, max_alloc) =
		max_alloc_during(|| s0.round2_reveal(&ssid, &oversized_message, b"", others));
	assert!(
		matches!(result, Err(ThresholdError::MessageTooLong { .. })),
		"expected MessageTooLong, got {result:?}"
	);
	assert!(
		max_alloc < SINGLE_COMMITMENT_SIZE,
		"oversized message still triggered commitment packing: \
		 largest allocation during the rejected call was {max_alloc} bytes \
		 (>= one packed commitment of {SINGLE_COMMITMENT_SIZE} bytes)"
	);

	// The rejected attempts must not have consumed the session: a well-formed
	// request still succeeds.
	s0.round2_reveal(&ssid, b"message", b"context", others)
		.expect("valid inputs must still be accepted after rejected attempts");
}
