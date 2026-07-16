//! Audit regression test: `ResharingRound5Broadcast` deserialization must
//! bound the `error_message: Option<String>` field.
//!
//! The custom deserializer bounds `share_commitments` and `partial_pks`
//! against `MAX_SUBSETS`, but `error_message` was read through borsh's
//! default path with an attacker-controlled, unbounded u32 length prefix.
//! Two consequences, both checked here:
//!
//! 1. A ~90-byte truncated broadcast claiming a near-`u32::MAX` length forces
//!    every recipient to allocate borsh's internal 1 MiB first chunk before
//!    the truncation is detected — a >10,000x memory amplification per
//!    message. (borsh 1.6.1 caps the eager allocation at 1 MiB, so the
//!    original audit's 4 GiB-per-message OOM does not reproduce at this
//!    version, but the amplification and the missing bound are real.)
//! 2. A fully-delivered oversized `error_message` (up to 4 GiB) would be
//!    accepted and retained, unlike every other variable-length resharing
//!    field, which is explicitly bounded.
//!
//! This test lives in its own integration-test binary because it installs a
//! tracking global allocator; sharing the binary with unrelated tests would
//! add allocation noise from parallel test threads.

use std::{
	alloc::{GlobalAlloc, Layout, System},
	sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use borsh::{BorshDeserialize, BorshSerialize};
use qp_rusty_crystals_threshold::resharing::{
	ResharingRound5Broadcast, MAX_ERROR_MESSAGE_LEN, RESHARING_SSID_SIZE,
};

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

/// Serialize the fixed prefix of a Round 5 broadcast: ssid, party_id, empty
/// `share_commitments`, empty `partial_pks`, `success = false`.
fn round5_prefix() -> Vec<u8> {
	let mut buf = Vec::new();
	buf.extend_from_slice(&[0xABu8; RESHARING_SSID_SIZE]);
	buf.extend_from_slice(&1u32.to_le_bytes()); // party_id
	buf.extend_from_slice(&0u32.to_le_bytes()); // share_commitments: 0 entries
	buf.extend_from_slice(&0u32.to_le_bytes()); // partial_pks: 0 entries
	buf.push(0); // success = false
	buf
}

#[test]
fn round5_error_message_length_is_bounded() {
	// A tiny broadcast whose error_message length prefix claims ~4 GiB, with
	// only a few payload bytes actually delivered. Deserialization must
	// reject the claimed length up front instead of allocating a large
	// buffer and then discovering the truncation.
	let mut malicious = round5_prefix();
	malicious.push(1); // Option::Some flag
	malicious.extend_from_slice(&u32::MAX.to_le_bytes()); // claimed String length
	malicious.extend_from_slice(b"tiny"); // actual payload: 4 bytes

	let (result, max_alloc) =
		max_alloc_during(|| ResharingRound5Broadcast::try_from_slice(&malicious));
	assert!(result.is_err(), "truncated huge-length broadcast must be rejected");
	assert!(
		max_alloc < 64 * 1024,
		"a ~90-byte broadcast claiming a 4 GiB error_message forced a {max_alloc}-byte \
		 allocation before the length was rejected"
	);

	// A fully-delivered error_message one byte over the bound must also be
	// rejected: the serializer is unbounded, so build the bytes directly.
	let oversized = ResharingRound5Broadcast {
		ssid: [0xABu8; RESHARING_SSID_SIZE],
		party_id: 1,
		share_commitments: Default::default(),
		partial_pks: Default::default(),
		success: false,
		error_message: Some("x".repeat(MAX_ERROR_MESSAGE_LEN + 1)),
	};
	let mut bytes = Vec::new();
	oversized.serialize(&mut bytes).unwrap();
	assert!(
		ResharingRound5Broadcast::try_from_slice(&bytes).is_err(),
		"error_message longer than MAX_ERROR_MESSAGE_LEN must be rejected"
	);

	// A legitimate failure broadcast with a short message still round-trips.
	let legit = ResharingRound5Broadcast {
		ssid: [0xABu8; RESHARING_SSID_SIZE],
		party_id: 1,
		share_commitments: Default::default(),
		partial_pks: Default::default(),
		success: false,
		error_message: Some("Share verification failed".to_string()),
	};
	let mut bytes = Vec::new();
	legit.serialize(&mut bytes).unwrap();
	let decoded = ResharingRound5Broadcast::try_from_slice(&bytes)
		.expect("legitimate error_message must round-trip");
	assert_eq!(decoded.error_message.as_deref(), Some("Share verification failed"));
	assert!(!decoded.success);

	// And a success broadcast with no message still round-trips.
	let none = ResharingRound5Broadcast {
		ssid: [0xABu8; RESHARING_SSID_SIZE],
		party_id: 2,
		share_commitments: Default::default(),
		partial_pks: Default::default(),
		success: true,
		error_message: None,
	};
	let mut bytes = Vec::new();
	none.serialize(&mut bytes).unwrap();
	let decoded = ResharingRound5Broadcast::try_from_slice(&bytes)
		.expect("None error_message must round-trip");
	assert_eq!(decoded.error_message, None);
}
