//! Regression test (security review): a full DKG run must not leave plaintext
//! copies of subset shared secrets K_S in dead stack memory.
//!
//! The companion heap test (`heap_zeroization.rs`) catches secret-bearing
//! heap blocks freed unwiped (transport frames, map nodes, queue buffers);
//! this probe covers the stack side. K_S is a `Copy` `[u8; 32]`, so it is
//! duplicated onto the stack every time it is squeezed, looked up out of a
//! map (`let Some(&shared_secret) = ...`), passed by value, or folded into a
//! derivation — copies that no drop reaches if codegen fails to elide them.
//!
//! Detection uses the same painted-stack technique as the dealer probe: run
//! all three parties of a deterministic 2-of-3 DKG to completion on a
//! sentinel-painted stack via `psm::on_stack`, then scan the buffer — which
//! we own, so the read is sound — for a K_S learned from an identical,
//! unprobed first run (all randomness is SHAKE-derived from fixed per-party
//! seeds and a fixed session nonce, so the two runs produce byte-identical
//! secrets). The probed run never extracts K_S in harness code — capture is
//! compiled in only for the reference run — so the probe machinery cannot
//! plant a match itself.
//!
//! Only compiled for optimized builds (`cargo test --release`): unoptimized
//! codegen materializes additional compiler-generated move temporaries for
//! large by-value structs which no source-level fix can wipe, so a zero-copy
//! assertion is only meaningful once those are elided.
#![cfg(not(debug_assertions))]

mod common;

use std::collections::BTreeMap;

use qp_rusty_crystals_threshold::{
	keygen::dkg::{Dkg, DkgAction, DkgConfig, TranscriptSigner},
	ThresholdConfig,
};

use common::probe_stack_for;

// 16 MiB: the DKG state machine drives keygen-scale work (K x L matrix
// expansion, NTT chains) for three parties plus serialization buffers.
const STACK_BYTES: usize = 16 * 1024 * 1024;

/// Simple test signer for DKG transcript signing.
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

/// Run a deterministic 2-of-3 DKG among three in-process parties. All
/// randomness is SHAKE-derived from the fixed per-party seeds and session
/// nonce, so every invocation produces byte-identical secrets and frames.
///
/// With `capture` set, returns a subset shared secret K_S — the last 32
/// bytes of the first Round 1 private frame (a subset leader delivering K_S
/// to the other member of a size-2 subset). With `capture` unset, no harness
/// code ever touches secret frame bytes, so the run is safe to execute
/// inside the painted-stack probe without planting the pattern itself.
fn run_local_dkg_2of3(capture: bool) -> Option<[u8; 32]> {
	let threshold_config = ThresholdConfig::new(2, 3).expect("valid config");
	let participants: Vec<u32> = vec![0, 1, 2];
	let pk_map: BTreeMap<u32, u32> = participants.iter().map(|&p| (p, p)).collect();
	let session_nonce = [0x3Eu8; 32];

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
			let mut seed = [0x90u8; 32];
			seed[0] = party_id as u8;
			Dkg::new(config, seed, &session_nonce)
		})
		.collect();

	let mut queues: Vec<Vec<(u32, Vec<u8>)>> = vec![Vec::new(); participants.len()];
	let mut ks_tail: Option<[u8; 32]> = None;
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
					// is the secret itself. Only the reference run extracts
					// it — the probed run must never copy secret bytes into
					// harness stack frames.
					if capture && ks_tail.is_none() && data.len() >= 32 {
						ks_tail = Some(data[data.len() - 32..].try_into().unwrap());
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
	if capture {
		Some(ks_tail.expect("a Round 1 private frame was exchanged"))
	} else {
		None
	}
}

#[test]
fn dkg_leaves_no_shared_secret_copies_on_the_stack() {
	// Reference run (unprobed): learn the K_S the probed run must wipe.
	let pattern = run_local_dkg_2of3(true).expect("reference run captures K_S");

	// Sanity: the technique detects an unwiped copy. A closure that
	// deliberately leaves K_S in a dead stack frame must be seen.
	assert!(
		probe_stack_for(STACK_BYTES, &pattern, || {
			let leaked: [u8; 32] = pattern;
			core::hint::black_box(&leaked);
		}),
		"probe self-check: a deliberately leaked stack copy was not detected"
	);

	// Real scenario: the identical DKG run, end to end, on the painted
	// stack. Every legitimate copy of K_S lives in heap-backed state that
	// is wiped on drop (verified by heap_zeroization); anything left in the
	// painted region is a stack copy the protocol failed to wipe.
	let leaked = probe_stack_for(STACK_BYTES, &pattern, || {
		let _ = run_local_dkg_2of3(false);
	});
	assert!(!leaked, "the DKG left a plaintext subset shared secret K_S in stack memory");
}
