//! Regression test (security review): a full DKG run must not leave plaintext
//! copies of subset shared secrets K_S — or the subset seeds derived from
//! them via `h_keygen` — in dead stack memory.
//!
//! The companion heap test (`heap_zeroization.rs`) catches secret-bearing
//! heap blocks freed unwiped (transport frames, map nodes, queue buffers);
//! this probe covers the stack side. K_S is a `Copy` `[u8; 32]`, so it is
//! duplicated onto the stack every time it is squeezed, looked up out of a
//! map (`let Some(&shared_secret) = ...`), passed by value, or folded into a
//! derivation — copies that no drop reaches if codegen fails to elide them.
//! The `[u8; SUBSET_SEED_SIZE]` seed `h_keygen` derives from K_S is equally
//! sensitive (it deterministically expands to the subset's secret
//! contribution) and is bound to locals in `compute_my_contributions` and
//! `verify_partial_pk_commitment`, so it is probed with the same technique.
//!
//! Detection uses the same painted-stack technique as the dealer probe: run
//! all three parties of a deterministic 2-of-3 DKG to completion on a
//! sentinel-painted stack via `psm::on_stack`, then scan the buffer — which
//! we own, so the read is sound — for secrets learned from an identical,
//! unprobed first run (all randomness is SHAKE-derived from fixed per-party
//! seeds and a fixed session nonce, so the two runs produce byte-identical
//! secrets). The probed run never extracts secrets in harness code — capture
//! is compiled in only for the reference run — so the probe machinery cannot
//! plant a match itself.
//!
//! Only compiled for optimized builds (`cargo test --release`): unoptimized
//! codegen materializes additional compiler-generated move temporaries for
//! large by-value structs which no source-level fix can wipe, so a zero-copy
//! assertion is only meaningful once those are elided.
#![cfg(not(debug_assertions))]

use std::collections::BTreeMap;

use qp_rusty_crystals_test_utils::probe_stack_for_named;
use qp_rusty_crystals_threshold::{
	keygen::dkg::{
		h_keygen, Dkg, DkgAction, DkgConfig, DkgMessage, SubsetMask, TranscriptSigner,
		RANDOMNESS_SIZE, SHARED_SECRET_SIZE, SUBSET_SEED_SIZE,
	},
	ThresholdConfig,
};

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

/// Secrets recovered from the reference run's wire frames: every subset
/// shared secret K_S and every subset seed `h_keygen(S, K_S, R)` derived
/// from it.
struct CapturedSecrets {
	shared_secrets: Vec<[u8; SHARED_SECRET_SIZE]>,
	subset_seeds: Vec<[u8; SUBSET_SEED_SIZE]>,
}

/// Run a deterministic 2-of-3 DKG among three in-process parties. All
/// randomness is SHAKE-derived from the fixed per-party seeds and session
/// nonce, so every invocation produces byte-identical secrets and frames.
///
/// With `capture` set, records a copy of every exchanged frame and, after
/// completion, parses out each subset shared secret K_S (from the Round 1
/// private messages) and recomputes each subset seed via the public
/// `h_keygen` (global randomness R is the sorted concatenation of the
/// Round 2 broadcasts). With `capture` unset, no harness code ever touches
/// secret frame bytes, so the run is safe to execute inside the
/// painted-stack probe without planting the patterns itself.
fn run_local_dkg_2of3(capture: bool) -> Option<CapturedSecrets> {
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
	let mut captured_frames: Vec<Vec<u8>> = Vec::new();
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
				DkgAction::SendMany(data) => {
					if capture {
						captured_frames.push(data.clone());
					}
					for (j, queue) in queues.iter_mut().enumerate() {
						if j != i {
							queue.push((i as u32, data.clone()));
						}
					}
				},
				DkgAction::SendPrivate(to, mut data) => {
					// Round 1 private frames carry K_S. Only the reference
					// run copies them out — the probed run must never copy
					// secret bytes into harness stack frames.
					if capture {
						captured_frames.push(data.to_vec());
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
		Some(extract_secrets(&captured_frames))
	} else {
		None
	}
}

/// Parse the reference run's frames: pull each (subset, K_S) pair from the
/// Round 1 private messages and each party's randomness from the Round 2
/// broadcasts, then recompute every subset seed exactly as the protocol does
/// (`R` = randomness concatenated in ascending party order).
fn extract_secrets(frames: &[Vec<u8>]) -> CapturedSecrets {
	let mut per_subset_ks: BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]> = BTreeMap::new();
	let mut randomness: BTreeMap<u32, [u8; RANDOMNESS_SIZE]> = BTreeMap::new();
	for frame in frames {
		match borsh::from_slice::<DkgMessage>(frame).expect("captured frame deserializes") {
			DkgMessage::Round1Private(private) => {
				per_subset_ks.insert(private.subset_mask, private.shared_secret);
			},
			DkgMessage::Round2Broadcast(broadcast) => {
				randomness.insert(broadcast.party_id, broadcast.randomness);
			},
			_ => {},
		}
	}
	assert_eq!(per_subset_ks.len(), 3, "2-of-3 DKG exchanges K_S for all three subsets");
	assert_eq!(randomness.len(), 3, "all three parties broadcast randomness");

	// BTreeMap iterates in ascending party order, matching the protocol's
	// global-randomness construction.
	let global_randomness: Vec<u8> = randomness.values().flatten().copied().collect();

	let subset_seeds = per_subset_ks
		.iter()
		.map(|(&subset, ks)| h_keygen(subset, ks, &global_randomness))
		.collect();
	CapturedSecrets { shared_secrets: per_subset_ks.into_values().collect(), subset_seeds }
}

#[test]
fn dkg_leaves_no_secret_copies_on_the_stack() {
	// Reference run (unprobed): learn the secrets the probed run must wipe.
	let secrets = run_local_dkg_2of3(true).expect("reference run captures secrets");
	let mut patterns: Vec<(String, &[u8])> = Vec::new();
	for (i, ks) in secrets.shared_secrets.iter().enumerate() {
		patterns.push((format!("shared secret K_S #{i}"), ks.as_slice()));
	}
	for (i, seed) in secrets.subset_seeds.iter().enumerate() {
		patterns.push((format!("subset seed #{i}"), seed.as_slice()));
	}
	let named: Vec<(&str, &[u8])> =
		patterns.iter().map(|(name, bytes)| (name.as_str(), *bytes)).collect();

	// Sanity: the technique detects an unwiped copy. A closure that
	// deliberately leaves K_S in a dead stack frame must be seen.
	let planted = secrets.shared_secrets[0];
	assert!(
		!probe_stack_for_named(STACK_BYTES, &named, || {
			let leaked: [u8; SHARED_SECRET_SIZE] = planted;
			core::hint::black_box(&leaked);
		})
		.is_empty(),
		"probe self-check: a deliberately leaked stack copy was not detected"
	);

	// Real scenario: the identical DKG run, end to end, on the painted
	// stack. Every legitimate copy of K_S (and of the seeds derived from it)
	// lives in heap-backed state that is wiped on drop (verified by
	// heap_zeroization); anything left in the painted region is a stack copy
	// the protocol failed to wipe.
	let leaked = probe_stack_for_named(STACK_BYTES, &named, || {
		let _ = run_local_dkg_2of3(false);
	});
	assert!(leaked.is_empty(), "the DKG left plaintext secrets in stack memory: {leaked:?}");
}
