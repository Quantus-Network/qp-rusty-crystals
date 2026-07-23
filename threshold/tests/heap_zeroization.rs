//! Regression tests (security review): secret-bearing intermediates must never
//! be freed while still containing key material.
//!
//! Several code paths copy secrets into ordinary heap-backed buffers:
//!
//! - `hash_secret_shares` (via `derive_dkg_contribution`) linearizes secret
//!   share polynomial coefficients into a reusable `Vec<u8>`;
//! - `Dkg::message` receives Round 1 private frames whose bytes contain the
//!   serialized subset secret K_S;
//! - `sample_hyperball` (via `ThresholdSigner::round1_commit_with_seed`)
//!   squeezes the per-signature mask randomness into a scratch `Vec<u8>`;
//! - the resharing protocol's `party_key` derivation linearizes the new
//!   committee share's polynomial coefficients into a reusable `Vec<u8>`.
//!
//! Ordinary vectors do not overwrite their backing allocation when cleared or
//! dropped, so each of these left secrets in allocator memory after the
//! structured zeroizing types had been wiped.
//!
//! The test installs a global allocator that scans every freed block for the
//! current scenario's secret pattern at `dealloc` time (the block is still
//! valid inside the hook, so the scan is sound). This file contains exactly
//! one test so no unrelated concurrent allocations can race the scanner.

use core::sync::atomic::{AtomicBool, Ordering};
use std::{
	alloc::{GlobalAlloc, Layout, System},
	collections::BTreeMap,
	sync::Mutex,
};

use qp_rusty_crystals_dilithium::fips202;
use qp_rusty_crystals_threshold::{
	derive_dkg_contribution, generate_with_dealer,
	keygen::dkg::{
		compute_dkg_ssid, Dkg, DkgAction, DkgConfig, DkgMessage, Round1Private, TranscriptSigner,
	},
	resharing::{Action, ResharingConfig},
	PrivateKeyShare, ThresholdConfig, ThresholdSigner,
};

mod common;

/// The 32-byte pattern the allocator currently scans for. Updated between
/// scenarios (only while scanning is off, so `try_lock` in the hook never
/// contends and never misses).
static PATTERN: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
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
			if let Ok(pattern) = PATTERN.try_lock() {
				let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
				if block.windows(32).any(|w| w == *pattern) {
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

/// Run `f` with the allocator scanning for `pattern`, and assert no freed
/// block still contained it.
fn assert_no_secret_bearing_free(scenario: &str, pattern: [u8; 32], f: impl FnOnce()) {
	*PATTERN.lock().unwrap() = pattern;
	SECRET_FREED_UNCLEARED.store(false, Ordering::SeqCst);
	SCANNING.store(true, Ordering::SeqCst);
	f();
	SCANNING.store(false, Ordering::SeqCst);
	assert!(
		!SECRET_FREED_UNCLEARED.load(Ordering::SeqCst),
		"{scenario}: a heap block ({} bytes) still containing secret material was freed \
		 without being zeroized",
		LEAK_SIZE.load(Ordering::SeqCst)
	);
}

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

/// Coefficient pattern for the share-digest scenario: eight i32 coefficients
/// whose little-endian bytes form a distinctive 32-byte sequence. Each value
/// is 0x003C5A4x (< Q), so the planted share passes the (-Q, Q) import check.
fn share_coefficient_pattern() -> [u8; 32] {
	let mut pattern = [0u8; 32];
	for i in 0..8 {
		pattern[4 * i..4 * i + 4].copy_from_slice(&[0x41 + i as u8, 0x5A, 0x3C, 0x00]);
	}
	pattern
}

/// A `PrivateKeyShare` whose last eight s2 coefficients are the pattern above:
/// serialize a dealer share, overwrite the trailing coefficient bytes, and
/// re-import through the public Borsh boundary.
fn share_with_planted_coefficients() -> PrivateKeyShare {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let (_pk, shares) = generate_with_dealer(&[0x42u8; 32], config).expect("keygen succeeds");

	let mut blob = borsh::to_vec(&shares[0]).expect("share serializes");
	let tail = blob.len() - 32;
	blob[tail..].copy_from_slice(&share_coefficient_pattern());
	borsh::from_slice(&blob).expect("planted share re-imports")
}

/// First 32 bytes of the SHAKE256 stream `sample_hyperball` squeezes into its
/// scratch buffer for iteration 0 of `round1_commit_with_seed(ssid, seed)`.
/// Recomputed here through the public fips202 API, mirroring the derivation in
/// `protocol/signing.rs` (iteration 0 leaves the seed unmodified).
fn hyperball_stream_pattern(ssid: &[u8; 32], seed: &[u8; 32]) -> [u8; 32] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, seed);
	fips202::shake256_absorb(&mut state, ssid);
	fips202::shake256_absorb(&mut state, b"rho_prime");
	fips202::shake256_absorb(&mut state, &[0u8]);
	fips202::shake256_finalize(&mut state);
	let mut iter_rho_prime = [0u8; 64];
	fips202::shake256_squeeze(&mut iter_rho_prime, &mut state);

	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, b"H");
	fips202::shake256_absorb(&mut state, &iter_rho_prime);
	fips202::shake256_absorb(&mut state, &0u16.to_le_bytes());
	fips202::shake256_finalize(&mut state);
	let mut pattern = [0u8; 32];
	fips202::shake256_squeeze(&mut pattern, &mut state);
	pattern
}

/// Run a deterministic 2-of-2 -> 2-of-2 resharing locally and return the new
/// share of party 0 plus the last 32 bytes of the first Round 4 transport
/// frame (raw sub-share s2 coefficients). All seeds are fixed, and the leader
/// is given the full expected active set, so two invocations produce
/// byte-identical shares and frames — which lets the caller learn the secret
/// coefficients from a first (unscanned) run and scan for them during a
/// second run.
fn run_local_reshare() -> (PrivateKeyShare, [u8; 32]) {
	let config = ThresholdConfig::new(2, 2).expect("valid config");
	let (pk, old_shares) = generate_with_dealer(&[0x51u8; 32], config).expect("keygen succeeds");
	let participants = vec![0u32, 1u32];
	let session_nonce = [0x7Bu8; 32];

	let mut protocols: Vec<_> = participants
		.iter()
		.map(|&party_id| {
			let rcfg = ResharingConfig::new(
				Some(old_shares[party_id as usize].clone()),
				2,
				participants.clone(),
				2,
				participants.clone(),
				party_id,
				pk.clone(),
			)
			.expect("valid resharing config");
			let mut seed = [0x60u8; 32];
			seed[0] = party_id as u8;
			common::new_test_protocol(rcfg, seed, &session_nonce)
		})
		.collect();

	// The leader proposes as soon as both old members commit; no transport
	// timeout is needed, keeping the run fully deterministic.
	protocols[0].set_expected_active_set(&participants).expect("leader accepts expected set");

	let mut queues: Vec<Vec<(u32, Vec<u8>)>> = vec![Vec::new(); participants.len()];
	// Tail of the first private (Round 4) frame observed: the final s2
	// coefficients of a raw sub-share, captured to a stack array so the
	// caller can later scan freed heap blocks for them.
	let mut round4_tail: Option<[u8; 32]> = None;
	for _ in 0..1000 {
		if protocols.iter().all(|p| p.is_done()) {
			break;
		}
		for i in 0..protocols.len() {
			if protocols[i].is_done() {
				continue;
			}
			for (from, data) in std::mem::take(&mut queues[i]) {
				protocols[i].message(from, data).expect("message is processed");
			}
			match protocols[i].poke().expect("poke succeeds") {
				Action::Wait | Action::Return(_) => {},
				Action::SendMany(data) => {
					for (j, queue) in queues.iter_mut().enumerate() {
						if j != i {
							queue.push((i as u32, data.clone()));
						}
					}
				},
				Action::SendPrivate(to, mut data) => {
					// The only private frames in this protocol are Round 4
					// sub-share deliveries.
					if round4_tail.is_none() && data.len() >= 32 {
						round4_tail = Some(data[data.len() - 32..].try_into().unwrap());
					}
					queues[to as usize].push((i as u32, std::mem::take(&mut *data)));
				},
			}
		}
	}
	assert!(protocols.iter().all(|p| p.is_done()), "resharing must complete");

	let share = protocols[0]
		.take_output()
		.expect("party 0 has an output")
		.private_share
		.expect("new committee member carries a share");
	(share, round4_tail.expect("a Round 4 private frame was exchanged"))
}

/// Run a deterministic 2-of-3 DKG locally and return a subset shared secret
/// K_S, captured as the last 32 bytes of the first Round 1 private frame (a
/// subset leader delivering K_S to another member; subsets have size
/// n-t+1 = 2 here, so privates are exchanged). All randomness is
/// SHAKE-derived from the fixed per-party seeds and session nonce, so two
/// invocations produce byte-identical secrets — a first (unscanned) run
/// reveals the K_S a second, scanned run must wipe.
fn run_local_dkg_2of3() -> [u8; 32] {
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
				DkgAction::SendMany(data) => {
					for (j, queue) in queues.iter_mut().enumerate() {
						if j != i {
							queue.push((i as u32, data.clone()));
						}
					}
				},
				DkgAction::SendPrivate(to, mut data) => {
					// Round 1 private frames carry K_S; the serialized tail
					// is the secret itself.
					if ks_tail.is_none() && data.len() >= 32 {
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
	ks_tail.expect("a Round 1 private frame was exchanged")
}

#[test]
fn secret_intermediates_are_wiped_before_their_heap_memory_is_freed() {
	// Scenario 1: hash_secret_shares linearization buffer.
	// The buffer holds every secret share coefficient in serialized form; it
	// used to be a plain Vec that was clear()ed and dropped unwiped.
	let share = share_with_planted_coefficients();
	assert_no_secret_bearing_free(
		"derive_dkg_contribution (share-digest buffer)",
		share_coefficient_pattern(),
		|| {
			let contribution = derive_dkg_contribution(&share, &[0x11u8; 32]);
			assert_ne!(contribution, [0u8; 32]);
		},
	);
	drop(share);

	// Scenario 2: incoming DKG transport frame carrying K_S.
	// An attacker cannot choose K_S, but the receiving node's own heap must
	// not retain the secret after Dkg::message returns, whatever the message's
	// fate (here: dropped for SSID mismatch, the earliest-exit path).
	let ks_pattern = *b"dkg-round1-private-ks-pattern-32";
	let threshold_config = ThresholdConfig::new(2, 3).expect("valid config");
	let participants: Vec<u32> = vec![0, 1, 2];
	let pk_map: BTreeMap<u32, u32> = participants.iter().map(|&p| (p, p)).collect();
	let config = DkgConfig::new(
		threshold_config,
		0,
		participants.clone(),
		TestSigner { id: 0 },
		pk_map,
	)
	.expect("valid DKG config");
	let session_nonce = [0xA5u8; 32];
	let ssid = compute_dkg_ssid(2, 3, &participants, &session_nonce);
	let mut dkg = Dkg::new(config, [0x77u8; 32], &session_nonce);

	let frame = borsh::to_vec(&DkgMessage::Round1Private(Round1Private {
		ssid: [0u8; 32], // wrong session: message is deserialized, then dropped
		from_party_id: 1,
		subset_mask: 0b011,
		shared_secret: ks_pattern,
	}))
	.expect("round1 private serializes");
	assert!(ssid != [0u8; 32], "test setup: frame must not match the real ssid");

	assert_no_secret_bearing_free("Dkg::message (Round 1 private frame)", ks_pattern, || {
		dkg.message(1, frame).expect("well-formed frame is processed");
	});
	drop(dkg);

	// Scenario 3: hyperball sampling scratch buffer.
	// The raw SHAKE stream that becomes the per-signature mask y was squeezed
	// into a plain Vec; leaking y alongside the published response z = y + c*s1
	// recovers the secret share.
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let (pk, shares) = generate_with_dealer(&[7u8; 32], config).expect("keygen succeeds");
	let mut signer =
		ThresholdSigner::new(shares.into_iter().next().unwrap(), pk, config).expect("signer");
	let sign_ssid = [0x5Cu8; 32];
	let round1_seed = [0x33u8; 32];

	assert_no_secret_bearing_free(
		"round1_commit_with_seed (hyperball XOF buffer)",
		hyperball_stream_pattern(&sign_ssid, &round1_seed),
		|| {
			signer
				.round1_commit_with_seed(&sign_ssid, &round1_seed)
				.expect("round 1 commit succeeds");
		},
	);
	drop(signer);

	// Scenario 4: resharing party_key linearization buffer.
	// build_private_key_share serializes every new share coefficient into a
	// scratch Vec to derive party_key; a plain Vec leaves those coefficients
	// in freed allocator memory (and its incremental growth frees unwiped
	// intermediate blocks). The run is deterministic, so a first unscanned
	// run reveals the coefficients the second, scanned run must wipe: the
	// pattern is the tail of the serialized share (the last s2 coefficients
	// of the highest subset mask), which is exactly the tail of the scratch
	// buffer's final contents.
	// The reference blob holds the real share, so wipe it before it is freed:
	// dropping it plain would plant the pattern in recycled allocator memory
	// and make the scanner flag stale bytes instead of a live leak.
	let (reference_share, round4_tail) = run_local_reshare();
	let blob = zeroize::Zeroizing::new(borsh::to_vec(&reference_share).expect("share serializes"));
	let mut reshare_pattern = [0u8; 32];
	reshare_pattern.copy_from_slice(&blob[blob.len() - 32..]);
	drop(blob);
	drop(reference_share);

	assert_no_secret_bearing_free(
		"resharing build_private_key_share (party-key buffer)",
		reshare_pattern,
		|| {
			let (share, _) = run_local_reshare();
			drop(share);
		},
	);

	// Scenario 5: resharing Round 4 transport frames.
	// The private frames carry raw sub-share coefficients; the frame buffer
	// must be wiped when the receiving protocol has consumed it (and the
	// sender-side serialization must not free unwiped intermediates).
	assert_no_secret_bearing_free(
		"resharing transport frames (Round 4 sub-shares)",
		round4_tail,
		|| {
			let (share, _) = run_local_reshare();
			drop(share);
		},
	);

	// Scenario 6: DKG K_S relocation out of Copy-typed containers.
	// The subset shared secret K_S is a Copy `[u8; 32]`, so moving it out of
	// a container leaves the source bytes intact: `transition_to_round2`
	// consumed `received_shared_secrets` and freed the map nodes unwiped
	// (past the reach of `DkgState::zeroize`, which finds the field already
	// None), and `pending_privates.pop()` left the queued `Round1Private`
	// bytes in the Vec buffer beyond the shrunken length, where the drop-time
	// wipe (which only covers live elements) cannot reach them. The run is
	// deterministic, so a first unscanned run reveals the K_S the scanned run
	// must have wiped from every freed block.
	let dkg_ks_pattern = run_local_dkg_2of3();
	assert_no_secret_bearing_free(
		"DKG K_S containers (received_shared_secrets map, pending_privates queue)",
		dkg_ks_pattern,
		|| {
			let _ = run_local_dkg_2of3();
		},
	);
}
