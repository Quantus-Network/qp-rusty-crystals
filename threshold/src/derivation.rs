//! Key derivation utilities for threshold Dilithium.
//!
//! This module provides functions for deriving DKG contributions from master keys
//! in a threshold-secure manner. Unlike ECC schemes where derivation is linear
//! (derived_share = master_share + tweak), Dilithium requires running a full
//! DKG protocol for each derived key.
//!
//! # Architecture
//!
//! For Dilithium key derivation:
//! 1. Each party derives a DKG contribution from their master share + tweak
//! 2. Parties run full DKG using these contributions for randomness
//! 3. The resulting shares are stored (cannot be recomputed on-the-fly)
//! 4. There is one canonical derived key per `(master_key, tweak)`: the key produced by the single
//!    DKG run performed for that tweak, then stored and looked up by [`DerivedKeyId`], which binds
//!    the domain and tweak **plus the TR hash of that run's public key** — because a different DKG
//!    attempt for the same tweak produces a different key (see below), the identifier must pin down
//!    *which* attempt's output it refers to
//!
//! # The derived key is NOT recomputable
//!
//! Only the per-party *contribution* ([`derive_dkg_contribution`]) is a
//! deterministic function of `(master_share, tweak)`. The derived public key
//! itself is **not** a pure function of `(master_key, tweak)`: every DKG
//! session mixes a mandatory fresh `session_nonce` (via the session SSID) into
//! each party's Round 1 randomness, and the final key is derived from the
//! aggregated `global_randomness`. This is deliberate — without the nonce
//! binding, an adversary who observed a failed attempt's Round 2 reveals could
//! predict honest randomness on retry and grind the result.
//!
//! Consequently, re-running the DKG for the same `(master_key, tweak)` — e.g.
//! during node re-provisioning, disaster recovery, or to cross-check a
//! contract-stored address — yields a **different** key. Recovery flows must
//! restore the *stored* derived shares (step 3); they can never regenerate
//! them.
//!
//! # Tweak Computation
//!
//! The tweak should be computed by the caller using the same algorithm as the
//! NEAR MPC contract (`derive_dilithium_tweak`). This keeps the contract and
//! the MPC nodes agreed on *which* derived key a request refers to: the
//! contract stores the derived public key produced by the canonical DKG run,
//! keyed by the same tweak the nodes use to derive their contributions and
//! look up their stored shares. Node-side storage must additionally be keyed
//! by the registered key itself (via [`DerivedKeyId`]'s `public_key_hash`), so
//! that shares from a superseded or concurrent DKG attempt can never be
//! confused with the canonical run's shares.
//!
//! # Security
//!
//! The contribution input is bound to the share's actual secret polynomials
//! (`s1`, `s2`), which are the ground-truth secret of the threshold scheme.
//! The `key` byte string is *not* used here, even though current code derives
//! it from secret material and it must itself be treated as secret (the
//! dealer squeezes it from the secret master seed; the DKG and resharing
//! paths bind it to the secret subset shares under `dkg-party-key-v2` /
//! `reshare-party-key-v2` — never log, cache, or expose it). The reason is
//! share vintage: shares serialized by pre-v2 code derived `key` from the
//! public `rho` and `party_id` only, so a contribution bound to `key` would
//! carry no secrecy for those shares, while binding to the polynomials is
//! sound for every share ever produced.

use alloc::vec::Vec;

use qp_rusty_crystals_dilithium::fips202;
use zeroize::Zeroizing;

use crate::{
	keys::{PrivateKeyShare, PublicKey, TR_SIZE},
	params::{K, L, N, SUITE_ID, THRESHOLD_SSID_VERSION},
};

/// Domain separator for DKG contribution derivation.
///
/// Bumped to v3 when the absorb list gained [`THRESHOLD_SSID_VERSION`] and
/// [`SUITE_ID`], so contributions on different parameter sets diverge even
/// when the underlying share bytes happen to collide in length.
const DKG_CONTRIBUTION_DOMAIN: &[u8] = b"near-mpc-dilithium-dkg-contribution-v3";

/// Derive a DKG contribution from a master share and tweak.
///
/// This function produces a deterministic 32-byte value that a party uses
/// as their per-party seed input in the DKG protocol. The contribution
/// incorporates secret material from the master share, ensuring that:
///
/// 1. Only parties with valid master shares can compute their contribution
/// 2. The contribution is deterministic (same share + tweak = same result)
/// 3. Different parties produce different contributions
/// 4. The contribution binds the derived key to the master key
///
/// # Arguments
/// * `master_share` - This party's master private key share
/// * `tweak` - The derivation tweak (computed from account_id + path by the caller)
///
/// # Returns
/// A 32-byte contribution passed as the `seed` argument to [`crate::keygen::dkg::Dkg::new`].
///
/// # Session freshness
///
/// The contribution alone does **not** include a DKG session nonce. Callers
/// **must** supply a fresh, unique `session_nonce` to [`crate::keygen::dkg::Dkg::new`]
/// for every DKG attempt (including retries of the same derived key). Round 1
/// randomness and leader subset secrets are derived from both this seed and the
/// session SSID (which incorporates `session_nonce`), so a retry with a new
/// nonce produces fresh honest randomness even though the contribution is
/// unchanged.
///
/// # Security
///
/// The contribution is computed as
/// `SHAKE256(domain || version || suite || party_id || tweak || H(secret_shares))`,
/// where `secret_shares` is the canonical serialization of every `(subset_mask, s1, s2)`
/// triple in the share. The shares are the actual cryptographic secret of the threshold
/// scheme, so an attacker who does not hold a valid `PrivateKeyShare` cannot compute
/// `derive_dkg_contribution` for any party — even though `party_id`, `tweak`, and
/// `rho` are public. Version and suite bind the digest to the active ML-DSA
/// parameter set (same discipline as the DKG / signing / resharing SSIDs).
pub fn derive_dkg_contribution(master_share: &PrivateKeyShare, tweak: &[u8; 32]) -> [u8; 32] {
	let party_id_bytes = master_share.party_id().to_le_bytes();
	// The digest is secret-share-derived keying material, so it lives in a
	// self-wiping buffer filled in place (security review): a plain local —
	// or a by-value return from the hash — would leave an unwipeable copy in
	// dead stack memory (pinned by `shares_digest_never_survives_derivation`).
	let mut shares_digest = Zeroizing::new([0u8; 64]);
	hash_secret_shares(master_share, &mut shares_digest);

	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, DKG_CONTRIBUTION_DOMAIN);
	fips202::shake256_absorb(&mut state, &THRESHOLD_SSID_VERSION.to_le_bytes());
	fips202::shake256_absorb(&mut state, &SUITE_ID.to_le_bytes());
	fips202::shake256_absorb(&mut state, &party_id_bytes);
	fips202::shake256_absorb(&mut state, tweak);
	fips202::shake256_absorb(&mut state, &*shares_digest);
	fips202::shake256_finalize(&mut state);

	let mut contribution = [0u8; 32];
	fips202::shake256_squeeze(&mut contribution, &mut state);

	contribution
}

/// Hash all secret share polynomials into `digest` (64 bytes of keying material).
///
/// `BTreeMap` iteration is deterministic by key, so the digest is stable across calls
/// and across machines holding the same share data.
///
/// Writes into a caller-provided buffer instead of returning by value so the
/// caller can keep the (secret-derived) digest in a zeroizing container with
/// no dead by-value copy left in this frame.
pub(crate) fn hash_secret_shares(master_share: &PrivateKeyShare, digest: &mut [u8; 64]) {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, b"threshold-share-digest-v1");
	fips202::shake256_absorb(&mut state, &master_share.party_id().to_le_bytes());

	// The linearization buffer holds raw secret share coefficients, so it must
	// be a zeroizing container (a plain Vec freed after `clear()` leaves the
	// coefficients in allocator memory) and it must be allocated at full size
	// up front (growing mid-fill would free an unwiped intermediate block).
	const SUBSET_BYTES: usize = 2 + (L + K) * N as usize * core::mem::size_of::<i32>();
	let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(SUBSET_BYTES));
	for (subset_mask, share_data) in master_share.shares() {
		buf.clear();
		buf.extend_from_slice(&subset_mask.to_le_bytes());
		for poly in &share_data.s1 {
			for coeff in poly {
				buf.extend_from_slice(&coeff.to_le_bytes());
			}
		}
		for poly in &share_data.s2 {
			for coeff in poly {
				buf.extend_from_slice(&coeff.to_le_bytes());
			}
		}
		fips202::shake256_absorb(&mut state, &buf);
	}

	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(digest, &mut state);
}

/// Identifier for a derived key, used for storage lookup.
///
/// This uniquely identifies one *specific DKG output*: the domain and tweak
/// select which derived key a request refers to, and `public_key_hash` binds
/// the identifier to the concrete key produced by one DKG session. MPC nodes
/// use this to look up stored derived shares.
///
/// The public-key binding is load-bearing. Derived keys are **not**
/// recomputable (see the module docs): every DKG attempt for the same
/// `(master_key, tweak)` mixes a fresh `session_nonce` and yields a different
/// key, so `(domain_id, tweak)` alone does not identify a key — it identifies
/// a *family* of possible keys, one per DKG attempt. Without the binding, a
/// repeated-request or retry race can store one session's shares under an
/// identifier that the rest of the system associates with a different
/// session's public key, leaving nodes disagreeing or signing under an
/// unregistered key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DerivedKeyId {
	/// The domain ID (identifies the master key)
	pub domain_id: u64,
	/// The derivation tweak (derived from account + path by the caller)
	pub tweak: [u8; 32],
	/// TR hash (`SHAKE256` of the packed key, as in FIPS 204) of the derived
	/// public key produced by the canonical DKG run for this `(domain, tweak)`.
	/// Binds the identifier to that run's non-recomputable output.
	pub public_key_hash: [u8; TR_SIZE],
}

impl DerivedKeyId {
	/// Create an identifier for a derived key produced by a completed DKG run.
	///
	/// `derived_public_key` is the DKG output's public key (e.g.
	/// [`DkgOutput::public_key`](crate::keygen::dkg::DkgOutput)); its TR hash
	/// becomes the session binding.
	pub fn new(domain_id: u64, tweak: [u8; 32], derived_public_key: &PublicKey) -> Self {
		Self { domain_id, tweak, public_key_hash: *derived_public_key.tr() }
	}

	/// Create an identifier from a stored/registered public-key hash.
	///
	/// For lookups where the full public key is not at hand but its TR hash
	/// was recorded (e.g. alongside the contract-registered derived key).
	pub fn from_key_hash(domain_id: u64, tweak: [u8; 32], public_key_hash: [u8; TR_SIZE]) -> Self {
		Self { domain_id, tweak, public_key_hash }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{keys::SecretShareData, participants::ParticipantList};
	use alloc::collections::BTreeMap;

	/// Helper to create a test PrivateKeyShare with synthetic share data.
	///
	/// The `key_byte` value is fanned out into both the legacy `key` field and the
	/// (now security-relevant) `s1`/`s2` polynomial coefficients, so callers that
	/// previously distinguished shares by their `key` parameter still get distinct
	/// derivation outputs under the new contribution function.
	fn create_test_share(party_id: u32, key_byte: u8) -> PrivateKeyShare {
		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		let mut shares = BTreeMap::new();
		shares.insert(
			0b011,
			SecretShareData {
				s1: [[key_byte as i32; 256]; crate::params::L],
				s2: [[key_byte as i32; 256]; crate::params::K],
			},
		);
		PrivateKeyShare::new(
			party_id,
			3,
			2,
			[key_byte; 32],
			[0u8; 32],
			[0u8; 64],
			shares,
			dkg_participants,
		)
	}

	/// Create a test tweak (simulates what the contract would compute)
	fn test_tweak(account: &str, path: &str) -> [u8; 32] {
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, b"test-tweak:");
		fips202::shake256_absorb(&mut state, account.as_bytes());
		fips202::shake256_absorb(&mut state, b":");
		fips202::shake256_absorb(&mut state, path.as_bytes());
		fips202::shake256_finalize(&mut state);

		let mut tweak = [0u8; 32];
		fips202::shake256_squeeze(&mut tweak, &mut state);
		tweak
	}

	/// Regression probe (security review): the 64-byte secret-share digest
	/// must not survive in dead stack memory after `derive_dkg_contribution`
	/// returns — it lets a memory-disclosure attacker reproduce the party's
	/// contribution for any tweak. Painted-stack technique as in the
	/// `*_stack_zeroization` integration tests; release-only because the
	/// assertion is about codegen.
	// Local probe copy: unit tests cannot take a `dev-dependency`, so this
	// cannot call `qp_rusty_crystals_test_utils`. Unsafe is scoped to this
	// test only (the crate otherwise denies unsafe_code).
	#[allow(unsafe_code)]
	#[cfg(not(debug_assertions))]
	#[test]
	fn shares_digest_never_survives_derivation() {
		use alloc::alloc::{alloc, dealloc, Layout};

		const PAINT: u8 = 0xAA;
		const STACK_BYTES: usize = 1024 * 1024;
		const ALIGN: usize = 4096;

		fn probe_stack_for<F: FnOnce()>(pattern: &[u8], f: F) -> bool {
			let layout = Layout::from_size_align(STACK_BYTES, ALIGN).unwrap();
			unsafe {
				let base = alloc(layout);
				assert!(!base.is_null(), "probe stack allocation failed");
				core::ptr::write_bytes(base, PAINT, STACK_BYTES);

				psm::on_stack(base, STACK_BYTES, f);

				let region = core::slice::from_raw_parts(base, STACK_BYTES);
				let found = region.windows(pattern.len()).any(|w| w == pattern);
				dealloc(base, layout);
				found
			}
		}

		let share = create_test_share(0, 42);
		let tweak = [0x5Au8; 32];
		// Reference digest, computed outside the probed region.
		let mut digest = Zeroizing::new([0u8; 64]);
		hash_secret_shares(&share, &mut digest);

		// Sanity: the technique detects an unwiped copy.
		assert!(
			probe_stack_for(&*digest, || {
				let leaked: [u8; 64] = *digest;
				core::hint::black_box(&leaked);
			}),
			"probe self-check: a deliberately leaked digest copy was not detected"
		);

		let leaked = probe_stack_for(&*digest, || {
			let contribution = derive_dkg_contribution(&share, &tweak);
			core::hint::black_box(&contribution);
		});
		assert!(
			!leaked,
			"the secret-share digest survived in dead stack memory after \
			 derive_dkg_contribution returned"
		);
	}

	#[test]
	fn test_derive_dkg_contribution_deterministic() {
		let share = create_test_share(0, 42);
		let tweak = test_tweak("alice.near", "ethereum");

		let contribution1 = derive_dkg_contribution(&share, &tweak);
		let contribution2 = derive_dkg_contribution(&share, &tweak);
		assert_eq!(contribution1, contribution2);
	}

	/// Contribution digest must bind the active suite: a hand-rolled hash that
	/// swaps in a different `SUITE_ID` must not collide with the real output.
	#[test]
	fn test_derive_dkg_contribution_binds_suite() {
		let share = create_test_share(0, 42);
		let tweak = [0x11u8; 32];
		let real = derive_dkg_contribution(&share, &tweak);
		let mut shares_digest = Zeroizing::new([0u8; 64]);
		hash_secret_shares(&share, &mut shares_digest);

		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, DKG_CONTRIBUTION_DOMAIN);
		fips202::shake256_absorb(&mut state, &THRESHOLD_SSID_VERSION.to_le_bytes());
		fips202::shake256_absorb(&mut state, &(SUITE_ID ^ 0xDEAD).to_le_bytes());
		fips202::shake256_absorb(&mut state, &share.party_id().to_le_bytes());
		fips202::shake256_absorb(&mut state, &tweak);
		fips202::shake256_absorb(&mut state, &*shares_digest);
		fips202::shake256_finalize(&mut state);
		let mut other_suite = [0u8; 32];
		fips202::shake256_squeeze(&mut other_suite, &mut state);

		assert_ne!(real, other_suite, "contribution must change when SUITE_ID changes");
	}

	#[test]
	fn test_derive_dkg_contribution_different_parties() {
		let tweak = test_tweak("alice.near", "ethereum");

		let share0 = create_test_share(0, 42);
		let share1 = create_test_share(1, 42);

		let contribution0 = derive_dkg_contribution(&share0, &tweak);
		let contribution1 = derive_dkg_contribution(&share1, &tweak);
		assert_ne!(contribution0, contribution1);
	}

	#[test]
	fn test_derive_dkg_contribution_different_keys() {
		let tweak = test_tweak("alice.near", "ethereum");

		let share_a = create_test_share(0, 1);
		let share_b = create_test_share(0, 2);

		let contribution_a = derive_dkg_contribution(&share_a, &tweak);
		let contribution_b = derive_dkg_contribution(&share_b, &tweak);
		assert_ne!(contribution_a, contribution_b);
	}

	#[test]
	fn test_derive_dkg_contribution_different_tweaks() {
		let share = create_test_share(0, 42);

		let tweak_eth = test_tweak("alice.near", "ethereum");
		let tweak_btc = test_tweak("alice.near", "bitcoin");

		let contribution_eth = derive_dkg_contribution(&share, &tweak_eth);
		let contribution_btc = derive_dkg_contribution(&share, &tweak_btc);
		assert_ne!(contribution_eth, contribution_btc);
	}

	#[test]
	fn test_contribution_independent_of_legacy_key_field() {
		// Two shares that differ ONLY in the `key` byte string must still
		// produce the same contribution: the binding comes from the secret
		// polynomial shares directly, not from the derived `key` (which
		// pre-v2 code computed from public inputs only).
		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		let mut shares = BTreeMap::new();
		shares.insert(
			0b011,
			SecretShareData {
				s1: [[7i32; 256]; crate::params::L],
				s2: [[7i32; 256]; crate::params::K],
			},
		);
		let share_a = PrivateKeyShare::new(
			0,
			3,
			2,
			[1u8; 32],
			[0u8; 32],
			[0u8; 64],
			shares.clone(),
			dkg_participants.clone(),
		);
		let share_b = PrivateKeyShare::new(
			0,
			3,
			2,
			[2u8; 32], // different `key`, same shares
			[0u8; 32],
			[0u8; 64],
			shares,
			dkg_participants,
		);

		let tweak = test_tweak("alice.near", "ethereum");
		assert_eq!(
			derive_dkg_contribution(&share_a, &tweak),
			derive_dkg_contribution(&share_b, &tweak),
			"contribution must depend on secret share polynomials, not on `key` field"
		);
	}

	#[test]
	fn test_derived_key_id_new() {
		let tweak = test_tweak("alice.near", "ethereum");
		let key_hash = [0x5Au8; TR_SIZE];
		let id1 = DerivedKeyId::from_key_hash(5, tweak, key_hash);
		let id2 = DerivedKeyId::from_key_hash(5, tweak, key_hash);
		assert_eq!(id1, id2);

		let id3 = DerivedKeyId::from_key_hash(6, tweak, key_hash);
		assert_ne!(id1, id3); // Different domain
	}

	#[test]
	fn test_derived_key_id_different_tweaks() {
		let tweak1 = test_tweak("alice.near", "ethereum");
		let tweak2 = test_tweak("bob.near", "ethereum");
		let key_hash = [0x5Au8; TR_SIZE];

		let id1 = DerivedKeyId::from_key_hash(5, tweak1, key_hash);
		let id2 = DerivedKeyId::from_key_hash(5, tweak2, key_hash);
		assert_ne!(id1, id2);
	}

	#[test]
	fn test_derived_key_id_binds_derived_key() {
		// Same (domain, tweak), different DKG outputs: the IDs must differ,
		// and `new` must agree with `from_key_hash` on the TR binding.
		let tweak = test_tweak("alice.near", "ethereum");
		let pk_a = crate::keygen::generate_with_dealer(
			&[3u8; 32],
			crate::ThresholdConfig::new(2, 3).unwrap(),
		)
		.unwrap()
		.0;
		let pk_b = crate::keygen::generate_with_dealer(
			&[4u8; 32],
			crate::ThresholdConfig::new(2, 3).unwrap(),
		)
		.unwrap()
		.0;

		let id_a = DerivedKeyId::new(5, tweak, &pk_a);
		let id_b = DerivedKeyId::new(5, tweak, &pk_b);
		assert_ne!(id_a, id_b, "different DKG outputs must not collide");
		assert_eq!(id_a, DerivedKeyId::from_key_hash(5, tweak, *pk_a.tr()));
	}
}
