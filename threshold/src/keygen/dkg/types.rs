//! Types for Distributed Key Generation (DKG) protocol.
//!
//! This module implements the 4-round DKG protocol from the Mithril paper (Appendix D).
//!
//! ## Protocol Overview
//!
//! **Round 1: Shared secret establishment + commitment**
//! - Leaders (min(S) for each subset S) generate K_S and distribute via secure P2P
//! - All parties commit to random r_i: broadcast c_i = H(i, r_i)
//!
//! **Round 2: Reveal randomness**
//! - All parties reveal r_i
//! - Verify commitments: c_j = H(j, r_j)
//!
//! **Round 3: Derive secrets + commit to partial PKs (leaders only)**
//! - Compute global randomness R = r_1 || ... || r_N
//! - Leaders derive s_S = H_keygen(S, K_S, R) and compute t_S = A·s_S
//! - Leaders broadcast commitment to partial PK
//!
//! **Round 4: Reveal partial PKs + transcript signing**
//! - Leaders reveal t_S
//! - Non-leaders verify: recompute s_S from K_S and R, verify commitment
//! - All parties sign transcript with long-term key
//!
//! **Aggregate: Verify signatures + combine PKs**
//! - Verify all transcript signatures
//! - Compute final public key: t = Σ t_S

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use zeroize::Zeroize;

use crate::{config::ThresholdConfig, error::MAX_PARTIES};

use qp_rusty_crystals_dilithium::fips202;

// ============================================================================
// Transcript Signing Trait
// ============================================================================

/// Trait for signing DKG transcripts.
///
/// This allows the DKG protocol to be agnostic to the signature scheme used.
/// Implementors can use Ed25519, ML-DSA, or any other scheme.
pub trait TranscriptSigner {
	/// The signature type produced by this signer.
	type Signature: Clone + AsRef<[u8]>;

	/// The public key type for verification.
	type PublicKey: Clone + PartialEq;

	/// Sign a transcript hash.
	fn sign(&self, transcript_hash: &[u8; 32]) -> Self::Signature;

	/// Verify a signature on a transcript hash.
	fn verify(
		public_key: &Self::PublicKey,
		transcript_hash: &[u8; 32],
		signature: &Self::Signature,
	) -> bool;

	/// Verify a signature from raw bytes.
	///
	/// This is used when deserializing signatures from the wire.
	/// Implementors should parse the bytes into their Signature type and verify.
	fn verify_bytes(
		public_key: &Self::PublicKey,
		transcript_hash: &[u8; 32],
		signature_bytes: &[u8],
	) -> bool;

	/// Get this signer's public key.
	fn public_key(&self) -> Self::PublicKey;
}

// ============================================================================
// Type Aliases and Constants
// ============================================================================

use crate::participants::ParticipantId;

/// Subset mask - a bitmask indicating which parties are in a subset.
pub type SubsetMask = u16;

/// Size of commitment hash in bytes.
pub const COMMITMENT_HASH_SIZE: usize = 32;

/// Size of subset seed in bytes.
pub const SUBSET_SEED_SIZE: usize = 64;

/// Size of shared secret K_S in bytes.
pub const SHARED_SECRET_SIZE: usize = 32;

/// Size of randomness r_i in bytes.
pub const RANDOMNESS_SIZE: usize = 32;

// Domain separators for hash functions
/// Domain separator for commitment hash.
pub const DOMAIN_COMMIT: &[u8] = b"MITHRIL_DKG_COMMIT_V1";

/// Domain separator for seed derivation.
pub const DOMAIN_SEED: &[u8] = b"MITHRIL_DKG_SEED_V1";

/// Domain separator for keygen.
pub const DOMAIN_KEYGEN: &[u8] = b"MITHRIL_DKG_KEYGEN_V1";

/// Domain separator for partial PK commitment.
pub const DOMAIN_PK_COMMIT: &[u8] = b"MITHRIL_DKG_PK_COMMIT_V1";

/// Domain separator for transcript hash.
pub const DOMAIN_TRANSCRIPT: &[u8] = b"MITHRIL_DKG_TRANSCRIPT_V1";

use qp_rusty_crystals_dilithium::params::{K, L, N};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the DKG protocol.
#[derive(Clone)]
pub struct MithrilDkgConfig<S: TranscriptSigner> {
	/// The threshold configuration (t, n).
	pub threshold_config: ThresholdConfig,
	/// This party's identifier.
	pub my_party_id: ParticipantId,
	/// All participants in the DKG (sorted).
	pub all_participants: Vec<ParticipantId>,
	/// This party's signing key for transcript authentication.
	pub my_signer: S,
	/// Public keys of all participants for signature verification.
	pub participant_public_keys: BTreeMap<ParticipantId, S::PublicKey>,
}

impl<S: TranscriptSigner> MithrilDkgConfig<S> {
	/// Create a new DKG configuration.
	pub fn new(
		threshold_config: ThresholdConfig,
		my_party_id: ParticipantId,
		all_participants: Vec<ParticipantId>,
		my_signer: S,
		participant_public_keys: BTreeMap<ParticipantId, S::PublicKey>,
	) -> Result<Self, &'static str> {
		if all_participants.len() != threshold_config.total_parties() as usize {
			return Err("participant count doesn't match threshold config");
		}
		if !all_participants.contains(&my_party_id) {
			return Err("my_party_id not in all_participants");
		}
		if participant_public_keys.len() != all_participants.len() {
			return Err("must provide public keys for all participants");
		}
		for p in &all_participants {
			if !participant_public_keys.contains_key(p) {
				return Err("missing public key for participant");
			}
		}

		let mut sorted_participants = all_participants;
		sorted_participants.sort();

		// Check for duplicate participant IDs after sorting (duplicates will be adjacent)
		for i in 1..sorted_participants.len() {
			if sorted_participants[i] == sorted_participants[i - 1] {
				return Err("duplicate participant ID in all_participants");
			}
		}

		Ok(Self {
			threshold_config,
			my_party_id,
			all_participants: sorted_participants,
			my_signer,
			participant_public_keys,
		})
	}

	/// Get the threshold value.
	pub fn threshold(&self) -> u32 {
		self.threshold_config.threshold()
	}

	/// Get total number of parties.
	pub fn total_parties(&self) -> u32 {
		self.threshold_config.total_parties()
	}

	/// Get this party's index in the sorted participant list.
	pub fn my_index(&self) -> Option<usize> {
		self.all_participants.iter().position(|&p| p == self.my_party_id)
	}

	/// Check if this party is in a subset.
	pub fn is_in_subset(&self, subset_mask: SubsetMask) -> bool {
		if let Some(my_idx) = self.my_index() {
			(subset_mask & (1 << my_idx)) != 0
		} else {
			false
		}
	}

	/// Get the leader (minimum party ID) for a subset.
	pub fn get_leader(&self, subset_mask: SubsetMask) -> Option<ParticipantId> {
		self.all_participants
			.iter()
			.enumerate()
			.filter(|(idx, _)| (subset_mask & (1 << idx)) != 0)
			.map(|(_, &pid)| pid)
			.min()
	}

	/// Check if this party is the leader for a subset.
	pub fn is_leader(&self, subset_mask: SubsetMask) -> bool {
		self.get_leader(subset_mask) == Some(self.my_party_id)
	}

	/// Get all parties in a subset.
	pub fn get_parties_in_subset(&self, subset_mask: SubsetMask) -> Vec<ParticipantId> {
		self.all_participants
			.iter()
			.enumerate()
			.filter(|(idx, _)| (subset_mask & (1 << idx)) != 0)
			.map(|(_, &pid)| pid)
			.collect()
	}

	/// Get all subsets where this party is the leader.
	pub fn my_leader_subsets(&self) -> Vec<SubsetMask> {
		self.all_subsets().into_iter().filter(|&mask| self.is_leader(mask)).collect()
	}

	/// Get all subsets this party belongs to.
	pub fn my_subsets(&self) -> Vec<SubsetMask> {
		self.all_subsets().into_iter().filter(|&mask| self.is_in_subset(mask)).collect()
	}

	/// Check if a subset mask is valid for this threshold configuration.
	///
	/// A valid subset has exactly `k = n - t + 1` members, where each member
	/// is a participant in the DKG.
	pub fn is_valid_subset(&self, subset_mask: SubsetMask) -> bool {
		let n = self.total_parties();
		let t = self.threshold();
		let k = n - t + 1;

		// Check correct number of bits set
		if subset_mask.count_ones() != k {
			return false;
		}

		// Check all set bits correspond to valid participant indices
		let max_valid_mask = (1u16 << n) - 1;
		(subset_mask & !max_valid_mask) == 0
	}

	/// Get all valid subsets for this threshold configuration.
	///
	/// # Panics
	/// Panics if `n > MAX_PARTIES`. This should never happen since
	/// `ThresholdConfig::new()` enforces this constraint.
	pub fn all_subsets(&self) -> Vec<SubsetMask> {
		let n = self.total_parties();
		let t = self.threshold();

		// This is a programmer error if violated - ThresholdConfig enforces n <= MAX_PARTIES.
		assert!(n <= MAX_PARTIES, "all_subsets: n={} exceeds MAX_PARTIES ({})", n, MAX_PARTIES);

		let k = n - t + 1;
		let max_mask: u32 = 1u32 << n;
		let mut subsets = Vec::new();
		for mask in 0..max_mask {
			if mask.count_ones() == k {
				subsets.push(mask as SubsetMask);
			}
		}
		subsets.sort();
		subsets
	}
}

impl<S: TranscriptSigner + fmt::Debug> fmt::Debug for MithrilDkgConfig<S>
where
	S::PublicKey: fmt::Debug,
{
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MithrilDkgConfig")
			.field("threshold_config", &self.threshold_config)
			.field("my_party_id", &self.my_party_id)
			.field("all_participants", &self.all_participants)
			.finish()
	}
}

// ============================================================================
// Contribution Types
// ============================================================================

/// Contribution for a single subset (η-bounded secret polynomials).
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubsetContribution {
	/// Share of s1 polynomial vector.
	pub s1: Vec<[i32; N as usize]>,
	/// Share of s2 polynomial vector.
	pub s2: Vec<[i32; N as usize]>,
}

impl SubsetContribution {
	/// Create a new empty subset contribution.
	pub fn new() -> Self {
		Self { s1: vec![[0i32; N as usize]; L], s2: vec![[0i32; N as usize]; K] }
	}

	/// Check if all coefficients are within the η bound.
	pub fn verify_bounds(&self, eta: i32) -> bool {
		for poly in &self.s1 {
			for &coeff in poly {
				if coeff < -eta || coeff > eta {
					return false;
				}
			}
		}
		for poly in &self.s2 {
			for &coeff in poly {
				if coeff < -eta || coeff > eta {
					return false;
				}
			}
		}
		true
	}
}

impl Default for SubsetContribution {
	fn default() -> Self {
		Self::new()
	}
}

impl Zeroize for SubsetContribution {
	fn zeroize(&mut self) {
		for poly in &mut self.s1 {
			poly.zeroize();
		}
		for poly in &mut self.s2 {
			poly.zeroize();
		}
	}
}

/// Partial public key for a single subset.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct PartialPublicKey {
	/// The subset this partial public key corresponds to.
	pub subset_mask: SubsetMask,
	/// The partial public key t = A·s1 + s2.
	pub t: Vec<[i32; N as usize]>,
}

impl PartialPublicKey {
	/// Create a new partial public key with zero coefficients.
	pub fn new(subset_mask: SubsetMask) -> Self {
		Self { subset_mask, t: vec![[0i32; N as usize]; K] }
	}
}

// ============================================================================
// Round Messages
// ============================================================================

/// Round 1 broadcast: Commitment to randomness.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct MithrilRound1Broadcast {
	/// The party sending this message.
	pub party_id: ParticipantId,
	/// Commitment c_i = H(i, r_i).
	pub commitment: [u8; COMMITMENT_HASH_SIZE],
}

/// Round 1 private: Shared secret K_S (leader to subset members).
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct MithrilRound1Private {
	/// The party sending this message.
	pub from_party_id: ParticipantId,
	/// The subset this shared secret is for.
	pub subset_mask: SubsetMask,
	/// The shared secret K_S.
	pub shared_secret: [u8; SHARED_SECRET_SIZE],
}

/// Round 2 broadcast: Reveal randomness.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct MithrilRound2Broadcast {
	/// The party sending this message.
	pub party_id: ParticipantId,
	/// The revealed randomness r_i.
	pub randomness: [u8; RANDOMNESS_SIZE],
}

/// Round 3 broadcast: Commitment to partial PKs (leaders only).
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct MithrilRound3Broadcast {
	/// The party sending this message.
	pub party_id: ParticipantId,
	/// Commitments to partial public keys.
	pub partial_pk_commitments: BTreeMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]>,
}

/// Round 4 broadcast: Reveal partial PKs + transcript signature.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct MithrilRound4Broadcast {
	/// The party sending this message.
	pub party_id: ParticipantId,
	/// Partial public keys for subsets where this party is leader.
	pub partial_public_keys: BTreeMap<SubsetMask, PartialPublicKey>,
	/// Signature on transcript.
	pub transcript_signature: Vec<u8>,
}

/// Message wrapper enum.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum MithrilDkgMessage {
	/// Round 1 broadcast.
	Round1Broadcast(MithrilRound1Broadcast),
	/// Round 1 private.
	Round1Private(MithrilRound1Private),
	/// Round 2 broadcast.
	Round2Broadcast(MithrilRound2Broadcast),
	/// Round 3 broadcast.
	Round3Broadcast(MithrilRound3Broadcast),
	/// Round 4 broadcast.
	Round4Broadcast(MithrilRound4Broadcast),
}

// ============================================================================
// Hash Functions
// ============================================================================

/// Compute commitment hash: H_commit(party_id, data).
pub fn h_commit(party_id: ParticipantId, data: &[u8]) -> [u8; COMMITMENT_HASH_SIZE] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, DOMAIN_COMMIT, DOMAIN_COMMIT.len());
	fips202::shake256_absorb(&mut state, &party_id.to_le_bytes(), 4);
	fips202::shake256_absorb(&mut state, data, data.len());
	fips202::shake256_finalize(&mut state);

	let mut hash = [0u8; COMMITMENT_HASH_SIZE];
	fips202::shake256_squeeze(&mut hash, COMMITMENT_HASH_SIZE, &mut state);
	hash
}

/// Compute commitment hash for partial PK.
pub fn h_commit_pk(
	subset_mask: SubsetMask,
	partial_pk: &PartialPublicKey,
) -> [u8; COMMITMENT_HASH_SIZE] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, DOMAIN_PK_COMMIT, DOMAIN_PK_COMMIT.len());
	fips202::shake256_absorb(&mut state, &subset_mask.to_le_bytes(), 2);

	for poly in &partial_pk.t {
		for coeff in poly {
			fips202::shake256_absorb(&mut state, &coeff.to_le_bytes(), 4);
		}
	}

	fips202::shake256_finalize(&mut state);

	let mut hash = [0u8; COMMITMENT_HASH_SIZE];
	fips202::shake256_squeeze(&mut hash, COMMITMENT_HASH_SIZE, &mut state);
	hash
}

/// Derive ρ from global randomness.
pub fn h_seed(global_randomness: &[u8]) -> [u8; 32] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, DOMAIN_SEED, DOMAIN_SEED.len());
	fips202::shake256_absorb(&mut state, global_randomness, global_randomness.len());
	fips202::shake256_finalize(&mut state);

	let mut rho = [0u8; 32];
	fips202::shake256_squeeze(&mut rho, 32, &mut state);
	rho
}

/// Derive subset secret: H_keygen(S, K_S, R).
pub fn h_keygen(
	subset_mask: SubsetMask,
	shared_secret: &[u8; SHARED_SECRET_SIZE],
	global_randomness: &[u8],
) -> [u8; SUBSET_SEED_SIZE] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, DOMAIN_KEYGEN, DOMAIN_KEYGEN.len());
	fips202::shake256_absorb(&mut state, &subset_mask.to_le_bytes(), 2);
	fips202::shake256_absorb(&mut state, shared_secret, SHARED_SECRET_SIZE);
	fips202::shake256_absorb(&mut state, global_randomness, global_randomness.len());
	fips202::shake256_finalize(&mut state);

	let mut seed = [0u8; SUBSET_SEED_SIZE];
	fips202::shake256_squeeze(&mut seed, SUBSET_SEED_SIZE, &mut state);
	seed
}

/// Compute transcript hash from rounds 1-3.
pub fn compute_transcript_hash(
	round1_broadcasts: &BTreeMap<ParticipantId, MithrilRound1Broadcast>,
	round2_broadcasts: &BTreeMap<ParticipantId, MithrilRound2Broadcast>,
	round3_broadcasts: &BTreeMap<ParticipantId, MithrilRound3Broadcast>,
) -> [u8; 32] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, DOMAIN_TRANSCRIPT, DOMAIN_TRANSCRIPT.len());

	// BTreeMap iterates in sorted order, so no need to sort
	for (party_id, msg) in round1_broadcasts {
		fips202::shake256_absorb(&mut state, &party_id.to_le_bytes(), 4);
		fips202::shake256_absorb(&mut state, &msg.commitment, COMMITMENT_HASH_SIZE);
	}

	for (party_id, msg) in round2_broadcasts {
		fips202::shake256_absorb(&mut state, &party_id.to_le_bytes(), 4);
		fips202::shake256_absorb(&mut state, &msg.randomness, RANDOMNESS_SIZE);
	}

	for (party_id, msg) in round3_broadcasts {
		fips202::shake256_absorb(&mut state, &party_id.to_le_bytes(), 4);
		// partial_pk_commitments is already a BTreeMap, iterates in sorted order
		for (mask, commitment) in &msg.partial_pk_commitments {
			fips202::shake256_absorb(&mut state, &mask.to_le_bytes(), 2);
			fips202::shake256_absorb(&mut state, commitment, COMMITMENT_HASH_SIZE);
		}
	}

	fips202::shake256_finalize(&mut state);

	let mut hash = [0u8; 32];
	fips202::shake256_squeeze(&mut hash, 32, &mut state);
	hash
}

/// Compute hash of partial output.
pub fn compute_partial_output_hash(
	partial_pks: &BTreeMap<SubsetMask, PartialPublicKey>,
) -> [u8; 32] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, b"PARTIAL_OUTPUT", 14);

	// BTreeMap iterates in sorted order by key, so no need to sort
	for (mask, pk) in partial_pks {
		fips202::shake256_absorb(&mut state, &mask.to_le_bytes(), 2);
		for poly in &pk.t {
			for coeff in poly {
				fips202::shake256_absorb(&mut state, &coeff.to_le_bytes(), 4);
			}
		}
	}

	fips202::shake256_finalize(&mut state);

	let mut hash = [0u8; 32];
	fips202::shake256_squeeze(&mut hash, 32, &mut state);
	hash
}

/// Compute the message to sign.
pub fn compute_signing_message(
	transcript_hash: &[u8; 32],
	partial_output_hash: &[u8; 32],
) -> [u8; 32] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, b"SIGN_MESSAGE", 12);
	fips202::shake256_absorb(&mut state, transcript_hash, 32);
	fips202::shake256_absorb(&mut state, partial_output_hash, 32);
	fips202::shake256_finalize(&mut state);

	let mut hash = [0u8; 32];
	fips202::shake256_squeeze(&mut hash, 32, &mut state);
	hash
}

/// Derive an η-bounded SubsetContribution from a seed.
pub fn derive_subset_contribution(
	combined_seed: &[u8; SUBSET_SEED_SIZE],
	eta: i32,
) -> SubsetContribution {
	let mut contribution = SubsetContribution::new();

	for i in 0..L {
		sample_poly_leq_eta(&mut contribution.s1[i], combined_seed, i as u16, eta);
	}

	for i in 0..K {
		sample_poly_leq_eta(&mut contribution.s2[i], combined_seed, (L + i) as u16, eta);
	}

	contribution
}

fn sample_poly_leq_eta(
	poly: &mut [i32; N as usize],
	seed: &[u8; SUBSET_SEED_SIZE],
	nonce: u16,
	eta: i32,
) {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, seed, SUBSET_SEED_SIZE);
	fips202::shake256_absorb(&mut state, &nonce.to_le_bytes(), 2);
	fips202::shake256_finalize(&mut state);

	let mut buf = [0u8; 512];
	fips202::shake256_squeeze(&mut buf, 512, &mut state);

	let mut idx = 0;
	for coeff in poly.iter_mut() {
		loop {
			if idx >= buf.len() {
				fips202::shake256_squeeze(&mut buf, 512, &mut state);
				idx = 0;
			}

			let b = buf[idx] as i32;
			idx += 1;

			let bound = 2 * eta + 1;
			if b < (256 / bound) * bound {
				*coeff = (b % bound) - eta;
				break;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Clone, Debug)]
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

	#[test]
	fn test_config_leader_detection() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let mut public_keys = BTreeMap::new();
		public_keys.insert(0, 0u32);
		public_keys.insert(1, 1u32);
		public_keys.insert(2, 2u32);

		let config: MithrilDkgConfig<TestSigner> = MithrilDkgConfig::new(
			threshold_config,
			0,
			vec![0, 1, 2],
			TestSigner { id: 0 },
			public_keys,
		)
		.unwrap();

		assert!(config.is_leader(0b011));
		assert!(config.is_leader(0b101));
		assert!(!config.is_leader(0b110));
	}

	#[test]
	fn test_config_rejects_duplicate_participants() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let mut public_keys = BTreeMap::new();
		public_keys.insert(0, 0u32);
		public_keys.insert(1, 1u32);
		public_keys.insert(2, 2u32);
		// 3 unique public keys, but participant list has duplicate

		// Duplicate participant ID (1 appears twice) - will fail participant count check first
		// since 3 participants but vec has [0,1,1] which after dedup would be 2 unique
		// Actually the check is on vec length vs config, so [0,1,1].len() == 3 passes that.
		// The public_keys check passes since all 3 IDs (0,1,2) have keys but vec is [0,1,1].
		// Wait - the for loop checks each p in all_participants has a key. [0,1,1] all have keys.
		// So we should hit the duplicate check!
		let result: Result<MithrilDkgConfig<TestSigner>, _> = MithrilDkgConfig::new(
			threshold_config,
			0,
			vec![0, 1, 1], // duplicate!
			TestSigner { id: 0 },
			public_keys,
		);

		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "duplicate participant ID in all_participants");
	}

	#[test]
	fn test_config_rejects_duplicate_participants_unsorted() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let mut public_keys = BTreeMap::new();
		public_keys.insert(0, 0u32);
		public_keys.insert(1, 1u32);
		public_keys.insert(2, 2u32);

		// Duplicate at non-adjacent positions before sorting
		let result: Result<MithrilDkgConfig<TestSigner>, _> = MithrilDkgConfig::new(
			threshold_config,
			0,
			vec![0, 2, 0], // duplicate 0, not adjacent before sort
			TestSigner { id: 0 },
			public_keys,
		);

		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "duplicate participant ID in all_participants");
	}

	#[test]
	fn test_is_valid_subset() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let mut public_keys = BTreeMap::new();
		public_keys.insert(0, 0u32);
		public_keys.insert(1, 1u32);
		public_keys.insert(2, 2u32);

		let config: MithrilDkgConfig<TestSigner> = MithrilDkgConfig::new(
			threshold_config,
			0,
			vec![0, 1, 2],
			TestSigner { id: 0 },
			public_keys,
		)
		.unwrap();

		// For 2-of-3: k = 3 - 2 + 1 = 2, so valid subsets have exactly 2 members
		// Valid subsets: 0b011, 0b101, 0b110
		assert!(config.is_valid_subset(0b011), "0b011 should be valid");
		assert!(config.is_valid_subset(0b101), "0b101 should be valid");
		assert!(config.is_valid_subset(0b110), "0b110 should be valid");

		// Invalid: wrong size
		assert!(!config.is_valid_subset(0b111), "0b111 invalid: size 3, need 2");
		assert!(!config.is_valid_subset(0b001), "0b001 invalid: size 1, need 2");
		assert!(!config.is_valid_subset(0b010), "0b010 invalid: size 1, need 2");
		assert!(!config.is_valid_subset(0b100), "0b100 invalid: size 1, need 2");
		assert!(!config.is_valid_subset(0b000), "0b000 invalid: size 0, need 2");

		// Invalid: bits outside valid participant range (only 3 participants, so bits 0-2 valid)
		assert!(!config.is_valid_subset(0b1001), "0b1001 invalid: bit 3 set, only 3 participants");
		assert!(!config.is_valid_subset(0b1010), "0b1010 invalid: bit 3 set, only 3 participants");
	}

	#[test]
	fn test_h_commit_deterministic() {
		let hash1 = h_commit(42, b"test");
		let hash2 = h_commit(42, b"test");
		assert_eq!(hash1, hash2);
	}

	#[test]
	fn test_derive_contribution_bounded() {
		let seed = [42u8; SUBSET_SEED_SIZE];
		let contribution = derive_subset_contribution(&seed, 2);
		assert!(contribution.verify_bounds(2));
	}
}
