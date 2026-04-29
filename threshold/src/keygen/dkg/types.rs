//! Types for Distributed Key Generation (DKG) protocol.
//!
//! This module defines the message types exchanged during the 5-round DKG protocol,
//! as well as configuration and output types.

use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::serde_helpers::serde_poly_vec;

use crate::{
	config::ThresholdConfig,
	keys::{PrivateKeyShare, PublicKey},
};

/// Participant identifier.
///
/// This is a u32 to match NEAR's participant ID type directly.
/// The actual party ID values are still constrained to 0..n-1 (where n <= MAX_PARTIES).
pub type ParticipantId = u32;

/// Subset mask - a bitmask indicating which parties are in a subset.
/// Uses u16 to support up to 16 parties.
pub type SubsetMask = u16;

/// Size of session ID in bytes.
pub const SESSION_ID_SIZE: usize = 32;

/// Size of commitment hash in bytes.
pub const COMMITMENT_HASH_SIZE: usize = 32;

/// Size of subset seed contribution in bytes.
/// This matches Mithril's 64-byte seed used for PolyDeriveUniformLeqEta.
pub const SUBSET_SEED_SIZE: usize = 64;

// ML-DSA-87 parameters
/// Number of polynomials in s1 vector.
pub const L: usize = 7;
/// Number of polynomials in s2 vector.
pub const K: usize = 8;
/// Polynomial degree.
pub const N: usize = 256;

/// Configuration for the DKG protocol.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DkgConfig {
	/// The threshold configuration (t, n).
	pub threshold_config: ThresholdConfig,
	/// This party's identifier.
	pub my_party_id: ParticipantId,
	/// All participants in the DKG (sorted).
	pub all_participants: Vec<ParticipantId>,
}

impl DkgConfig {
	/// Create a new DKG configuration.
	///
	/// # Arguments
	/// * `threshold_config` - The (t, n) threshold configuration
	/// * `my_party_id` - This party's identifier (0 to n-1)
	/// * `all_participants` - List of all participant IDs
	///
	/// # Errors
	/// Returns an error if:
	/// - `my_party_id` is not in `all_participants`
	/// - `all_participants` length doesn't match `threshold_config.total_parties()`
	pub fn new(
		threshold_config: ThresholdConfig,
		my_party_id: ParticipantId,
		all_participants: Vec<ParticipantId>,
	) -> Result<Self, &'static str> {
		if all_participants.len() != threshold_config.total_parties() as usize {
			return Err("participant count doesn't match threshold config");
		}
		if !all_participants.contains(&my_party_id) {
			return Err("my_party_id not in all_participants");
		}

		let mut sorted_participants = all_participants;
		sorted_participants.sort();

		Ok(Self { threshold_config, my_party_id, all_participants: sorted_participants })
	}

	/// Get the threshold value (minimum parties to sign).
	pub fn threshold(&self) -> u32 {
		self.threshold_config.threshold()
	}

	/// Get the total number of parties.
	pub fn total_parties(&self) -> u32 {
		self.threshold_config.total_parties()
	}

	/// Get all participants except self.
	pub fn other_participants(&self) -> impl Iterator<Item = ParticipantId> + '_ {
		self.all_participants.iter().copied().filter(move |&p| p != self.my_party_id)
	}
}

/// Contribution for a single subset.
///
/// Contains the random η-bounded polynomial coefficients that this party
/// contributes to a specific subset's share.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SubsetContribution {
	/// Share of s1 polynomial vector (L polynomials, each with N coefficients).
	#[cfg_attr(feature = "serde", serde(with = "serde_poly_vec"))]
	pub s1: Vec<[i32; N]>,
	/// Share of s2 polynomial vector (K polynomials, each with N coefficients).
	#[cfg_attr(feature = "serde", serde(with = "serde_poly_vec"))]
	pub s2: Vec<[i32; N]>,
}

impl SubsetContribution {
	/// Create a new empty subset contribution.
	pub fn new() -> Self {
		Self { s1: vec![[0i32; N]; L], s2: vec![[0i32; N]; K] }
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

/// Seed contribution for a single subset.
///
/// Each party generates a random seed for each subset they belong to.
/// The combined seed (hash of all parties' seeds in the subset) is used
/// to deterministically derive the actual η-bounded secret contribution.
///
/// This is the key to the HQ1-secure DKG: instead of each party generating
/// independent η-bounded contributions (which would blow up bounds when summed),
/// parties contribute entropy that is combined before sampling.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SubsetSeedContribution {
	/// Random seed bytes contributed by this party for this subset.
	#[cfg_attr(feature = "serde", serde(with = "crate::serde_helpers::serde_byte_array"))]
	pub seed: [u8; SUBSET_SEED_SIZE],
}

impl SubsetSeedContribution {
	/// Create a new subset seed contribution with zero bytes.
	pub fn new() -> Self {
		Self { seed: [0u8; SUBSET_SEED_SIZE] }
	}

	/// Create a new subset seed contribution from the given bytes.
	pub fn from_bytes(seed: [u8; SUBSET_SEED_SIZE]) -> Self {
		Self { seed }
	}
}

impl Default for SubsetSeedContribution {
	fn default() -> Self {
		Self::new()
	}
}

/// Partial public key for a single subset.
///
/// This is the public component t_I = A·s_I (mod q) computed from secret
/// contributions. Only partial public keys are broadcast, never raw secrets.
///
/// SECURITY: This is the fix for HQ1 - we broadcast partial public keys
/// instead of raw secret polynomials.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PartialPublicKey {
	/// The subset this partial public key corresponds to.
	pub subset_mask: SubsetMask,
	/// The partial public key t_I = A·s1_I + s2_I (K polynomials, each with N coefficients).
	/// This is computed as: for each row i of A, t_I[i] = Σ_j A[i][j]·s1_I[j] + s2_I[i]
	#[cfg_attr(feature = "serde", serde(with = "serde_poly_vec"))]
	pub t: Vec<[i32; N]>,
}

impl PartialPublicKey {
	/// Create a new partial public key with zero coefficients.
	pub fn new(subset_mask: SubsetMask) -> Self {
		Self { subset_mask, t: vec![[0i32; N]; K] }
	}

	/// Verify that all coefficients are within valid range [0, Q).
	pub fn verify_range(&self, q: i32) -> bool {
		for poly in &self.t {
			for &coeff in poly {
				if coeff < 0 || coeff >= q {
					return false;
				}
			}
		}
		true
	}
}

/// Public contributions from one party (revealed in Round 3).
///
/// In the seed-based DKG protocol, this contains only the rho contribution.
/// The seed contributions are sent via P2P in Round 3, not broadcast.
/// Partial public keys are computed in Round 4 after seeds are combined.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PartyPublicContributions {
	/// The party that generated these contributions.
	pub party_id: ParticipantId,
	/// Hashes of seed contributions for each subset (for verification without revealing).
	/// Key is the subset mask. Value is H(seed) - allows P2P recipients to verify.
	pub subset_seed_hashes: HashMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]>,
}

impl PartyPublicContributions {
	/// Create a new empty party public contributions structure.
	pub fn new(party_id: ParticipantId) -> Self {
		Self {
			party_id,
			subset_seed_hashes: HashMap::new(),
		}
	}
}

/// Seed contributions from one party for all subsets they belong to.
///
/// In the seed-based DKG protocol, each party generates random seeds
/// (not secret polynomials) for each subset. These seeds are:
/// - Committed to in Round 2
/// - Revealed via P2P in Round 3 to other subset members
/// - Combined with other parties' seeds to derive the final η-bounded secret
///
/// This ensures the combined secret has the correct distribution (bounded by η)
/// rather than having bounds blow up when multiple parties' contributions are summed.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PartySeedContributions {
	/// The party that generated these seed contributions.
	pub party_id: ParticipantId,
	/// Seed contributions for each subset this party belongs to.
	/// Key is the subset mask (bitmask of party IDs in the subset).
	pub subset_seeds: HashMap<SubsetMask, SubsetSeedContribution>,
}

impl PartySeedContributions {
	/// Create a new empty party seed contributions structure.
	pub fn new(party_id: ParticipantId) -> Self {
		Self {
			party_id,
			subset_seeds: HashMap::new(),
		}
	}
}

// ============================================================================
// Round Messages
// ============================================================================

/// Round 1 message: Session ID contribution.
///
/// Each party contributes random bytes to form a unique session ID,
/// preventing replay attacks across different DKG runs.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DkgRound1Broadcast {
	/// The party sending this message.
	pub party_id: ParticipantId,
	/// Random bytes contributed to the session ID.
	pub session_id_contribution: [u8; SESSION_ID_SIZE],
}

/// Round 2 message: Commitment hash.
///
/// Each party broadcasts a hash of their contributions before revealing them.
/// This prevents parties from adapting their contributions based on others'.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DkgRound2Broadcast {
	/// The party sending this message.
	pub party_id: ParticipantId,
	/// Hash of (party_id || seed_hashes).
	/// This commits to the public contributions before others reveal.
	pub commitment_hash: [u8; COMMITMENT_HASH_SIZE],
	/// Public contributions: seed hashes for each subset.
	/// Sent along with commitment so others can verify P2P seeds later.
	pub public_contributions: PartyPublicContributions,
}

/// Round 3 P2P message: Seed contribution for a specific subset.
///
/// SEED-BASED DKG: Seeds are exchanged via P2P only with parties in the same subset.
/// This ensures:
/// 1. Each party only learns seeds for subsets they belong to
/// 2. The threshold property is preserved (t-1 parties cannot reconstruct s)
///
/// After receiving all seeds for a subset, each party:
/// 1. Computes combined_seed = H(seed_0 || seed_1 || ... || seed_{k-1})
/// 2. Derives the actual secret s_I = DeriveUniformLeqEta(combined_seed)
/// 3. Computes the partial public key t_I = A·s_I for broadcast in Round 4
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DkgRound3Private {
	/// The party sending this message.
	pub from_party_id: ParticipantId,
	/// The subset this seed is for.
	pub subset_mask: SubsetMask,
	/// The seed contribution for this subset (combined with others to derive secret).
	pub seed_contribution: SubsetSeedContribution,
}

/// Round 4 broadcast message: Partial public keys derived from combined seeds.
///
/// SEED-BASED DKG: After combining seeds and deriving η-bounded secrets,
/// each party broadcasts their partial public keys for subsets they're in.
/// All parties receive these and sum them to compute the final public key.
///
/// This is the key to achieving η-bounded secrets: the partial public key t_I
/// corresponds to a single s_I that was derived from combined seeds, NOT
/// the sum of k independent contributions.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DkgRound4Broadcast {
	/// The party sending this message.
	pub party_id: ParticipantId,
	/// Partial public keys for each subset this party belongs to.
	/// Key is subset_mask, value is t_I = A·s1_I + s2_I (K polynomials).
	pub partial_public_keys: HashMap<SubsetMask, PartialPublicKey>,
}

/// Round 5 message: Confirmation.
///
/// Each party confirms they successfully computed their shares and
/// the public key. All parties must agree on the public key hash.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DkgRound5Broadcast {
	/// The party sending this message.
	pub party_id: ParticipantId,
	/// Whether this party succeeded in computing their share.
	pub success: bool,
	/// Hash of the computed public key (for consensus verification).
	pub public_key_hash: [u8; COMMITMENT_HASH_SIZE],
}

// ============================================================================
// Serialized Message Wrapper
// ============================================================================

/// Wrapper enum for all DKG message types.
///
/// This allows messages to be serialized/deserialized without knowing
/// the specific round at deserialization time.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DkgMessage {
	/// Round 1: Session ID contribution (broadcast).
	Round1(DkgRound1Broadcast),
	/// Round 2: Commitment hash for seeds (broadcast).
	Round2(DkgRound2Broadcast),
	/// Round 3: P2P seed contribution (sent only to subset members).
	Round3(DkgRound3Private),
	/// Round 4: Partial public keys derived from combined seeds (broadcast).
	Round4(DkgRound4Broadcast),
	/// Round 5: Confirmation (broadcast).
	Round5(DkgRound5Broadcast),
}

impl DkgMessage {
	/// Get the party ID of the sender.
	pub fn party_id(&self) -> ParticipantId {
		match self {
			DkgMessage::Round1(msg) => msg.party_id,
			DkgMessage::Round2(msg) => msg.party_id,
			DkgMessage::Round3(msg) => msg.from_party_id,
			DkgMessage::Round4(msg) => msg.party_id,
			DkgMessage::Round5(msg) => msg.party_id,
		}
	}

	/// Get the round number (1-5).
	pub fn round(&self) -> u8 {
		match self {
			DkgMessage::Round1(_) => 1,
			DkgMessage::Round2(_) => 2,
			DkgMessage::Round3(_) => 3,
			DkgMessage::Round4(_) => 4,
			DkgMessage::Round5(_) => 5,
		}
	}
}

// ============================================================================
// Output Types
// ============================================================================

/// Output of a successful DKG protocol run.
///
/// This contains everything needed to participate in threshold signing.
#[derive(Debug, Clone)]
pub struct DkgOutput {
	/// The threshold public key (shared by all parties).
	pub public_key: PublicKey,
	/// This party's private key share.
	pub private_share: PrivateKeyShare,
}

// ============================================================================
// Seed-Based Secret Derivation
// ============================================================================

use qp_rusty_crystals_dilithium::fips202;

/// Combine multiple seed contributions into a single combined seed.
///
/// This function takes seed contributions from all parties in a subset
/// and combines them using SHAKE256 to produce a deterministic combined seed.
/// The combination is done by sorting parties by ID (to ensure all parties
/// get the same result) and hashing all seeds together.
///
/// # Arguments
/// * `seeds` - HashMap from party_id to their seed contribution
///
/// # Returns
/// A 64-byte combined seed that can be used with `derive_subset_contribution`
pub fn combine_seeds(seeds: &HashMap<ParticipantId, SubsetSeedContribution>) -> [u8; SUBSET_SEED_SIZE] {
	let mut state = fips202::KeccakState::default();
	
	// Sort by party ID to ensure deterministic ordering
	let mut sorted_parties: Vec<_> = seeds.keys().collect();
	sorted_parties.sort();
	
	// Domain separator for seed combination
	let domain = b"DKG_SEED_COMBINE_V1";
	fips202::shake256_absorb(&mut state, domain, domain.len());
	
	// Absorb each seed in order
	for party_id in sorted_parties {
		// Include party ID to prevent malleability
		let id_bytes = party_id.to_le_bytes();
		fips202::shake256_absorb(&mut state, &id_bytes, 4);
		
		let seed = &seeds[party_id];
		fips202::shake256_absorb(&mut state, &seed.seed, SUBSET_SEED_SIZE);
	}
	
	fips202::shake256_finalize(&mut state);
	
	let mut combined = [0u8; SUBSET_SEED_SIZE];
	fips202::shake256_squeeze(&mut combined, SUBSET_SEED_SIZE, &mut state);
	combined
}

/// Hash a seed to produce a commitment hash.
///
/// This is used in Round 3 to broadcast seed hashes without revealing the seeds.
pub fn hash_seed(seed: &SubsetSeedContribution) -> [u8; COMMITMENT_HASH_SIZE] {
	let mut state = fips202::KeccakState::default();
	
	let domain = b"DKG_SEED_HASH_V1";
	fips202::shake256_absorb(&mut state, domain, domain.len());
	fips202::shake256_absorb(&mut state, &seed.seed, SUBSET_SEED_SIZE);
	fips202::shake256_finalize(&mut state);
	
	let mut hash = [0u8; COMMITMENT_HASH_SIZE];
	fips202::shake256_squeeze(&mut hash, COMMITMENT_HASH_SIZE, &mut state);
	hash
}

/// Derive an η-bounded SubsetContribution from a combined seed.
///
/// This implements the same sampling strategy as Mithril's PolyDeriveUniformLeqEta:
/// - Uses SHAKE256 with the seed and a nonce
/// - Rejection samples to get uniform values in [0, 2*eta]
/// - Shifts to get values in [-eta, eta]
///
/// The resulting contribution has all coefficients in [-η, η] and is
/// deterministically derived from the seed, so all parties in the subset
/// will compute the same contribution.
///
/// # Arguments
/// * `combined_seed` - The 64-byte seed from `combine_seeds`
/// * `eta` - The bound for coefficients (typically 2 for ML-DSA-87)
pub fn derive_subset_contribution(combined_seed: &[u8; SUBSET_SEED_SIZE], eta: i32) -> SubsetContribution {
	let mut contribution = SubsetContribution::new();
	
	// Sample s1 (L polynomials)
	for i in 0..L {
		sample_poly_leq_eta(&mut contribution.s1[i], combined_seed, i as u16, eta);
	}
	
	// Sample s2 (K polynomials)
	for i in 0..K {
		sample_poly_leq_eta(&mut contribution.s2[i], combined_seed, (L + i) as u16, eta);
	}
	
	contribution
}

/// Sample a polynomial with coefficients uniformly in [-eta, eta].
///
/// This uses rejection sampling similar to Mithril's PolyDeriveUniformLeqEta.
/// For eta=2, we need uniform samples in {-2, -1, 0, 1, 2} (5 values).
///
/// # Arguments
/// * `poly` - Output polynomial (N=256 coefficients)
/// * `seed` - 64-byte seed
/// * `nonce` - 16-bit nonce to derive different polynomials from same seed
/// * `eta` - Bound for coefficients
fn sample_poly_leq_eta(poly: &mut [i32; N], seed: &[u8; SUBSET_SEED_SIZE], nonce: u16, eta: i32) {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, seed, SUBSET_SEED_SIZE);
	fips202::shake256_absorb(&mut state, &nonce.to_le_bytes(), 2);
	fips202::shake256_finalize(&mut state);
	
	let mut buf = [0u8; 512];
	fips202::shake256_squeeze(&mut buf, 512, &mut state);
	
	let mut idx = 0;
	for i in 0..N {
		loop {
			if idx >= buf.len() {
				// Need more random bytes
				fips202::shake256_squeeze(&mut buf, 512, &mut state);
				idx = 0;
			}
			
			let b = buf[idx] as i32;
			idx += 1;
			
			// Rejection sampling for uniform in [-eta, eta]
			// bound = 2*eta + 1 = number of valid values
			// We reject values >= (256 / bound) * bound to avoid bias
			let bound = 2 * eta + 1;
			if b < (256 / bound) * bound {
				poly[i] = (b % bound) - eta;
				break;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_dkg_config_creation() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let config = DkgConfig::new(threshold_config, 1, vec![0, 1, 2]);

		assert!(config.is_ok());
		let config = config.unwrap();
		assert_eq!(config.threshold(), 2);
		assert_eq!(config.total_parties(), 3);
		assert_eq!(config.my_party_id, 1);
	}

	#[test]
	fn test_dkg_config_invalid_party_id() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let config = DkgConfig::new(threshold_config, 5, vec![0, 1, 2]);

		assert!(config.is_err());
	}

	#[test]
	fn test_dkg_config_wrong_participant_count() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let config = DkgConfig::new(threshold_config, 0, vec![0, 1]);

		assert!(config.is_err());
	}

	#[test]
	fn test_dkg_config_other_participants() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let config = DkgConfig::new(threshold_config, 1, vec![0, 1, 2]).unwrap();

		let others: Vec<_> = config.other_participants().collect();
		assert_eq!(others, vec![0, 2]);
	}

	#[test]
	fn test_subset_contribution_bounds() {
		let mut contrib = SubsetContribution::new();
		assert!(contrib.verify_bounds(2));

		// Set a coefficient outside bounds
		contrib.s1[0][0] = 5;
		assert!(!contrib.verify_bounds(2));
		assert!(contrib.verify_bounds(5));
	}

	#[test]
	fn test_dkg_message_party_id() {
		let msg = DkgMessage::Round1(DkgRound1Broadcast {
			party_id: 2,
			session_id_contribution: [0u8; 32],
		});
		assert_eq!(msg.party_id(), 2);
		assert_eq!(msg.round(), 1);
	}

	#[test]
	fn test_derive_subset_contribution_bounds() {
		// Test that derived contributions are within [-eta, eta]
		let seed = [42u8; SUBSET_SEED_SIZE];
		let contribution = derive_subset_contribution(&seed, 2);
		
		assert!(contribution.verify_bounds(2), "Derived contribution should be within [-2, 2]");
		
		// Verify all coefficients are actually bounded
		for poly in &contribution.s1 {
			for &coeff in poly {
				assert!(coeff >= -2 && coeff <= 2, "s1 coefficient {} out of bounds", coeff);
			}
		}
		for poly in &contribution.s2 {
			for &coeff in poly {
				assert!(coeff >= -2 && coeff <= 2, "s2 coefficient {} out of bounds", coeff);
			}
		}
	}

	#[test]
	fn test_derive_subset_contribution_deterministic() {
		// Same seed should produce same contribution
		let seed = [123u8; SUBSET_SEED_SIZE];
		let contribution1 = derive_subset_contribution(&seed, 2);
		let contribution2 = derive_subset_contribution(&seed, 2);
		
		for i in 0..L {
			assert_eq!(contribution1.s1[i], contribution2.s1[i], "s1[{}] mismatch", i);
		}
		for i in 0..K {
			assert_eq!(contribution1.s2[i], contribution2.s2[i], "s2[{}] mismatch", i);
		}
	}

	#[test]
	fn test_combine_seeds_deterministic() {
		// Same seeds in same order should produce same combined seed
		let mut seeds = HashMap::new();
		seeds.insert(0, SubsetSeedContribution::from_bytes([1u8; SUBSET_SEED_SIZE]));
		seeds.insert(1, SubsetSeedContribution::from_bytes([2u8; SUBSET_SEED_SIZE]));
		seeds.insert(2, SubsetSeedContribution::from_bytes([3u8; SUBSET_SEED_SIZE]));
		
		let combined1 = combine_seeds(&seeds);
		let combined2 = combine_seeds(&seeds);
		
		assert_eq!(combined1, combined2);
	}

	#[test]
	fn test_combine_seeds_order_independent() {
		// Seeds should be combined in party ID order, regardless of insertion order
		let mut seeds1 = HashMap::new();
		seeds1.insert(0, SubsetSeedContribution::from_bytes([1u8; SUBSET_SEED_SIZE]));
		seeds1.insert(1, SubsetSeedContribution::from_bytes([2u8; SUBSET_SEED_SIZE]));
		
		let mut seeds2 = HashMap::new();
		seeds2.insert(1, SubsetSeedContribution::from_bytes([2u8; SUBSET_SEED_SIZE]));
		seeds2.insert(0, SubsetSeedContribution::from_bytes([1u8; SUBSET_SEED_SIZE]));
		
		let combined1 = combine_seeds(&seeds1);
		let combined2 = combine_seeds(&seeds2);
		
		assert_eq!(combined1, combined2, "Seed combination should be order-independent");
	}

	#[test]
	fn test_combine_seeds_different_inputs() {
		// Different seeds should produce different combined seeds
		let mut seeds1 = HashMap::new();
		seeds1.insert(0, SubsetSeedContribution::from_bytes([1u8; SUBSET_SEED_SIZE]));
		
		let mut seeds2 = HashMap::new();
		seeds2.insert(0, SubsetSeedContribution::from_bytes([2u8; SUBSET_SEED_SIZE]));
		
		let combined1 = combine_seeds(&seeds1);
		let combined2 = combine_seeds(&seeds2);
		
		assert_ne!(combined1, combined2, "Different seeds should produce different combined seeds");
	}

	#[test]
	fn test_hash_seed() {
		let seed = SubsetSeedContribution::from_bytes([42u8; SUBSET_SEED_SIZE]);
		let hash1 = hash_seed(&seed);
		let hash2 = hash_seed(&seed);
		
		assert_eq!(hash1, hash2, "Hash should be deterministic");
		
		// Different seed should produce different hash
		let seed2 = SubsetSeedContribution::from_bytes([43u8; SUBSET_SEED_SIZE]);
		let hash3 = hash_seed(&seed2);
		
		assert_ne!(hash1, hash3, "Different seeds should have different hashes");
	}
}
