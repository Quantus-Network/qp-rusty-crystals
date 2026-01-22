//! Types for the Resharing (Committee Handoff) protocol.
//!
//! This module defines the configuration, message types, and output structures
//! for the resharing protocol that enables changing the participant set while
//! preserving the same public key.

use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
	keys::{PrivateKeyShare, PublicKey},
	participants::{ParticipantId, ParticipantList},
	ThresholdConfig,
};

#[cfg(feature = "serde")]
use crate::serde_helpers::{serde_participant_list, serde_poly_vec};

// ML-DSA-87 parameters (same as DKG)
/// Number of polynomials in s1 vector.
pub const L: usize = 7;
/// Number of polynomials in s2 vector.
pub const K: usize = 8;
/// Polynomial degree.
pub const N: usize = 256;

/// Size of commitment hash in bytes.
pub const COMMITMENT_HASH_SIZE: usize = 32;

/// Subset mask - a bitmask indicating which parties are in a subset.
/// Uses u16 to support up to 16 parties.
pub type SubsetMask = u16;

// ============================================================================
// Resharing Role
// ============================================================================

/// Role of a party in the resharing protocol.
///
/// During resharing, parties can have different roles depending on whether
/// they are in the old committee, new committee, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ResharingRole {
	/// Party is only in the old committee (leaving after resharing).
	OldOnly,
	/// Party is only in the new committee (joining during resharing).
	NewOnly,
	/// Party is in both old and new committees (staying).
	Both,
}

impl ResharingRole {
	/// Returns true if this party is in the old committee.
	pub fn is_old_committee(&self) -> bool {
		matches!(self, ResharingRole::OldOnly | ResharingRole::Both)
	}

	/// Returns true if this party is in the new committee.
	pub fn is_new_committee(&self) -> bool {
		matches!(self, ResharingRole::NewOnly | ResharingRole::Both)
	}

	/// Returns true if this party has an existing share (old committee member).
	pub fn has_existing_share(&self) -> bool {
		self.is_old_committee()
	}

	/// Returns true if this party will receive a new share (new committee member).
	pub fn will_receive_share(&self) -> bool {
		self.is_new_committee()
	}
}

// ============================================================================
// Resharing Configuration
// ============================================================================

/// Configuration for the resharing protocol.
///
/// Specifies the old and new committee structures, and this party's role.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResharingConfig {
	/// Threshold configuration for the old committee.
	pub old_threshold: u32,
	/// Participants in the old committee (sorted).
	#[cfg_attr(feature = "serde", serde(with = "serde_participant_list"))]
	pub old_participants: ParticipantList,
	/// Threshold configuration for the new committee.
	pub new_threshold: u32,
	/// Participants in the new committee (sorted).
	#[cfg_attr(feature = "serde", serde(with = "serde_participant_list"))]
	pub new_participants: ParticipantList,
	/// This party's identifier.
	pub my_party_id: ParticipantId,
	/// This party's role in the resharing.
	pub role: ResharingRole,
	/// This party's existing private key share (if in old committee).
	/// None if this party is NewOnly.
	pub existing_share: Option<PrivateKeyShare>,
	/// The public key (must be preserved during resharing).
	pub public_key: PublicKey,
}

impl ResharingConfig {
	/// Create a new resharing configuration.
	///
	/// # Arguments
	/// * `old_threshold` - Threshold of the old committee
	/// * `old_participants` - Participant IDs in the old committee
	/// * `new_threshold` - Threshold of the new committee
	/// * `new_participants` - Participant IDs in the new committee
	/// * `my_party_id` - This party's identifier
	/// * `existing_share` - This party's existing share (None if joining)
	/// * `public_key` - The public key to preserve
	///
	/// # Errors
	/// Returns an error if:
	/// - `my_party_id` is not in either committee
	/// - `existing_share` is provided but party is not in old committee
	/// - `existing_share` is missing but party is in old committee
	/// - Threshold configurations are invalid
	pub fn new(
		old_threshold: u32,
		old_participants: Vec<ParticipantId>,
		new_threshold: u32,
		new_participants: Vec<ParticipantId>,
		my_party_id: ParticipantId,
		existing_share: Option<PrivateKeyShare>,
		public_key: PublicKey,
	) -> Result<Self, ResharingConfigError> {
		// Validate threshold configs
		let old_n = old_participants.len() as u32;
		let new_n = new_participants.len() as u32;

		if old_threshold < 2 || old_threshold > old_n {
			return Err(ResharingConfigError::InvalidOldThreshold {
				threshold: old_threshold,
				parties: old_n,
			});
		}

		if new_threshold < 2 || new_threshold > new_n {
			return Err(ResharingConfigError::InvalidNewThreshold {
				threshold: new_threshold,
				parties: new_n,
			});
		}

		// Create participant lists
		let old_participant_list = ParticipantList::new(&old_participants)
			.ok_or(ResharingConfigError::DuplicateParticipant)?;

		let new_participant_list = ParticipantList::new(&new_participants)
			.ok_or(ResharingConfigError::DuplicateParticipant)?;

		// Determine role
		let in_old = old_participant_list.contains(my_party_id);
		let in_new = new_participant_list.contains(my_party_id);

		let role = match (in_old, in_new) {
			(true, true) => ResharingRole::Both,
			(true, false) => ResharingRole::OldOnly,
			(false, true) => ResharingRole::NewOnly,
			(false, false) =>
				return Err(ResharingConfigError::PartyNotInEitherCommittee {
					party_id: my_party_id,
				}),
		};

		// Validate existing share matches role
		match (&role, &existing_share) {
			(ResharingRole::NewOnly, Some(_)) => {
				return Err(ResharingConfigError::UnexpectedExistingShare);
			},
			(ResharingRole::OldOnly | ResharingRole::Both, None) => {
				return Err(ResharingConfigError::MissingExistingShare);
			},
			_ => {},
		}

		Ok(Self {
			old_threshold,
			old_participants: old_participant_list,
			new_threshold,
			new_participants: new_participant_list,
			my_party_id,
			role,
			existing_share,
			public_key,
		})
	}

	/// Get old threshold config.
	pub fn old_config(&self) -> ThresholdConfig {
		ThresholdConfig::new(self.old_threshold, self.old_participants.len() as u32)
			.expect("validated in constructor")
	}

	/// Get new threshold config.
	pub fn new_config(&self) -> ThresholdConfig {
		ThresholdConfig::new(self.new_threshold, self.new_participants.len() as u32)
			.expect("validated in constructor")
	}

	/// Get all parties involved in resharing (union of old and new).
	pub fn all_participants(&self) -> Vec<ParticipantId> {
		let mut all: Vec<ParticipantId> =
			self.old_participants.iter().chain(self.new_participants.iter()).collect();
		all.sort();
		all.dedup();
		all
	}

	/// Get parties that are leaving (in old but not new).
	pub fn leaving_participants(&self) -> Vec<ParticipantId> {
		self.old_participants
			.iter()
			.filter(|p| !self.new_participants.contains(*p))
			.collect()
	}

	/// Get parties that are joining (in new but not old).
	pub fn joining_participants(&self) -> Vec<ParticipantId> {
		self.new_participants
			.iter()
			.filter(|p| !self.old_participants.contains(*p))
			.collect()
	}

	/// Get parties that are staying (in both old and new).
	pub fn staying_participants(&self) -> Vec<ParticipantId> {
		self.old_participants
			.iter()
			.filter(|p| self.new_participants.contains(*p))
			.collect()
	}
}

/// Errors that can occur when creating a resharing configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResharingConfigError {
	/// Invalid old committee threshold.
	InvalidOldThreshold { threshold: u32, parties: u32 },
	/// Invalid new committee threshold.
	InvalidNewThreshold { threshold: u32, parties: u32 },
	/// Party is not in either committee.
	PartyNotInEitherCommittee { party_id: ParticipantId },
	/// Duplicate participant ID in a committee.
	DuplicateParticipant,
	/// Existing share provided but party is not in old committee.
	UnexpectedExistingShare,
	/// No existing share provided but party is in old committee.
	MissingExistingShare,
}

impl std::fmt::Display for ResharingConfigError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ResharingConfigError::InvalidOldThreshold { threshold, parties } => {
				write!(f, "Invalid old threshold: t={}, n={}", threshold, parties)
			},
			ResharingConfigError::InvalidNewThreshold { threshold, parties } => {
				write!(f, "Invalid new threshold: t={}, n={}", threshold, parties)
			},
			ResharingConfigError::PartyNotInEitherCommittee { party_id } => {
				write!(f, "Party {} is not in either old or new committee", party_id)
			},
			ResharingConfigError::DuplicateParticipant => {
				write!(f, "Duplicate participant ID in committee")
			},
			ResharingConfigError::UnexpectedExistingShare => {
				write!(f, "Existing share provided but party is not in old committee")
			},
			ResharingConfigError::MissingExistingShare => {
				write!(f, "No existing share provided but party is in old committee")
			},
		}
	}
}

impl std::error::Error for ResharingConfigError {}

// ============================================================================
// Resharing Messages
// ============================================================================

/// Wrapper enum for all resharing protocol messages.
///
/// This allows messages to be serialized/deserialized without knowing
/// the specific round at deserialization time.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ResharingMessage {
	/// Round 1: Blinded share contributions from old committee.
	Round1(ResharingRound1Broadcast),
	/// Round 2: New share distributions to new committee.
	Round2(ResharingRound2Message),
	/// Round 3: Verification commitments from new committee.
	Round3(ResharingRound3Broadcast),
}

impl ResharingMessage {
	/// Get the party ID that sent this message.
	pub fn party_id(&self) -> ParticipantId {
		match self {
			ResharingMessage::Round1(msg) => msg.party_id,
			ResharingMessage::Round2(msg) => msg.from_party_id,
			ResharingMessage::Round3(msg) => msg.party_id,
		}
	}

	/// Get the round number of this message.
	pub fn round(&self) -> u8 {
		match self {
			ResharingMessage::Round1(_) => 1,
			ResharingMessage::Round2(_) => 2,
			ResharingMessage::Round3(_) => 3,
		}
	}
}

// ============================================================================
// Round 1: Blinded Share Contributions
// ============================================================================

/// Round 1 broadcast from old committee members.
///
/// Each old committee member broadcasts their blinded share contribution
/// along with the blinding values used. The blinding values are needed
/// by dealers to correctly remove the total blinding when generating
/// new shares.
///
/// **Security note:** Broadcasting the blinding values is safe because:
/// - The blinding alone doesn't reveal the secret
/// - The blinded contribution hides the actual share values
/// - Only the combination of all participants' shares (which requires threshold cooperation) can
///   recover the secret
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResharingRound1Broadcast {
	/// Party ID of the sender.
	pub party_id: ParticipantId,
	/// Blinded contribution to s1 reconstruction.
	/// This is: recovered_s1_share + blinding_s1
	pub blinded_s1_contribution: BlindedContribution,
	/// Blinded contribution to s2 reconstruction.
	/// This is: recovered_s2_share + blinding_s2
	pub blinded_s2_contribution: BlindedContribution,
	/// The blinding values used for s1 (needed by dealers to remove total blinding).
	pub blinding_s1: BlindedContribution,
	/// The blinding values used for s2 (needed by dealers to remove total blinding).
	pub blinding_s2: BlindedContribution,
	/// Commitment to the blinding values (for verification that blinding matches).
	pub blinding_commitment: [u8; COMMITMENT_HASH_SIZE],
}

/// A blinded polynomial vector contribution.
///
/// Contains the sum of a party's recovered share and their random blinding value.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlindedContribution {
	/// Polynomial coefficients (L or K polynomials, each with N coefficients).
	#[cfg_attr(feature = "serde", serde(with = "serde_poly_vec"))]
	pub coefficients: Vec<[i32; N]>,
}

impl BlindedContribution {
	/// Create a new blinded contribution with the given number of polynomials.
	pub fn new(num_polynomials: usize) -> Self {
		Self { coefficients: vec![[0i32; N]; num_polynomials] }
	}

	/// Create a blinded contribution for s1 (L polynomials).
	pub fn new_s1() -> Self {
		Self::new(L)
	}

	/// Create a blinded contribution for s2 (K polynomials).
	pub fn new_s2() -> Self {
		Self::new(K)
	}
}

// ============================================================================
// Round 2: New Share Distribution
// ============================================================================

/// Round 2 message containing new shares for a specific party.
///
/// This is a private message from the dealing parties to new committee members.
/// Each new party receives their subset shares from the dealers.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResharingRound2Message {
	/// Party ID of the sender (dealer).
	pub from_party_id: ParticipantId,
	/// Party ID of the recipient.
	pub to_party_id: ParticipantId,
	/// The new shares for the recipient, keyed by subset mask.
	pub shares: HashMap<SubsetMask, NewShareData>,
}

/// New share data for a specific subset.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NewShareData {
	/// Share of s1 polynomial vector (L polynomials).
	#[cfg_attr(feature = "serde", serde(with = "serde_poly_vec"))]
	pub s1: Vec<[i32; N]>,
	/// Share of s2 polynomial vector (K polynomials).
	#[cfg_attr(feature = "serde", serde(with = "serde_poly_vec"))]
	pub s2: Vec<[i32; N]>,
}

impl NewShareData {
	/// Create a new empty share data.
	pub fn new() -> Self {
		Self { s1: vec![[0i32; N]; L], s2: vec![[0i32; N]; K] }
	}
}

impl Default for NewShareData {
	fn default() -> Self {
		Self::new()
	}
}

// ============================================================================
// Round 3: Verification
// ============================================================================

/// Round 3 broadcast for share verification.
///
/// Each new committee member broadcasts commitments to their received shares
/// so that consistency can be verified.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResharingRound3Broadcast {
	/// Party ID of the sender.
	pub party_id: ParticipantId,
	/// Commitments to each subset share, keyed by subset mask.
	pub share_commitments: HashMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]>,
	/// Indicates success or failure of share reception.
	pub success: bool,
	/// Optional error message if success is false.
	pub error_message: Option<String>,
}

// ============================================================================
// Resharing Output
// ============================================================================

/// Output of a successful resharing protocol.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResharingOutput {
	/// The new private key share for this party.
	/// None if this party was OldOnly (leaving the committee).
	pub private_share: Option<PrivateKeyShare>,
	/// The public key (unchanged from input).
	pub public_key: PublicKey,
	/// The new threshold configuration.
	pub new_config: ThresholdConfig,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	fn make_test_public_key() -> PublicKey {
		// Create a dummy public key for testing
		let bytes = [0u8; 2592];
		PublicKey::from_bytes(&bytes).unwrap()
	}

	#[test]
	fn test_resharing_role() {
		assert!(ResharingRole::OldOnly.is_old_committee());
		assert!(!ResharingRole::OldOnly.is_new_committee());
		assert!(ResharingRole::OldOnly.has_existing_share());
		assert!(!ResharingRole::OldOnly.will_receive_share());

		assert!(!ResharingRole::NewOnly.is_old_committee());
		assert!(ResharingRole::NewOnly.is_new_committee());
		assert!(!ResharingRole::NewOnly.has_existing_share());
		assert!(ResharingRole::NewOnly.will_receive_share());

		assert!(ResharingRole::Both.is_old_committee());
		assert!(ResharingRole::Both.is_new_committee());
		assert!(ResharingRole::Both.has_existing_share());
		assert!(ResharingRole::Both.will_receive_share());
	}

	#[test]
	fn test_config_invalid_old_threshold() {
		let result = ResharingConfig::new(
			1, // invalid: too low
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			0,
			None, // Will fail before checking this
			make_test_public_key(),
		);

		assert!(matches!(result, Err(ResharingConfigError::InvalidOldThreshold { .. })));
	}

	#[test]
	fn test_config_invalid_new_threshold() {
		let result = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			5, // invalid: exceeds party count
			vec![0, 1, 2],
			0,
			None, // Will fail before checking this
			make_test_public_key(),
		);

		assert!(matches!(result, Err(ResharingConfigError::InvalidNewThreshold { .. })));
	}

	#[test]
	fn test_config_party_not_in_either() {
		let result = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			99, // not in either committee
			None,
			make_test_public_key(),
		);

		assert!(matches!(result, Err(ResharingConfigError::PartyNotInEitherCommittee { .. })));
	}

	#[test]
	fn test_config_duplicate_participant() {
		let result = ResharingConfig::new(
			2,
			vec![0, 1, 1], // duplicate
			2,
			vec![0, 1, 2],
			0,
			None,
			make_test_public_key(),
		);

		assert!(matches!(result, Err(ResharingConfigError::DuplicateParticipant)));
	}

	#[test]
	fn test_config_missing_share_for_old_member() {
		let result = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			0,    // in old committee
			None, // but no share provided
			make_test_public_key(),
		);

		assert!(matches!(result, Err(ResharingConfigError::MissingExistingShare)));
	}

	#[test]
	fn test_blinded_contribution_sizes() {
		let s1 = BlindedContribution::new_s1();
		assert_eq!(s1.coefficients.len(), L);
		assert_eq!(s1.coefficients[0].len(), N);

		let s2 = BlindedContribution::new_s2();
		assert_eq!(s2.coefficients.len(), K);
		assert_eq!(s2.coefficients[0].len(), N);
	}

	#[test]
	fn test_message_round_numbers() {
		let r1 = ResharingMessage::Round1(ResharingRound1Broadcast {
			party_id: 0,
			blinded_s1_contribution: BlindedContribution::new_s1(),
			blinded_s2_contribution: BlindedContribution::new_s2(),
			blinding_s1: BlindedContribution::new_s1(),
			blinding_s2: BlindedContribution::new_s2(),
			blinding_commitment: [0u8; COMMITMENT_HASH_SIZE],
		});
		assert_eq!(r1.round(), 1);
		assert_eq!(r1.party_id(), 0);

		let r2 = ResharingMessage::Round2(ResharingRound2Message {
			from_party_id: 1,
			to_party_id: 2,
			shares: HashMap::new(),
		});
		assert_eq!(r2.round(), 2);
		assert_eq!(r2.party_id(), 1);

		let r3 = ResharingMessage::Round3(ResharingRound3Broadcast {
			party_id: 2,
			share_commitments: HashMap::new(),
			success: true,
			error_message: None,
		});
		assert_eq!(r3.round(), 3);
		assert_eq!(r3.party_id(), 2);
	}

	#[test]
	fn test_new_share_data_default() {
		let share = NewShareData::default();
		assert_eq!(share.s1.len(), L);
		assert_eq!(share.s2.len(), K);
	}

	#[test]
	fn test_resharing_config_role_detection() {
		use crate::{generate_with_dealer, ThresholdConfig};

		let config = ThresholdConfig::new(2, 3).expect("valid config");
		let seed = [42u8; 32];
		let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

		// Test OldOnly role (party leaving)
		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1], // party 2 is leaving
			2,
			Some(shares[2].clone()),
			public_key.clone(),
		)
		.expect("valid config");
		assert_eq!(resharing_config.role, ResharingRole::OldOnly);
		assert!(resharing_config.role.is_old_committee());
		assert!(!resharing_config.role.is_new_committee());

		// Test NewOnly role (party joining)
		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 3], // party 3 is joining
			3,
			None,
			public_key.clone(),
		)
		.expect("valid config");
		assert_eq!(resharing_config.role, ResharingRole::NewOnly);
		assert!(!resharing_config.role.is_old_committee());
		assert!(resharing_config.role.is_new_committee());

		// Test Both role (party staying)
		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 3],
			0,
			Some(shares[0].clone()),
			public_key.clone(),
		)
		.expect("valid config");
		assert_eq!(resharing_config.role, ResharingRole::Both);
		assert!(resharing_config.role.is_old_committee());
		assert!(resharing_config.role.is_new_committee());
	}

	#[test]
	fn test_resharing_config_participant_helpers() {
		use crate::{generate_with_dealer, ThresholdConfig};

		let config = ThresholdConfig::new(2, 3).expect("valid config");
		let seed = [42u8; 32];
		let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

		// Test with old={0,1,2}, new={1,2,3}
		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![1, 2, 3],
			1, // staying
			Some(shares[1].clone()),
			public_key.clone(),
		)
		.expect("valid config");

		// Test leaving_participants (in old but not new)
		let leaving = resharing_config.leaving_participants();
		assert_eq!(leaving.len(), 1);
		assert!(leaving.contains(&0));

		// Test joining_participants (in new but not old)
		let joining = resharing_config.joining_participants();
		assert_eq!(joining.len(), 1);
		assert!(joining.contains(&3));

		// Test staying_participants (in both)
		let staying = resharing_config.staying_participants();
		assert_eq!(staying.len(), 2);
		assert!(staying.contains(&1));
		assert!(staying.contains(&2));

		// Test all_participants (union)
		let all = resharing_config.all_participants();
		assert_eq!(all.len(), 4);
		assert!(all.contains(&0));
		assert!(all.contains(&1));
		assert!(all.contains(&2));
		assert!(all.contains(&3));
	}

	#[test]
	fn test_blinded_contribution_new() {
		// Test creating contributions of various sizes
		for size in 1..10 {
			let contrib = BlindedContribution::new(size);
			assert_eq!(contrib.coefficients.len(), size);
			for poly in &contrib.coefficients {
				assert_eq!(poly.len(), N);
				// All coefficients should be initialized to zero
				for &coeff in poly {
					assert_eq!(coeff, 0);
				}
			}
		}
	}

	#[test]
	fn test_new_share_data_initialization() {
		let share = NewShareData::new();

		// Verify correct dimensions
		assert_eq!(share.s1.len(), L);
		assert_eq!(share.s2.len(), K);

		// Verify all initialized to zero
		for poly in &share.s1 {
			assert_eq!(poly.len(), N);
			for &coeff in poly {
				assert_eq!(coeff, 0);
			}
		}
		for poly in &share.s2 {
			assert_eq!(poly.len(), N);
			for &coeff in poly {
				assert_eq!(coeff, 0);
			}
		}
	}

	#[test]
	fn test_resharing_config_threshold_boundaries() {
		let pk = make_test_public_key();

		// Test minimum valid threshold (t=2)
		let result = ResharingConfig::new(2, vec![0, 1], 2, vec![0, 1], 0, None, pk.clone());
		// This will fail because party 0 is in old committee but has no share
		assert!(matches!(result, Err(ResharingConfigError::MissingExistingShare)));

		// Test threshold = n (all parties required)
		let result = ResharingConfig::new(3, vec![0, 1, 2], 3, vec![0, 1, 2], 0, None, pk.clone());
		assert!(matches!(result, Err(ResharingConfigError::MissingExistingShare)));

		// Test invalid: threshold > n
		let result = ResharingConfig::new(4, vec![0, 1, 2], 2, vec![0, 1, 2], 0, None, pk.clone());
		assert!(matches!(result, Err(ResharingConfigError::InvalidOldThreshold { .. })));

		// Test invalid: threshold < 2
		let result = ResharingConfig::new(1, vec![0, 1, 2], 2, vec![0, 1, 2], 0, None, pk.clone());
		assert!(matches!(result, Err(ResharingConfigError::InvalidOldThreshold { .. })));
	}

	#[test]
	fn test_resharing_message_party_id_extraction() {
		// Test Round1
		let r1 = ResharingMessage::Round1(ResharingRound1Broadcast {
			party_id: 42,
			blinded_s1_contribution: BlindedContribution::new_s1(),
			blinded_s2_contribution: BlindedContribution::new_s2(),
			blinding_s1: BlindedContribution::new_s1(),
			blinding_s2: BlindedContribution::new_s2(),
			blinding_commitment: [0u8; COMMITMENT_HASH_SIZE],
		});
		assert_eq!(r1.party_id(), 42);

		// Test Round2
		let r2 = ResharingMessage::Round2(ResharingRound2Message {
			from_party_id: 99,
			to_party_id: 100,
			shares: HashMap::new(),
		});
		assert_eq!(r2.party_id(), 99); // Should return from_party_id

		// Test Round3
		let r3 = ResharingMessage::Round3(ResharingRound3Broadcast {
			party_id: 77,
			share_commitments: HashMap::new(),
			success: true,
			error_message: None,
		});
		assert_eq!(r3.party_id(), 77);
	}

	#[test]
	fn test_resharing_round3_broadcast_error_handling() {
		// Test successful broadcast
		let success = ResharingRound3Broadcast {
			party_id: 0,
			share_commitments: HashMap::new(),
			success: true,
			error_message: None,
		};
		assert!(success.success);
		assert!(success.error_message.is_none());

		// Test failed broadcast with error message
		let failure = ResharingRound3Broadcast {
			party_id: 1,
			share_commitments: HashMap::new(),
			success: false,
			error_message: Some("Share verification failed".to_string()),
		};
		assert!(!failure.success);
		assert_eq!(failure.error_message, Some("Share verification failed".to_string()));
	}

	#[test]
	fn test_resharing_config_error_display() {
		// Test error message formatting
		let err = ResharingConfigError::InvalidOldThreshold { threshold: 5, parties: 3 };
		let msg = format!("{}", err);
		assert!(msg.contains("5"));
		assert!(msg.contains("3"));

		let err = ResharingConfigError::PartyNotInEitherCommittee { party_id: 99 };
		let msg = format!("{}", err);
		assert!(msg.contains("99"));

		let err = ResharingConfigError::DuplicateParticipant;
		let msg = format!("{}", err);
		assert!(msg.contains("Duplicate"));
	}
}
