//! Types for the Resharing (Committee Handoff) protocol.
//!
//! This module defines the configuration, message types, and output structures
//! for the resharing protocol that enables changing the participant set while
//! preserving the same public key.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};

use qp_rusty_crystals_dilithium::params::{K, L, N};

use crate::{
	error::MAX_PARTIES,
	keys::{PrivateKeyShare, PublicKey},
	participants::{ParticipantId, ParticipantList},
	ThresholdConfig,
};

/// Size of commitment hash in bytes.
pub const COMMITMENT_HASH_SIZE: usize = 32;

/// Size of entropy contribution in bytes.
pub const ENTROPY_SIZE: usize = 32;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
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
///
/// # Construction
///
/// Use [`ResharingConfig::new()`] to create a configuration. Direct field access
/// is not available to ensure all configurations are validated.
///
/// # Deserialization
///
/// When deserializing, the configuration is validated to ensure both old and new
/// committee configurations are supported by the threshold scheme. Invalid
/// configurations will fail deserialization.
#[derive(Debug, Clone, BorshSerialize)]
pub struct ResharingConfig {
	/// Threshold configuration for the old committee.
	old_threshold: u32,
	/// Participants in the old committee (sorted).
	old_participants: ParticipantList,
	/// Threshold configuration for the new committee.
	new_threshold: u32,
	/// Participants in the new committee (sorted).
	new_participants: ParticipantList,
	/// This party's identifier.
	my_party_id: ParticipantId,
	/// This party's role in the resharing.
	role: ResharingRole,
	/// This party's existing private key share (if in old committee).
	/// None if this party is NewOnly.
	existing_share: Option<PrivateKeyShare>,
	/// The public key (must be preserved during resharing).
	public_key: PublicKey,
}

impl BorshDeserialize for ResharingConfig {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let old_threshold = u32::deserialize_reader(reader)?;
		let old_participants = ParticipantList::deserialize_reader(reader)?;
		let new_threshold = u32::deserialize_reader(reader)?;
		let new_participants = ParticipantList::deserialize_reader(reader)?;
		let my_party_id = ParticipantId::deserialize_reader(reader)?;
		let role = ResharingRole::deserialize_reader(reader)?;
		let existing_share = Option::<PrivateKeyShare>::deserialize_reader(reader)?;
		let public_key = PublicKey::deserialize_reader(reader)?;

		Self::from_raw_parts(
			old_threshold,
			old_participants,
			new_threshold,
			new_participants,
			my_party_id,
			role,
			existing_share,
			public_key,
		)
		.map_err(|e| {
			borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				alloc::string::ToString::to_string(&e),
			)
		})
	}
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
	/// - Threshold configurations are invalid or unsupported
	/// - Duplicate participant IDs in either committee
	/// - Either committee exceeds MAX_PARTIES
	pub fn new(
		old_threshold: u32,
		old_participants: Vec<ParticipantId>,
		new_threshold: u32,
		new_participants: Vec<ParticipantId>,
		my_party_id: ParticipantId,
		existing_share: Option<PrivateKeyShare>,
		public_key: PublicKey,
	) -> Result<Self, ResharingConfigError> {
		// Check party counts first to give appropriate error messages
		if old_participants.len() > MAX_PARTIES as usize {
			return Err(ResharingConfigError::TooManyOldParties {
				parties: old_participants.len() as u32,
				max: MAX_PARTIES,
			});
		}
		if new_participants.len() > MAX_PARTIES as usize {
			return Err(ResharingConfigError::TooManyNewParties {
				parties: new_participants.len() as u32,
				max: MAX_PARTIES,
			});
		}

		// Create participant lists (validates no duplicates, sorted)
		let old_participant_list = ParticipantList::new(&old_participants)
			.ok_or(ResharingConfigError::DuplicateParticipant)?;

		let new_participant_list = ParticipantList::new(&new_participants)
			.ok_or(ResharingConfigError::DuplicateParticipant)?;

		// Determine role based on membership
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

		Self::from_raw_parts(
			old_threshold,
			old_participant_list,
			new_threshold,
			new_participant_list,
			my_party_id,
			role,
			existing_share,
			public_key,
		)
	}

	/// Internal constructor from already-parsed parts.
	/// Validates all invariants.
	fn from_raw_parts(
		old_threshold: u32,
		old_participants: ParticipantList,
		new_threshold: u32,
		new_participants: ParticipantList,
		my_party_id: ParticipantId,
		role: ResharingRole,
		existing_share: Option<PrivateKeyShare>,
		public_key: PublicKey,
	) -> Result<Self, ResharingConfigError> {
		let old_n = old_participants.len() as u32;
		let new_n = new_participants.len() as u32;

		// Validate old committee against ThresholdConfig requirements
		// This checks MAX_PARTIES, threshold bounds, and supported (t, n) combinations
		if ThresholdConfig::new(old_threshold, old_n).is_err() {
			return Err(if old_n > MAX_PARTIES {
				ResharingConfigError::TooManyOldParties { parties: old_n, max: MAX_PARTIES }
			} else {
				ResharingConfigError::InvalidOldThreshold {
					threshold: old_threshold,
					parties: old_n,
				}
			});
		}

		// Validate new committee against ThresholdConfig requirements
		if ThresholdConfig::new(new_threshold, new_n).is_err() {
			return Err(if new_n > MAX_PARTIES {
				ResharingConfigError::TooManyNewParties { parties: new_n, max: MAX_PARTIES }
			} else {
				ResharingConfigError::InvalidNewThreshold {
					threshold: new_threshold,
					parties: new_n,
				}
			});
		}

		// Validate role matches actual membership
		let in_old = old_participants.contains(my_party_id);
		let in_new = new_participants.contains(my_party_id);

		let expected_role = match (in_old, in_new) {
			(true, true) => ResharingRole::Both,
			(true, false) => ResharingRole::OldOnly,
			(false, true) => ResharingRole::NewOnly,
			(false, false) =>
				return Err(ResharingConfigError::PartyNotInEitherCommittee {
					party_id: my_party_id,
				}),
		};

		if role != expected_role {
			return Err(ResharingConfigError::RoleMismatch {
				party_id: my_party_id,
				expected: expected_role,
				actual: role,
			});
		}

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
			old_participants,
			new_threshold,
			new_participants,
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

	/// Get the old committee threshold value.
	pub fn old_threshold(&self) -> u32 {
		self.old_threshold
	}

	/// Get the new committee threshold value.
	pub fn new_threshold(&self) -> u32 {
		self.new_threshold
	}

	/// Get the old committee participants.
	pub fn old_participants(&self) -> &ParticipantList {
		&self.old_participants
	}

	/// Get the new committee participants.
	pub fn new_participants(&self) -> &ParticipantList {
		&self.new_participants
	}

	/// Get this party's identifier.
	pub fn my_party_id(&self) -> ParticipantId {
		self.my_party_id
	}

	/// Get this party's role in the resharing.
	pub fn role(&self) -> ResharingRole {
		self.role
	}

	/// Get this party's existing private key share (if in old committee).
	pub fn existing_share(&self) -> Option<&PrivateKeyShare> {
		self.existing_share.as_ref()
	}

	/// Get the public key.
	pub fn public_key(&self) -> &PublicKey {
		&self.public_key
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
	/// Too many parties in old committee (max 6).
	TooManyOldParties { parties: u32, max: u32 },
	/// Too many parties in new committee (max 6).
	TooManyNewParties { parties: u32, max: u32 },
	/// Party is not in either committee.
	PartyNotInEitherCommittee { party_id: ParticipantId },
	/// Duplicate participant ID in a committee.
	DuplicateParticipant,
	/// Existing share provided but party is not in old committee.
	UnexpectedExistingShare,
	/// No existing share provided but party is in old committee.
	MissingExistingShare,
	/// Role field doesn't match actual committee membership.
	RoleMismatch { party_id: ParticipantId, expected: ResharingRole, actual: ResharingRole },
}

impl fmt::Display for ResharingConfigError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			ResharingConfigError::InvalidOldThreshold { threshold, parties } => {
				write!(f, "Invalid old threshold: t={}, n={}", threshold, parties)
			},
			ResharingConfigError::InvalidNewThreshold { threshold, parties } => {
				write!(f, "Invalid new threshold: t={}, n={}", threshold, parties)
			},
			ResharingConfigError::TooManyOldParties { parties, max } => {
				write!(f, "Too many parties in old committee: {} (max {})", parties, max)
			},
			ResharingConfigError::TooManyNewParties { parties, max } => {
				write!(f, "Too many parties in new committee: {} (max {})", parties, max)
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
			ResharingConfigError::RoleMismatch { party_id, expected, actual } => {
				write!(
					f,
					"Role mismatch for party {}: expected {:?}, got {:?}",
					party_id, expected, actual
				)
			},
		}
	}
}

// ============================================================================
// Resharing Messages
// ============================================================================

/// Wrapper enum for all resharing protocol messages.
///
/// This allows messages to be serialized/deserialized without knowing
/// the specific round at deserialization time.
///
/// # Protocol Rounds (5-round forward-secrecy protocol)
///
/// - **Round 1**: Entropy commitment (old committee broadcasts `H(entropy)`)
/// - **Round 2**: Entropy reveal (old committee reveals entropy, session seed computed)
/// - **Round 3**: Sub-share commitments (designated dealers broadcast `H(r_{I→J})`)
/// - **Round 4**: Private delivery (dealers send `r_{I→J}` to new committee)
/// - **Round 5**: Verification (share commitments, partial PKs, accusations)
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum ResharingMessage {
	/// Round 1: Entropy commitment from old committee members.
	Round1(ResharingRound1EntropyCommitment),
	/// Round 2: Entropy reveal from old committee members.
	Round2(ResharingRound2EntropyReveal),
	/// Round 3: Hash commitments to per-subset sub-shares from old committee.
	Round3(ResharingRound3Broadcast),
	/// Round 4: New share distributions to new committee.
	Round4(ResharingRound4Message),
	/// Round 5: Verification commitments from new committee.
	Round5(ResharingRound5Broadcast),
}

impl ResharingMessage {
	/// Get the party ID that sent this message.
	pub fn party_id(&self) -> ParticipantId {
		match self {
			ResharingMessage::Round1(msg) => msg.party_id,
			ResharingMessage::Round2(msg) => msg.party_id,
			ResharingMessage::Round3(msg) => msg.party_id,
			ResharingMessage::Round4(msg) => msg.from_party_id,
			ResharingMessage::Round5(msg) => msg.party_id,
		}
	}

	/// Get the round number of this message.
	pub fn round(&self) -> u8 {
		match self {
			ResharingMessage::Round1(_) => 1,
			ResharingMessage::Round2(_) => 2,
			ResharingMessage::Round3(_) => 3,
			ResharingMessage::Round4(_) => 4,
			ResharingMessage::Round5(_) => 5,
		}
	}
}

// ============================================================================
// Round 1: Entropy Commitment (Forward Secrecy)
// ============================================================================

/// Round 1 broadcast from old committee members.
///
/// Each old committee member generates fresh entropy and broadcasts a hash
/// commitment to it. This is the first step of the commit-reveal scheme that
/// provides forward secrecy by ensuring the session seed cannot be predicted
/// before all commitments are published.
///
/// # Forward Secrecy
///
/// By having all old committee members contribute entropy via commit-reveal,
/// an attacker who compromises old shares after resharing cannot determine
/// the randomness used to derive new shares, even if they observe all protocol
/// messages.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ResharingRound1EntropyCommitment {
	/// Party ID of the sender.
	pub party_id: ParticipantId,
	/// Hash commitment to the entropy: `SHAKE256("resharing-entropy-commit-v1" || entropy)`.
	pub commitment: [u8; COMMITMENT_HASH_SIZE],
}

// ============================================================================
// Round 2: Entropy Reveal (Forward Secrecy)
// ============================================================================

/// Round 2 broadcast from old committee members.
///
/// Each old committee member reveals their entropy contribution. All parties
/// verify the revealed entropy matches the Round 1 commitment, then compute
/// the session seed as:
///
/// ```text
/// session_seed = SHAKE256("resharing-session-seed-v1" || party_id_1 || entropy_1 || ...)
/// ```
///
/// where parties are processed in sorted order by party ID.
///
/// # Verification
///
/// If any party's revealed entropy does not match their commitment, the
/// protocol fails immediately with `CommitmentMismatch(party_id)`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ResharingRound2EntropyReveal {
	/// Party ID of the sender.
	pub party_id: ParticipantId,
	/// The revealed entropy (32 bytes of randomness).
	pub entropy: [u8; ENTROPY_SIZE],
}

// ============================================================================
// Round 3: Per-Subset Commitment Broadcast
// ============================================================================

/// Round 3 broadcast from old committee members.
///
/// Each old committee member broadcasts hash commitments to the per-subset
/// "sub-share" contributions they will privately deliver in Round 4. A party
/// only commits to subsets where they are the *designated dealer* (the
/// lowest-ID old participant in the subset). Other members of the same old
/// subset independently recompute the same contributions and verify the
/// commitment in Round 5.
///
/// # Security
///
/// Unlike the previous design, **no share values, blindings, or aggregations
/// are revealed in clear**. The only public data is the hash commitment to
/// each `r_{I→J}`, which is hiding because each `r_{I→J}` has at least
/// `5^256 ≈ 2^594` bits of entropy (the η-bounded sample space) or is itself
/// a function of secret share material.
///
/// # Forward Secrecy
///
/// The session seed (computed from Round 1-2 entropy contributions) is mixed
/// into the PRF that derives sub-shares, ensuring that even if old shares are
/// later compromised, the specific randomness used in this resharing cannot
/// be reconstructed.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ResharingRound3Broadcast {
	/// Party ID of the sender.
	pub party_id: ParticipantId,
	/// Commitments keyed by `(old_subset_mask, new_subset_mask)`.
	///
	/// The sender is the designated dealer for `old_subset_mask`. Each commitment is
	/// `SHAKE256("resharing-commit-v3" || old_subset || new_subset || pack(r))`.
	pub commitments: BTreeMap<SubsetPair, [u8; COMMITMENT_HASH_SIZE]>,
}

/// Composite key identifying a contribution from one old subset to one new subset.
pub type SubsetPair = (SubsetMask, SubsetMask);

// ============================================================================
// Round 4: Private Sub-Share Reveal
// ============================================================================

/// Round 4 private message from a designated dealer to a new committee member.
///
/// For each pair `(I, J)` where the sender is the designated dealer of old subset
/// `I` and the recipient is a member of new subset `J`, the message carries the
/// deterministic sub-share `r_{I→J}` such that `Σ_J r_{I→J} = s_I^old`.
///
/// New shares are then computed (privately, by each new committee member) as
/// `s_J^new = Σ_I r_{I→J}`.
///
/// # ⚠️ Security Warning
///
/// This message contains **secret share material in plaintext**. It **MUST** be
/// transmitted via [`Action::SendPrivate`] over an authenticated-encrypted channel.
/// The protocol does not provide encryption; the transport layer must ensure:
/// - Confidentiality (only the recipient can read)
/// - Authenticity (recipient verifies sender identity)
/// - Integrity (cannot be modified in transit)
///
/// Transmitting this message over an unencrypted channel exposes sub-shares to
/// eavesdroppers and compromises the threshold scheme's security.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ResharingRound4Message {
	/// Party ID of the sender (dealer).
	pub from_party_id: ParticipantId,
	/// Party ID of the recipient.
	pub to_party_id: ParticipantId,
	/// Per-`(old_subset, new_subset)` contributions destined for the recipient.
	pub contributions: BTreeMap<SubsetPair, NewShareData>,
}

/// New share data for a specific subset.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct NewShareData {
	/// Share of s1 polynomial vector (exactly L polynomials).
	pub s1: [[i32; N as usize]; L],
	/// Share of s2 polynomial vector (exactly K polynomials).
	pub s2: [[i32; N as usize]; K],
}

impl NewShareData {
	/// Create a new empty share data (all zeros).
	pub fn new() -> Self {
		Self { s1: [[0i32; N as usize]; L], s2: [[0i32; N as usize]; K] }
	}
}

impl Default for NewShareData {
	fn default() -> Self {
		Self::new()
	}
}

// ============================================================================
// Round 5: Verification
// ============================================================================

/// Round 5 broadcast.
///
/// Round 5 has three purposes:
///
/// 1. **New committee verification.** Each new committee member broadcasts a commitment to each
///    `s_J^new` they computed for new subsets `J` containing them. Other members of the same `J`
///    should produce identical commitments; any mismatch indicates inconsistent dealing (e.g., a
///    malicious dealer who sent different `r_{I→J}` to different recipients).
///
/// 2. **Old committee cross-verification.** Old committee members that share an old subset `I` with
///    the dealer `D_I` independently recompute the deterministic `r_{I→J}` values from their own
///    copy of `s_I^old` and compare them against `D_I`'s broadcast commitments. Any mismatch is
///    reported as a `DealerAccusation`. If the accusation is correct (the accuser's recomputation
///    matches their own private knowledge of `s_I`), the resharing fails.
///
/// 3. **Public-key invariant verification.** Each new committee member additionally publishes
///    `t_J^new = A·s1_J^new + s2_J^new mod Q` for every new subset `J` it belongs to. Anyone can
///    sum these `t_J` and check that the result reconstructs the original public key. This catches
///    a malicious dealer that lies about the residual `r_{I→J}` in a *size-1* old subset (`t = n`
///    configurations), where there is no other old-subset member to cross-verify in purpose 2.
///    Publishing `t_J^new` is safe: recovering `s_J^new` from `t_J^new` is the LWE problem.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ResharingRound5Broadcast {
	/// Party ID of the sender.
	pub party_id: ParticipantId,
	/// Commitments to each computed new subset share (only populated by new committee members).
	pub share_commitments: BTreeMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]>,
	/// Partial public-key contributions `t_J^new = A·s1_J^new + s2_J^new mod Q`,
	/// one entry per new subset `J` this party belongs to. Empty for old-only parties.
	/// Each entry has exactly `K` polynomials (enforced by the fixed-size array type).
	pub partial_pks: BTreeMap<SubsetMask, [[i32; N as usize]; K]>,
	/// Accusations against dealers whose broadcast commitments did not match
	/// the sender's independent recomputation.
	pub accusations: Vec<DealerAccusation>,
	/// Indicates whether this party processed Round 3/4 successfully.
	pub success: bool,
	/// Optional error message if `success` is false.
	pub error_message: Option<String>,
}

/// An accusation that a dealer published a commitment that does not match
/// the independent recomputation by another member of the same old subset.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DealerAccusation {
	/// The party being accused (the broadcaster of the bad commitment).
	pub dealer: ParticipantId,
	/// The old subset for which the dealer's commitment was wrong.
	pub old_subset: SubsetMask,
	/// The new subset whose `r_{I→J}` commitment was wrong.
	pub new_subset: SubsetMask,
}

// ============================================================================
// Resharing Output
// ============================================================================

/// Output of a successful resharing protocol.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
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
	use alloc::{format, string::ToString};

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
	fn test_message_round_numbers() {
		let r1 = ResharingMessage::Round1(ResharingRound1EntropyCommitment {
			party_id: 0,
			commitment: [0u8; COMMITMENT_HASH_SIZE],
		});
		assert_eq!(r1.round(), 1);
		assert_eq!(r1.party_id(), 0);

		let r2 = ResharingMessage::Round2(ResharingRound2EntropyReveal {
			party_id: 1,
			entropy: [0u8; ENTROPY_SIZE],
		});
		assert_eq!(r2.round(), 2);
		assert_eq!(r2.party_id(), 1);

		let r3 = ResharingMessage::Round3(ResharingRound3Broadcast {
			party_id: 2,
			commitments: BTreeMap::new(),
		});
		assert_eq!(r3.round(), 3);
		assert_eq!(r3.party_id(), 2);

		let r4 = ResharingMessage::Round4(ResharingRound4Message {
			from_party_id: 3,
			to_party_id: 4,
			contributions: BTreeMap::new(),
		});
		assert_eq!(r4.round(), 4);
		assert_eq!(r4.party_id(), 3);

		let r5 = ResharingMessage::Round5(ResharingRound5Broadcast {
			party_id: 5,
			share_commitments: BTreeMap::new(),
			partial_pks: BTreeMap::new(),
			accusations: Vec::new(),
			success: true,
			error_message: None,
		});
		assert_eq!(r5.round(), 5);
		assert_eq!(r5.party_id(), 5);
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
	fn test_new_share_data_initialization() {
		let share = NewShareData::new();

		// Verify correct dimensions
		assert_eq!(share.s1.len(), L);
		assert_eq!(share.s2.len(), K);

		// Verify all initialized to zero
		for poly in &share.s1 {
			assert_eq!(poly.len(), N as usize);
			for &coeff in poly {
				assert_eq!(coeff, 0);
			}
		}
		for poly in &share.s2 {
			assert_eq!(poly.len(), N as usize);
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
		let r1 = ResharingMessage::Round1(ResharingRound1EntropyCommitment {
			party_id: 42,
			commitment: [0u8; COMMITMENT_HASH_SIZE],
		});
		assert_eq!(r1.party_id(), 42);

		let r2 = ResharingMessage::Round2(ResharingRound2EntropyReveal {
			party_id: 99,
			entropy: [0u8; ENTROPY_SIZE],
		});
		assert_eq!(r2.party_id(), 99);

		let r3 = ResharingMessage::Round3(ResharingRound3Broadcast {
			party_id: 77,
			commitments: BTreeMap::new(),
		});
		assert_eq!(r3.party_id(), 77);

		let r4 = ResharingMessage::Round4(ResharingRound4Message {
			from_party_id: 88,
			to_party_id: 100,
			contributions: BTreeMap::new(),
		});
		assert_eq!(r4.party_id(), 88);

		let r5 = ResharingMessage::Round5(ResharingRound5Broadcast {
			party_id: 55,
			share_commitments: BTreeMap::new(),
			partial_pks: BTreeMap::new(),
			accusations: Vec::new(),
			success: true,
			error_message: None,
		});
		assert_eq!(r5.party_id(), 55);
	}

	#[test]
	fn test_resharing_round5_broadcast_error_handling() {
		let success = ResharingRound5Broadcast {
			party_id: 0,
			share_commitments: BTreeMap::new(),
			partial_pks: BTreeMap::new(),
			accusations: Vec::new(),
			success: true,
			error_message: None,
		};
		assert!(success.success);
		assert!(success.error_message.is_none());

		let failure = ResharingRound5Broadcast {
			party_id: 1,
			share_commitments: BTreeMap::new(),
			partial_pks: BTreeMap::new(),
			accusations: Vec::new(),
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

		let err = ResharingConfigError::TooManyOldParties { parties: 10, max: 6 };
		let msg = format!("{}", err);
		assert!(msg.contains("10"));
		assert!(msg.contains("6"));
		assert!(msg.contains("old"));
	}

	#[test]
	fn test_config_too_many_old_parties() {
		let pk = make_test_public_key();

		// Test with 7 parties in old committee (exceeds MAX_PARTIES=6)
		let result = ResharingConfig::new(
			2,
			vec![0, 1, 2, 3, 4, 5, 6], // 7 parties
			2,
			vec![0, 1, 2],
			0,
			None,
			pk.clone(),
		);

		assert!(matches!(
			result,
			Err(ResharingConfigError::TooManyOldParties { parties: 7, max: 6 })
		));
	}

	#[test]
	fn test_config_too_many_new_parties() {
		let pk = make_test_public_key();

		// Test with 7 parties in new committee (exceeds MAX_PARTIES=6)
		let result = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2, 3, 4, 5, 6], // 7 parties
			0,
			None,
			pk.clone(),
		);

		assert!(matches!(
			result,
			Err(ResharingConfigError::TooManyNewParties { parties: 7, max: 6 })
		));
	}

	#[test]
	fn test_round5_broadcast_serialization_roundtrip() {
		use borsh::{BorshDeserialize, BorshSerialize};

		// Create a Round5 broadcast with valid data
		let mut partial_pks: BTreeMap<SubsetMask, [[i32; N as usize]; K]> = BTreeMap::new();
		partial_pks.insert(0b011, [[42i32; N as usize]; K]);

		let broadcast = ResharingRound5Broadcast {
			party_id: 5,
			share_commitments: BTreeMap::new(),
			partial_pks,
			accusations: Vec::new(),
			success: true,
			error_message: None,
		};

		// Serialize and deserialize
		let mut data = Vec::new();
		broadcast.serialize(&mut data).unwrap();
		let broadcast2 = ResharingRound5Broadcast::try_from_slice(&data).unwrap();

		assert_eq!(broadcast.party_id, broadcast2.party_id);
		assert_eq!(broadcast.partial_pks.len(), broadcast2.partial_pks.len());
		assert_eq!(broadcast.partial_pks.get(&0b011), broadcast2.partial_pks.get(&0b011));
		assert_eq!(broadcast.success, broadcast2.success);
	}

	#[test]
	fn test_round5_broadcast_partial_pk_fixed_size() {
		// Verify that partial_pks entries have exactly K polynomials at compile time
		let mut partial_pks: BTreeMap<SubsetMask, [[i32; N as usize]; K]> = BTreeMap::new();
		partial_pks.insert(0b011, [[0i32; N as usize]; K]);

		let broadcast = ResharingRound5Broadcast {
			party_id: 0,
			share_commitments: BTreeMap::new(),
			partial_pks,
			accusations: Vec::new(),
			success: true,
			error_message: None,
		};

		// The fixed-size array type guarantees exactly K polynomials
		assert_eq!(broadcast.partial_pks.get(&0b011).unwrap().len(), K);
	}

	#[test]
	fn test_new_share_data_borsh_roundtrip() {
		// Valid NewShareData should round-trip successfully
		let share_data = NewShareData::new();
		assert_eq!(share_data.s1.len(), L);
		assert_eq!(share_data.s2.len(), K);

		let serialized = borsh::to_vec(&share_data).unwrap();
		let deserialized: NewShareData = borsh::from_slice(&serialized).unwrap();
		assert_eq!(deserialized.s1.len(), L);
		assert_eq!(deserialized.s2.len(), K);
	}

	#[test]
	fn test_new_share_data_fixed_size_compile_time() {
		// This test verifies that NewShareData uses fixed-size arrays.
		// The type system enforces exact dimensions at compile time,
		// preventing truncation attacks (cf. WSTS PR #88 vulnerability pattern).
		//
		// If someone tried to change s1 to Vec<[i32; N]>, this test would fail to compile.
		let share_data = NewShareData::new();

		// These assertions are compile-time guarantees via the array type
		let _s1: &[[i32; N as usize]; L] = &share_data.s1;
		let _s2: &[[i32; N as usize]; K] = &share_data.s2;

		// Runtime verification (redundant but documents the invariant)
		assert_eq!(core::mem::size_of_val(&share_data.s1), L * N as usize * 4);
		assert_eq!(core::mem::size_of_val(&share_data.s2), K * N as usize * 4);
	}

	#[test]
	fn test_new_share_data_rejects_truncated_serialization() {
		// Manually craft truncated serialized data - should fail deserialization
		let share_data = NewShareData::new();
		let serialized = borsh::to_vec(&share_data).unwrap();

		// Truncate to half - should fail
		let truncated = &serialized[..serialized.len() / 2];
		let result: Result<NewShareData, _> = borsh::from_slice(truncated);
		assert!(result.is_err(), "Should reject truncated data");
	}
}
