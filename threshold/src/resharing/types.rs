//! Types for the Resharing (Committee Handoff) protocol.
//!
//! This module defines the configuration, message types, and output structures
//! for the resharing protocol that enables changing the participant set while
//! preserving the same public key.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use qp_rusty_crystals_dilithium::params::{K, L, N};

use crate::{
	error::{MAX_PARTIES, MAX_SUBSETS, MAX_SUBSET_PAIRS},
	keys::{PrivateKeyShare, PublicKey},
	participants::{ParticipantId, ParticipantList},
	ThresholdConfig,
};

/// Size of commitment hash in bytes.
pub const COMMITMENT_HASH_SIZE: usize = 32;

/// Size of entropy contribution in bytes.
pub const ENTROPY_SIZE: usize = 32;

/// Size of session identifier (SSID) in bytes.
pub const RESHARING_SSID_SIZE: usize = 32;

/// Current resharing protocol version baked into the SSID.
///
/// Bump when the round structure or wire format changes incompatibly.
pub const RESHARING_PROTOCOL_VERSION: u32 = 2;

/// Cryptographic suite identifier for threshold ML-DSA-87 RSS resharing.
pub const RESHARING_SUITE_ML_DSA_87: u32 = 1;

/// Maximum absolute value for sub-share coefficients in resharing.
///
/// This bound defends against malicious dealers who might inject arbitrarily large
/// coefficients into `r_{I→J}` sub-shares. While the PK preservation check ensures
/// `Σ_J r_{I→J} ≡ s_I^old (mod Q)`, it does not prevent large individual coefficients
/// that could push recovered signing partials beyond hyperball bounds.
///
/// The bound is derived from honest behavior analysis:
/// - For input coefficient `c` split across `m` new subsets: base = `|c|/m`
/// - Plus pairwise noise: `(m-1) * η` where η=2
/// - Post-resharing coefficients typically |coeff| < 150 (4σ bound for 4-of-6)
/// - For m=20 (4-of-6): max honest sub-share ≈ 150/20 + 19*2 ≈ 46
///
/// Bound of 500 provides ~10x margin over expected honest behavior while catching
/// attacks that could compromise hyperball security (e.g., injecting Q/2 ≈ 4.2M).
pub const SUBSHARE_COEFF_BOUND: i32 = 500;

/// Domain separator for SSID computation (V2 includes version, suite, epoch).
const DOMAIN_RESHARING_SSID: &[u8] = b"RESHARING_SSID_V2";

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
/// For old committee members, the existing share is stored here as the single
/// source of truth for old committee parameters.
#[derive(Debug, Clone)]
pub struct ResharingConfig {
	old_threshold: u32,
	old_participants: ParticipantList,
	new_threshold: u32,
	new_participants: ParticipantList,
	my_party_id: ParticipantId,
	role: ResharingRole,
	public_key: PublicKey,
	/// The existing share for old committee members. None for NewOnly parties.
	existing_share: Option<PrivateKeyShare>,
}

impl ResharingConfig {
	/// Create a new resharing configuration.
	///
	/// # Arguments
	///
	/// * `existing_share` - The party's existing share if they're in the old committee, `None` if
	///   joining
	/// * `old_participants` - List of all old committee member IDs
	/// * `new_threshold` - Threshold for the new committee
	/// * `new_participants` - List of all new committee member IDs
	/// * `my_party_id` - This party's ID (only used if `existing_share` is `None`)
	/// * `public_key` - The threshold public key
	///
	/// When `existing_share` is `Some`:
	/// - `old_threshold` is extracted from the share
	/// - `my_party_id` parameter is ignored (share's party_id is used)
	/// - Share's TR must match public_key's TR
	/// - Share's party_id must be in old_participants
	///
	/// When `existing_share` is `None`:
	/// - `my_party_id` must NOT be in old_participants (new-only member)
	/// - `my_party_id` must be in new_participants
	pub fn new(
		existing_share: Option<PrivateKeyShare>,
		old_threshold: u32,
		old_participants: Vec<ParticipantId>,
		new_threshold: u32,
		new_participants: Vec<ParticipantId>,
		my_party_id: ParticipantId,
		public_key: PublicKey,
	) -> Result<Self, ResharingConfigError> {
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

		let old_participant_list = ParticipantList::new(&old_participants)
			.ok_or(ResharingConfigError::DuplicateParticipant)?;

		let new_participant_list = ParticipantList::new(&new_participants)
			.ok_or(ResharingConfigError::DuplicateParticipant)?;

		// Determine actual values based on whether we have an existing share
		let (actual_party_id, actual_old_threshold, role) = if let Some(ref share) = existing_share
		{
			// Old committee member: extract values from share
			let party_id = share.party_id();
			let threshold = share.threshold();

			// Validate share's TR matches public key
			if share.tr() != public_key.tr() {
				return Err(ResharingConfigError::PublicKeyMismatch);
			}

			// Validate share's party_id is in old committee
			if !old_participant_list.contains(party_id) {
				return Err(ResharingConfigError::SharePartyNotInOldCommittee { party_id });
			}

			// The share's stored subset masks are defined relative to its
			// embedded DKG participant list, but the protocol maps mask bits
			// to parties through `old_participants` (dealer assignment,
			// subset enumeration, share lookup). The two lists must be
			// identical, or this party would deal sub-share material derived
			// from its real share under a different identity mapping than
			// the one the shares were created with. The party-count check
			// additionally rejects shares whose stored `total_parties` is
			// inconsistent with their own participant list.
			if share.dkg_participants() != &old_participant_list ||
				share.total_parties() as usize != old_participant_list.len()
			{
				return Err(ResharingConfigError::OldCommitteeMismatch);
			}

			// Validate share's threshold matches old_threshold parameter
			if threshold != old_threshold {
				return Err(ResharingConfigError::ThresholdMismatch {
					share_threshold: threshold,
					config_threshold: old_threshold,
				});
			}

			// Determine role based on new committee membership
			let role = if new_participant_list.contains(party_id) {
				ResharingRole::Both
			} else {
				ResharingRole::OldOnly
			};

			(party_id, threshold, role)
		} else {
			// New-only member: use provided values
			// Validate they're NOT in old committee
			if old_participant_list.contains(my_party_id) {
				return Err(ResharingConfigError::OldMemberMustProvideShare {
					party_id: my_party_id,
				});
			}
			// Validate they ARE in new committee
			if !new_participant_list.contains(my_party_id) {
				return Err(ResharingConfigError::PartyNotInEitherCommittee {
					party_id: my_party_id,
				});
			}

			(my_party_id, old_threshold, ResharingRole::NewOnly)
		};

		// Validate thresholds
		let old_n = old_participant_list.len() as u32;
		let new_n = new_participant_list.len() as u32;

		if ThresholdConfig::new(actual_old_threshold, old_n).is_err() {
			return Err(ResharingConfigError::InvalidOldThreshold {
				threshold: actual_old_threshold,
				parties: old_n,
			});
		}

		if ThresholdConfig::new(new_threshold, new_n).is_err() {
			return Err(ResharingConfigError::InvalidNewThreshold {
				threshold: new_threshold,
				parties: new_n,
			});
		}

		Ok(Self {
			old_threshold: actual_old_threshold,
			old_participants: old_participant_list,
			new_threshold,
			new_participants: new_participant_list,
			my_party_id: actual_party_id,
			role,
			public_key,
			existing_share,
		})
	}

	/// Get the existing share (for old committee members).
	///
	/// Returns `Some` for OldOnly and Both roles, `None` for NewOnly.
	pub fn existing_share(&self) -> Option<&PrivateKeyShare> {
		self.existing_share.as_ref()
	}

	/// Securely erase the old committee share held in this config.
	///
	/// Called automatically when the protocol completes successfully. Integrators
	/// should treat the returned new share as the only live key material after
	/// a successful handoff.
	pub fn zeroize_existing_share(&mut self) {
		if let Some(mut share) = self.existing_share.take() {
			share.zeroize();
		}
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
	/// Old committee member must provide their existing share.
	OldMemberMustProvideShare { party_id: ParticipantId },
	/// Share's party_id is not in the old committee.
	SharePartyNotInOldCommittee { party_id: ParticipantId },
	/// Old committee does not exactly match the share's embedded DKG
	/// participant list, so the share's subset masks would be interpreted
	/// under a different identity mapping than the one they were created
	/// with.
	OldCommitteeMismatch,
	/// Share's public key (TR) doesn't match the provided public key.
	PublicKeyMismatch,
	/// Share's threshold doesn't match the old_threshold parameter.
	ThresholdMismatch { share_threshold: u32, config_threshold: u32 },
	/// Signer configuration is missing the verifying key for a new committee member.
	MissingVerifyingKey(ParticipantId),
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
			ResharingConfigError::MissingVerifyingKey(party_id) => {
				write!(f, "Missing verifying key for new committee member {}", party_id)
			},
			ResharingConfigError::DuplicateParticipant => {
				write!(f, "Duplicate participant ID in committee")
			},
			ResharingConfigError::OldMemberMustProvideShare { party_id } => {
				write!(
					f,
					"Party {} is in old committee but no existing share was provided",
					party_id
				)
			},
			ResharingConfigError::SharePartyNotInOldCommittee { party_id } => {
				write!(
					f,
					"Share's party_id ({}) is not in the old committee participant list",
					party_id
				)
			},
			ResharingConfigError::OldCommitteeMismatch => {
				write!(f, "Old committee does not match the share's embedded DKG participant list")
			},
			ResharingConfigError::PublicKeyMismatch => {
				write!(f, "Share's public key hash (TR) does not match the provided public key")
			},
			ResharingConfigError::ThresholdMismatch { share_threshold, config_threshold } => {
				write!(
					f,
					"Share threshold ({}) does not match old_threshold parameter ({})",
					share_threshold, config_threshold
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
/// # Protocol Rounds (session-randomized protocol with active-set liveness)
///
/// - **Round 1**: Entropy commitment / Ready (old committee broadcasts `H(entropy)`)
/// - **Act proposal**: Leader proposes the active set `Act` of ready old members
/// - **Round 2**: Entropy reveal (active members reveal entropy, session seed computed)
/// - **Round 3**: Sub-share commitments (designated dealers broadcast `H(r_{I→J})`)
/// - **Round 4**: Private delivery (dealers send `r_{I→J}` to new committee)
/// - **Round 5**: Verification (share commitments, partial PKs)
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum ResharingMessage {
	/// Round 1: Entropy commitment from old committee members (doubles as Ready).
	Round1(ResharingRound1EntropyCommitment),
	/// Round 2: Entropy reveal from active old committee members.
	Round2(ResharingRound2EntropyReveal),
	/// Round 3: Hash commitments to per-subset sub-shares from active old committee.
	Round3(ResharingRound3Broadcast),
	/// Round 4: New share distributions to new committee.
	Round4(ResharingRound4Message),
	/// Round 5: Verification commitments from new committee.
	Round5(ResharingRound5Broadcast),
	/// Active-set proposal from the session leader (between Rounds 1 and 2).
	///
	/// Appended after the round variants to preserve Borsh variant indices of
	/// the pre-existing wire format.
	ActProposal(ResharingActProposal),
	/// Round 6: Signed acceptance of the session transcript from new committee
	/// members. Appended to preserve Borsh variant indices.
	Accept(ResharingAccept),
}

impl ResharingMessage {
	/// Get the session identifier (SSID) from this message.
	pub fn ssid(&self) -> &[u8; RESHARING_SSID_SIZE] {
		match self {
			ResharingMessage::Round1(msg) => &msg.ssid,
			ResharingMessage::Round2(msg) => &msg.ssid,
			ResharingMessage::Round3(msg) => &msg.ssid,
			ResharingMessage::Round4(msg) => &msg.ssid,
			ResharingMessage::Round5(msg) => &msg.ssid,
			ResharingMessage::ActProposal(msg) => &msg.ssid,
			ResharingMessage::Accept(msg) => &msg.ssid,
		}
	}

	/// Get the party ID that sent this message.
	pub fn party_id(&self) -> ParticipantId {
		match self {
			ResharingMessage::Round1(msg) => msg.party_id,
			ResharingMessage::Round2(msg) => msg.party_id,
			ResharingMessage::Round3(msg) => msg.party_id,
			ResharingMessage::Round4(msg) => msg.from_party_id,
			ResharingMessage::Round5(msg) => msg.party_id,
			ResharingMessage::ActProposal(msg) => msg.party_id,
			ResharingMessage::Accept(msg) => msg.party_id,
		}
	}

	/// Get the round number of this message.
	///
	/// The Act proposal sits between Rounds 1 and 2; it reports round 1
	/// (it concludes the Ready phase that Round 1 commitments open).
	pub fn round(&self) -> u8 {
		match self {
			ResharingMessage::Round1(_) => 1,
			ResharingMessage::ActProposal(_) => 1,
			ResharingMessage::Round2(_) => 2,
			ResharingMessage::Round3(_) => 3,
			ResharingMessage::Round4(_) => 4,
			ResharingMessage::Round5(_) => 5,
			ResharingMessage::Accept(_) => 6,
		}
	}
}

// ============================================================================
// Round 1: Entropy Commitment (Session Randomization)
// ============================================================================

/// Round 1 broadcast from old committee members.
///
/// Each old committee member generates fresh entropy and broadcasts a hash
/// commitment to it. This is the first step of the commit-reveal scheme that
/// makes the session seed unpredictable before reveals and prevents parties
/// from choosing their entropy after seeing others' revealed values.
///
/// # Threat Model
///
/// The entropy is revealed publicly in Round 2. This provides session
/// randomization and anti-bias properties, but not post-compromise forward
/// secrecy: an attacker who records the transcript and later compromises old
/// subset shares can recompute deterministic resharing randomness.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ResharingRound1EntropyCommitment {
	/// Session identifier binding this message to the resharing session.
	pub ssid: [u8; RESHARING_SSID_SIZE],
	/// Party ID of the sender.
	pub party_id: ParticipantId,
	/// Hash commitment to the entropy: `SHAKE256("resharing-entropy-commit-v1" || entropy)`.
	pub commitment: [u8; COMMITMENT_HASH_SIZE],
}

// ============================================================================
// Active-Set Proposal (Ready-Round Liveness)
// ============================================================================

/// Active-set ("Act") proposal broadcast by the session leader.
///
/// Round 1 entropy commitments double as *Ready* signals: an old committee
/// member that broadcasts its commitment is declaring itself online and
/// willing to participate. The session leader (the lowest-ID new committee
/// member) collects these and proposes the active set `Act` — the old
/// committee members that will contribute entropy and deal sub-shares.
///
/// The leader proposes automatically once every old committee member has
/// committed (fast path). If some old members are offline, the caller invokes
/// [`ResharingProtocol::close_ready_window`](super::ResharingProtocol::close_ready_window)
/// on the leader after a transport-level timeout, and the leader proposes
/// `Act` = the members that committed so far.
///
/// # Validity
///
/// Every party independently verifies the proposal and aborts on violation:
///
/// - sender is the session leader,
/// - `active_set` is strictly sorted, unique, and a subset of the old committee,
/// - `|active_set| >= t_old`.
///
/// The threshold requirement guarantees every old RSS subset `I` (size
/// `n_old - t_old + 1`) intersects `Act`, so a live dealer exists for every
/// subset: dealers are reassigned to the lowest-ID member of `I ∩ Act`.
///
/// # Trust in the leader
///
/// The leader cannot break safety: it cannot forge Ready signals (parties
/// only advance once they have seen the Round 1 commitment of every `Act`
/// member), and the deterministic sub-share derivation means dealer *identity*
/// does not affect the derived shares. A malicious leader can at most deny
/// service (abort/stall) or select *which* committed members participate —
/// the session seed remains unbiased because `|Act| >= t_old` guarantees at
/// least one honest member whose entropy is unpredictable at proposal time
/// (commitments hide entropy until Round 2). Equivocating proposals put the
/// receiving parties in different sessions; their deterministic sub-share
/// commitments then disagree and the protocol aborts.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ResharingActProposal {
	/// Session identifier binding this message to the resharing session.
	pub ssid: [u8; RESHARING_SSID_SIZE],
	/// Party ID of the sender (must be the session leader).
	pub party_id: ParticipantId,
	/// Proposed active set: old committee members that will contribute entropy
	/// and deal sub-shares. Strictly sorted, unique, `|active_set| >= t_old`.
	pub active_set: Vec<ParticipantId>,
}

// ============================================================================
// Round 6: Signed Transcript Acceptance
// ============================================================================

/// Maximum accepted signature length in bytes (bounds deserialization).
///
/// Large enough for ML-DSA-87 signatures (4627 bytes) with headroom; small
/// enough to bound memory on malformed input.
pub const MAX_ACCEPT_SIGNATURE_LEN: usize = 8192;

/// Round 6 broadcast: a new committee member's signed acceptance of the
/// session transcript.
///
/// After completing all Round 5 verifications (sub-share commitment checks,
/// new-share consistency, recovered-partial norm guard, and public-key
/// preservation), each new committee member signs the session's transcript
/// hash with its long-term key (see
/// [`TranscriptSigner`](crate::keygen::dkg::TranscriptSigner)) and broadcasts
/// the signature.
///
/// # What agreement on the transcript hash provides
///
/// The transcript hash covers the active set, the session seed, every active
/// member's Round 3 dealer commitments, and every required Round 5 broadcast.
/// Each party verifies every received acceptance against its *own* computed
/// transcript hash, so a valid set of acceptances from the full new committee
/// implies all of them observed identical protocol broadcasts. A dealer that
/// equivocates (sends different Round 3/5 broadcasts to different parties)
/// causes signature verification to fail on at least one honest party, which
/// then aborts.
///
/// The signature is over `SHAKE256("resharing-accept-v3" || ssid ||
/// transcript_hash || len(active_set) || active_set || len(new_committee) ||
/// new_committee)` (see [`compute_accept_hash`]), domain-separating
/// acceptances from any other use of the same long-term key and binding the
/// certificate's `active_set` and `new_committee`.
#[derive(Debug, Clone, BorshSerialize)]
pub struct ResharingAccept {
	/// Session identifier binding this message to the resharing session.
	pub ssid: [u8; RESHARING_SSID_SIZE],
	/// Party ID of the sender (must be a new committee member).
	pub party_id: ParticipantId,
	/// Signature over the acceptance hash (raw bytes, scheme-dependent).
	pub signature: Vec<u8>,
}

impl BorshDeserialize for ResharingAccept {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let ssid = <[u8; RESHARING_SSID_SIZE]>::deserialize_reader(reader)?;
		let party_id = ParticipantId::deserialize_reader(reader)?;
		let sig_len = u32::deserialize_reader(reader)? as usize;
		if sig_len > MAX_ACCEPT_SIGNATURE_LEN {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"ResharingAccept.signature exceeds MAX_ACCEPT_SIGNATURE_LEN",
			));
		}
		// Chunked read: don't allocate the claimed length up front, so a
		// truncated body cannot force an allocation larger than what was
		// actually delivered (same pattern as the certificate accepts).
		let signature = crate::broadcast::read_length_prefixed(reader, sig_len)?;
		Ok(Self { ssid, party_id, signature })
	}
}

/// Long-term-key signing configuration for the resharing protocol.
///
/// Mirrors the DKG's signer configuration: this party's signer plus the
/// verifying keys of (at least) every new committee member. Only new
/// committee members produce acceptance signatures, but every participant
/// verifies them, so every participant needs the new committee's keys.
#[derive(Clone)]
pub struct ResharingSignerConfig<S: crate::keygen::dkg::TranscriptSigner> {
	/// This party's signer for transcript acceptance (used only if this party
	/// is in the new committee).
	pub my_signer: S,
	/// Verifying keys, keyed by participant ID. Must cover every new
	/// committee member; extra entries are ignored.
	pub verifying_keys: BTreeMap<ParticipantId, S::PublicKey>,
}

impl<S: crate::keygen::dkg::TranscriptSigner> ResharingSignerConfig<S> {
	/// Create a signer configuration, checking that `verifying_keys` covers
	/// every new committee member.
	pub fn new(
		my_signer: S,
		verifying_keys: BTreeMap<ParticipantId, S::PublicKey>,
		new_participants: &[ParticipantId],
	) -> Result<Self, ResharingConfigError> {
		for p in new_participants {
			if !verifying_keys.contains_key(p) {
				return Err(ResharingConfigError::MissingVerifyingKey(*p));
			}
		}
		Ok(Self { my_signer, verifying_keys })
	}
}

/// Publicly verifiable certificate of a completed resharing session.
///
/// The no-ZK analog of a handoff certificate: it attests *process integrity*
/// and *public-key preservation* — every new committee member verified its
/// shares, observed the same transcript, and confirmed the reshared key still
/// reconstructs the original public key. It does **not** prove statements
/// about share distributions (that would require the deferred ZK machinery).
///
/// Verification requires only the new committee's verifying keys — no share
/// material. A verifier that additionally holds the broadcast transcript can
/// recompute `transcript_hash` and the `Σ_J t_J^new = T` public-key check
/// independently.
///
/// The certificate is self-describing: `new_committee` names the complete set
/// of required acceptors and is bound into the acceptance hash, so
/// [`verify`](Self::verify) derives the required signer set from the signed
/// certificate itself rather than trusting the caller to supply it.
#[derive(Debug, Clone, BorshSerialize)]
pub struct ResharingCertificate {
	/// Session identifier of the completed session.
	pub ssid: [u8; RESHARING_SSID_SIZE],
	/// The active set of old committee members that dealt in this session.
	pub active_set: Vec<ParticipantId>,
	/// The new committee members, strictly sorted ascending. Every member
	/// must contribute an acceptance signature. Bound into the acceptance
	/// hash, so it cannot be rewritten without invalidating the signatures.
	pub new_committee: Vec<ParticipantId>,
	/// Hash of the session transcript (active set, session seed, Round 3
	/// dealer commitments, Round 5 broadcasts).
	pub transcript_hash: [u8; COMMITMENT_HASH_SIZE],
	/// Acceptance signatures from every new committee member, keyed by
	/// participant ID.
	pub accepts: BTreeMap<ParticipantId, Vec<u8>>,
}

impl BorshDeserialize for ResharingCertificate {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let ssid = <[u8; RESHARING_SSID_SIZE]>::deserialize_reader(reader)?;

		// active_set is at most one entry per old committee member.
		let active_len = u32::deserialize_reader(reader)? as usize;
		if active_len > MAX_PARTIES as usize {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"ResharingCertificate.active_set exceeds MAX_PARTIES",
			));
		}
		let mut active_set = Vec::with_capacity(active_len);
		for _ in 0..active_len {
			active_set.push(ParticipantId::deserialize_reader(reader)?);
		}

		// new_committee is at most one entry per new committee member.
		let committee_len = u32::deserialize_reader(reader)? as usize;
		if committee_len > MAX_PARTIES as usize {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"ResharingCertificate.new_committee exceeds MAX_PARTIES",
			));
		}
		let mut new_committee = Vec::with_capacity(committee_len);
		for _ in 0..committee_len {
			new_committee.push(ParticipantId::deserialize_reader(reader)?);
		}

		let transcript_hash = <[u8; COMMITMENT_HASH_SIZE]>::deserialize_reader(reader)?;

		// accepts holds at most one signature per new committee member.
		let accepts_len = u32::deserialize_reader(reader)? as usize;
		if accepts_len > MAX_PARTIES as usize {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"ResharingCertificate.accepts exceeds MAX_PARTIES",
			));
		}
		let mut accepts = BTreeMap::new();
		for _ in 0..accepts_len {
			let party_id = ParticipantId::deserialize_reader(reader)?;
			let sig_len = u32::deserialize_reader(reader)? as usize;
			if sig_len > MAX_ACCEPT_SIGNATURE_LEN {
				return Err(borsh::io::Error::new(
					borsh::io::ErrorKind::InvalidData,
					"ResharingCertificate accept signature exceeds MAX_ACCEPT_SIGNATURE_LEN",
				));
			}
			// Read incrementally rather than pre-allocating the claimed length.
			let signature = crate::broadcast::read_length_prefixed(reader, sig_len)?;
			accepts.insert(party_id, signature);
		}

		Ok(Self { ssid, active_set, new_committee, transcript_hash, accepts })
	}
}

impl ResharingCertificate {
	/// Verify the certificate: every member of the certificate's own
	/// `new_committee` has a valid acceptance signature over this
	/// certificate's `ssid`, `transcript_hash`, `active_set`, and
	/// `new_committee`.
	///
	/// The required signer set comes from the certificate itself (where it is
	/// bound into the signed acceptance hash), not from a caller-supplied
	/// list, so a caller cannot accidentally weaken verification by passing a
	/// truncated or empty committee.
	///
	/// # Security
	///
	/// `verifying_keys` is the one remaining trusted input: it MUST be
	/// exactly the authentic key map of the expected new committee, obtained
	/// from a trusted source (e.g., the verifier's own configuration or key
	/// registry for the handoff). Verification fails unless the key map's key
	/// set equals `new_committee` exactly — a superset (e.g., an all-parties
	/// registry) is rejected, because it would let any subset of key holders
	/// mint a certificate naming only themselves. An empty or non-canonical
	/// (unsorted/duplicated) committee is rejected outright.
	pub fn verify<S: crate::keygen::dkg::TranscriptSigner>(
		&self,
		verifying_keys: &BTreeMap<ParticipantId, S::PublicKey>,
	) -> bool {
		// An empty committee would make the `.all(...)` below vacuously true;
		// no signature would be checked, so an unsigned certificate would
		// verify.
		if self.new_committee.is_empty() {
			return false;
		}
		// Canonical form: strictly ascending (also rejects duplicates), so a
		// padded list cannot satisfy the length check below.
		if !self.new_committee.windows(2).all(|w| w[0] < w[1]) {
			return false;
		}
		// The caller's trusted key map must match the committee exactly:
		// together with the membership check in the loop below, equal lengths
		// mean equal sets.
		if verifying_keys.len() != self.new_committee.len() {
			return false;
		}
		let accept_hash = compute_accept_hash(
			&self.ssid,
			&self.transcript_hash,
			&self.active_set,
			&self.new_committee,
		);
		self.new_committee
			.iter()
			.all(|p| match (verifying_keys.get(p), self.accepts.get(p)) {
				(Some(pk), Some(sig)) => S::verify_bytes(pk, &accept_hash, sig),
				_ => false,
			})
	}
}

/// Domain separator for the acceptance hash.
///
/// Bumped to v2 when `active_set` was folded into the hash, and to v3 when
/// `new_committee` was; a signature under an older domain can therefore never
/// be reinterpreted as a newer acceptance.
const ACCEPT_DOMAIN: &[u8] = b"resharing-accept-v3";

/// Compute the 32-byte hash that new committee members sign to accept the
/// session transcript:
/// `SHAKE256("resharing-accept-v3" || ssid || transcript_hash || len(active_set) || active_set ||
/// len(new_committee) || new_committee)`.
///
/// `active_set` and `new_committee` are bound directly (in addition to being
/// committed inside `transcript_hash` and the SSID respectively) so that a
/// party holding *only* the certificate — which cannot recompute
/// `transcript_hash` or open the SSID — still authenticates the certificate's
/// explicit fields. Without this, `active_set` or `new_committee` could be
/// rewritten while `ssid`/`transcript_hash`/`accepts` stayed valid, and the
/// tampered certificate would still verify.
///
/// Callers pass both lists in the same order stored in the certificate (the
/// protocol keeps them strictly sorted), so honest signers and verifiers hash
/// an identical byte string.
pub fn compute_accept_hash(
	ssid: &[u8; RESHARING_SSID_SIZE],
	transcript_hash: &[u8; COMMITMENT_HASH_SIZE],
	active_set: &[ParticipantId],
	new_committee: &[ParticipantId],
) -> [u8; 32] {
	use qp_rusty_crystals_dilithium::fips202;
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, ACCEPT_DOMAIN);
	fips202::shake256_absorb(&mut state, ssid);
	fips202::shake256_absorb(&mut state, transcript_hash);
	fips202::shake256_absorb(&mut state, &(active_set.len() as u32).to_le_bytes());
	for &p in active_set {
		fips202::shake256_absorb(&mut state, &p.to_le_bytes());
	}
	fips202::shake256_absorb(&mut state, &(new_committee.len() as u32).to_le_bytes());
	for &p in new_committee {
		fips202::shake256_absorb(&mut state, &p.to_le_bytes());
	}
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; 32];
	fips202::shake256_squeeze(&mut out, &mut state);
	out
}

// ============================================================================
// Round 2: Entropy Reveal (Public Session Seed)
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
	/// Session identifier binding this message to the resharing session.
	pub ssid: [u8; RESHARING_SSID_SIZE],
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
/// Each active old committee member broadcasts hash commitments to the
/// per-subset "sub-share" contributions they will privately deliver in Round 4.
/// A party only commits to subsets where they are the *designated dealer* (the
/// lowest-ID *active* old participant in the subset, `min(I ∩ Act)`). Other
/// active members of the same old subset independently recompute the same
/// contributions and verify the commitments before Round 4 private delivery
/// begins.
///
/// # Security
///
/// Unlike the previous design, **no share values, blindings, or aggregations
/// are revealed in clear**. The only public data is the hash commitment to
/// each `r_{I→J}`, which is hiding because each `r_{I→J}` has at least
/// `5^256 ≈ 2^594` bits of entropy (the η-bounded sample space) or is itself
/// a function of secret share material.
///
/// # Session Randomization
///
/// The session seed (computed from Round 1-2 entropy contributions) is mixed
/// into the PRF that derives sub-shares, so fresh entropy changes the
/// deterministic split for this session.
///
/// After Round 2, the session seed is public transcript material. This protocol
/// does not provide post-compromise forward secrecy against an attacker who
/// records the transcript and later obtains old subset shares.
#[derive(Debug, Clone, BorshSerialize)]
pub struct ResharingRound3Broadcast {
	/// Session identifier binding this message to the resharing session.
	pub ssid: [u8; RESHARING_SSID_SIZE],
	/// Party ID of the sender.
	pub party_id: ParticipantId,
	/// Commitments keyed by `(old_subset_mask, new_subset_mask)`.
	///
	/// The sender is the designated dealer for `old_subset_mask`. Each commitment is
	/// `SHAKE256("resharing-commit-v3" || old_subset || new_subset || pack(r))`.
	pub commitments: BTreeMap<SubsetPair, [u8; COMMITMENT_HASH_SIZE]>,
}

impl BorshDeserialize for ResharingRound3Broadcast {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let ssid = <[u8; RESHARING_SSID_SIZE]>::deserialize_reader(reader)?;
		let party_id = ParticipantId::deserialize_reader(reader)?;

		// Read map length and validate against MAX_SUBSET_PAIRS
		let len = u32::deserialize_reader(reader)? as usize;
		if len > MAX_SUBSET_PAIRS {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"ResharingRound3Broadcast.commitments exceeds MAX_SUBSET_PAIRS",
			));
		}

		let mut commitments = BTreeMap::new();
		for _ in 0..len {
			let key = SubsetPair::deserialize_reader(reader)?;
			let value = <[u8; COMMITMENT_HASH_SIZE]>::deserialize_reader(reader)?;
			commitments.insert(key, value);
		}

		Ok(Self { ssid, party_id, commitments })
	}
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
#[derive(Clone, BorshSerialize)]
pub struct ResharingRound4Message {
	/// Session identifier binding this message to the resharing session.
	pub ssid: [u8; RESHARING_SSID_SIZE],
	/// Party ID of the sender (dealer).
	pub from_party_id: ParticipantId,
	/// Party ID of the recipient.
	pub to_party_id: ParticipantId,
	/// Per-`(old_subset, new_subset)` contributions destined for the recipient.
	pub contributions: BTreeMap<SubsetPair, NewShareData>,
}

impl BorshDeserialize for ResharingRound4Message {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let ssid = <[u8; RESHARING_SSID_SIZE]>::deserialize_reader(reader)?;
		let from_party_id = ParticipantId::deserialize_reader(reader)?;
		let to_party_id = ParticipantId::deserialize_reader(reader)?;

		// Read map length and validate against MAX_SUBSET_PAIRS
		let len = u32::deserialize_reader(reader)? as usize;
		if len > MAX_SUBSET_PAIRS {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"ResharingRound4Message.contributions exceeds MAX_SUBSET_PAIRS",
			));
		}

		let mut contributions = BTreeMap::new();
		for _ in 0..len {
			let key = SubsetPair::deserialize_reader(reader)?;
			let value = NewShareData::deserialize_reader(reader)?;
			contributions.insert(key, value);
		}

		Ok(Self { ssid, from_party_id, to_party_id, contributions })
	}
}

impl fmt::Debug for ResharingRound4Message {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("ResharingRound4Message")
			.field(
				"ssid",
				&format_args!(
					"[{:02x}{:02x}{:02x}{:02x}...]",
					self.ssid[0], self.ssid[1], self.ssid[2], self.ssid[3]
				),
			)
			.field("from_party_id", &self.from_party_id)
			.field("to_party_id", &self.to_party_id)
			.field(
				"contributions",
				&format_args!("<{} entries, REDACTED>", self.contributions.len()),
			)
			.finish()
	}
}

/// New share data for a specific subset.
#[derive(Clone, BorshSerialize, BorshDeserialize, Zeroize, ZeroizeOnDrop)]
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

	/// Check if all coefficients are within the allowed bound.
	///
	/// Returns `true` if all coefficients satisfy `|coeff| <= bound`.
	/// This is used to reject malicious sub-shares with excessively large coefficients.
	///
	/// The magnitude is computed with [`i32::unsigned_abs`], which returns a
	/// `u32` and therefore handles `i32::MIN` correctly. Using `i32::abs` here
	/// would panic on `i32::MIN` in overflow-checking builds and, worse, wrap
	/// back to a negative value in release builds — letting a dealer's
	/// `i32::MIN` coefficient slip past this trust-boundary check.
	pub fn coefficients_within_bound(&self, bound: i32) -> bool {
		let bound = bound.max(0) as u32;
		for poly in &self.s1 {
			for &coeff in poly {
				if coeff.unsigned_abs() > bound {
					return false;
				}
			}
		}
		for poly in &self.s2 {
			for &coeff in poly {
				if coeff.unsigned_abs() > bound {
					return false;
				}
			}
		}
		true
	}

	/// Find the maximum absolute coefficient value.
	///
	/// Useful for debugging and diagnostics. Returns a `u32` because the
	/// magnitude of `i32::MIN` (2_147_483_648) does not fit in an `i32`; the
	/// magnitude is computed with the non-overflowing [`i32::unsigned_abs`].
	pub fn max_abs_coefficient(&self) -> u32 {
		let mut max_abs = 0u32;
		for poly in &self.s1 {
			for &coeff in poly {
				max_abs = max_abs.max(coeff.unsigned_abs());
			}
		}
		for poly in &self.s2 {
			for &coeff in poly {
				max_abs = max_abs.max(coeff.unsigned_abs());
			}
		}
		max_abs
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
/// 2. **Public-key invariant verification.** Each new committee member additionally publishes
///    `t_J^new = A·s1_J^new + s2_J^new mod Q` for every new subset `J` it belongs to. Anyone can
///    sum these `t_J` and check that the result reconstructs the original public key. This catches
///    a malicious dealer that lies about the residual `r_{I→J}` in a *size-1* old subset (`t = n`
///    configurations), where there is no other old-subset member to cross-verify. Publishing
///    `t_J^new` is safe: recovering `s_J^new` from `t_J^new` is the LWE problem.
#[derive(Debug, Clone, BorshSerialize)]
pub struct ResharingRound5Broadcast {
	/// Session identifier binding this message to the resharing session.
	pub ssid: [u8; RESHARING_SSID_SIZE],
	/// Party ID of the sender.
	pub party_id: ParticipantId,
	/// Commitments to each computed new subset share (only populated by new committee members).
	pub share_commitments: BTreeMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]>,
	/// Partial public-key contributions `t_J^new = A·s1_J^new + s2_J^new mod Q`,
	/// one entry per new subset `J` this party belongs to. Empty for old-only parties.
	/// Each entry has exactly `K` polynomials (enforced by the fixed-size array type).
	pub partial_pks: BTreeMap<SubsetMask, [[i32; N as usize]; K]>,
	/// Indicates whether this party processed Round 3/4 successfully.
	pub success: bool,
	/// Optional error message if `success` is false.
	pub error_message: Option<String>,
}

impl BorshDeserialize for ResharingRound5Broadcast {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let ssid = <[u8; RESHARING_SSID_SIZE]>::deserialize_reader(reader)?;
		let party_id = ParticipantId::deserialize_reader(reader)?;

		// Read share_commitments with bound check
		let len1 = u32::deserialize_reader(reader)? as usize;
		if len1 > MAX_SUBSETS {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"ResharingRound5Broadcast.share_commitments exceeds MAX_SUBSETS",
			));
		}
		let mut share_commitments = BTreeMap::new();
		for _ in 0..len1 {
			let key = SubsetMask::deserialize_reader(reader)?;
			let value = <[u8; COMMITMENT_HASH_SIZE]>::deserialize_reader(reader)?;
			share_commitments.insert(key, value);
		}

		// Read partial_pks with bound check
		let len2 = u32::deserialize_reader(reader)? as usize;
		if len2 > MAX_SUBSETS {
			return Err(borsh::io::Error::new(
				borsh::io::ErrorKind::InvalidData,
				"ResharingRound5Broadcast.partial_pks exceeds MAX_SUBSETS",
			));
		}
		let mut partial_pks = BTreeMap::new();
		for _ in 0..len2 {
			let key = SubsetMask::deserialize_reader(reader)?;
			let value = <[[i32; N as usize]; K]>::deserialize_reader(reader)?;
			partial_pks.insert(key, value);
		}

		let success = bool::deserialize_reader(reader)?;
		let error_message = Option::<String>::deserialize_reader(reader)?;

		Ok(Self { ssid, party_id, share_commitments, partial_pks, success, error_message })
	}
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
	/// Certificate of the completed session: acceptance signatures from every
	/// new committee member over the agreed transcript hash. Verifiable by any
	/// third party holding the new committee's verifying keys.
	pub certificate: ResharingCertificate,
}

// ============================================================================
// SSID Computation
// ============================================================================

/// Compute the Session Identifier (SSID) for a resharing protocol session.
///
/// The SSID uniquely identifies a resharing session and is included in all protocol
/// messages to prevent cross-session replay attacks (CVE-2022-47930 class).
///
/// # SSID Structure
///
/// ```text
/// SSID = SHAKE256(
///     "RESHARING_SSID_V2" ||
///     protocol_version (u32 LE) ||
///     suite_id (u32 LE) ||
///     epoch (u64 LE) ||
///     old_threshold (u32 LE) ||
///     old_n (u32 LE) ||
///     old_num_participants (u32 LE) ||
///     sorted_old_participant_ids (each u32 LE) ||
///     new_threshold (u32 LE) ||
///     new_n (u32 LE) ||
///     new_num_participants (u32 LE) ||
///     sorted_new_participant_ids (each u32 LE) ||
///     public_key_bytes ||
///     session_nonce[32]
/// )
/// ```
///
/// # Arguments
///
/// * `protocol_version` - Wire/logic version ([`RESHARING_PROTOCOL_VERSION`])
/// * `suite_id` - Cryptographic suite ([`RESHARING_SUITE_ML_DSA_87`])
/// * `epoch` - Monotonic handoff counter for this public key (0 for the first resharing after
///   keygen; increment for each subsequent handoff)
/// * `old_threshold` - Threshold of the old committee
/// * `old_n` - Total parties in the old committee
/// * `old_participants` - Participant IDs in the old committee
/// * `new_threshold` - Threshold of the new committee
/// * `new_n` - Total parties in the new committee
/// * `new_participants` - Participant IDs in the new committee
/// * `public_key` - The public key being reshared
/// * `session_nonce` - Unique nonce for this session (e.g., from transport layer)
#[allow(clippy::too_many_arguments)] // flat list of independent hash inputs
pub fn compute_resharing_ssid(
	protocol_version: u32,
	suite_id: u32,
	epoch: u64,
	old_threshold: u32,
	old_n: u32,
	old_participants: &[ParticipantId],
	new_threshold: u32,
	new_n: u32,
	new_participants: &[ParticipantId],
	public_key: &PublicKey,
	session_nonce: &[u8; 32],
) -> [u8; RESHARING_SSID_SIZE] {
	use qp_rusty_crystals_dilithium::fips202;

	let mut ssid = [0u8; RESHARING_SSID_SIZE];
	let mut state = fips202::KeccakState::default();

	// Domain separator
	fips202::shake256_absorb(&mut state, DOMAIN_RESHARING_SSID);

	// Protocol binding (version, suite, epoch)
	fips202::shake256_absorb(&mut state, &protocol_version.to_le_bytes());
	fips202::shake256_absorb(&mut state, &suite_id.to_le_bytes());
	fips202::shake256_absorb(&mut state, &epoch.to_le_bytes());

	// Old committee configuration
	fips202::shake256_absorb(&mut state, &old_threshold.to_le_bytes());
	fips202::shake256_absorb(&mut state, &old_n.to_le_bytes());

	// Old participants (sorted)
	let old_num = old_participants.len() as u32;
	fips202::shake256_absorb(&mut state, &old_num.to_le_bytes());
	let mut sorted_old = old_participants.to_vec();
	sorted_old.sort();
	for pid in &sorted_old {
		fips202::shake256_absorb(&mut state, &pid.to_le_bytes());
	}

	// New committee configuration
	fips202::shake256_absorb(&mut state, &new_threshold.to_le_bytes());
	fips202::shake256_absorb(&mut state, &new_n.to_le_bytes());

	// New participants (sorted)
	let new_num = new_participants.len() as u32;
	fips202::shake256_absorb(&mut state, &new_num.to_le_bytes());
	let mut sorted_new = new_participants.to_vec();
	sorted_new.sort();
	for pid in &sorted_new {
		fips202::shake256_absorb(&mut state, &pid.to_le_bytes());
	}

	// Public key
	fips202::shake256_absorb(&mut state, public_key.as_bytes());

	// Session nonce
	fips202::shake256_absorb(&mut state, session_nonce);

	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut ssid, &mut state);

	ssid
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::{format, string::ToString};

	/// Test SSID for use in unit tests.
	const TEST_SSID: [u8; RESHARING_SSID_SIZE] = [0xABu8; RESHARING_SSID_SIZE];

	fn make_test_public_key() -> PublicKey {
		// Dummy public key for testing. Must have a nonzero t1 region:
		// import paths reject the degenerate all-zero t1 key.
		let bytes = [0x42u8; 2592];
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
		// For NewOnly party - no share provided
		let result = ResharingConfig::new(
			None, // NewOnly party
			1,    // invalid: too low
			vec![0, 1, 2],
			2,
			vec![0, 1, 2, 3], // party 3 joining
			3,
			make_test_public_key(),
		);

		assert!(matches!(result, Err(ResharingConfigError::InvalidOldThreshold { .. })));
	}

	#[test]
	fn test_config_invalid_new_threshold() {
		// For NewOnly party - no share provided
		let result = ResharingConfig::new(
			None, // NewOnly party
			2,
			vec![0, 1, 2],
			5,                // invalid: exceeds party count
			vec![0, 1, 2, 3], // party 3 joining
			3,
			make_test_public_key(),
		);

		assert!(matches!(result, Err(ResharingConfigError::InvalidNewThreshold { .. })));
	}

	#[test]
	fn test_config_party_not_in_either() {
		// NewOnly party but not in new committee
		let result = ResharingConfig::new(
			None, // No share - should be NewOnly
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2], // party 99 NOT in new committee
			99,            // not in either committee
			make_test_public_key(),
		);

		assert!(matches!(result, Err(ResharingConfigError::PartyNotInEitherCommittee { .. })));
	}

	#[test]
	fn test_config_duplicate_participant() {
		let result = ResharingConfig::new(
			None, // NewOnly
			2,
			vec![0, 1, 1], // duplicate
			2,
			vec![0, 1, 2, 3], // party 3 joining
			3,
			make_test_public_key(),
		);

		assert!(matches!(result, Err(ResharingConfigError::DuplicateParticipant)));
	}

	#[test]
	fn test_message_round_numbers() {
		let r1 = ResharingMessage::Round1(ResharingRound1EntropyCommitment {
			ssid: TEST_SSID,
			party_id: 0,
			commitment: [0u8; COMMITMENT_HASH_SIZE],
		});
		assert_eq!(r1.round(), 1);
		assert_eq!(r1.party_id(), 0);

		let r2 = ResharingMessage::Round2(ResharingRound2EntropyReveal {
			ssid: TEST_SSID,
			party_id: 1,
			entropy: [0u8; ENTROPY_SIZE],
		});
		assert_eq!(r2.round(), 2);
		assert_eq!(r2.party_id(), 1);

		let r3 = ResharingMessage::Round3(ResharingRound3Broadcast {
			ssid: TEST_SSID,
			party_id: 2,
			commitments: BTreeMap::new(),
		});
		assert_eq!(r3.round(), 3);
		assert_eq!(r3.party_id(), 2);

		let r4 = ResharingMessage::Round4(ResharingRound4Message {
			ssid: TEST_SSID,
			from_party_id: 3,
			to_party_id: 4,
			contributions: BTreeMap::new(),
		});
		assert_eq!(r4.round(), 4);
		assert_eq!(r4.party_id(), 3);

		let r5 = ResharingMessage::Round5(ResharingRound5Broadcast {
			ssid: TEST_SSID,
			party_id: 5,
			share_commitments: BTreeMap::new(),
			partial_pks: BTreeMap::new(),
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

		// Test OldOnly role (party leaving) - party 2 has share, is in old but not new
		let resharing_config = ResharingConfig::new(
			Some(shares[2].clone()),
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1], // party 2 is leaving
			2,
			public_key.clone(),
		)
		.expect("valid config");
		assert_eq!(resharing_config.role, ResharingRole::OldOnly);
		assert!(resharing_config.role.is_old_committee());
		assert!(!resharing_config.role.is_new_committee());

		// Test NewOnly role (party joining)
		let resharing_config = ResharingConfig::new(
			None, // NewOnly - no share
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 3], // party 3 is joining
			3,
			public_key.clone(),
		)
		.expect("valid config");
		assert_eq!(resharing_config.role, ResharingRole::NewOnly);
		assert!(!resharing_config.role.is_old_committee());
		assert!(resharing_config.role.is_new_committee());

		// Test Both role (party staying)
		let resharing_config = ResharingConfig::new(
			Some(shares[0].clone()),
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 3],
			0, // ignored when share provided
			public_key.clone(),
		)
		.expect("valid config");
		assert_eq!(resharing_config.role, ResharingRole::Both);
		assert!(resharing_config.role.is_old_committee());
		assert!(resharing_config.role.is_new_committee());
	}

	/// Security review: the caller-supplied old committee must exactly match
	/// the share's embedded DKG participant list. The share's subset masks
	/// are defined relative to that embedded list, but the protocol maps
	/// mask bits to parties through `config.old_participants()` (dealer
	/// assignment, subset enumeration, share lookup). If the two lists
	/// differ, an old member deals Round 4 sub-share material derived from
	/// its real share under the wrong identity mapping before any later
	/// consistency check can fire.
	#[test]
	fn test_config_rejects_old_committee_not_matching_share_dkg_list() {
		use crate::{generate_with_dealer, ThresholdConfig};

		let config = ThresholdConfig::new(2, 3).expect("valid config");
		let seed = [42u8; 32];
		// Dealer keygen embeds dkg_participants = [0, 1, 2] in every share.
		let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

		// Same size, victim's ID present, threshold and TR match — but two
		// committee members are swapped for attacker-chosen IDs.
		let result = ResharingConfig::new(
			Some(shares[1].clone()),
			2,
			vec![1, 5, 6],
			2,
			vec![1, 5, 6],
			1,
			public_key.clone(),
		);
		assert!(
			matches!(result, Err(ResharingConfigError::OldCommitteeMismatch)),
			"old committee differing from the share's DKG list must be rejected, got {:?}",
			result.map(|_| ())
		);

		// A superset also shifts the mask-bit-to-party mapping.
		let result = ResharingConfig::new(
			Some(shares[1].clone()),
			2,
			vec![0, 1, 2, 3],
			2,
			vec![0, 1, 2, 3],
			1,
			public_key.clone(),
		);
		assert!(
			matches!(result, Err(ResharingConfigError::OldCommitteeMismatch)),
			"old committee superset of the share's DKG list must be rejected"
		);

		// The exact DKG committee still works.
		let result = ResharingConfig::new(
			Some(shares[1].clone()),
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			1,
			public_key.clone(),
		);
		assert!(result.is_ok(), "matching old committee must be accepted");
	}

	#[test]
	fn test_resharing_config_participant_helpers() {
		use crate::{generate_with_dealer, ThresholdConfig};

		let config = ThresholdConfig::new(2, 3).expect("valid config");
		let seed = [42u8; 32];
		let (public_key, shares) = generate_with_dealer(&seed, config).expect("keygen");

		// Test with old={0,1,2}, new={1,2,3}
		let resharing_config = ResharingConfig::new(
			Some(shares[1].clone()), // party 1's share
			2,
			vec![0, 1, 2],
			2,
			vec![1, 2, 3],
			1, // ignored when share provided
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

		// Test minimum valid threshold (t=2) - NewOnly party for simpler testing
		let result = ResharingConfig::new(None, 2, vec![0, 1], 2, vec![0, 1, 2], 2, pk.clone());
		assert!(result.is_ok());

		// Test threshold = n (all parties required) - NewOnly party
		let result =
			ResharingConfig::new(None, 3, vec![0, 1, 2], 3, vec![0, 1, 2, 3], 3, pk.clone());
		assert!(result.is_ok());

		// Test invalid: threshold > n
		let result =
			ResharingConfig::new(None, 4, vec![0, 1, 2], 2, vec![0, 1, 2, 3], 3, pk.clone());
		assert!(matches!(result, Err(ResharingConfigError::InvalidOldThreshold { .. })));

		// Test invalid: threshold < 2
		let result =
			ResharingConfig::new(None, 1, vec![0, 1, 2], 2, vec![0, 1, 2, 3], 3, pk.clone());
		assert!(matches!(result, Err(ResharingConfigError::InvalidOldThreshold { .. })));
	}

	#[test]
	fn test_resharing_message_party_id_extraction() {
		let r1 = ResharingMessage::Round1(ResharingRound1EntropyCommitment {
			ssid: TEST_SSID,
			party_id: 42,
			commitment: [0u8; COMMITMENT_HASH_SIZE],
		});
		assert_eq!(r1.party_id(), 42);

		let r2 = ResharingMessage::Round2(ResharingRound2EntropyReveal {
			ssid: TEST_SSID,
			party_id: 99,
			entropy: [0u8; ENTROPY_SIZE],
		});
		assert_eq!(r2.party_id(), 99);

		let r3 = ResharingMessage::Round3(ResharingRound3Broadcast {
			ssid: TEST_SSID,
			party_id: 77,
			commitments: BTreeMap::new(),
		});
		assert_eq!(r3.party_id(), 77);

		let r4 = ResharingMessage::Round4(ResharingRound4Message {
			ssid: TEST_SSID,
			from_party_id: 88,
			to_party_id: 100,
			contributions: BTreeMap::new(),
		});
		assert_eq!(r4.party_id(), 88);

		let r5 = ResharingMessage::Round5(ResharingRound5Broadcast {
			ssid: TEST_SSID,
			party_id: 55,
			share_commitments: BTreeMap::new(),
			partial_pks: BTreeMap::new(),
			success: true,
			error_message: None,
		});
		assert_eq!(r5.party_id(), 55);
	}

	#[test]
	fn test_resharing_round5_broadcast_error_handling() {
		let success = ResharingRound5Broadcast {
			ssid: TEST_SSID,
			party_id: 0,
			share_commitments: BTreeMap::new(),
			partial_pks: BTreeMap::new(),
			success: true,
			error_message: None,
		};
		assert!(success.success);
		assert!(success.error_message.is_none());

		let failure = ResharingRound5Broadcast {
			ssid: TEST_SSID,
			party_id: 1,
			share_commitments: BTreeMap::new(),
			partial_pks: BTreeMap::new(),
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
		// Use a NewOnly party for simpler testing
		let result = ResharingConfig::new(
			None, // NewOnly
			2,
			vec![0, 1, 2, 3, 4, 5, 6], // 7 parties
			2,
			vec![0, 1, 2, 7], // party 7 joining
			7,
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
			None, // NewOnly
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2, 3, 4, 5, 6], // 7 parties
			6,                         // party 6 is NewOnly
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
			ssid: TEST_SSID,
			party_id: 5,
			share_commitments: BTreeMap::new(),
			partial_pks,
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
			ssid: TEST_SSID,
			party_id: 0,
			share_commitments: BTreeMap::new(),
			partial_pks,
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

	#[test]
	fn test_resharing_ssid_binds_version_suite_and_epoch() {
		let pk = make_test_public_key();
		let nonce = [0x55u8; 32];
		let old = vec![0u32, 1u32, 2u32];
		let newp = vec![0u32, 1u32, 3u32];

		let base = |epoch: u64| {
			compute_resharing_ssid(
				RESHARING_PROTOCOL_VERSION,
				RESHARING_SUITE_ML_DSA_87,
				epoch,
				2,
				3,
				&old,
				2,
				3,
				&newp,
				&pk,
				&nonce,
			)
		};

		assert_ne!(base(0), base(1), "epoch must change the SSID");

		let other_suite = compute_resharing_ssid(
			RESHARING_PROTOCOL_VERSION,
			RESHARING_SUITE_ML_DSA_87 + 1,
			0,
			2,
			3,
			&old,
			2,
			3,
			&newp,
			&pk,
			&nonce,
		);
		assert_ne!(base(0), other_suite, "suite must change the SSID");
	}

	#[test]
	fn test_resharing_certificate_roundtrip_within_bounds() {
		let mut accepts = BTreeMap::new();
		accepts.insert(1u32, alloc::vec![9u8; 16]);
		accepts.insert(2u32, alloc::vec![3u8; 4627]);

		let cert = ResharingCertificate {
			ssid: TEST_SSID,
			active_set: alloc::vec![0, 1, 2],
			new_committee: alloc::vec![1, 2],
			transcript_hash: [7u8; COMMITMENT_HASH_SIZE],
			accepts,
		};

		let bytes = borsh::to_vec(&cert).unwrap();
		let back: ResharingCertificate = borsh::from_slice(&bytes).unwrap();
		assert_eq!(back.active_set, cert.active_set);
		assert_eq!(back.new_committee, cert.new_committee);
		assert_eq!(back.accepts, cert.accepts);
		assert_eq!(back.transcript_hash, cert.transcript_hash);
	}

	/// A fully-present certificate whose `active_set` count exceeds `MAX_PARTIES`
	/// must be rejected. Before the bounded deserializer this parsed successfully
	/// (borsh would happily build the oversized collection).
	#[test]
	fn test_resharing_certificate_rejects_oversized_active_set() {
		let huge = MAX_PARTIES + 100;

		let mut payload = Vec::new();
		payload.extend_from_slice(&[0u8; RESHARING_SSID_SIZE]); // ssid
		payload.extend_from_slice(&huge.to_le_bytes()); // active_set len
		for i in 0..huge {
			payload.extend_from_slice(&i.to_le_bytes()); // ParticipantId entries
		}
		payload.extend_from_slice(&0u32.to_le_bytes()); // new_committee len = 0
		payload.extend_from_slice(&[0u8; COMMITMENT_HASH_SIZE]); // transcript_hash
		payload.extend_from_slice(&0u32.to_le_bytes()); // accepts len = 0

		let result: Result<ResharingCertificate, _> = borsh::from_slice(&payload);
		assert!(result.is_err(), "active_set exceeding MAX_PARTIES must be rejected");
	}

	/// Same, for the `new_committee` list count.
	#[test]
	fn test_resharing_certificate_rejects_oversized_new_committee() {
		let huge = MAX_PARTIES + 100;

		let mut payload = Vec::new();
		payload.extend_from_slice(&[0u8; RESHARING_SSID_SIZE]); // ssid
		payload.extend_from_slice(&0u32.to_le_bytes()); // active_set len = 0
		payload.extend_from_slice(&huge.to_le_bytes()); // new_committee len
		for i in 0..huge {
			payload.extend_from_slice(&i.to_le_bytes()); // ParticipantId entries
		}
		payload.extend_from_slice(&[0u8; COMMITMENT_HASH_SIZE]); // transcript_hash
		payload.extend_from_slice(&0u32.to_le_bytes()); // accepts len = 0

		let result: Result<ResharingCertificate, _> = borsh::from_slice(&payload);
		assert!(result.is_err(), "new_committee exceeding MAX_PARTIES must be rejected");
	}

	/// Same, for the `accepts` map count.
	#[test]
	fn test_resharing_certificate_rejects_oversized_accepts() {
		let huge = MAX_PARTIES + 50;

		let mut payload = Vec::new();
		payload.extend_from_slice(&[0u8; RESHARING_SSID_SIZE]); // ssid
		payload.extend_from_slice(&0u32.to_le_bytes()); // active_set len = 0
		payload.extend_from_slice(&0u32.to_le_bytes()); // new_committee len = 0
		payload.extend_from_slice(&[0u8; COMMITMENT_HASH_SIZE]); // transcript_hash
		payload.extend_from_slice(&huge.to_le_bytes()); // accepts len
		for i in 0..huge {
			payload.extend_from_slice(&i.to_le_bytes()); // key: ParticipantId
			payload.extend_from_slice(&0u32.to_le_bytes()); // value: empty signature
		}

		let result: Result<ResharingCertificate, _> = borsh::from_slice(&payload);
		assert!(result.is_err(), "accepts exceeding MAX_PARTIES must be rejected");
	}

	/// Regression test (security review): a `ResharingAccept` whose signature
	/// length prefix claims the maximum but whose body is truncated must fail
	/// deserialization without allocating the full claimed length up front
	/// (the chunked `read_length_prefixed` path, mirroring the certificate
	/// accepts and Round 2/3 broadcasts).
	#[test]
	fn test_resharing_accept_rejects_truncated_signature() {
		// Honest round-trip still works.
		let accept =
			ResharingAccept { ssid: TEST_SSID, party_id: 3, signature: alloc::vec![0xAAu8; 4627] };
		let bytes = borsh::to_vec(&accept).unwrap();
		let back: ResharingAccept = borsh::from_slice(&bytes).unwrap();
		assert_eq!(back.party_id, accept.party_id);
		assert_eq!(back.signature, accept.signature);

		// Claim the maximum signature length but deliver only a few bytes.
		let mut payload = Vec::new();
		payload.extend_from_slice(&TEST_SSID); // ssid
		payload.extend_from_slice(&3u32.to_le_bytes()); // party_id
		payload.extend_from_slice(&(MAX_ACCEPT_SIGNATURE_LEN as u32).to_le_bytes()); // claimed len
		payload.extend_from_slice(&[0xBBu8; 8]); // truncated body

		let result: Result<ResharingAccept, _> = borsh::from_slice(&payload);
		assert!(result.is_err(), "truncated accept signature must be rejected");

		// A length above the maximum is rejected outright.
		let mut oversized = Vec::new();
		oversized.extend_from_slice(&TEST_SSID);
		oversized.extend_from_slice(&3u32.to_le_bytes());
		oversized.extend_from_slice(&((MAX_ACCEPT_SIGNATURE_LEN + 1) as u32).to_le_bytes());

		let result: Result<ResharingAccept, _> = borsh::from_slice(&oversized);
		assert!(result.is_err(), "oversized accept signature length must be rejected");
	}
}
