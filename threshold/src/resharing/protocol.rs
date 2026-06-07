//! Resharing Protocol State Machine.
//!
//! This module implements the resharing protocol using the poke/message pattern
//! compatible with NEAR MPC's `run_protocol` infrastructure.
//!
//! See `resharing/mod.rs` for a full description of the cryptographic protocol.
//! In short:
//!
//! - **Round 1 (Entropy commitment)**: Old committee members commit to fresh entropy.
//! - **Round 2 (Entropy reveal)**: Old committee members reveal entropy. All parties compute the
//!   public session seed from these reveals after checking the commitments.
//! - **Round 3 (Sub-share commitments)**: Each designated dealer broadcasts hash commitments to
//!   deterministic sub-shares `r_{I→J}` derived from `s_I^old` and the public session seed.
//! - **Round 4 (Private delivery)**: Dealers privately deliver `r_{I→J}` to new committee members.
//! - **Round 5 (Verification)**: New committee members verify received sub-shares, sum them into
//!   new shares `s_J^new`, and broadcast commitments so each new subset can cross-verify.
//!
//! The SSID binds every message to the resharing configuration and session nonce for replay
//! protection. The entropy commit-reveal provides public per-session randomization and pre-reveal
//! unpredictability, not post-compromise forward secrecy: a recorded transcript plus later access
//! to old subset shares is enough to recompute deterministic sub-share derivation.
//!
//! # State Machine
//!
//! ```text
//! Round1Generate -> Round1Waiting -> Round2Generate -> Round2Waiting
//!     -> Round3Generate -> Round3Waiting -> Combining -> Done
//! ```

use alloc::{
	collections::BTreeMap,
	format,
	string::{String, ToString},
	vec::Vec,
};
use core::fmt;

use qp_rusty_crystals_dilithium::{
	fips202,
	params::{ETA, K, L, N, Q},
};

use crate::{
	keys::{PrivateKeyShare, SecretShareData},
	participants::ParticipantId,
};

use super::types::{
	compute_resharing_ssid, NewShareData, ResharingConfig, ResharingMessage, ResharingOutput,
	ResharingRound1EntropyCommitment, ResharingRound2EntropyReveal, ResharingRound3Broadcast,
	ResharingRound4Message, ResharingRound5Broadcast, SubsetMask, SubsetPair, COMMITMENT_HASH_SIZE,
	ENTROPY_SIZE, RESHARING_SSID_SIZE,
};

/// Domain separator for the per-subset PRF seed (includes public session seed for randomization).
const SUBSET_SEED_DOMAIN: &[u8] = b"resharing-subset-prf-v3";

/// Domain separator for bounded conditional splitting noise.
const BOUNDED_SPLIT_DOMAIN: &[u8] = b"resharing-bounded-split-v1";

const COMMIT_DOMAIN: &[u8] = b"resharing-commit-v3";

const NEW_SHARE_COMMIT_DOMAIN: &[u8] = b"resharing-new-share-commit-v3";

/// Domain separator for entropy commitment.
const ENTROPY_COMMIT_DOMAIN: &[u8] = b"resharing-entropy-commit-v1";

/// Domain separator for session seed derivation.
const SESSION_SEED_DOMAIN: &[u8] = b"resharing-session-seed-v1";

/// Maximum resharing message size in bytes (2 MB).
/// This limits the size of serialized resharing protocol messages.
/// Larger configurations (e.g., 4-of-6) require more space due to
/// the number of subset pairs: for (t,n), there are C(n, n-t+1)² pairs.
pub const MAX_RESHARING_MESSAGE_SIZE: usize = 2 * 1024 * 1024;

// ============================================================================
// Action Enum
// ============================================================================

/// Actions returned by the protocol's `poke` method.
#[derive(Debug, Clone)]
pub enum Action<T> {
	/// Do nothing, waiting for more messages from other participants.
	Wait,
	/// Send a message to all other participants (broadcast).
	/// Requires authenticated delivery (integrity).
	SendMany(Vec<u8>),
	/// Send a private message to a specific participant.
	///
	/// # ⚠️ Security Requirement
	///
	/// This message contains **secret share material** and **MUST** be transmitted
	/// over an authenticated-encrypted channel. The protocol does not encrypt
	/// this data; the transport layer must provide:
	/// - **Confidentiality**: Only the recipient can read the message
	/// - **Authenticity**: Recipient can verify the sender's identity
	/// - **Integrity**: Message cannot be modified in transit
	///
	/// Sending this message over an unencrypted channel exposes secret shares
	/// to eavesdroppers and compromises the security of the threshold scheme.
	SendPrivate(ParticipantId, Vec<u8>),
	/// The protocol has completed, returning the output.
	Return(T),
}

// ============================================================================
// Protocol Error
// ============================================================================

/// Errors that can occur during the resharing protocol.
#[derive(Debug, Clone)]
pub enum ResharingProtocolError {
	/// The protocol is in an invalid state for the requested operation.
	InvalidState(String),
	/// A message was received from an unknown party.
	UnknownParty(ParticipantId),
	/// A duplicate message was received from a party.
	DuplicateMessage(ParticipantId),
	/// Commitment verification failed for a party.
	CommitmentMismatch(ParticipantId),
	/// Share verification failed.
	ShareVerificationFailed(String),
	/// A dealer failed to deliver valid Round 4 data (logged for debugging, not used for blame).
	DealerDeliveryFailed {
		/// The dealer that failed to deliver.
		dealer: ParticipantId,
		/// Description of what was missing or invalid.
		reason: String,
	},
	/// Serialization error.
	SerializationError(String),
	/// Protocol aborted due to a failure (no specific party blamed).
	ProtocolAborted(String),
	/// Not enough parties participated.
	InsufficientParties {
		/// The minimum number of parties required.
		required: usize,
		/// The number of parties that actually participated.
		received: usize,
	},
	/// Internal error.
	InternalError(String),
	/// A malformed message was received from a party.
	MalformedMessage {
		/// The party that sent the malformed message.
		from: ParticipantId,
		/// Reason for the failure.
		reason: String,
	},
}

impl fmt::Display for ResharingProtocolError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			ResharingProtocolError::InvalidState(s) => write!(f, "Invalid state: {}", s),
			ResharingProtocolError::UnknownParty(p) => write!(f, "Unknown party: {}", p),
			ResharingProtocolError::DuplicateMessage(p) => {
				write!(f, "Duplicate message from party: {}", p)
			},
			ResharingProtocolError::CommitmentMismatch(p) => {
				write!(f, "Commitment mismatch for party: {}", p)
			},
			ResharingProtocolError::ShareVerificationFailed(s) => {
				write!(f, "Share verification failed: {}", s)
			},
			ResharingProtocolError::DealerDeliveryFailed { dealer, reason } => {
				write!(f, "Dealer {} failed to deliver: {}", dealer, reason)
			},
			ResharingProtocolError::SerializationError(s) => {
				write!(f, "Serialization error: {}", s)
			},
			ResharingProtocolError::ProtocolAborted(reason) => {
				write!(f, "Protocol aborted: {}", reason)
			},
			ResharingProtocolError::InsufficientParties { required, received } => {
				write!(f, "Insufficient parties: required {}, received {}", required, received)
			},
			ResharingProtocolError::InternalError(s) => write!(f, "Internal error: {}", s),
			ResharingProtocolError::MalformedMessage { from, reason } => {
				write!(f, "Malformed message from party {}: {}", from, reason)
			},
		}
	}
}

// ============================================================================
// Protocol State
// ============================================================================

/// Current state of the resharing protocol.
///
/// # Protocol Rounds (5-round session-randomized protocol)
///
/// - **Round 1**: Entropy commitment (old committee broadcasts `H(entropy)`)
/// - **Round 2**: Entropy reveal (old committee reveals entropy, session seed computed)
/// - **Round 3**: Sub-share commitments (designated dealers broadcast `H(r_{I→J})`)
/// - **Round 4**: Private delivery (dealers send `r_{I→J}` to new committee)
/// - **Round 5**: Verification (share commitments, partial PKs, accusations)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResharingState {
	/// Generating Round 1 message (entropy commitment).
	Round1Generate,
	/// Waiting for Round 1 messages from old committee members.
	Round1Waiting,
	/// Generating Round 2 message (entropy reveal).
	Round2Generate,
	/// Waiting for Round 2 messages from old committee members.
	Round2Waiting,
	/// Generating Round 3 message (commitments to per-subset sub-shares).
	Round3Generate,
	/// Waiting for Round 3 messages from old committee members.
	Round3Waiting,
	/// Generating Round 4 messages (private sub-share reveals).
	Round4Generate,
	/// Waiting for Round 4 messages (receiving sub-shares).
	Round4Waiting,
	/// Generating Round 5 message (verification commitments + accusations).
	Round5Generate,
	/// Waiting for Round 5 messages.
	Round5Waiting,
	/// Combining shares and finalizing.
	Combining,
	/// Protocol completed successfully.
	Done,
	/// Protocol failed.
	Failed(String),
}

// ============================================================================
// Resharing Protocol
// ============================================================================

/// The main resharing protocol state machine.
pub struct ResharingProtocol {
	config: ResharingConfig,
	state: ResharingState,

	/// Session identifier (SSID) for this resharing session.
	/// Computed from old/new committee configs + public key + session nonce.
	/// Included in all messages to prevent cross-session replay attacks.
	ssid: [u8; RESHARING_SSID_SIZE],

	/// Seed for entropy generation (provided by caller).
	seed: [u8; 32],

	/// This party's existing private key share (if in old committee).
	/// None if this party is NewOnly (joining the new committee).
	existing_share: Option<PrivateKeyShare>,

	/// Old subset masks (from the existing share's stored shares), in canonical
	/// (BTreeMap) order. Indexed by `old_subset_index`.
	old_subset_order: Vec<SubsetMask>,
	/// New subset masks for the new committee, in canonical order. Indexed by
	/// `new_subset_index`. Used to assign per-old-subset "residual" new subsets.
	new_subset_order: Vec<SubsetMask>,

	// ========================================================================
	// Round 1-2: Entropy commit-reveal (public session randomization)
	// ========================================================================
	/// This party's generated entropy (old committee members only).
	my_entropy: Option<[u8; ENTROPY_SIZE]>,
	/// Round 1 entropy commitments received from old committee members.
	round1_entropy_commits: BTreeMap<ParticipantId, [u8; COMMITMENT_HASH_SIZE]>,
	/// Round 2 entropy reveals received from old committee members.
	round2_entropy_reveals: BTreeMap<ParticipantId, [u8; ENTROPY_SIZE]>,
	/// Session seed computed from all entropy contributions (computed after Round 2).
	session_seed: Option<[u8; 32]>,

	// ========================================================================
	// Round 3-4: Sub-share commitment and delivery
	// ========================================================================
	/// Pre-computed sub-shares we are responsible for dealing.
	/// Keyed by `(old_subset, new_subset)`.
	my_subshares: BTreeMap<SubsetPair, NewShareData>,
	/// Our Round 3 broadcast (commitments for subsets we deal).
	my_round3: Option<ResharingRound3Broadcast>,
	/// Round 3 broadcasts received from other old committee members.
	round3_broadcasts: BTreeMap<ParticipantId, ResharingRound3Broadcast>,

	/// Round 4 messages we have queued to send (each addressed to a specific recipient).
	pending_round4: Vec<ResharingRound4Message>,
	/// Index of the next pending Round 4 message to emit.
	round4_sent_count: usize,
	/// Round 4 messages we received, keyed by sender.
	/// Each value is the merged set of `(I, J) -> r` from that sender.
	round4_messages: BTreeMap<ParticipantId, ResharingRound4Message>,

	// ========================================================================
	// Round 5: Verification
	// ========================================================================
	/// Round 5 broadcasts.
	round5_broadcasts: BTreeMap<ParticipantId, ResharingRound5Broadcast>,

	/// Computed new shares: `new_subset -> s_J^new`. Populated in Round 5.
	new_shares: BTreeMap<SubsetMask, NewShareData>,
	/// Final output (cached so `take_output` can return it after Combining).
	completed_output: Option<ResharingOutput>,
}

impl ResharingProtocol {
	/// Create a new resharing protocol instance.
	///
	/// * `existing_share` - Required for old committee members (`OldOnly`/`Both`), `None` for
	///   `NewOnly`.
	/// * `seed` - 32 bytes of cryptographic randomness for this party's entropy contribution.
	/// * `session_nonce` - Unique nonce for SSID computation (prevents cross-session replay).
	pub fn new(
		config: ResharingConfig,
		existing_share: Option<PrivateKeyShare>,
		seed: [u8; 32],
		session_nonce: &[u8; 32],
	) -> Self {
		let old_participants: Vec<_> = config.old_participants().iter().collect();
		let new_participants: Vec<_> = config.new_participants().iter().collect();
		let ssid = compute_resharing_ssid(
			config.old_threshold(),
			config.old_participants().len() as u32,
			&old_participants,
			config.new_threshold(),
			config.new_participants().len() as u32,
			&new_participants,
			config.public_key(),
			session_nonce,
		);
		let old_subset_order = compute_old_subset_order(&config);
		let new_subset_order = compute_new_subset_order(&config);
		Self {
			config,
			state: ResharingState::Round1Generate,
			ssid,
			seed,
			existing_share,
			old_subset_order,
			new_subset_order,
			my_entropy: None,
			round1_entropy_commits: BTreeMap::new(),
			round2_entropy_reveals: BTreeMap::new(),
			session_seed: None,
			my_subshares: BTreeMap::new(),
			my_round3: None,
			round3_broadcasts: BTreeMap::new(),
			pending_round4: Vec::new(),
			round4_sent_count: 0,
			round4_messages: BTreeMap::new(),
			round5_broadcasts: BTreeMap::new(),
			new_shares: BTreeMap::new(),
			completed_output: None,
		}
	}

	/// Get the session identifier (SSID) for this resharing session.
	///
	/// The SSID uniquely identifies this session and is included in all messages
	/// to prevent cross-session replay attacks.
	pub fn ssid(&self) -> &[u8; RESHARING_SSID_SIZE] {
		&self.ssid
	}

	/// Get the current protocol state.
	pub fn state(&self) -> &ResharingState {
		&self.state
	}

	/// Get this party's ID.
	pub fn my_party_id(&self) -> ParticipantId {
		self.config.my_party_id()
	}

	/// Get the configuration.
	pub fn config(&self) -> &ResharingConfig {
		&self.config
	}

	/// Take the completed output from the protocol.
	pub fn take_output(&mut self) -> Option<ResharingOutput> {
		if matches!(self.state, ResharingState::Done) {
			self.completed_output.take()
		} else {
			None
		}
	}

	/// Check if the protocol has completed successfully.
	pub fn is_done(&self) -> bool {
		matches!(self.state, ResharingState::Done)
	}

	/// Check if the protocol has failed.
	pub fn is_failed(&self) -> bool {
		matches!(self.state, ResharingState::Failed(_))
	}

	fn serialize_message(msg: &ResharingMessage) -> Result<Vec<u8>, ResharingProtocolError> {
		borsh::to_vec(msg).map_err(|e| {
			ResharingProtocolError::SerializationError(format!("Failed to serialize: {}", e))
		})
	}

	fn deserialize_message(data: &[u8]) -> Result<ResharingMessage, ResharingProtocolError> {
		if data.len() > MAX_RESHARING_MESSAGE_SIZE {
			return Err(ResharingProtocolError::SerializationError(format!(
				"Message size {} exceeds maximum {}",
				data.len(),
				MAX_RESHARING_MESSAGE_SIZE
			)));
		}
		borsh::from_slice(data).map_err(|e| {
			ResharingProtocolError::SerializationError(format!("Failed to deserialize: {}", e))
		})
	}

	/// Advance the protocol state machine.
	pub fn poke(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		match &self.state {
			ResharingState::Round1Generate => self.handle_round1_generate(),
			ResharingState::Round1Waiting => self.handle_round1_waiting(),
			ResharingState::Round2Generate => self.handle_round2_generate(),
			ResharingState::Round2Waiting => self.handle_round2_waiting(),
			ResharingState::Round3Generate => self.handle_round3_generate(),
			ResharingState::Round3Waiting => self.handle_round3_waiting(),
			ResharingState::Round4Generate => self.handle_round4_generate(),
			ResharingState::Round4Waiting => self.handle_round4_waiting(),
			ResharingState::Round5Generate => self.handle_round5_generate(),
			ResharingState::Round5Waiting => self.handle_round5_waiting(),
			ResharingState::Combining => self.handle_combining(),
			ResharingState::Done =>
				Err(ResharingProtocolError::InvalidState("Protocol already completed".to_string())),
			ResharingState::Failed(reason) =>
				Err(ResharingProtocolError::InvalidState(format!("Protocol failed: {}", reason))),
		}
	}

	/// Handle an incoming message from another party.
	pub fn message(
		&mut self,
		from: ParticipantId,
		data: Vec<u8>,
	) -> Result<(), ResharingProtocolError> {
		if matches!(self.state, ResharingState::Done | ResharingState::Failed(_)) {
			return Ok(());
		}

		// Ignore messages from self
		if from == self.config.my_party_id() {
			return Ok(());
		}

		// Ignore messages from non-participants (neither old nor new committee)
		let all_participants = self.config.all_participants();
		if !all_participants.contains(&from) {
			log::warn!(
				"Resharing: Ignoring message from non-participant {} (not in {:?})",
				from,
				all_participants
			);
			return Ok(());
		}

		let msg = match Self::deserialize_message(&data) {
			Ok(m) => m,
			Err(e) =>
				return Err(ResharingProtocolError::MalformedMessage { from, reason: e.to_string() }),
		};

		// Verify SSID matches for all message types to prevent cross-session replay
		if msg.ssid() != &self.ssid {
			log::warn!(
				"Resharing: Rejecting message from {} - SSID mismatch (cross-session replay attempt?)",
				from
			);
			return Ok(()); // SSID mismatch, silently ignore (not an error, likely cross-session)
		}

		if msg.party_id() != from {
			return Ok(());
		}

		match msg {
			ResharingMessage::Round1(m) => self.handle_round1_message(from, m),
			ResharingMessage::Round2(m) => self.handle_round2_message(from, m),
			ResharingMessage::Round3(broadcast) => self.handle_round3_message(from, broadcast),
			ResharingMessage::Round4(m) => self.handle_round4_message(from, m),
			ResharingMessage::Round5(broadcast) => self.handle_round5_message(from, broadcast),
		}

		Ok(())
	}

	// ========================================================================
	// Round 1: Entropy Commitment (Session Randomization)
	// ========================================================================

	fn handle_round1_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Only old committee members participate in Round 1 (entropy commitment).
		// New-only parties skip directly to Round 2 waiting.
		if !self.config.role().is_old_committee() {
			self.state = ResharingState::Round2Waiting;
			return Ok(Action::Wait);
		}

		// Generate entropy from the seed provided at construction
		let entropy = self.generate_entropy();
		self.my_entropy = Some(entropy);

		// Compute commitment: H("resharing-entropy-commit-v1" || entropy)
		let commitment = commit_entropy(&entropy);
		self.round1_entropy_commits.insert(self.config.my_party_id(), commitment);

		let broadcast = ResharingRound1EntropyCommitment {
			ssid: self.ssid,
			party_id: self.config.my_party_id(),
			commitment,
		};
		let data = Self::serialize_message(&ResharingMessage::Round1(broadcast))?;
		self.state = ResharingState::Round1Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round1_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.have_all_round1_entropy_commits() {
			self.state = ResharingState::Round2Generate;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round1_message(
		&mut self,
		from: ParticipantId,
		msg: ResharingRound1EntropyCommitment,
	) {
		// Accept Round 1 messages during Round 1 or Round 2 (for late arrivals)
		if !matches!(
			self.state,
			ResharingState::Round1Generate |
				ResharingState::Round1Waiting |
				ResharingState::Round2Generate |
				ResharingState::Round2Waiting
		) {
			return;
		}
		// Only old committee members send entropy commitments
		if !self.config.old_participants().contains(from) {
			return;
		}
		// Ignore duplicates
		if self.round1_entropy_commits.contains_key(&from) {
			return;
		}
		self.round1_entropy_commits.insert(from, msg.commitment);
	}

	fn have_all_round1_entropy_commits(&self) -> bool {
		// We need entropy commitments from all old committee members
		self.round1_entropy_commits.len() >= self.config.old_participants().len()
	}

	/// Generate this party's entropy contribution from the constructor seed.
	fn generate_entropy(&self) -> [u8; ENTROPY_SIZE] {
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, b"resharing-entropy-derive-v1");
		fips202::shake256_absorb(&mut state, &self.seed);
		fips202::shake256_absorb(&mut state, &self.config.my_party_id().to_le_bytes());
		fips202::shake256_finalize(&mut state);
		let mut entropy = [0u8; ENTROPY_SIZE];
		fips202::shake256_squeeze(&mut entropy, &mut state);
		entropy
	}

	// ========================================================================
	// Round 2: Entropy Reveal (Public Session Seed)
	// ========================================================================

	fn handle_round2_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Only old committee members participate in Round 2 (entropy reveal).
		// New-only parties stay in Round 2 waiting.
		if !self.config.role().is_old_committee() {
			self.state = ResharingState::Round2Waiting;
			return Ok(Action::Wait);
		}

		let entropy = self.my_entropy.ok_or_else(|| {
			ResharingProtocolError::InternalError("Missing entropy for Round 2".to_string())
		})?;

		// Store our own reveal
		self.round2_entropy_reveals.insert(self.config.my_party_id(), entropy);

		let broadcast = ResharingRound2EntropyReveal {
			ssid: self.ssid,
			party_id: self.config.my_party_id(),
			entropy,
		};
		let data = Self::serialize_message(&ResharingMessage::Round2(broadcast))?;
		self.state = ResharingState::Round2Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round2_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.have_all_round2_entropy_reveals() {
			// Verify all reveals match their commitments and compute session seed
			self.verify_entropy_and_compute_session_seed()?;
			self.state = ResharingState::Round3Generate;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round2_message(&mut self, from: ParticipantId, msg: ResharingRound2EntropyReveal) {
		// Accept Round 2 messages during Round 1-3 (for late arrivals)
		if !matches!(
			self.state,
			ResharingState::Round1Waiting |
				ResharingState::Round2Generate |
				ResharingState::Round2Waiting |
				ResharingState::Round3Generate |
				ResharingState::Round3Waiting
		) {
			return;
		}
		// Only old committee members send entropy reveals
		if !self.config.old_participants().contains(from) {
			return;
		}
		// Ignore duplicates
		if self.round2_entropy_reveals.contains_key(&from) {
			return;
		}
		self.round2_entropy_reveals.insert(from, msg.entropy);
	}

	fn have_all_round2_entropy_reveals(&self) -> bool {
		// We need entropy reveals from all old committee members
		self.round2_entropy_reveals.len() >= self.config.old_participants().len()
	}

	/// Verify all entropy reveals match their commitments and compute the session seed.
	fn verify_entropy_and_compute_session_seed(&mut self) -> Result<(), ResharingProtocolError> {
		// Verify each reveal matches its commitment
		for (&party_id, &entropy) in &self.round2_entropy_reveals {
			let expected_commit = commit_entropy(&entropy);
			let actual_commit = self.round1_entropy_commits.get(&party_id).ok_or_else(|| {
				ResharingProtocolError::InternalError(format!(
					"Missing entropy commitment from party {} during verification",
					party_id
				))
			})?;
			if expected_commit != *actual_commit {
				return Err(ResharingProtocolError::CommitmentMismatch(party_id));
			}
		}

		// Compute session seed: SHAKE256("resharing-session-seed-v1" || ssid || party_id_1 ||
		// entropy_1 || ...). The SSID is included so that even if parties reuse entropy seeds
		// across different resharing sessions, the session_seed (and thus the sub-share
		// derivation) will differ. Process parties in sorted order for determinism.
		let mut sorted_parties: Vec<_> = self.round2_entropy_reveals.iter().collect();
		sorted_parties.sort_by_key(|(party_id, _)| *party_id);

		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, SESSION_SEED_DOMAIN);
		fips202::shake256_absorb(&mut state, &self.ssid);
		for (&party_id, entropy) in &sorted_parties {
			fips202::shake256_absorb(&mut state, &party_id.to_le_bytes());
			fips202::shake256_absorb(&mut state, *entropy);
		}
		fips202::shake256_finalize(&mut state);
		let mut session_seed = [0u8; 32];
		fips202::shake256_squeeze(&mut session_seed, &mut state);
		self.session_seed = Some(session_seed);

		Ok(())
	}

	// ========================================================================
	// Round 3: Sub-Share Commitments
	// ========================================================================

	fn handle_round3_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Only old committee members participate in Round 3.
		if !self.config.role().is_old_committee() {
			self.state = ResharingState::Round4Waiting;
			return Ok(Action::Wait);
		}

		// Compute sub-shares using the public session seed for per-session randomization.
		self.compute_my_subshares()?;
		let commitments = self.commit_to_my_subshares();

		let broadcast = ResharingRound3Broadcast {
			ssid: self.ssid,
			party_id: self.config.my_party_id(),
			commitments,
		};
		self.my_round3 = Some(broadcast.clone());
		self.round3_broadcasts.insert(self.config.my_party_id(), broadcast.clone());

		// Pre-build the per-recipient Round 4 messages so we can stream them in
		// later pokes without re-deriving anything.
		self.build_pending_round4_messages();

		let data = Self::serialize_message(&ResharingMessage::Round3(broadcast))?;
		self.state = ResharingState::Round3Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round3_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.have_enough_round3() {
			self.state = ResharingState::Round4Generate;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round3_message(&mut self, from: ParticipantId, broadcast: ResharingRound3Broadcast) {
		// Accept Round 3 messages during Round 2-4 states (for late arrivals and NewOnly parties)
		if !matches!(
			self.state,
			ResharingState::Round2Waiting |
				ResharingState::Round3Generate |
				ResharingState::Round3Waiting |
				ResharingState::Round4Generate |
				ResharingState::Round4Waiting
		) {
			return;
		}
		if !self.config.old_participants().contains(from) {
			return;
		}
		if self.round3_broadcasts.contains_key(&from) {
			return;
		}
		self.round3_broadcasts.insert(from, broadcast);
	}

	fn have_enough_round3(&self) -> bool {
		// We need a Round 3 broadcast from every party that is a designated dealer for at
		// least one old subset. Conservative requirement: all old participants.
		self.round3_broadcasts.len() >= self.config.old_participants().len()
	}

	// ========================================================================
	// Round 4: Private Sub-Share Reveal
	// ========================================================================

	fn handle_round4_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Old-only parties without dealer responsibilities and new-only parties simply
		// wait for inbound traffic.
		if !self.config.role().is_old_committee() || self.pending_round4.is_empty() {
			self.state = ResharingState::Round4Waiting;
			return self.poke();
		}

		self.state = ResharingState::Round4Waiting;
		self.send_next_round4_message()
	}

	fn handle_round4_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Old-committee dealers continue to drain pending Round 4 messages.
		if self.config.role().is_old_committee() &&
			self.round4_sent_count < self.pending_round4.len()
		{
			return self.send_next_round4_message();
		}

		// New committee members proceed to Round 5 once they have received from every
		// expected dealer.
		if self.config.role().is_new_committee() && self.have_all_expected_round4() {
			self.state = ResharingState::Round5Generate;
			return self.poke();
		}

		// Old-only parties advance to Round 5 generation (they will broadcast accusations
		// only).
		if !self.config.role().is_new_committee() &&
			self.round4_sent_count >= self.pending_round4.len()
		{
			self.state = ResharingState::Round5Generate;
			return self.poke();
		}

		Ok(Action::Wait)
	}

	fn send_next_round4_message(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.round4_sent_count >= self.pending_round4.len() {
			return Ok(Action::Wait);
		}
		let msg = &self.pending_round4[self.round4_sent_count];
		let to_party = msg.to_party_id;
		let data = Self::serialize_message(&ResharingMessage::Round4(msg.clone()))?;
		self.round4_sent_count += 1;
		Ok(Action::SendPrivate(to_party, data))
	}

	fn handle_round4_message(&mut self, from: ParticipantId, msg: ResharingRound4Message) {
		if matches!(self.state, ResharingState::Done | ResharingState::Failed(_)) {
			return;
		}
		if !self.config.role().is_new_committee() {
			return;
		}
		if !self.config.old_participants().contains(from) {
			return;
		}
		if msg.to_party_id != self.config.my_party_id() {
			return;
		}
		// Reject duplicates from the same dealer.
		if self.round4_messages.contains_key(&from) {
			return;
		}
		self.round4_messages.insert(from, msg);
	}

	fn have_all_expected_round4(&self) -> bool {
		// Expected senders = the set of designated dealers for each old subset.
		let expected: BTreeMap<ParticipantId, ()> =
			self.designated_dealer_set().into_iter().map(|p| (p, ())).collect();
		expected.keys().all(|d| self.round4_messages.contains_key(d))
	}

	fn designated_dealer_set(&self) -> Vec<ParticipantId> {
		let mut set: alloc::collections::BTreeSet<ParticipantId> =
			alloc::collections::BTreeSet::new();
		for &i_mask in &self.old_subset_order {
			if let Some(d) = self.designated_dealer_for(i_mask) {
				set.insert(d);
			}
		}
		set.into_iter().collect()
	}

	// ========================================================================
	// Round 5: Verification
	// ========================================================================

	fn handle_round5_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		let mut share_commitments: BTreeMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]> =
			BTreeMap::new();
		let mut success = true;
		let mut error_message: Option<String> = None;

		// New committee members verify privately-received sub-shares against the
		// broadcast commitments, sum them into new subset shares, and commit.
		if self.config.role().is_new_committee() {
			match self.verify_and_aggregate_new_shares() {
				Ok(commits) => share_commitments = commits,
				Err(e) => {
					success = false;
					error_message = Some(e.to_string());
				},
			}
		}

		// Compute partial public-key contributions `t_J = A·s1_J + s2_J mod Q`
		// for every new subset we hold. These are summed and checked against the
		// original public key in Combining; this catches a malicious dealer that
		// lies about a residual `r_{I→J}` in a size-1 old subset, where there is
		// no peer in the old subset to cross-verify the commitment.
		let partial_pks = if self.config.role().is_new_committee() && success {
			self.compute_my_partial_pks()
		} else {
			BTreeMap::new()
		};

		let broadcast = ResharingRound5Broadcast {
			ssid: self.ssid,
			party_id: self.config.my_party_id(),
			share_commitments,
			partial_pks,
			success,
			error_message,
		};
		self.round5_broadcasts.insert(self.config.my_party_id(), broadcast.clone());
		let data = Self::serialize_message(&ResharingMessage::Round5(broadcast))?;
		self.state = ResharingState::Round5Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round5_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.have_all_round5() {
			self.state = ResharingState::Combining;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round5_message(&mut self, from: ParticipantId, broadcast: ResharingRound5Broadcast) {
		if matches!(self.state, ResharingState::Done | ResharingState::Failed(_)) {
			return;
		}
		if !self.config.all_participants().contains(&from) {
			return;
		}
		if self.round5_broadcasts.contains_key(&from) {
			return;
		}
		// Note: partial_pks shape is validated during deserialization (BorshDeserialize impl)
		self.round5_broadcasts.insert(from, broadcast);
	}

	fn have_all_round5(&self) -> bool {
		// Round 5 has contributions from BOTH old and new committee members
		// (old members file accusations; new members commit to new shares),
		// so we need broadcasts from every party that is in either committee.
		let union = self.config.all_participants();
		union.iter().all(|p| self.round5_broadcasts.contains_key(p))
	}

	// ========================================================================
	// Combining
	// ========================================================================

	fn handle_combining(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Check if any party reported failure - abort without attribution
		let failed_parties: Vec<ParticipantId> = self
			.round5_broadcasts
			.iter()
			.filter(|(_, b)| !b.success)
			.map(|(id, _)| *id)
			.collect();

		if !failed_parties.is_empty() {
			let reason =
				format!("Protocol aborted: {} parties reported failure", failed_parties.len());
			self.state = ResharingState::Failed(reason.clone());
			return Err(ResharingProtocolError::ProtocolAborted(reason));
		}

		// New committee members must agree on every shared new subset.
		self.verify_new_share_consistency()?;

		// Verify the resharing preserved the public key invariant. This catches
		// a malicious dealer that lies about a residual `r_{I→J}`.
		self.verify_public_key_preservation()?;

		let output = self.build_output()?;
		self.completed_output = Some(output.clone());
		self.state = ResharingState::Done;
		Ok(Action::Return(output))
	}

	// ========================================================================
	// Cryptographic Helpers
	// ========================================================================

	/// Pre-compute every sub-share `r_{I→J}` we are responsible for dealing.
	/// Uses the public session seed for per-session randomization.
	fn compute_my_subshares(&mut self) -> Result<(), ResharingProtocolError> {
		let existing = self.existing_share.as_ref().ok_or_else(|| {
			ResharingProtocolError::InternalError("Missing existing share".to_string())
		})?;
		let shares = existing.shares();
		let new_subsets = self.new_subset_order.clone();
		let n_new = new_subsets.len();
		if n_new == 0 {
			return Err(ResharingProtocolError::InternalError(
				"No new subsets to deal to".to_string(),
			));
		}

		// Get session seed for deterministic per-session PRF derivation.
		let session_seed = self.session_seed.ok_or_else(|| {
			ResharingProtocolError::InternalError("Missing session seed".to_string())
		})?;

		for &i_mask in self.old_subset_order.clone().iter() {
			// Only compute for subsets where we are the designated dealer.
			if self.designated_dealer_for(i_mask) != Some(self.config.my_party_id()) {
				continue;
			}
			let s_i = shares.get(&i_mask).ok_or_else(|| {
				ResharingProtocolError::InternalError(format!(
					"Designated dealer for subset {:b} but no share data",
					i_mask
				))
			})?;
			let subshares =
				derive_subshares_with_session_seed(i_mask, s_i, &new_subsets, &session_seed);
			for (j_idx, j_mask) in new_subsets.iter().enumerate() {
				self.my_subshares.insert((i_mask, *j_mask), subshares[j_idx].clone());
			}
		}
		Ok(())
	}

	/// Compute hash commitments to every sub-share we will deal.
	fn commit_to_my_subshares(&self) -> BTreeMap<SubsetPair, [u8; COMMITMENT_HASH_SIZE]> {
		let mut out = BTreeMap::new();
		for (pair, share) in &self.my_subshares {
			out.insert(*pair, commit_subshare(pair.0, pair.1, share));
		}
		out
	}

	/// Build the per-recipient Round 4 messages we will emit one-by-one in `poke`.
	///
	/// Self-deals (when this party is also a member of `J`) are inserted directly
	/// into `round4_messages`; only outbound messages are queued in `pending_round4`.
	/// This mirrors the DKG pattern (`process_round1` skips self) and removes the
	/// implicit "network must loopback SendPrivate(self, _)" requirement.
	fn build_pending_round4_messages(&mut self) {
		let mut by_recipient: BTreeMap<ParticipantId, BTreeMap<SubsetPair, NewShareData>> =
			BTreeMap::new();
		for (pair, share) in &self.my_subshares {
			let j_mask = pair.1;
			for (idx, party) in self.config.new_participants().iter().enumerate() {
				if (j_mask & (1 << idx)) != 0 {
					by_recipient.entry(party).or_default().insert(*pair, share.clone());
				}
			}
		}
		let me = self.config.my_party_id();
		for (recipient, contributions) in by_recipient {
			let msg = ResharingRound4Message {
				ssid: self.ssid,
				from_party_id: me,
				to_party_id: recipient,
				contributions,
			};
			if recipient == me {
				self.round4_messages.insert(me, msg);
			} else {
				self.pending_round4.push(msg);
			}
		}
	}

	/// Find the designated dealer for an old subset: the lowest-ID old
	/// participant that is a member of the subset.
	///
	/// Bit positions in `i_mask` correspond to indices in the (sorted)
	/// `old_participants` list, so the dealer is the party at the lowest
	/// set bit. Works for every party — in particular NewOnly parties that
	/// don't hold an `existing_share`.
	fn designated_dealer_for(&self, i_mask: SubsetMask) -> Option<ParticipantId> {
		for (bit, party) in self.config.old_participants().iter().enumerate() {
			if (i_mask & (1 << bit)) != 0 {
				return Some(party);
			}
		}
		None
	}

	/// New committee post-Round-4 work: verify each received `r_{I→J}` against the
	/// matching Round 3 commitment, then sum them into `s_J^new` and produce a
	/// commitment per new subset we are in.
	fn verify_and_aggregate_new_shares(
		&mut self,
	) -> Result<BTreeMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]>, ResharingProtocolError> {
		let my_idx =
			self.config.new_participants().index_of(self.config.my_party_id()).ok_or_else(
				|| ResharingProtocolError::InternalError("not in new committee".into()),
			)?;

		// Collect every (I, J, dealer, r) we expect to use.
		let new_subsets = &self.new_subset_order;
		let mut s_new: BTreeMap<SubsetMask, NewShareData> = BTreeMap::new();
		for &j_mask in new_subsets {
			if (j_mask & (1 << my_idx)) == 0 {
				continue;
			}
			s_new.insert(j_mask, NewShareData::new());
		}

		for &i_mask in &self.old_subset_order {
			let dealer = match self.designated_dealer_for(i_mask) {
				Some(d) => d,
				None =>
					return Err(ResharingProtocolError::ShareVerificationFailed(format!(
						"no designated dealer found for old subset {:b}",
						i_mask
					))),
			};
			let dealer_r3 = self.round3_broadcasts.get(&dealer).ok_or_else(|| {
				ResharingProtocolError::DealerDeliveryFailed {
					dealer,
					reason: format!("missing Round 3 commitment for subset {:b}", i_mask),
				}
			})?;
			let dealer_r4 = self.round4_messages.get(&dealer).ok_or_else(|| {
				ResharingProtocolError::DealerDeliveryFailed {
					dealer,
					reason: format!("missing Round 4 message for subset {:b}", i_mask),
				}
			})?;
			for &j_mask in new_subsets {
				if (j_mask & (1 << my_idx)) == 0 {
					continue;
				}
				let r = dealer_r4.contributions.get(&(i_mask, j_mask)).ok_or_else(|| {
					ResharingProtocolError::DealerDeliveryFailed {
						dealer,
						reason: format!("did not deliver r_{{{:b}->{:b}}}", i_mask, j_mask),
					}
				})?;
				let expected_commit = commit_subshare(i_mask, j_mask, r);
				let dealer_commit =
					dealer_r3.commitments.get(&(i_mask, j_mask)).ok_or_else(|| {
						ResharingProtocolError::DealerDeliveryFailed {
							dealer,
							reason: format!("did not commit to r_{{{:b}->{:b}}}", i_mask, j_mask),
						}
					})?;
				if *dealer_commit != expected_commit {
					return Err(ResharingProtocolError::DealerDeliveryFailed {
						dealer,
						reason: format!(
							"sent r_{{{:b}->{:b}}} that doesn't match commitment",
							i_mask, j_mask
						),
					});
				}
				let acc = s_new.get_mut(&j_mask).unwrap();
				add_share_into(acc, r);
			}
		}

		// Reduce mod Q and stash.
		let mut commitments = BTreeMap::new();
		for (j_mask, mut share) in s_new {
			reduce_share_mod_q(&mut share);
			commitments.insert(j_mask, commit_new_share(j_mask, &share));
			self.new_shares.insert(j_mask, share);
		}
		Ok(commitments)
	}

	/// All members of new subset J must produce identical `s_J^new` (and thus identical
	/// commitments). Cross-verify that.
	///
	/// Only accepts share commitments from parties that are actually in the new subset.
	fn verify_new_share_consistency(&self) -> Result<(), ResharingProtocolError> {
		let mut by_subset: BTreeMap<SubsetMask, Vec<(ParticipantId, [u8; COMMITMENT_HASH_SIZE])>> =
			BTreeMap::new();
		for (party, broadcast) in &self.round5_broadcasts {
			for (j_mask, commit) in &broadcast.share_commitments {
				// Only accept commitments from parties that are in this new subset
				if self.config.new_participants().is_in_mask(*party, *j_mask) {
					by_subset.entry(*j_mask).or_default().push((*party, *commit));
				} else {
					log::warn!(
						"Ignoring share commitment from party {} for new_subset {:b}: \
						 party not in subset",
						party,
						j_mask
					);
				}
			}
		}
		for (j_mask, commits) in &by_subset {
			if commits.len() < 2 {
				continue;
			}
			let first = commits[0].1;
			for (party, commit) in &commits[1..] {
				if *commit != first {
					return Err(ResharingProtocolError::ShareVerificationFailed(format!(
						"members of new subset {:b} disagree: party {} differs from party {}",
						j_mask, party, commits[0].0
					)));
				}
			}
		}
		Ok(())
	}

	/// Extract `rho` (matrix-A seed). Old/Both parties take it from their existing
	/// share; NewOnly parties extract it from the public key prefix.
	fn derive_rho(&self) -> [u8; 32] {
		if let Some(existing) = self.existing_share.as_ref() {
			*existing.rho()
		} else {
			let mut rho = [0u8; 32];
			rho.copy_from_slice(&self.config.public_key().as_bytes()[..32]);
			rho
		}
	}

	/// Compute `t_J = A·s1_J^new + s2_J^new mod Q` for every new subset we hold.
	fn compute_my_partial_pks(&self) -> BTreeMap<SubsetMask, [[i32; N as usize]; K]> {
		let rho = self.derive_rho();
		self.new_shares
			.iter()
			.map(|(j_mask, share)| {
				let t =
					crate::protocol::partial_pk::compute_partial_pk_t(&rho, &share.s1, &share.s2);
				(*j_mask, t)
			})
			.collect()
	}

	/// Cross-check the broadcast partial PKs and sum them to confirm the
	/// resharing reconstructs the original public key.
	///
	/// Only accepts partial PK contributions from parties that are actually in the new subset.
	fn verify_public_key_preservation(&self) -> Result<(), ResharingProtocolError> {
		let mut canonical: BTreeMap<SubsetMask, [[i32; N as usize]; K]> = BTreeMap::new();
		for (party, broadcast) in &self.round5_broadcasts {
			for (j_mask, t_partial) in &broadcast.partial_pks {
				// Only accept partial PKs from parties that are in this new subset
				if !self.config.new_participants().is_in_mask(*party, *j_mask) {
					log::warn!(
						"Ignoring partial PK from party {} for new_subset {:b}: \
						 party not in subset",
						party,
						j_mask
					);
					continue;
				}
				match canonical.get(j_mask) {
					None => {
						canonical.insert(*j_mask, *t_partial);
					},
					Some(existing) =>
						if existing != t_partial {
							return Err(ResharingProtocolError::ShareVerificationFailed(format!(
								"members of new subset {:b} disagree on partial PK t_J",
								j_mask
							)));
						},
				}
			}
		}
		for j_mask in &self.new_subset_order {
			if !canonical.contains_key(j_mask) {
				return Err(ResharingProtocolError::ShareVerificationFailed(format!(
					"missing partial PK contribution for new subset {:b}",
					j_mask
				)));
			}
		}
		let rho = self.derive_rho();
		let recovered = crate::protocol::partial_pk::pack_combined_pk(&rho, canonical.values());
		if recovered.as_bytes() != self.config.public_key().as_bytes() {
			return Err(ResharingProtocolError::ShareVerificationFailed(
				"recovered public key does not match the original — a dealer corrupted at \
				 least one sub-share contribution"
					.to_string(),
			));
		}
		Ok(())
	}

	fn build_output(&self) -> Result<ResharingOutput, ResharingProtocolError> {
		if !self.config.role().is_new_committee() {
			return Ok(ResharingOutput {
				private_share: None,
				public_key: self.config.public_key().clone(),
				new_config: self.config.new_config(),
			});
		}
		let new_share = self.build_private_key_share()?;
		Ok(ResharingOutput {
			private_share: Some(new_share),
			public_key: self.config.public_key().clone(),
			new_config: self.config.new_config(),
		})
	}

	fn build_private_key_share(&self) -> Result<PrivateKeyShare, ResharingProtocolError> {
		let mut shares_data: BTreeMap<u16, SecretShareData> = BTreeMap::new();
		for (j_mask, share) in &self.new_shares {
			// Convert from Vec to fixed-size arrays
			let mut s1_arr = [[0i32; N as usize]; L];
			for (i, poly) in share.s1.iter().enumerate().take(L) {
				s1_arr[i] = *poly;
			}
			let mut s2_arr = [[0i32; N as usize]; K];
			for (i, poly) in share.s2.iter().enumerate().take(K) {
				s2_arr[i] = *poly;
			}
			shares_data.insert(*j_mask, SecretShareData { s1: s1_arr, s2: s2_arr });
		}

		let rho = self.derive_rho();
		let tr = if let Some(existing) = self.existing_share.as_ref() {
			*existing.tr()
		} else {
			*self.config.public_key().tr()
		};

		// Derive `party_key` from the actual share polynomials so it carries real
		// entropy (mirrors the C3 fix in the DKG path).
		let mut party_key = [0u8; 32];
		{
			let mut h = fips202::KeccakState::default();
			fips202::shake256_absorb(&mut h, b"reshare-party-key-v2");
			fips202::shake256_absorb(&mut h, &rho);
			fips202::shake256_absorb(&mut h, &self.config.my_party_id().to_le_bytes());
			let mut buf: Vec<u8> = Vec::new();
			for (j_mask, share) in &self.new_shares {
				buf.clear();
				buf.extend_from_slice(&j_mask.to_le_bytes());
				for poly in &share.s1 {
					for c in poly {
						buf.extend_from_slice(&c.to_le_bytes());
					}
				}
				for poly in &share.s2 {
					for c in poly {
						buf.extend_from_slice(&c.to_le_bytes());
					}
				}
				fips202::shake256_absorb(&mut h, &buf);
			}
			fips202::shake256_finalize(&mut h);
			fips202::shake256_squeeze(&mut party_key, &mut h);
		}

		Ok(PrivateKeyShare::new(
			self.config.my_party_id(),
			self.config.new_participants().len() as u32,
			self.config.new_threshold(),
			party_key,
			rho,
			tr,
			shares_data,
			self.config.new_participants().clone(),
		))
	}
}

// ============================================================================
// Free Functions: subset enumeration and sub-share derivation
// ============================================================================

/// Canonical enumeration of all old RSS subsets: every `k_old`-subset of the
/// `n_old` old committee positions. **Identical for every party**, so the
/// `i_idx` used to pick a residual `J` in `derive_subshares` is consistent
/// across all parties — without this consistency, dealers' commitments would
/// not match the verifiers' independent recomputations.
fn compute_old_subset_order(config: &ResharingConfig) -> Vec<SubsetMask> {
	let n = config.old_participants().len();
	let k = n - config.old_threshold() as usize + 1;
	generate_subset_masks(n, k)
}

fn compute_new_subset_order(config: &ResharingConfig) -> Vec<SubsetMask> {
	let n = config.new_participants().len();
	let k = n - config.new_threshold() as usize + 1;
	generate_subset_masks(n, k)
}

/// Enumerate subset masks of size `k` over `n` bits in canonical (numerically
/// ascending) order using Gosper's hack.
fn generate_subset_masks(n: usize, k: usize) -> Vec<SubsetMask> {
	if k == 0 || k > n {
		return Vec::new();
	}
	let mut out = Vec::new();
	let max_val: u32 = 1u32 << n;
	let mut mask: u32 = (1u32 << k) - 1;
	while mask < max_val {
		out.push(mask as SubsetMask);
		let c = mask & mask.wrapping_neg();
		let r = mask + c;
		mask = (((r ^ mask) >> 2) / c) | r;
	}
	out
}

/// Derive bounded sub-shares `r_{I→J}` for every new subset `J` such that
/// `Σ_J r_{I→J} = s_I` (mod Q).
///
/// Earlier versions sampled all but one sub-share as η-bounded values and let
/// one residual absorb the full difference. That preserves the secret, but the
/// residual can become a full-ring value and cause recovered signing partials
/// to leave the hyperball proof regime after repeated resharings.
///
/// This splitter first distributes the centered coefficient of `s_I` as evenly
/// as possible across all new subsets, then adds deterministic pairwise
/// zero-sum η-bounded noise. The integer sum of the outputs is exactly the
/// centered representative of `s_I`, hence the modular sum is `s_I`.
fn derive_subshares_with_session_seed(
	i_mask: SubsetMask,
	s_i: &SecretShareData,
	new_subsets: &[SubsetMask],
	session_seed: &[u8; 32],
) -> Vec<NewShareData> {
	debug_assert!(!new_subsets.is_empty());
	let mut out: Vec<NewShareData> = (0..new_subsets.len()).map(|_| NewShareData::new()).collect();

	// Build a PRF seed from (domain || session_seed || I_mask || s1 || s2).
	// All members of subset I know `s_i` and have computed the same session_seed,
	// so they derive the same PRF seed.
	let prf_seed = build_subset_seed_with_session(i_mask, s_i, session_seed);
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, BOUNDED_SPLIT_DOMAIN);
	fips202::shake256_absorb(&mut state, &prf_seed);
	for &j_mask in new_subsets {
		fips202::shake256_absorb(&mut state, &j_mask.to_le_bytes());
	}
	fips202::shake256_finalize(&mut state);

	let m = new_subsets.len();

	for poly_idx in 0..L {
		for coeff_idx in 0..N as usize {
			balanced_split_coeff(
				s_i.s1[poly_idx][coeff_idx],
				&mut out,
				true,
				poly_idx,
				coeff_idx,
				&mut state,
			);
		}
	}
	for poly_idx in 0..K {
		for coeff_idx in 0..N as usize {
			balanced_split_coeff(
				s_i.s2[poly_idx][coeff_idx],
				&mut out,
				false,
				poly_idx,
				coeff_idx,
				&mut state,
			);
		}
	}

	// Add pairwise zero-sum noise. Every unordered pair contributes +δ to one
	// subset and -δ to the other, so the sum over all new subsets stays exact.
	for a in 0..m {
		for b in (a + 1)..m {
			for poly_idx in 0..L {
				for coeff_idx in 0..N as usize {
					let delta = sample_eta_coeff(&mut state);
					out[a].s1[poly_idx][coeff_idx] += delta;
					out[b].s1[poly_idx][coeff_idx] -= delta;
				}
			}
			for poly_idx in 0..K {
				for coeff_idx in 0..N as usize {
					let delta = sample_eta_coeff(&mut state);
					out[a].s2[poly_idx][coeff_idx] += delta;
					out[b].s2[poly_idx][coeff_idx] -= delta;
				}
			}
		}
	}
	out
}

fn balanced_split_coeff(
	coeff: i32,
	out: &mut [NewShareData],
	is_s1: bool,
	poly_idx: usize,
	coeff_idx: usize,
	state: &mut fips202::KeccakState,
) {
	let m = out.len();
	let centered = center_mod_q(coeff);
	let m_i32 = m as i32;
	let base = centered.div_euclid(m_i32);
	let remainder = centered.rem_euclid(m_i32) as usize;
	let offset = sample_uniform_usize(state, m);

	for (j_idx, share) in out.iter_mut().enumerate() {
		let gets_remainder = ((j_idx + m - offset) % m) < remainder;
		let value = base + if gets_remainder { 1 } else { 0 };
		if is_s1 {
			share.s1[poly_idx][coeff_idx] = value;
		} else {
			share.s2[poly_idx][coeff_idx] = value;
		}
	}
}

#[inline]
fn center_mod_q(coeff: i32) -> i32 {
	let reduced = mod_q(coeff);
	if reduced > Q / 2 {
		reduced - Q
	} else {
		reduced
	}
}

fn sample_eta_coeff(state: &mut fips202::KeccakState) -> i32 {
	let eta_i32 = ETA as i32;
	let bound = 2 * eta_i32 + 1;
	let cutoff = (256 / bound) * bound;
	let mut buf = [0u8; 1];
	loop {
		fips202::shake256_squeeze(&mut buf, state);
		let b = buf[0] as i32;
		if b < cutoff {
			return (b % bound) - eta_i32;
		}
	}
}

fn sample_uniform_usize(state: &mut fips202::KeccakState, upper: usize) -> usize {
	if upper <= 1 {
		return 0;
	}
	let cutoff = (256 / upper) * upper;
	let mut buf = [0u8; 1];
	loop {
		fips202::shake256_squeeze(&mut buf, state);
		let b = buf[0] as usize;
		if b < cutoff {
			return b % upper;
		}
	}
}

/// Build subset seed incorporating the public session seed.
fn build_subset_seed_with_session(
	i_mask: SubsetMask,
	s_i: &SecretShareData,
	session_seed: &[u8; 32],
) -> [u8; 64] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, SUBSET_SEED_DOMAIN);
	// Mix in session seed for per-session randomization.
	fips202::shake256_absorb(&mut state, session_seed);
	fips202::shake256_absorb(&mut state, &i_mask.to_le_bytes());
	let mut buf: Vec<u8> = Vec::new();
	for poly in &s_i.s1 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	for poly in &s_i.s2 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; 64];
	fips202::shake256_squeeze(&mut out, &mut state);
	out
}

/// Compute commitment to entropy: H("resharing-entropy-commit-v1" || entropy).
fn commit_entropy(entropy: &[u8; ENTROPY_SIZE]) -> [u8; COMMITMENT_HASH_SIZE] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, ENTROPY_COMMIT_DOMAIN);
	fips202::shake256_absorb(&mut state, entropy);
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; COMMITMENT_HASH_SIZE];
	fips202::shake256_squeeze(&mut out, &mut state);
	out
}

fn commit_subshare(
	i_mask: SubsetMask,
	j_mask: SubsetMask,
	r: &NewShareData,
) -> [u8; COMMITMENT_HASH_SIZE] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, COMMIT_DOMAIN);
	fips202::shake256_absorb(&mut state, &i_mask.to_le_bytes());
	fips202::shake256_absorb(&mut state, &j_mask.to_le_bytes());
	let mut buf: Vec<u8> = Vec::new();
	for poly in &r.s1 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	for poly in &r.s2 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; COMMITMENT_HASH_SIZE];
	fips202::shake256_squeeze(&mut out, &mut state);
	out
}

fn commit_new_share(j_mask: SubsetMask, share: &NewShareData) -> [u8; COMMITMENT_HASH_SIZE] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, NEW_SHARE_COMMIT_DOMAIN);
	fips202::shake256_absorb(&mut state, &j_mask.to_le_bytes());
	let mut buf: Vec<u8> = Vec::new();
	for poly in &share.s1 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	for poly in &share.s2 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; COMMITMENT_HASH_SIZE];
	fips202::shake256_squeeze(&mut out, &mut state);
	out
}

fn add_share_into(acc: &mut NewShareData, r: &NewShareData) {
	// Bounded conditional sub-shares are small for supported n <= 6 configurations,
	// so accumulation cannot overflow i32 before the final mod-Q reduction.
	for (a, b) in acc.s1.iter_mut().zip(r.s1.iter()) {
		for (ac, bc) in a.iter_mut().zip(b.iter()) {
			*ac += *bc;
		}
	}
	for (a, b) in acc.s2.iter_mut().zip(r.s2.iter()) {
		for (ac, bc) in a.iter_mut().zip(b.iter()) {
			*ac += *bc;
		}
	}
}
fn reduce_share_mod_q(share: &mut NewShareData) {
	for poly in share.s1.iter_mut() {
		for c in poly.iter_mut() {
			*c = mod_q(*c);
		}
	}
	for poly in share.s2.iter_mut() {
		for c in poly.iter_mut() {
			*c = mod_q(*c);
		}
	}
}

#[inline]
fn mod_q(x: i32) -> i32 {
	let r = x % Q;
	if r < 0 {
		r + Q
	} else {
		r
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	/// Test SSID for use in unit tests.
	const TEST_SSID: [u8; RESHARING_SSID_SIZE] = [0xABu8; RESHARING_SSID_SIZE];

	#[test]
	fn test_generate_subset_masks() {
		let s = generate_subset_masks(3, 2);
		assert_eq!(s, vec![0b011, 0b101, 0b110]);

		let s = generate_subset_masks(4, 2);
		assert_eq!(s.len(), 6);
		// Canonical ascending order.
		for i in 1..s.len() {
			assert!(s[i - 1] < s[i]);
		}

		let s = generate_subset_masks(5, 3);
		assert_eq!(s.len(), 10);
		for i in 1..s.len() {
			assert!(s[i - 1] < s[i]);
		}
	}

	#[test]
	fn test_generate_subset_masks_edge_cases() {
		assert!(generate_subset_masks(0, 0).is_empty());
		assert!(generate_subset_masks(3, 0).is_empty());
		assert!(generate_subset_masks(3, 4).is_empty());
		assert_eq!(generate_subset_masks(4, 4), vec![0b1111]);
	}

	#[test]
	fn test_subset_seed_is_deterministic_for_same_share() {
		let s = SecretShareData { s1: [[3i32; N as usize]; L], s2: [[5i32; N as usize]; K] };
		let session_seed = [42u8; 32];
		assert_eq!(
			build_subset_seed_with_session(0b011, &s, &session_seed),
			build_subset_seed_with_session(0b011, &s, &session_seed)
		);
	}

	#[test]
	fn test_derive_subshares_sums_to_original_share() {
		let s = SecretShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let subshares = derive_subshares_with_session_seed(0b011, &s, &new_subsets, &session_seed);
		let mut sum_s1: Vec<[i64; N as usize]> = vec![[0i64; N as usize]; L];
		let mut sum_s2: Vec<[i64; N as usize]> = vec![[0i64; N as usize]; K];
		for sub in &subshares {
			for (a, b) in sum_s1.iter_mut().zip(sub.s1.iter()) {
				for (ac, bc) in a.iter_mut().zip(b.iter()) {
					*ac += *bc as i64;
				}
			}
			for (a, b) in sum_s2.iter_mut().zip(sub.s2.iter()) {
				for (ac, bc) in a.iter_mut().zip(b.iter()) {
					*ac += *bc as i64;
				}
			}
		}
		for (poly_idx, poly) in sum_s1.iter().enumerate() {
			for (c_idx, &v) in poly.iter().enumerate() {
				let expected = s.s1[poly_idx][c_idx] as i64;
				let q = Q as i64;
				assert_eq!((v % q + q) % q, (expected % q + q) % q);
			}
		}
		for (poly_idx, poly) in sum_s2.iter().enumerate() {
			for (c_idx, &v) in poly.iter().enumerate() {
				let expected = s.s2[poly_idx][c_idx] as i64;
				let q = Q as i64;
				assert_eq!((v % q + q) % q, (expected % q + q) % q);
			}
		}
	}

	#[test]
	fn test_derive_subshares_are_bounded_for_small_inputs() {
		let s = SecretShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let subshares = derive_subshares_with_session_seed(0b011, &s, &new_subsets, &session_seed);
		let max_expected = 1 + (new_subsets.len() as i32 - 1) * ETA as i32;

		for sub in &subshares {
			for poly in &sub.s1 {
				for &coeff in poly {
					assert!(
						coeff.abs() <= max_expected,
						"s1 coefficient {} exceeded {}",
						coeff,
						max_expected
					);
				}
			}
			for poly in &sub.s2 {
				for &coeff in poly {
					assert!(
						coeff.abs() <= max_expected,
						"s2 coefficient {} exceeded {}",
						coeff,
						max_expected
					);
				}
			}
		}
	}

	#[test]
	fn test_derive_subshares_handles_centered_mod_q_inputs() {
		let s = SecretShareData { s1: [[Q - 1; N as usize]; L], s2: [[Q - 2; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let subshares = derive_subshares_with_session_seed(0b011, &s, &new_subsets, &session_seed);

		let mut sum_s1: Vec<[i64; N as usize]> = vec![[0i64; N as usize]; L];
		let mut sum_s2: Vec<[i64; N as usize]> = vec![[0i64; N as usize]; K];
		for sub in &subshares {
			for (a, b) in sum_s1.iter_mut().zip(sub.s1.iter()) {
				for (ac, bc) in a.iter_mut().zip(b.iter()) {
					*ac += *bc as i64;
				}
			}
			for (a, b) in sum_s2.iter_mut().zip(sub.s2.iter()) {
				for (ac, bc) in a.iter_mut().zip(b.iter()) {
					*ac += *bc as i64;
				}
			}
		}

		let q = Q as i64;
		for poly in &sum_s1 {
			for &v in poly {
				assert_eq!((v % q + q) % q, (Q - 1) as i64);
			}
		}
		for poly in &sum_s2 {
			for &v in poly {
				assert_eq!((v % q + q) % q, (Q - 2) as i64);
			}
		}
	}

	#[test]
	fn test_derive_subshares_is_deterministic() {
		let s = SecretShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let a = derive_subshares_with_session_seed(0b011, &s, &new_subsets, &session_seed);
		let b = derive_subshares_with_session_seed(0b011, &s, &new_subsets, &session_seed);
		for (x, y) in a.iter().zip(b.iter()) {
			assert_eq!(x.s1, y.s1);
			assert_eq!(x.s2, y.s2);
		}
	}

	#[test]
	fn test_commit_subshare_distinguishes_inputs() {
		let r1 = NewShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let r2 = NewShareData { s1: [[1i32; N as usize]; L], s2: [[3i32; N as usize]; K] };
		let c1 = commit_subshare(0b011, 0b101, &r1);
		let c2 = commit_subshare(0b011, 0b101, &r2);
		assert_ne!(c1, c2);
		// Different subsets should also differ.
		let c3 = commit_subshare(0b011, 0b110, &r1);
		assert_ne!(c1, c3);
	}

	#[test]
	fn test_resharing_state_transitions() {
		assert_ne!(ResharingState::Round1Generate, ResharingState::Round1Waiting);
		assert_ne!(ResharingState::Round2Generate, ResharingState::Round2Waiting);
		assert_ne!(ResharingState::Round3Generate, ResharingState::Round3Waiting);
		assert_ne!(ResharingState::Combining, ResharingState::Done);
	}

	#[test]
	fn test_action_variants() {
		let wait: Action<()> = Action::Wait;
		let send_many: Action<()> = Action::SendMany(vec![1, 2, 3]);
		let send_private: Action<()> = Action::SendPrivate(42, vec![4, 5, 6]);
		let ret: Action<i32> = Action::Return(123);

		match wait {
			Action::Wait => {},
			_ => panic!("Expected Wait"),
		}
		match send_many {
			Action::SendMany(data) => assert_eq!(data, vec![1, 2, 3]),
			_ => panic!("Expected SendMany"),
		}
		match send_private {
			Action::SendPrivate(to, data) => {
				assert_eq!(to, 42);
				assert_eq!(data, vec![4, 5, 6]);
			},
			_ => panic!("Expected SendPrivate"),
		}
		match ret {
			Action::Return(val) => assert_eq!(val, 123),
			_ => panic!("Expected Return"),
		}
	}

	#[test]
	fn test_mod_q() {
		assert_eq!(mod_q(0), 0);
		assert_eq!(mod_q(1), 1);
		assert_eq!(mod_q(Q - 1), Q - 1);
		assert_eq!(mod_q(Q), 0);
		assert_eq!(mod_q(Q + 1), 1);
		assert_eq!(mod_q(-1), Q - 1);
		assert_eq!(mod_q(-Q), 0);
		assert_eq!(mod_q(-Q - 1), Q - 1);
	}

	#[test]
	fn test_subshares_for_disjoint_share_data_diverge() {
		// Two different `s_I^old` values must produce different sub-share splits
		// (otherwise an attacker who saw them couldn't distinguish secrets).
		let s_a = SecretShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let s_b = SecretShareData { s1: [[3i32; N as usize]; L], s2: [[5i32; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let a = derive_subshares_with_session_seed(0b011, &s_a, &new_subsets, &session_seed);
		let b = derive_subshares_with_session_seed(0b011, &s_b, &new_subsets, &session_seed);
		// The bounded split includes PRF-derived zero-sum noise keyed by `s_i`,
		// so shares for different old secrets must differ.
		assert_ne!(a[1].s1, b[1].s1);
	}

	#[test]
	fn test_subshares_independent_per_old_subset() {
		// Different old subsets sharing the same `s_I^old` value must still produce
		// different sub-shares, because the PRF seed mixes `i_mask`.
		let s = SecretShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let a = derive_subshares_with_session_seed(0b011, &s, &new_subsets, &session_seed);
		let b = derive_subshares_with_session_seed(0b101, &s, &new_subsets, &session_seed);
		// The bounded split includes PRF-derived zero-sum noise keyed on `i_mask`,
		// so shares for different old subsets must differ.
		assert_ne!(a[1].s1, b[1].s1);
	}

	#[test]
	fn test_round3_broadcast_does_not_leak_subshares() {
		// Sanity: a Round 3 broadcast carries hash commitments and nothing else.
		// In particular it must not contain any plaintext NewShareData fields.
		let mut commitments = BTreeMap::new();
		commitments.insert((0b011u16, 0b101u16), [9u8; COMMITMENT_HASH_SIZE]);
		let r3 = ResharingRound3Broadcast { ssid: TEST_SSID, party_id: 7, commitments };
		// The struct only has `ssid`, `party_id` (u32) and `commitments` (BTreeMap of hashes).
		// If anyone ever adds back leaky plaintext fields, this test should be
		// updated alongside the security review.
		assert_eq!(r3.party_id, 7);
		assert_eq!(r3.commitments.len(), 1);
	}

	#[test]
	fn test_protocol_error_display() {
		let err = ResharingProtocolError::InvalidState("test".to_string());
		assert!(err.to_string().contains("Invalid state"));

		let err = ResharingProtocolError::UnknownParty(42);
		assert!(err.to_string().contains("42"));

		let err = ResharingProtocolError::InsufficientParties { required: 3, received: 2 };
		assert!(err.to_string().contains("3"));
		assert!(err.to_string().contains("2"));
	}
}
