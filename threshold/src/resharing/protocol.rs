//! Resharing Protocol State Machine.
//!
//! This module implements the resharing protocol using the poke/message pattern
//! compatible with NEAR MPC's `run_protocol` infrastructure.
//!
//! # Protocol Overview
//!
//! The resharing protocol has 3 rounds:
//! 1. **Round 1 (Blinded Reconstruction)**: Old committee members broadcast blinded
//!    contributions to reconstruct the secret
//! 2. **Round 2 (Re-dealing)**: Dealers generate and distribute new shares to new committee
//! 3. **Round 3 (Verification)**: New committee members verify share consistency
//!
//! # State Machine
//!
//! ```text
//! Round1Generate -> Round1Waiting -> Round2Generate -> Round2Waiting
//!     -> Round3Generate -> Round3Waiting -> Combining -> Done
//! ```

use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::participants::ParticipantId;

use super::types::{
	BlindedContribution, NewShareData, ResharingConfig, ResharingMessage, ResharingOutput,
	ResharingRound1Broadcast, ResharingRound2Message, ResharingRound3Broadcast, SubsetMask,
	COMMITMENT_HASH_SIZE, K, L, N,
};

// ============================================================================
// Action Enum
// ============================================================================

/// Actions returned by the protocol's `poke` method.
///
/// This enum matches the pattern used by NEAR MPC's cait-sith protocols,
/// enabling integration with `run_protocol`.
#[derive(Debug, Clone)]
pub enum Action<T> {
	/// Do nothing, waiting for more messages from other participants.
	Wait,
	/// Send a message to all other participants (broadcast).
	SendMany(Vec<u8>),
	/// Send a private message to a specific participant.
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
	/// Serialization error.
	SerializationError(String),
	/// A party reported failure.
	PartyFailure(Vec<ParticipantId>),
	/// Not enough parties participated.
	InsufficientParties { required: usize, received: usize },
	/// Internal error.
	InternalError(String),
}

impl std::fmt::Display for ResharingProtocolError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
			ResharingProtocolError::SerializationError(s) => {
				write!(f, "Serialization error: {}", s)
			},
			ResharingProtocolError::PartyFailure(parties) => {
				write!(f, "Party failure: {:?}", parties)
			},
			ResharingProtocolError::InsufficientParties { required, received } => {
				write!(f, "Insufficient parties: required {}, received {}", required, received)
			},
			ResharingProtocolError::InternalError(s) => write!(f, "Internal error: {}", s),
		}
	}
}

impl std::error::Error for ResharingProtocolError {}

// ============================================================================
// Protocol State
// ============================================================================

/// Current state of the resharing protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ResharingState {
	/// Generating Round 1 message (blinded contribution).
	Round1Generate,
	/// Waiting for Round 1 messages from other old committee members.
	Round1Waiting,
	/// Generating Round 2 messages (new share distribution).
	Round2Generate,
	/// Waiting for Round 2 messages (receiving new shares).
	Round2Waiting,
	/// Generating Round 3 message (verification commitment).
	Round3Generate,
	/// Waiting for Round 3 messages from other new committee members.
	Round3Waiting,
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
///
/// Implements the committee handoff protocol for RSS-based threshold Dilithium.
/// Uses the poke/message pattern compatible with NEAR MPC.
///
/// # Usage
///
/// ```ignore
/// let mut protocol = ResharingProtocol::new(config, seed)?;
///
/// loop {
///     match protocol.poke()? {
///         Action::Wait => { /* wait for messages */ }
///         Action::SendMany(data) => { /* broadcast */ }
///         Action::SendPrivate(to, data) => { /* send to specific party */ }
///         Action::Return(output) => {
///             // Done!
///             break;
///         }
///     }
///     // When messages arrive: protocol.message(from, data);
/// }
/// ```
pub struct ResharingProtocol {
	/// Configuration for this resharing.
	config: ResharingConfig,
	/// Current protocol state.
	state: ResharingState,
	/// Random seed for generating blinding values.
	seed: [u8; 32],

	// Round 1 data
	/// Our blinding values for s1 (if we're in old committee).
	my_blinding_s1: Option<Vec<[i32; N]>>,
	/// Our blinding values for s2 (if we're in old committee).
	my_blinding_s2: Option<Vec<[i32; N]>>,
	/// Our Round 1 broadcast (if we're in old committee).
	my_round1: Option<ResharingRound1Broadcast>,
	/// Collected Round 1 broadcasts from old committee.
	round1_broadcasts: HashMap<ParticipantId, ResharingRound1Broadcast>,

	// Round 2 data
	/// Our Round 2 messages to send (if we're a dealer).
	my_round2_messages: Vec<ResharingRound2Message>,
	/// Collected Round 2 messages we received (if we're in new committee).
	round2_messages: HashMap<ParticipantId, ResharingRound2Message>,
	/// Number of Round 2 messages sent.
	round2_sent_count: usize,

	// Round 3 data
	/// Our Round 3 broadcast (if we're in new committee).
	my_round3: Option<ResharingRound3Broadcast>,
	/// Collected Round 3 broadcasts from new committee.
	round3_broadcasts: HashMap<ParticipantId, ResharingRound3Broadcast>,

	// Final output
	/// The new shares we've received/computed (if we're in new committee).
	new_shares: HashMap<SubsetMask, NewShareData>,
}

impl ResharingProtocol {
	/// Create a new resharing protocol instance.
	///
	/// # Arguments
	///
	/// * `config` - The resharing configuration
	/// * `seed` - Random seed for blinding value generation
	///
	/// # Returns
	///
	/// A new protocol instance ready to run.
	pub fn new(config: ResharingConfig, seed: [u8; 32]) -> Self {
		Self {
			config,
			state: ResharingState::Round1Generate,
			seed,
			my_blinding_s1: None,
			my_blinding_s2: None,
			my_round1: None,
			round1_broadcasts: HashMap::new(),
			my_round2_messages: Vec::new(),
			round2_messages: HashMap::new(),
			round2_sent_count: 0,
			my_round3: None,
			round3_broadcasts: HashMap::new(),
			new_shares: HashMap::new(),
		}
	}

	/// Get the current protocol state.
	pub fn state(&self) -> &ResharingState {
		&self.state
	}

	/// Get this party's ID.
	pub fn my_party_id(&self) -> ParticipantId {
		self.config.my_party_id
	}

	/// Get the configuration.
	pub fn config(&self) -> &ResharingConfig {
		&self.config
	}

	/// Check if we have enough Round 1 messages.
	fn have_enough_round1(&self) -> bool {
		self.round1_broadcasts.len() >= self.config.old_threshold as usize
	}

	/// Check if we have enough Round 2 messages.
	fn have_enough_round2(&self) -> bool {
		// We need messages from at least threshold old committee members
		self.round2_messages.len() >= self.config.old_threshold as usize
	}

	/// Check if we have all Round 3 messages.
	fn have_all_round3(&self) -> bool {
		self.round3_broadcasts.len() >= self.config.new_participants.len()
	}

	/// Serialize a message for transmission.
	fn serialize_message(msg: &ResharingMessage) -> Result<Vec<u8>, ResharingProtocolError> {
		#[cfg(feature = "serde")]
		{
			bincode::serialize(msg).map_err(|e| {
				ResharingProtocolError::SerializationError(format!("Failed to serialize: {}", e))
			})
		}
		#[cfg(not(feature = "serde"))]
		{
			let _ = msg;
			Err(ResharingProtocolError::SerializationError("serde feature not enabled".to_string()))
		}
	}

	/// Deserialize a message from bytes.
	fn deserialize_message(data: &[u8]) -> Result<ResharingMessage, ResharingProtocolError> {
		#[cfg(feature = "serde")]
		{
			bincode::deserialize(data).map_err(|e| {
				ResharingProtocolError::SerializationError(format!("Failed to deserialize: {}", e))
			})
		}
		#[cfg(not(feature = "serde"))]
		{
			let _ = data;
			Err(ResharingProtocolError::SerializationError("serde feature not enabled".to_string()))
		}
	}

	/// Advance the protocol state machine.
	///
	/// Call this method repeatedly to drive the protocol forward.
	/// It returns an action indicating what to do next.
	pub fn poke(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		match &self.state {
			ResharingState::Round1Generate => self.handle_round1_generate(),
			ResharingState::Round1Waiting => self.handle_round1_waiting(),
			ResharingState::Round2Generate => self.handle_round2_generate(),
			ResharingState::Round2Waiting => self.handle_round2_waiting(),
			ResharingState::Round3Generate => self.handle_round3_generate(),
			ResharingState::Round3Waiting => self.handle_round3_waiting(),
			ResharingState::Combining => self.handle_combining(),
			ResharingState::Done => {
				Err(ResharingProtocolError::InvalidState("Protocol already completed".to_string()))
			},
			ResharingState::Failed(reason) => {
				Err(ResharingProtocolError::InvalidState(format!("Protocol failed: {}", reason)))
			},
		}
	}

	/// Handle an incoming message from another party.
	///
	/// # Arguments
	///
	/// * `from` - The party ID that sent the message
	/// * `data` - The serialized message data
	pub fn message(&mut self, from: ParticipantId, data: Vec<u8>) {
		// Ignore messages if protocol is done or failed
		if matches!(self.state, ResharingState::Done | ResharingState::Failed(_)) {
			return;
		}

		// Deserialize and route the message
		let msg = match Self::deserialize_message(&data) {
			Ok(m) => m,
			Err(e) => {
				tracing::warn!("Failed to deserialize message from {}: {}", from, e);
				return;
			},
		};

		// Verify sender matches message
		if msg.party_id() != from {
			tracing::warn!("Message party_id {} doesn't match sender {}", msg.party_id(), from);
			return;
		}

		match msg {
			ResharingMessage::Round1(broadcast) => {
				self.handle_round1_message(from, broadcast);
			},
			ResharingMessage::Round2(msg) => {
				self.handle_round2_message(from, msg);
			},
			ResharingMessage::Round3(broadcast) => {
				self.handle_round3_message(from, broadcast);
			},
		}
	}

	// ========================================================================
	// Round 1: Blinded Reconstruction
	// ========================================================================

	fn handle_round1_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Only old committee members participate in Round 1
		if !self.config.role.is_old_committee() {
			// New-only parties skip to waiting for Round 2
			self.state = ResharingState::Round2Waiting;
			return Ok(Action::Wait);
		}

		// Generate blinding values
		let (blinding_s1, blinding_s2) = self.generate_blinding_values();
		self.my_blinding_s1 = Some(blinding_s1.clone());
		self.my_blinding_s2 = Some(blinding_s2.clone());

		// Compute blinded contribution: recovered_share + blinding
		let (blinded_s1, blinded_s2) =
			self.compute_blinded_contribution(&blinding_s1, &blinding_s2)?;

		// Compute commitment to blinding values
		let blinding_commitment = self.compute_blinding_commitment(&blinding_s1, &blinding_s2);

		// Create Round 1 broadcast
		let broadcast = ResharingRound1Broadcast {
			party_id: self.config.my_party_id,
			blinded_s1_contribution: BlindedContribution { coefficients: blinded_s1 },
			blinded_s2_contribution: BlindedContribution { coefficients: blinded_s2 },
			blinding_commitment,
		};

		// Store our broadcast
		self.my_round1 = Some(broadcast.clone());
		self.round1_broadcasts.insert(self.config.my_party_id, broadcast.clone());

		// Serialize and broadcast
		let msg = ResharingMessage::Round1(broadcast);
		let data = Self::serialize_message(&msg)?;

		self.state = ResharingState::Round1Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round1_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.have_enough_round1() {
			self.state = ResharingState::Round2Generate;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round1_message(&mut self, from: ParticipantId, broadcast: ResharingRound1Broadcast) {
		// Ignore if not in expected state
		if !matches!(self.state, ResharingState::Round1Generate | ResharingState::Round1Waiting) {
			return;
		}

		// Verify sender is in old committee
		if !self.config.old_participants.contains(from) {
			tracing::warn!("Round 1 message from non-old-committee member: {}", from);
			return;
		}

		// Ignore duplicates
		if self.round1_broadcasts.contains_key(&from) {
			return;
		}

		// Store the broadcast
		self.round1_broadcasts.insert(from, broadcast);
	}

	// ========================================================================
	// Round 2: Re-dealing
	// ========================================================================

	fn handle_round2_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Only old committee members who participated in Round 1 can deal
		if !self.config.role.is_old_committee() {
			self.state = ResharingState::Round2Waiting;
			return Ok(Action::Wait);
		}

		// Generate new shares for the new committee
		self.generate_new_shares()?;

		// If we have messages to send, start sending them
		if !self.my_round2_messages.is_empty() {
			self.state = ResharingState::Round2Waiting;
			return self.send_next_round2_message();
		}

		// No messages to send (shouldn't happen if we're a dealer)
		self.state = ResharingState::Round2Waiting;
		Ok(Action::Wait)
	}

	fn handle_round2_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// If we still have Round 2 messages to send, send them
		if self.round2_sent_count < self.my_round2_messages.len() {
			return self.send_next_round2_message();
		}

		// Check if we've received enough messages (for new committee members)
		if self.config.role.is_new_committee() && self.have_enough_round2() {
			self.state = ResharingState::Round3Generate;
			return self.poke();
		}

		// Old-only parties go straight to waiting for completion
		if !self.config.role.is_new_committee()
			&& self.round2_sent_count >= self.my_round2_messages.len()
		{
			// Old-only parties don't participate in Round 3
			self.state = ResharingState::Combining;
			return self.poke();
		}

		Ok(Action::Wait)
	}

	fn send_next_round2_message(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.round2_sent_count >= self.my_round2_messages.len() {
			return Ok(Action::Wait);
		}

		let msg = &self.my_round2_messages[self.round2_sent_count];
		let to_party = msg.to_party_id;
		let resharing_msg = ResharingMessage::Round2(msg.clone());
		let data = Self::serialize_message(&resharing_msg)?;

		self.round2_sent_count += 1;

		Ok(Action::SendPrivate(to_party, data))
	}

	fn handle_round2_message(&mut self, from: ParticipantId, msg: ResharingRound2Message) {
		// Ignore if not in expected state
		if !matches!(self.state, ResharingState::Round2Generate | ResharingState::Round2Waiting) {
			return;
		}

		// Verify sender is in old committee
		if !self.config.old_participants.contains(from) {
			tracing::warn!("Round 2 message from non-old-committee member: {}", from);
			return;
		}

		// Verify message is for us
		if msg.to_party_id != self.config.my_party_id {
			tracing::warn!(
				"Round 2 message intended for {} received by {}",
				msg.to_party_id,
				self.config.my_party_id
			);
			return;
		}

		// Ignore duplicates
		if self.round2_messages.contains_key(&from) {
			return;
		}

		// Store the message and accumulate shares
		for (subset_mask, share_data) in &msg.shares {
			let entry = self.new_shares.entry(*subset_mask).or_insert_with(NewShareData::new);
			// Add the share data (will be combined later)
			for i in 0..L {
				for j in 0..N {
					entry.s1[i][j] = entry.s1[i][j].wrapping_add(share_data.s1[i][j]);
				}
			}
			for i in 0..K {
				for j in 0..N {
					entry.s2[i][j] = entry.s2[i][j].wrapping_add(share_data.s2[i][j]);
				}
			}
		}

		self.round2_messages.insert(from, msg);
	}

	// ========================================================================
	// Round 3: Verification
	// ========================================================================

	fn handle_round3_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Only new committee members participate in Round 3
		if !self.config.role.is_new_committee() {
			self.state = ResharingState::Combining;
			return self.poke();
		}

		// Compute commitments to our new shares
		let share_commitments = self.compute_share_commitments();

		// Create Round 3 broadcast
		let broadcast = ResharingRound3Broadcast {
			party_id: self.config.my_party_id,
			share_commitments,
			success: true,
			error_message: None,
		};

		// Store our broadcast
		self.my_round3 = Some(broadcast.clone());
		self.round3_broadcasts.insert(self.config.my_party_id, broadcast.clone());

		// Serialize and broadcast
		let msg = ResharingMessage::Round3(broadcast);
		let data = Self::serialize_message(&msg)?;

		self.state = ResharingState::Round3Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round3_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.have_all_round3() {
			self.state = ResharingState::Combining;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round3_message(&mut self, from: ParticipantId, broadcast: ResharingRound3Broadcast) {
		// Ignore if not in expected state
		if !matches!(self.state, ResharingState::Round3Generate | ResharingState::Round3Waiting) {
			return;
		}

		// Verify sender is in new committee
		if !self.config.new_participants.contains(from) {
			tracing::warn!("Round 3 message from non-new-committee member: {}", from);
			return;
		}

		// Ignore duplicates
		if self.round3_broadcasts.contains_key(&from) {
			return;
		}

		// Store the broadcast
		self.round3_broadcasts.insert(from, broadcast);
	}

	// ========================================================================
	// Combining and Finalization
	// ========================================================================

	fn handle_combining(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Verify Round 3 results (check for failures)
		let failed_parties: Vec<ParticipantId> = self
			.round3_broadcasts
			.iter()
			.filter(|(_, b)| !b.success)
			.map(|(id, _)| *id)
			.collect();

		if !failed_parties.is_empty() {
			self.state =
				ResharingState::Failed(format!("Parties reported failure: {:?}", failed_parties));
			return Err(ResharingProtocolError::PartyFailure(failed_parties));
		}

		// Verify share commitments are consistent
		// (Parties sharing the same subset should have matching commitments)
		self.verify_share_consistency()?;

		// Build the output
		let output = self.build_output()?;

		self.state = ResharingState::Done;
		Ok(Action::Return(output))
	}

	// ========================================================================
	// Helper Methods
	// ========================================================================

	/// Generate random blinding values for s1 and s2.
	fn generate_blinding_values(&self) -> (Vec<[i32; N]>, Vec<[i32; N]>) {
		use qp_rusty_crystals_dilithium::fips202;

		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, &self.seed, 32);
		fips202::shake256_absorb(&mut state, &self.config.my_party_id.to_le_bytes(), 4);
		fips202::shake256_absorb(&mut state, b"blinding", 8);
		fips202::shake256_finalize(&mut state);

		let mut blinding_s1 = vec![[0i32; N]; L];
		let mut blinding_s2 = vec![[0i32; N]; K];

		// Sample η-bounded blinding values
		let eta = 2i32; // ML-DSA-87 uses η=2

		for poly in blinding_s1.iter_mut() {
			for coeff in poly.iter_mut() {
				let mut buf = [0u8; 1];
				loop {
					fips202::shake256_squeeze(&mut buf, 1, &mut state);
					let b = buf[0] as i32;
					let bound = 2 * eta + 1;
					if b < (256 / bound) * bound {
						*coeff = (b % bound) - eta;
						break;
					}
				}
			}
		}

		for poly in blinding_s2.iter_mut() {
			for coeff in poly.iter_mut() {
				let mut buf = [0u8; 1];
				loop {
					fips202::shake256_squeeze(&mut buf, 1, &mut state);
					let b = buf[0] as i32;
					let bound = 2 * eta + 1;
					if b < (256 / bound) * bound {
						*coeff = (b % bound) - eta;
						break;
					}
				}
			}
		}

		(blinding_s1, blinding_s2)
	}

	/// Compute blinded contribution: recovered_share + blinding.
	fn compute_blinded_contribution(
		&self,
		blinding_s1: &[[i32; N]],
		blinding_s2: &[[i32; N]],
	) -> Result<(Vec<[i32; N]>, Vec<[i32; N]>), ResharingProtocolError> {
		// Get existing share
		let existing_share = self.config.existing_share.as_ref().ok_or_else(|| {
			ResharingProtocolError::InternalError("Missing existing share".to_string())
		})?;

		// Recover our share contribution
		// For now, we'll use a simplified approach - in full implementation,
		// this would use recover_share from secret_sharing.rs
		let shares = existing_share.shares();

		// Sum all our subset shares to get our contribution
		let mut contribution_s1 = vec![[0i32; N]; L];
		let mut contribution_s2 = vec![[0i32; N]; K];

		for (_subset_mask, share_data) in shares {
			for i in 0..L.min(share_data.s1.len()) {
				for j in 0..N {
					contribution_s1[i][j] = contribution_s1[i][j].wrapping_add(share_data.s1[i][j]);
				}
			}
			for i in 0..K.min(share_data.s2.len()) {
				for j in 0..N {
					contribution_s2[i][j] = contribution_s2[i][j].wrapping_add(share_data.s2[i][j]);
				}
			}
		}

		// Add blinding
		for i in 0..L {
			for j in 0..N {
				contribution_s1[i][j] = contribution_s1[i][j].wrapping_add(blinding_s1[i][j]);
			}
		}
		for i in 0..K {
			for j in 0..N {
				contribution_s2[i][j] = contribution_s2[i][j].wrapping_add(blinding_s2[i][j]);
			}
		}

		Ok((contribution_s1, contribution_s2))
	}

	/// Compute commitment to blinding values.
	fn compute_blinding_commitment(
		&self,
		blinding_s1: &[[i32; N]],
		blinding_s2: &[[i32; N]],
	) -> [u8; COMMITMENT_HASH_SIZE] {
		use qp_rusty_crystals_dilithium::fips202;

		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, b"blinding_commitment", 19);

		// Hash all blinding coefficients
		for poly in blinding_s1 {
			for coeff in poly {
				fips202::shake256_absorb(&mut state, &coeff.to_le_bytes(), 4);
			}
		}
		for poly in blinding_s2 {
			for coeff in poly {
				fips202::shake256_absorb(&mut state, &coeff.to_le_bytes(), 4);
			}
		}

		fips202::shake256_finalize(&mut state);
		let mut commitment = [0u8; COMMITMENT_HASH_SIZE];
		fips202::shake256_squeeze(&mut commitment, COMMITMENT_HASH_SIZE, &mut state);
		commitment
	}

	/// Generate new shares for the new committee.
	fn generate_new_shares(&mut self) -> Result<(), ResharingProtocolError> {
		// Aggregate blinded contributions from Round 1
		let (blinded_s1_total, blinded_s2_total) = self.aggregate_round1_contributions()?;

		// Compute total blinding to remove
		let (total_blinding_s1, total_blinding_s2) = self.compute_total_blinding();

		// Generate fresh RSS shares for the new committee
		// The shares should sum to: blinded_total - total_blinding = original_secret
		self.my_round2_messages = self.deal_new_shares(
			&blinded_s1_total,
			&blinded_s2_total,
			&total_blinding_s1,
			&total_blinding_s2,
		)?;

		Ok(())
	}

	/// Aggregate Round 1 contributions to get blinded total secret.
	fn aggregate_round1_contributions(
		&self,
	) -> Result<(Vec<[i32; N]>, Vec<[i32; N]>), ResharingProtocolError> {
		let mut total_s1 = vec![[0i32; N]; L];
		let mut total_s2 = vec![[0i32; N]; K];

		for broadcast in self.round1_broadcasts.values() {
			for i in 0..L {
				for j in 0..N {
					total_s1[i][j] = total_s1[i][j]
						.wrapping_add(broadcast.blinded_s1_contribution.coefficients[i][j]);
				}
			}
			for i in 0..K {
				for j in 0..N {
					total_s2[i][j] = total_s2[i][j]
						.wrapping_add(broadcast.blinded_s2_contribution.coefficients[i][j]);
				}
			}
		}

		Ok((total_s1, total_s2))
	}

	/// Compute the total blinding value to remove from the aggregated contributions.
	fn compute_total_blinding(&self) -> (Vec<[i32; N]>, Vec<[i32; N]>) {
		// For simplicity, we sum the blinding values we know about
		// In a full implementation, this would be coordinated across dealers
		let mut total_s1 = vec![[0i32; N]; L];
		let mut total_s2 = vec![[0i32; N]; K];

		if let Some(ref blinding_s1) = self.my_blinding_s1 {
			for i in 0..L {
				for j in 0..N {
					total_s1[i][j] = total_s1[i][j].wrapping_add(blinding_s1[i][j]);
				}
			}
		}
		if let Some(ref blinding_s2) = self.my_blinding_s2 {
			for i in 0..K {
				for j in 0..N {
					total_s2[i][j] = total_s2[i][j].wrapping_add(blinding_s2[i][j]);
				}
			}
		}

		(total_s1, total_s2)
	}

	/// Deal new shares to the new committee.
	fn deal_new_shares(
		&self,
		blinded_s1_total: &[[i32; N]],
		blinded_s2_total: &[[i32; N]],
		total_blinding_s1: &[[i32; N]],
		total_blinding_s2: &[[i32; N]],
	) -> Result<Vec<ResharingRound2Message>, ResharingProtocolError> {
		use qp_rusty_crystals_dilithium::fips202;

		let new_t = self.config.new_threshold;
		let new_n = self.config.new_participants.len() as u32;

		// Compute the actual secret: blinded_total - total_blinding
		let mut secret_s1 = vec![[0i32; N]; L];
		let mut secret_s2 = vec![[0i32; N]; K];

		for i in 0..L {
			for j in 0..N {
				secret_s1[i][j] = blinded_s1_total[i][j].wrapping_sub(total_blinding_s1[i][j]);
			}
		}
		for i in 0..K {
			for j in 0..N {
				secret_s2[i][j] = blinded_s2_total[i][j].wrapping_sub(total_blinding_s2[i][j]);
			}
		}

		// Generate subset structure for new committee
		// Subsets have size (n - t + 1)
		let subset_size = new_n - new_t + 1;
		let subsets = generate_subsets(new_n as usize, subset_size as usize);

		// Initialize share accumulator for each new party
		let mut party_shares: HashMap<ParticipantId, HashMap<SubsetMask, NewShareData>> =
			HashMap::new();
		for party_id in self.config.new_participants.iter() {
			party_shares.insert(party_id, HashMap::new());
		}

		// Generate random shares for all but the last subset
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, &self.seed, 32);
		fips202::shake256_absorb(&mut state, b"new_shares", 10);
		fips202::shake256_finalize(&mut state);

		let eta = 2i32;
		let mut shares_sum_s1 = vec![[0i32; N]; L];
		let mut shares_sum_s2 = vec![[0i32; N]; K];

		for (idx, &subset_mask) in subsets.iter().enumerate() {
			let is_last = idx == subsets.len() - 1;

			let share = if is_last {
				// Last subset: compute to make sum equal to secret
				let mut s1 = vec![[0i32; N]; L];
				let mut s2 = vec![[0i32; N]; K];
				for i in 0..L {
					for j in 0..N {
						s1[i][j] = secret_s1[i][j].wrapping_sub(shares_sum_s1[i][j]);
					}
				}
				for i in 0..K {
					for j in 0..N {
						s2[i][j] = secret_s2[i][j].wrapping_sub(shares_sum_s2[i][j]);
					}
				}
				NewShareData { s1, s2 }
			} else {
				// Random η-bounded share
				let mut s1 = vec![[0i32; N]; L];
				let mut s2 = vec![[0i32; N]; K];

				for poly in s1.iter_mut() {
					for coeff in poly.iter_mut() {
						let mut buf = [0u8; 1];
						loop {
							fips202::shake256_squeeze(&mut buf, 1, &mut state);
							let b = buf[0] as i32;
							let bound = 2 * eta + 1;
							if b < (256 / bound) * bound {
								*coeff = (b % bound) - eta;
								break;
							}
						}
					}
				}
				for poly in s2.iter_mut() {
					for coeff in poly.iter_mut() {
						let mut buf = [0u8; 1];
						loop {
							fips202::shake256_squeeze(&mut buf, 1, &mut state);
							let b = buf[0] as i32;
							let bound = 2 * eta + 1;
							if b < (256 / bound) * bound {
								*coeff = (b % bound) - eta;
								break;
							}
						}
					}
				}

				// Add to running sum
				for i in 0..L {
					for j in 0..N {
						shares_sum_s1[i][j] = shares_sum_s1[i][j].wrapping_add(s1[i][j]);
					}
				}
				for i in 0..K {
					for j in 0..N {
						shares_sum_s2[i][j] = shares_sum_s2[i][j].wrapping_add(s2[i][j]);
					}
				}

				NewShareData { s1, s2 }
			};

			// Distribute to all parties in this subset
			for (party_idx, party_id) in self.config.new_participants.iter().enumerate() {
				if (subset_mask & (1 << party_idx)) != 0 {
					if let Some(shares) = party_shares.get_mut(&party_id) {
						shares.insert(subset_mask, share.clone());
					}
				}
			}
		}

		// Create Round 2 messages for each new party
		let mut messages = Vec::new();
		for party_id in self.config.new_participants.iter() {
			if let Some(shares) = party_shares.remove(&party_id) {
				messages.push(ResharingRound2Message {
					from_party_id: self.config.my_party_id,
					to_party_id: party_id,
					shares,
				});
			}
		}

		Ok(messages)
	}

	/// Compute commitments to our new shares.
	fn compute_share_commitments(&self) -> HashMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]> {
		use qp_rusty_crystals_dilithium::fips202;

		let mut commitments = HashMap::new();

		for (subset_mask, share_data) in &self.new_shares {
			let mut state = fips202::KeccakState::default();
			fips202::shake256_absorb(&mut state, b"share_commitment", 16);
			fips202::shake256_absorb(&mut state, &subset_mask.to_le_bytes(), 2);

			// Hash share coefficients
			for poly in &share_data.s1 {
				for coeff in poly {
					fips202::shake256_absorb(&mut state, &coeff.to_le_bytes(), 4);
				}
			}
			for poly in &share_data.s2 {
				for coeff in poly {
					fips202::shake256_absorb(&mut state, &coeff.to_le_bytes(), 4);
				}
			}

			fips202::shake256_finalize(&mut state);
			let mut commitment = [0u8; COMMITMENT_HASH_SIZE];
			fips202::shake256_squeeze(&mut commitment, COMMITMENT_HASH_SIZE, &mut state);

			commitments.insert(*subset_mask, commitment);
		}

		commitments
	}

	/// Verify that parties sharing the same subset have consistent commitments.
	fn verify_share_consistency(&self) -> Result<(), ResharingProtocolError> {
		// Group commitments by subset
		let mut subset_commitments: HashMap<
			SubsetMask,
			Vec<(ParticipantId, [u8; COMMITMENT_HASH_SIZE])>,
		> = HashMap::new();

		for (party_id, broadcast) in &self.round3_broadcasts {
			for (subset_mask, commitment) in &broadcast.share_commitments {
				subset_commitments
					.entry(*subset_mask)
					.or_default()
					.push((*party_id, *commitment));
			}
		}

		// For each subset, verify all parties have the same commitment
		for (subset_mask, commitments) in &subset_commitments {
			if commitments.len() < 2 {
				continue;
			}

			let first_commitment = &commitments[0].1;
			for (party_id, commitment) in &commitments[1..] {
				if commitment != first_commitment {
					return Err(ResharingProtocolError::ShareVerificationFailed(format!(
						"Commitment mismatch for subset {:b}: party {} differs from party {}",
						subset_mask, party_id, commitments[0].0
					)));
				}
			}
		}

		Ok(())
	}

	/// Build the final resharing output.
	fn build_output(&self) -> Result<ResharingOutput, ResharingProtocolError> {
		// If we're not in the new committee, we don't get a new share
		if !self.config.role.is_new_committee() {
			return Ok(ResharingOutput {
				private_share: None,
				public_key: self.config.public_key.clone(),
				new_config: self.config.new_config(),
			});
		}

		// Build new private key share from accumulated shares
		let new_share = self.build_private_key_share()?;

		Ok(ResharingOutput {
			private_share: Some(new_share),
			public_key: self.config.public_key.clone(),
			new_config: self.config.new_config(),
		})
	}

	/// Build a new PrivateKeyShare from accumulated Round 2 data.
	fn build_private_key_share(&self) -> Result<PrivateKeyShare, ResharingProtocolError> {
		use crate::keys::SecretShareData;

		// Convert new_shares to SecretShareData format
		let mut shares_data: HashMap<u16, SecretShareData> = HashMap::new();
		for (subset_mask, share) in &self.new_shares {
			let s1_data: Vec<[i32; 256]> = share.s1.clone();
			let s2_data: Vec<[i32; 256]> = share.s2.clone();
			shares_data.insert(*subset_mask, SecretShareData { s1: s1_data, s2: s2_data });
		}

		// Get rho and tr from existing share or public key
		let (rho, tr) = if let Some(ref existing) = self.config.existing_share {
			(*existing.rho(), *existing.tr())
		} else {
			// For new parties, derive from public key
			([0u8; 32], *self.config.public_key.tr())
		};

		// Generate a new party key
		let mut party_key = [0u8; 32];
		{
			use qp_rusty_crystals_dilithium::fips202;
			let mut state = fips202::KeccakState::default();
			fips202::shake256_absorb(&mut state, &self.seed, 32);
			fips202::shake256_absorb(&mut state, b"party_key", 9);
			fips202::shake256_absorb(&mut state, &self.config.my_party_id.to_le_bytes(), 4);
			fips202::shake256_finalize(&mut state);
			fips202::shake256_squeeze(&mut party_key, 32, &mut state);
		}

		Ok(PrivateKeyShare::new(
			self.config.my_party_id,
			self.config.new_participants.len() as u32,
			self.config.new_threshold,
			party_key,
			rho,
			tr,
			shares_data,
			self.config.new_participants.clone(),
		))
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate all subsets of size `size` from `n` elements.
/// Returns subset masks as u16.
fn generate_subsets(n: usize, size: usize) -> Vec<SubsetMask> {
	if size > n || size == 0 {
		return Vec::new();
	}

	let mut subsets = Vec::new();
	let max_val: u16 = 1 << n;

	// Start with the smallest subset of the given size
	let mut subset: u16 = (1 << size) - 1;

	while subset < max_val {
		subsets.push(subset);

		// Gosper's hack to get next subset of same size
		let c = subset & (!subset + 1);
		let r = subset + c;
		subset = (((r ^ subset) >> 2) / c) | r;
	}

	subsets
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_generate_subsets() {
		// C(3, 2) = 3 subsets of size 2
		let subsets = generate_subsets(3, 2);
		assert_eq!(subsets.len(), 3);
		assert!(subsets.contains(&0b011)); // {0, 1}
		assert!(subsets.contains(&0b101)); // {0, 2}
		assert!(subsets.contains(&0b110)); // {1, 2}

		// C(4, 2) = 6 subsets of size 2
		let subsets = generate_subsets(4, 2);
		assert_eq!(subsets.len(), 6);

		// C(5, 3) = 10 subsets of size 3
		let subsets = generate_subsets(5, 3);
		assert_eq!(subsets.len(), 10);
	}

	#[test]
	fn test_resharing_state_transitions() {
		// Test that state enum variants are distinct
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

		// Just verify they compile and can be matched
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
