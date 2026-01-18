//! Signing Protocol Adapter for NEAR MPC Integration.
//!
//! This module provides `DilithiumSignProtocol`, which wraps the `ThresholdSigner`
//! in the poke/message pattern used by NEAR MPC's `run_protocol` infrastructure.
//!
//! # Overview
//!
//! The threshold signing protocol has 3 rounds:
//! 1. **Round 1 (Commitment)**: Each party generates random values and broadcasts a commitment hash
//! 2. **Round 2 (Reveal)**: Each party reveals their commitment data
//! 3. **Round 3 (Response)**: Each party computes and broadcasts their signature share
//!
//! After Round 3, the leader attempts to combine the shares into a final signature.
//! If combination fails (due to rejection sampling), the leader broadcasts a Retry
//! message and all parties reset and try again. If combination succeeds, the leader
//! broadcasts the signature to all parties.
//!
//! ## Message Buffering
//!
//! In distributed systems, messages may arrive out of order. For example, a fast
//! node might send its Round 2 message before a slower node has finished processing
//! all Round 1 messages. To handle this, we buffer messages that arrive for future
//! rounds and process them when we transition to the appropriate state.
//!
//! # Usage
//!
//! ```ignore
//! use qp_rusty_crystals_threshold::signing_protocol::{DilithiumSignProtocol, Action};
//! use qp_rusty_crystals_threshold::{ThresholdSigner, ThresholdConfig};
//!
//! // Create the protocol instance
//! let signer = ThresholdSigner::new(my_share, public_key, config)?;
//! let mut protocol = DilithiumSignProtocol::new(
//!     signer,
//!     message.to_vec(),
//!     context.to_vec(),
//!     vec![0, 1, 2],  // participating parties
//!     my_party_id,
//! );
//!
//! // Run the protocol
//! loop {
//!     match protocol.poke()? {
//!         Action::Wait => { /* wait for messages */ }
//!         Action::SendMany(data) => { /* broadcast to all participants */ }
//!         Action::Return(signature) => {
//!             // Signing complete!
//!             break;
//!         }
//!     }
//!     // When messages arrive: protocol.message(from_party_id, data);
//! }
//! ```
//!
//! # NEAR MPC Compatibility
//!
//! This protocol adapter is designed to work with NEAR MPC's `run_protocol` function.
//! The `Action` enum matches the pattern expected by cait-sith based protocols.

use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
	broadcast::{Round1Broadcast, Round2Broadcast, Round3Broadcast, Signature},
	participants::{ParticipantId, ParticipantList},
	signer::ThresholdSigner,
};

// ============================================================================
// Action Enum (matches DKG pattern)
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
	/// The protocol has completed, returning the output.
	Return(T),
}

/// Maximum number of retry attempts before giving up.
/// With high k_iterations, retries should be rare, but we still need a limit
/// to prevent infinite loops if something is fundamentally broken.
pub const MAX_RETRY_ATTEMPTS: u32 = 100;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during the signing protocol.
#[derive(Debug, Clone)]
pub enum SignProtocolError {
	/// Error during signing operations.
	SigningError(String),
	/// Error serializing or deserializing messages.
	SerializationError(String),
	/// Protocol has already completed.
	AlreadyComplete,
	/// Protocol has failed.
	ProtocolFailed(String),
	/// Invalid message received.
	InvalidMessage(String),
	/// Missing required data.
	MissingData(String),
}

impl std::fmt::Display for SignProtocolError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			SignProtocolError::SigningError(s) => write!(f, "Signing error: {}", s),
			SignProtocolError::SerializationError(s) => write!(f, "Serialization error: {}", s),
			SignProtocolError::AlreadyComplete => write!(f, "Protocol already complete"),
			SignProtocolError::ProtocolFailed(s) => write!(f, "Protocol failed: {}", s),
			SignProtocolError::InvalidMessage(s) => write!(f, "Invalid message: {}", s),
			SignProtocolError::MissingData(s) => write!(f, "Missing data: {}", s),
		}
	}
}

impl std::error::Error for SignProtocolError {}

// ============================================================================
// Message Types
// ============================================================================

/// Wrapper enum for all signing protocol messages.
/// Message types for the signing protocol.
///
/// These are serialized and sent over the network between parties.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SigningMessage {
	/// Round 1: Commitment hash.
	Round1(Round1Broadcast),
	/// Round 2: Commitment reveal.
	Round2(Round2Broadcast),
	/// Round 3: Signature response.
	Round3(Round3Broadcast),
	/// Round 4: Leader's decision - signature combination succeeded.
	Round4Complete(Vec<u8>),
	/// Round 4: Leader's decision - combination failed, retry needed.
	Round4Retry,
}

impl SigningMessage {
	/// Get the party ID of the sender (for Round 1-3 messages).
	/// Returns None for Round 4 messages (which come from leader).
	pub fn party_id(&self) -> Option<ParticipantId> {
		match self {
			SigningMessage::Round1(r) => Some(r.party_id),
			SigningMessage::Round2(r) => Some(r.party_id),
			SigningMessage::Round3(r) => Some(r.party_id),
			SigningMessage::Round4Complete(_) => None,
			SigningMessage::Round4Retry => None,
		}
	}

	/// Get the round number (1-4).
	pub fn round(&self) -> u8 {
		match self {
			SigningMessage::Round1(_) => 1,
			SigningMessage::Round2(_) => 2,
			SigningMessage::Round3(_) => 3,
			SigningMessage::Round4Complete(_) => 4,
			SigningMessage::Round4Retry => 4,
		}
	}

	/// Check if this is a Round 4 message (leader decision).
	pub fn is_round4(&self) -> bool {
		matches!(self, SigningMessage::Round4Complete(_) | SigningMessage::Round4Retry)
	}
}

// ============================================================================
// Protocol State
// ============================================================================

/// State of the signing protocol.
#[derive(Debug, Clone, PartialEq)]
pub enum SignProtocolState {
	/// Ready to generate Round 1 commitment.
	Round1Generate,
	/// Waiting for Round 1 messages from other participants.
	Round1Waiting,

	/// Ready to generate Round 2 reveal.
	Round2Generate,
	/// Waiting for Round 2 messages from other participants.
	Round2Waiting,

	/// Ready to generate Round 3 response.
	Round3Generate,
	/// Waiting for Round 3 messages from other participants.
	Round3Waiting,

	/// Leader: Ready to attempt combining and decide (Complete or Retry).
	Round4Deciding,
	/// Follower: Waiting for leader's Round 4 decision.
	WaitingForLeaderDecision,

	/// Protocol completed successfully.
	Done,
	/// Protocol failed after max retries.
	Failed(String),
}

// ============================================================================
// Protocol Implementation
// ============================================================================

/// Buffer for messages that arrive before we're ready to process them.
///
/// In distributed systems, messages may arrive out of order. For example:
/// - Node A is still in Round1Waiting (hasn't received all Round1 messages)
/// - Node B has moved to Round2 and sends its Round2 message
/// - Node A receives the Round2 message but can't process it yet
///
/// Instead of dropping these messages, we buffer them and process them
/// when we transition to the appropriate state.
#[derive(Debug, Clone, Default)]
pub struct SignMessageBuffer {
	/// Buffered Round 2 messages (from parties that are ahead of us).
	pub round2: Vec<Round2Broadcast>,
	/// Buffered Round 3 messages.
	pub round3: Vec<Round3Broadcast>,
}

impl SignMessageBuffer {
	/// Create a new empty message buffer.
	pub fn new() -> Self {
		Self { round2: Vec::new(), round3: Vec::new() }
	}

	/// Buffer a Round 2 message for later processing.
	pub fn buffer_round2(&mut self, msg: Round2Broadcast) {
		self.round2.push(msg);
	}

	/// Buffer a Round 3 message for later processing.
	pub fn buffer_round3(&mut self, msg: Round3Broadcast) {
		self.round3.push(msg);
	}

	/// Take all buffered Round 2 messages.
	pub fn take_round2(&mut self) -> Vec<Round2Broadcast> {
		std::mem::take(&mut self.round2)
	}

	/// Take all buffered Round 3 messages.
	pub fn take_round3(&mut self) -> Vec<Round3Broadcast> {
		std::mem::take(&mut self.round3)
	}

	/// Check if the buffer is empty.
	pub fn is_empty(&self) -> bool {
		self.round2.is_empty() && self.round3.is_empty()
	}

	/// Clear all buffered messages.
	pub fn clear(&mut self) {
		self.round2.clear();
		self.round3.clear();
	}
}

/// Signing protocol adapter that wraps `ThresholdSigner` in the poke/message pattern.
///
/// This struct implements the threshold signing protocol using the same
/// action-based pattern used by NEAR MPC's cait-sith protocols.
///
/// # Example
///
/// ```ignore
/// let mut protocol = DilithiumSignProtocol::new(
///     signer,
///     b"message to sign".to_vec(),
///     b"context".to_vec(),
///     vec![0, 1, 2],
///     1,  // my party id
/// );
///
/// loop {
///     match protocol.poke()? {
///         Action::Wait => { /* wait */ }
///         Action::SendMany(data) => { /* broadcast */ }
///         Action::Return(sig) => { break; }
///     }
///     // Handle incoming: protocol.message(from, data);
/// }
/// ```
pub struct DilithiumSignProtocol {
	/// The underlying threshold signer.
	signer: ThresholdSigner,
	/// Current protocol state.
	state: SignProtocolState,
	/// All participants in this signing session (with ID-to-index mapping).
	participants: ParticipantList,
	/// This party's identifier.
	my_participant_id: ParticipantId,
	/// The leader's identifier (makes combine/retry decisions).
	leader_id: ParticipantId,
	/// The message to sign.
	message: Vec<u8>,
	/// The context string for signing.
	context: Vec<u8>,

	/// Collected Round 1 broadcasts from other parties.
	r1_broadcasts: HashMap<ParticipantId, Round1Broadcast>,
	/// Collected Round 2 broadcasts from other parties.
	r2_broadcasts: HashMap<ParticipantId, Round2Broadcast>,
	/// Collected Round 3 broadcasts from other parties.
	r3_broadcasts: HashMap<ParticipantId, Round3Broadcast>,

	/// Our own Round 1 broadcast (stored for inclusion in collections).
	my_r1: Option<Round1Broadcast>,
	/// Our own Round 2 broadcast.
	my_r2: Option<Round2Broadcast>,
	/// Our own Round 3 broadcast.
	my_r3: Option<Round3Broadcast>,

	/// Buffer for messages that arrive before we're ready to process them.
	message_buffer: SignMessageBuffer,

	/// Number of retry attempts so far.
	retry_count: u32,
	/// Signature received from leader (for followers).
	received_signature: Option<Signature>,
}

impl DilithiumSignProtocol {
	/// Create a new signing protocol instance.
	///
	/// # Arguments
	///
	/// * `signer` - The threshold signer for this party
	/// * `message` - The message to sign
	/// * `context` - The context string (can be empty, max 255 bytes)
	/// * `participants` - All participant IDs in this signing session (can be arbitrary u32 values)
	/// * `my_participant_id` - This party's identifier
	/// * `leader_id` - The leader's identifier (responsible for combine/retry decisions)
	///
	/// # Panics
	///
	/// Panics if `my_participant_id` is not in `participants`, if `leader_id` is not in
	/// `participants`, or if there are duplicate IDs.
	pub fn new(
		signer: ThresholdSigner,
		message: Vec<u8>,
		context: Vec<u8>,
		participants: Vec<ParticipantId>,
		my_participant_id: ParticipantId,
		leader_id: ParticipantId,
	) -> Self {
		let participant_list =
			ParticipantList::new(&participants).expect("participants must not contain duplicates");
		assert!(
			participant_list.contains(my_participant_id),
			"my_participant_id must be in participants"
		);
		assert!(participant_list.contains(leader_id), "leader_id must be in participants");

		Self {
			signer,
			state: SignProtocolState::Round1Generate,
			participants: participant_list,
			my_participant_id,
			leader_id,
			message,
			context,
			r1_broadcasts: HashMap::new(),
			r2_broadcasts: HashMap::new(),
			r3_broadcasts: HashMap::new(),
			my_r1: None,
			my_r2: None,
			my_r3: None,
			message_buffer: SignMessageBuffer::new(),
			retry_count: 0,
			received_signature: None,
		}
	}

	/// Get the current protocol state (for debugging/monitoring).
	pub fn state(&self) -> &SignProtocolState {
		&self.state
	}

	/// Get this party's identifier.
	pub fn my_participant_id(&self) -> ParticipantId {
		self.my_participant_id
	}

	/// Get all participants.
	pub fn participants(&self) -> &ParticipantList {
		&self.participants
	}

	/// Get the leader's identifier.
	pub fn leader_id(&self) -> ParticipantId {
		self.leader_id
	}

	/// Check if this party is the leader.
	pub fn is_leader(&self) -> bool {
		self.my_participant_id == self.leader_id
	}

	/// Get the current retry count.
	pub fn retry_count(&self) -> u32 {
		self.retry_count
	}

	/// Get the number of participants required (threshold).
	fn threshold(&self) -> usize {
		self.signer.config().threshold() as usize
	}

	/// Check if we have enough Round 1 broadcasts to proceed.
	fn have_enough_r1(&self) -> bool {
		self.r1_broadcasts.len() >= self.threshold()
	}

	/// Check if we have enough Round 2 broadcasts to proceed.
	fn have_enough_r2(&self) -> bool {
		self.r2_broadcasts.len() >= self.threshold()
	}

	/// Check if we have enough Round 3 broadcasts to proceed.
	fn have_enough_r3(&self) -> bool {
		self.r3_broadcasts.len() >= self.threshold()
	}

	/// Serialize a message for network transmission.
	fn serialize_message(&self, msg: &SigningMessage) -> Result<Vec<u8>, SignProtocolError> {
		// Use a simple format: 1-byte tag + serialized content
		// Tag: 1 = Round1, 2 = Round2, 3 = Round3
		let mut result = Vec::new();

		match msg {
			SigningMessage::Round1(r1) => {
				result.push(1u8);
				result.extend_from_slice(&r1.party_id.to_le_bytes());
				result.extend_from_slice(&r1.commitment_hash);
			},
			SigningMessage::Round2(r2) => {
				result.push(2u8);
				result.extend_from_slice(&r2.party_id.to_le_bytes());
				// Length-prefix the commitment data
				let len = r2.commitment_data.len() as u32;
				result.extend_from_slice(&len.to_le_bytes());
				result.extend_from_slice(&r2.commitment_data);
			},
			SigningMessage::Round3(r3) => {
				result.push(3u8);
				result.extend_from_slice(&r3.party_id.to_le_bytes());
				// Length-prefix the response data
				let len = r3.response.len() as u32;
				result.extend_from_slice(&len.to_le_bytes());
				result.extend_from_slice(&r3.response);
			},
			SigningMessage::Round4Complete(sig_bytes) => {
				result.push(4u8);
				// Length-prefix the signature bytes
				let len = sig_bytes.len() as u32;
				result.extend_from_slice(&len.to_le_bytes());
				result.extend_from_slice(sig_bytes);
			},
			SigningMessage::Round4Retry => {
				result.push(5u8);
				// No additional data needed
			},
		}

		Ok(result)
	}

	/// Deserialize a message from network bytes.
	fn deserialize_message(&self, data: &[u8]) -> Result<SigningMessage, SignProtocolError> {
		if data.is_empty() {
			return Err(SignProtocolError::SerializationError("Empty message".to_string()));
		}

		let tag = data[0];
		let rest = &data[1..];

		match tag {
			1 => {
				// Round 1: party_id (4 bytes) + commitment_hash (32 bytes)
				if rest.len() < 36 {
					return Err(SignProtocolError::SerializationError(
						"Round 1 message too short".to_string(),
					));
				}
				let party_id = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
				let mut commitment_hash = [0u8; 32];
				commitment_hash.copy_from_slice(&rest[4..36]);
				Ok(SigningMessage::Round1(Round1Broadcast { party_id, commitment_hash }))
			},
			2 => {
				// Round 2: party_id (4 bytes) + len (4 bytes) + data
				if rest.len() < 8 {
					return Err(SignProtocolError::SerializationError(
						"Round 2 message too short".to_string(),
					));
				}
				let party_id = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
				let len = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
				if rest.len() < 8 + len {
					return Err(SignProtocolError::SerializationError(
						"Round 2 message data truncated".to_string(),
					));
				}
				let commitment_data = rest[8..8 + len].to_vec();
				Ok(SigningMessage::Round2(Round2Broadcast { party_id, commitment_data }))
			},
			3 => {
				// Round 3: party_id (4 bytes) + len (4 bytes) + data
				if rest.len() < 8 {
					return Err(SignProtocolError::SerializationError(
						"Round 3 message too short".to_string(),
					));
				}
				let party_id = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
				let len = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
				if rest.len() < 8 + len {
					return Err(SignProtocolError::SerializationError(
						"Round 3 message data truncated".to_string(),
					));
				}
				let response = rest[8..8 + len].to_vec();
				Ok(SigningMessage::Round3(Round3Broadcast { party_id, response }))
			},
			4 => {
				// Round 4 Complete: len (4 bytes) + signature bytes
				if rest.len() < 4 {
					return Err(SignProtocolError::SerializationError(
						"Round 4 Complete message too short".to_string(),
					));
				}
				let len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
				if rest.len() < 4 + len {
					return Err(SignProtocolError::SerializationError(
						"Round 4 Complete message data truncated".to_string(),
					));
				}
				let sig_bytes = rest[4..4 + len].to_vec();
				Ok(SigningMessage::Round4Complete(sig_bytes))
			},
			5 => {
				// Round 4 Retry: no additional data
				Ok(SigningMessage::Round4Retry)
			},
			_ => {
				Err(SignProtocolError::SerializationError(format!("Unknown message tag: {}", tag)))
			},
		}
	}

	/// Advance the protocol state machine.
	///
	/// This method should be called repeatedly until it returns `Action::Return`
	/// with the final signature, or returns an error.
	///
	/// # Returns
	///
	/// - `Action::Wait` - Waiting for messages from other participants
	/// - `Action::SendMany(data)` - Broadcast this data to all other participants
	/// - `Action::Return(signature)` - Protocol complete, here's the signature
	///
	/// # Errors
	///
	/// Returns an error if the protocol fails or encounters an invalid state.
	pub fn poke(&mut self) -> Result<Action<Signature>, SignProtocolError> {
		match &self.state {
			SignProtocolState::Round1Generate => {
				// Generate Round 1 commitment
				let mut rng = rand::thread_rng();
				let r1 = self
					.signer
					.round1_commit(&mut rng)
					.map_err(|e| SignProtocolError::SigningError(e.to_string()))?;

				// Store our broadcast
				self.my_r1 = Some(r1.clone());
				self.r1_broadcasts.insert(self.my_participant_id, r1.clone());

				// Serialize and prepare to send
				let msg = SigningMessage::Round1(r1);
				let data = self.serialize_message(&msg)?;

				// Transition to waiting state
				self.state = SignProtocolState::Round1Waiting;

				Ok(Action::SendMany(data))
			},

			SignProtocolState::Round1Waiting => {
				if self.have_enough_r1() {
					// Ready to proceed to Round 2
					self.state = SignProtocolState::Round2Generate;
					// Process any buffered Round 2 messages
					self.process_buffered_round2();
					self.poke()
				} else {
					Ok(Action::Wait)
				}
			},

			SignProtocolState::Round2Generate => {
				// Collect other parties' Round 1 broadcasts
				let others: Vec<Round1Broadcast> = self
					.r1_broadcasts
					.values()
					.filter(|r| r.party_id != self.signer.party_id())
					.cloned()
					.collect();

				// Generate Round 2 reveal
				let r2 = self
					.signer
					.round2_reveal(&self.message, &self.context, &others)
					.map_err(|e| SignProtocolError::SigningError(e.to_string()))?;

				// Store our broadcast
				self.my_r2 = Some(r2.clone());
				self.r2_broadcasts.insert(self.my_participant_id, r2.clone());

				// Serialize and prepare to send
				let msg = SigningMessage::Round2(r2);
				let data = self.serialize_message(&msg)?;

				// Transition to waiting state
				self.state = SignProtocolState::Round2Waiting;

				Ok(Action::SendMany(data))
			},

			SignProtocolState::Round2Waiting => {
				if self.have_enough_r2() {
					// Ready to proceed to Round 3
					self.state = SignProtocolState::Round3Generate;
					// Process any buffered Round 3 messages
					self.process_buffered_round3();
					self.poke()
				} else {
					Ok(Action::Wait)
				}
			},

			SignProtocolState::Round3Generate => {
				// Collect other parties' Round 2 broadcasts
				let others: Vec<Round2Broadcast> = self
					.r2_broadcasts
					.values()
					.filter(|r| r.party_id != self.signer.party_id())
					.cloned()
					.collect();

				// Generate Round 3 response
				let r3 = self
					.signer
					.round3_respond(&others)
					.map_err(|e| SignProtocolError::SigningError(e.to_string()))?;

				// Store our broadcast
				self.my_r3 = Some(r3.clone());
				self.r3_broadcasts.insert(self.my_participant_id, r3.clone());

				// Serialize and prepare to send
				let msg = SigningMessage::Round3(r3);
				let data = self.serialize_message(&msg)?;

				// Transition to waiting state
				self.state = SignProtocolState::Round3Waiting;

				Ok(Action::SendMany(data))
			},

			SignProtocolState::Round3Waiting => {
				if self.have_enough_r3() {
					// Ready for Round 4 decision
					if self.is_leader() {
						self.state = SignProtocolState::Round4Deciding;
					} else {
						self.state = SignProtocolState::WaitingForLeaderDecision;
					}
					self.poke()
				} else {
					Ok(Action::Wait)
				}
			},

			SignProtocolState::Round4Deciding => {
				// Leader: attempt to combine and decide
				let r2_vec: Vec<Round2Broadcast> = self.r2_broadcasts.values().cloned().collect();
				let r3_vec: Vec<Round3Broadcast> = self.r3_broadcasts.values().cloned().collect();

				// Attempt to combine
				match self.signer.combine_with_message(
					&self.message,
					&self.context,
					&r2_vec,
					&r3_vec,
				) {
					Ok(signature) => {
						// Success! Broadcast signature to all parties
						let msg = SigningMessage::Round4Complete(signature.as_bytes().to_vec());
						let data = self.serialize_message(&msg)?;
						self.state = SignProtocolState::Done;
						// Store signature for return after sending
						self.received_signature = Some(signature);
						Ok(Action::SendMany(data))
					},
					Err(_) => {
						// Combination failed - check retry limit
						self.retry_count += 1;
						if self.retry_count >= MAX_RETRY_ATTEMPTS {
							self.state = SignProtocolState::Failed(format!(
								"Signature combination failed after {} attempts",
								MAX_RETRY_ATTEMPTS
							));
							return Err(SignProtocolError::SigningError(format!(
								"Exceeded maximum retry attempts ({})",
								MAX_RETRY_ATTEMPTS
							)));
						}

						// Broadcast retry request
						let msg = SigningMessage::Round4Retry;
						let data = self.serialize_message(&msg)?;

						// Reset for next attempt
						self.reset_for_retry();

						Ok(Action::SendMany(data))
					},
				}
			},

			SignProtocolState::WaitingForLeaderDecision => {
				// Follower: check if we received leader's decision
				if let Some(signature) = self.received_signature.take() {
					self.state = SignProtocolState::Done;
					return Ok(Action::Return(signature));
				}
				// Still waiting
				Ok(Action::Wait)
			},

			SignProtocolState::Done => {
				// If we have a signature (leader after SendMany), return it
				if let Some(signature) = self.received_signature.take() {
					return Ok(Action::Return(signature));
				}
				Err(SignProtocolError::AlreadyComplete)
			},

			SignProtocolState::Failed(msg) => Err(SignProtocolError::ProtocolFailed(msg.clone())),
		}
	}

	/// Process an incoming message from another participant.
	///
	/// Messages are automatically routed to the appropriate collection
	/// based on the message type. Invalid or duplicate messages are
	/// silently ignored.
	///
	/// # Arguments
	///
	/// * `from` - The participant ID that sent the message
	/// * `data` - The serialized message bytes
	pub fn message(&mut self, from: ParticipantId, data: Vec<u8>) {
		// Don't process messages in terminal states
		if matches!(self.state, SignProtocolState::Done | SignProtocolState::Failed(_)) {
			return;
		}

		// Ignore messages from self
		if from == self.my_participant_id {
			return;
		}

		// Ignore messages from non-participants
		if !self.participants.contains(from) {
			return;
		}

		// Deserialize and route the message
		let msg = match self.deserialize_message(&data) {
			Ok(m) => m,
			Err(_) => return, // Silently ignore malformed messages
		};

		// For Round 1-3 messages, verify the claimed sender matches
		if let Some(party_id) = msg.party_id() {
			if party_id != from {
				return; // Sender mismatch, ignore
			}
		}

		// Round 4 messages must come from leader
		if msg.is_round4() && from != self.leader_id {
			return; // Only leader can send Round 4 messages
		}

		// Route to appropriate collection or buffer for later
		match msg {
			SigningMessage::Round1(r1) => {
				// Accept Round 1 messages during Round 1 waiting or earlier Round 2 states
				if matches!(
					self.state,
					SignProtocolState::Round1Generate
						| SignProtocolState::Round1Waiting
						| SignProtocolState::Round2Generate
						| SignProtocolState::Round2Waiting
				) {
					self.r1_broadcasts.entry(r1.party_id).or_insert(r1);
				}
				// Round 1 messages don't need buffering - if we're past Round 1, they're late
			},
			SigningMessage::Round2(r2) => {
				// Accept Round 2 messages during Round 2 or Round 3 states
				if matches!(
					self.state,
					SignProtocolState::Round2Generate
						| SignProtocolState::Round2Waiting
						| SignProtocolState::Round3Generate
						| SignProtocolState::Round3Waiting
				) {
					self.r2_broadcasts.entry(r2.party_id).or_insert(r2);
				} else if matches!(
					self.state,
					SignProtocolState::Round1Generate | SignProtocolState::Round1Waiting
				) {
					// Buffer Round 2 messages that arrive while we're still in Round 1
					#[cfg(debug_assertions)]
					eprintln!(
						"Buffering Round 2 message from {} (current state: {:?})",
						r2.party_id, self.state
					);
					self.message_buffer.buffer_round2(r2);
				}
			},
			SigningMessage::Round3(r3) => {
				// Accept Round 3 messages during Round 3 waiting or later
				if matches!(
					self.state,
					SignProtocolState::Round3Generate
						| SignProtocolState::Round3Waiting
						| SignProtocolState::Round4Deciding
						| SignProtocolState::WaitingForLeaderDecision
				) {
					self.r3_broadcasts.entry(r3.party_id).or_insert(r3);
				} else if matches!(
					self.state,
					SignProtocolState::Round1Generate
						| SignProtocolState::Round1Waiting
						| SignProtocolState::Round2Generate
						| SignProtocolState::Round2Waiting
				) {
					// Buffer Round 3 messages that arrive while we're still in earlier rounds
					#[cfg(debug_assertions)]
					eprintln!(
						"Buffering Round 3 message from {} (current state: {:?})",
						r3.party_id, self.state
					);
					self.message_buffer.buffer_round3(r3);
				}
			},
			SigningMessage::Round4Complete(sig_bytes) => {
				// Only followers process Round4Complete
				if !self.is_leader()
					&& matches!(self.state, SignProtocolState::WaitingForLeaderDecision)
				{
					if let Some(signature) = Signature::from_bytes(&sig_bytes) {
						self.received_signature = Some(signature);
					}
				}
			},
			SigningMessage::Round4Retry => {
				// Only followers process Round4Retry
				if !self.is_leader() {
					// Reset for retry
					self.retry_count += 1;
					if self.retry_count >= MAX_RETRY_ATTEMPTS {
						self.state = SignProtocolState::Failed(format!(
							"Exceeded maximum retry attempts ({})",
							MAX_RETRY_ATTEMPTS
						));
						return;
					}
					self.reset_for_retry();
				}
			},
		}
	}

	/// Process buffered Round 2 messages after transitioning to Round 2.
	fn process_buffered_round2(&mut self) {
		let buffered = self.message_buffer.take_round2();
		for r2 in buffered {
			// Don't overwrite if we already have a message from this party
			self.r2_broadcasts.entry(r2.party_id).or_insert(r2);
		}
	}

	/// Process buffered Round 3 messages after transitioning to Round 3.
	fn process_buffered_round3(&mut self) {
		let buffered = self.message_buffer.take_round3();
		for r3 in buffered {
			// Don't overwrite if we already have a message from this party
			self.r3_broadcasts.entry(r3.party_id).or_insert(r3);
		}
	}

	/// Reset the protocol to start a new signing session.
	///
	/// This clears all collected broadcasts and resets the state machine.
	/// The signer is also reset to allow a fresh round of signing.
	pub fn reset(&mut self) {
		self.state = SignProtocolState::Round1Generate;
		self.r1_broadcasts.clear();
		self.r2_broadcasts.clear();
		self.r3_broadcasts.clear();
		self.my_r1 = None;
		self.my_r2 = None;
		self.my_r3 = None;
		self.message_buffer.clear();
		self.retry_count = 0;
		self.received_signature = None;
		self.signer.reset();
	}

	/// Reset the protocol for a retry attempt (keeps retry count).
	///
	/// This is called when the leader decides to retry after combination failure.
	fn reset_for_retry(&mut self) {
		self.state = SignProtocolState::Round1Generate;
		self.r1_broadcasts.clear();
		self.r2_broadcasts.clear();
		self.r3_broadcasts.clear();
		self.my_r1 = None;
		self.my_r2 = None;
		self.my_r3 = None;
		self.message_buffer.clear();
		self.received_signature = None;
		self.signer.reset();
	}
}

// ============================================================================
// Helper function for running local simulations
// ============================================================================

/// Run a complete local signing protocol for testing.
///
/// This function simulates the signing protocol with all parties running locally.
/// It's useful for testing but should not be used in production where parties
/// are on separate machines.
///
/// # Arguments
///
/// * `signers` - Vector of threshold signers (one per participating party)
/// * `message` - The message to sign
/// * `context` - The context string
///
/// # Returns
///
/// The final signature on success.
///
/// # Example
///
/// ```ignore
/// use qp_rusty_crystals_threshold::signing_protocol::run_local_signing;
/// use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig, ThresholdSigner};
///
/// let config = ThresholdConfig::new(2, 3)?;
/// let (pk, shares) = generate_with_dealer(&[0u8; 32], config)?;
///
/// let signers: Vec<_> = shares.into_iter()
///     .take(2)  // Only need threshold parties
///     .map(|s| ThresholdSigner::new(s, pk.clone(), config).unwrap())
///     .collect();
///
/// let signature = run_local_signing(signers, b"message", b"context")?;
/// ```
pub fn run_local_signing(
	signers: Vec<ThresholdSigner>,
	message: &[u8],
	context: &[u8],
) -> Result<Signature, SignProtocolError> {
	run_local_signing_with_stats(signers, message, context).map(|(sig, _)| sig)
}

/// Signing result with statistics about the protocol execution.
#[derive(Debug, Clone)]
pub struct SigningStats {
	/// Number of retries that occurred during signing.
	pub retry_count: u32,
}

/// Run a complete local signing protocol for testing, returning statistics.
///
/// This function simulates the signing protocol with all parties running locally.
/// It's useful for testing but should not be used in production where parties
/// are on separate machines.
///
/// # Arguments
///
/// * `signers` - Vector of threshold signers (one per participating party)
/// * `message` - The message to sign
/// * `context` - The context string
///
/// # Returns
///
/// A tuple of (signature, stats) on success, where stats contains retry count.
///
/// # Example
///
/// ```ignore
/// use qp_rusty_crystals_threshold::signing_protocol::run_local_signing_with_stats;
/// use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig, ThresholdSigner};
///
/// let config = ThresholdConfig::new(2, 3)?;
/// let (pk, shares) = generate_with_dealer(&[0u8; 32], config)?;
///
/// let signers: Vec<_> = shares.into_iter()
///     .take(2)  // Only need threshold parties
///     .map(|s| ThresholdSigner::new(s, pk.clone(), config).unwrap())
///     .collect();
///
/// let (signature, stats) = run_local_signing_with_stats(signers, b"message", b"context")?;
/// println!("Signing completed with {} retries", stats.retry_count);
/// ```
pub fn run_local_signing_with_stats(
	signers: Vec<ThresholdSigner>,
	message: &[u8],
	context: &[u8],
) -> Result<(Signature, SigningStats), SignProtocolError> {
	let num_parties = signers.len();
	if num_parties < 2 {
		return Err(SignProtocolError::MissingData("Need at least 2 signers".to_string()));
	}

	// Get participant IDs - leader is the first (lowest) ID
	let participants: Vec<ParticipantId> = signers.iter().map(|s| s.party_id()).collect();
	let leader_id = *participants.iter().min().unwrap();

	// Create protocol instances
	let mut protocols: Vec<DilithiumSignProtocol> = signers
		.into_iter()
		.map(|signer| {
			let my_id = signer.party_id();
			DilithiumSignProtocol::new(
				signer,
				message.to_vec(),
				context.to_vec(),
				participants.clone(),
				my_id,
				leader_id,
			)
		})
		.collect();

	// Message queues: pending_messages[to] = vec of (from, data)
	let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); num_parties];

	// Run until any party completes
	let mut iterations = 0;
	const MAX_ITERATIONS: usize = 10000; // Increased for retries

	loop {
		iterations += 1;
		if iterations > MAX_ITERATIONS {
			return Err(SignProtocolError::ProtocolFailed(
				"Signing did not complete in time".to_string(),
			));
		}

		// Deliver pending messages
		for party_idx in 0..num_parties {
			let messages = std::mem::take(&mut pending_messages[party_idx]);
			for (from, data) in messages {
				protocols[party_idx].message(from, data);
			}
		}

		// Poke each party
		for party_idx in 0..num_parties {
			let my_id = protocols[party_idx].my_participant_id();

			match protocols[party_idx].poke()? {
				Action::Wait => {},
				Action::SendMany(data) => {
					// Broadcast to all other parties
					for (other_idx, other_id) in participants.iter().enumerate() {
						if *other_id != my_id {
							pending_messages[other_idx].push((my_id, data.clone()));
						}
					}
				},
				Action::Return(signature) => {
					// Get retry count from the leader (who tracks retries)
					let leader_idx =
						participants.iter().position(|&id| id == leader_id).unwrap_or(0);
					let retry_count = protocols[leader_idx].retry_count();
					let stats = SigningStats { retry_count };
					return Ok((signature, stats));
				},
			}
		}
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{generate_with_dealer, verify_signature, ThresholdConfig};

	#[test]
	fn test_protocol_creation() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let protocol = DilithiumSignProtocol::new(
			signer,
			b"test message".to_vec(),
			b"context".to_vec(),
			vec![0, 1, 2],
			0,
			0, // leader_id
		);

		assert_eq!(protocol.my_participant_id(), 0);
		assert_eq!(protocol.participants().as_slice(), &[0, 1, 2]);
		assert_eq!(protocol.leader_id(), 0);
		assert!(protocol.is_leader());
	}

	#[test]
	fn test_message_serialization_round1() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let protocol =
			DilithiumSignProtocol::new(signer, b"test".to_vec(), b"ctx".to_vec(), vec![0, 1], 0, 0);

		let r1 = Round1Broadcast::new(1, [0x42u8; 32]);
		let msg = SigningMessage::Round1(r1.clone());
		let serialized = protocol.serialize_message(&msg).unwrap();
		let deserialized = protocol.deserialize_message(&serialized).unwrap();

		match deserialized {
			SigningMessage::Round1(recovered) => {
				assert_eq!(recovered.party_id, r1.party_id);
				assert_eq!(recovered.commitment_hash, r1.commitment_hash);
			},
			_ => panic!("Wrong message type"),
		}
	}

	#[test]
	fn test_message_serialization_round2() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let protocol =
			DilithiumSignProtocol::new(signer, b"test".to_vec(), b"ctx".to_vec(), vec![0, 1], 0, 0);

		let r2 = Round2Broadcast::new(2, vec![1, 2, 3, 4, 5, 6, 7, 8]);
		let msg = SigningMessage::Round2(r2.clone());
		let serialized = protocol.serialize_message(&msg).unwrap();
		let deserialized = protocol.deserialize_message(&serialized).unwrap();

		match deserialized {
			SigningMessage::Round2(recovered) => {
				assert_eq!(recovered.party_id, r2.party_id);
				assert_eq!(recovered.commitment_data, r2.commitment_data);
			},
			_ => panic!("Wrong message type"),
		}
	}

	#[test]
	fn test_message_serialization_round3() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let protocol =
			DilithiumSignProtocol::new(signer, b"test".to_vec(), b"ctx".to_vec(), vec![0, 1], 0, 0);

		let r3 = Round3Broadcast::new(3, vec![10, 20, 30, 40, 50]);
		let msg = SigningMessage::Round3(r3.clone());
		let serialized = protocol.serialize_message(&msg).unwrap();
		let deserialized = protocol.deserialize_message(&serialized).unwrap();

		match deserialized {
			SigningMessage::Round3(recovered) => {
				assert_eq!(recovered.party_id, r3.party_id);
				assert_eq!(recovered.response, r3.response);
			},
			_ => panic!("Wrong message type"),
		}
	}

	#[test]
	fn test_local_signing_2_of_3() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let message = b"Test message for signing";
		let context = b"test-context";

		// Try multiple times due to rejection sampling
		let mut success = false;
		for _ in 0..100 {
			let signers: Vec<_> = shares
				.iter()
				.take(2)
				.map(|s| ThresholdSigner::new(s.clone(), pk.clone(), config).unwrap())
				.collect();

			match run_local_signing(signers, message, context) {
				Ok(signature) => {
					// Verify the signature
					assert!(
						verify_signature(&pk, message, context, &signature),
						"Signature should verify"
					);
					success = true;
					break;
				},
				Err(_) => continue, // Retry on rejection sampling failure
			}
		}

		assert!(success, "Signing should succeed within 100 attempts");
	}

	#[test]
	fn test_local_signing_3_of_5() {
		let config = ThresholdConfig::new(3, 5).unwrap();
		let (pk, shares) = generate_with_dealer(&[123u8; 32], config).unwrap();

		let message = b"Another test message";
		let context = b"";

		// Try multiple times due to rejection sampling
		let mut success = false;
		for _ in 0..100 {
			let signers: Vec<_> = shares
				.iter()
				.take(3)
				.map(|s| ThresholdSigner::new(s.clone(), pk.clone(), config).unwrap())
				.collect();

			match run_local_signing(signers, message, context) {
				Ok(signature) => {
					assert!(
						verify_signature(&pk, message, context, &signature),
						"Signature should verify"
					);
					success = true;
					break;
				},
				Err(_) => continue,
			}
		}

		assert!(success, "Signing should succeed within 100 attempts");
	}

	#[test]
	fn test_protocol_state_transitions() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol =
			DilithiumSignProtocol::new(signer, b"test".to_vec(), b"ctx".to_vec(), vec![0, 1], 0, 0);

		// Initially in Round1Generate
		assert_eq!(*protocol.state(), SignProtocolState::Round1Generate);

		// After first poke, should send and move to Round1Waiting
		let action = protocol.poke().unwrap();
		assert!(matches!(action, Action::SendMany(_)));
		assert_eq!(*protocol.state(), SignProtocolState::Round1Waiting);

		// Without other messages, should wait
		let action = protocol.poke().unwrap();
		assert!(matches!(action, Action::Wait));
	}

	#[test]
	fn test_protocol_reset() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol =
			DilithiumSignProtocol::new(signer, b"test".to_vec(), b"ctx".to_vec(), vec![0, 1], 0, 0);

		// Advance state
		let _ = protocol.poke().unwrap();
		assert_eq!(*protocol.state(), SignProtocolState::Round1Waiting);

		// Reset
		protocol.reset();
		assert_eq!(*protocol.state(), SignProtocolState::Round1Generate);
		assert!(protocol.r1_broadcasts.is_empty());
	}

	#[test]
	fn test_message_from_self_ignored() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol =
			DilithiumSignProtocol::new(signer, b"test".to_vec(), b"ctx".to_vec(), vec![0, 1], 0, 0);

		// Generate Round 1
		let action = protocol.poke().unwrap();
		let data = match action {
			Action::SendMany(d) => d,
			_ => panic!("Expected SendMany"),
		};

		// Try to deliver our own message (should be ignored)
		let initial_count = protocol.r1_broadcasts.len();
		protocol.message(0, data);
		assert_eq!(protocol.r1_broadcasts.len(), initial_count);
	}

	#[test]
	fn test_message_from_non_participant_ignored() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1, 2],
			0,
			0, // leader_id
		);

		// Generate Round 1
		let _ = protocol.poke().unwrap();

		// Create a message from party 99 (not a participant)
		let r1 = Round1Broadcast::new(99, [0x42u8; 32]);
		let msg = SigningMessage::Round1(r1);
		let data = protocol.serialize_message(&msg).unwrap();

		// Deliver message from non-participant (should be ignored)
		let initial_count = protocol.r1_broadcasts.len();
		protocol.message(99, data);
		assert_eq!(protocol.r1_broadcasts.len(), initial_count);
	}

	#[test]
	fn test_message_buffer_creation() {
		let buffer = SignMessageBuffer::new();
		assert!(buffer.is_empty());
		assert!(buffer.round2.is_empty());
		assert!(buffer.round3.is_empty());
	}

	#[test]
	fn test_message_buffer_round2() {
		let mut buffer = SignMessageBuffer::new();
		assert!(buffer.is_empty());

		let msg = Round2Broadcast::new(1, vec![1, 2, 3, 4]);
		buffer.buffer_round2(msg);

		assert!(!buffer.is_empty());
		assert_eq!(buffer.round2.len(), 1);

		let taken = buffer.take_round2();
		assert_eq!(taken.len(), 1);
		assert_eq!(taken[0].party_id, 1);
		assert!(buffer.is_empty());
	}

	#[test]
	fn test_message_buffer_round3() {
		let mut buffer = SignMessageBuffer::new();

		let msg = Round3Broadcast::new(2, vec![5, 6, 7, 8]);
		buffer.buffer_round3(msg);

		assert!(!buffer.is_empty());
		assert_eq!(buffer.round3.len(), 1);

		let taken = buffer.take_round3();
		assert_eq!(taken.len(), 1);
		assert_eq!(taken[0].party_id, 2);
		assert!(buffer.is_empty());
	}

	#[test]
	fn test_out_of_order_round2_buffering() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test message".to_vec(),
			b"context".to_vec(),
			vec![0, 1, 2],
			0,
			0, // leader_id
		);

		// Start Round 1 - generates and sends our Round 1 message
		let _ = protocol.poke().unwrap();
		assert!(matches!(protocol.state(), SignProtocolState::Round1Waiting));

		// Now simulate receiving a Round 2 message BEFORE we've received all Round 1 messages
		// This is what happens in distributed systems with network delays
		let r2 = Round2Broadcast::new(1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
		let msg = SigningMessage::Round2(r2);
		let data = protocol.serialize_message(&msg).unwrap();

		// Send the Round 2 message - it should be buffered, not rejected
		protocol.message(1, data);

		// Verify the message was buffered (not in r2_broadcasts yet)
		assert!(!protocol.message_buffer.round2.is_empty());
		assert_eq!(protocol.message_buffer.round2.len(), 1);
		assert_eq!(protocol.message_buffer.round2[0].party_id, 1);
		// Should NOT be in r2_broadcasts yet
		assert!(!protocol.r2_broadcasts.contains_key(&1));
	}

	#[test]
	fn test_out_of_order_round3_buffering() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test message".to_vec(),
			b"context".to_vec(),
			vec![0, 1, 2],
			0,
			0, // leader_id
		);

		// Start Round 1
		let _ = protocol.poke().unwrap();
		assert!(matches!(protocol.state(), SignProtocolState::Round1Waiting));

		// Simulate receiving a Round 3 message while still in Round 1
		let r3 = Round3Broadcast::new(2, vec![10, 20, 30, 40]);
		let msg = SigningMessage::Round3(r3);
		let data = protocol.serialize_message(&msg).unwrap();

		// Send the Round 3 message - it should be buffered
		protocol.message(2, data);

		// Verify the message was buffered
		assert!(!protocol.message_buffer.round3.is_empty());
		assert_eq!(protocol.message_buffer.round3.len(), 1);
		assert_eq!(protocol.message_buffer.round3[0].party_id, 2);
		// Should NOT be in r3_broadcasts yet
		assert!(!protocol.r3_broadcasts.contains_key(&2));
	}

	#[test]
	fn test_buffered_messages_processed_on_state_transition() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		// Create protocol for party 0
		let signer0 = ThresholdSigner::new(shares[0].clone(), pk.clone(), config).unwrap();
		let mut protocol0 = DilithiumSignProtocol::new(
			signer0,
			b"test message".to_vec(),
			b"context".to_vec(),
			vec![0, 1, 2],
			0,
			0, // leader_id
		);

		// Create protocol for party 1 (to generate valid messages)
		let signer1 = ThresholdSigner::new(shares[1].clone(), pk.clone(), config).unwrap();
		let mut protocol1 = DilithiumSignProtocol::new(
			signer1,
			b"test message".to_vec(),
			b"context".to_vec(),
			vec![0, 1, 2],
			1,
			0, // leader_id
		);

		// Start both protocols - generate Round 1
		let r1_data0 = match protocol0.poke().unwrap() {
			Action::SendMany(d) => d,
			_ => panic!("Expected SendMany"),
		};
		let r1_data1 = match protocol1.poke().unwrap() {
			Action::SendMany(d) => d,
			_ => panic!("Expected SendMany"),
		};

		// Party 1 receives Round 1 from party 0 and advances
		protocol1.message(0, r1_data0.clone());

		// Create a fake Round 1 from party 2
		let r1_party2 = Round1Broadcast::new(2, [0x42u8; 32]);
		let r1_msg2 = SigningMessage::Round1(r1_party2);
		let r1_data2 = protocol1.serialize_message(&r1_msg2).unwrap();
		protocol1.message(2, r1_data2.clone());

		// Party 1 should now advance to Round 2
		let r2_data1 = match protocol1.poke().unwrap() {
			Action::SendMany(d) => d,
			_ => panic!("Expected SendMany for Round 2"),
		};

		// Now party 0 receives the Round 2 message from party 1 BEFORE completing Round 1
		// This should be buffered
		protocol0.message(1, r2_data1);
		assert!(!protocol0.message_buffer.round2.is_empty());
		assert!(!protocol0.r2_broadcasts.contains_key(&1));

		// Now party 0 receives the remaining Round 1 messages
		protocol0.message(1, r1_data1);
		protocol0.message(2, r1_data2);

		// Party 0 should now advance to Round 2 and process the buffered Round 2 message
		let _ = protocol0.poke().unwrap();

		// The buffered message should have been processed
		assert!(protocol0.message_buffer.round2.is_empty());
		// And the Round 2 message from party 1 should now be in r2_broadcasts
		assert!(protocol0.r2_broadcasts.contains_key(&1));
	}

	#[test]
	fn test_protocol_reset_clears_buffer() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1, 2],
			0,
			0,
		);

		// Start Round 1
		let _ = protocol.poke().unwrap();

		// Buffer some messages
		let r2 = Round2Broadcast::new(1, vec![1, 2, 3, 4]);
		let msg = SigningMessage::Round2(r2);
		let data = protocol.serialize_message(&msg).unwrap();
		protocol.message(1, data);

		assert!(!protocol.message_buffer.is_empty());

		// Reset should clear the buffer
		protocol.reset();
		assert!(protocol.message_buffer.is_empty());
	}
}
