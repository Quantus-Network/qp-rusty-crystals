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
//! If combination fails (due to rejection sampling), the leader broadcasts an `Abort`
//! by returning `SignProtocolError::ProtocolFailed`; the caller (e.g. NEAR MPC) is
//! expected to retry by constructing a fresh `DilithiumSignProtocol` instance with a
//! new round1 seed and a new transport channel. If combination succeeds, the leader
//! broadcasts the signature to all parties.
//!
//! # Session Isolation (Caller Responsibility)
//!
//! This protocol does **not** include cryptographic session identifiers. Instead, session
//! isolation is the caller's responsibility:
//!
//! - **Fresh randomness**: Each signing attempt MUST use a fresh `round1_seed`
//! - **Transport isolation**: Messages from different sessions must not be mixed (e.g., via
//!   ChannelId)
//! - **No instance reuse**: Create a new `DilithiumSignProtocol` for each signing attempt
//!
//! NEAR MPC satisfies these requirements by generating `round1_seed` via `rand::random()` and
//! using unique `ChannelId`s per attempt.
//!
//! # No in-protocol retries
//!
//! Earlier revisions of this protocol included a `Round4Retry` message that allowed
//! the leader to silently reset all followers and re-run rounds 1-3 on the same
//! protocol instance. That was removed because:
//!
//! 1. Threshold signatures are defined *without* session identifiers, relying on each honest
//!    party's local state to enforce per-attempt freshness. In-protocol retries on a single
//!    instance violate that assumption because the receiver's state machine has no way to bind
//!    incoming rounds to "the current attempt" without an explicit session id, which the wire
//!    format does not carry.
//! 2. NEAR MPC already drives retries externally by allocating a fresh `ChannelId`, a fresh
//!    `round1_seed`, and a fresh `DilithiumSignProtocol` per attempt (up to
//!    `MAX_ATTEMPTS_PER_REQUEST_AS_LEADER`). Stale messages from a previous attempt are silently
//!    dropped at the transport layer because their `ChannelId` no longer routes anywhere.
//! 3. Keeping in-protocol retries on a stable `ChannelId` was the root cause of an audited replay
//!    vulnerability: replayed round 1/2 traffic from an earlier attempt could be `or_insert`ed into
//!    the current attempt's broadcast maps and later consumed as if it belonged to the live
//!    session, or a replayed `Round4Retry` could force followers to reset and exhaust the retry
//!    budget.
//!
//! # Participant Set Requirement
//!
//! **IMPORTANT**: The threshold signing scheme requires **exactly T (threshold) active
//! participants** to sign. This is a fundamental design limitation of the replicated secret
//! sharing (RSS) scheme (see `RSSRecover` algorithm).
//!
//! - Signing with **fewer than T** parties will fail (cannot reconstruct the secret).
//! - Signing with **more than T** parties is **not supported** and will be rejected. The
//!   `compute_sharing_patterns(T, parties)` function returns exactly T entries, so additional
//!   parties would have no valid sharing pattern assignment.
//!
//! The leader should pre-select exactly T participants from the available nodes before
//! starting the signing protocol.
//!
//! # Trust Model
//!
//! The protocol uses a leader-based approach for Round 4 (signature combination):
//!
//! - The **leader** (party with lowest ID among participants) combines signature shares. On success
//!   it broadcasts `Round4Complete(signature)`; on failure it returns
//!   `SignProtocolError::ProtocolFailed`, ending the protocol instance. The caller is responsible
//!   for starting a fresh attempt with new randomness.
//! - **Followers** verify the leader's signature before accepting it. This removes the leader trust
//!   assumption for signature validity (a malicious leader cannot send a forged signature).
//!
//! **Security properties:**
//! - A malicious leader cannot forge signatures (requires threshold parties to collude).
//! - A malicious leader cannot send invalid signatures (followers verify before accepting).
//! - A malicious leader CAN cause denial-of-signature by aborting; in that case the caller (e.g.
//!   NEAR MPC) will retry with a fresh protocol instance, potentially with a different leader
//!   selected by the application layer.
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
//! let round1_seed: [u8; 32] = get_random_seed(); // Must be cryptographically random
//! let mut protocol = DilithiumSignProtocol::new(
//!     signer,
//!     message.to_vec(),
//!     context.to_vec(),
//!     vec![0, 1, 2],  // participating parties
//!     my_party_id,
//!     leader_id,
//!     round1_seed,
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

use alloc::{
	collections::BTreeMap,
	format,
	string::{String, ToString},
	vec,
	vec::Vec,
};
use core::{fmt, mem};

use borsh::{BorshDeserialize, BorshSerialize};
use log::warn;
use qp_rusty_crystals_dilithium::{fips202, ml_dsa_87::MAX_MESSAGE_SIZE};
use zeroize::Zeroize;

use crate::{
	broadcast::{Round1Broadcast, Round2Broadcast, Round3Broadcast, Signature, SSID_SIZE},
	participants::{ParticipantId, ParticipantList},
	protocol::signing::compute_ssid,
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

/// Maximum signing message size in bytes (12 MiB).
/// This limits the size of serialized signing protocol messages. It must exceed the largest
/// per-round payload, which is the Round 2 commitment broadcast: k_iterations × (k × POLY_Q_SIZE).
/// The 4-of-6 resharing-hardened config uses k=1600, giving a ~9.42 MB commitment broadcast, so the
/// 4 MiB limit no longer fits; 12 MiB leaves headroom above `MAX_COMMITMENT_DATA_SIZE`.
/// near-mpc's transport frames up to 100 MiB (`MAX_MESSAGE_SIZE_BYTES`), so this is well within the
/// network layer's budget.
pub const MAX_SIGNING_MESSAGE_SIZE: usize = 12 * 1024 * 1024;

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
	/// Malformed message received from a party.
	///
	/// This indicates a participant sent data that could not be deserialized.
	/// This could indicate a bug, network corruption, or malicious behavior.
	MalformedMessage {
		/// Party ID that sent the malformed message.
		from: u32,
		/// Reason for the failure.
		reason: String,
	},
	/// Invalid configuration provided to protocol constructor.
	InvalidConfig(String),
}

impl fmt::Display for SignProtocolError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			SignProtocolError::SigningError(s) => write!(f, "Signing error: {}", s),
			SignProtocolError::SerializationError(s) => write!(f, "Serialization error: {}", s),
			SignProtocolError::AlreadyComplete => write!(f, "Protocol already complete"),
			SignProtocolError::ProtocolFailed(s) => write!(f, "Protocol failed: {}", s),
			SignProtocolError::InvalidMessage(s) => write!(f, "Invalid message: {}", s),
			SignProtocolError::MissingData(s) => write!(f, "Missing data: {}", s),
			SignProtocolError::MalformedMessage { from, reason } => {
				write!(f, "Malformed message from party {}: {}", from, reason)
			},
			SignProtocolError::InvalidConfig(s) => write!(f, "Invalid configuration: {}", s),
		}
	}
}

// ============================================================================
// Message Types
// ============================================================================

/// Round 4 broadcast message: signature from leader.
///
/// In Round 4, the leader broadcasts the combined signature to all parties.
///
/// # Security
///
/// The SSID binds this message to the current signing session, preventing
/// a malicious leader from replaying a valid signature from a previous session.
/// Followers MUST verify both the SSID and the signature itself.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Round4Broadcast {
	/// Session identifier binding this message to a specific signing session.
	pub ssid: [u8; SSID_SIZE],
	/// The combined signature. Using the exact-size [`Signature`] type (rather
	/// than a raw `Vec<u8>`) bounds deserialization to exactly `SIGNATURE_SIZE`
	/// bytes, so a malformed Round 4 message cannot advertise an oversized
	/// signature payload before the SSID/leader checks run.
	pub signature: Signature,
}

impl Round4Broadcast {
	/// Create a new Round 4 broadcast.
	pub fn new(ssid: [u8; SSID_SIZE], signature: Signature) -> Self {
		Self { ssid, signature }
	}
}

/// Message types for the signing protocol.
///
/// These are serialized and sent over the network between parties.
///
/// # Session Identifier (SSID)
///
/// All messages include a session identifier (SSID) that binds the message to
/// a specific signing session. This prevents cross-session replay attacks where
/// an attacker could reuse messages from a previous session. Receivers MUST
/// verify that the SSID matches their expected value before processing.
///
/// # Replay safety
///
/// Per-message integrity within an attempt is enforced by:
///
/// - All messages contain an SSID that is verified against the expected value.
/// - A receiver only accepts `Round2` from peer `P` when it has already accepted a `Round1`
///   broadcast from `P` in the same instance, and the round-2 reveal hashes back to the round-1
///   commitment hash (see `message()`).
/// - A receiver only accepts `Round3` from peer `P` when it has accepted that peer's `Round2`
///   reveal, which was itself bound to the peer's `Round1` commitment.
/// - `Round4Complete` is verified by the follower against the public key, message, context, and
///   SSID for the current instance before being accepted as the output.
///
/// There is no `Round4Retry`: combination failure is a hard error and a fresh
/// instance must be constructed for any retry. See the module-level docs.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum SigningMessage {
	/// Round 1: Commitment hash.
	Round1(Round1Broadcast),
	/// Round 2: Commitment reveal.
	Round2(Round2Broadcast),
	/// Round 3: Signature response.
	Round3(Round3Broadcast),
	/// Round 4: Leader's decision - signature combination succeeded.
	Round4Complete(Round4Broadcast),
}

impl SigningMessage {
	/// Get the session identifier (SSID) from the message.
	pub fn ssid(&self) -> &[u8; SSID_SIZE] {
		match self {
			SigningMessage::Round1(r) => &r.ssid,
			SigningMessage::Round2(r) => &r.ssid,
			SigningMessage::Round3(r) => &r.ssid,
			SigningMessage::Round4Complete(r) => &r.ssid,
		}
	}

	/// Get the party ID of the sender (for Round 1-3 messages).
	/// Returns None for Round 4 messages (which come from leader).
	pub fn party_id(&self) -> Option<ParticipantId> {
		match self {
			SigningMessage::Round1(r) => Some(r.party_id),
			SigningMessage::Round2(r) => Some(r.party_id),
			SigningMessage::Round3(r) => Some(r.party_id),
			SigningMessage::Round4Complete(_) => None,
		}
	}

	/// Get the round number (1-4).
	pub fn round(&self) -> u8 {
		match self {
			SigningMessage::Round1(_) => 1,
			SigningMessage::Round2(_) => 2,
			SigningMessage::Round3(_) => 3,
			SigningMessage::Round4Complete(_) => 4,
		}
	}

	/// Check if this is a Round 4 message (leader decision).
	pub fn is_round4(&self) -> bool {
		matches!(self, SigningMessage::Round4Complete(_))
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

	/// Leader: Ready to attempt combining the signature shares.
	/// On success the leader broadcasts `Round4Complete`; on failure the protocol
	/// transitions to `Failed` and the caller must spawn a fresh instance to retry.
	Round4Deciding,
	/// Follower: Waiting for leader's Round 4 decision.
	WaitingForLeaderDecision,

	/// Protocol completed successfully.
	Done,
	/// Protocol failed.
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
///
/// # Security
///
/// The buffer uses `BTreeMap` keyed by party_id to:
/// 1. **Deduplicate**: Only one message per party is stored (later messages ignored)
/// 2. **Bound memory**: At most MAX_PARTIES entries per round
///
/// Round4Complete is buffered separately since only the leader sends it and followers
/// may receive it before transitioning to `WaitingForLeaderDecision` state.
#[derive(Debug, Clone, Default)]
pub struct SignMessageBuffer {
	/// Buffered Round 2 messages, keyed by party_id.
	round2: BTreeMap<ParticipantId, Round2Broadcast>,
	/// Buffered Round 3 messages, keyed by party_id.
	round3: BTreeMap<ParticipantId, Round3Broadcast>,
	/// Buffered Round4Complete from the leader.
	/// Only one is stored (first arrival); subsequent ones are ignored.
	round4_complete: Option<Round4Broadcast>,
}

impl SignMessageBuffer {
	/// Create a new empty message buffer.
	pub fn new() -> Self {
		Self { round2: BTreeMap::new(), round3: BTreeMap::new(), round4_complete: None }
	}

	/// Buffer a Round 2 message for later processing.
	/// Only the first message from each party is stored; duplicates are ignored.
	pub fn buffer_round2(&mut self, msg: Round2Broadcast) {
		self.round2.entry(msg.party_id).or_insert(msg);
	}

	/// Buffer a Round 3 message for later processing.
	/// Only the first message from each party is stored; duplicates are ignored.
	pub fn buffer_round3(&mut self, msg: Round3Broadcast) {
		self.round3.entry(msg.party_id).or_insert(msg);
	}

	/// Buffer a Round4Complete for later processing.
	/// Only the first one is stored; subsequent ones are ignored.
	pub fn buffer_round4_complete(&mut self, msg: Round4Broadcast) {
		if self.round4_complete.is_none() {
			self.round4_complete = Some(msg);
		}
	}

	/// Take all buffered Round 2 messages.
	pub fn take_round2(&mut self) -> Vec<Round2Broadcast> {
		mem::take(&mut self.round2).into_values().collect()
	}

	/// Take all buffered Round 3 messages.
	pub fn take_round3(&mut self) -> Vec<Round3Broadcast> {
		mem::take(&mut self.round3).into_values().collect()
	}

	/// Take the buffered Round4Complete, if any.
	pub fn take_round4_complete(&mut self) -> Option<Round4Broadcast> {
		self.round4_complete.take()
	}

	/// Check if the buffer is empty.
	pub fn is_empty(&self) -> bool {
		self.round2.is_empty() && self.round3.is_empty() && self.round4_complete.is_none()
	}

	/// Clear all buffered messages.
	pub fn clear(&mut self) {
		self.round2.clear();
		self.round3.clear();
		self.round4_complete = None;
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
/// let round1_seed: [u8; 32] = get_random_seed(); // Must be cryptographically random
/// let mut protocol = DilithiumSignProtocol::new(
///     signer,
///     b"message to sign".to_vec(),
///     b"context".to_vec(),
///     vec![0, 1, 2],
///     1,  // my party id
///     0,  // leader id
///     round1_seed,
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
	/// Random seed for Round 1 commitment (32 bytes, cryptographically random).
	round1_seed: [u8; 32],
	/// Session identifier binding all protocol messages to this signing session.
	ssid: [u8; SSID_SIZE],

	/// Collected Round 1 broadcasts from other parties.
	r1_broadcasts: BTreeMap<ParticipantId, Round1Broadcast>,
	/// Collected Round 2 broadcasts from other parties.
	r2_broadcasts: BTreeMap<ParticipantId, Round2Broadcast>,
	/// Collected Round 3 broadcasts from other parties.
	r3_broadcasts: BTreeMap<ParticipantId, Round3Broadcast>,

	/// Our own Round 1 broadcast (stored for inclusion in collections).
	my_r1: Option<Round1Broadcast>,
	/// Our own Round 2 broadcast.
	my_r2: Option<Round2Broadcast>,
	/// Our own Round 3 broadcast.
	my_r3: Option<Round3Broadcast>,

	/// Buffer for messages that arrive before we're ready to process them.
	message_buffer: SignMessageBuffer,

	/// Signature received from leader (for followers).
	received_signature: Option<Signature>,
}

impl Drop for DilithiumSignProtocol {
	fn drop(&mut self) {
		// Zeroize the round1_seed which is the key-leaking secret if exposed
		self.round1_seed.zeroize();
	}
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
	/// * `round1_seed` - A 32-byte cryptographically random seed for Round 1
	/// * `attempt_nonce` - A 32-byte nonce unique to this signing attempt (must be agreed upon by
	///   all participants, e.g., derived from the transport layer's session/channel ID)
	///
	/// # Errors
	///
	/// Returns `Err(SignProtocolError::InvalidConfig)` if:
	/// - `participants` contains duplicates
	/// - `my_participant_id` is not in `participants`
	/// - `leader_id` is not in `participants`
	/// - Any participant is not in the original DKG participant set
	///
	/// # Security Warning
	///
	/// - The `round1_seed` MUST be generated from a cryptographically secure source and MUST be
	///   unique for each signing session. Reusing seeds compromises security.
	/// - The `attempt_nonce` MUST be agreed upon by all participants BEFORE the protocol starts.
	///   Using different nonces will cause SSID mismatch and message rejection.
	pub fn new(
		signer: ThresholdSigner,
		message: Vec<u8>,
		context: Vec<u8>,
		participants: Vec<ParticipantId>,
		my_participant_id: ParticipantId,
		leader_id: ParticipantId,
		round1_seed: [u8; 32],
		attempt_nonce: [u8; 32],
	) -> Result<Self, SignProtocolError> {
		let participant_list = ParticipantList::new(&participants).ok_or_else(|| {
			SignProtocolError::InvalidConfig("participants contains duplicates".to_string())
		})?;

		if !participant_list.contains(my_participant_id) {
			return Err(SignProtocolError::InvalidConfig(
				"my_participant_id is not in participants".to_string(),
			));
		}

		if !participant_list.contains(leader_id) {
			return Err(SignProtocolError::InvalidConfig(
				"leader_id is not in participants".to_string(),
			));
		}

		// Validate all signing participants are valid DKG participants
		let dkg_participants = signer.dkg_participants();
		for &participant in &participants {
			if !dkg_participants.contains(participant) {
				return Err(SignProtocolError::InvalidConfig(format!(
					"signing participant {} is not in the DKG participant set (act ⊆ [N] violated)",
					participant
				)));
			}
		}

		// Validate exactly threshold participants.
		// The RSS scheme (RSSRecover algorithm) assumes exactly T active parties.
		// The sharing patterns computed by `compute_sharing_patterns(T, parties)`
		// return exactly T entries, so more than T active parties would cause index-out-of-bounds
		// errors in `recover_share`. Fewer than T parties cannot reconstruct the secret.
		let threshold = signer.config().threshold() as usize;
		if participants.len() != threshold {
			return Err(SignProtocolError::InvalidConfig(format!(
				"Threshold signing requires exactly {} (threshold) active participants, but {} were provided. \
				The scheme does not support more or fewer than threshold parties.",
				threshold,
				participants.len()
			)));
		}

		// Validate message size against ML-DSA limit.
		// Dilithium verification rejects messages larger than MAX_MESSAGE_SIZE, so rejecting
		// early prevents wasted threshold work on inputs the verifier will never accept.
		if message.len() > MAX_MESSAGE_SIZE {
			return Err(SignProtocolError::InvalidConfig(format!(
				"message size {} exceeds ML-DSA limit of {} bytes",
				message.len(),
				MAX_MESSAGE_SIZE
			)));
		}

		// Validate context size (ML-DSA limit is 255 bytes).
		if context.len() > 255 {
			return Err(SignProtocolError::InvalidConfig(format!(
				"context size {} exceeds ML-DSA limit of 255 bytes",
				context.len()
			)));
		}

		// Compute session identifier (SSID) that binds all messages to this session
		let ssid = compute_ssid(
			signer.public_key(),
			signer.config().threshold(),
			signer.config().total_parties(),
			&participant_list,
			&message,
			&context,
			&attempt_nonce,
		);

		Ok(Self {
			signer,
			state: SignProtocolState::Round1Generate,
			participants: participant_list,
			my_participant_id,
			leader_id,
			message,
			context,
			round1_seed,
			ssid,
			r1_broadcasts: BTreeMap::new(),
			r2_broadcasts: BTreeMap::new(),
			r3_broadcasts: BTreeMap::new(),
			my_r1: None,
			my_r2: None,
			my_r3: None,
			message_buffer: SignMessageBuffer::new(),
			received_signature: None,
		})
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

	/// Get the session identifier (SSID) for this protocol instance.
	///
	/// The SSID uniquely identifies this signing session and is included in all
	/// broadcast messages to prevent cross-session replay attacks.
	pub fn ssid(&self) -> &[u8; SSID_SIZE] {
		&self.ssid
	}

	/// Check if this party is the leader.
	pub fn is_leader(&self) -> bool {
		self.my_participant_id == self.leader_id
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

	// ========================================================================
	// Party status helpers
	// ========================================================================

	/// Get the list of parties we are currently waiting for.
	///
	/// Returns the party IDs that have not yet sent their message for the
	/// current round. Applications can use this for monitoring/debugging.
	///
	/// # Note on Participant Set
	///
	/// The threshold signing protocol assumes a **fixed participant set**
	/// that is agreed upon before the protocol starts. The recommended approach
	/// (used by NEAR MPC) is for the leader to pre-select exactly `threshold`
	/// currently-alive participants and broadcast this list to all parties.
	/// All parties then use this pre-agreed list.
	///
	/// This avoids consensus issues that would arise from mid-protocol party
	/// removal (different parties might have different views of who is active).
	pub fn waiting_for(&self) -> Vec<ParticipantId> {
		let all_others: Vec<ParticipantId> =
			self.participants.iter().filter(|&id| id != self.my_participant_id).collect();

		match &self.state {
			SignProtocolState::Round1Waiting => all_others
				.into_iter()
				.filter(|id| !self.r1_broadcasts.contains_key(id))
				.collect(),
			SignProtocolState::Round2Waiting => all_others
				.into_iter()
				.filter(|id| !self.r2_broadcasts.contains_key(id))
				.collect(),
			SignProtocolState::Round3Waiting => all_others
				.into_iter()
				.filter(|id| !self.r3_broadcasts.contains_key(id))
				.collect(),
			SignProtocolState::WaitingForLeaderDecision => {
				// Waiting for leader only
				if self.received_signature.is_none() {
					vec![self.leader_id]
				} else {
					vec![]
				}
			},
			_ => vec![], // Not in a waiting state
		}
	}

	/// Serialize a message for network transmission.
	fn serialize_message(&self, msg: &SigningMessage) -> Result<Vec<u8>, SignProtocolError> {
		borsh::to_vec(msg).map_err(|e| SignProtocolError::SerializationError(e.to_string()))
	}

	/// Deserialize a message from network bytes.
	fn deserialize_message(&self, data: &[u8]) -> Result<SigningMessage, SignProtocolError> {
		if data.is_empty() {
			return Err(SignProtocolError::SerializationError("Empty message".to_string()));
		}

		// Reject oversized messages before any parsing to prevent resource exhaustion
		if data.len() > MAX_SIGNING_MESSAGE_SIZE {
			return Err(SignProtocolError::SerializationError(format!(
				"Message size {} exceeds maximum {}",
				data.len(),
				MAX_SIGNING_MESSAGE_SIZE
			)));
		}

		borsh::from_slice(data).map_err(|e| SignProtocolError::SerializationError(e.to_string()))
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
				// Generate Round 1 commitment using the round1 seed for this instance.
				// Per-attempt seed freshness is the caller's responsibility: every new
				// DilithiumSignProtocol instance is expected to receive a fresh seed.
				let r1 = self
					.signer
					.round1_commit_with_seed(&self.ssid, &self.round1_seed)
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
					.round2_reveal(&self.ssid, &self.message, &self.context, &others)
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
				// Collect other parties' Round 1 broadcasts (for commitment verification)
				let others_r1: Vec<Round1Broadcast> = self
					.r1_broadcasts
					.values()
					.filter(|r| r.party_id != self.signer.party_id())
					.cloned()
					.collect();

				// Collect other parties' Round 2 broadcasts
				let others_r2: Vec<Round2Broadcast> = self
					.r2_broadcasts
					.values()
					.filter(|r| r.party_id != self.signer.party_id())
					.cloned()
					.collect();

				// Generate Round 3 response
				let r3 = self
					.signer
					.round3_respond(&self.ssid, &others_r1, &others_r2)
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
						// Process any Round4Complete that arrived before we were ready
						self.process_buffered_round4_complete();
					}
					self.poke()
				} else {
					Ok(Action::Wait)
				}
			},

			SignProtocolState::Round4Deciding => {
				// Leader: attempt to combine the signature shares.
				//
				// On success: broadcast Round4Complete and return the signature.
				// On failure: this protocol instance is dead. The caller must spawn
				// a fresh DilithiumSignProtocol with new randomness to retry.
				// Rejection sampling failures are normal in ML-DSA and are handled
				// by the application layer (e.g. NEAR MPC re-spawns with a new
				// ChannelId and round1_seed).
				let r2_vec: Vec<Round2Broadcast> = self.r2_broadcasts.values().cloned().collect();
				let r3_vec: Vec<Round3Broadcast> = self.r3_broadcasts.values().cloned().collect();

				match self.signer.combine(&r2_vec, &r3_vec) {
					Ok(signature) => {
						// Success! Broadcast signature to all parties
						let r4 = Round4Broadcast { ssid: self.ssid, signature: signature.clone() };
						let msg = SigningMessage::Round4Complete(r4);
						let data = self.serialize_message(&msg)?;
						self.state = SignProtocolState::Done;
						// Store signature for return after sending
						self.received_signature = Some(signature);
						Ok(Action::SendMany(data))
					},
					Err(e) => {
						// Combination failed (most commonly: ML-DSA rejection sampling
						// did not produce a valid signature this attempt). Terminate
						// this instance; the caller will retry with a fresh one.
						let msg = format!("Signature combination failed: {}", e);
						self.state = SignProtocolState::Failed(msg.clone());
						Err(SignProtocolError::SigningError(msg))
					},
				}
			},

			SignProtocolState::WaitingForLeaderDecision => {
				// Follower: check if we received leader's decision
				if let Some(signature) = self.received_signature.take() {
					// Verify the signature before accepting it
					let public_key = self.signer.public_key();
					if crate::verify_signature(public_key, &self.message, &self.context, &signature)
					{
						self.state = SignProtocolState::Done;
						return Ok(Action::Return(signature));
					} else {
						// Leader sent an invalid signature - this is a protocol failure
						self.state =
							SignProtocolState::Failed("Leader sent invalid signature".to_string());
						return Err(SignProtocolError::ProtocolFailed(
							"Leader sent invalid signature".to_string(),
						));
					}
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
	/// based on the message type. Messages from self, non-participants,
	/// or in terminal states are ignored with `Ok(())`.
	///
	/// # Arguments
	///
	/// * `from` - The participant ID that sent the message
	/// * `data` - The serialized message bytes
	///
	/// # Errors
	///
	/// Returns `Err(SignProtocolError::MalformedMessage)` if the message
	/// cannot be deserialized. This allows callers to detect and log
	/// malformed messages from participants.
	///
	/// # Returns
	///
	/// * `Ok(())` - Message was processed (or legitimately ignored)
	/// * `Err(_)` - Message was malformed and could not be deserialized
	pub fn message(&mut self, from: ParticipantId, data: Vec<u8>) -> Result<(), SignProtocolError> {
		// Don't process messages in terminal states
		if matches!(self.state, SignProtocolState::Done | SignProtocolState::Failed(_)) {
			return Ok(());
		}

		// Ignore messages from self
		if from == self.my_participant_id {
			return Ok(());
		}

		// Ignore messages from non-participants
		if !self.participants.contains(from) {
			warn!(
				"Signing: Ignoring message from non-participant {} (not in {:?})",
				from,
				self.participants.iter().collect::<Vec<_>>()
			);
			return Ok(());
		}

		// Deserialize and route the message
		let msg = match self.deserialize_message(&data) {
			Ok(m) => m,
			Err(e) => {
				return Err(SignProtocolError::MalformedMessage { from, reason: e.to_string() });
			},
		};

		// Verify SSID matches for all message types
		let msg_ssid = msg.ssid();
		if *msg_ssid != self.ssid {
			warn!(
				"Signing: Rejecting message from {} - SSID mismatch (cross-session replay attempt?)",
				from
			);
			return Ok(()); // SSID mismatch, ignore (not an error, likely cross-session replay)
		}

		// For Round 1-3 messages, verify the claimed sender matches
		if let Some(party_id) = msg.party_id() {
			if party_id != from {
				warn!(
					"Signing: Sender mismatch: envelope from {} but message claims party {}",
					from, party_id
				);
				return Ok(()); // Sender mismatch, ignore (not an error, just a bad actor)
			}
		}

		// Round 4 messages must come from leader
		if msg.is_round4() && from != self.leader_id {
			warn!(
				"Signing: Round 4 message from non-leader {} (leader is {})",
				from, self.leader_id
			);
			return Ok(()); // Only leader can send Round 4 messages
		}

		// Route to appropriate collection or buffer for later
		match msg {
			SigningMessage::Round1(r1) => {
				// Accept Round 1 messages during Round 1 waiting or earlier Round 2 states.
				// First-wins is safe here because Round 2 acceptance below requires the
				// Round 2 reveal to hash back to this Round 1 commitment; a replayed or
				// junk Round 1 will simply have no matching Round 2 and the session will
				// eventually time out and be retried by the application layer.
				if matches!(
					self.state,
					SignProtocolState::Round1Generate |
						SignProtocolState::Round1Waiting |
						SignProtocolState::Round2Generate |
						SignProtocolState::Round2Waiting
				) {
					self.r1_broadcasts.entry(r1.party_id).or_insert(r1);
				}
				// Round 1 messages don't need buffering - if we're past Round 1, they're late
			},
			SigningMessage::Round2(r2) => {
				// Per the threshold signing protocol, Round 2 reveals must hash
				// back to the Round 1 commitment from the same party. We enforce that
				// check at receive time (rather than only later in round3_respond) so
				// that a replayed or otherwise-stale Round 2 cannot occupy the slot for
				// peer `r2.party_id` in `r2_broadcasts` and lock out the honest reveal.
				//
				// If the corresponding Round 1 has not been received yet, we buffer the
				// Round 2 and re-verify when it's processed by process_buffered_round2.
				if matches!(
					self.state,
					SignProtocolState::Round2Generate |
						SignProtocolState::Round2Waiting |
						SignProtocolState::Round3Generate |
						SignProtocolState::Round3Waiting
				) {
					if !self.round2_matches_stored_round1(&r2) {
						warn!(
							"Signing: Rejecting Round 2 from party {} - commitment hash does not \
							 match stored Round 1 (likely stale/replayed)",
							r2.party_id
						);
						return Ok(());
					}
					self.r2_broadcasts.entry(r2.party_id).or_insert(r2);
				} else if matches!(
					self.state,
					SignProtocolState::Round1Generate | SignProtocolState::Round1Waiting
				) {
					// Buffer Round 2 messages that arrive while we're still in Round 1.
					// The commitment-hash check is deferred to process_buffered_round2,
					// which runs after we transition to Round 2 and the corresponding
					// Round 1 broadcasts are available.
					self.message_buffer.buffer_round2(r2);
				}
			},
			SigningMessage::Round3(r3) => {
				// Accept Round 3 messages during Round 3 waiting or later.
				// The Round 3 response is implicitly bound to the same attempt's Round 1
				// and Round 2 because it's verified during combine() against
				// the aggregated commitments (which only validate if r3 was computed
				// from the same c = SampleInBall(H(mu || HighBits(w))) the honest party
				// derived from the now-fixed r2_broadcasts in this instance).
				if matches!(
					self.state,
					SignProtocolState::Round3Generate |
						SignProtocolState::Round3Waiting |
						SignProtocolState::Round4Deciding |
						SignProtocolState::WaitingForLeaderDecision
				) {
					self.r3_broadcasts.entry(r3.party_id).or_insert(r3);
				} else if matches!(
					self.state,
					SignProtocolState::Round1Generate |
						SignProtocolState::Round1Waiting |
						SignProtocolState::Round2Generate |
						SignProtocolState::Round2Waiting
				) {
					// Buffer Round 3 messages that arrive while we're still in earlier rounds
					self.message_buffer.buffer_round3(r3);
				}
			},
			SigningMessage::Round4Complete(r4) => {
				// Only followers process Round4Complete
				if self.is_leader() {
					return Ok(());
				}

				if matches!(self.state, SignProtocolState::WaitingForLeaderDecision) {
					// We're ready for it - process immediately. The signature was
					// already length-validated during deserialization.
					self.received_signature = Some(r4.signature);
				} else if matches!(
					self.state,
					SignProtocolState::Round1Generate |
						SignProtocolState::Round1Waiting |
						SignProtocolState::Round2Generate |
						SignProtocolState::Round2Waiting |
						SignProtocolState::Round3Generate |
						SignProtocolState::Round3Waiting
				) {
					// Buffer Round4Complete that arrives before we're ready
					// (can happen if leader receives all Round 3 faster than we do)
					self.message_buffer.buffer_round4_complete(r4);
				}
			},
		}

		Ok(())
	}

	/// Verify that a Round 2 reveal hashes back to the Round 1 commitment we
	/// previously accepted from the same party.
	///
	/// Returns `false` (and the message should be dropped) if either:
	/// - We have no Round 1 from the claimed party (replay before any Round 1, or Round 2 from a
	///   non-participant — already filtered earlier, but cheap to re-verify), or
	/// - The commitment_data is empty (every participant must contribute), or
	/// - The hash does not match (the reveal does not correspond to that commitment, most likely a
	///   replay from an earlier protocol instance).
	fn round2_matches_stored_round1(&self, r2: &Round2Broadcast) -> bool {
		let Some(r1) = self.r1_broadcasts.get(&r2.party_id) else {
			return false;
		};
		// Empty commitment_data is NOT allowed - every participant must contribute.
		// Allowing empty data would let an attacker bypass commitment binding by:
		// 1. Sending a legitimate Round 1 commitment hash
		// 2. Observing other parties' Round 2 reveals
		// 3. Sending empty Round 2 to bypass hash verification while still counting as participant
		if r2.commitment_data.is_empty() {
			return false;
		}
		crate::protocol::signing::verify_commitment_hash(
			&self.ssid,
			r2.party_id,
			&r2.commitment_data,
			&r1.commitment_hash,
		)
	}

	/// Process buffered Round 2 messages after transitioning to Round 2.
	///
	/// Buffered Round 2 messages still need the commitment-hash binding check
	/// against the Round 1 broadcasts we have now accumulated; any that fail are
	/// dropped here rather than poisoning `r2_broadcasts`.
	fn process_buffered_round2(&mut self) {
		let buffered = self.message_buffer.take_round2();
		for r2 in buffered {
			if !self.round2_matches_stored_round1(&r2) {
				warn!(
					"Signing: Dropping buffered Round 2 from party {} - commitment hash mismatch \
					 (likely stale/replayed)",
					r2.party_id
				);
				continue;
			}
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

	/// Process buffered Round4Complete after transitioning to WaitingForLeaderDecision.
	/// This handles the case where the leader's Round4Complete arrives before we've
	/// collected all Round 3 messages (possible when network ordering is not guaranteed).
	fn process_buffered_round4_complete(&mut self) {
		if let Some(r4) = self.message_buffer.take_round4_complete() {
			// SSID already verified when the message was received; the signature
			// was length-validated during deserialization.
			self.received_signature = Some(r4.signature);
		}
	}
}

// ============================================================================
// Helper function for running local simulations
// ============================================================================

/// Derive a per-party seed from a session seed.
/// Formula: `party_seed = SHAKE256("local-signing-party-seed" || session_seed || party_id)`
fn derive_party_seed(session_seed: &[u8; 32], party_id: ParticipantId) -> [u8; 32] {
	const DOMAIN: &[u8] = b"local-signing-party-seed";
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, DOMAIN);
	fips202::shake256_absorb(&mut state, session_seed);
	fips202::shake256_absorb(&mut state, &party_id.to_le_bytes());
	fips202::shake256_finalize(&mut state);
	let mut derived = [0u8; 32];
	fips202::shake256_squeeze(&mut derived, &mut state);
	derived
}

/// Derive an attempt nonce from a session seed for SSID computation.
/// All parties must derive this from the same session seed to get matching SSIDs.
/// Formula: `attempt_nonce = SHAKE256("local-signing-attempt-nonce" || session_seed)`
fn derive_attempt_nonce(session_seed: &[u8; 32]) -> [u8; 32] {
	const DOMAIN: &[u8] = b"local-signing-attempt-nonce";
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, DOMAIN);
	fips202::shake256_absorb(&mut state, session_seed);
	fips202::shake256_finalize(&mut state);
	let mut derived = [0u8; 32];
	fips202::shake256_squeeze(&mut derived, &mut state);
	derived
}

/// Run a complete local signing protocol, simulating all parties locally.
///
/// This function is useful for testing and benchmarking. In production,
/// parties run on separate machines and communicate over a network.
///
/// # Arguments
///
/// * `signers` - Vector of threshold signers (one per participating party)
/// * `message` - The message to sign
/// * `context` - The context string
/// * `session_seed` - A 32-byte seed used to derive per-party Round 1 seeds. For secure signing,
///   this should be cryptographically random and unique per session. For deterministic tests, a
///   fixed seed can be used.
///
/// # Returns
///
/// The produced signature on success. If the underlying ML-DSA rejection sampling
/// happens to abort on this attempt, returns `Err(SignProtocolError::SigningError)`
/// — callers should retry with a different `session_seed`.
pub fn run_local_signing(
	signers: Vec<ThresholdSigner>,
	message: &[u8],
	context: &[u8],
	session_seed: &[u8; 32],
) -> Result<Signature, SignProtocolError> {
	let num_parties = signers.len();
	if num_parties < 2 {
		return Err(SignProtocolError::MissingData("Need at least 2 signers".to_string()));
	}

	// Get participant IDs - leader is the first (lowest) ID
	let participants: Vec<ParticipantId> = signers.iter().map(|s| s.party_id()).collect();
	let leader_id = *participants.iter().min().unwrap();

	// Derive attempt_nonce from session_seed for SSID computation
	// All parties must use the same attempt_nonce
	let attempt_nonce = derive_attempt_nonce(session_seed);

	// Create protocol instances with per-party seeds derived from session_seed
	let mut protocols: Vec<DilithiumSignProtocol> = signers
		.into_iter()
		.map(|signer| {
			let my_id = signer.party_id();
			let round1_seed = derive_party_seed(session_seed, my_id);
			DilithiumSignProtocol::new(
				signer,
				message.to_vec(),
				context.to_vec(),
				participants.clone(),
				my_id,
				leader_id,
				round1_seed,
				attempt_nonce,
			)
		})
		.collect::<Result<Vec<_>, _>>()?;

	// Message queues: pending_messages[to] = vec of (from, data)
	let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); num_parties];

	// Run until any party completes
	let mut iterations = 0;
	const MAX_ITERATIONS: usize = 32;

	loop {
		iterations += 1;
		if iterations > MAX_ITERATIONS {
			return Err(SignProtocolError::ProtocolFailed(
				"Signing did not complete in time".to_string(),
			));
		}

		// Deliver pending messages
		for (party_idx, protocol) in protocols.iter_mut().enumerate() {
			let messages = mem::take(&mut pending_messages[party_idx]);
			for (from, data) in messages {
				protocol.message(from, data)?;
			}
		}

		// Poke each party
		for protocol in protocols.iter_mut() {
			let my_id = protocol.my_participant_id();

			match protocol.poke()? {
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
					return Ok(signature);
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

		// Sign with exactly threshold (2) participants
		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let protocol = DilithiumSignProtocol::new(
			signer,
			b"test message".to_vec(),
			b"context".to_vec(),
			vec![0, 1], // exactly threshold participants
			0,
			0,          // leader_id
			[0xAA; 32], // round1_seed
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		assert_eq!(protocol.my_participant_id(), 0);
		assert_eq!(protocol.participants().as_slice(), &[0, 1]);
		assert_eq!(protocol.leader_id(), 0);
		assert!(protocol.is_leader());
	}

	#[test]
	fn test_protocol_rejects_duplicate_participants() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let result = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1, 1], // duplicate!
			0,
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		);

		assert!(matches!(result, Err(SignProtocolError::InvalidConfig(_))));
	}

	#[test]
	fn test_protocol_rejects_missing_my_participant() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let result = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1, 2],
			99, // not in participants!
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		);

		assert!(matches!(result, Err(SignProtocolError::InvalidConfig(_))));
	}

	#[test]
	fn test_protocol_rejects_missing_leader() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let result = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1, 2],
			0,
			99, // leader not in participants!
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		);

		assert!(matches!(result, Err(SignProtocolError::InvalidConfig(_))));
	}

	#[test]
	fn test_protocol_rejects_non_dkg_participant() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let result = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1, 99], // 99 was not in DKG!
			0,
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		);

		assert!(matches!(result, Err(SignProtocolError::InvalidConfig(_))));
	}

	#[test]
	fn test_message_serialization_round1() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		let r2 = Round2Broadcast::new(*protocol.ssid(), 2, vec![1, 2, 3, 4, 5, 6, 7, 8]);
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
		let protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		let r3 = Round3Broadcast::new(*protocol.ssid(), 3, vec![10, 20, 30, 40, 50]);
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

			let session_seed: [u8; 32] = rand::random();
			match run_local_signing(signers, message, context, &session_seed) {
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

			let session_seed: [u8; 32] = rand::random();
			match run_local_signing(signers, message, context, &session_seed) {
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
		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

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
	fn test_message_from_self_ignored() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		// Generate Round 1
		let action = protocol.poke().unwrap();
		let data = match action {
			Action::SendMany(d) => d,
			_ => panic!("Expected SendMany"),
		};

		// Try to deliver our own message (should be ignored with Ok(()))
		let initial_count = protocol.r1_broadcasts.len();
		assert!(protocol.message(0, data).is_ok());
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
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		// Generate Round 1
		let _ = protocol.poke().unwrap();

		// Create a message from party 99 (not a participant)
		// Use our SSID so the message passes SSID check but fails participant check
		let r1 = Round1Broadcast::new(*protocol.ssid(), 99, [0x42u8; 32]);
		let msg = SigningMessage::Round1(r1);
		let data = protocol.serialize_message(&msg).unwrap();

		// Deliver message from non-participant (should be ignored with Ok(()))
		let initial_count = protocol.r1_broadcasts.len();
		assert!(protocol.message(99, data).is_ok());
		assert_eq!(protocol.r1_broadcasts.len(), initial_count);
	}

	#[test]
	fn test_message_buffer_creation() {
		let buffer = SignMessageBuffer::new();
		assert!(buffer.is_empty());
	}

	#[test]
	fn test_message_buffer_round2() {
		let mut buffer = SignMessageBuffer::new();
		assert!(buffer.is_empty());

		let ssid = [0xCC; SSID_SIZE];
		let msg = Round2Broadcast::new(ssid, 1, vec![1, 2, 3, 4]);
		buffer.buffer_round2(msg);

		assert!(!buffer.is_empty());

		let taken = buffer.take_round2();
		assert_eq!(taken.len(), 1);
		assert_eq!(taken[0].party_id, 1);
		assert!(buffer.is_empty());
	}

	#[test]
	fn test_message_buffer_deduplication() {
		let mut buffer = SignMessageBuffer::new();
		let ssid = [0xCC; SSID_SIZE];

		// Buffer first message from party 1
		let msg1 = Round2Broadcast::new(ssid, 1, vec![1, 2, 3, 4]);
		buffer.buffer_round2(msg1);

		// Try to buffer duplicate from party 1 - should be ignored
		let msg1_dup = Round2Broadcast::new(ssid, 1, vec![5, 6, 7, 8]);
		buffer.buffer_round2(msg1_dup);

		// Buffer message from party 2
		let msg2 = Round2Broadcast::new(ssid, 2, vec![9, 10, 11, 12]);
		buffer.buffer_round2(msg2);

		let taken = buffer.take_round2();
		assert_eq!(taken.len(), 2); // Only 2 unique parties
							  // First message from party 1 should be kept (not the duplicate)
		let party1_msg = taken.iter().find(|m| m.party_id == 1).unwrap();
		assert_eq!(party1_msg.commitment_data, vec![1, 2, 3, 4]);
	}

	#[test]
	fn test_message_buffer_round3() {
		let mut buffer = SignMessageBuffer::new();
		let ssid = [0xCC; SSID_SIZE];

		let msg = Round3Broadcast::new(ssid, 2, vec![5, 6, 7, 8]);
		buffer.buffer_round3(msg);

		assert!(!buffer.is_empty());

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
			vec![0, 1], // exactly threshold participants
			0,
			0, // leader_id
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		// Start Round 1 - generates and sends our Round 1 message
		let _ = protocol.poke().unwrap();
		assert!(matches!(protocol.state(), SignProtocolState::Round1Waiting));

		// Now simulate receiving a Round 2 message BEFORE we've received all Round 1 messages
		// This is what happens in distributed systems with network delays
		let r2 = Round2Broadcast::new(*protocol.ssid(), 1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
		let msg = SigningMessage::Round2(r2);
		let data = protocol.serialize_message(&msg).unwrap();

		// Send the Round 2 message - it should be buffered, not rejected
		protocol.message(1, data).unwrap();

		// Verify the message was buffered (not in r2_broadcasts yet)
		assert!(!protocol.message_buffer.is_empty());
		assert!(protocol.message_buffer.round2.contains_key(&1));
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
			vec![0, 1], // exactly threshold participants
			0,
			0, // leader_id
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		// Start Round 1
		let _ = protocol.poke().unwrap();
		assert!(matches!(protocol.state(), SignProtocolState::Round1Waiting));

		// Simulate receiving a Round 3 message while still in Round 1
		let r3 = Round3Broadcast::new(*protocol.ssid(), 1, vec![10, 20, 30, 40]);
		let msg = SigningMessage::Round3(r3);
		let data = protocol.serialize_message(&msg).unwrap();

		// Send the Round 3 message - it should be buffered
		protocol.message(1, data).unwrap();

		// Verify the message was buffered
		assert!(!protocol.message_buffer.is_empty());
		assert!(protocol.message_buffer.round3.contains_key(&1));
		// Should NOT be in r3_broadcasts yet
		assert!(!protocol.r3_broadcasts.contains_key(&1));
	}

	/// Round4Complete messages that arrive before a follower reaches WaitingForLeaderDecision
	/// should be buffered and processed when the follower transitions. This prevents
	/// deadlock when the leader finishes faster than followers (e.g., due to network delays
	/// in receiving other parties' Round 3 messages).
	#[test]
	fn test_out_of_order_round4_complete_buffering() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let message = b"test message".to_vec();
		let context = b"context".to_vec();

		// Run a full signing protocol to get a valid signature
		let mut valid_sig = None;
		for _ in 0..100 {
			let signers: Vec<_> = shares
				.iter()
				.take(2)
				.map(|s| ThresholdSigner::new(s.clone(), pk.clone(), config).unwrap())
				.collect();

			let session_seed: [u8; 32] = rand::random();

			match run_local_signing(signers, &message, &context, &session_seed) {
				Ok(sig) => {
					valid_sig = Some(sig);
					break;
				},
				Err(_) => continue,
			}
		}
		let valid_sig = valid_sig.expect("Should have produced a valid signature");

		// Create a follower protocol (party 1 with party 0 as leader)
		let signer = ThresholdSigner::new(shares[1].clone(), pk.clone(), config).unwrap();
		let mut follower = DilithiumSignProtocol::new(
			signer,
			message.clone(),
			context.clone(),
			vec![0, 1],
			1, // follower
			0, // leader is party 0
			[0xDD; 32],
			[0xEE; 32], // attempt_nonce
		)
		.unwrap();

		// Start the follower - it's in Round1Waiting
		let _ = follower.poke().unwrap();
		assert!(matches!(follower.state(), SignProtocolState::Round1Waiting));

		// Simulate receiving Round4Complete from leader BEFORE follower is ready
		// (this can happen if leader finishes all rounds faster)
		let round4_msg = SigningMessage::Round4Complete(Round4Broadcast {
			ssid: *follower.ssid(),
			signature: valid_sig.clone(),
		});
		let round4_data = follower.serialize_message(&round4_msg).unwrap();
		follower.message(0, round4_data).unwrap();

		// Verify the message was buffered (not processed yet)
		assert!(
			follower.message_buffer.round4_complete.is_some(),
			"Round4Complete should be buffered when follower is in early state"
		);
		assert!(follower.received_signature.is_none(), "Signature should not be set yet");

		// Now manually advance the follower to WaitingForLeaderDecision
		// (simulating normal protocol progression)
		follower.state = SignProtocolState::Round3Waiting;
		// Pretend we have enough Round 3 messages by setting threshold
		let ssid = *follower.ssid();
		follower.r3_broadcasts.insert(0, Round3Broadcast::new(ssid, 0, vec![1, 2, 3]));
		follower.r3_broadcasts.insert(1, Round3Broadcast::new(ssid, 1, vec![4, 5, 6]));

		// Poke should transition to WaitingForLeaderDecision, process buffered Round4Complete,
		// verify the signature, and return it - all in one shot since poke() recurses
		let result = follower.poke();
		match result {
			Ok(Action::Return(sig)) => {
				assert_eq!(sig.as_bytes(), valid_sig.as_bytes());
			},
			other => panic!("Expected Action::Return with valid signature, got: {:?}", other),
		}
		assert!(matches!(follower.state, SignProtocolState::Done));

		// Verify the buffer was cleared
		assert!(
			follower.message_buffer.round4_complete.is_none(),
			"Buffer should be cleared after processing"
		);
	}

	#[test]
	fn test_buffered_messages_processed_on_state_transition() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		// Create protocol for party 0 with exactly threshold (2) participants
		let signer0 = ThresholdSigner::new(shares[0].clone(), pk.clone(), config).unwrap();
		let mut protocol0 = DilithiumSignProtocol::new(
			signer0,
			b"test message".to_vec(),
			b"context".to_vec(),
			vec![0, 1], // exactly threshold participants
			0,
			0, // leader_id
			[0xAA; 32],
			[0xCC; 32], // attempt_nonce
		)
		.unwrap();

		// Create protocol for party 1 (to generate valid messages)
		let signer1 = ThresholdSigner::new(shares[1].clone(), pk.clone(), config).unwrap();
		let mut protocol1 = DilithiumSignProtocol::new(
			signer1,
			b"test message".to_vec(),
			b"context".to_vec(),
			vec![0, 1], // exactly threshold participants
			1,
			0,          // leader_id
			[0xBB; 32], // Different seed for party 1
			[0xCC; 32], // Same attempt_nonce for both parties
		)
		.unwrap();

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
		protocol1.message(0, r1_data0.clone()).unwrap();

		// With only 2 parties (threshold), after party 1 receives from party 0,
		// it has all the round 1 messages it needs

		// Party 1 should now advance to Round 2
		let r2_data1 = match protocol1.poke().unwrap() {
			Action::SendMany(d) => d,
			_ => panic!("Expected SendMany for Round 2"),
		};

		// Now party 0 receives the Round 2 message from party 1 BEFORE completing Round 1
		// This should be buffered
		protocol0.message(1, r2_data1).unwrap();
		assert!(!protocol0.message_buffer.round2.is_empty());
		assert!(!protocol0.r2_broadcasts.contains_key(&1));

		// Now party 0 receives the remaining Round 1 message from party 1
		protocol0.message(1, r1_data1).unwrap();

		// Party 0 should now advance to Round 2 and process the buffered Round 2 message
		let _ = protocol0.poke().unwrap();

		// The buffered message should have been processed
		assert!(protocol0.message_buffer.round2.is_empty());
		// And the Round 2 message from party 1 should now be in r2_broadcasts
		assert!(protocol0.r2_broadcasts.contains_key(&1));
	}

	#[test]
	fn test_follower_rejects_invalid_signature_from_leader() {
		// Followers must verify signatures before accepting them
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		// Create a follower (party 1, with party 0 as leader)
		// Use exactly threshold (2) participants
		let signer = ThresholdSigner::new(shares[1].clone(), pk.clone(), config).unwrap();
		let mut follower = DilithiumSignProtocol::new(
			signer,
			b"test message".to_vec(),
			b"context".to_vec(),
			vec![0, 1], // exactly threshold participants
			1,          // follower
			0,          // leader is party 0
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		// Manually set follower to WaitingForLeaderDecision state
		follower.state = SignProtocolState::WaitingForLeaderDecision;

		// Create an invalid signature (all zeros)
		let invalid_sig = Signature::from_bytes(&[0u8; 4627]).unwrap();
		follower.received_signature = Some(invalid_sig);

		// Follower should reject the invalid signature
		let result = follower.poke();
		assert!(result.is_err(), "Follower should reject invalid signature");
		match result {
			Err(SignProtocolError::ProtocolFailed(msg)) => {
				assert!(
					msg.contains("invalid signature"),
					"Error should mention invalid signature, got: {}",
					msg
				);
			},
			other => panic!("Expected ProtocolFailed, got: {:?}", other),
		}
		assert!(matches!(follower.state, SignProtocolState::Failed(_)));
	}

	#[test]
	fn test_follower_accepts_valid_signature_from_leader() {
		// Followers should accept valid signatures from the leader
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let message = b"test message".to_vec();
		let context = b"context".to_vec();

		// Run a full signing protocol to get a valid signature using run_local_signing
		// Try multiple times due to rejection sampling
		let mut valid_sig = None;
		for _ in 0..100 {
			let signers: Vec<_> = shares
				.iter()
				.take(2)
				.map(|s| ThresholdSigner::new(s.clone(), pk.clone(), config).unwrap())
				.collect();

			let session_seed: [u8; 32] = rand::random();

			match run_local_signing(signers, &message, &context, &session_seed) {
				Ok(sig) => {
					valid_sig = Some(sig);
					break;
				},
				Err(_) => continue,
			}
		}

		let valid_sig = valid_sig.expect("Should have produced a valid signature");

		// Verify the signature is actually valid
		assert!(verify_signature(&pk, &message, &context, &valid_sig), "Signature should be valid");

		// Now test that a new follower would accept this valid signature
		let signer = ThresholdSigner::new(shares[1].clone(), pk.clone(), config).unwrap();
		let mut follower = DilithiumSignProtocol::new(
			signer,
			message.clone(),
			context.clone(),
			vec![0, 1], // exactly threshold participants
			1,          // follower
			0,          // leader is party 0
			[0xCC; 32],
			[0xDD; 32], // attempt_nonce
		)
		.unwrap();

		// Manually set follower to WaitingForLeaderDecision state
		follower.state = SignProtocolState::WaitingForLeaderDecision;
		follower.received_signature = Some(valid_sig.clone());

		// Follower should accept the valid signature
		let result = follower.poke();
		match result {
			Ok(Action::Return(sig)) => {
				assert_eq!(sig.as_bytes(), valid_sig.as_bytes());
			},
			other => panic!("Expected Action::Return with valid signature, got: {:?}", other),
		}
		assert!(matches!(follower.state, SignProtocolState::Done));
	}

	/// A Round 2 reveal that does not hash back to the previously-accepted Round 1
	/// commitment for the same party must be silently dropped (and must NOT occupy
	/// the slot in `r2_broadcasts`). This is the receive-time enforcement of the
	/// paper's ShareSign_3 binding (Fig. 6), and the direct fix for the audited
	/// replay-poisoning vulnerability.
	#[test]
	fn test_round2_with_mismatched_commitment_is_dropped() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		// Advance the protocol past Round 1 so Round 2 is accepted at intake.
		// We do this by manually installing a Round 1 broadcast from peer 1 and
		// transitioning to Round2Waiting (matching what would happen after a
		// successful Round 1 exchange in production).
		let _ = protocol.poke().unwrap(); // Round1Generate -> Round1Waiting (and stores my_r1)
		let ssid = *protocol.ssid();
		let fake_r1 = Round1Broadcast::new(ssid, 1, [0xDE; 32]); // commitment we'll mismatch against
		protocol.r1_broadcasts.insert(1, fake_r1);
		protocol.state = SignProtocolState::Round2Waiting;

		// Now deliver a Round 2 whose commitment_data does NOT hash to [0xDE; 32].
		let bad_r2 = Round2Broadcast::new(ssid, 1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
		let msg = SigningMessage::Round2(bad_r2);
		let data = protocol.serialize_message(&msg).unwrap();
		protocol.message(1, data).unwrap();

		assert!(
			!protocol.r2_broadcasts.contains_key(&1),
			"Round 2 with mismatched commitment hash must not be accepted into r2_broadcasts"
		);
	}

	/// Buffered Round 2 messages must also be subjected to the commitment-hash
	/// check when they're drained on transition into Round 2. A replayed Round 2
	/// that arrived early (so was buffered) must not poison the live r2_broadcasts
	/// map once the corresponding Round 1 has been collected.
	#[test]
	fn test_buffered_round2_with_mismatched_commitment_is_dropped() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		// In Round1Waiting, a Round 2 from peer 1 should be buffered (no Round 1
		// from peer 1 yet, so the check is necessarily deferred).
		let _ = protocol.poke().unwrap();
		let ssid = *protocol.ssid();
		let bad_r2 = Round2Broadcast::new(ssid, 1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
		let msg = SigningMessage::Round2(bad_r2);
		let data = protocol.serialize_message(&msg).unwrap();
		protocol.message(1, data).unwrap();
		assert!(protocol.message_buffer.round2.contains_key(&1));

		// Now install a Round 1 from peer 1 whose commitment_hash does NOT
		// correspond to the buffered Round 2's commitment_data, and drain the buffer.
		let fake_r1 = Round1Broadcast::new(ssid, 1, [0xDE; 32]);
		protocol.r1_broadcasts.insert(1, fake_r1);
		protocol.process_buffered_round2();

		assert!(
			!protocol.r2_broadcasts.contains_key(&1),
			"Buffered Round 2 with mismatched commitment hash must be dropped, not promoted"
		);
		assert!(protocol.message_buffer.round2.is_empty());
	}

	/// Empty commitment_data in Round 2 must be rejected.
	/// This prevents an attacker from bypassing commitment binding by:
	/// 1. Sending a legitimate Round 1 commitment hash
	/// 2. Observing other parties' Round 2 reveals
	/// 3. Sending empty Round 2 to bypass hash verification while still counting as participant
	#[test]
	fn test_empty_commitment_data_rejected() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		// Advance to Round2Waiting
		let _ = protocol.poke().unwrap();
		let ssid = *protocol.ssid();
		let legitimate_r1 = Round1Broadcast::new(ssid, 1, [0xAB; 32]);
		protocol.r1_broadcasts.insert(1, legitimate_r1);
		protocol.state = SignProtocolState::Round2Waiting;

		// Send an EMPTY Round 2 - this should be rejected
		let empty_r2 = Round2Broadcast::new(ssid, 1, vec![]); // Empty commitment_data
		let msg = SigningMessage::Round2(empty_r2);
		let data = protocol.serialize_message(&msg).unwrap();
		protocol.message(1, data).unwrap();

		// Empty Round 2 must NOT be accepted
		assert!(
			!protocol.r2_broadcasts.contains_key(&1),
			"Empty commitment_data must be rejected - attacker cannot bypass commitment binding"
		);
	}

	/// A leader whose `combine()` fails must surface that as a hard
	/// error and transition to `Failed`. There is no in-protocol retry; the
	/// caller is expected to spawn a fresh DilithiumSignProtocol instance to
	/// retry, on a fresh transport channel.
	#[test]
	fn test_combination_failure_is_terminal() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();
		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"ctx".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32], // attempt_nonce
		)
		.unwrap();

		// Force the protocol into Round4Deciding with empty broadcasts so that
		// combination cannot succeed.
		protocol.state = SignProtocolState::Round4Deciding;

		let result = protocol.poke();
		assert!(result.is_err(), "combination on empty state must fail");
		assert!(
			matches!(protocol.state, SignProtocolState::Failed(_)),
			"protocol must transition to Failed on combination error"
		);

		// Subsequent pokes must continue to fail (the instance is dead).
		let again = protocol.poke();
		assert!(matches!(again, Err(SignProtocolError::ProtocolFailed(_))));
	}

	#[test]
	fn test_protocol_rejects_oversized_message() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();

		// Create a message larger than MAX_MESSAGE_SIZE (64 MiB)
		let oversized_message = vec![0u8; MAX_MESSAGE_SIZE + 1];

		let result = DilithiumSignProtocol::new(
			signer,
			oversized_message,
			b"ctx".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32],
		);

		assert!(matches!(result, Err(SignProtocolError::InvalidConfig(_))));
		if let Err(SignProtocolError::InvalidConfig(msg)) = result {
			assert!(msg.contains("message size"), "Error should mention message size: {}", msg);
			assert!(msg.contains("exceeds"), "Error should mention limit exceeded: {}", msg);
		}
	}

	#[test]
	fn test_protocol_rejects_oversized_context() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();

		// Create a context larger than 255 bytes
		let oversized_context = vec![0u8; 256];

		let result = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			oversized_context,
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32],
		);

		assert!(matches!(result, Err(SignProtocolError::InvalidConfig(_))));
		if let Err(SignProtocolError::InvalidConfig(msg)) = result {
			assert!(msg.contains("context size"), "Error should mention context size: {}", msg);
			assert!(msg.contains("255"), "Error should mention 255 byte limit: {}", msg);
		}
	}

	#[test]
	fn test_protocol_accepts_max_valid_sizes() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[42u8; 32], config).unwrap();

		let signer = ThresholdSigner::new(shares[0].clone(), pk, config).unwrap();

		// Max valid context (255 bytes)
		let max_context = vec![0u8; 255];

		let result = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			max_context,
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
			[0xBB; 32],
		);

		assert!(result.is_ok(), "Should accept 255-byte context");
	}

	/// A Round 4 message whose signature field is not exactly `SIGNATURE_SIZE`
	/// bytes must be rejected at deserialization. Before switching the field to
	/// the exact-size `Signature` type, the derived `Vec<u8>` deserializer
	/// accepted any length up to the message cap.
	#[test]
	fn test_round4_rejects_wrong_size_signature() {
		use crate::broadcast::SIGNATURE_SIZE;

		let mut payload = Vec::new();
		payload.extend_from_slice(&[0xABu8; SSID_SIZE]); // ssid
		payload.extend_from_slice(&100u32.to_le_bytes()); // sig len = 100 (wrong)
		payload.extend_from_slice(&[0u8; 100]);

		let result: Result<Round4Broadcast, _> = borsh::from_slice(&payload);
		assert!(
			result.is_err(),
			"Round4Broadcast must reject a signature that is not SIGNATURE_SIZE bytes"
		);

		// A correctly-sized signature round-trips.
		let sig = Signature::from_bytes(&[7u8; SIGNATURE_SIZE]).unwrap();
		let r4 = Round4Broadcast::new([0xABu8; SSID_SIZE], sig);
		let bytes = borsh::to_vec(&r4).unwrap();
		let recovered: Round4Broadcast = borsh::from_slice(&bytes).unwrap();
		assert_eq!(recovered.signature.as_bytes(), r4.signature.as_bytes());
	}
}
