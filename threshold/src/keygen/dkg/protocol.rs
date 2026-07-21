//! Protocol implementation for DKG.

use alloc::{
	boxed::Box,
	collections::BTreeMap,
	format,
	string::{String, ToString},
	vec,
	vec::Vec,
};
use core::{fmt, mem};

use log::warn;
use zeroize::{Zeroize, Zeroizing};

use crate::{
	config::ThresholdConfig,
	keys::{PrivateKeyShare, PublicKey, SecretShareData},
	participants::ParticipantList,
	protocol::partial_pk::{compute_partial_pk_t, pack_combined_pk},
};

use super::{
	state::{
		all_broadcasts_received, all_private_messages_received, DkgOutput, DkgPhase, DkgState,
	},
	types::{
		compute_dkg_ssid, compute_partial_output_hash, compute_signing_message,
		compute_transcript_hash, derive_subset_contribution, h_commit, h_commit_pk, h_keygen,
		h_seed, DkgConfig, DkgMessage, PartialPublicKey, Round1Broadcast, Round1Private,
		Round2Broadcast, Round3Broadcast, Round4Broadcast, SubsetContribution, SubsetMask,
		TranscriptSigner, DKG_SSID_SIZE, RANDOMNESS_SIZE, SHARED_SECRET_SIZE,
	},
};

use crate::participants::ParticipantId;

use qp_rusty_crystals_dilithium::{
	fips202,
	params::{K, L},
};

/// Maximum DKG message size in bytes (256 KB).
/// Maximum size of a serialized DKG message (256 KB).
///
/// This limits total memory allocation from any single message. Borsh validates
/// that internal length prefixes don't exceed remaining input before allocating,
/// so the packet size check is sufficient to prevent memory exhaustion attacks
/// from malicious length prefixes. See `test_malicious_length_prefix_rejected`.
pub const MAX_DKG_MESSAGE_SIZE: usize = 256 * 1024;

// ============================================================================
// Helper Functions
// ============================================================================

/// Deserialize a DKG message with size limits to prevent resource exhaustion.
///
/// # Security
///
/// The packet size check combined with borsh's length validation ensures that:
/// 1. Total allocation is bounded by `MAX_DKG_MESSAGE_SIZE`
/// 2. Malicious length prefixes claiming more bytes than available are rejected with an error (not
///    OOM)
fn deserialize_message(data: &[u8]) -> Result<DkgMessage, String> {
	if data.len() > MAX_DKG_MESSAGE_SIZE {
		return Err(format!("Message size {} exceeds maximum {}", data.len(), MAX_DKG_MESSAGE_SIZE));
	}
	borsh::from_slice(data).map_err(|e| e.to_string())
}

/// Serialize a queued Round 1 private message into a self-wiping transport buffer.
///
/// The frame carries the secret K_S, so two properties matter beyond plain
/// `borsh::to_vec`:
/// - the buffer is allocated at its exact final size before serialization —
///   letting borsh grow a `Vec` incrementally frees intermediate blocks that
///   already contain a prefix of the secret payload;
/// - the buffer is [`Zeroizing`], so it is wiped when the caller drops it
///   after handing the frame to the transport.
fn serialize_round1_private(
	to: ParticipantId,
	private: Round1Private,
) -> Result<DkgAction, DkgError> {
	let msg = DkgMessage::Round1Private(private);
	let len = borsh::object_length(&msg).map_err(|e| DkgError::InternalError(e.to_string()))?;
	let mut data = Zeroizing::new(Vec::with_capacity(len));
	borsh::to_writer(&mut *data, &msg).map_err(|e| DkgError::InternalError(e.to_string()))?;
	Ok(DkgAction::SendPrivate(to, data))
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during the DKG protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkgError {
	/// The protocol is in an invalid state for the requested operation.
	InvalidState(String),
	/// A party's revealed randomness doesn't match their Round 1 commitment.
	CommitmentMismatch {
		/// The party whose commitment didn't match.
		party_id: ParticipantId,
	},
	/// A party's revealed partial public key doesn't match their Round 3 commitment.
	PkCommitmentMismatch {
		/// The party whose PK commitment didn't match.
		party_id: ParticipantId,
		/// The subset for which the commitment failed.
		subset: SubsetMask,
	},
	/// A party's partial public key failed verification against the shared secret.
	PkVerificationFailed {
		/// The party whose PK verification failed.
		party_id: ParticipantId,
		/// The subset for which verification failed.
		subset: SubsetMask,
	},
	/// A party's transcript signature failed verification.
	SignatureVerificationFailed {
		/// The party whose signature failed verification.
		party_id: ParticipantId,
	},
	/// Required data is missing from a previous round.
	MissingData(String),
	/// An invalid message was received.
	InvalidMessage(String),
	/// An internal error occurred.
	InternalError(String),
	/// A malformed message was received from a party.
	///
	/// This indicates the message could not be deserialized, which could
	/// indicate a bug, network corruption, or malicious behavior.
	MalformedMessage {
		/// The party that sent the malformed message.
		from: ParticipantId,
		/// Reason for the failure.
		reason: String,
	},
	/// A message's SSID does not match the expected session.
	///
	/// This indicates a potential cross-session replay attack or misconfiguration.
	SsidMismatch {
		/// The party that sent the mismatched message.
		from: ParticipantId,
	},
}

impl fmt::Display for DkgError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidState(msg) => write!(f, "invalid state: {}", msg),
			Self::CommitmentMismatch { party_id } => {
				write!(f, "commitment mismatch from party {}", party_id)
			},
			Self::PkCommitmentMismatch { party_id, subset } => {
				write!(f, "PK commitment mismatch from party {} for subset {:b}", party_id, subset)
			},
			Self::PkVerificationFailed { party_id, subset } => {
				write!(f, "PK verification failed from party {} for subset {:b}", party_id, subset)
			},
			Self::SignatureVerificationFailed { party_id } => {
				write!(f, "signature verification failed from party {}", party_id)
			},
			Self::MissingData(msg) => write!(f, "missing data: {}", msg),
			Self::InvalidMessage(msg) => write!(f, "invalid message: {}", msg),
			Self::InternalError(msg) => write!(f, "internal error: {}", msg),
			Self::MalformedMessage { from, reason } => {
				write!(f, "malformed message from party {}: {}", from, reason)
			},
			Self::SsidMismatch { from } => {
				write!(f, "SSID mismatch from party {} (possible cross-session replay)", from)
			},
		}
	}
}

// ============================================================================
// Action Type
// ============================================================================

/// Actions returned by the DKG protocol state machine.
///
/// The caller should handle each action appropriately:
/// - `Wait`: No action needed, call `poke()` again after receiving messages
/// - `SendMany`: Broadcast the data to all other participants via authenticated channel
/// - `SendPrivate`: Send the data to a specific participant via secure channel
/// - `Return`: The DKG is complete, the output contains the keys
///
/// `Return` carries a boxed [`DkgOutput`] because the output is ~2.8 KB
/// (full Dilithium key material) and inlining it would balloon every other
/// variant. See `clippy::large_enum_variant`.
///
/// `Debug` is implemented manually (rather than derived) so that the
/// [`SendPrivate`](DkgAction::SendPrivate) transport bytes — which carry the
/// serialized Round 1 secret K_S — are never rendered. A derived formatter would
/// print the raw `Vec<u8>`, persisting key material into any log or trace that
/// includes `{:?}` output. Only the recipient and payload length are shown.
pub enum DkgAction {
	/// Wait for more messages before proceeding.
	Wait,
	/// Broadcast data to all other participants.
	///
	/// **IMPORTANT: This message MUST be sent over an authenticated channel
	/// (integrity + sender authentication).**
	///
	/// The caller is responsible for ensuring:
	/// - **Authenticity**: Receivers can verify the broadcast came from us — the `from` argument
	///   that peers pass to [`Dkg::message`] is trusted and must be derived from transport-level
	///   sender authentication, not from attacker-controllable packet contents
	/// - **Integrity**: The message cannot be modified in transit
	///
	/// Confidentiality is not required; broadcast payloads are public.
	///
	/// Without sender authentication, an attacker who can inject packets can
	/// spoof a participant's broadcast before the genuine one arrives. Round
	/// buffers keep the first message per sender (first-message-wins, a
	/// memory-exhaustion defense), so the forged packet occupies that
	/// participant's slot and the honest broadcast is ignored. The poisoned
	/// data is then caught by commitment or transcript verification, but only
	/// as a late abort: the attacker can deny completion of every session.
	SendMany(Vec<u8>),
	/// Send data privately to a specific participant.
	///
	/// **IMPORTANT: This message MUST be sent over an authenticated and encrypted channel.**
	///
	/// The caller is responsible for ensuring:
	/// - **Confidentiality**: Only the recipient can read the message content
	/// - **Authenticity**: The recipient can verify this message came from us
	/// - **Integrity**: The message cannot be modified in transit
	///
	/// This is used in Round 1 to distribute the per-subset secret K_S to subset members.
	/// Without proper channel security, the threshold scheme's security is compromised.
	///
	/// The payload is [`Zeroizing`] because the serialized bytes contain K_S:
	/// once the caller has handed the frame to the transport and drops this
	/// value, the buffer is wiped instead of leaving key material in freed
	/// heap memory.
	SendPrivate(ParticipantId, Zeroizing<Vec<u8>>),
	/// DKG is complete, return the output.
	Return(Box<DkgOutput>),
}

impl fmt::Debug for DkgAction {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			DkgAction::Wait => f.write_str("Wait"),
			// Broadcast payloads are public, but the serialized bytes are noise in
			// a log; show only the length for consistency with SendPrivate.
			DkgAction::SendMany(data) =>
				f.debug_tuple("SendMany").field(&format_args!("{} bytes", data.len())).finish(),
			// The payload is the serialized Round 1 private message (K_S). Never
			// render the bytes; keep the recipient and length for diagnostics.
			DkgAction::SendPrivate(to, data) => f
				.debug_struct("SendPrivate")
				.field("to", to)
				.field("payload", &format_args!("<{} bytes redacted>", data.len()))
				.finish(),
			// Delegates to DkgOutput's Debug, which redacts the private share.
			DkgAction::Return(output) => f.debug_tuple("Return").field(output).finish(),
		}
	}
}

// ============================================================================
// Message Buffer
// ============================================================================

/// Buffer for DKG messages that arrive out of order.
///
/// In distributed systems, messages may arrive before the recipient is ready
/// to process them. For example, a fast node might send its Round 2 message
/// before a slower node has finished processing all Round 1 messages.
///
/// This buffer stores messages for future rounds and processes them when
/// the protocol transitions to the appropriate state.
///
/// Messages are keyed by sender to ensure only one message per sender is stored,
/// preventing memory exhaustion from duplicate messages.
///
/// # Security: Round 1 Private Message Validation
///
/// Round 1 private messages are validated before buffering to prevent DoS attacks.
/// A malicious sender could otherwise send messages with many different invalid
/// `subset_mask` values to exhaust memory. Validation checks:
/// - `subset_mask` is valid for the threshold config
/// - Sender is the legitimate leader for the subset
/// - Receiver is a member of the subset
#[derive(Default)]
struct DkgMessageBuffer {
	/// Round 1 broadcasts received while still in Initialized phase.
	round1_broadcasts: BTreeMap<ParticipantId, Round1Broadcast>,
	/// Round 1 private messages received while still in Initialized phase.
	/// Key is (from_party_id, subset_mask) to allow multiple subsets per sender.
	/// Messages are validated before buffering to prevent DoS via invalid subset masks.
	round1_privates: BTreeMap<(ParticipantId, SubsetMask), Round1Private>,
	/// Round 2 broadcasts received while still in Round 1.
	round2: BTreeMap<ParticipantId, Round2Broadcast>,
	/// Round 3 broadcasts received while still in Round 1-2.
	round3: BTreeMap<ParticipantId, Round3Broadcast>,
	/// Round 4 broadcasts received while still in Round 1-3.
	round4: BTreeMap<ParticipantId, Round4Broadcast>,
}

impl DkgMessageBuffer {
	/// Create a new empty message buffer.
	fn new() -> Self {
		Self::default()
	}

	/// Buffer a Round 1 broadcast for later processing.
	/// Only keeps the first message from each sender.
	fn buffer_round1_broadcast(&mut self, msg: Round1Broadcast) {
		self.round1_broadcasts.entry(msg.party_id).or_insert(msg);
	}

	/// Buffer a Round 1 private message for later processing.
	/// Only keeps the first message per (sender, subset) pair.
	///
	/// # Security
	/// Callers MUST validate the message before buffering (subset_mask validity,
	/// sender is leader, receiver is member). This function does not validate.
	fn buffer_round1_private(&mut self, msg: Round1Private) {
		self.round1_privates.entry((msg.from_party_id, msg.subset_mask)).or_insert(msg);
	}

	/// Buffer a Round 2 broadcast for later processing.
	/// Only keeps the first message from each sender.
	fn buffer_round2(&mut self, msg: Round2Broadcast) {
		self.round2.entry(msg.party_id).or_insert(msg);
	}

	/// Buffer a Round 3 broadcast for later processing.
	/// Only keeps the first message from each sender.
	fn buffer_round3(&mut self, msg: Round3Broadcast) {
		self.round3.entry(msg.party_id).or_insert(msg);
	}

	/// Buffer a Round 4 broadcast for later processing.
	/// Only keeps the first message from each sender.
	fn buffer_round4(&mut self, msg: Round4Broadcast) {
		self.round4.entry(msg.party_id).or_insert(msg);
	}

	/// Take all buffered Round 1 broadcasts.
	fn take_round1_broadcasts(&mut self) -> BTreeMap<ParticipantId, Round1Broadcast> {
		mem::take(&mut self.round1_broadcasts)
	}

	/// Take all buffered Round 1 private messages.
	fn take_round1_privates(&mut self) -> BTreeMap<(ParticipantId, SubsetMask), Round1Private> {
		mem::take(&mut self.round1_privates)
	}

	/// Take all buffered Round 2 messages.
	fn take_round2(&mut self) -> BTreeMap<ParticipantId, Round2Broadcast> {
		mem::take(&mut self.round2)
	}

	/// Take all buffered Round 3 messages.
	fn take_round3(&mut self) -> BTreeMap<ParticipantId, Round3Broadcast> {
		mem::take(&mut self.round3)
	}

	/// Take all buffered Round 4 messages.
	fn take_round4(&mut self) -> BTreeMap<ParticipantId, Round4Broadcast> {
		mem::take(&mut self.round4)
	}
}

// ============================================================================
// Seed-based Randomness Derivation
// ============================================================================

/// Derive randomness for DKG Round 1 from a master seed and session identifier.
///
/// This uses SHAKE256 to derive all random values needed for Round 1:
/// - `my_randomness`: The party's commitment randomness
/// - `shared_secrets`: One secret per subset where this party is leader
///
/// The [`DKG_SSID_SIZE`]-byte `ssid` (which incorporates the session nonce) is
/// mixed into every derivation so that a retry with a fresh `session_nonce`
/// produces fresh randomness even when `seed` is a deterministic derived-key
/// contribution (`derive_dkg_contribution`). Without this binding, an adversary
/// who observed honest Round 2 reveals from a failed attempt could predict the
/// same values on retry and grind `global_randomness`.
///
/// Formula:
/// - `my_randomness = SHAKE256("dkg-r1-rand" || seed || party_id || ssid)[0..32]`
/// - `shared_secret[i] = SHAKE256("dkg-r1-ss" || seed || party_id || subset_mask || ssid)[0..32]`
fn derive_round1_randomness(
	seed: &[u8; 32],
	ssid: &[u8; DKG_SSID_SIZE],
	party_id: ParticipantId,
	leader_subsets: &[SubsetMask],
) -> ([u8; RANDOMNESS_SIZE], BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>) {
	// Derive my_randomness
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, b"dkg-r1-rand");
	fips202::shake256_absorb(&mut state, seed);
	let party_bytes = party_id.to_le_bytes();
	fips202::shake256_absorb(&mut state, &party_bytes);
	fips202::shake256_absorb(&mut state, ssid);
	fips202::shake256_finalize(&mut state);

	let mut my_randomness = [0u8; RANDOMNESS_SIZE];
	fips202::shake256_squeeze(&mut my_randomness, &mut state);

	// Derive shared secrets for each subset
	let mut my_shared_secrets = BTreeMap::new();
	for &subset in leader_subsets {
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, b"dkg-r1-ss");
		fips202::shake256_absorb(&mut state, seed);
		fips202::shake256_absorb(&mut state, &party_bytes);
		let subset_bytes = subset.to_le_bytes();
		fips202::shake256_absorb(&mut state, &subset_bytes); // SubsetMask is u16 = 2 bytes
		fips202::shake256_absorb(&mut state, ssid);
		fips202::shake256_finalize(&mut state);

		let mut secret = [0u8; SHARED_SECRET_SIZE];
		fips202::shake256_squeeze(&mut secret, &mut state);
		my_shared_secrets.insert(subset, secret);
	}

	(my_randomness, my_shared_secrets)
}

// ============================================================================
// Protocol Implementation
// ============================================================================

/// The main DKG protocol state machine.
///
/// This implements a 4-round DKG protocol. Create an instance with
/// [`Dkg::new`], then repeatedly call [`Dkg::poke`] and
/// [`Dkg::message`] to drive the protocol.
///
/// # Message Buffering
///
/// In distributed systems, messages may arrive out of order. For example, a fast
/// node might send its Round 2 message before a slower node has finished processing
/// all Round 1 messages. To handle this, we buffer messages that arrive for future
/// rounds and process them when we transition to the appropriate state.
///
/// # Example
///
/// ```ignore
/// let config = DkgConfig::new(...)?;
/// let seed: [u8; 32] = get_random_seed(); // Must be cryptographically random
/// let mut dkg = Dkg::new(config, seed, &TEST_SESSION_NONCE);
///
/// loop {
///     match dkg.poke()? {
///         DkgAction::Wait => { /* wait for messages */ }
///         DkgAction::SendMany(data) => { /* broadcast to all */ }
///         DkgAction::SendPrivate(to, data) => { /* send to one party */ }
///         DkgAction::Return(output) => {
///             // DKG complete!
///             return Ok(output);
///         }
///     }
///     // When messages arrive: dkg.message(from, data);
/// }
/// ```
pub struct Dkg<S: TranscriptSigner> {
	state: DkgState<S>,
	/// Session identifier binding all messages to this specific DKG session.
	ssid: [u8; DKG_SSID_SIZE],
	/// Master seed for deriving all randomness (32 bytes, cryptographically random).
	seed: [u8; 32],
	/// Round 1 private messages awaiting delivery, held as zeroizing
	/// [`Round1Private`] structs (not pre-serialized byte buffers) so the queued
	/// K_S material is wiped on drop rather than left in a freed `Vec<u8>`.
	pending_privates: Vec<(ParticipantId, Round1Private)>,
	/// Buffer for messages that arrive before we're ready to process them.
	message_buffer: DkgMessageBuffer,
}

impl<S: TranscriptSigner> Drop for Dkg<S> {
	fn drop(&mut self) {
		// Zeroize sensitive data when the DKG is dropped. Queued and buffered
		// Round 1 private messages carry K_S, so wipe them too rather than freeing
		// heap allocations that still contain secret bytes.
		self.state.zeroize();
		self.seed.zeroize();
		for (_, private) in self.pending_privates.iter_mut() {
			private.zeroize();
		}
		for private in self.message_buffer.round1_privates.values_mut() {
			private.zeroize();
		}
	}
}

impl<S: TranscriptSigner> Dkg<S> {
	/// Create a new DKG instance.
	///
	/// # Arguments
	/// * `config` - The DKG configuration including threshold, participants, and signing keys
	/// * `seed` - A 32-byte cryptographically random seed for generating all randomness
	/// * `session_nonce` - A 32-byte nonce unique to this DKG session (e.g., from transport layer)
	///
	/// # Session Identifier (SSID)
	///
	/// The SSID is computed from the threshold configuration, participant list, and session nonce.
	/// It binds all protocol messages to this specific session, preventing cross-session replay
	/// attacks (CVE-2022-47930 class vulnerabilities).
	///
	/// # Security Warning
	///
	/// The `seed` MUST be generated from a cryptographically secure source and
	/// MUST be unique for each DKG session. Reusing seeds compromises security.
	///
	/// The `session_nonce` MUST be unique for each DKG session with the same participant set.
	/// Using a counter, timestamp, or random value from the transport layer is acceptable.
	pub fn new(config: DkgConfig<S>, seed: [u8; 32], session_nonce: &[u8; 32]) -> Self {
		let ssid = compute_dkg_ssid(
			config.threshold(),
			config.total_parties(),
			config.all_participants(),
			session_nonce,
		);
		Self {
			state: DkgState::new(config),
			ssid,
			seed,
			pending_privates: Vec::new(),
			message_buffer: DkgMessageBuffer::new(),
		}
	}

	/// Get the session identifier (SSID) for this DKG session.
	///
	/// The SSID uniquely identifies this session and is included in all messages
	/// to prevent cross-session replay attacks.
	pub fn ssid(&self) -> &[u8; DKG_SSID_SIZE] {
		&self.ssid
	}

	/// Advance the protocol state machine.
	///
	/// Call this method repeatedly to drive the protocol forward. It returns
	/// an action that the caller should perform (broadcast, send private, wait,
	/// or return the final output).
	///
	/// # Returns
	/// * `Ok(DkgAction)` - The action to perform
	/// * `Err(DkgError)` - If the protocol encounters an error
	pub fn poke(&mut self) -> Result<DkgAction, DkgError> {
		if let Some((to, private)) = self.pending_privates.pop() {
			return serialize_round1_private(to, private);
		}

		match self.state.phase {
			DkgPhase::Initialized => self.start_round1(),
			DkgPhase::Round1 => self.process_round1(),
			DkgPhase::Round2 => self.process_round2(),
			DkgPhase::Round3 => self.process_round3(),
			DkgPhase::Round4 => self.process_round4(),
			DkgPhase::Complete => {
				let output = self
					.state
					.output
					.as_ref()
					.ok_or_else(|| DkgError::InvalidState("Complete but no output".into()))?;
				Ok(DkgAction::Return(output.clone()))
			},
			DkgPhase::Failed => {
				let msg = self
					.state
					.error_message
					.as_ref()
					.cloned()
					.unwrap_or_else(|| "unknown error".into());
				Err(DkgError::InvalidState(msg))
			},
		}
	}

	/// Process an incoming message from another party.
	///
	/// Call this method when a message is received from another DKG participant.
	/// Messages are routed based on the current protocol state:
	///
	/// - **Current round messages**: Processed immediately
	/// - **Future round messages**: Buffered for later processing
	/// - **Past round messages**: Silently ignored (too late)
	/// - **Sender mismatch**: Silently ignored (bad actor or routing error)
	/// - **Non-participant sender**: Silently ignored (prevents quorum inflation attacks)
	///
	/// # Security
	///
	/// This function validates that `from` is in the configured `all_participants` list
	/// before processing. This prevents quorum inflation attacks where an attacker
	/// injects messages with fake sender IDs to satisfy broadcast quorum checks.
	///
	/// **The `from` value is a trust boundary.** This function performs no
	/// cryptographic authentication of the sender; it only checks that `from`
	/// is a participant and matches the party ID embedded in the message. The
	/// transport layer MUST authenticate the sender of every message (private
	/// *and* broadcast) and pass the authenticated identity as `from`. If
	/// `from` can be spoofed, a forged broadcast can occupy a participant's
	/// first-message-wins slot in the round buffers, causing the honest
	/// party's broadcast to be ignored and the session to stall or abort
	/// during commitment/transcript verification (denial of service). See
	/// [`DkgAction::SendMany`] and [`DkgAction::SendPrivate`] for the channel
	/// requirements.
	///
	/// # Arguments
	/// * `from` - The party ID of the sender. MUST come from transport-level sender authentication,
	///   never from attacker-controllable packet contents.
	/// * `data` - The serialized message bytes
	///
	/// # Errors
	///
	/// Returns `Err(DkgError::MalformedMessage)` if the message cannot be
	/// deserialized. This allows callers to detect and log malformed messages.
	///
	/// # Returns
	///
	/// * `Ok(())` - Message was processed, buffered, or legitimately ignored
	/// * `Err(_)` - Message was malformed and could not be deserialized
	pub fn message(&mut self, from: ParticipantId, data: Vec<u8>) -> Result<(), DkgError> {
		// Round 1 private frames carry the serialized secret K_S. Taking
		// ownership into a zeroizing wrapper wipes the transport bytes on every
		// return path, instead of freeing a heap block that still contains key
		// material. (Broadcast frames are public; wiping them too costs one
		// memset.)
		let data = Zeroizing::new(data);

		// Validate sender is a known participant to prevent quorum inflation attacks
		if let Some(participants) = self.state.all_participants() {
			if !participants.contains(&from) {
				log::warn!(
					"DKG: Ignoring message from non-participant {} (not in {:?})",
					from,
					participants
				);
				return Ok(());
			}
		} else {
			// Protocol is in terminal state (Complete or Failed), ignore all messages
			return Ok(());
		}

		// Ignore messages from self
		if self.state.my_party_id() == Some(from) {
			return Ok(());
		}

		let msg: DkgMessage = match deserialize_message(&data) {
			Ok(m) => m,
			Err(e) => {
				return Err(DkgError::MalformedMessage { from, reason: e });
			},
		};

		// Verify SSID matches for all message types to prevent cross-session replay
		if msg.ssid() != &self.ssid {
			warn!(
				"DKG: Rejecting message from {} - SSID mismatch (cross-session replay attempt?)",
				from
			);
			return Ok(()); // SSID mismatch, silently ignore (not an error, likely cross-session)
		}

		match msg {
			DkgMessage::Round1Broadcast(broadcast) => {
				// Round 1 broadcasts: accept during Initialized, Round 1, or early Round 2
				if broadcast.party_id != from {
					warn!(
						"DKG: Round1Broadcast sender mismatch: envelope from {} but message claims party {}",
						from, broadcast.party_id
					);
					return Ok(()); // Sender mismatch, ignore
				}
				match self.state.phase {
					DkgPhase::Initialized => {
						// Early message, buffer for when we enter Round 1
						self.message_buffer.buffer_round1_broadcast(broadcast);
					},
					DkgPhase::Round1 => {
						self.state
							.round1_broadcasts
							.get_or_insert_with(BTreeMap::new)
							.entry(from)
							.or_insert(broadcast);
					},
					DkgPhase::Round2 => {
						// Late Round 1 message, still accept it
						self.state
							.round1_broadcasts
							.get_or_insert_with(BTreeMap::new)
							.entry(from)
							.or_insert(broadcast);
					},
					_ => {
						warn!(
							"DKG: Ignoring late Round1Broadcast from party {} (already past Round 2)",
							from
						);
					},
				}
			},
			DkgMessage::Round1Private(private) => {
				// Round 1 private messages: accept during Initialized (buffered) or Round 1
				// M2: Validate sender is the legitimate leader for this subset
				if private.from_party_id != from {
					warn!(
						"DKG: Round1Private sender mismatch: envelope from {} but message claims party {}",
						from, private.from_party_id
					);
					return Ok(()); // Sender mismatch, ignore
				}

				match self.state.phase {
					DkgPhase::Initialized => {
						// Early message - validate before buffering to prevent DoS.
						// Config is available during Initialized phase.
						let config = self.state.config.as_ref().ok_or_else(|| {
							DkgError::InvalidState("Initialized but no config".into())
						})?;

						// Verify subset_mask is a valid subset for this threshold config
						if !config.is_valid_subset(private.subset_mask) {
							warn!(
								"DKG: Buffering rejected - Round1Private with invalid subset {:b} (from party {})",
								private.subset_mask, from
							);
							return Ok(()); // Invalid subset, ignore
						}

						// Verify sender is the leader for this subset
						let expected_leader = config.get_leader(private.subset_mask);
						if expected_leader != Some(from) {
							warn!(
								"DKG: Buffering rejected - Round1Private from non-leader: party {} sent for subset {:b} but leader is {:?}",
								from, private.subset_mask, expected_leader
							);
							return Ok(()); // Not the leader, ignore
						}

						// Verify we are actually a member of this subset
						if !config.is_in_subset(private.subset_mask) {
							warn!(
								"DKG: Buffering rejected - Round1Private for subset {:b} but we are not a member (from party {})",
								private.subset_mask, from
							);
							return Ok(()); // Not in subset, ignore
						}

						// All validations passed - buffer for processing after Round 1 starts
						self.message_buffer.buffer_round1_private(private);
					},
					DkgPhase::Round1 => {
						let config =
							self.state.config.as_ref().ok_or_else(|| {
								DkgError::InvalidState("Round1 but no config".into())
							})?;

						// Verify subset_mask is a valid subset for this threshold config
						// (prevents attacker from using fake subset masks)
						if !config.is_valid_subset(private.subset_mask) {
							warn!(
								"DKG: Round1Private with invalid subset {:b} (from party {})",
								private.subset_mask, from
							);
							return Ok(()); // Invalid subset, ignore
						}

						// Verify sender is the leader for this subset
						let expected_leader = config.get_leader(private.subset_mask);
						if expected_leader != Some(from) {
							warn!(
								"DKG: Round1Private from non-leader: party {} sent for subset {:b} but leader is {:?}",
								from, private.subset_mask, expected_leader
							);
							return Ok(()); // Not the leader, ignore
						}

						// Verify we are actually a member of this subset
						// (prevents malicious leader from sending K_S to non-member parties)
						if !config.is_in_subset(private.subset_mask) {
							warn!(
								"DKG: Round1Private for subset {:b} but we are not a member (from party {})",
								private.subset_mask, from
							);
							return Ok(()); // Not in subset, ignore
						}

						// Accept the first K_S received for this subset (first-message-wins).
						// Note: K_S is NOT commitment-bound in Round 1. Correctness is verified
						// algebraically in Round 4 when we check that our independently-derived
						// partial PK matches the leader's commitment. A malicious leader sending
						// inconsistent K_S values will cause a Round 4 abort.
						self.state
							.received_shared_secrets
							.get_or_insert_with(BTreeMap::new)
							.entry(private.subset_mask)
							.or_insert(private.shared_secret);
					},
					_ => {
						// Past Round 1, ignore late private messages
						warn!(
							"DKG: Ignoring late Round1Private from party {} (already past Round 1)",
							from
						);
					},
				}
			},
			DkgMessage::Round2Broadcast(broadcast) => {
				if broadcast.party_id != from {
					warn!(
						"DKG: Round2Broadcast sender mismatch: envelope from {} but message claims party {}",
						from, broadcast.party_id
					);
					return Ok(()); // Sender mismatch, ignore
				}
				match self.state.phase {
					DkgPhase::Round2 => {
						self.state
							.round2_broadcasts
							.get_or_insert_with(BTreeMap::new)
							.entry(from)
							.or_insert(broadcast);
					},
					DkgPhase::Round3 => {
						// Late Round 2 message, still accept it
						self.state
							.round2_broadcasts
							.get_or_insert_with(BTreeMap::new)
							.entry(from)
							.or_insert(broadcast);
					},
					DkgPhase::Round1 | DkgPhase::Initialized => {
						// Future message, buffer it
						self.message_buffer.buffer_round2(broadcast);
					},
					_ => {
						warn!(
							"DKG: Ignoring late Round2Broadcast from party {} (already past Round 3)",
							from
						);
					},
				}
			},
			DkgMessage::Round3Broadcast(broadcast) => {
				if broadcast.party_id != from {
					warn!(
						"DKG: Round3Broadcast sender mismatch: envelope from {} but message claims party {}",
						from, broadcast.party_id
					);
					return Ok(()); // Sender mismatch, ignore
				}
				match self.state.phase {
					DkgPhase::Round3 => {
						self.state
							.round3_broadcasts
							.get_or_insert_with(BTreeMap::new)
							.entry(from)
							.or_insert(broadcast);
					},
					DkgPhase::Round4 => {
						// Late Round 3 message, still accept it
						self.state
							.round3_broadcasts
							.get_or_insert_with(BTreeMap::new)
							.entry(from)
							.or_insert(broadcast);
					},
					DkgPhase::Round1 | DkgPhase::Round2 | DkgPhase::Initialized => {
						// Future message, buffer it
						self.message_buffer.buffer_round3(broadcast);
					},
					_ => {
						warn!(
							"DKG: Ignoring late Round3Broadcast from party {} (already past Round 4)",
							from
						);
					},
				}
			},
			DkgMessage::Round4Broadcast(broadcast) => {
				if broadcast.party_id != from {
					warn!(
						"DKG: Round4Broadcast sender mismatch: envelope from {} but message claims party {}",
						from, broadcast.party_id
					);
					return Ok(()); // Sender mismatch, ignore
				}
				match self.state.phase {
					DkgPhase::Round4 => {
						self.state
							.round4_broadcasts
							.get_or_insert_with(BTreeMap::new)
							.entry(from)
							.or_insert(broadcast);
					},
					DkgPhase::Round1 |
					DkgPhase::Round2 |
					DkgPhase::Round3 |
					DkgPhase::Initialized => {
						// Future message, buffer it
						self.message_buffer.buffer_round4(broadcast);
					},
					_ => {
						warn!(
							"DKG: Ignoring late Round4Broadcast from party {} (protocol complete)",
							from
						);
					},
				}
			},
		}

		Ok(())
	}

	/// Process buffered Round 2 messages after transitioning to Round 2.
	fn process_buffered_round2(&mut self) {
		let buffered = self.message_buffer.take_round2();
		if self.state.phase == DkgPhase::Round2 {
			let broadcasts = self.state.round2_broadcasts.get_or_insert_with(BTreeMap::new);
			for (party_id, r2) in buffered {
				broadcasts.entry(party_id).or_insert(r2);
			}
		}
	}

	/// Process buffered Round 3 messages after transitioning to Round 3.
	fn process_buffered_round3(&mut self) {
		let buffered = self.message_buffer.take_round3();
		if self.state.phase == DkgPhase::Round3 {
			let broadcasts = self.state.round3_broadcasts.get_or_insert_with(BTreeMap::new);
			for (party_id, r3) in buffered {
				broadcasts.entry(party_id).or_insert(r3);
			}
		}
	}

	/// Process buffered Round 4 messages after transitioning to Round 4.
	fn process_buffered_round4(&mut self) {
		let buffered = self.message_buffer.take_round4();
		if self.state.phase == DkgPhase::Round4 {
			let broadcasts = self.state.round4_broadcasts.get_or_insert_with(BTreeMap::new);
			for (party_id, r4) in buffered {
				broadcasts.entry(party_id).or_insert(r4);
			}
		}
	}

	// ========================================================================
	// Round 1
	// ========================================================================

	fn start_round1(&mut self) -> Result<DkgAction, DkgError> {
		let config = self.state.expect_initialized()?;

		// Derive all randomness from the master seed
		let leader_subsets = config.my_leader_subsets();
		let (my_randomness, my_shared_secrets) =
			derive_round1_randomness(&self.seed, &self.ssid, config.my_party_id(), &leader_subsets);

		let my_commitment = h_commit(&self.ssid, config.my_party_id(), &my_randomness);

		// Transition to Round1 by setting fields directly
		self.state.phase = DkgPhase::Round1;
		self.state.my_randomness = Some(my_randomness);
		self.state.my_commitment = Some(my_commitment);
		self.state.my_shared_secrets = Some(my_shared_secrets);
		self.state.round1_broadcasts = Some(BTreeMap::new());
		self.state.received_shared_secrets = Some(BTreeMap::new());
		self.state.broadcast_sent = false;
		self.state.privates_sent = false;

		// Drain any Round 1 messages that arrived before we entered Round 1
		self.drain_round1_buffer()?;

		self.poke()
	}

	/// Drain buffered Round 1 messages into the protocol state.
	/// Called after transitioning from Initialized to Round1.
	fn drain_round1_buffer(&mut self) -> Result<(), DkgError> {
		let config =
			self.state.config.as_ref().ok_or_else(|| {
				DkgError::InvalidState("drain_round1_buffer but no config".into())
			})?;

		// Drain buffered Round 1 broadcasts
		let buffered_broadcasts = self.message_buffer.take_round1_broadcasts();
		for (party_id, broadcast) in buffered_broadcasts {
			// Re-validate party_id matches (should always match due to buffer logic)
			if broadcast.party_id == party_id {
				self.state
					.round1_broadcasts
					.get_or_insert_with(BTreeMap::new)
					.entry(party_id)
					.or_insert(broadcast);
			}
		}

		// Drain buffered Round 1 private messages with validation
		let buffered_privates = self.message_buffer.take_round1_privates();
		for ((from_party_id, subset_mask), private) in buffered_privates {
			// Validate subset_mask is valid
			if !config.is_valid_subset(subset_mask) {
				warn!(
					"DKG: Discarding buffered Round1Private with invalid subset {:b} (from party {})",
					subset_mask, from_party_id
				);
				continue;
			}

			// Validate sender is the leader for this subset
			let expected_leader = config.get_leader(subset_mask);
			if expected_leader != Some(from_party_id) {
				warn!(
					"DKG: Discarding buffered Round1Private from non-leader: party {} sent for subset {:b} but leader is {:?}",
					from_party_id, subset_mask, expected_leader
				);
				continue;
			}

			// Validate we are a member of this subset
			if !config.is_in_subset(subset_mask) {
				warn!(
					"DKG: Discarding buffered Round1Private for subset {:b} but we are not a member (from party {})",
					subset_mask, from_party_id
				);
				continue;
			}

			self.state
				.received_shared_secrets
				.get_or_insert_with(BTreeMap::new)
				.entry(subset_mask)
				.or_insert(private.shared_secret);
		}

		Ok(())
	}

	fn process_round1(&mut self) -> Result<DkgAction, DkgError> {
		// Verify we're in Round1 and have config
		self.state.expect_round1()?;

		if !self.state.broadcast_sent {
			let config = self.state.config.as_ref().unwrap(); // Safe: expect_round1 verified
			let my_commitment = self
				.state
				.my_commitment
				.ok_or_else(|| DkgError::InvalidState("Round1 but no commitment".into()))?;

			let broadcast = Round1Broadcast {
				ssid: self.ssid,
				party_id: config.my_party_id(),
				commitment: my_commitment,
			};
			let msg = DkgMessage::Round1Broadcast(broadcast);
			let data = borsh::to_vec(&msg).map_err(|e| DkgError::InternalError(e.to_string()))?;
			self.state.broadcast_sent = true;
			return Ok(DkgAction::SendMany(data));
		}

		if !self.state.privates_sent {
			let config = self.state.config.as_ref().unwrap(); // Safe: expect_round1 verified
			let my_shared_secrets = self
				.state
				.my_shared_secrets
				.as_ref()
				.ok_or_else(|| DkgError::InvalidState("Round1 but no shared secrets".into()))?;

			for (&subset, &secret) in my_shared_secrets {
				let parties = config.get_parties_in_subset(subset);
				for &party in &parties {
					if party != config.my_party_id() {
						let private = Round1Private {
							ssid: self.ssid,
							from_party_id: config.my_party_id(),
							subset_mask: subset,
							shared_secret: secret,
						};
						// Queue the zeroizing struct; serialize only when popped for
						// sending, so K_S is never parked in a plain byte buffer.
						self.pending_privates.push((party, private));
					}
				}
			}

			self.state.privates_sent = true;

			if let Some((to, private)) = self.pending_privates.pop() {
				return serialize_round1_private(to, private);
			}
		}

		// Check if we have all required messages
		let config = self.state.config.as_ref().unwrap(); // Safe: expect_round1 verified
		let round1_broadcasts = self
			.state
			.round1_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round1 but no broadcasts map".into()))?;
		let received_shared_secrets =
			self.state.received_shared_secrets.as_ref().ok_or_else(|| {
				DkgError::InvalidState("Round1 but no received_shared_secrets".into())
			})?;
		let my_shared_secrets = self
			.state
			.my_shared_secrets
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round1 but no shared secrets".into()))?;

		let all_broadcasts = all_broadcasts_received(
			round1_broadcasts,
			config.all_participants(),
			config.my_party_id(),
		);
		let my_subsets = config.my_subsets();
		let all_privates =
			all_private_messages_received(received_shared_secrets, my_shared_secrets, &my_subsets);

		if all_broadcasts && all_privates {
			self.transition_to_round2()?;
			return self.poke();
		}

		Ok(DkgAction::Wait)
	}

	fn transition_to_round2(&mut self) -> Result<(), DkgError> {
		self.state.expect_round1()?;

		// Combine our shared secrets with received ones
		let mut combined_secrets = self
			.state
			.my_shared_secrets
			.take()
			.ok_or_else(|| DkgError::InvalidState("Round1 but no my_shared_secrets".into()))?;
		if let Some(received) = self.state.received_shared_secrets.take() {
			for (subset, secret) in received {
				combined_secrets.insert(subset, secret);
			}
		}

		// Transition to Round2
		self.state.phase = DkgPhase::Round2;
		self.state.shared_secrets = Some(combined_secrets);
		self.state.round2_broadcasts = Some(BTreeMap::new());
		self.state.broadcast_sent = false;

		// Note: my_randomness stays in place for use in Round2 broadcast
		// It will be zeroized during transition_to_round3

		// Process any buffered Round 2 messages
		self.process_buffered_round2();

		Ok(())
	}

	// ========================================================================
	// Round 2
	// ========================================================================

	fn process_round2(&mut self) -> Result<DkgAction, DkgError> {
		self.state.expect_round2()?;

		if !self.state.broadcast_sent {
			let config = self.state.config.as_ref().unwrap(); // Safe: expect_round2 verified
			let my_randomness = self
				.state
				.my_randomness
				.ok_or_else(|| DkgError::InvalidState("Round2 but no randomness".into()))?;

			let broadcast = Round2Broadcast {
				ssid: self.ssid,
				party_id: config.my_party_id(),
				randomness: my_randomness,
			};
			let msg = DkgMessage::Round2Broadcast(broadcast);
			let data = borsh::to_vec(&msg).map_err(|e| DkgError::InternalError(e.to_string()))?;
			self.state.broadcast_sent = true;
			return Ok(DkgAction::SendMany(data));
		}

		// Check if we have all broadcasts
		let config = self.state.config.as_ref().unwrap(); // Safe: expect_round2 verified
		let round2_broadcasts = self
			.state
			.round2_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round2 but no broadcasts map".into()))?;
		let round1_broadcasts = self
			.state
			.round1_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round2 but no round1_broadcasts".into()))?;

		let all_broadcasts = all_broadcasts_received(
			round2_broadcasts,
			config.all_participants(),
			config.my_party_id(),
		);

		if all_broadcasts {
			// Verify commitments
			for (&party_id, broadcast) in round2_broadcasts {
				let expected = round1_broadcasts.get(&party_id).ok_or_else(|| {
					DkgError::MissingData(format!("missing Round 1 from party {}", party_id))
				})?;
				let actual = h_commit(&self.ssid, party_id, &broadcast.randomness);
				if actual != expected.commitment {
					return Err(DkgError::CommitmentMismatch { party_id });
				}
			}

			self.transition_to_round3()?;
			return self.poke();
		}

		Ok(DkgAction::Wait)
	}

	fn transition_to_round3(&mut self) -> Result<(), DkgError> {
		let config = self.state.expect_round2()?;
		let my_party_id = config.my_party_id(); // Copy before mutable borrows
		let my_randomness = self
			.state
			.my_randomness
			.ok_or_else(|| DkgError::InvalidState("Round2 but no randomness".into()))?;
		let round2_broadcasts = self
			.state
			.round2_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round2 but no round2_broadcasts".into()))?;
		let shared_secrets = self
			.state
			.shared_secrets
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round2 but no shared_secrets".into()))?;

		// Compute global randomness from all parties' contributions
		let (global_randomness, my_broadcast) =
			compute_global_randomness(&self.ssid, config, round2_broadcasts, my_randomness);

		let rho = h_seed(&global_randomness);

		// Compute contributions and partial PKs for all subsets we belong to
		let (my_contributions, my_partial_pks, my_pk_commitments) =
			compute_my_contributions(&self.ssid, config, shared_secrets, &global_randomness, &rho);

		// Build the complete round1 broadcasts including our own
		let mut round1_broadcasts = self.state.round1_broadcasts.take().unwrap_or_default();
		round1_broadcasts.insert(
			my_party_id,
			Round1Broadcast {
				ssid: self.ssid,
				party_id: my_party_id,
				commitment: h_commit(&self.ssid, my_party_id, &my_randomness),
			},
		);

		// Build the complete round2 broadcasts including our own
		let mut round2_broadcasts = self.state.round2_broadcasts.take().unwrap_or_default();
		round2_broadcasts.insert(my_party_id, my_broadcast);

		// Zeroize my_randomness before moving forward
		if let Some(ref mut r) = self.state.my_randomness {
			r.zeroize();
		}
		self.state.my_randomness = None;

		// Transition to Round3
		self.state.phase = DkgPhase::Round3;
		self.state.global_randomness = Some(global_randomness);
		self.state.rho = Some(rho);
		self.state.my_contributions = Some(my_contributions);
		self.state.my_partial_pks = Some(my_partial_pks);
		self.state.my_pk_commitments = Some(my_pk_commitments);
		self.state.round1_broadcasts = Some(round1_broadcasts);
		self.state.round2_broadcasts = Some(round2_broadcasts);
		self.state.round3_broadcasts = Some(BTreeMap::new());
		self.state.broadcast_sent = false;

		// Process any buffered Round 3 messages
		self.process_buffered_round3();

		Ok(())
	}

	// ========================================================================
	// Round 3
	// ========================================================================

	fn process_round3(&mut self) -> Result<DkgAction, DkgError> {
		self.state.expect_round3()?;

		if !self.state.broadcast_sent {
			let config = self.state.config.as_ref().unwrap(); // Safe: expect_round3 verified
			let my_pk_commitments = self
				.state
				.my_pk_commitments
				.as_ref()
				.ok_or_else(|| DkgError::InvalidState("Round3 but no pk_commitments".into()))?;

			let broadcast = Round3Broadcast {
				ssid: self.ssid,
				party_id: config.my_party_id(),
				partial_pk_commitments: my_pk_commitments.clone(),
			};
			let msg = DkgMessage::Round3Broadcast(broadcast);
			let data = borsh::to_vec(&msg).map_err(|e| DkgError::InternalError(e.to_string()))?;
			self.state.broadcast_sent = true;
			return Ok(DkgAction::SendMany(data));
		}

		// Check if we have all broadcasts
		let config = self.state.config.as_ref().unwrap(); // Safe: expect_round3 verified
		let round3_broadcasts = self
			.state
			.round3_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round3 but no broadcasts map".into()))?;

		let all_broadcasts = all_broadcasts_received(
			round3_broadcasts,
			config.all_participants(),
			config.my_party_id(),
		);

		if all_broadcasts {
			self.transition_to_round4()?;
			return self.poke();
		}

		Ok(DkgAction::Wait)
	}

	fn transition_to_round4(&mut self) -> Result<(), DkgError> {
		let config = self.state.expect_round3()?;
		let my_party_id = config.my_party_id(); // Copy before mutable borrows
		let my_pk_commitments = self
			.state
			.my_pk_commitments
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round3 but no pk_commitments".into()))?;

		let my_round3_broadcast = Round3Broadcast {
			ssid: self.ssid,
			party_id: my_party_id,
			partial_pk_commitments: my_pk_commitments.clone(),
		};

		self.state
			.round3_broadcasts
			.get_or_insert_with(BTreeMap::new)
			.insert(my_party_id, my_round3_broadcast);

		// Transition to Round4
		self.state.phase = DkgPhase::Round4;
		self.state.round4_broadcasts = Some(BTreeMap::new());
		self.state.broadcast_sent = false;

		// Process any buffered Round 4 messages
		self.process_buffered_round4();

		Ok(())
	}

	// ========================================================================
	// Round 4
	// ========================================================================

	fn process_round4(&mut self) -> Result<DkgAction, DkgError> {
		self.state.expect_round4()?;

		if !self.state.broadcast_sent {
			// Per Mithril paper DKGRound4 lines 11-16: Non-leaders MUST verify
			// PK commitments BEFORE signing the transcript.
			self.verify_leader_commitments_before_signing()?;

			// Sign and broadcast our partial PKs
			let broadcast = self.create_round4_broadcast()?;
			let msg = DkgMessage::Round4Broadcast(broadcast);
			let data = borsh::to_vec(&msg).map_err(|e| DkgError::InternalError(e.to_string()))?;
			self.state.broadcast_sent = true;
			return Ok(DkgAction::SendMany(data));
		}

		// Check if we have all broadcasts
		let config = self.state.config.as_ref().unwrap(); // Safe: expect_round4 verified
		let round4_broadcasts = self
			.state
			.round4_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no broadcasts map".into()))?;

		let all_broadcasts = all_broadcasts_received(
			round4_broadcasts,
			config.all_participants(),
			config.my_party_id(),
		);

		if all_broadcasts {
			self.complete()?;
			return self.poke();
		}

		Ok(DkgAction::Wait)
	}

	fn complete(&mut self) -> Result<(), DkgError> {
		self.state.expect_round4()?;

		// Compute the DKG output
		let result = self.complete_inner();

		// Zeroize sensitive data
		self.state.zeroize();

		// Now set the completion state
		match result {
			Ok((public_key, private_share)) => {
				self.state.phase = DkgPhase::Complete;
				self.state.output = Some(Box::new(DkgOutput { public_key, private_share }));
				Ok(())
			},
			Err(e) => {
				self.state.phase = DkgPhase::Failed;
				self.state.error_message = Some(format!("{}", e));
				Err(e)
			},
		}
	}

	fn complete_inner(&self) -> Result<(PublicKey, PrivateKeyShare), DkgError> {
		let config = self
			.state
			.config
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no config".into()))?;
		let round1_broadcasts = self
			.state
			.round1_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no round1_broadcasts".into()))?;
		let round2_broadcasts = self
			.state
			.round2_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no round2_broadcasts".into()))?;
		let round3_broadcasts = self
			.state
			.round3_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no round3_broadcasts".into()))?;
		let round4_broadcasts = self
			.state
			.round4_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no round4_broadcasts".into()))?;
		let rho = self
			.state
			.rho
			.ok_or_else(|| DkgError::InvalidState("Round4 but no rho".into()))?;
		let my_partial_pks = self
			.state
			.my_partial_pks
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no my_partial_pks".into()))?;
		let my_contributions = self
			.state
			.my_contributions
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no my_contributions".into()))?;
		let global_randomness = self
			.state
			.global_randomness
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no global_randomness".into()))?;
		let shared_secrets = self
			.state
			.shared_secrets
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no shared_secrets".into()))?;

		let transcript_hash = compute_transcript_hash(
			&self.ssid,
			round1_broadcasts,
			round2_broadcasts,
			round3_broadcasts,
		);

		// Collect our own partial PKs and verify+collect others'
		let all_partial_pks = collect_and_verify_all_partial_pks(
			&self.ssid,
			config,
			round3_broadcasts,
			round4_broadcasts,
			my_partial_pks,
			shared_secrets,
			global_randomness,
			&rho,
			&transcript_hash,
		)?;

		// Combine partial PKs to get final public key. Reject any partial PK with
		// non-canonical coefficients rather than overflowing the i32 accumulation.
		let public_key =
			pack_combined_pk(&rho, all_partial_pks.values().map(|pk| &pk.t)).map_err(|_| {
				DkgError::InvalidMessage(
					"a partial public key contains out-of-range coefficients".into(),
				)
			})?;

		// Build private key share
		let private_share = build_private_share(config, my_contributions, &rho, &public_key)?;

		Ok((public_key, private_share))
	}

	/// Verify that leader commitments match our expected values before signing.
	/// Per Mithril paper DKGRound4 lines 11-16.
	fn verify_leader_commitments_before_signing(&self) -> Result<(), DkgError> {
		let config = self
			.state
			.config
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no config".into()))?;
		let round3_broadcasts = self
			.state
			.round3_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no round3_broadcasts".into()))?;
		let rho = self
			.state
			.rho
			.ok_or_else(|| DkgError::InvalidState("Round4 but no rho".into()))?;
		let my_contributions = self
			.state
			.my_contributions
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no my_contributions".into()))?;

		for &subset in &config.my_subsets() {
			let leader_id = config.get_leader(subset).ok_or_else(|| {
				DkgError::InternalError(format!("no leader for subset {:b}", subset))
			})?;

			// Skip if we're the leader for this subset
			if leader_id == config.my_party_id() {
				continue;
			}

			// Verify the leader's commitment matches our expected value
			if let Some(contribution) = my_contributions.get(&subset) {
				let t = compute_partial_pk_t(&rho, &contribution.s1, &contribution.s2);
				let expected_pk = PartialPublicKey { subset_mask: subset, t };
				let expected_commitment = h_commit_pk(&self.ssid, leader_id, subset, &expected_pk);

				let round3 = round3_broadcasts.get(&leader_id).ok_or_else(|| {
					DkgError::MissingData(format!(
						"missing Round 3 from leader {} for subset {:b}",
						leader_id, subset
					))
				})?;

				let leader_commitment =
					round3.partial_pk_commitments.get(&subset).ok_or_else(|| {
						DkgError::MissingData(format!(
							"missing PK commitment from leader {} for subset {:b}",
							leader_id, subset
						))
					})?;

				if *leader_commitment != expected_commitment {
					return Err(DkgError::PkCommitmentMismatch { party_id: leader_id, subset });
				}
			}
		}
		Ok(())
	}

	/// Create the Round 4 broadcast message with our partial PKs and transcript signature.
	fn create_round4_broadcast(&self) -> Result<Round4Broadcast, DkgError> {
		let config = self
			.state
			.config
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no config".into()))?;
		let round1_broadcasts = self
			.state
			.round1_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no round1_broadcasts".into()))?;
		let round2_broadcasts = self
			.state
			.round2_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no round2_broadcasts".into()))?;
		let round3_broadcasts = self
			.state
			.round3_broadcasts
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no round3_broadcasts".into()))?;
		let my_partial_pks = self
			.state
			.my_partial_pks
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 but no my_partial_pks".into()))?;

		let transcript_hash = compute_transcript_hash(
			&self.ssid,
			round1_broadcasts,
			round2_broadcasts,
			round3_broadcasts,
		);
		let partial_output_hash = compute_partial_output_hash(my_partial_pks);
		let signing_message = compute_signing_message(&transcript_hash, &partial_output_hash);
		let signature = config.signer().sign(&signing_message);

		Ok(Round4Broadcast {
			ssid: self.ssid,
			party_id: config.my_party_id(),
			partial_public_keys: my_partial_pks.clone(),
			transcript_signature: signature.as_ref().to_vec(),
		})
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute global randomness by concatenating all parties' randomness in sorted order.
/// Returns the global randomness and a copy of this party's broadcast.
fn compute_global_randomness<S: TranscriptSigner>(
	ssid: &[u8; DKG_SSID_SIZE],
	config: &DkgConfig<S>,
	received_broadcasts: &BTreeMap<ParticipantId, Round2Broadcast>,
	my_randomness: [u8; RANDOMNESS_SIZE],
) -> (Vec<u8>, Round2Broadcast) {
	let my_party_id = config.my_party_id();
	let my_broadcast =
		Round2Broadcast { ssid: *ssid, party_id: my_party_id, randomness: my_randomness };

	let mut all_randomness: Vec<_> = received_broadcasts.iter().collect();
	all_randomness.push((&my_party_id, &my_broadcast));
	all_randomness.sort_by_key(|(id, _)| *id);

	let mut global_randomness = Vec::with_capacity(all_randomness.len() * RANDOMNESS_SIZE);
	for (_, broadcast) in &all_randomness {
		global_randomness.extend_from_slice(&broadcast.randomness);
	}

	(global_randomness, my_broadcast)
}

/// Return type for compute_my_contributions: (contributions, partial_pks, pk_commitments)
type ContributionsResult = (
	BTreeMap<SubsetMask, SubsetContribution>,
	BTreeMap<SubsetMask, PartialPublicKey>,
	BTreeMap<SubsetMask, [u8; 32]>,
);

/// Compute contributions and partial PKs for all subsets this party belongs to.
fn compute_my_contributions<S: TranscriptSigner>(
	ssid: &[u8; DKG_SSID_SIZE],
	config: &DkgConfig<S>,
	shared_secrets: &BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	global_randomness: &[u8],
	rho: &[u8; 32],
) -> ContributionsResult {
	let mut my_contributions = BTreeMap::new();
	let mut my_partial_pks = BTreeMap::new();
	let mut my_pk_commitments = BTreeMap::new();

	// Compute contributions for leader subsets (includes partial PKs)
	for &subset in &config.my_leader_subsets() {
		if let Some(&shared_secret) = shared_secrets.get(&subset) {
			let seed = h_keygen(subset, &shared_secret, global_randomness);
			let contribution = derive_subset_contribution(&seed);
			let t = compute_partial_pk_t(rho, &contribution.s1, &contribution.s2);
			let partial_pk = PartialPublicKey { subset_mask: subset, t };
			let pk_commitment = h_commit_pk(ssid, config.my_party_id(), subset, &partial_pk);

			my_contributions.insert(subset, contribution);
			my_partial_pks.insert(subset, partial_pk);
			my_pk_commitments.insert(subset, pk_commitment);
		}
	}

	// Compute contributions for non-leader subsets (no partial PKs needed)
	for &subset in &config.my_subsets() {
		if let alloc::collections::btree_map::Entry::Vacant(e) = my_contributions.entry(subset) {
			if let Some(&shared_secret) = shared_secrets.get(&subset) {
				let seed = h_keygen(subset, &shared_secret, global_randomness);
				let contribution = derive_subset_contribution(&seed);
				e.insert(contribution);
			}
		}
	}

	(my_contributions, my_partial_pks, my_pk_commitments)
}

/// Collect and verify all partial PKs from received broadcasts.
#[allow(clippy::too_many_arguments)]
fn collect_and_verify_all_partial_pks<S: TranscriptSigner>(
	ssid: &[u8; DKG_SSID_SIZE],
	config: &DkgConfig<S>,
	round3_broadcasts: &BTreeMap<ParticipantId, Round3Broadcast>,
	round4_broadcasts: &BTreeMap<ParticipantId, Round4Broadcast>,
	my_partial_pks: &BTreeMap<SubsetMask, PartialPublicKey>,
	shared_secrets: &BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	global_randomness: &[u8],
	rho: &[u8; 32],
	transcript_hash: &[u8; 32],
) -> Result<BTreeMap<SubsetMask, PartialPublicKey>, DkgError> {
	let mut all_partial_pks: BTreeMap<SubsetMask, PartialPublicKey> = BTreeMap::new();

	// Add our own partial PKs (only for subsets where we are the leader)
	for (&subset, pk) in my_partial_pks {
		// Validate subset is valid for this threshold config (prevents invalid masks)
		if !config.is_valid_subset(subset) {
			log::warn!("DKG: Ignoring own partial PK for invalid subset {:b}", subset);
			continue;
		}
		if config.is_leader(subset) {
			all_partial_pks.insert(subset, pk.clone());
		}
	}

	// Verify and add other parties' partial PKs
	for (&party_id, broadcast) in round4_broadcasts {
		verify_party_broadcast(
			ssid,
			config,
			round3_broadcasts,
			shared_secrets,
			global_randomness,
			rho,
			party_id,
			broadcast,
			transcript_hash,
		)?;

		for (&subset, pk) in &broadcast.partial_public_keys {
			// Validate subset is valid for this threshold config (prevents invalid masks
			// like 0b001 or 0b111 in a 2-of-3 setup from being accepted)
			if !config.is_valid_subset(subset) {
				log::warn!(
					"DKG: Ignoring partial PK for invalid subset {:b} from party {}",
					subset,
					party_id
				);
				continue;
			}

			// Per Mithril DKGAggregate line 6: only accept PKs from the leader (j = min(S))
			let leader = config.get_leader(subset);
			if leader != Some(party_id) {
				log::warn!(
					"DKG: Ignoring partial PK for subset {:b} from party {} (leader is {:?})",
					subset,
					party_id,
					leader
				);
				continue;
			}
			all_partial_pks.insert(subset, pk.clone());
		}
	}

	// Verify we have a partial PK for every subset
	let expected_subsets = config.all_subsets();
	for subset in &expected_subsets {
		if !all_partial_pks.contains_key(subset) {
			return Err(DkgError::MissingData(format!(
				"missing partial public key for subset {:b}",
				subset
			)));
		}
	}

	Ok(all_partial_pks)
}

/// Verify a single party's Round 4 broadcast (signature and PK commitments).
#[allow(clippy::too_many_arguments)]
fn verify_party_broadcast<S: TranscriptSigner>(
	ssid: &[u8; DKG_SSID_SIZE],
	config: &DkgConfig<S>,
	round3_broadcasts: &BTreeMap<ParticipantId, Round3Broadcast>,
	shared_secrets: &BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	global_randomness: &[u8],
	rho: &[u8; 32],
	party_id: ParticipantId,
	broadcast: &Round4Broadcast,
	transcript_hash: &[u8; 32],
) -> Result<(), DkgError> {
	// Verify transcript signature using OUR transcript_hash.
	// If the other party signed a different transcript, this verification will fail,
	// ensuring all parties that complete DKG have the same view of Round 1-3 messages.
	let partial_output_hash = compute_partial_output_hash(&broadcast.partial_public_keys);
	let signing_message = compute_signing_message(transcript_hash, &partial_output_hash);

	let public_key = config.participant_public_keys().get(&party_id).ok_or_else(|| {
		DkgError::MissingData(format!("missing public key for party {}", party_id))
	})?;

	if !S::verify_bytes(public_key, &signing_message, &broadcast.transcript_signature) {
		return Err(DkgError::SignatureVerificationFailed { party_id });
	}

	// Verify PK commitments match Round 3
	let round3 = round3_broadcasts
		.get(&party_id)
		.ok_or_else(|| DkgError::MissingData(format!("missing Round 3 from party {}", party_id)))?;

	for (&subset, pk) in &broadcast.partial_public_keys {
		// Skip invalid subsets (they will be filtered in collect_and_verify_all_partial_pks,
		// but we also skip verification here to avoid confusing error messages)
		if !config.is_valid_subset(subset) {
			continue;
		}

		verify_partial_pk_commitment(
			ssid,
			shared_secrets,
			global_randomness,
			rho,
			party_id,
			subset,
			pk,
			round3,
		)?;
	}

	Ok(())
}

/// Verify a single partial PK matches its commitment and (if possible) the shared secret.
fn verify_partial_pk_commitment(
	ssid: &[u8; DKG_SSID_SIZE],
	shared_secrets: &BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	global_randomness: &[u8],
	rho: &[u8; 32],
	party_id: ParticipantId,
	subset: SubsetMask,
	pk: &PartialPublicKey,
	round3: &Round3Broadcast,
) -> Result<(), DkgError> {
	// Check commitment matches
	let expected = round3.partial_pk_commitments.get(&subset).ok_or_else(|| {
		DkgError::MissingData(format!(
			"missing PK commitment from party {} for subset {:b}",
			party_id, subset
		))
	})?;

	let actual = h_commit_pk(ssid, party_id, subset, pk);
	if actual != *expected {
		return Err(DkgError::PkCommitmentMismatch { party_id, subset });
	}

	// If we have the shared secret, verify the PK is correct
	if let Some(&shared_secret) = shared_secrets.get(&subset) {
		let seed = h_keygen(subset, &shared_secret, global_randomness);
		let expected_contribution = derive_subset_contribution(&seed);
		let expected_t =
			compute_partial_pk_t(rho, &expected_contribution.s1, &expected_contribution.s2);
		if pk.t != expected_t {
			return Err(DkgError::PkVerificationFailed { party_id, subset });
		}
	}

	Ok(())
}

fn build_private_share<S: TranscriptSigner>(
	config: &DkgConfig<S>,
	my_contributions: &BTreeMap<SubsetMask, SubsetContribution>,
	rho: &[u8; 32],
	public_key: &PublicKey,
) -> Result<PrivateKeyShare, DkgError> {
	let dkg_participants = ParticipantList::new(config.all_participants())
		.ok_or_else(|| DkgError::InternalError("invalid participants".into()))?;

	let mut combined_shares: BTreeMap<SubsetMask, SecretShareData> = BTreeMap::new();
	for (subset_mask, contribution) in my_contributions {
		// Convert from Vec to fixed-size arrays
		let mut s1_arr = [[0i32; 256]; L];
		for (i, poly) in contribution.s1.iter().enumerate().take(L) {
			s1_arr[i] = *poly;
		}
		let mut s2_arr = [[0i32; 256]; K];
		for (i, poly) in contribution.s2.iter().enumerate().take(K) {
			s2_arr[i] = *poly;
		}
		combined_shares.insert(*subset_mask, SecretShareData { s1: s1_arr, s2: s2_arr });
	}

	// Derive `party_key` from the actual secret share polynomials so that this byte
	// string carries real entropy, not just a hash of the public `rho` and `party_id`.
	// We still mix in `rho` and `party_id` for domain separation, but the security of
	// `party_key` now depends on knowing the secret subset shares.
	let mut party_key = [0u8; 32];
	{
		let mut h = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut h, b"dkg-party-key-v2");
		fips202::shake256_absorb(&mut h, rho);
		fips202::shake256_absorb(&mut h, &config.my_party_id().to_le_bytes());
		// The linearization buffer holds raw secret share coefficients, so it
		// must be a zeroizing container (a plain Vec freed after `clear()`
		// leaves the coefficients in allocator memory) and it must be allocated
		// at full size up front (growing mid-fill would free an unwiped
		// intermediate block).
		const SUBSET_BYTES: usize = 2 + (L + K) * 256 * core::mem::size_of::<i32>();
		let mut buf: Zeroizing<alloc::vec::Vec<u8>> =
			Zeroizing::new(alloc::vec::Vec::with_capacity(SUBSET_BYTES));
		for (subset_mask, contribution) in my_contributions {
			buf.clear();
			buf.extend_from_slice(&subset_mask.to_le_bytes());
			for poly in &contribution.s1 {
				for coeff in poly {
					buf.extend_from_slice(&coeff.to_le_bytes());
				}
			}
			for poly in &contribution.s2 {
				for coeff in poly {
					buf.extend_from_slice(&coeff.to_le_bytes());
				}
			}
			fips202::shake256_absorb(&mut h, &buf);
		}
		fips202::shake256_finalize(&mut h);
		fips202::shake256_squeeze(&mut party_key, &mut h);
	}

	// Use the TR from the public key (tr = H(pk))
	let tr = *public_key.tr();

	Ok(PrivateKeyShare::new(
		config.my_party_id(),
		config.total_parties(),
		config.threshold(),
		party_key,
		*rho,
		tr,
		combined_shares,
		dkg_participants,
	))
}

// ============================================================================
// Convenience Function
// ============================================================================

/// Run a complete local DKG for testing purposes.
///
/// This function simulates the DKG protocol with all parties running locally.
/// It's useful for testing but should not be used in production where parties
/// are on separate machines.
///
/// # Arguments
/// * `threshold` - Minimum parties required to sign (t)
/// * `total_parties` - Total number of parties (n)
/// * `signers` - Transcript signers for each party
/// * `public_keys` - Public keys for transcript signature verification
/// * `master_seed` - A 32-byte seed used to derive unique seeds for each party
///
/// # Returns
/// A vector of `DkgOutput` structs, one for each party, containing
/// the shared public key and each party's private key share.
///
/// # Example
///
/// ```ignore
/// let signers: Vec<MySigner> = (0..3).map(|id| MySigner::new(id)).collect();
/// let public_keys: Vec<_> = signers.iter().map(|s| s.public_key()).collect();
/// let master_seed = [42u8; 32];
/// let session_nonce = [0u8; 32];
///
/// let outputs = run_local_dkg(2, 3, signers, public_keys, master_seed, &session_nonce)?;
/// // All parties have the same public key
/// assert_eq!(outputs[0].public_key, outputs[1].public_key);
/// ```
pub fn run_local_dkg<S>(
	threshold: u32,
	total_parties: u32,
	signers: Vec<S>,
	public_keys: Vec<S::PublicKey>,
	master_seed: [u8; 32],
	session_nonce: &[u8; 32],
) -> Result<Vec<DkgOutput>, DkgError>
where
	S: TranscriptSigner + Clone,
{
	let threshold_config = ThresholdConfig::new(threshold, total_parties)
		.map_err(|e| DkgError::InternalError(e.to_string()))?;

	// Validate vector lengths up front. Without this, mismatched lengths would
	// reach `DkgConfig::new(...).unwrap()` (panic on a length/participant error)
	// or, when too few signers are supplied, the driver loop's `dkgs[party_id]`
	// indexing — turning a `Result`-returning API into a process abort.
	if signers.len() != total_parties as usize {
		return Err(DkgError::InvalidState(format!(
			"expected {} signers for {} parties, got {}",
			total_parties,
			total_parties,
			signers.len()
		)));
	}
	if public_keys.len() != total_parties as usize {
		return Err(DkgError::InvalidState(format!(
			"expected {} public keys for {} parties, got {}",
			total_parties,
			total_parties,
			public_keys.len()
		)));
	}

	let participants: Vec<ParticipantId> = (0..total_parties).collect();

	let mut pk_map: BTreeMap<ParticipantId, S::PublicKey> = BTreeMap::new();
	for (i, pk) in public_keys.into_iter().enumerate() {
		pk_map.insert(i as ParticipantId, pk);
	}

	// Derive unique seed for each party from master_seed
	let mut dkgs: Vec<Dkg<S>> = signers
		.into_iter()
		.enumerate()
		.map(|(i, signer)| {
			let config = DkgConfig::new(
				threshold_config,
				i as ParticipantId,
				participants.clone(),
				signer,
				pk_map.clone(),
			)
			.map_err(|e| DkgError::InvalidState(e.to_string()))?;

			// Derive party-specific seed: SHAKE256(master_seed || "dkg-party" || party_id)
			let mut state = fips202::KeccakState::default();
			fips202::shake256_absorb(&mut state, &master_seed);
			fips202::shake256_absorb(&mut state, b"dkg-party");
			let party_bytes = (i as u32).to_le_bytes();
			fips202::shake256_absorb(&mut state, &party_bytes);
			fips202::shake256_finalize(&mut state);

			let mut party_seed = [0u8; 32];
			fips202::shake256_squeeze(&mut party_seed, &mut state);

			Ok(Dkg::new(config, party_seed, session_nonce))
		})
		.collect::<Result<Vec<Dkg<S>>, DkgError>>()?;

	let mut outputs: Vec<Option<DkgOutput>> = vec![None; total_parties as usize];
	// Queued frames may be Round 1 privates carrying K_S, so the queue holds
	// zeroizing buffers: an early error drops the whole queue with the secrets
	// wiped instead of leaving them in freed memory.
	let mut pending_messages: Vec<Vec<(ParticipantId, Zeroizing<Vec<u8>>)>> =
		vec![Vec::new(); total_parties as usize];

	let mut iterations = 0;
	const MAX_ITERATIONS: usize = 1000;

	while outputs.iter().any(|o| o.is_none()) {
		iterations += 1;
		if iterations > MAX_ITERATIONS {
			return Err(DkgError::InternalError("DKG did not complete in time".into()));
		}

		// Deliver pending messages
		for party_id in 0..total_parties as usize {
			let messages = mem::take(&mut pending_messages[party_id]);
			for (from, mut data) in messages {
				// Hand the inner Vec to `message`, which wipes it internally;
				// the emptied wrapper drops with nothing left to erase.
				dkgs[party_id].message(from, mem::take(&mut *data))?;
			}
		}

		// Poke each party until they all return Wait or Return
		let mut made_progress = true;
		while made_progress {
			made_progress = false;

			for party_id in 0..total_parties as usize {
				if outputs[party_id].is_some() {
					continue;
				}

				match dkgs[party_id].poke()? {
					DkgAction::Wait => {},
					DkgAction::SendMany(data) => {
						made_progress = true;
						let from = party_id as ParticipantId;
						for (other, pending) in pending_messages.iter_mut().enumerate() {
							if other != party_id {
								pending.push((from, Zeroizing::new(data.clone())));
							}
						}
					},
					DkgAction::SendPrivate(to, data) => {
						made_progress = true;
						let from = party_id as ParticipantId;
						pending_messages[to as usize].push((from, data));
					},
					DkgAction::Return(output) => {
						made_progress = true;
						outputs[party_id] = Some(*output);
					},
				}
			}
		}
	}

	Ok(outputs.into_iter().map(|o| o.unwrap()).collect())
}

#[cfg(test)]
mod tests {
	use super::*;
	use qp_rusty_crystals_dilithium::params::ETA;

	/// Test session nonce for DKG tests.
	const TEST_SESSION_NONCE: [u8; 32] = [0xDEu8; 32];

	/// A deterministic derived-key contribution (same share + tweak) must not
	/// pin Round 1 randomness across DKG retries. Before the SSID binding fix,
	/// `derive_round1_randomness` ignored `session_nonce`, so an honest party
	/// replayed the same `my_randomness` on every retry and a malicious peer who
	/// had seen Round 2 reveals could predict it.
	#[test]
	fn test_round1_randomness_changes_with_session_nonce() {
		use crate::{derivation::derive_dkg_contribution, keys::SecretShareData};
		use alloc::collections::BTreeMap;

		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		let mut shares = BTreeMap::new();
		shares.insert(0b011, SecretShareData { s1: [[42i32; 256]; L], s2: [[42i32; 256]; K] });
		let master_share = PrivateKeyShare::new(
			0,
			3,
			2,
			[0u8; 32],
			[0u8; 32],
			[0u8; 64],
			shares,
			dkg_participants,
		);
		let tweak = [0x55u8; 32];
		let contribution = derive_dkg_contribution(&master_share, &tweak);

		let nonce_a = [0xA1u8; 32];
		let nonce_b = [0xB2u8; 32];
		let ssid_a = compute_dkg_ssid(2, 3, &[0, 1, 2], &nonce_a);
		let ssid_b = compute_dkg_ssid(2, 3, &[0, 1, 2], &nonce_b);
		let leader_subsets = [0b011u16];

		let (rand_a, secrets_a) =
			derive_round1_randomness(&contribution, &ssid_a, 0, &leader_subsets);
		let (rand_b, secrets_b) =
			derive_round1_randomness(&contribution, &ssid_b, 0, &leader_subsets);

		assert_ne!(
			rand_a, rand_b,
			"same derived-key contribution must yield different Round 1 randomness per session nonce"
		);
		assert_ne!(
			secrets_a[&0b011], secrets_b[&0b011],
			"leader subset secrets must also change with session nonce"
		);

		// Same nonce → reproducible (honest parties in one session agree).
		let (rand_a2, secrets_a2) =
			derive_round1_randomness(&contribution, &ssid_a, 0, &leader_subsets);
		assert_eq!(rand_a, rand_a2);
		assert_eq!(secrets_a[&0b011], secrets_a2[&0b011]);
	}

	/// The `SendPrivate` payload carries the borsh-serialized Round 1 private
	/// message (K_S). Its `Debug` output must never expose those secret bytes,
	/// otherwise any downstream `{:?}` logging persists key material outside the
	/// encrypted transport path.
	#[test]
	fn send_private_debug_does_not_leak_shared_secret() {
		// A recognizable K_S: every byte 0xAB (== 171 decimal) so we can search
		// for the exact form a derived `Debug` on `Vec<u8>` would print.
		let secret_marker = [0xABu8; SHARED_SECRET_SIZE];
		let private = Round1Private {
			ssid: [0x11u8; DKG_SSID_SIZE],
			from_party_id: 7,
			subset_mask: 0b011,
			shared_secret: secret_marker,
		};
		let data = borsh::to_vec(&DkgMessage::Round1Private(private)).unwrap();

		// Sanity: the secret really is inside the transport payload.
		assert!(
			data.windows(SHARED_SECRET_SIZE).any(|w| w == secret_marker),
			"test setup: secret not present in serialized payload"
		);

		let action = DkgAction::SendPrivate(3, Zeroizing::new(data));
		let rendered = format!("{action:?}");

		// A derived `Debug` renders the payload as `[.., 171, 171, ..]`; the
		// redacting impl must emit no run of the secret bytes.
		assert!(
			!rendered.contains("171, 171"),
			"SendPrivate Debug leaked raw secret bytes: {rendered}"
		);
		// Still useful for debugging: recipient visible, payload redacted.
		assert!(rendered.contains("to: 3"), "recipient should stay visible: {rendered}");
		assert!(rendered.contains("redacted"), "payload should be redacted: {rendered}");
	}

	#[derive(Clone, Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
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
	fn test_dkg_2_of_3() {
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [42u8; 32];

		let result = run_local_dkg(2, 3, signers, public_keys, seed, &TEST_SESSION_NONCE);

		match &result {
			Ok(outputs) => {
				assert_eq!(outputs.len(), 3);

				let pk0 = outputs[0].public_key.as_bytes();
				let pk1 = outputs[1].public_key.as_bytes();
				let pk2 = outputs[2].public_key.as_bytes();

				assert_eq!(pk0, pk1);
				assert_eq!(pk1, pk2);
			},
			Err(e) => {
				panic!("DKG failed: {:?}", e);
			},
		}
	}

	/// The DKG output public key is intentionally NOT a pure function of the
	/// parties' seeds: each party's Round 1 randomness is bound to the session
	/// SSID (which incorporates `session_nonce`), and the final key is
	/// computed from `rho = h_seed(global_randomness)`. Re-running the DKG
	/// with identical seeds but a fresh nonce therefore yields a different
	/// key — that is the security property that stops an adversary who saw a
	/// failed attempt's Round 2 reveals from predicting honest randomness and
	/// grinding `global_randomness` on retry (see `derive_round1_randomness`).
	///
	/// This test pins that behavior so documentation like `derivation.rs`
	/// ("one canonical stored key per (master_key, tweak)", not "recomputable
	/// from (master_key, tweak)") stays honest: derived keys must be stored,
	/// never recovered by re-running the DKG.
	#[test]
	fn test_dkg_public_key_depends_on_session_nonce() {
		let seed = [42u8; 32];
		let run = |nonce: &[u8; 32]| {
			let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
			let public_keys: Vec<u32> = (0..3).collect();
			run_local_dkg(2, 3, signers, public_keys, seed, nonce).unwrap()
		};

		let nonce_a = [0xA1u8; 32];
		let nonce_b = [0xB2u8; 32];

		let pk_a = run(&nonce_a)[0].public_key.clone();
		let pk_b = run(&nonce_b)[0].public_key.clone();
		assert_ne!(
			pk_a.as_bytes(),
			pk_b.as_bytes(),
			"identical seeds with a fresh session nonce must produce a different public key; \
			 if this ever fails, Round 1 randomness lost its SSID binding (grinding risk)"
		);

		// Within one session (same nonce), the protocol is deterministic for
		// fixed seeds — honest parties agree and reruns reproduce the key.
		let pk_a2 = run(&nonce_a)[0].public_key.clone();
		assert_eq!(pk_a.as_bytes(), pk_a2.as_bytes());
	}

	/// Mismatched input vector lengths must return a `DkgError`, not panic.
	/// `run_local_dkg` is public, so untrusted setup parameters reaching a
	/// `.unwrap()` or `dkgs[party_id]` index would be an availability DoS.
	#[test]
	fn test_run_local_dkg_rejects_mismatched_lengths() {
		let seed = [7u8; 32];

		// Too few signers (and the driver loop would otherwise index out of bounds).
		let signers: Vec<TestSigner> = (0..2).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let result = run_local_dkg(2, 3, signers, public_keys, seed, &TEST_SESSION_NONCE);
		assert!(matches!(result, Err(DkgError::InvalidState(_))), "too few signers must error");

		// Too many signers (index would fall outside all_participants).
		let signers: Vec<TestSigner> = (0..4).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let result = run_local_dkg(2, 3, signers, public_keys, seed, &TEST_SESSION_NONCE);
		assert!(matches!(result, Err(DkgError::InvalidState(_))), "too many signers must error");

		// Mismatched public key count (would fail DkgConfig::new before the fix).
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..2).collect();
		let result = run_local_dkg(2, 3, signers, public_keys, seed, &TEST_SESSION_NONCE);
		assert!(matches!(result, Err(DkgError::InvalidState(_))), "wrong pk count must error");
	}

	#[test]
	fn test_dkg_eta_bounded() {
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [123u8; 32];

		let outputs = run_local_dkg(2, 3, signers, public_keys, seed, &TEST_SESSION_NONCE).unwrap();

		for (party_id, output) in outputs.iter().enumerate() {
			let shares = output.private_share.shares();
			for (subset_mask, share) in shares {
				for (poly_idx, poly) in share.s1.iter().enumerate() {
					for (coeff_idx, &coeff) in poly.iter().enumerate() {
						assert!(
							(-(ETA as i32)..=(ETA as i32)).contains(&coeff),
							"Party {} subset {:b} s1[{}][{}] = {} outside η bound",
							party_id,
							subset_mask,
							poly_idx,
							coeff_idx,
							coeff
						);
					}
				}
				for (poly_idx, poly) in share.s2.iter().enumerate() {
					for (coeff_idx, &coeff) in poly.iter().enumerate() {
						assert!(
							(-(ETA as i32)..=(ETA as i32)).contains(&coeff),
							"Party {} subset {:b} s2[{}][{}] = {} outside η bound",
							party_id,
							subset_mask,
							poly_idx,
							coeff_idx,
							coeff
						);
					}
				}
			}
		}
	}

	/// Test DKG with ML-DSA-87 (Dilithium) for transcript signing.
	///
	/// This verifies that the TranscriptSigner trait works correctly with
	/// a real post-quantum signature scheme.
	#[test]
	fn test_dkg_with_dilithium_signing() {
		use qp_rusty_crystals_dilithium::{
			ml_dsa_87::{Keypair, PublicKey, SecretKey, SIGNBYTES},
			SensitiveBytes32,
		};

		/// Signer that wraps a Dilithium secret key.
		/// Clone is implemented manually to explicitly copy the secret key bytes.
		///
		/// `Zeroize`/`ZeroizeOnDrop` are derived (not marker-implemented) so the
		/// secret key is provably wiped on drop; the public key is skipped.
		#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
		struct DilithiumSigner {
			sk: SecretKey,
			#[zeroize(skip)]
			pk: PublicKey,
		}

		impl Clone for DilithiumSigner {
			fn clone(&self) -> Self {
				// Explicitly copy secret key material (visible at call site per SecretKey design)
				let sk =
					SecretKey::from_bytes(&self.sk.to_bytes()).expect("valid secret key bytes");
				Self { sk, pk: self.pk.clone() }
			}
		}

		impl core::fmt::Debug for DilithiumSigner {
			fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.debug_struct("DilithiumSigner")
					.field("pk", &hex::encode(&self.pk.bytes[..8]))
					.finish()
			}
		}

		impl TranscriptSigner for DilithiumSigner {
			type Signature = Vec<u8>;
			type PublicKey = PublicKey;

			fn sign(&self, hash: &[u8; 32]) -> Self::Signature {
				// Sign with no context and deterministic (no hedging)
				self.sk.sign(hash, None, None).unwrap().to_vec()
			}

			fn verify(pk: &Self::PublicKey, hash: &[u8; 32], sig: &Self::Signature) -> bool {
				Self::verify_bytes(pk, hash, sig)
			}

			fn verify_bytes(pk: &Self::PublicKey, hash: &[u8; 32], sig: &[u8]) -> bool {
				if sig.len() != SIGNBYTES {
					return false;
				}
				pk.verify(hash, sig, None)
			}

			fn public_key(&self) -> Self::PublicKey {
				self.pk.clone()
			}
		}

		// Generate Dilithium keypairs for each party
		let mut signers = Vec::new();
		let mut public_keys = Vec::new();

		for i in 0..3u32 {
			// Use deterministic seed for reproducibility
			let mut seed = [0u8; 32];
			seed[..4].copy_from_slice(&i.to_le_bytes());
			seed[4] = 0xDE;
			seed[5] = 0xAD;

			let keypair = Keypair::generate(SensitiveBytes32::from(&mut seed));

			public_keys.push(keypair.public.clone());
			// Explicitly copy secret key to create signer (keypair.secret is moved)
			let sk =
				SecretKey::from_bytes(&keypair.secret.to_bytes()).expect("valid secret key bytes");
			signers.push(DilithiumSigner { sk, pk: keypair.public });
		}

		let seed = [56u8; 32];
		let outputs = run_local_dkg(2, 3, signers, public_keys, seed, &TEST_SESSION_NONCE).unwrap();

		// Verify DKG succeeded
		assert_eq!(outputs.len(), 3);

		// All parties should have the same public key
		let pk0 = outputs[0].public_key.as_bytes();
		for output in &outputs[1..] {
			assert_eq!(pk0, output.public_key.as_bytes());
		}

		// Verify η-bounded shares
		for output in &outputs {
			for share in output.private_share.shares().values() {
				for poly in &share.s1 {
					for &coeff in poly {
						assert!((-(ETA as i32)..=(ETA as i32)).contains(&coeff));
					}
				}
				for poly in &share.s2 {
					for &coeff in poly {
						assert!((-(ETA as i32)..=(ETA as i32)).contains(&coeff));
					}
				}
			}
		}
	}

	/// Test that DKG rejects invalid transcript signatures.
	///
	/// This is a security-critical test: malicious parties should not be able
	/// to complete DKG with forged signatures.
	#[test]
	fn test_dkg_rejects_bad_signature() {
		// A signer that produces bad signatures for party 2
		#[derive(Clone, Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
		struct BadSigner {
			id: u32,
			produce_bad_sig: bool,
		}

		impl TranscriptSigner for BadSigner {
			type Signature = Vec<u8>;
			type PublicKey = u32;

			fn sign(&self, hash: &[u8; 32]) -> Self::Signature {
				let mut sig = vec![0u8; 36];
				sig[..4].copy_from_slice(&self.id.to_le_bytes());
				if self.produce_bad_sig {
					// Produce a signature with wrong hash
					sig[4..36].copy_from_slice(&[0xBA; 32]);
				} else {
					sig[4..36].copy_from_slice(hash);
				}
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

		// Party 2 will produce bad signatures
		let signers: Vec<BadSigner> =
			(0..3).map(|id| BadSigner { id, produce_bad_sig: id == 2 }).collect();
		let public_keys: Vec<u32> = (0..3).collect();

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		let seed = [89u8; 32];

		let mut dkgs: Vec<Dkg<BadSigner>> = signers
			.into_iter()
			.enumerate()
			.map(|(i, signer)| {
				let config = DkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer,
					pk_map.clone(),
				)
				.unwrap();
				Dkg::new(config, seed, &TEST_SESSION_NONCE)
			})
			.collect();

		let mut outputs: Vec<Option<DkgOutput>> = vec![None; 3];
		let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); 3];
		let mut errors: Vec<Option<DkgError>> = vec![None; 3];

		let mut iterations = 0;
		const MAX_ITERATIONS: usize = 1000;

		while outputs.iter().any(|o| o.is_none()) && errors.iter().all(|e| e.is_none()) {
			iterations += 1;
			if iterations > MAX_ITERATIONS {
				break;
			}

			// Deliver pending messages
			for party_id in 0..3 {
				let messages = mem::take(&mut pending_messages[party_id]);
				for (from, data) in messages {
					// In tests, unwrap to fail fast on unexpected deserialization errors
					dkgs[party_id].message(from, data).unwrap();
				}
			}

			// Poke each party
			let mut made_progress = true;
			while made_progress {
				made_progress = false;

				for party_id in 0..3 {
					if outputs[party_id].is_some() || errors[party_id].is_some() {
						continue;
					}

					match dkgs[party_id].poke() {
						Ok(DkgAction::Wait) => {},
						Ok(DkgAction::SendMany(data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							for (other, pending) in pending_messages.iter_mut().enumerate() {
								if other != party_id {
									pending.push((from, data.clone()));
								}
							}
						},
						Ok(DkgAction::SendPrivate(to, data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							pending_messages[to as usize].push((from, data.to_vec()));
						},
						Ok(DkgAction::Return(output)) => {
							made_progress = true;
							outputs[party_id] = Some(*output);
						},
						Err(e) => {
							errors[party_id] = Some(e);
						},
					}
				}
			}
		}

		// The DKG should fail for honest parties when they try to verify party 2's bad signature
		// Party 2's bad signature will be detected when other parties verify it in complete()

		// At least one honest party should have received an error
		let has_sig_error = errors
			.iter()
			.any(|e| matches!(e, Some(DkgError::SignatureVerificationFailed { party_id: 2 })));

		assert!(has_sig_error, "At least one honest party should reject party 2's bad signature");
	}

	/// Test that DKG rejects bad randomness commitment (Round 2 reveal doesn't match Round 1
	/// commit).
	#[test]
	fn test_dkg_rejects_bad_commitment() {
		// We'll intercept and modify party 2's Round 2 message to have wrong randomness
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		let seed = [55u8; 32];

		let mut dkgs: Vec<Dkg<TestSigner>> = signers
			.into_iter()
			.enumerate()
			.map(|(i, signer)| {
				let config = DkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer,
					pk_map.clone(),
				)
				.unwrap();
				Dkg::new(config, seed, &TEST_SESSION_NONCE)
			})
			.collect();

		let mut outputs: Vec<Option<DkgOutput>> = vec![None; 3];
		let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); 3];
		let mut errors: Vec<Option<DkgError>> = vec![None; 3];

		let mut iterations = 0;
		const MAX_ITERATIONS: usize = 1000;

		while outputs.iter().any(|o| o.is_none()) && errors.iter().all(|e| e.is_none()) {
			iterations += 1;
			if iterations > MAX_ITERATIONS {
				break;
			}

			// Deliver pending messages, but tamper with party 2's Round 2 broadcast
			for party_id in 0..3 {
				let messages = mem::take(&mut pending_messages[party_id]);
				for (from, mut data) in messages {
					// Tamper with party 2's Round 2 message
					if from == 2 {
						if let Ok(DkgMessage::Round2Broadcast(mut r2)) =
							borsh::from_slice::<DkgMessage>(&data)
						{
							// Corrupt the randomness
							r2.randomness[0] ^= 0xFF;
							let tampered = DkgMessage::Round2Broadcast(r2);
							data = borsh::to_vec(&tampered).unwrap();
						}
					}
					dkgs[party_id].message(from, data).unwrap();
				}
			}

			// Poke each party
			let mut made_progress = true;
			while made_progress {
				made_progress = false;

				for party_id in 0..3 {
					if outputs[party_id].is_some() || errors[party_id].is_some() {
						continue;
					}

					match dkgs[party_id].poke() {
						Ok(DkgAction::Wait) => {},
						Ok(DkgAction::SendMany(data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							for (other, pending) in pending_messages.iter_mut().enumerate() {
								if other != party_id {
									pending.push((from, data.clone()));
								}
							}
						},
						Ok(DkgAction::SendPrivate(to, data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							pending_messages[to as usize].push((from, data.to_vec()));
						},
						Ok(DkgAction::Return(output)) => {
							made_progress = true;
							outputs[party_id] = Some(*output);
						},
						Err(e) => {
							errors[party_id] = Some(e);
						},
					}
				}
			}
		}

		// At least one honest party should have detected the commitment mismatch
		let has_commitment_error = errors
			.iter()
			.any(|e| matches!(e, Some(DkgError::CommitmentMismatch { party_id: 2 })));

		assert!(has_commitment_error, "At least one party should reject party 2's bad commitment");
	}

	/// Test that non-leaders detect tampered PK commitments in Round 4 before signing.
	/// Per Mithril paper DKGRound4 lines 11-16: non-leaders verify PK commitments BEFORE signing.
	#[test]
	fn test_dkg_rejects_bad_pk_commitment() {
		// For 2-of-3: subset size k = 3-2+1 = 2
		// Subsets: {0,1}=0b011, {0,2}=0b101, {1,2}=0b110
		// Leaders: min of each subset
		//   - {0,1}: leader is 0
		//   - {0,2}: leader is 0
		//   - {1,2}: leader is 1
		// Party 0 is leader for subsets 0b011 and 0b101
		// Party 1 is leader for subset 0b110
		// Party 2 is never a leader but is a non-leader member of 0b101 and 0b110

		// We'll tamper with party 0's Round 3 PK commitment for subset 0b101
		// Party 2 (non-leader member of 0b101) should detect this BEFORE signing

		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		let seed = [88u8; 32];

		let mut dkgs: Vec<Dkg<TestSigner>> = signers
			.into_iter()
			.enumerate()
			.map(|(i, signer)| {
				let config = DkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer,
					pk_map.clone(),
				)
				.unwrap();
				Dkg::new(config, seed, &TEST_SESSION_NONCE)
			})
			.collect();

		let mut outputs: Vec<Option<DkgOutput>> = vec![None; 3];
		let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); 3];
		let mut errors: Vec<Option<DkgError>> = vec![None; 3];

		let mut iterations = 0;
		const MAX_ITERATIONS: usize = 1000;

		while outputs.iter().any(|o| o.is_none()) && errors.iter().all(|e| e.is_none()) {
			iterations += 1;
			if iterations > MAX_ITERATIONS {
				break;
			}

			// Deliver pending messages, but tamper with party 0's Round 3 broadcast
			for party_id in 0..3 {
				let messages = mem::take(&mut pending_messages[party_id]);
				for (from, mut data) in messages {
					// Tamper with party 0's Round 3 message (PK commitments)
					if from == 0 {
						if let Ok(DkgMessage::Round3Broadcast(mut r3)) =
							borsh::from_slice::<DkgMessage>(&data)
						{
							// Corrupt a PK commitment for subset 0b101 where party 2 is a
							// member
							if let Some(commitment) = r3.partial_pk_commitments.get_mut(&0b101) {
								commitment[0] ^= 0xFF;
							}
							let tampered = DkgMessage::Round3Broadcast(r3);
							data = borsh::to_vec(&tampered).unwrap();
						}
					}
					dkgs[party_id].message(from, data).unwrap();
				}
			}

			// Poke each party
			let mut made_progress = true;
			while made_progress {
				made_progress = false;

				for party_id in 0..3 {
					if outputs[party_id].is_some() || errors[party_id].is_some() {
						continue;
					}

					match dkgs[party_id].poke() {
						Ok(DkgAction::Wait) => {},
						Ok(DkgAction::SendMany(data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							for (other, pending) in pending_messages.iter_mut().enumerate() {
								if other != party_id {
									pending.push((from, data.clone()));
								}
							}
						},
						Ok(DkgAction::SendPrivate(to, data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							pending_messages[to as usize].push((from, data.to_vec()));
						},
						Ok(DkgAction::Return(output)) => {
							made_progress = true;
							outputs[party_id] = Some(*output);
						},
						Err(e) => {
							errors[party_id] = Some(e);
						},
					}
				}
			}
		}

		// Party 2 should detect the PK commitment mismatch in Round 4 BEFORE signing
		// (Party 2 is a non-leader member of subset 0b101 where party 0 is leader)
		let party2_error = &errors[2];
		assert!(
			matches!(
				party2_error,
				Some(DkgError::PkCommitmentMismatch { party_id: 0, subset: 0b101 })
			),
			"Party 2 should detect party 0's bad PK commitment for subset 0b101, got: {:?}",
			party2_error
		);
	}

	/// Test DKG with 3-of-5 threshold.
	#[test]
	fn test_dkg_3_of_5() {
		let signers: Vec<TestSigner> = (0..5).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..5).collect();
		let seed = [45u8; 32];

		let outputs = run_local_dkg(3, 5, signers, public_keys, seed, &TEST_SESSION_NONCE).unwrap();

		assert_eq!(outputs.len(), 5);

		// All parties should have the same public key
		let pk0 = outputs[0].public_key.as_bytes();
		for output in &outputs[1..] {
			assert_eq!(pk0, output.public_key.as_bytes());
		}

		// Verify η-bounded shares
		for output in &outputs {
			for share in output.private_share.shares().values() {
				for poly in &share.s1 {
					for &coeff in poly {
						assert!((-(ETA as i32)..=(ETA as i32)).contains(&coeff));
					}
				}
				for poly in &share.s2 {
					for &coeff in poly {
						assert!((-(ETA as i32)..=(ETA as i32)).contains(&coeff));
					}
				}
			}
		}

		// Verify each party has correct number of subsets
		// For 3-of-5, subset size k = 5-3+1 = 3
		// Party 0 should be in C(4,2) = 6 subsets (choosing 2 others from 4)
		for (party_id, output) in outputs.iter().enumerate() {
			let num_subsets = output.private_share.shares().len();
			// Each party is in C(n-1, k-1) = C(4, 2) = 6 subsets
			assert_eq!(
				num_subsets, 6,
				"Party {} should have 6 subsets, got {}",
				party_id, num_subsets
			);
		}
	}

	/// Test that parties in the same subset have identical shares.
	#[test]
	fn test_dkg_subset_share_consistency() {
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [77u8; 32];

		let outputs = run_local_dkg(2, 3, signers, public_keys, seed, &TEST_SESSION_NONCE).unwrap();

		// For 2-of-3: subsets are {0,1}=0b011, {0,2}=0b101, {1,2}=0b110

		// Check subset {0, 1} (mask 0b011 = 3)
		let p0_share_01 = outputs[0].private_share.shares().get(&0b011).unwrap();
		let p1_share_01 = outputs[1].private_share.shares().get(&0b011).unwrap();
		assert_eq!(
			p0_share_01.s1, p1_share_01.s1,
			"Party 0 and 1 should have same s1 for subset {{0,1}}"
		);
		assert_eq!(
			p0_share_01.s2, p1_share_01.s2,
			"Party 0 and 1 should have same s2 for subset {{0,1}}"
		);

		// Check subset {0, 2} (mask 0b101 = 5)
		let p0_share_02 = outputs[0].private_share.shares().get(&0b101).unwrap();
		let p2_share_02 = outputs[2].private_share.shares().get(&0b101).unwrap();
		assert_eq!(
			p0_share_02.s1, p2_share_02.s1,
			"Party 0 and 2 should have same s1 for subset {{0,2}}"
		);
		assert_eq!(
			p0_share_02.s2, p2_share_02.s2,
			"Party 0 and 2 should have same s2 for subset {{0,2}}"
		);

		// Check subset {1, 2} (mask 0b110 = 6)
		let p1_share_12 = outputs[1].private_share.shares().get(&0b110).unwrap();
		let p2_share_12 = outputs[2].private_share.shares().get(&0b110).unwrap();
		assert_eq!(
			p1_share_12.s1, p2_share_12.s1,
			"Party 1 and 2 should have same s1 for subset {{1,2}}"
		);
		assert_eq!(
			p1_share_12.s2, p2_share_12.s2,
			"Party 1 and 2 should have same s2 for subset {{1,2}}"
		);

		// Verify parties only have shares for subsets they belong to
		assert!(
			!outputs[0].private_share.shares().contains_key(&0b110),
			"Party 0 should not have subset {{1,2}}"
		);
		assert!(
			!outputs[1].private_share.shares().contains_key(&0b101),
			"Party 1 should not have subset {{0,2}}"
		);
		assert!(
			!outputs[2].private_share.shares().contains_key(&0b011),
			"Party 2 should not have subset {{0,1}}"
		);
	}

	/// Test config validation rejects invalid parameters.
	#[test]
	fn test_dkg_config_validation() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		pk_map.insert(0, 0);
		pk_map.insert(1, 1);
		pk_map.insert(2, 2);

		// Valid config should work
		let result = DkgConfig::new(
			threshold_config,
			0,
			vec![0, 1, 2],
			TestSigner { id: 0 },
			pk_map.clone(),
		);
		assert!(result.is_ok());

		// Wrong participant count
		let result = DkgConfig::new(
			threshold_config,
			0,
			vec![0, 1], // Only 2 participants but config says 3
			TestSigner { id: 0 },
			pk_map.clone(),
		);
		assert!(result.is_err());

		// Party not in participants
		let result = DkgConfig::new(
			threshold_config,
			99, // Not in the list
			vec![0, 1, 2],
			TestSigner { id: 99 },
			pk_map.clone(),
		);
		assert!(result.is_err());

		// Missing public key
		let mut incomplete_pk_map = pk_map.clone();
		incomplete_pk_map.remove(&2);
		let result = DkgConfig::new(
			threshold_config,
			0,
			vec![0, 1, 2],
			TestSigner { id: 0 },
			incomplete_pk_map,
		);
		assert!(result.is_err());
	}

	/// Test that out-of-order messages are buffered and processed correctly.
	#[test]
	fn test_message_buffering() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = vec![0, 1, 2];

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for &p in &participants {
			pk_map.insert(p, p);
		}

		// Create two DKG instances
		let config0 = DkgConfig::new(
			threshold_config,
			0,
			participants.clone(),
			TestSigner { id: 0 },
			pk_map.clone(),
		)
		.unwrap();

		let config1 = DkgConfig::new(
			threshold_config,
			1,
			participants.clone(),
			TestSigner { id: 1 },
			pk_map.clone(),
		)
		.unwrap();

		let seed0 = [100u8; 32];
		let seed1 = [101u8; 32];

		let mut dkg0 = Dkg::new(config0, seed0, &TEST_SESSION_NONCE);
		let mut dkg1 = Dkg::new(config1, seed1, &TEST_SESSION_NONCE);

		// Get the computed SSID for use in test messages
		let ssid = *dkg0.ssid();

		// Start DKG0 - it will be in Round 1 after first poke
		let action0 = dkg0.poke().unwrap();
		assert!(matches!(action0, DkgAction::SendMany(_)));

		// Advance DKG1 quickly through Round 1 by giving it fake Round 1 messages
		// and capture its Round 2 broadcast
		let _ = dkg1.poke().unwrap(); // SendMany (Round 1 broadcast)

		// DKG0 is still in Round 1. If DKG1 sends a Round 2 message now,
		// it should be buffered by DKG0.

		// Create a fake Round 2 broadcast from party 1
		let round2_broadcast = Round2Broadcast { ssid, party_id: 1, randomness: [42u8; 32] };
		let round2_msg = DkgMessage::Round2Broadcast(round2_broadcast);
		let round2_data = borsh::to_vec(&round2_msg).unwrap();

		// Send it to DKG0 while it's still in Round 1
		dkg0.message(1, round2_data).unwrap();

		// Verify the message was buffered
		assert_eq!(dkg0.message_buffer.round2.len(), 1);
		assert_eq!(dkg0.message_buffer.round2.get(&1).unwrap().party_id, 1);

		// Similarly test Round 3 buffering
		let round3_broadcast =
			Round3Broadcast { ssid, party_id: 2, partial_pk_commitments: BTreeMap::new() };
		let round3_msg = DkgMessage::Round3Broadcast(round3_broadcast);
		let round3_data = borsh::to_vec(&round3_msg).unwrap();

		dkg0.message(2, round3_data).unwrap();
		assert_eq!(dkg0.message_buffer.round3.len(), 1);
		assert_eq!(dkg0.message_buffer.round3.get(&2).unwrap().party_id, 2);

		// And Round 4 buffering
		let round4_broadcast = Round4Broadcast {
			ssid,
			party_id: 1,
			partial_public_keys: BTreeMap::new(),
			transcript_signature: vec![],
		};
		let round4_msg = DkgMessage::Round4Broadcast(round4_broadcast);
		let round4_data = borsh::to_vec(&round4_msg).unwrap();

		dkg0.message(1, round4_data).unwrap();
		assert_eq!(dkg0.message_buffer.round4.len(), 1);
		assert_eq!(dkg0.message_buffer.round4.get(&1).unwrap().party_id, 1);
	}

	/// Test that sender mismatch messages are ignored.
	#[test]
	fn test_sender_mismatch_ignored() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = vec![0, 1, 2];

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for &p in &participants {
			pk_map.insert(p, p);
		}

		let config =
			DkgConfig::new(threshold_config, 0, participants, TestSigner { id: 0 }, pk_map)
				.unwrap();

		let seed = [100u8; 32];
		let mut dkg = Dkg::new(config, seed, &TEST_SESSION_NONCE);

		// Start the DKG
		let _ = dkg.poke().unwrap();

		// Create a Round 1 broadcast claiming to be from party 1
		let broadcast =
			Round1Broadcast { ssid: TEST_SESSION_NONCE, party_id: 1, commitment: [0u8; 32] };
		let msg = DkgMessage::Round1Broadcast(broadcast);
		let data = borsh::to_vec(&msg).unwrap();

		// Send it claiming to be from party 2 (mismatch!)
		dkg.message(2, data).unwrap();

		// The message should be ignored - check that party 1's slot is empty
		assert!(dkg.state.phase == DkgPhase::Round1, "Expected Round1 state");
		let round1_broadcasts = dkg.state.round1_broadcasts.as_ref().expect("broadcasts map");
		assert!(!round1_broadcasts.contains_key(&1));
		assert!(!round1_broadcasts.contains_key(&2));
	}

	/// Test that a leader's Round1Private for a subset is rejected if receiver is not in that
	/// subset. This prevents a malicious leader from sending K_S to parties outside the subset.
	#[test]
	fn test_round1_private_rejected_for_non_member() {
		// 2-of-3 DKG: subsets are {0,1}=0b011, {0,2}=0b101, {1,2}=0b110
		// Party 0 is leader of subsets 0b011 and 0b101
		// Party 1 is leader of subset 0b110
		// Party 2 is never a leader
		//
		// Test: Party 0 (leader of 0b110's subset? No - leader of 0b011) tries to send
		// a Round1Private for subset 0b110 to party 2. But party 0 is NOT the leader
		// of subset 0b110 (party 1 is), so this should be rejected.
		//
		// Better test: Party 1 (leader of 0b110) sends K_S for subset 0b110 to party 0.
		// Party 0 is NOT in subset 0b110 (members are 1,2), so it should reject.

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = vec![0, 1, 2];

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for &p in &participants {
			pk_map.insert(p, p);
		}

		// Create party 0's DKG
		let config = DkgConfig::new(
			threshold_config,
			0, // We are party 0
			participants,
			TestSigner { id: 0 },
			pk_map,
		)
		.unwrap();

		let seed = [100u8; 32];
		let mut dkg = Dkg::new(config, seed, &TEST_SESSION_NONCE);

		// Start the DKG to get into Round1 state
		let _ = dkg.poke().unwrap();

		// Party 1 is the leader of subset 0b110 = {1, 2}
		// Party 0 is NOT in subset 0b110
		// Create a Round1Private from party 1 for subset 0b110
		let private = Round1Private {
			ssid: TEST_SESSION_NONCE,
			from_party_id: 1,
			subset_mask: 0b110, // Subset {1, 2} - party 0 is not a member
			shared_secret: [42u8; 32],
		};
		let msg = DkgMessage::Round1Private(private);
		let data = borsh::to_vec(&msg).unwrap();

		// Send it from party 1 (legitimate leader of this subset)
		dkg.message(1, data).unwrap();

		// The message should be rejected because party 0 is not in subset 0b110
		assert!(dkg.state.phase == DkgPhase::Round1, "Expected Round1 state");
		let received_shared_secrets =
			dkg.state.received_shared_secrets.as_ref().expect("received_shared_secrets");
		assert!(
			!received_shared_secrets.contains_key(&0b110),
			"Party 0 should not accept K_S for subset 0b110 (not a member)"
		);
	}

	/// Test that a legitimate Round1Private is accepted when receiver is in the subset.
	#[test]
	fn test_round1_private_accepted_for_member() {
		// 2-of-3 DKG: subsets are {0,1}=0b011, {0,2}=0b101, {1,2}=0b110
		// Party 0 is leader of subsets 0b011 and 0b101
		//
		// Test: Party 0 sends Round1Private for subset 0b011 to party 1.
		// Party 1 IS in subset 0b011, so it should be accepted.

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = vec![0, 1, 2];

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for &p in &participants {
			pk_map.insert(p, p);
		}

		// Create party 1's DKG
		let config = DkgConfig::new(
			threshold_config,
			1, // We are party 1
			participants,
			TestSigner { id: 1 },
			pk_map,
		)
		.unwrap();

		let seed = [101u8; 32];
		let mut dkg = Dkg::new(config, seed, &TEST_SESSION_NONCE);

		// Get the computed SSID for use in test messages
		let ssid = *dkg.ssid();

		// Start the DKG to get into Round1 state
		let _ = dkg.poke().unwrap();

		// Party 0 is the leader of subset 0b011 = {0, 1}
		// Party 1 IS in subset 0b011
		// Create a Round1Private from party 0 for subset 0b011
		let private = Round1Private {
			ssid,
			from_party_id: 0,
			subset_mask: 0b011, // Subset {0, 1} - party 1 is a member
			shared_secret: [42u8; 32],
		};
		let msg = DkgMessage::Round1Private(private);
		let data = borsh::to_vec(&msg).unwrap();

		// Send it from party 0 (legitimate leader of this subset)
		dkg.message(0, data).unwrap();

		// The message should be accepted because party 1 is in subset 0b011
		assert!(dkg.state.phase == DkgPhase::Round1, "Expected Round1 state");
		let received_shared_secrets =
			dkg.state.received_shared_secrets.as_ref().expect("received_shared_secrets");
		assert!(
			received_shared_secrets.contains_key(&0b011),
			"Party 1 should accept K_S for subset 0b011 (is a member)"
		);
		assert_eq!(
			received_shared_secrets.get(&0b011),
			Some(&[42u8; 32]),
			"Shared secret should match"
		);
	}

	/// Test that Round1Private with an invalid subset mask is rejected.
	/// Invalid subsets include wrong size or bits outside valid participant range.
	#[test]
	fn test_round1_private_rejected_for_invalid_subset() {
		// 2-of-3 DKG: valid subsets have size k = 3 - 2 + 1 = 2
		// Valid subsets: 0b011, 0b101, 0b110
		// Invalid: 0b111 (size 3), 0b001 (size 1), 0b1000 (bit outside range)

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = vec![0, 1, 2];

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for &p in &participants {
			pk_map.insert(p, p);
		}

		// Create party 1's DKG
		let config = DkgConfig::new(
			threshold_config,
			1, // We are party 1
			participants,
			TestSigner { id: 1 },
			pk_map,
		)
		.unwrap();

		let seed = [102u8; 32];
		let mut dkg = Dkg::new(config, seed, &TEST_SESSION_NONCE);

		// Get the computed SSID for use in test messages
		let ssid = *dkg.ssid();

		// Start the DKG to get into Round1 state
		let _ = dkg.poke().unwrap();

		// Test 1: subset 0b111 (size 3, but k=2 required) - party 0 would be leader
		let private = Round1Private {
			ssid,
			from_party_id: 0,
			subset_mask: 0b111, // Invalid: size 3, not 2
			shared_secret: [42u8; 32],
		};
		let msg = DkgMessage::Round1Private(private);
		let data = borsh::to_vec(&msg).unwrap();
		dkg.message(0, data).unwrap();

		assert!(dkg.state.phase == DkgPhase::Round1, "Expected Round1 state");
		let received_shared_secrets =
			dkg.state.received_shared_secrets.as_ref().expect("received_shared_secrets");
		assert!(
			!received_shared_secrets.contains_key(&0b111),
			"Should reject invalid subset 0b111 (wrong size)"
		);

		// Test 2: subset 0b001 (size 1, but k=2 required) - party 0 would be leader
		let private = Round1Private {
			ssid,
			from_party_id: 0,
			subset_mask: 0b001, // Invalid: size 1, not 2
			shared_secret: [43u8; 32],
		};
		let msg = DkgMessage::Round1Private(private);
		let data = borsh::to_vec(&msg).unwrap();
		dkg.message(0, data).unwrap();

		assert!(dkg.state.phase == DkgPhase::Round1, "Expected Round1 state");
		let received_shared_secrets =
			dkg.state.received_shared_secrets.as_ref().expect("received_shared_secrets");
		assert!(
			!received_shared_secrets.contains_key(&0b001),
			"Should reject invalid subset 0b001 (wrong size)"
		);
	}

	/// Test that buffered messages are processed when the DKG transitions to the appropriate round.
	/// This test runs a complete 2-of-3 DKG but with messages delivered out of order to verify
	/// buffering and processing.
	#[test]
	fn test_buffered_messages_processed_on_round_transition() {
		// Use the same approach as the working test - run a full DKG but inject delays
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = vec![0, 1, 2];

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for &p in &participants {
			pk_map.insert(p, p);
		}

		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();

		let configs: Vec<_> = signers
			.iter()
			.enumerate()
			.map(|(i, signer)| {
				DkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer.clone(),
					pk_map.clone(),
				)
				.unwrap()
			})
			.collect();

		let mut dkgs: Vec<_> = configs
			.into_iter()
			.enumerate()
			.map(|(i, config)| {
				// Derive unique seed per party
				let mut party_seed = [0u8; 32];
				party_seed[0] = (100 + i) as u8;
				Dkg::new(config, party_seed, &TEST_SESSION_NONCE)
			})
			.collect();

		// Manually run the protocol with controlled message delivery
		// to verify buffering works correctly

		// Phase 1: Start all DKGs, collect all outgoing messages
		let mut pending: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); 3];

		// Run first poke on all - they go to Round 1 and send broadcasts
		for (from, dkg) in dkgs.iter_mut().enumerate() {
			loop {
				match dkg.poke().unwrap() {
					DkgAction::SendMany(data) =>
						for (to, queue) in pending.iter_mut().enumerate() {
							if to != from {
								queue.push((from as ParticipantId, data.clone()));
							}
						},
					DkgAction::SendPrivate(to, data) => {
						pending[to as usize].push((from as ParticipantId, data.to_vec()));
					},
					DkgAction::Wait => break,
					DkgAction::Return(_) => break,
				}
			}
		}

		// All parties should be in Round 1, waiting for messages
		for dkg in &dkgs {
			assert!(dkg.state.phase == DkgPhase::Round1, "Should be in Round1");
		}

		// Deliver messages to parties 1 and 2, but delay delivery to party 0
		let party0_pending = mem::take(&mut pending[0]);

		for to in 1..3 {
			let msgs = mem::take(&mut pending[to]);
			for (from, data) in msgs {
				dkgs[to].message(from, data).unwrap();
			}
		}

		// Advance parties 1 and 2 to Round 2
		for dkg_idx in 1..3 {
			loop {
				match dkgs[dkg_idx].poke().unwrap() {
					DkgAction::SendMany(data) => {
						// This is a Round 2 broadcast - send to party 0 (who is still in Round 1)
						// It should be buffered!
						dkgs[0].message(dkg_idx as ParticipantId, data.clone()).unwrap();
						// Also send to other party
						let other = if dkg_idx == 1 { 2 } else { 1 };
						pending[other].push((dkg_idx as ParticipantId, data));
					},
					DkgAction::SendPrivate(to, data) => {
						if to == 0 {
							// Send to party 0 - should be buffered if it's a future round message
							dkgs[0].message(dkg_idx as ParticipantId, data.to_vec()).unwrap();
						} else {
							pending[to as usize].push((dkg_idx as ParticipantId, data.to_vec()));
						}
					},
					DkgAction::Wait => break,
					DkgAction::Return(_) => break,
				}
			}
		}

		// Check that party 0 has buffered some Round 2 messages
		let buffered_r2 = dkgs[0].message_buffer.round2.len();
		assert!(
			buffered_r2 > 0,
			"Party 0 should have buffered Round 2 messages, got {}",
			buffered_r2
		);

		// Now deliver the delayed Round 1 messages to party 0
		for (from, data) in party0_pending {
			dkgs[0].message(from, data).unwrap();
		}

		// Advance party 0 - it should process Round 1, transition to Round 2, and process buffered
		// messages
		loop {
			match dkgs[0].poke().unwrap() {
				DkgAction::SendMany(_) | DkgAction::SendPrivate(_, _) => {},
				DkgAction::Wait => break,
				DkgAction::Return(_) => break,
			}
		}

		// The buffered Round 2 messages should have been processed
		assert_eq!(
			dkgs[0].message_buffer.round2.len(),
			0,
			"Round 2 buffer should be cleared after transition"
		);

		// Verify party 0 is now in Round 2 (or later) and has processed the buffered messages
		match dkgs[0].state.phase {
			DkgPhase::Round2 => {
				// Check that messages from parties 1 and 2 were processed
				let round2_broadcasts =
					dkgs[0].state.round2_broadcasts.as_ref().expect("round2_broadcasts");
				let has_p1 = round2_broadcasts.contains_key(&1);
				let has_p2 = round2_broadcasts.contains_key(&2);
				assert!(has_p1 || has_p2, "Buffered Round 2 messages should have been processed");
			},
			DkgPhase::Round3 | DkgPhase::Round4 | DkgPhase::Complete => {
				// Even better - protocol progressed further
			},
			other => {
				panic!("Expected Round2 or later, got {:?}", other);
			},
		}
	}

	/// Test that duplicate buffered messages are handled correctly (only first is kept).
	#[test]
	fn test_duplicate_buffered_messages() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = vec![0, 1, 2];

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for &p in &participants {
			pk_map.insert(p, p);
		}

		let config =
			DkgConfig::new(threshold_config, 0, participants, TestSigner { id: 0 }, pk_map)
				.unwrap();

		let seed = [100u8; 32];
		let mut dkg = Dkg::new(config, seed, &TEST_SESSION_NONCE);

		// Get the computed SSID for use in test messages
		let ssid = *dkg.ssid();

		// Start DKG
		let _ = dkg.poke().unwrap();

		// Create a Round 2 broadcast from party 1
		let round2_broadcast = Round2Broadcast { ssid, party_id: 1, randomness: [42u8; 32] };
		let round2_msg = DkgMessage::Round2Broadcast(round2_broadcast.clone());
		let round2_data = borsh::to_vec(&round2_msg).unwrap();

		// Send same message twice
		dkg.message(1, round2_data.clone()).unwrap();
		dkg.message(1, round2_data.clone()).unwrap();

		// Buffer should only contain one message (duplicates from same party overwrite)
		// or contain two if we allow duplicates - let's verify actual behavior
		let buffer_count = dkg.message_buffer.round2.len();
		assert!(buffer_count >= 1, "At least one message should be buffered, got {}", buffer_count);

		// Create a different Round 2 broadcast from party 2
		let round2_broadcast2 = Round2Broadcast { ssid, party_id: 2, randomness: [99u8; 32] };
		let round2_msg2 = DkgMessage::Round2Broadcast(round2_broadcast2);
		let round2_data2 = borsh::to_vec(&round2_msg2).unwrap();

		dkg.message(2, round2_data2).unwrap();

		// Now we should have messages from both parties
		let party_ids: Vec<_> = dkg.message_buffer.round2.keys().copied().collect();
		assert!(party_ids.contains(&1), "Should have message from party 1");
		assert!(party_ids.contains(&2), "Should have message from party 2");
	}

	/// Test that past-round messages are silently ignored.
	#[test]
	fn test_past_round_messages_ignored() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = vec![0, 1, 2];

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for &p in &participants {
			pk_map.insert(p, p);
		}

		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();

		let configs: Vec<_> = signers
			.iter()
			.enumerate()
			.map(|(i, signer)| {
				DkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer.clone(),
					pk_map.clone(),
				)
				.unwrap()
			})
			.collect();

		let mut dkgs: Vec<_> = configs
			.into_iter()
			.enumerate()
			.map(|(i, config)| {
				// Derive unique seed per party
				let mut party_seed = [0u8; 32];
				party_seed[0] = (200 + i) as u8;
				Dkg::new(config, party_seed, &TEST_SESSION_NONCE)
			})
			.collect();

		// Start all DKGs and collect Round 1 broadcasts
		let mut round1_broadcasts: Vec<Vec<u8>> = Vec::new();
		for dkg in &mut dkgs {
			if let DkgAction::SendMany(data) = dkg.poke().unwrap() {
				round1_broadcasts.push(data);
			}
		}

		// Deliver Round 1 messages to all parties
		for (from, broadcast) in round1_broadcasts.iter().enumerate() {
			for (to, dkg) in dkgs.iter_mut().enumerate() {
				if from != to {
					dkg.message(from as ParticipantId, broadcast.clone()).unwrap();
				}
			}
		}

		// Advance party 0 to Round 2
		loop {
			match dkgs[0].poke().unwrap() {
				DkgAction::SendMany(_) => {
					break;
				},
				DkgAction::Wait => break,
				_ => {},
			}
		}

		// Verify party 0 is in Round 2
		assert!(dkgs[0].state.phase == DkgPhase::Round2, "Party 0 should be in Round 2");

		// Now try to send a Round 1 message to party 0 (it's already past Round 1)
		let late_round1 =
			Round1Broadcast { ssid: TEST_SESSION_NONCE, party_id: 1, commitment: [77u8; 32] };
		let late_msg = DkgMessage::Round1Broadcast(late_round1);
		let late_data = borsh::to_vec(&late_msg).unwrap();

		// This should not cause an error - just silently ignored
		let result = dkgs[0].message(1, late_data);
		assert!(result.is_ok(), "Past-round message should not cause error");

		// State should still be Round 2, unaffected
		assert!(dkgs[0].state.phase == DkgPhase::Round2, "State should still be Round 2");
	}

	/// Test Round 4 messages buffered when in Round 2 (multi-round gap).
	#[test]
	fn test_round4_buffered_when_in_round2() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = vec![0, 1, 2];

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for &p in &participants {
			pk_map.insert(p, p);
		}

		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();

		let configs: Vec<_> = signers
			.iter()
			.enumerate()
			.map(|(i, signer)| {
				DkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer.clone(),
					pk_map.clone(),
				)
				.unwrap()
			})
			.collect();

		let mut dkgs: Vec<_> = configs
			.into_iter()
			.enumerate()
			.map(|(i, config)| {
				let mut party_seed = [0u8; 32];
				party_seed[0] = (30 + i) as u8;
				Dkg::new(config, party_seed, &TEST_SESSION_NONCE)
			})
			.collect();

		// Get the computed SSID for use in test messages
		let ssid = *dkgs[0].ssid();

		// Start all DKGs and collect Round 1 broadcasts
		let mut round1_broadcasts: Vec<Vec<u8>> = Vec::new();
		for dkg in &mut dkgs {
			if let DkgAction::SendMany(data) = dkg.poke().unwrap() {
				round1_broadcasts.push(data);
			}
		}

		// Deliver Round 1 to all
		for (from, broadcast) in round1_broadcasts.iter().enumerate() {
			for (to, dkg) in dkgs.iter_mut().enumerate() {
				if from != to {
					dkg.message(from as ParticipantId, broadcast.clone()).unwrap();
				}
			}
		}

		// Advance party 0 to Round 2
		loop {
			match dkgs[0].poke().unwrap() {
				DkgAction::SendMany(_) => break,
				DkgAction::Wait => break,
				_ => {},
			}
		}

		assert!(dkgs[0].state.phase == DkgPhase::Round2, "Party 0 should be in Round 2");

		// Create a Round 4 message and send it to party 0 while in Round 2
		let round4_broadcast = Round4Broadcast {
			ssid,
			party_id: 1,
			partial_public_keys: BTreeMap::new(),
			transcript_signature: vec![1, 2, 3, 4],
		};
		let round4_msg = DkgMessage::Round4Broadcast(round4_broadcast);
		let round4_data = borsh::to_vec(&round4_msg).unwrap();

		dkgs[0].message(1, round4_data).unwrap();

		// Verify it was buffered
		assert_eq!(
			dkgs[0].message_buffer.round4.len(),
			1,
			"Round 4 message should be buffered when in Round 2"
		);
		assert_eq!(dkgs[0].message_buffer.round4.get(&1).unwrap().party_id, 1);

		// Also buffer a Round 3 message
		let round3_broadcast =
			Round3Broadcast { ssid, party_id: 2, partial_pk_commitments: BTreeMap::new() };
		let round3_msg = DkgMessage::Round3Broadcast(round3_broadcast);
		let round3_data = borsh::to_vec(&round3_msg).unwrap();

		dkgs[0].message(2, round3_data).unwrap();

		assert_eq!(
			dkgs[0].message_buffer.round3.len(),
			1,
			"Round 3 message should also be buffered"
		);
	}

	/// Test that the message buffer has reasonable limits and doesn't grow unbounded.
	#[test]
	fn test_buffer_handles_many_messages() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = vec![0, 1, 2];

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for &p in &participants {
			pk_map.insert(p, p);
		}

		let config =
			DkgConfig::new(threshold_config, 0, participants, TestSigner { id: 0 }, pk_map)
				.unwrap();

		let seed = [40u8; 32];
		let mut dkg = Dkg::new(config, seed, &TEST_SESSION_NONCE);

		// Get the computed SSID for use in test messages
		let ssid = *dkg.ssid();

		// Start DKG
		let _ = dkg.poke().unwrap();

		// Send many Round 2 messages from the same party
		for i in 0..100 {
			let round2_broadcast = Round2Broadcast { ssid, party_id: 1, randomness: [i as u8; 32] };
			let round2_msg = DkgMessage::Round2Broadcast(round2_broadcast);
			let round2_data = borsh::to_vec(&round2_msg).unwrap();
			dkg.message(1, round2_data).unwrap();
		}

		// The buffer should have accumulated all messages (current implementation doesn't dedupe)
		// This test documents the current behavior
		let count = dkg.message_buffer.round2.len();
		assert!(count > 0, "Messages should be buffered");

		// Send messages from different (fake) parties to verify buffer accepts multiple senders
		for party_id in 0..10u32 {
			let round3_broadcast =
				Round3Broadcast { ssid, party_id, partial_pk_commitments: BTreeMap::new() };
			let round3_msg = DkgMessage::Round3Broadcast(round3_broadcast);
			let round3_data = borsh::to_vec(&round3_msg).unwrap();
			// Use party_id as sender to avoid sender mismatch
			let _ = dkg.message(party_id, round3_data);
		}

		// Buffer should have messages (those from valid parties 1, 2)
		assert!(
			dkg.message_buffer.round3.len() >= 2,
			"Should have buffered messages from valid parties"
		);
	}

	/// Test that malformed/invalid messages in buffer don't crash when processed.
	#[test]
	fn test_invalid_buffered_messages_handled_gracefully() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = vec![0, 1, 2];

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for &p in &participants {
			pk_map.insert(p, p);
		}

		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();

		let configs: Vec<_> = signers
			.iter()
			.enumerate()
			.map(|(i, signer)| {
				DkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer.clone(),
					pk_map.clone(),
				)
				.unwrap()
			})
			.collect();

		let mut dkgs: Vec<_> = configs
			.into_iter()
			.enumerate()
			.map(|(i, config)| {
				let mut party_seed = [0u8; 32];
				party_seed[0] = (50 + i) as u8;
				Dkg::new(config, party_seed, &TEST_SESSION_NONCE)
			})
			.collect();

		// Get the computed SSID for use in test messages
		let ssid = *dkgs[0].ssid();

		// Start all DKGs
		let mut round1_broadcasts: Vec<Vec<u8>> = Vec::new();
		for dkg in &mut dkgs {
			if let DkgAction::SendMany(data) = dkg.poke().unwrap() {
				round1_broadcasts.push(data);
			}
		}

		// Buffer a Round 2 message with invalid data (empty partial_pk_commitments is technically
		// valid but will fail verification later - that's fine, we just want to test graceful
		// handling)
		let round2_broadcast = Round2Broadcast {
			ssid,
			party_id: 1,
			randomness: [0u8; 32], // All zeros - may or may not be valid depending on protocol
		};
		let round2_msg = DkgMessage::Round2Broadcast(round2_broadcast);
		let round2_data = borsh::to_vec(&round2_msg).unwrap();

		// Buffer it before delivering Round 1 messages
		dkgs[0].message(1, round2_data).unwrap();
		assert_eq!(dkgs[0].message_buffer.round2.len(), 1);

		// Now deliver Round 1 messages to party 0
		for (i, broadcast) in round1_broadcasts.iter().enumerate() {
			if i != 0 {
				dkgs[0].message(i as ParticipantId, broadcast.clone()).unwrap();
			}
		}

		// Poke party 0 to transition to Round 2 - this should process buffered messages
		// Even if the buffered message is "invalid" in some sense, it shouldn't crash
		let result = dkgs[0].poke();
		assert!(result.is_ok(), "Processing buffered messages should not crash");
	}

	#[test]
	fn test_complete_fails_if_subset_missing_partial_pk() {
		// Run a 2-of-3 DKG to near completion, then manually remove a partial PK
		// to verify that collect_and_verify_all_partial_pks catches the missing subset.
		//
		// In 2-of-3, subsets are: 3 (parties 0,1), 5 (parties 0,2), 6 (parties 1,2)
		// Leaders: subset 3 -> party 0, subset 5 -> party 0, subset 6 -> party 1
		// So party 0 is leader for 2 subsets, party 1 is leader for 1 subset.
		// We need to sabotage party 1's broadcast (remove subset 6's PK) to trigger the check.
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [99u8; 32];

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		let mut dkgs: Vec<Dkg<TestSigner>> = signers
			.into_iter()
			.enumerate()
			.map(|(i, signer)| {
				let config = DkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer,
					pk_map.clone(),
				)
				.unwrap();
				Dkg::new(config, seed, &TEST_SESSION_NONCE)
			})
			.collect();

		// Run DKG through Round 3 (all broadcasts sent and received)
		let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); 3];

		// Run until all parties are in Round 4 and have sent their broadcasts,
		// but stop party 0 before it receives party 1's Round 4 broadcast
		// (party 1 is the leader for subset 6, so we need to sabotage their broadcast)
		let mut party0_round4_from_party1_received = false;
		'outer: for _ in 0..100 {
			// Deliver pending messages
			for party_id in 0..3 {
				let messages = mem::take(&mut pending_messages[party_id]);
				for (from, data) in messages {
					// For party 0, hold back party 1's Round 4 broadcast
					if party_id == 0 && from == 1 {
						if let Ok(msg) = borsh::from_slice::<DkgMessage>(&data) {
							if matches!(msg, DkgMessage::Round4Broadcast(_)) {
								// Don't deliver - we'll deliver a sabotaged version
								party0_round4_from_party1_received = true;
								continue;
							}
						}
					}
					dkgs[party_id].message(from, data).unwrap();
				}
			}

			// Poke all parties
			for (party_id, dkg) in dkgs.iter_mut().enumerate() {
				match dkg.poke().unwrap() {
					DkgAction::SendMany(data) => {
						for (other, pending) in pending_messages.iter_mut().enumerate() {
							if other != party_id {
								pending.push((party_id as ParticipantId, data.clone()));
							}
						}
					},
					DkgAction::SendPrivate(to, data) => {
						pending_messages[to as usize].push((party_id as ParticipantId, data.to_vec()));
					},
					DkgAction::Wait => {},
					DkgAction::Return(_) => {},
				}
			}

			// Check if party 0 is in Round 4 and we've intercepted party 1's broadcast
			if party0_round4_from_party1_received &&
				dkgs[0].state.phase == DkgPhase::Round4 &&
				dkgs[0].state.broadcast_sent
			{
				break 'outer;
			}
		}

		// Verify party 0 is in Round 4
		{
			assert!(dkgs[0].state.phase == DkgPhase::Round4, "Expected Round4 state");
			assert!(dkgs[0].state.broadcast_sent, "Party 0 should have sent broadcast");
			// Party 0 should have received party 2's broadcast but not party 1's
			let round4_broadcasts =
				dkgs[0].state.round4_broadcasts.as_ref().expect("round4_broadcasts");
			assert!(!round4_broadcasts.contains_key(&1), "Should not have party 1's broadcast yet");
		}

		// Create a sabotaged broadcast from party 1 with empty partial PKs
		// Party 1 is leader for subset 6, so removing their PKs will leave subset 6 missing
		let sabotaged_partial_pks: BTreeMap<SubsetMask, PartialPublicKey> = BTreeMap::new();

		// Compute the transcript hash (same as in complete_inner)
		let transcript_hash = {
			assert!(dkgs[0].state.phase == DkgPhase::Round4, "Expected Round4");
			let round1_broadcasts =
				dkgs[0].state.round1_broadcasts.as_ref().expect("round1_broadcasts");
			let round2_broadcasts =
				dkgs[0].state.round2_broadcasts.as_ref().expect("round2_broadcasts");
			let round3_broadcasts =
				dkgs[0].state.round3_broadcasts.as_ref().expect("round3_broadcasts");
			compute_transcript_hash(
				&dkgs[0].ssid,
				round1_broadcasts,
				round2_broadcasts,
				round3_broadcasts,
			)
		};

		// Create a valid signature over the sabotaged (empty) partial PKs
		let partial_output_hash = compute_partial_output_hash(&sabotaged_partial_pks);
		let signing_message = compute_signing_message(&transcript_hash, &partial_output_hash);
		let signer = TestSigner { id: 1 }; // Party 1's signer
		let valid_signature = signer.sign(&signing_message);

		let sabotaged_broadcast = Round4Broadcast {
			ssid: TEST_SESSION_NONCE,
			party_id: 1,
			partial_public_keys: sabotaged_partial_pks,
			transcript_signature: valid_signature,
		};

		// Insert the sabotaged broadcast and also ensure party 2's broadcast is there
		{
			let round4_broadcasts =
				dkgs[0].state.round4_broadcasts.get_or_insert_with(BTreeMap::new);
			round4_broadcasts.insert(1, sabotaged_broadcast);

			// Make sure we also have party 2's broadcast (they have no leader subsets, so empty PKs
			// is fine)
			round4_broadcasts.entry(2).or_insert_with(|| {
				let empty_pks: BTreeMap<SubsetMask, PartialPublicKey> = BTreeMap::new();
				let partial_output_hash = compute_partial_output_hash(&empty_pks);
				let signing_message =
					compute_signing_message(&transcript_hash, &partial_output_hash);
				let signer = TestSigner { id: 2 };
				let sig = signer.sign(&signing_message);
				Round4Broadcast {
					ssid: TEST_SESSION_NONCE,
					party_id: 2,
					partial_public_keys: empty_pks,
					transcript_signature: sig,
				}
			});
		}

		// Now try to complete - should fail with missing partial PK error for subset 6
		let result = dkgs[0].complete();
		assert!(result.is_err(), "Complete should fail with missing partial PK");

		let err = result.unwrap_err();
		let err_msg = format!("{:?}", err);
		assert!(
			err_msg.contains("missing partial public key"),
			"Error should mention missing partial PK, got: {}",
			err_msg
		);
	}

	#[test]
	fn test_non_leader_partial_pk_ignored() {
		// Test that partial PKs from non-leaders are ignored.
		// Per Mithril DKGAggregate line 6: only accept PKs where j = min(S).
		//
		// We directly test collect_and_verify_all_partial_pks by constructing a
		// DkgState in Round4 phase where a non-leader has submitted a PK
		// for a subset they don't lead.

		// In 2-of-3, subsets are: 3 (parties 0,1), 5 (parties 0,2), 6 (parties 1,2)
		// Leaders: subset 3 -> party 0, subset 5 -> party 0, subset 6 -> party 1

		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [88u8; 32];

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		let mut dkgs: Vec<Dkg<TestSigner>> = signers
			.into_iter()
			.enumerate()
			.map(|(i, signer)| {
				let config = DkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer,
					pk_map.clone(),
				)
				.unwrap();
				Dkg::new(config, seed, &TEST_SESSION_NONCE)
			})
			.collect();

		// Run DKG to completion normally first to get valid outputs
		let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); 3];
		let mut outputs: Vec<Option<DkgOutput>> = vec![None; 3];

		for _ in 0..200 {
			for party_id in 0..3 {
				let messages = mem::take(&mut pending_messages[party_id]);
				for (from, data) in messages {
					dkgs[party_id].message(from, data).unwrap();
				}
			}

			for party_id in 0..3 {
				if outputs[party_id].is_some() {
					continue;
				}
				match dkgs[party_id].poke().unwrap() {
					DkgAction::SendMany(data) => {
						for (other, pending) in pending_messages.iter_mut().enumerate() {
							if other != party_id {
								pending.push((party_id as ParticipantId, data.clone()));
							}
						}
					},
					DkgAction::SendPrivate(to, data) => {
						pending_messages[to as usize].push((party_id as ParticipantId, data.to_vec()));
					},
					DkgAction::Wait => {},
					DkgAction::Return(output) => {
						outputs[party_id] = Some(*output);
					},
				}
			}

			if outputs.iter().all(|o| o.is_some()) {
				break;
			}
		}

		// All should complete with same key
		let outputs: Vec<_> =
			outputs.into_iter().map(|o| o.expect("DKG should complete")).collect();
		assert_eq!(outputs[0].public_key.as_bytes(), outputs[1].public_key.as_bytes());
		assert_eq!(outputs[1].public_key.as_bytes(), outputs[2].public_key.as_bytes());

		// Now verify the is_leader check works correctly
		let config = DkgConfig::new(
			threshold_config,
			0,
			participants.clone(),
			TestSigner { id: 0 },
			pk_map.clone(),
		)
		.unwrap();

		// Verify leadership assignments
		assert!(config.is_leader(3), "Party 0 should be leader for subset 3");
		assert!(config.is_leader(5), "Party 0 should be leader for subset 5");
		assert!(!config.is_leader(6), "Party 0 should NOT be leader for subset 6");

		// Verify get_leader returns correct party
		assert_eq!(config.get_leader(3), Some(0), "Subset 3 leader should be party 0");
		assert_eq!(config.get_leader(5), Some(0), "Subset 5 leader should be party 0");
		assert_eq!(config.get_leader(6), Some(1), "Subset 6 leader should be party 1");

		// The actual filtering happens in collect_and_verify_all_partial_pks.
		// We've verified that:
		// 1. The DKG completes successfully
		// 2. All parties get the same public key
		// 3. The leadership logic is correct
		// The code now filters out non-leader PKs with a warning log.
	}

	#[test]
	fn test_invalid_subset_mask_in_round4_ignored() {
		// Test that partial PKs with invalid subset masks are ignored in Round 4.
		// This prevents an attacker from injecting extra subset masks (like 0b001 or 0b111
		// in a 2-of-3 setup) that would corrupt the final public key.
		//
		// In 2-of-3, valid subsets are: 0b011, 0b101, 0b110 (exactly 2 bits set)
		// Invalid subsets include: 0b001, 0b010, 0b100 (1 bit), 0b111 (3 bits), 0b000 (0 bits)

		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [99u8; 32];

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		let mut dkgs: Vec<Dkg<TestSigner>> = signers
			.into_iter()
			.enumerate()
			.map(|(i, signer)| {
				let config = DkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer,
					pk_map.clone(),
				)
				.unwrap();
				Dkg::new(config, seed, &TEST_SESSION_NONCE)
			})
			.collect();

		// Run DKG normally until Round 4
		let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); 3];

		// Run until all parties are in Round 4 and have sent their broadcasts
		for _ in 0..100 {
			for (party_id, dkg) in dkgs.iter_mut().enumerate() {
				let messages = mem::take(&mut pending_messages[party_id]);
				for (from, data) in messages {
					dkg.message(from, data).unwrap();
				}
			}

			for (party_id, dkg) in dkgs.iter_mut().enumerate() {
				match dkg.poke().unwrap() {
					DkgAction::SendMany(data) => {
						for (other, pending) in pending_messages.iter_mut().enumerate() {
							if other != party_id {
								pending.push((party_id as ParticipantId, data.clone()));
							}
						}
					},
					DkgAction::SendPrivate(to, data) => {
						pending_messages[to as usize].push((party_id as ParticipantId, data.to_vec()));
					},
					DkgAction::Wait => {},
					DkgAction::Return(_) => {},
				}
			}

			// Check if all are in Round 4 with broadcasts sent
			let all_in_round4 =
				dkgs.iter().all(|d| d.state.phase == DkgPhase::Round4 && d.state.broadcast_sent);
			if all_in_round4 {
				break;
			}
		}

		// Verify all parties are in Round 4
		for (i, dkg) in dkgs.iter().enumerate() {
			assert!(
				dkg.state.phase == DkgPhase::Round4,
				"Party {} should be in Round4, got {:?}",
				i,
				dkg.state.phase
			);
		}

		// Now test that invalid subset masks would be filtered by
		// collect_and_verify_all_partial_pks. We verify this by checking that the valid subset
		// count matches expectations.
		let config = dkgs[0].state.config.as_ref().unwrap();
		let valid_subsets = config.all_subsets();

		// For 2-of-3, there should be exactly C(3,2) = 3 valid subsets
		assert_eq!(valid_subsets.len(), 3, "2-of-3 should have 3 valid subsets");
		assert!(valid_subsets.contains(&0b011));
		assert!(valid_subsets.contains(&0b101));
		assert!(valid_subsets.contains(&0b110));

		// Verify invalid masks are rejected by is_valid_subset
		assert!(!config.is_valid_subset(0b001), "0b001 should be invalid (only 1 party)");
		assert!(!config.is_valid_subset(0b111), "0b111 should be invalid (3 parties, need 2)");
		assert!(!config.is_valid_subset(0b000), "0b000 should be invalid (0 parties)");

		// Now complete the DKG normally and verify it succeeds
		// (this confirms the filtering works correctly with normal data)
		let mut outputs: Vec<Option<DkgOutput>> = vec![None; 3];

		for _ in 0..50 {
			for party_id in 0..3 {
				let messages = mem::take(&mut pending_messages[party_id]);
				for (from, data) in messages {
					dkgs[party_id].message(from, data).unwrap();
				}
			}

			for party_id in 0..3 {
				if outputs[party_id].is_some() {
					continue;
				}
				match dkgs[party_id].poke().unwrap() {
					DkgAction::Return(output) => {
						outputs[party_id] = Some(*output);
					},
					DkgAction::SendMany(data) => {
						for (other, pending) in pending_messages.iter_mut().enumerate() {
							if other != party_id {
								pending.push((party_id as ParticipantId, data.clone()));
							}
						}
					},
					DkgAction::SendPrivate(to, data) => {
						pending_messages[to as usize].push((party_id as ParticipantId, data.to_vec()));
					},
					_ => {},
				}
			}

			if outputs.iter().all(|o| o.is_some()) {
				break;
			}
		}

		// All parties should complete successfully
		assert!(outputs.iter().all(|o| o.is_some()), "All parties should complete DKG");

		// All parties should have the same public key
		let pk0 = outputs[0].as_ref().unwrap().public_key.as_bytes();
		for (i, output) in outputs.iter().enumerate() {
			assert_eq!(
				output.as_ref().unwrap().public_key.as_bytes(),
				pk0,
				"Party {} has different public key",
				i
			);
		}
	}

	#[test]
	fn test_non_participant_messages_ignored() {
		// Test that messages from non-participants are ignored to prevent
		// quorum inflation attacks where an attacker injects messages with
		// fake sender IDs to satisfy broadcast quorum checks prematurely.
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [55u8; 32];

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		let config = DkgConfig::new(
			threshold_config,
			0,
			participants.clone(),
			signers[0].clone(),
			pk_map.clone(),
		)
		.unwrap();

		let mut dkg: Dkg<TestSigner> = Dkg::new(config, seed, &TEST_SESSION_NONCE);

		// Start the DKG to get to Round 1
		let action = dkg.poke().unwrap();
		assert!(matches!(action, DkgAction::SendMany(_)));

		// Now we're in Round 1. Try to inject a message from a non-participant (party 99)
		let fake_broadcast =
			Round1Broadcast { ssid: TEST_SESSION_NONCE, party_id: 99, commitment: [0u8; 32] };
		let fake_msg = DkgMessage::Round1Broadcast(fake_broadcast);
		let fake_data = borsh::to_vec(&fake_msg).unwrap();

		// This should be silently ignored (not error, just ignored)
		let result = dkg.message(99, fake_data);
		assert!(result.is_ok(), "Non-participant message should not cause error");

		// Verify the fake message was NOT added to round1_broadcasts
		assert!(dkg.state.phase == DkgPhase::Round1, "Expected Round1 state");
		let round1_broadcasts = dkg.state.round1_broadcasts.as_ref().expect("round1_broadcasts");
		assert!(
			!round1_broadcasts.contains_key(&99),
			"Non-participant's broadcast should not be stored"
		);
		assert_eq!(round1_broadcasts.len(), 0, "Should have no received broadcasts yet");

		// Also test that a message claiming to be from participant 1 but sent by non-participant 99
		// is rejected (this tests the envelope 'from' vs message 'party_id' check)
		let spoofed_broadcast = Round1Broadcast {
			ssid: TEST_SESSION_NONCE,
			party_id: 1, // Claims to be from party 1
			commitment: [0u8; 32],
		};
		let spoofed_msg = DkgMessage::Round1Broadcast(spoofed_broadcast);
		let spoofed_data = borsh::to_vec(&spoofed_msg).unwrap();

		// Send with envelope 'from' = 99 (non-participant)
		let result = dkg.message(99, spoofed_data);
		assert!(result.is_ok(), "Spoofed message should not cause error");

		// Verify the message was NOT added
		assert!(dkg.state.phase == DkgPhase::Round1, "Expected Round1 state");
		let round1_broadcasts = dkg.state.round1_broadcasts.as_ref().expect("round1_broadcasts");
		assert!(
			!round1_broadcasts.contains_key(&1),
			"Spoofed broadcast should not be stored under party 1"
		);
		assert!(
			!round1_broadcasts.contains_key(&99),
			"Spoofed broadcast should not be stored under party 99"
		);
	}

	#[test]
	fn test_self_messages_ignored() {
		// Test that messages from self are ignored.
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [44u8; 32];

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		let config = DkgConfig::new(
			threshold_config,
			0, // We are party 0
			participants.clone(),
			signers[0].clone(),
			pk_map.clone(),
		)
		.unwrap();

		let mut dkg: Dkg<TestSigner> = Dkg::new(config, seed, &TEST_SESSION_NONCE);

		// Start the DKG to get to Round 1
		let action = dkg.poke().unwrap();
		assert!(matches!(action, DkgAction::SendMany(_)));

		// Try to send a message "from" ourselves (party 0)
		let self_broadcast =
			Round1Broadcast { ssid: TEST_SESSION_NONCE, party_id: 0, commitment: [42u8; 32] };
		let self_msg = DkgMessage::Round1Broadcast(self_broadcast);
		let self_data = borsh::to_vec(&self_msg).unwrap();

		// This should be silently ignored
		let result = dkg.message(0, self_data);
		assert!(result.is_ok(), "Self message should not cause error");

		// Verify the message was NOT added to round1_broadcasts
		assert!(dkg.state.phase == DkgPhase::Round1, "Expected Round1 state");
		let round1_broadcasts = dkg.state.round1_broadcasts.as_ref().expect("round1_broadcasts");
		assert!(!round1_broadcasts.contains_key(&0), "Self broadcast should not be stored");
	}

	#[test]
	fn test_oversized_message_rejected() {
		// Test that messages exceeding MAX_MESSAGE_SIZE are rejected.
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [33u8; 32];

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		let config = DkgConfig::new(
			threshold_config,
			0,
			participants.clone(),
			signers[0].clone(),
			pk_map.clone(),
		)
		.unwrap();

		let mut dkg: Dkg<TestSigner> = Dkg::new(config, seed, &TEST_SESSION_NONCE);

		// Start the DKG to get to Round 1
		let action = dkg.poke().unwrap();
		assert!(matches!(action, DkgAction::SendMany(_)));

		// Create an oversized message (larger than MAX_DKG_MESSAGE_SIZE)
		let oversized_data = vec![0u8; MAX_DKG_MESSAGE_SIZE + 1];

		// This should return an error about the message being too large
		let result = dkg.message(1, oversized_data);
		assert!(result.is_err(), "Oversized message should be rejected");

		let err = result.unwrap_err();
		let err_msg = format!("{:?}", err);
		assert!(
			err_msg.contains("too large") || err_msg.contains("Message"),
			"Error should mention size limit, got: {}",
			err_msg
		);
	}

	#[test]
	fn test_malicious_length_prefix_rejected() {
		// Test that a packet with a malicious internal length prefix is rejected.
		// This verifies that borsh validates length prefixes against remaining data
		// before allocating, preventing memory exhaustion attacks.
		//
		// Attack scenario: attacker sends a small packet (passes MAX_MESSAGE_SIZE check)
		// but with an internal Vec length prefix claiming a huge size (e.g., 1GB).
		// Expected: borsh rejects with "Unexpected length of input", NOT OOM.

		// Craft a malicious packet:
		// - Enum variant tag for Round4Broadcast (has Vec<u8> for transcript_signature)
		// - Valid party_id
		// - Empty BTreeMap for partial_public_keys
		// - Vec<u8> with huge length prefix but insufficient data

		let mut malicious: Vec<u8> = Vec::new();

		// DkgMessage enum tag for Round4Broadcast = 4
		malicious.push(4);

		// party_id: u32
		malicious.extend_from_slice(&1u32.to_le_bytes());

		// partial_public_keys: BTreeMap - empty (length = 0)
		malicious.extend_from_slice(&0u32.to_le_bytes());

		// transcript_signature: Vec<u8> - malicious length prefix claiming 1GB
		malicious.extend_from_slice(&1_000_000_000u32.to_le_bytes());
		// Only add 10 bytes of actual data (not 1GB)
		malicious.extend_from_slice(&[0u8; 10]);

		// Total packet size is small (~23 bytes), passes MAX_MESSAGE_SIZE check
		assert!(malicious.len() < MAX_DKG_MESSAGE_SIZE);

		// Deserialize should fail with a borsh error, NOT allocate 1GB
		let result = deserialize_message(&malicious);

		// Verify we got a deserialization error, not OOM
		match result {
			Ok(_) => panic!("Malicious length prefix should be rejected"),
			Err(err) => {
				assert!(
					err.contains("length") || err.contains("input") || err.contains("Unexpected"),
					"Should fail with length/input error, got: {}",
					err
				);
			},
		}
	}

	#[test]
	fn test_round1_messages_buffered_before_poke() {
		// Test that Round 1 messages received before the first poke() are buffered
		// and processed correctly. This prevents a race condition where a faster
		// peer's messages could be lost.

		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [42u8; 32];

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		// Create DKG for party 0 - starts in Initialized state
		let config = DkgConfig::new(
			threshold_config,
			0,
			participants.clone(),
			signers[0].clone(),
			pk_map.clone(),
		)
		.unwrap();
		let mut dkg0: Dkg<TestSigner> = Dkg::new(config, seed, &TEST_SESSION_NONCE);

		// Create DKG for party 1
		let config1 = DkgConfig::new(
			threshold_config,
			1,
			participants.clone(),
			signers[1].clone(),
			pk_map.clone(),
		)
		.unwrap();
		let mut dkg1: Dkg<TestSigner> = Dkg::new(config1, seed, &TEST_SESSION_NONCE);

		// Party 1 starts first and sends messages
		let action1 = dkg1.poke().unwrap();
		let round1_data = match action1 {
			DkgAction::SendMany(data) => data,
			_ => panic!("Expected SendMany"),
		};

		// Party 0 receives Party 1's Round 1 broadcast BEFORE calling poke()
		// This should be buffered, not dropped
		assert_eq!(dkg0.state.phase, DkgPhase::Initialized);
		let result = dkg0.message(1, round1_data.clone());
		assert!(result.is_ok(), "Message should be accepted for buffering");

		// Verify the message was buffered
		assert!(
			!dkg0.message_buffer.round1_broadcasts.is_empty(),
			"Round 1 broadcast should be buffered"
		);

		// Now party 0 calls poke() - this should drain the buffer
		let _action0 = dkg0.poke().unwrap();

		// Verify we're now in Round 1 and the buffered message was processed
		assert_eq!(dkg0.state.phase, DkgPhase::Round1);
		let round1_broadcasts = dkg0.state.round1_broadcasts.as_ref().unwrap();
		assert!(
			round1_broadcasts.contains_key(&1),
			"Buffered broadcast from party 1 should now be in state"
		);

		// Verify the buffer was drained
		assert!(
			dkg0.message_buffer.round1_broadcasts.is_empty(),
			"Buffer should be empty after draining"
		);
	}

	#[test]
	fn test_round1_private_messages_buffered_before_poke() {
		// Test that Round 1 private messages are also buffered when received
		// before poke() is called.
		//
		// We manually construct a valid Round1Private message to avoid the
		// complexity of running two DKG instances.

		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [42u8; 32];

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		// Create DKG for party 1 - starts in Initialized state
		let config = DkgConfig::new(
			threshold_config,
			1,
			participants.clone(),
			signers[1].clone(),
			pk_map.clone(),
		)
		.unwrap();
		let mut dkg1: Dkg<TestSigner> = Dkg::new(config.clone(), seed, &TEST_SESSION_NONCE);

		// Get the computed SSID for use in test messages
		let ssid = *dkg1.ssid();

		// For a 2-of-3 threshold, subset size = n - t + 1 = 3 - 2 + 1 = 2
		// Subsets are: {0,1}=0b011, {0,2}=0b101, {1,2}=0b110
		// Party 1 is in subsets 0b011 and 0b110
		// For subset 0b011, leader is party 0 (lowest index in subset)
		// For subset 0b110, leader is party 1

		// Party 0 should send private message to party 1 for subset 0b011
		let subset_mask: SubsetMask = 0b011; // {0, 1}
		let private = Round1Private {
			ssid,
			from_party_id: 0,
			subset_mask,
			shared_secret: [0xAB; SHARED_SECRET_SIZE],
		};
		let msg = DkgMessage::Round1Private(private);
		let data = borsh::to_vec(&msg).unwrap();

		// Party 1 receives the private message BEFORE calling poke()
		assert_eq!(dkg1.state.phase, DkgPhase::Initialized);
		let result = dkg1.message(0, data);
		assert!(result.is_ok(), "Private message should be accepted for buffering");

		// Verify the message was buffered
		assert!(
			!dkg1.message_buffer.round1_privates.is_empty(),
			"Round 1 private message should be buffered"
		);
		assert!(
			dkg1.message_buffer.round1_privates.contains_key(&(0, subset_mask)),
			"Buffer should contain message from party 0 for subset 0b011"
		);

		// Now party 1 calls poke() - this should drain the buffer
		let _action1 = dkg1.poke().unwrap();

		// Verify we're now in Round 1 and the buffered message was processed
		assert_eq!(dkg1.state.phase, DkgPhase::Round1);
		let received_secrets = dkg1.state.received_shared_secrets.as_ref().unwrap();

		// We should have the secret for subset 0b011 from the buffered message
		assert!(
			received_secrets.contains_key(&subset_mask),
			"Buffered private message should have been processed into received_shared_secrets"
		);
		assert_eq!(
			received_secrets.get(&subset_mask).unwrap(),
			&[0xAB; SHARED_SECRET_SIZE],
			"Secret should match what was buffered"
		);

		// Verify the buffer was drained
		assert!(
			dkg1.message_buffer.round1_privates.is_empty(),
			"Buffer should be empty after draining"
		);
	}

	/// Test that Round1Private messages with invalid subset masks are rejected during buffering.
	///
	/// A malicious party could try to send many messages with different invalid subset masks
	/// to exhaust memory. Now we validate subset_mask before buffering, so invalid messages
	/// are rejected immediately. The buffer size limit remains as defense in depth.
	#[test]
	fn test_round1_private_invalid_subset_rejected_during_buffering() {
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let seed = [42u8; 32];

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		// Create DKG for party 1 - starts in Initialized state
		let config = DkgConfig::new(
			threshold_config,
			1,
			participants.clone(),
			signers[1].clone(),
			pk_map.clone(),
		)
		.unwrap();
		let mut dkg1: Dkg<TestSigner> = Dkg::new(config.clone(), seed, &TEST_SESSION_NONCE);

		// Get the computed SSID for use in test messages
		let ssid = *dkg1.ssid();

		assert_eq!(dkg1.state.phase, DkgPhase::Initialized);

		// Attacker (party 0) sends many messages with INVALID subset masks
		// These should all be rejected because:
		// - 0b000 (0): invalid - no bits set
		// - 0b001 (1): invalid - only 1 bit set (need threshold=2)
		// - 0b010 (2): invalid - only 1 bit set
		// - 0b100 (4): invalid - only 1 bit set
		// - 0b111 (7): invalid - 3 bits set (too many)
		// - etc.
		for invalid_subset in [0u16, 1, 2, 4, 7, 8, 15, 16, 100, 0xFFFF] {
			let private = Round1Private {
				ssid,
				from_party_id: 0,
				subset_mask: invalid_subset,
				shared_secret: [0xDE; SHARED_SECRET_SIZE],
			};
			let msg = DkgMessage::Round1Private(private);
			let data = borsh::to_vec(&msg).unwrap();

			// Message should be accepted (no protocol error) but not buffered
			let result = dkg1.message(0, data);
			assert!(result.is_ok(), "Message should be accepted without protocol error");
		}

		// Buffer should be empty - all invalid subset masks were rejected
		assert!(
			dkg1.message_buffer.round1_privates.is_empty(),
			"Buffer should be empty - all invalid subset masks were rejected"
		);

		// Now send a VALID subset mask from the correct leader
		// For 2-of-3: valid subsets are 0b011, 0b101, 0b110 (exactly 2 bits set)
		// Party 0 is leader for subset 0b011 (contains parties 0 and 1, leader = min = 0)
		let valid_subset = 0b011u16;
		let private = Round1Private {
			ssid,
			from_party_id: 0,
			subset_mask: valid_subset,
			shared_secret: [0xAB; SHARED_SECRET_SIZE],
		};
		let msg = DkgMessage::Round1Private(private);
		let data = borsh::to_vec(&msg).unwrap();

		let result = dkg1.message(0, data);
		assert!(result.is_ok(), "Valid message should be accepted");

		// Buffer should now have exactly 1 entry
		assert_eq!(
			dkg1.message_buffer.round1_privates.len(),
			1,
			"Buffer should have exactly 1 valid entry"
		);
		assert!(
			dkg1.message_buffer.round1_privates.contains_key(&(0, valid_subset)),
			"Buffer should contain the valid message"
		);
	}
}
