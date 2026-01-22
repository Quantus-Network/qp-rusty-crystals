//! DKG Protocol State Machine.
//!
//! This module defines the state machine for the 4-round DKG protocol.
//! The state machine tracks which round we're in, what data we've collected
//! from other parties, and manages transitions between rounds.
//!
//! ## Message Buffering
//!
//! In distributed systems, messages may arrive out of order. For example, a fast
//! node might send its Round 2 message before a slower node has finished processing
//! all Round 1 messages. To handle this, we buffer messages that arrive for future
//! rounds and process them when we transition to the appropriate state.

use std::collections::HashMap;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::types::{
	DkgConfig, DkgMessage, DkgOutput, DkgRound1Broadcast, DkgRound2Broadcast, DkgRound3Broadcast,
	DkgRound4Broadcast, ParticipantId, PartyContributions, COMMITMENT_HASH_SIZE, SESSION_ID_SIZE,
};

use crate::participants::ParticipantList;

/// The current state of the DKG protocol.
#[derive(Debug, Clone)]
pub enum DkgState {
	/// Initial state, ready to start Round 1.
	Initialized,

	/// Round 1: Generating and sending session ID contribution.
	Round1Generating,

	/// Round 1: Waiting for session ID contributions from other parties.
	Round1Waiting,

	/// Round 2: Generating contributions and sending commitment hash.
	Round2Generating,

	/// Round 2: Waiting for commitment hashes from other parties.
	Round2Waiting,

	/// Round 3: Revealing contributions.
	Round3Revealing,

	/// Round 3: Waiting for revealed contributions from other parties.
	Round3Waiting,

	/// Round 4: Sending confirmation.
	Round4Confirming,

	/// Round 4: Waiting for confirmations from other parties.
	Round4Waiting,

	/// Protocol completed successfully.
	Complete,

	/// Protocol failed with an error.
	Failed(String),
}

impl DkgState {
	/// Get a human-readable name for the current state.
	pub fn name(&self) -> &'static str {
		match self {
			DkgState::Initialized => "Initialized",
			DkgState::Round1Generating => "Round1Generating",
			DkgState::Round1Waiting => "Round1Waiting",
			DkgState::Round2Generating => "Round2Generating",
			DkgState::Round2Waiting => "Round2Waiting",
			DkgState::Round3Revealing => "Round3Revealing",
			DkgState::Round3Waiting => "Round3Waiting",
			DkgState::Round4Confirming => "Round4Confirming",
			DkgState::Round4Waiting => "Round4Waiting",
			DkgState::Complete => "Complete",
			DkgState::Failed(_) => "Failed",
		}
	}

	/// Check if the protocol is still in progress.
	pub fn is_in_progress(&self) -> bool {
		!matches!(self, DkgState::Complete | DkgState::Failed(_))
	}

	/// Check if the protocol has completed successfully.
	pub fn is_complete(&self) -> bool {
		matches!(self, DkgState::Complete)
	}

	/// Check if the protocol has failed.
	pub fn is_failed(&self) -> bool {
		matches!(self, DkgState::Failed(_))
	}

	/// Get the current round number (0 = not started, 1-4 = in progress, 5 = complete).
	pub fn round_number(&self) -> u8 {
		match self {
			DkgState::Initialized => 0,
			DkgState::Round1Generating | DkgState::Round1Waiting => 1,
			DkgState::Round2Generating | DkgState::Round2Waiting => 2,
			DkgState::Round3Revealing | DkgState::Round3Waiting => 3,
			DkgState::Round4Confirming | DkgState::Round4Waiting => 4,
			DkgState::Complete => 5,
			DkgState::Failed(_) => 0,
		}
	}

	/// Check if messages for a given round can be accepted in this state.
	pub fn can_accept_round(&self, msg_round: u8) -> bool {
		let current_round = self.round_number();
		// Can accept messages for current round or already-processed rounds (duplicates will be
		// caught later)
		msg_round <= current_round
	}
}

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
pub struct MessageBuffer {
	/// Buffered Round 2 messages (from parties that are ahead of us).
	pub round2: Vec<DkgRound2Broadcast>,
	/// Buffered Round 3 messages.
	pub round3: Vec<DkgRound3Broadcast>,
	/// Buffered Round 4 messages.
	pub round4: Vec<DkgRound4Broadcast>,
}

impl MessageBuffer {
	/// Create a new empty message buffer.
	pub fn new() -> Self {
		Self { round2: Vec::new(), round3: Vec::new(), round4: Vec::new() }
	}

	/// Buffer a message for later processing.
	pub fn buffer(&mut self, msg: DkgMessage) {
		match msg {
			DkgMessage::Round1(_) => {
				// Round 1 messages should never need buffering since it's the first round
				// If we receive a Round1 message late, we're already past it
			},
			DkgMessage::Round2(m) => self.round2.push(m),
			DkgMessage::Round3(m) => self.round3.push(m),
			DkgMessage::Round4(m) => self.round4.push(m),
		}
	}

	/// Take all buffered messages for a specific round.
	pub fn take_round2(&mut self) -> Vec<DkgRound2Broadcast> {
		std::mem::take(&mut self.round2)
	}

	/// Take all buffered Round 3 messages.
	pub fn take_round3(&mut self) -> Vec<DkgRound3Broadcast> {
		std::mem::take(&mut self.round3)
	}

	/// Take all buffered Round 4 messages.
	pub fn take_round4(&mut self) -> Vec<DkgRound4Broadcast> {
		std::mem::take(&mut self.round4)
	}

	/// Check if there are any buffered messages.
	pub fn is_empty(&self) -> bool {
		self.round2.is_empty() && self.round3.is_empty() && self.round4.is_empty()
	}
}

/// Accumulated data from Round 1.
#[derive(Debug, Clone)]
pub struct Round1Data {
	/// My session ID contribution.
	pub my_contribution: [u8; SESSION_ID_SIZE],
	/// Session ID contributions from all parties (including self).
	pub session_ids: HashMap<ParticipantId, [u8; SESSION_ID_SIZE]>,
	/// Combined session ID (computed after all contributions received).
	pub combined_session_id: Option<[u8; SESSION_ID_SIZE]>,
}

impl Round1Data {
	/// Create new Round 1 data storage.
	pub fn new() -> Self {
		Self {
			my_contribution: [0u8; SESSION_ID_SIZE],
			session_ids: HashMap::new(),
			combined_session_id: None,
		}
	}

	/// Check if we've received all session ID contributions.
	pub fn is_complete(&self, expected_count: usize) -> bool {
		self.session_ids.len() == expected_count
	}

	/// Add a session ID contribution from a party.
	pub fn add_contribution(
		&mut self,
		party_id: ParticipantId,
		contribution: [u8; SESSION_ID_SIZE],
	) {
		self.session_ids.insert(party_id, contribution);
	}
}

impl Default for Round1Data {
	fn default() -> Self {
		Self::new()
	}
}

/// Accumulated data from Round 2.
#[derive(Debug, Clone)]
pub struct Round2Data {
	/// My commitment hash.
	pub my_commitment_hash: [u8; COMMITMENT_HASH_SIZE],
	/// My contributions (kept secret until Round 3).
	pub my_contributions: Option<PartyContributions>,
	/// Commitment hashes from all parties (including self).
	pub commitment_hashes: HashMap<ParticipantId, [u8; COMMITMENT_HASH_SIZE]>,
}

impl Round2Data {
	/// Create new Round 2 data storage.
	pub fn new() -> Self {
		Self {
			my_commitment_hash: [0u8; COMMITMENT_HASH_SIZE],
			my_contributions: None,
			commitment_hashes: HashMap::new(),
		}
	}

	/// Check if we've received all commitment hashes.
	pub fn is_complete(&self, expected_count: usize) -> bool {
		self.commitment_hashes.len() == expected_count
	}

	/// Add a commitment hash from a party.
	pub fn add_commitment_hash(
		&mut self,
		party_id: ParticipantId,
		hash: [u8; COMMITMENT_HASH_SIZE],
	) {
		self.commitment_hashes.insert(party_id, hash);
	}
}

impl Default for Round2Data {
	fn default() -> Self {
		Self::new()
	}
}

/// Accumulated data from Round 3.
#[derive(Debug, Clone)]
pub struct Round3Data {
	/// Revealed contributions from all parties (including self).
	pub contributions: HashMap<ParticipantId, PartyContributions>,
	/// Verification results for each party.
	pub verification_results: HashMap<ParticipantId, bool>,
}

impl Round3Data {
	/// Create new Round 3 data storage.
	pub fn new() -> Self {
		Self { contributions: HashMap::new(), verification_results: HashMap::new() }
	}

	/// Check if we've received all contributions.
	pub fn is_complete(&self, expected_count: usize) -> bool {
		self.contributions.len() == expected_count
	}

	/// Add revealed contributions from a party.
	pub fn add_contributions(
		&mut self,
		party_id: ParticipantId,
		contributions: PartyContributions,
	) {
		self.contributions.insert(party_id, contributions);
	}

	/// Record verification result for a party.
	pub fn set_verification_result(&mut self, party_id: ParticipantId, valid: bool) {
		self.verification_results.insert(party_id, valid);
	}

	/// Check if all verifications passed.
	pub fn all_verified(&self) -> bool {
		!self.verification_results.is_empty() && self.verification_results.values().all(|&v| v)
	}
}

impl Default for Round3Data {
	fn default() -> Self {
		Self::new()
	}
}

/// Accumulated data from Round 4.
#[derive(Debug, Clone)]
pub struct Round4Data {
	/// My confirmation message.
	pub my_confirmation: Option<DkgRound4Broadcast>,
	/// Confirmations from all parties (including self).
	pub confirmations: HashMap<ParticipantId, DkgRound4Broadcast>,
	/// The computed public key hash (for consensus).
	pub my_public_key_hash: [u8; COMMITMENT_HASH_SIZE],
}

impl Round4Data {
	/// Create new Round 4 data storage.
	pub fn new() -> Self {
		Self {
			my_confirmation: None,
			confirmations: HashMap::new(),
			my_public_key_hash: [0u8; COMMITMENT_HASH_SIZE],
		}
	}

	/// Check if we've received all confirmations.
	pub fn is_complete(&self, expected_count: usize) -> bool {
		self.confirmations.len() == expected_count
	}

	/// Add a confirmation from a party.
	pub fn add_confirmation(&mut self, party_id: ParticipantId, confirmation: DkgRound4Broadcast) {
		self.confirmations.insert(party_id, confirmation);
	}

	/// Check if all parties succeeded and agree on the public key.
	pub fn consensus_reached(&self) -> bool {
		if self.confirmations.is_empty() {
			return false;
		}

		// All must have succeeded
		if !self.confirmations.values().all(|c| c.success) {
			return false;
		}

		// All must agree on the public key hash
		self.confirmations
			.values()
			.all(|c| c.public_key_hash == self.my_public_key_hash)
	}

	/// Get the list of parties that failed.
	pub fn failed_parties(&self) -> Vec<ParticipantId> {
		self.confirmations
			.iter()
			.filter(|(_, c)| !c.success)
			.map(|(&id, _)| id)
			.collect()
	}

	/// Get the list of parties with mismatched public key hashes.
	pub fn mismatched_parties(&self) -> Vec<ParticipantId> {
		self.confirmations
			.iter()
			.filter(|(_, c)| c.public_key_hash != self.my_public_key_hash)
			.map(|(&id, _)| id)
			.collect()
	}
}

impl Default for Round4Data {
	fn default() -> Self {
		Self::new()
	}
}

/// Complete state storage for the DKG protocol.
///
/// This structure holds all accumulated data across all rounds,
/// allowing the protocol to be driven by the state machine.
pub struct DkgStateData {
	/// The DKG configuration.
	pub config: DkgConfig,
	/// Current protocol state.
	pub state: DkgState,
	/// Participant list for ID-to-index mapping.
	/// This allows arbitrary party IDs (like NEAR's large IDs) to be mapped
	/// to sequential indices (0, 1, 2, ...) for bitmask operations.
	pub participants: ParticipantList,
	/// Data from Round 1.
	pub round1: Round1Data,
	/// Data from Round 2.
	pub round2: Round2Data,
	/// Data from Round 3.
	pub round3: Round3Data,
	/// Data from Round 4.
	pub round4: Round4Data,
	/// The final output (set when protocol completes).
	pub output: Option<DkgOutput>,
	/// Buffer for messages that arrive before we're ready to process them.
	pub message_buffer: MessageBuffer,
}

impl DkgStateData {
	/// Create a new DKG state data structure.
	///
	/// # Panics
	/// Panics if the participant list cannot be created (e.g., duplicate IDs).
	pub fn new(config: DkgConfig) -> Self {
		let participants = ParticipantList::new(&config.all_participants)
			.expect("DkgConfig should have valid participant IDs");
		Self {
			config,
			state: DkgState::Initialized,
			participants,
			round1: Round1Data::new(),
			round2: Round2Data::new(),
			round3: Round3Data::new(),
			round4: Round4Data::new(),
			output: None,
			message_buffer: MessageBuffer::new(),
		}
	}

	/// Get the index for a party ID.
	/// Returns None if the party ID is not in the participant list.
	pub fn party_index(&self, party_id: ParticipantId) -> Option<usize> {
		self.participants.index_of(party_id)
	}

	/// Get the party ID for an index.
	/// Returns None if the index is out of bounds.
	pub fn party_id_at(&self, index: usize) -> Option<ParticipantId> {
		self.participants.get(index)
	}

	/// Get the index for this party (my_party_id).
	pub fn my_index(&self) -> usize {
		self.participants
			.index_of(self.config.my_party_id)
			.expect("my_party_id should be in participant list")
	}

	/// Get the expected number of participants.
	pub fn expected_count(&self) -> usize {
		self.config.total_parties() as usize
	}

	/// Transition to a new state and process any buffered messages for that state.
	///
	/// Returns a list of errors from processing buffered messages (if any).
	/// These are logged but don't prevent the transition.
	pub fn transition_to(&mut self, new_state: DkgState) -> Vec<String> {
		self.state = new_state;
		self.process_buffered_messages()
	}

	/// Process any buffered messages that are now valid for the current state.
	fn process_buffered_messages(&mut self) -> Vec<String> {
		let mut errors = Vec::new();

		match &self.state {
			DkgState::Round2Generating | DkgState::Round2Waiting => {
				let buffered = self.message_buffer.take_round2();
				for msg in buffered {
					if let Err(e) = self.process_round2(msg) {
						errors.push(e);
					}
				}
			},
			DkgState::Round3Revealing | DkgState::Round3Waiting => {
				let buffered = self.message_buffer.take_round3();
				for msg in buffered {
					if let Err(e) = self.process_round3(msg) {
						errors.push(e);
					}
				}
			},
			DkgState::Round4Confirming | DkgState::Round4Waiting => {
				let buffered = self.message_buffer.take_round4();
				for msg in buffered {
					if let Err(e) = self.process_round4(msg) {
						errors.push(e);
					}
				}
			},
			_ => {},
		}

		errors
	}

	/// Mark the protocol as failed with a reason.
	pub fn fail(&mut self, reason: String) {
		self.state = DkgState::Failed(reason);
	}

	/// Mark the protocol as complete and set the output.
	pub fn complete(&mut self, output: DkgOutput) {
		self.output = Some(output);
		self.state = DkgState::Complete;
	}

	/// Check if we can proceed to the next state based on received messages.
	pub fn can_advance(&self) -> bool {
		let expected = self.expected_count();
		match &self.state {
			DkgState::Round1Waiting => self.round1.is_complete(expected),
			DkgState::Round2Waiting => self.round2.is_complete(expected),
			DkgState::Round3Waiting => self.round3.is_complete(expected),
			DkgState::Round4Waiting => self.round4.is_complete(expected),
			_ => false,
		}
	}

	/// Process a Round 1 message.
	pub fn process_round1(&mut self, msg: DkgRound1Broadcast) -> Result<(), String> {
		if !matches!(self.state, DkgState::Round1Generating | DkgState::Round1Waiting) {
			return Err(format!("Cannot process Round 1 message in state {}", self.state.name()));
		}

		if !self.config.all_participants.contains(&msg.party_id) {
			return Err(format!("Unknown party ID: {}", msg.party_id));
		}

		if self.round1.session_ids.contains_key(&msg.party_id) {
			return Err(format!("Duplicate Round 1 message from party {}", msg.party_id));
		}

		self.round1.add_contribution(msg.party_id, msg.session_id_contribution);
		Ok(())
	}

	/// Process a Round 2 message.
	pub fn process_round2(&mut self, msg: DkgRound2Broadcast) -> Result<(), String> {
		if !matches!(self.state, DkgState::Round2Generating | DkgState::Round2Waiting) {
			return Err(format!("Cannot process Round 2 message in state {}", self.state.name()));
		}

		if !self.config.all_participants.contains(&msg.party_id) {
			return Err(format!("Unknown party ID: {}", msg.party_id));
		}

		if self.round2.commitment_hashes.contains_key(&msg.party_id) {
			return Err(format!("Duplicate Round 2 message from party {}", msg.party_id));
		}

		self.round2.add_commitment_hash(msg.party_id, msg.commitment_hash);
		Ok(())
	}

	/// Process a Round 3 message.
	pub fn process_round3(&mut self, msg: DkgRound3Broadcast) -> Result<(), String> {
		if !matches!(self.state, DkgState::Round3Revealing | DkgState::Round3Waiting) {
			return Err(format!("Cannot process Round 3 message in state {}", self.state.name()));
		}

		if !self.config.all_participants.contains(&msg.party_id) {
			return Err(format!("Unknown party ID: {}", msg.party_id));
		}

		if self.round3.contributions.contains_key(&msg.party_id) {
			return Err(format!("Duplicate Round 3 message from party {}", msg.party_id));
		}

		self.round3.add_contributions(msg.party_id, msg.contributions);
		Ok(())
	}

	/// Process a Round 4 message.
	pub fn process_round4(&mut self, msg: DkgRound4Broadcast) -> Result<(), String> {
		if !matches!(self.state, DkgState::Round4Confirming | DkgState::Round4Waiting) {
			return Err(format!("Cannot process Round 4 message in state {}", self.state.name()));
		}

		if !self.config.all_participants.contains(&msg.party_id) {
			return Err(format!("Unknown party ID: {}", msg.party_id));
		}

		if self.round4.confirmations.contains_key(&msg.party_id) {
			return Err(format!("Duplicate Round 4 message from party {}", msg.party_id));
		}

		self.round4.add_confirmation(msg.party_id, msg);
		Ok(())
	}
}

impl Zeroize for DkgStateData {
	fn zeroize(&mut self) {
		// Zeroize sensitive data
		self.round1.my_contribution.zeroize();
		for (_, sid) in self.round1.session_ids.iter_mut() {
			sid.zeroize();
		}
		self.round2.my_commitment_hash.zeroize();
		// PartyContributions contains secret data
		if let Some(ref mut contributions) = self.round2.my_contributions {
			contributions.rho_contribution.zeroize();
			for (_, subset) in contributions.subset_contributions.iter_mut() {
				for poly in &mut subset.s1 {
					poly.zeroize();
				}
				for poly in &mut subset.s2 {
					poly.zeroize();
				}
			}
		}
		self.round4.my_public_key_hash.zeroize();
	}
}

impl ZeroizeOnDrop for DkgStateData {}

impl std::fmt::Debug for DkgStateData {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("DkgStateData")
			.field("config", &self.config)
			.field("state", &self.state)
			.field("round1_complete", &self.round1.is_complete(self.expected_count()))
			.field("round2_complete", &self.round2.is_complete(self.expected_count()))
			.field("round3_complete", &self.round3.is_complete(self.expected_count()))
			.field("round4_complete", &self.round4.is_complete(self.expected_count()))
			.field("has_output", &self.output.is_some())
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::ThresholdConfig;

	fn make_test_config() -> DkgConfig {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		DkgConfig::new(threshold_config, 0, vec![0, 1, 2]).unwrap()
	}

	#[test]
	fn test_dkg_state_names() {
		assert_eq!(DkgState::Initialized.name(), "Initialized");
		assert_eq!(DkgState::Round1Waiting.name(), "Round1Waiting");
		assert_eq!(DkgState::Complete.name(), "Complete");
		assert_eq!(DkgState::Failed("test".into()).name(), "Failed");
	}

	#[test]
	fn test_dkg_state_round_numbers() {
		assert_eq!(DkgState::Initialized.round_number(), 0);
		assert_eq!(DkgState::Round1Generating.round_number(), 1);
		assert_eq!(DkgState::Round2Waiting.round_number(), 2);
		assert_eq!(DkgState::Round3Revealing.round_number(), 3);
		assert_eq!(DkgState::Round4Confirming.round_number(), 4);
		assert_eq!(DkgState::Complete.round_number(), 5);
	}

	#[test]
	fn test_dkg_state_predicates() {
		assert!(DkgState::Round1Waiting.is_in_progress());
		assert!(!DkgState::Complete.is_in_progress());
		assert!(!DkgState::Failed("err".into()).is_in_progress());

		assert!(DkgState::Complete.is_complete());
		assert!(!DkgState::Round1Waiting.is_complete());

		assert!(DkgState::Failed("err".into()).is_failed());
		assert!(!DkgState::Complete.is_failed());
	}

	#[test]
	fn test_round1_data() {
		let mut data = Round1Data::new();
		assert!(!data.is_complete(3));

		data.add_contribution(0, [1u8; 32]);
		data.add_contribution(1, [2u8; 32]);
		assert!(!data.is_complete(3));

		data.add_contribution(2, [3u8; 32]);
		assert!(data.is_complete(3));
	}

	#[test]
	fn test_round4_consensus() {
		let mut data = Round4Data::new();
		data.my_public_key_hash = [42u8; 32];

		// Empty - no consensus
		assert!(!data.consensus_reached());

		// Add matching confirmations
		data.add_confirmation(
			0,
			DkgRound4Broadcast { party_id: 0, success: true, public_key_hash: [42u8; 32] },
		);
		data.add_confirmation(
			1,
			DkgRound4Broadcast { party_id: 1, success: true, public_key_hash: [42u8; 32] },
		);
		assert!(data.consensus_reached());

		// Add mismatched confirmation
		data.add_confirmation(
			2,
			DkgRound4Broadcast { party_id: 2, success: true, public_key_hash: [99u8; 32] },
		);
		assert!(!data.consensus_reached());
		assert_eq!(data.mismatched_parties(), vec![2]);
	}

	#[test]
	fn test_dkg_state_data_creation() {
		let config = make_test_config();
		let state_data = DkgStateData::new(config);

		assert!(matches!(state_data.state, DkgState::Initialized));
		assert_eq!(state_data.expected_count(), 3);
		assert!(state_data.output.is_none());
	}

	#[test]
	fn test_dkg_state_data_transition() {
		let config = make_test_config();
		let mut state_data = DkgStateData::new(config);

		state_data.transition_to(DkgState::Round1Generating);
		assert!(matches!(state_data.state, DkgState::Round1Generating));

		state_data.fail("test error".into());
		assert!(matches!(state_data.state, DkgState::Failed(_)));
	}

	#[test]
	fn test_process_round1_message() {
		let config = make_test_config();
		let mut state_data = DkgStateData::new(config);
		state_data.transition_to(DkgState::Round1Generating);

		let msg = DkgRound1Broadcast { party_id: 1, session_id_contribution: [1u8; 32] };

		assert!(state_data.process_round1(msg.clone()).is_ok());
		assert!(state_data.round1.session_ids.contains_key(&1));

		// Duplicate should fail
		assert!(state_data.process_round1(msg).is_err());
	}

	#[test]
	fn test_process_round1_wrong_state() {
		let config = make_test_config();
		let mut state_data = DkgStateData::new(config);
		// Still in Initialized state

		let msg = DkgRound1Broadcast { party_id: 1, session_id_contribution: [1u8; 32] };

		assert!(state_data.process_round1(msg).is_err());
	}

	#[test]
	fn test_process_round1_unknown_party() {
		let config = make_test_config();
		let mut state_data = DkgStateData::new(config);
		state_data.transition_to(DkgState::Round1Generating);

		let msg = DkgRound1Broadcast {
			party_id: 99, // Not in participants
			session_id_contribution: [1u8; 32],
		};

		assert!(state_data.process_round1(msg).is_err());
	}

	#[test]
	fn test_can_advance() {
		let config = make_test_config();
		let mut state_data = DkgStateData::new(config);
		state_data.transition_to(DkgState::Round1Waiting);

		assert!(!state_data.can_advance());

		state_data.round1.add_contribution(0, [0u8; 32]);
		state_data.round1.add_contribution(1, [1u8; 32]);
		assert!(!state_data.can_advance());

		state_data.round1.add_contribution(2, [2u8; 32]);
		assert!(state_data.can_advance());
	}

	#[test]
	fn test_message_buffer_creation() {
		let buffer = MessageBuffer::new();
		assert!(buffer.is_empty());
		assert!(buffer.round2.is_empty());
		assert!(buffer.round3.is_empty());
		assert!(buffer.round4.is_empty());
	}

	#[test]
	fn test_message_buffer_round2() {
		let mut buffer = MessageBuffer::new();
		assert!(buffer.is_empty());

		let msg =
			DkgMessage::Round2(DkgRound2Broadcast { party_id: 1, commitment_hash: [42u8; 32] });
		buffer.buffer(msg);

		assert!(!buffer.is_empty());
		assert_eq!(buffer.round2.len(), 1);
		assert!(buffer.round3.is_empty());

		let taken = buffer.take_round2();
		assert_eq!(taken.len(), 1);
		assert_eq!(taken[0].party_id, 1);
		assert!(buffer.is_empty());
	}

	#[test]
	fn test_message_buffer_round3() {
		let mut buffer = MessageBuffer::new();

		let contributions = PartyContributions::new(2);
		let msg = DkgMessage::Round3(DkgRound3Broadcast { party_id: 2, contributions });
		buffer.buffer(msg);

		assert!(!buffer.is_empty());
		assert_eq!(buffer.round3.len(), 1);

		let taken = buffer.take_round3();
		assert_eq!(taken.len(), 1);
		assert_eq!(taken[0].party_id, 2);
		assert!(buffer.is_empty());
	}

	#[test]
	fn test_message_buffer_round4() {
		let mut buffer = MessageBuffer::new();

		let msg = DkgMessage::Round4(DkgRound4Broadcast {
			party_id: 1,
			success: true,
			public_key_hash: [99u8; 32],
		});
		buffer.buffer(msg);

		assert!(!buffer.is_empty());
		assert_eq!(buffer.round4.len(), 1);

		let taken = buffer.take_round4();
		assert_eq!(taken.len(), 1);
		assert_eq!(taken[0].party_id, 1);
		assert!(taken[0].success);
		assert!(buffer.is_empty());
	}

	#[test]
	fn test_message_buffer_round1_ignored() {
		let mut buffer = MessageBuffer::new();

		// Round 1 messages should not be buffered (first round, never needs buffering)
		let msg = DkgMessage::Round1(DkgRound1Broadcast {
			party_id: 1,
			session_id_contribution: [1u8; 32],
		});
		buffer.buffer(msg);

		// Buffer should still be empty since Round1 messages are ignored
		assert!(buffer.is_empty());
	}

	#[test]
	fn test_state_data_has_message_buffer() {
		let config = make_test_config();
		let state_data = DkgStateData::new(config);

		assert!(state_data.message_buffer.is_empty());
	}

	#[test]
	fn test_transition_processes_buffered_messages() {
		let config = make_test_config();
		let mut state_data = DkgStateData::new(config);

		// Start in Round1Generating
		let _ = state_data.transition_to(DkgState::Round1Generating);

		// Buffer a Round2 message (simulating out-of-order delivery)
		let msg = DkgRound2Broadcast { party_id: 1, commitment_hash: [42u8; 32] };
		state_data.message_buffer.round2.push(msg);

		// Transition through Round1 states
		let _ = state_data.transition_to(DkgState::Round1Waiting);
		// Add fake Round1 data to allow advancement
		state_data.round1.add_contribution(0, [0u8; 32]);
		state_data.round1.add_contribution(1, [1u8; 32]);
		state_data.round1.add_contribution(2, [2u8; 32]);

		// Now transition to Round2Generating - this should process the buffered message
		let errors = state_data.transition_to(DkgState::Round2Generating);

		// The buffered message should have been processed
		assert!(state_data.message_buffer.round2.is_empty());
		// The message should have been added to round2 data
		assert!(state_data.round2.commitment_hashes.contains_key(&1));
		// No errors expected since the message was valid
		assert!(errors.is_empty());
	}

	#[test]
	fn test_dkg_state_can_accept_round() {
		assert!(DkgState::Round1Waiting.can_accept_round(1));
		assert!(!DkgState::Round1Waiting.can_accept_round(2));

		assert!(DkgState::Round2Waiting.can_accept_round(1));
		assert!(DkgState::Round2Waiting.can_accept_round(2));
		assert!(!DkgState::Round2Waiting.can_accept_round(3));

		assert!(DkgState::Round3Waiting.can_accept_round(3));
		assert!(!DkgState::Round3Waiting.can_accept_round(4));
	}
}
