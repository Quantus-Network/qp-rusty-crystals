//! Protocol trait implementation for DKG.
//!
//! This module implements the `Protocol` trait pattern used by NEAR MPC,
//! allowing the DKG to be driven by the standard `run_protocol` function.
//!
//! The protocol uses a poke/message pattern:
//! - `poke()` is called repeatedly to advance the protocol
//! - `message()` is called when a message arrives from another party
//! - `poke()` returns an `Action` indicating what to do next

use std::collections::HashMap;

use rand::{Rng, SeedableRng};

use crate::{error::ThresholdError, participants::ParticipantList};

use super::{
	state::{DkgState, DkgStateData},
	types::{
		combine_seeds, derive_subset_contribution, hash_seed, DkgConfig, DkgMessage, DkgOutput,
		DkgRound1Broadcast, DkgRound2Broadcast, DkgRound3Private, DkgRound4Broadcast,
		DkgRound5Broadcast, ParticipantId, PartialPublicKey, PartyPublicContributions,
		PartySeedContributions, SubsetContribution, SubsetMask, SubsetSeedContribution,
		COMMITMENT_HASH_SIZE, K, L, N, SESSION_ID_SIZE, SUBSET_SEED_SIZE,
	},
};

// ============================================================================
// Action Enum (mirrors NEAR's threshold-signatures Protocol trait)
// ============================================================================

/// Represents an action to be taken by the protocol driver.
///
/// This mirrors the `Action` enum from NEAR's `threshold-signatures` crate.
#[derive(Debug, Clone)]
pub enum Action<T> {
	/// Do nothing, waiting for more messages.
	Wait,
	/// Send a message to all other participants.
	SendMany(Vec<u8>),
	/// Send a private message to a specific participant.
	SendPrivate(ParticipantId, Vec<u8>),
	/// The protocol has completed, returning the output.
	Return(T),
}

// ============================================================================
// Protocol Error
// ============================================================================

/// Errors that can occur during the DKG protocol.
#[derive(Debug, Clone)]
pub enum DkgProtocolError {
	/// The protocol is in an invalid state for the requested operation.
	InvalidState(String),
	/// A message was received from an unknown party.
	UnknownParty(ParticipantId),
	/// A duplicate message was received from a party.
	DuplicateMessage(ParticipantId),
	/// Commitment verification failed for a party.
	CommitmentMismatch(ParticipantId),
	/// Contribution bounds verification failed for a party.
	InvalidContributionBounds(ParticipantId),
	/// Consensus was not reached on the public key.
	ConsensusFailure(Vec<ParticipantId>),
	/// A party reported failure.
	PartyFailure(Vec<ParticipantId>),
	/// Serialization error.
	SerializationError(String),
	/// Randomness generation error.
	RandomnessError,
	/// Internal error.
	InternalError(String),
}

impl std::fmt::Display for DkgProtocolError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			DkgProtocolError::InvalidState(s) => write!(f, "Invalid state: {}", s),
			DkgProtocolError::UnknownParty(p) => write!(f, "Unknown party: {}", p),
			DkgProtocolError::DuplicateMessage(p) => {
				write!(f, "Duplicate message from party: {}", p)
			},
			DkgProtocolError::CommitmentMismatch(p) => {
				write!(f, "Commitment mismatch for party: {}", p)
			},
			DkgProtocolError::InvalidContributionBounds(p) => {
				write!(f, "Invalid contribution bounds for party: {}", p)
			},
			DkgProtocolError::ConsensusFailure(parties) => {
				write!(f, "Consensus failure, mismatched parties: {:?}", parties)
			},
			DkgProtocolError::PartyFailure(parties) => {
				write!(f, "Party failure: {:?}", parties)
			},
			DkgProtocolError::SerializationError(s) => write!(f, "Serialization error: {}", s),
			DkgProtocolError::RandomnessError => write!(f, "Randomness generation error"),
			DkgProtocolError::InternalError(s) => write!(f, "Internal error: {}", s),
		}
	}
}

impl std::error::Error for DkgProtocolError {}

impl From<DkgProtocolError> for ThresholdError {
	fn from(e: DkgProtocolError) -> Self {
		ThresholdError::InvalidConfiguration(e.to_string())
	}
}

// ============================================================================
// DKG Protocol Implementation
// ============================================================================

/// The main DKG protocol state machine.
///
/// This struct implements the distributed key generation protocol for
/// threshold Dilithium signatures. It follows the poke/message pattern
/// used by NEAR MPC.
///
/// # Usage
///
/// ```ignore
/// let mut dkg = DilithiumDkg::new(config, rng)?;
///
/// loop {
///     match dkg.poke()? {
///         Action::Wait => {
///             // Wait for messages from other parties
///         }
///         Action::SendMany(data) => {
///             // Broadcast data to all other parties
///             for party in other_parties {
///                 send(party, data.clone());
///             }
///         }
///         Action::SendPrivate(party, data) => {
///             // Send data privately to the specified party
///             send(party, data);
///         }
///         Action::Return(output) => {
///             // Protocol complete!
///             break;
///         }
///     }
///
///     // When a message arrives:
///     dkg.message(from_party, data);
/// }
/// ```
pub struct DilithiumDkg {
	/// Internal state data.
	state_data: DkgStateData,
	/// Random number generator.
	rng: rand::rngs::StdRng,
	/// Whether we've sent our broadcast message for the current round.
	sent_current_round: bool,
	/// SEED-BASED DKG: Public contributions to broadcast in Round 3.
	/// Contains seed hashes (not partial public keys) and rho contribution.
	my_public_contributions: Option<PartyPublicContributions>,
	/// SEED-BASED DKG: Our seed contributions (kept secret until Round 3 P2P).
	my_seed_contributions: Option<PartySeedContributions>,
	/// SEED-BASED DKG: P2P messages to send in Round 3.
	/// Contains seed contributions for each (party, subset) pair.
	round3_private_messages: Vec<DkgRound3Private>,
	/// Number of P2P messages sent so far in Round 3.
	round3_private_sent_count: usize,
}

impl DilithiumDkg {
	/// Create a new DKG protocol instance from a seed.
	///
	/// # Arguments
	/// * `config` - The DKG configuration
	/// * `seed` - A 32-byte seed for deterministic randomness
	pub fn new(config: DkgConfig, seed: [u8; 32]) -> Self {
		Self {
			state_data: DkgStateData::new(config),
			rng: rand::rngs::StdRng::from_seed(seed),
			sent_current_round: false,
			my_public_contributions: None,
			my_seed_contributions: None,
			round3_private_messages: Vec::new(),
			round3_private_sent_count: 0,
		}
	}

	/// Get the current protocol state.
	pub fn state(&self) -> &DkgState {
		&self.state_data.state
	}

	/// Get this party's ID.
	pub fn my_party_id(&self) -> ParticipantId {
		self.state_data.config.my_party_id
	}

	/// Get the DKG configuration.
	pub fn config(&self) -> &DkgConfig {
		&self.state_data.config
	}

	/// Poke the protocol to advance it.
	///
	/// This should be called repeatedly until it returns `Action::Return`
	/// or an error. Between calls, messages from other parties should be
	/// delivered via the `message()` method.
	///
	/// ## SEED-BASED DKG Protocol Flow:
	/// - Round 1: Session ID contribution (broadcast)
	/// - Round 2: Commit to seeds (broadcast commitment hash)
	/// - Round 3: P2P seed exchange (send seeds to subset members)
	/// - Round 4: Broadcast partial public keys (derived from combined seeds)
	/// - Round 5: Confirmation (verify consensus on public key)
	pub fn poke(&mut self) -> Result<Action<DkgOutput>, DkgProtocolError> {
		match &self.state_data.state {
			DkgState::Initialized => {
				// Start Round 1
				let _ = self.state_data.transition_to(DkgState::Round1Generating);
				self.sent_current_round = false;
				self.poke()
			},

			DkgState::Round1Generating => {
				if self.sent_current_round {
					let _ = self.state_data.transition_to(DkgState::Round1Waiting);
					return Ok(Action::Wait);
				}

				// Generate session ID contribution
				let session_id: [u8; SESSION_ID_SIZE] = self.rng.gen();

				self.state_data.round1.my_contribution = session_id;
				self.state_data.round1.add_contribution(self.my_party_id(), session_id);

				let msg = DkgRound1Broadcast {
					party_id: self.my_party_id(),
					session_id_contribution: session_id,
				};

				self.sent_current_round = true;
				Ok(Action::SendMany(self.serialize_message(&DkgMessage::Round1(msg))?))
			},

			DkgState::Round1Waiting => {
				if self.state_data.can_advance() {
					// Compute combined session ID
					self.compute_combined_session_id();
					let errors = self.state_data.transition_to(DkgState::Round2Generating);
					for e in errors {
						eprintln!("Error processing buffered message: {}", e);
					}
					self.sent_current_round = false;
					self.poke()
				} else {
					Ok(Action::Wait)
				}
			},

			DkgState::Round2Generating => {
				if self.sent_current_round {
					let errors = self.state_data.transition_to(DkgState::Round2Waiting);
					for e in errors {
						eprintln!("Error processing buffered message: {}", e);
					}
					return Ok(Action::Wait);
				}

				// SEED-BASED DKG: Generate random seeds for each subset
				let (seed_contributions, public_contributions) =
					self.generate_seed_contributions()?;

				// Commit to seed hashes + rho
				let commitment_hash = self.compute_public_commitment_hash(&public_contributions);

				// Store for later rounds
				self.my_seed_contributions = Some(seed_contributions.clone());
				self.my_public_contributions = Some(public_contributions.clone());

				// Generate P2P messages for Round 3
				self.round3_private_messages = self.generate_round3_seed_messages(&seed_contributions);
				self.round3_private_sent_count = 0;

				self.state_data.round2.my_commitment_hash = commitment_hash;
				// Add our own commitment and public contributions
				self.state_data.round2.add_commitment(self.my_party_id(), commitment_hash, public_contributions.clone());

				let msg = DkgRound2Broadcast { 
					party_id: self.my_party_id(), 
					commitment_hash,
					public_contributions,
				};

				self.sent_current_round = true;
				Ok(Action::SendMany(self.serialize_message(&DkgMessage::Round2(msg))?))
			},

			DkgState::Round2Waiting =>
				if self.state_data.can_advance() {
					// Verify all commitments before starting P2P seed exchange
					self.verify_all_contributions()?;
					
					let errors = self.state_data.transition_to(DkgState::Round3Sending);
					for e in errors {
						eprintln!("Error processing buffered message: {}", e);
					}
					self.sent_current_round = false;
					self.poke()
				} else {
					Ok(Action::Wait)
				},

			DkgState::Round3Sending => {
				// Send P2P messages with seed contributions
				if self.round3_private_sent_count < self.round3_private_messages.len() {
					return self.send_next_round3_private();
				}

				// All P2P messages sent, transition to waiting
				let errors = self.state_data.transition_to(DkgState::Round3Waiting);
				for e in errors {
					eprintln!("Error processing buffered message: {}", e);
				}
				self.poke()
			},

			DkgState::Round3Waiting => {
				// Check if we have all P2P seed messages for our subsets
				let my_subsets = self.compute_my_subsets();
				let p2p_complete = self
					.state_data
					.round3
					.is_p2p_complete(&my_subsets, self.state_data.config.total_parties());

				if !p2p_complete {
					return Ok(Action::Wait);
				}

				// Verify received seeds match broadcast commitment hashes
				self.verify_received_secrets()?;

				// Transition to Round 4 (partial public key broadcast)
				let errors = self.state_data.transition_to(DkgState::Round4Broadcasting);
				for e in errors {
					eprintln!("Error processing buffered message: {}", e);
				}
				self.sent_current_round = false;
				self.poke()
			},

			DkgState::Round4Broadcasting => {
				if self.sent_current_round {
					let errors = self.state_data.transition_to(DkgState::Round4Waiting);
					for e in errors {
						eprintln!("Error processing buffered message: {}", e);
					}
					return Ok(Action::Wait);
				}

				// Combine seeds and derive secrets, then compute partial public keys
				let round4_msg = self.compute_partial_public_keys()?;

				// Store our own partial public keys
				self.state_data.round4.add_partial_public_keys(self.my_party_id(), round4_msg.clone());

				self.sent_current_round = true;
				Ok(Action::SendMany(self.serialize_message(&DkgMessage::Round4(round4_msg))?))
			},

			DkgState::Round4Waiting => {
				if self.state_data.can_advance() {
					// All partial public keys received
					let errors = self.state_data.transition_to(DkgState::Round5Confirming);
					for e in errors {
						eprintln!("Error processing buffered message: {}", e);
					}
					self.sent_current_round = false;
					self.poke()
				} else {
					Ok(Action::Wait)
				}
			},

			DkgState::Round5Confirming => {
				if self.sent_current_round {
					let errors = self.state_data.transition_to(DkgState::Round5Waiting);
					for e in errors {
						eprintln!("Error processing buffered message: {}", e);
					}
					return Ok(Action::Wait);
				}

				// Compute final output from all partial public keys
				let (success, public_key_hash) = match self.compute_final_output() {
					Ok(output) => {
						let pk_hash = self.hash_public_key(&output.public_key);
						self.state_data.round5.my_public_key_hash = pk_hash;
						self.state_data.output = Some(output);
						(true, pk_hash)
					},
					Err(e) => {
						eprintln!("DKG computation failed: {}", e);
						(false, [0u8; COMMITMENT_HASH_SIZE])
					},
				};

				let msg =
					DkgRound5Broadcast { party_id: self.my_party_id(), success, public_key_hash };

				self.state_data.round5.add_confirmation(self.my_party_id(), msg.clone());

				self.sent_current_round = true;
				Ok(Action::SendMany(self.serialize_message(&DkgMessage::Round5(msg))?))
			},

			DkgState::Round5Waiting => {
				if self.state_data.can_advance() {
					// Verify consensus
					if !self.state_data.round5.consensus_reached() {
						let failed_parties: Vec<_> = self
							.state_data
							.round5
							.confirmations
							.iter()
							.filter(|(_, c)| {
								!c.success ||
									c.public_key_hash != self.state_data.round5.my_public_key_hash
							})
							.map(|(&id, _)| id)
							.collect();

						return Err(DkgProtocolError::ConsensusFailure(failed_parties));
					}

					let errors = self.state_data.transition_to(DkgState::Complete);
					for e in errors {
						eprintln!("Error processing buffered message: {}", e);
					}

					let output = self
						.state_data
						.output
						.clone()
						.ok_or_else(|| DkgProtocolError::InternalError("No output".into()))?;

					Ok(Action::Return(output))
				} else {
					Ok(Action::Wait)
				}
			},

			DkgState::Complete => {
				let output = self
					.state_data
					.output
					.clone()
					.ok_or_else(|| DkgProtocolError::InternalError("No output".into()))?;
				Ok(Action::Return(output))
			},

			DkgState::Failed(reason) => {
				Err(DkgProtocolError::InvalidState(reason.clone()))
			},
		}
	}

	/// Deliver a message from another party.
	///
	/// This should be called when a message is received from another party.
	/// The message will be processed according to the current protocol state.
	pub fn message(&mut self, from: ParticipantId, data: Vec<u8>) {
		// Deserialize and process the message
		let msg = match self.deserialize_message(&data) {
			Ok(m) => m,
			Err(e) => {
				eprintln!("Failed to deserialize message from {}: {}", from, e);
				return;
			},
		};

		// Verify sender matches message
		if msg.party_id() != from {
			eprintln!("Message party_id {} doesn't match sender {}", msg.party_id(), from);
			return;
		}

		let msg_round = msg.round();
		let current_round = self.state_data.state.round_number();

		// If message is for a future round, buffer it for later processing
		if msg_round > current_round {
			// Debug: buffering out-of-order message
			#[cfg(debug_assertions)]
			eprintln!(
				"Buffering round {} message from {} (current state: {})",
				msg_round,
				from,
				self.state_data.state.name()
			);
			self.state_data.message_buffer.buffer(msg);
			return;
		}

		// Process based on message type
		let result = match msg {
			DkgMessage::Round1(m) => self.state_data.process_round1(m),
			DkgMessage::Round2(m) => self.state_data.process_round2(m),
			DkgMessage::Round3(m) => self.state_data.process_round3_private(m),
			DkgMessage::Round4(m) => self.state_data.process_round4(m),
			DkgMessage::Round5(m) => self.state_data.process_round5(m),
		};

		if let Err(e) = result {
			eprintln!("Failed to process message from {}: {}", from, e);
		}
	}

	// ========================================================================
	// Helper Methods
	// ========================================================================

	/// Serialize a message for transmission.
	fn serialize_message(&self, msg: &DkgMessage) -> Result<Vec<u8>, DkgProtocolError> {
		bincode::serialize(msg).map_err(|e| DkgProtocolError::SerializationError(e.to_string()))
	}

	/// Deserialize a message from received bytes.
	fn deserialize_message(&self, data: &[u8]) -> Result<DkgMessage, DkgProtocolError> {
		bincode::deserialize(data).map_err(|e| DkgProtocolError::SerializationError(e.to_string()))
	}

	/// Compute the combined session ID from all contributions.
	fn compute_combined_session_id(&mut self) {
		use qp_rusty_crystals_dilithium::fips202;

		let mut state = fips202::KeccakState::default();

		// Sort by party ID for deterministic ordering
		let mut contributions: Vec<_> = self.state_data.round1.session_ids.iter().collect();
		contributions.sort_by_key(|(id, _)| *id);

		for (_, contribution) in contributions {
			fips202::shake256_absorb(&mut state, contribution, SESSION_ID_SIZE);
		}
		fips202::shake256_finalize(&mut state);

		let mut combined = [0u8; SESSION_ID_SIZE];
		fips202::shake256_squeeze(&mut combined, SESSION_ID_SIZE, &mut state);

		self.state_data.round1.combined_session_id = Some(combined);
	}

	/// Generate both secret contributions AND partial public keys.
	///
	/// SEED-BASED DKG: Generate random seed contributions for each subset.
	///
	/// This method generates:
	/// 1. Random seeds for each subset this party belongs to
	/// 2. Hashes of those seeds (for commitment verification)
	///
	/// The actual secret polynomials are derived later in Round 5, AFTER
	/// all parties have exchanged their seeds and combined them.
	fn generate_seed_contributions(
		&mut self,
	) -> Result<(PartySeedContributions, PartyPublicContributions), DkgProtocolError> {
		let my_id = self.my_party_id();
		let threshold = self.state_data.config.threshold();
		let parties = self.state_data.config.total_parties();

		let mut seed_contributions = PartySeedContributions::new(my_id);
		let mut public_contributions = PartyPublicContributions::new(my_id);

		// Get subsets this party belongs to
		let subsets = self.compute_subsets_for_party(my_id, threshold, parties);

		for subset_mask in subsets {
			// Generate random seed for this subset (64 bytes)
			let mut seed = [0u8; SUBSET_SEED_SIZE];
			self.rng.fill(&mut seed);
			let seed_contrib = SubsetSeedContribution::from_bytes(seed);

			// Compute hash of the seed (for commitment verification)
			let seed_hash = hash_seed(&seed_contrib);

			// Store seed and its hash
			seed_contributions.subset_seeds.insert(subset_mask, seed_contrib);
			public_contributions.subset_seed_hashes.insert(subset_mask, seed_hash);
		}

		Ok((seed_contributions, public_contributions))
	}

	/// Compute all subset masks that contain a given party.
	///
	/// This function uses the party's **index** (from ParticipantList) for bitmask
	/// operations, not the raw party ID. This allows arbitrary party IDs (like
	/// NEAR's large IDs) to work correctly.
	fn compute_subsets_for_party(
		&self,
		party_id: ParticipantId,
		threshold: u32,
		parties: u32,
	) -> Vec<SubsetMask> {
		// Get the party's index (0, 1, 2, ...) for bitmask operations
		let party_index = self
			.state_data
			.party_index(party_id)
			.expect("party_id should be in participant list");

		let subset_size = (parties - threshold + 1) as usize;
		let mut subsets = Vec::new();

		// Generate all subsets of size (n - t + 1) containing this party
		let mut subset: SubsetMask = (1 << subset_size) - 1;
		let max_val: SubsetMask = 1 << parties;

		while subset < max_val {
			// Check if this party (by index) is in the subset
			if (subset & (1 << party_index)) != 0 {
				subsets.push(subset);
			}

			// Gosper's hack for next subset of same size
			let c = subset & (!subset + 1);
			let r = subset + c;
			subset = (((r ^ subset) >> 2) / c) | r;
		}

		subsets
	}

	/// Compute the subsets this party belongs to.
	fn compute_my_subsets(&self) -> Vec<SubsetMask> {
		let my_id = self.my_party_id();
		let threshold = self.state_data.config.threshold();
		let parties = self.state_data.config.total_parties();
		self.compute_subsets_for_party(my_id, threshold, parties)
	}

	/// SEED-BASED DKG: Generate P2P messages to send seed contributions
	/// to other parties in the same subsets.
	///
	/// For each subset this party belongs to, we generate a message for each
	/// OTHER party in that subset (not ourselves).
	fn generate_round3_seed_messages(
		&self,
		seed_contributions: &PartySeedContributions,
	) -> Vec<DkgRound3Private> {
		let my_id = self.my_party_id();
		let mut messages = Vec::new();

		for (subset_mask, seed_contribution) in &seed_contributions.subset_seeds {
			// Find other parties in this subset
			for i in 0..self.state_data.config.total_parties() {
				let party_bit = 1u16 << i;
				if (*subset_mask & party_bit) != 0 {
					// This party is in the subset
					if let Some(party_id) = self.state_data.party_id_at(i as usize) {
						if party_id != my_id {
							// Send our seed contribution to this party
							messages.push(DkgRound3Private {
								from_party_id: my_id,
								subset_mask: *subset_mask,
								seed_contribution: seed_contribution.clone(),
							});
						}
					}
				}
			}
		}

		messages
	}

	/// Send the next P2P message in the Round 3 queue.
	fn send_next_round3_private(&mut self) -> Result<Action<DkgOutput>, DkgProtocolError> {
		if self.round3_private_sent_count >= self.round3_private_messages.len() {
			return Ok(Action::Wait);
		}

		let msg = &self.round3_private_messages[self.round3_private_sent_count];

		// Find the target party ID from the subset mask
		let target_party_id =
			self.find_recipient_for_private_message(self.round3_private_sent_count)?;

		let dkg_msg = DkgMessage::Round3(msg.clone());
		let data = self.serialize_message(&dkg_msg)?;

		self.round3_private_sent_count += 1;

		Ok(Action::SendPrivate(target_party_id, data))
	}

	/// Find the recipient party ID for a given P2P message index.
	fn find_recipient_for_private_message(
		&self,
		msg_index: usize,
	) -> Result<ParticipantId, DkgProtocolError> {
		let my_id = self.my_party_id();
		let seed_contributions =
			self.my_seed_contributions.as_ref().ok_or_else(|| {
				DkgProtocolError::InternalError("Missing my seed contributions".into())
			})?;

		let mut current_index = 0;
		for (subset_mask, _) in &seed_contributions.subset_seeds {
			for i in 0..self.state_data.config.total_parties() {
				let party_bit = 1u16 << i;
				if (*subset_mask & party_bit) != 0 {
					if let Some(party_id) = self.state_data.party_id_at(i as usize) {
						if party_id != my_id {
							if current_index == msg_index {
								return Ok(party_id);
							}
							current_index += 1;
						}
					}
				}
			}
		}

		Err(DkgProtocolError::InternalError(format!(
			"Could not find recipient for message index {}",
			msg_index
		)))
	}

	/// SEED-BASED DKG: Verify that received seeds match broadcast seed hashes.
	///
	/// For each received seed contribution, we verify that its hash matches
	/// the seed hash that was broadcast by the same party in Round 2.
	fn verify_received_secrets(&self) -> Result<(), DkgProtocolError> {
		// For each received seed contribution
		for ((from_party_id, subset_mask), received_seed) in
			&self.state_data.round3.received_seed_contributions
		{
			// Get the public contributions from Round 2 (seed hashes + rho)
			let public_contrib =
				self.state_data.round2.public_contributions.get(from_party_id).ok_or_else(
					|| {
						DkgProtocolError::InternalError(format!(
							"Missing public contributions from party {}",
							from_party_id
						))
					},
				)?;

			// Get the broadcast seed hash for this subset
			let expected_hash =
				public_contrib.subset_seed_hashes.get(subset_mask).ok_or_else(|| {
					DkgProtocolError::InternalError(format!(
						"Missing seed hash for subset {:b} from party {}",
						subset_mask, from_party_id
					))
				})?;

			// Compute hash of received seed and compare
			let actual_hash = hash_seed(received_seed);
			if actual_hash != *expected_hash {
				return Err(DkgProtocolError::CommitmentMismatch(*from_party_id));
			}
		}

		Ok(())
	}

	/// SEED-BASED DKG: Compute commitment hash for PUBLIC contributions.
	///
	/// This commits to:
	/// - Party ID
	/// - Rho contribution
	/// - Seed hashes (H(seed) for each subset), NOT raw seeds
	/// - Session ID (for domain separation)
	///
	/// SECURITY: The raw seeds are NEVER included in the commitment.
	fn compute_public_commitment_hash(
		&self,
		public_contributions: &PartyPublicContributions,
	) -> [u8; COMMITMENT_HASH_SIZE] {
		use qp_rusty_crystals_dilithium::fips202;

		let mut state = fips202::KeccakState::default();

		// Include party ID
		fips202::shake256_absorb(&mut state, &public_contributions.party_id.to_le_bytes(), 4);

		// Include seed hashes in sorted order by subset mask
		let mut seed_hashes: Vec<_> = public_contributions.subset_seed_hashes.iter().collect();
		seed_hashes.sort_by_key(|(mask, _)| *mask);

		for (mask, seed_hash) in seed_hashes {
			fips202::shake256_absorb(&mut state, &mask.to_le_bytes(), 2);
			fips202::shake256_absorb(&mut state, seed_hash, COMMITMENT_HASH_SIZE);
		}

		// Include session ID for domain separation
		if let Some(session_id) = &self.state_data.round1.combined_session_id {
			fips202::shake256_absorb(&mut state, session_id, SESSION_ID_SIZE);
		}

		fips202::shake256_finalize(&mut state);

		let mut hash = [0u8; COMMITMENT_HASH_SIZE];
		fips202::shake256_squeeze(&mut hash, COMMITMENT_HASH_SIZE, &mut state);

		hash
	}

	/// SEED-BASED DKG: Verify all revealed PUBLIC contributions against their commitments.
	///
	/// This verifies that each party's public_contributions (seed hashes + rho)
	/// match their commitment_hash from Round 2.
	fn verify_all_contributions(&self) -> Result<(), DkgProtocolError> {
		let my_id = self.my_party_id();

		for (party_id, public_contributions) in &self.state_data.round2.public_contributions {
			// Skip self (already verified implicitly)
			if *party_id == my_id {
				continue;
			}

			// Verify commitment hash matches
			let expected_hash =
				*self.state_data.round2.commitment_hashes.get(party_id).ok_or_else(|| {
					DkgProtocolError::InternalError(format!(
						"Missing commitment hash for party {}",
						party_id
					))
				})?;

			let actual_hash = self.compute_public_commitment_hash(public_contributions);

			if actual_hash != expected_hash {
				return Err(DkgProtocolError::CommitmentMismatch(*party_id));
			}

			// In seed-based DKG, seed hashes are just 32-byte values - no range check needed
			// The actual η-bounded check happens when we derive secrets from combined seeds
		}

		Ok(())
	}

	/// SEED-BASED DKG: Compute partial public keys from combined seeds.
	///
	/// After Round 3 P2P seed exchange, each party can:
	/// 1. Combine seeds from all parties for each subset
	/// 2. Derive η-bounded secrets from combined seeds
	/// 3. Compute partial public keys t_I = A·s1_I + s2_I
	///
	/// These partial public keys are then broadcast in Round 4.
	fn compute_partial_public_keys(&mut self) -> Result<DkgRound4Broadcast, DkgProtocolError> {
		use qp_rusty_crystals_dilithium::{poly, polyvec};
		use crate::protocol::primitives::Q;

		let my_id = self.my_party_id();
		let threshold = self.state_data.config.threshold();
		let parties = self.state_data.config.total_parties();

		// Use session_id as rho for matrix A expansion
		let rho = self
			.state_data
			.round1
			.combined_session_id
			.ok_or_else(|| DkgProtocolError::InternalError("Session ID not computed".into()))?;

		// Expand matrix A
		let mut a_matrix: Vec<polyvec::Polyvecl> =
			(0..K).map(|_| polyvec::Polyvecl::default()).collect();
		polyvec::matrix_expand(&mut a_matrix, &rho);

		// Get our own seed contributions
		let my_seed_contributions = self.my_seed_contributions.clone().ok_or_else(|| {
			DkgProtocolError::InternalError("Missing my seed contributions".into())
		})?;

		let my_subsets = self.compute_subsets_for_party(my_id, threshold, parties);

		let mut partial_public_keys: HashMap<SubsetMask, PartialPublicKey> = HashMap::new();
		let mut derived_secrets: HashMap<SubsetMask, SubsetContribution> = HashMap::new();

		for subset_mask in &my_subsets {
			// Collect seeds from all parties in this subset
			let mut seeds_for_subset: HashMap<ParticipantId, SubsetSeedContribution> = HashMap::new();

			// Add seeds from received seed contributions
			for ((from_party_id, received_mask), received_seed) in
				&self.state_data.round3.received_seed_contributions
			{
				if *received_mask == *subset_mask {
					seeds_for_subset.insert(*from_party_id, received_seed.clone());
				}
			}

			// Add our own seed
			if let Some(my_seed) = my_seed_contributions.subset_seeds.get(subset_mask) {
				seeds_for_subset.insert(my_id, my_seed.clone());
			}

			// Combine all seeds to get a single combined seed
			let combined_seed = combine_seeds(&seeds_for_subset);

			// Derive the η-bounded secret contribution from the combined seed
			let eta = 2i32; // ML-DSA-87 η parameter
			let derived_secret = derive_subset_contribution(&combined_seed, eta);

			// Compute partial public key t_I = A·s1_I + s2_I
			let mut s1_polyvec = polyvec::Polyvecl::default();
			for (i, poly_coeffs) in derived_secret.s1.iter().enumerate().take(L) {
				for (j, &coeff) in poly_coeffs.iter().enumerate().take(N) {
					s1_polyvec.vec[i].coeffs[j] = coeff;
				}
			}

			// Convert to NTT domain
			let mut s1h = s1_polyvec.clone();
			for s1h_poly in s1h.vec.iter_mut() {
				crate::circl_ntt::ntt(s1h_poly);
			}

			// Compute t_I = A * s1_I
			let mut t_subset = polyvec::Polyveck::default();
			for (i, a_row) in a_matrix.iter().enumerate().take(K) {
				for (a_poly, s1h_poly) in a_row.vec.iter().zip(s1h.vec.iter()).take(L) {
					let mut temp = poly::Poly::default();
					poly::pointwise_montgomery(&mut temp, a_poly, s1h_poly);
					t_subset.vec[i] = poly::add(&t_subset.vec[i], &temp);
				}
				poly::reduce(&mut t_subset.vec[i]);
				poly::invntt_tomont(&mut t_subset.vec[i]);
			}

			// Add s2_I: t_I = A * s1_I + s2_I
			for (i, poly_coeffs) in derived_secret.s2.iter().enumerate().take(K) {
				for (j, &coeff) in poly_coeffs.iter().enumerate().take(N) {
					t_subset.vec[i].coeffs[j] = t_subset.vec[i].coeffs[j].wrapping_add(coeff);
				}
			}

			// Reduce mod Q
			for t_poly in t_subset.vec.iter_mut().take(K) {
				poly::reduce(t_poly);
				for coeff in t_poly.coeffs.iter_mut() {
					*coeff = ((*coeff % Q) + Q) % Q;
				}
			}

			// Convert to PartialPublicKey format
			let t_coeffs: Vec<[i32; N]> = t_subset.vec.iter().take(K)
				.map(|p| p.coeffs)
				.collect();
			let partial_pk = PartialPublicKey {
				subset_mask: *subset_mask,
				t: t_coeffs,
			};

			partial_public_keys.insert(*subset_mask, partial_pk);
			derived_secrets.insert(*subset_mask, derived_secret);
		}

		// Store derived secrets for later use in compute_final_output
		self.state_data.round4.my_derived_secrets = derived_secrets;

		Ok(DkgRound4Broadcast {
			party_id: my_id,
			partial_public_keys,
		})
	}

	/// SEED-BASED DKG: Compute the final DKG output (public key and private share).
	///
	/// This method:
	/// 1. Sums partial public keys from Round 4 to get final public key t
	/// 2. Uses derived secrets (from Round 4) for private key shares
	///
	/// SECURITY: All parties in a subset derive the same η-bounded secret
	/// from combined seeds, matching the Mithril trusted dealer distribution.
	fn compute_final_output(&mut self) -> Result<DkgOutput, DkgProtocolError> {
		use crate::{
			keys::{PrivateKeyShare, PublicKey, SecretShareData, PUBLIC_KEY_SIZE, TR_SIZE},
			protocol::primitives::Q,
		};
		use qp_rusty_crystals_dilithium::{fips202, packing, poly, polyvec};

		let my_id = self.my_party_id();
		let threshold = self.state_data.config.threshold();
		let parties = self.state_data.config.total_parties();

		// Use session_id as rho for matrix A expansion.
		let rho = self
			.state_data
			.round1
			.combined_session_id
			.ok_or_else(|| DkgProtocolError::InternalError("Session ID not computed".into()))?;

		// Accumulate partial public keys from all parties to compute final t
		let mut t = polyvec::Polyveck::default();

		// Collect all unique subsets from Round 4 partial public keys
		let mut all_subsets: std::collections::HashSet<SubsetMask> = std::collections::HashSet::new();
		for round4_msg in self.state_data.round4.partial_public_keys.values() {
			for &subset_mask in round4_msg.partial_public_keys.keys() {
				all_subsets.insert(subset_mask);
			}
		}

		// For each subset, we need exactly one partial public key (all parties in subset have same one)
		// In the seed-based DKG, ALL parties in a subset compute the SAME partial public key
		// because they all derive from the same combined seed.
		// We just need one copy from any party in the subset.
		for subset_mask in &all_subsets {
			// Find a partial public key for this subset from any party
			let mut found_partial_pk: Option<&PartialPublicKey> = None;
			for round4_msg in self.state_data.round4.partial_public_keys.values() {
				if let Some(ppk) = round4_msg.partial_public_keys.get(subset_mask) {
					found_partial_pk = Some(ppk);
					break;
				}
			}

			if let Some(ppk) = found_partial_pk {
				// Add this subset's partial public key to total t
				for (i, poly_coeffs) in ppk.t.iter().enumerate().take(K) {
					for (j, &coeff) in poly_coeffs.iter().enumerate().take(N) {
						t.vec[i].coeffs[j] = t.vec[i].coeffs[j].wrapping_add(coeff);
					}
				}
			} else {
				return Err(DkgProtocolError::InternalError(format!(
					"Missing partial public key for subset {:b}",
					subset_mask
				)));
			}
		}

		// Normalize t mod Q
		for t_poly in t.vec.iter_mut().take(K) {
			poly::reduce(t_poly);
			for coeff in t_poly.coeffs.iter_mut() {
				*coeff = ((*coeff % Q) + Q) % Q;
			}
		}

		// Extract t1 (high bits)
		let mut t0 = polyvec::Polyveck::default();
		let mut t1 = t.clone();
		polyvec::k_power2round(&mut t1, &mut t0);

		// Pack public key
		let mut pk_packed = [0u8; PUBLIC_KEY_SIZE];
		packing::pack_pk(&mut pk_packed, &rho, &t1);

		// Compute TR = SHAKE256(pk)
		let mut tr = [0u8; TR_SIZE];
		let mut h_tr = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut h_tr, &pk_packed, pk_packed.len());
		fips202::shake256_finalize(&mut h_tr);
		fips202::shake256_squeeze(&mut tr, TR_SIZE, &mut h_tr);

		let public_key = PublicKey::new(pk_packed, tr);

		// Get our derived secrets from Round 4 computation
		let my_subsets = self.compute_subsets_for_party(my_id, threshold, parties);
		let mut combined_shares: HashMap<SubsetMask, SecretShareData> = HashMap::new();
		
		for subset_mask in &my_subsets {
			if let Some(derived_secret) = self.state_data.round4.my_derived_secrets.get(subset_mask) {
				let s1_share: Vec<[i32; N]> = derived_secret.s1.clone();
				let s2_share: Vec<[i32; N]> = derived_secret.s2.clone();
				combined_shares.insert(*subset_mask, SecretShareData { s1: s1_share, s2: s2_share });
			} else {
				return Err(DkgProtocolError::InternalError(format!(
					"Missing derived secret for subset {:b}",
					subset_mask
				)));
			}
		}

		// Generate a deterministic key for this party
		let mut party_key = [0u8; 32];
		{
			let mut state = fips202::KeccakState::default();
			// Use rho (which is session_id) and party_id to derive a unique key
			fips202::shake256_absorb(&mut state, &rho, 32);
			fips202::shake256_absorb(&mut state, &my_id.to_le_bytes(), 4);
			fips202::shake256_finalize(&mut state);
			fips202::shake256_squeeze(&mut party_key, 32, &mut state);
		}

		// Create ParticipantList from the DKG participants
		let dkg_participants =
			ParticipantList::new(&self.config().all_participants).ok_or_else(|| {
				DkgProtocolError::InternalError("Invalid DKG participants".to_string())
			})?;

		let private_share = PrivateKeyShare::new(
			my_id,
			parties,
			threshold,
			party_key,
			rho,
			tr,
			combined_shares,
			dkg_participants,
		);

		Ok(DkgOutput { public_key, private_share })
	}

	/// Hash the public key for consensus verification.
	fn hash_public_key(&self, public_key: &crate::keys::PublicKey) -> [u8; COMMITMENT_HASH_SIZE] {
		use qp_rusty_crystals_dilithium::fips202;

		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, public_key.as_bytes(), public_key.as_bytes().len());
		fips202::shake256_finalize(&mut state);

		let mut hash = [0u8; COMMITMENT_HASH_SIZE];
		fips202::shake256_squeeze(&mut hash, COMMITMENT_HASH_SIZE, &mut state);

		hash
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::ThresholdConfig;

	fn make_test_config(party_id: u32) -> DkgConfig {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		DkgConfig::new(threshold_config, party_id, vec![0u32, 1, 2]).unwrap()
	}

	#[test]
	fn test_dkg_creation() {
		let config = make_test_config(0);
		let dkg = DilithiumDkg::new(config, [0u8; 32]);

		assert!(matches!(dkg.state(), DkgState::Initialized));
		assert_eq!(dkg.my_party_id(), 0);
	}

	#[test]
	fn test_dkg_round1_generation() {
		let config = make_test_config(0);
		let mut dkg = DilithiumDkg::new(config, [0u8; 32]);

		// First poke should transition to Round1Generating and generate message
		let action = dkg.poke().unwrap();
		assert!(matches!(action, Action::SendMany(_)));

		// Second poke should transition to waiting
		let action = dkg.poke().unwrap();
		assert!(matches!(action, Action::Wait));
		assert!(matches!(dkg.state(), DkgState::Round1Waiting));
	}

	#[test]
	fn test_dkg_message_processing() {
		let config = make_test_config(0);
		let mut dkg = DilithiumDkg::new(config, [0u8; 32]);

		// Start round 1
		let _ = dkg.poke().unwrap();
		let _ = dkg.poke().unwrap();

		// Should be waiting
		assert!(matches!(dkg.state(), DkgState::Round1Waiting));

		// Receive messages from other parties
		let msg1 = DkgMessage::Round1(DkgRound1Broadcast {
			party_id: 1,
			session_id_contribution: [1u8; 32],
		});
		let msg2 = DkgMessage::Round1(DkgRound1Broadcast {
			party_id: 2,
			session_id_contribution: [2u8; 32],
		});

		// Use the DKG's serialization method to ensure compatibility
		let data1 = dkg.serialize_message(&msg1).unwrap();
		let data2 = dkg.serialize_message(&msg2).unwrap();

		dkg.message(1, data1);
		dkg.message(2, data2);

		// Should be able to advance now
		let action = dkg.poke().unwrap();
		assert!(matches!(action, Action::SendMany(_)));
	}

	#[test]
	fn test_subset_computation() {
		let config = make_test_config(0);
		let dkg = DilithiumDkg::new(config, [0u8; 32]);

		// For 2-of-3, subset size is 3 - 2 + 1 = 2
		// Party 0 should be in subsets: {0,1}, {0,2}
		let subsets = dkg.compute_subsets_for_party(0, 2, 3);
		assert_eq!(subsets.len(), 2);
		assert!(subsets.contains(&0b011)); // Party 0 and 1
		assert!(subsets.contains(&0b101)); // Party 0 and 2
	}

	#[test]
	fn test_message_buffering_out_of_order() {
		// Test that messages arriving out of order are buffered and processed later
		let config = make_test_config(0);
		let mut dkg = DilithiumDkg::new(config, [0u8; 32]);

		// Start round 1 - generates and sends our Round1 message
		let _ = dkg.poke().unwrap();
		// Transition to waiting
		let _ = dkg.poke().unwrap();
		assert!(matches!(dkg.state(), DkgState::Round1Waiting));

		// Now simulate receiving a Round2 message BEFORE we've received all Round1 messages
		// This is what happens in distributed systems with network delays
		let public_contrib = super::super::types::PartyPublicContributions::new(1);
		let round2_msg = DkgMessage::Round2(super::super::types::DkgRound2Broadcast {
			party_id: 1,
			commitment_hash: [42u8; 32],
			public_contributions: public_contrib,
		});
		let round2_data = dkg.serialize_message(&round2_msg).unwrap();

		// Send the Round2 message - it should be buffered, not rejected
		dkg.message(1, round2_data);

		// Verify the message was buffered
		assert!(!dkg.state_data.message_buffer.round2.is_empty());
		assert_eq!(dkg.state_data.message_buffer.round2.len(), 1);
		assert_eq!(dkg.state_data.message_buffer.round2[0].party_id, 1);

		// Now complete Round1 by receiving Round1 messages from other parties
		let r1_msg1 = DkgMessage::Round1(super::super::types::DkgRound1Broadcast {
			party_id: 1,
			session_id_contribution: [1u8; 32],
		});
		let r1_msg2 = DkgMessage::Round1(super::super::types::DkgRound1Broadcast {
			party_id: 2,
			session_id_contribution: [2u8; 32],
		});
		let r1_data1 = dkg.serialize_message(&r1_msg1).unwrap();
		let r1_data2 = dkg.serialize_message(&r1_msg2).unwrap();

		dkg.message(1, r1_data1);
		dkg.message(2, r1_data2);

		// Poke should now advance to Round2
		let action = dkg.poke().unwrap();
		assert!(matches!(action, Action::SendMany(_)));

		// The buffered Round2 message should have been processed during the transition
		assert!(dkg.state_data.message_buffer.round2.is_empty());
		// And the commitment hash from party 1 should be in round2 data
		assert!(dkg.state_data.round2.commitment_hashes.contains_key(&1));
	}

	#[test]
	fn test_message_buffering_multiple_rounds() {
		// Test buffering messages from multiple future rounds
		let config = make_test_config(0);
		let mut dkg = DilithiumDkg::new(config, [0u8; 32]);

		// Start round 1
		let _ = dkg.poke().unwrap();
		let _ = dkg.poke().unwrap();
		assert!(matches!(dkg.state(), DkgState::Round1Waiting));

		// Buffer Round2 message (simulating very fast peer)
		let public_contrib = super::super::types::PartyPublicContributions::new(1);
		let round2_msg = DkgMessage::Round2(super::super::types::DkgRound2Broadcast {
			party_id: 1,
			commitment_hash: [42u8; 32],
			public_contributions: public_contrib,
		});
		let round2_data = dkg.serialize_message(&round2_msg).unwrap();
		dkg.message(1, round2_data);

		// Should be buffered appropriately
		assert_eq!(dkg.state_data.message_buffer.round2.len(), 1);

		// Verify state hasn't changed unexpectedly
		assert!(matches!(dkg.state(), DkgState::Round1Waiting));
	}
}
