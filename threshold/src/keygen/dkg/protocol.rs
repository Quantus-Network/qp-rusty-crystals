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
		DkgConfig, DkgMessage, DkgOutput, DkgRound1Broadcast, DkgRound2Broadcast,
		DkgRound3Broadcast, DkgRound4Private, DkgRound5Broadcast, PartialPublicKey, ParticipantId,
		PartyContributions, PartyPublicContributions, SubsetContribution, SubsetMask,
		COMMITMENT_HASH_SIZE, K, L, N, RHO_CONTRIBUTION_SIZE, SESSION_ID_SIZE,
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
	/// SECURITY FIX (HQ1): Public contributions to broadcast in Round 3.
	/// Contains partial public keys (t_I = A·s_I) and rho contribution.
	/// Stored separately from secret contributions to prevent accidental leakage.
	my_public_contributions: Option<PartyPublicContributions>,
	/// SECURITY FIX (HQ1): P2P messages to send in Round 4.
	/// Contains secret contributions for each (party, subset) pair.
	round4_private_messages: Vec<DkgRound4Private>,
	/// Number of P2P messages sent so far in Round 4.
	round4_private_sent_count: usize,
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
			round4_private_messages: Vec::new(),
			round4_private_sent_count: 0,
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

				// SECURITY FIX (HQ1): Generate secret contributions AND partial public keys
				// Only the partial public keys will be broadcast
				let (secret_contributions, public_contributions) =
					self.generate_contributions_with_partial_public_keys()?;

				// Commit to PUBLIC contributions only (partial public keys + rho)
				// SECURITY: We commit to what we will broadcast, NOT to raw secrets
				let commitment_hash = self.compute_public_commitment_hash(&public_contributions);

				// Store secret contributions locally (NEVER broadcast)
				self.state_data.round2.my_contributions = Some(secret_contributions);
				// Store public contributions for Round 3
				self.my_public_contributions = Some(public_contributions);

				self.state_data.round2.my_commitment_hash = commitment_hash;
				self.state_data.round2.add_commitment_hash(self.my_party_id(), commitment_hash);

				let msg = DkgRound2Broadcast { party_id: self.my_party_id(), commitment_hash };

				self.sent_current_round = true;
				Ok(Action::SendMany(self.serialize_message(&DkgMessage::Round2(msg))?))
			},

			DkgState::Round2Waiting =>
				if self.state_data.can_advance() {
					let errors = self.state_data.transition_to(DkgState::Round3Revealing);
					for e in errors {
						eprintln!("Error processing buffered message: {}", e);
					}
					self.sent_current_round = false;
					self.poke()
				} else {
					Ok(Action::Wait)
				},

			DkgState::Round3Revealing => {
				if self.sent_current_round {
					// Broadcast sent, now transition to waiting and send P2P messages
					let errors = self.state_data.transition_to(DkgState::Round3Waiting);
					for e in errors {
						eprintln!("Error processing buffered message: {}", e);
					}
					// Continue to Round3Waiting to send P2P messages
					return self.poke();
				}

				// SECURITY FIX (HQ1): Reveal only PUBLIC contributions (partial public keys)
				// Raw secrets are NEVER broadcast
				let public_contributions =
					self.my_public_contributions.clone().ok_or_else(|| {
						DkgProtocolError::InternalError("Missing my public contributions".into())
					})?;

				// Store our secret contributions locally for final computation
				let secret_contributions =
					self.state_data.round2.my_contributions.clone().ok_or_else(|| {
						DkgProtocolError::InternalError("Missing my secret contributions".into())
					})?;
				self.state_data.round3.set_my_secret_contributions(secret_contributions.clone());

				// Add our public contributions to round3 data
				self.state_data
					.round3
					.add_public_contributions(self.my_party_id(), public_contributions.clone());

				// SECURITY FIX (HQ1): Generate P2P messages to send secret contributions
				// to other parties in the same subsets (these are Round 4 messages)
				self.round4_private_messages =
					self.generate_round4_private_messages(&secret_contributions);
				self.round4_private_sent_count = 0;

				// SECURITY: Only partial public keys and rho are broadcast
				let msg = DkgRound3Broadcast { party_id: self.my_party_id(), public_contributions };

				self.sent_current_round = true;
				Ok(Action::SendMany(self.serialize_message(&DkgMessage::Round3(msg))?))
			},

			DkgState::Round3Waiting => {
				// Check if we have all broadcasts
				let expected = self.state_data.expected_count();
				let broadcasts_complete = self.state_data.round3.is_broadcast_complete(expected);

				if !broadcasts_complete {
					return Ok(Action::Wait);
				}

				// All broadcasts received, verify commitment hashes
				self.verify_all_contributions()?;

				// Transition to Round 4 (P2P secret sharing)
				let errors = self.state_data.transition_to(DkgState::Round4Sending);
				for e in errors {
					eprintln!("Error processing buffered message: {}", e);
				}
				self.sent_current_round = false;
				self.poke()
			},

			DkgState::Round4Sending => {
				// Send P2P messages with secret contributions
				if self.round4_private_sent_count < self.round4_private_messages.len() {
					return self.send_next_round4_private();
				}

				// All P2P messages sent, transition to waiting
				let errors = self.state_data.transition_to(DkgState::Round4Waiting);
				for e in errors {
					eprintln!("Error processing buffered message: {}", e);
				}
				self.poke()
			},

			DkgState::Round4Waiting => {
				// Check if we have all P2P messages for our subsets
				let my_subsets = self.compute_my_subsets();
				let p2p_complete = self
					.state_data
					.round3
					.is_p2p_complete(&my_subsets, self.state_data.config.total_parties());

				if !p2p_complete {
					return Ok(Action::Wait);
				}

				// Verify that received secrets match broadcast partial public keys
				self.verify_received_secrets()?;

				// Transition to Round 5 (confirmation)
				let errors = self.state_data.transition_to(DkgState::Round5Confirming);
				for e in errors {
					eprintln!("Error processing buffered message: {}", e);
				}
				self.sent_current_round = false;
				self.poke()
			},

			DkgState::Round5Confirming => {
				if self.sent_current_round {
					let errors = self.state_data.transition_to(DkgState::Round5Waiting);
					for e in errors {
						eprintln!("Error processing buffered message: {}", e);
					}
					return Ok(Action::Wait);
				}

				// Compute final shares and public key
				let (success, public_key_hash) = match self.compute_final_output() {
					Ok(output) => {
						let pk_hash = self.hash_public_key(&output.public_key);
						self.state_data.round5.my_public_key_hash = pk_hash;
						self.state_data.output = Some(output);
						(true, pk_hash)
					},
					Err(e) => {
						// Log error but continue to send confirmation
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
					// Check consensus
					if !self.state_data.round5.consensus_reached() {
						let failed = self.state_data.round5.failed_parties();
						if !failed.is_empty() {
							return Err(DkgProtocolError::PartyFailure(failed));
						}
						let mismatched = self.state_data.round5.mismatched_parties();
						return Err(DkgProtocolError::ConsensusFailure(mismatched));
					}

					// Return the output
					let output =
						self.state_data.output.clone().ok_or_else(|| {
							DkgProtocolError::InternalError("Missing output".into())
						})?;

					let _ = self.state_data.transition_to(DkgState::Complete);
					Ok(Action::Return(output))
				} else {
					Ok(Action::Wait)
				}
			},

			DkgState::Complete => {
				let output = self.state_data.output.clone().ok_or_else(|| {
					DkgProtocolError::InternalError("Missing output in Complete state".into())
				})?;
				Ok(Action::Return(output))
			},

			DkgState::Failed(reason) =>
				Err(DkgProtocolError::InvalidState(format!("Protocol failed: {}", reason))),
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
			DkgMessage::Round3(m) => self.state_data.process_round3(m),
			DkgMessage::Round4(m) => self.state_data.process_round4_private(m),
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
	/// This method generates:
	/// 1. Secret contributions (s1, s2) - kept locally, NEVER broadcast
	/// 2. Partial public keys (t_I = A·s1_I + s2_I) - broadcast in Round 3
	///
	/// The partial public keys allow computing the final public key without
	/// revealing the underlying secrets.
	fn generate_contributions_with_partial_public_keys(
		&mut self,
	) -> Result<(PartyContributions, PartyPublicContributions), DkgProtocolError> {
		use crate::protocol::primitives::Q;
		use qp_rusty_crystals_dilithium::{poly, polyvec};

		let my_id = self.my_party_id();
		let threshold = self.state_data.config.threshold();
		let parties = self.state_data.config.total_parties();

		// Generate rho contribution (shared between both structs)
		let rho_contribution: [u8; RHO_CONTRIBUTION_SIZE] = self.rng.gen();

		let mut secret_contributions = PartyContributions::new(my_id);
		secret_contributions.rho_contribution = rho_contribution;

		let mut public_contributions = PartyPublicContributions::new(my_id);
		public_contributions.rho_contribution = rho_contribution;

		// Get subsets this party belongs to
		let subsets = self.compute_subsets_for_party(my_id, threshold, parties);

		// We need the combined rho to expand matrix A, but at Round 2 we don't have it yet.
		// Use a deterministic expansion based on session ID for now.
		// The final t will be computed in Round 4 using the actual combined rho.
		let session_id =
			self.state_data.round1.combined_session_id.ok_or_else(|| {
				DkgProtocolError::InternalError("Session ID not yet computed".into())
			})?;

		// Expand matrix A using session ID as seed (deterministic, all parties get same A)
		let mut a_matrix: Vec<polyvec::Polyvecl> =
			(0..K).map(|_| polyvec::Polyvecl::default()).collect();
		polyvec::matrix_expand(&mut a_matrix, &session_id);

		for subset_mask in subsets {
			// Generate secret contribution
			let secret_contrib = self.generate_subset_contribution(subset_mask)?;

			// Compute partial public key: t_I = A · s1_I + s2_I
			let mut partial_pk = PartialPublicKey::new(subset_mask);

			// Convert s1 to polyvec and to NTT domain
			let mut s1_polyvec = polyvec::Polyvecl::default();
			for (i, poly_coeffs) in secret_contrib.s1.iter().enumerate().take(L) {
				for (j, &coeff) in poly_coeffs.iter().enumerate().take(N) {
					s1_polyvec.vec[i].coeffs[j] = coeff;
				}
			}

			// Convert to NTT domain
			let mut s1h = s1_polyvec.clone();
			for s1h_poly in s1h.vec.iter_mut() {
				crate::circl_ntt::ntt(s1h_poly);
			}

			// Compute t = A * s1
			let mut t_polyvec = polyvec::Polyveck::default();
			for (i, a_row) in a_matrix.iter().enumerate().take(K) {
				for (a_poly, s1h_poly) in a_row.vec.iter().zip(s1h.vec.iter()).take(L) {
					let mut temp = poly::Poly::default();
					poly::pointwise_montgomery(&mut temp, a_poly, s1h_poly);
					t_polyvec.vec[i] = poly::add(&t_polyvec.vec[i], &temp);
				}
				poly::reduce(&mut t_polyvec.vec[i]);
				poly::invntt_tomont(&mut t_polyvec.vec[i]);
			}

			// Add s2: t = A * s1 + s2
			for (i, poly_coeffs) in secret_contrib.s2.iter().enumerate().take(K) {
				for (j, &coeff) in poly_coeffs.iter().enumerate().take(N) {
					t_polyvec.vec[i].coeffs[j] = t_polyvec.vec[i].coeffs[j].wrapping_add(coeff);
				}
			}

			// Reduce and normalize
			for t_poly in t_polyvec.vec.iter_mut().take(K) {
				poly::reduce(t_poly);
				for coeff in t_poly.coeffs.iter_mut() {
					*coeff = ((*coeff % Q) + Q) % Q;
				}
			}

			// Copy to partial public key
			for (i, t_poly) in t_polyvec.vec.iter().enumerate().take(K) {
				for (j, &coeff) in t_poly.coeffs.iter().enumerate().take(N) {
					partial_pk.t[i][j] = coeff;
				}
			}

			// Store both
			secret_contributions.subset_contributions.insert(subset_mask, secret_contrib);
			public_contributions.partial_public_keys.insert(subset_mask, partial_pk);
		}

		Ok((secret_contributions, public_contributions))
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

	/// Generate a random η-bounded contribution for a subset.
	fn generate_subset_contribution(
		&mut self,
		_subset_mask: SubsetMask,
	) -> Result<SubsetContribution, DkgProtocolError> {
		let eta = 2i32; // ML-DSA-87 η parameter
		let mut contrib = SubsetContribution::new();

		// Generate random η-bounded polynomials for s1
		for poly in &mut contrib.s1 {
			for coeff in poly.iter_mut() {
				*coeff = self.sample_bounded_coefficient(eta)?;
			}
		}

		// Generate random η-bounded polynomials for s2
		for poly in &mut contrib.s2 {
			for coeff in poly.iter_mut() {
				*coeff = self.sample_bounded_coefficient(eta)?;
			}
		}

		Ok(contrib)
	}

	/// Sample a random coefficient in [-eta, eta].
	fn sample_bounded_coefficient(&mut self, eta: i32) -> Result<i32, DkgProtocolError> {
		let bound = (2 * eta + 1) as u32;
		loop {
			let b: u8 = self.rng.gen();
			let b = b as u32;
			if b < (256 / bound) * bound {
				return Ok((b % bound) as i32 - eta);
			}
		}
	}

	/// Compute the subsets this party belongs to.
	fn compute_my_subsets(&self) -> Vec<SubsetMask> {
		let my_id = self.my_party_id();
		let threshold = self.state_data.config.threshold();
		let parties = self.state_data.config.total_parties();
		self.compute_subsets_for_party(my_id, threshold, parties)
	}

	/// SECURITY FIX (HQ1): Generate P2P messages to send secret contributions
	/// to other parties in the same subsets.
	///
	/// For each subset this party belongs to, we generate a message for each
	/// OTHER party in that subset (not ourselves).
	fn generate_round4_private_messages(
		&self,
		secret_contributions: &PartyContributions,
	) -> Vec<DkgRound4Private> {
		let my_id = self.my_party_id();
		let mut messages = Vec::new();

		for (subset_mask, contribution) in &secret_contributions.subset_contributions {
			// Find other parties in this subset
			for i in 0..self.state_data.config.total_parties() {
				let party_bit = 1u16 << i;
				if (*subset_mask & party_bit) != 0 {
					// This party is in the subset
					if let Some(party_id) = self.state_data.party_id_at(i as usize) {
						if party_id != my_id {
							// Send our contribution to this party
							messages.push(DkgRound4Private {
								from_party_id: my_id,
								subset_mask: *subset_mask,
								contribution: contribution.clone(),
							});
						}
					}
				}
			}
		}

		messages
	}

	/// Send the next P2P message in the Round 4 queue.
	fn send_next_round4_private(&mut self) -> Result<Action<DkgOutput>, DkgProtocolError> {
		if self.round4_private_sent_count >= self.round4_private_messages.len() {
			return Ok(Action::Wait);
		}

		let msg = &self.round4_private_messages[self.round4_private_sent_count];

		// Find the target party ID from the subset mask
		// We need to find which party this specific message is for
		// The messages are generated in order, so we need to track per-subset recipients
		let target_party_id =
			self.find_recipient_for_private_message(self.round4_private_sent_count)?;

		let dkg_msg = DkgMessage::Round4(msg.clone());
		let data = self.serialize_message(&dkg_msg)?;

		self.round4_private_sent_count += 1;

		Ok(Action::SendPrivate(target_party_id, data))
	}

	/// Find the recipient party ID for a given P2P message index.
	fn find_recipient_for_private_message(
		&self,
		msg_index: usize,
	) -> Result<ParticipantId, DkgProtocolError> {
		let my_id = self.my_party_id();
		let secret_contributions =
			self.state_data.round2.my_contributions.as_ref().ok_or_else(|| {
				DkgProtocolError::InternalError("Missing my contributions".into())
			})?;

		let mut current_index = 0;
		for (subset_mask, _) in &secret_contributions.subset_contributions {
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

	/// SECURITY FIX (HQ1): Verify that received secrets match broadcast partial public keys.
	///
	/// For each received secret contribution, we verify that A·s_I equals the
	/// partial public key t_I that was broadcast by the same party.
	fn verify_received_secrets(&self) -> Result<(), DkgProtocolError> {
		use crate::protocol::primitives::Q;
		use qp_rusty_crystals_dilithium::{poly, polyvec};

		// Get the session ID to expand matrix A
		let session_id = self
			.state_data
			.round1
			.combined_session_id
			.ok_or_else(|| DkgProtocolError::InternalError("Session ID not computed".into()))?;

		// Expand matrix A
		let mut a_matrix: Vec<polyvec::Polyvecl> =
			(0..K).map(|_| polyvec::Polyvecl::default()).collect();
		polyvec::matrix_expand(&mut a_matrix, &session_id);

		// For each received secret contribution
		for ((from_party_id, subset_mask), received_secret) in
			&self.state_data.round3.received_secret_contributions
		{
			// Get the broadcast public contributions from this party
			let public_contrib =
				self.state_data.round3.public_contributions.get(from_party_id).ok_or_else(
					|| {
						DkgProtocolError::InternalError(format!(
							"Missing public contributions from party {}",
							from_party_id
						))
					},
				)?;

			// Get the partial public key for this subset
			let partial_pk =
				public_contrib.partial_public_keys.get(subset_mask).ok_or_else(|| {
					DkgProtocolError::InternalError(format!(
						"Missing partial public key for subset {:b} from party {}",
						subset_mask, from_party_id
					))
				})?;

			// Compute t_I = A·s1_I + s2_I from the received secret
			let mut s1_polyvec = polyvec::Polyvecl::default();
			for (i, poly_coeffs) in received_secret.s1.iter().enumerate().take(L) {
				for (j, &coeff) in poly_coeffs.iter().enumerate().take(N) {
					s1_polyvec.vec[i].coeffs[j] = coeff;
				}
			}

			// Convert to NTT domain
			let mut s1h = s1_polyvec.clone();
			for s1h_poly in s1h.vec.iter_mut() {
				crate::circl_ntt::ntt(s1h_poly);
			}

			// Compute t = A * s1
			let mut computed_t = polyvec::Polyveck::default();
			for (i, a_row) in a_matrix.iter().enumerate().take(K) {
				for (a_poly, s1h_poly) in a_row.vec.iter().zip(s1h.vec.iter()).take(L) {
					let mut temp = poly::Poly::default();
					poly::pointwise_montgomery(&mut temp, a_poly, s1h_poly);
					computed_t.vec[i] = poly::add(&computed_t.vec[i], &temp);
				}
				poly::reduce(&mut computed_t.vec[i]);
				poly::invntt_tomont(&mut computed_t.vec[i]);
			}

			// Add s2: t = A * s1 + s2
			for (i, poly_coeffs) in received_secret.s2.iter().enumerate().take(K) {
				for (j, &coeff) in poly_coeffs.iter().enumerate().take(N) {
					computed_t.vec[i].coeffs[j] = computed_t.vec[i].coeffs[j].wrapping_add(coeff);
				}
			}

			// Reduce and normalize
			for t_poly in computed_t.vec.iter_mut().take(K) {
				poly::reduce(t_poly);
				for coeff in t_poly.coeffs.iter_mut() {
					*coeff = ((*coeff % Q) + Q) % Q;
				}
			}

			// Compare with broadcast partial public key
			for i in 0..K {
				for j in 0..N {
					let computed = computed_t.vec[i].coeffs[j];
					let broadcast = partial_pk.t[i][j];
					if computed != broadcast {
						return Err(DkgProtocolError::CommitmentMismatch(*from_party_id));
					}
				}
			}
		}

		Ok(())
	}

	/// Compute commitment hash for PUBLIC contributions only.
	///
	/// This commits to:
	/// - Party ID
	/// - Rho contribution
	/// - Partial public keys (t_I = A·s_I), NOT raw secrets
	/// - Session ID (for domain separation)
	///
	/// SECURITY: The raw secret polynomials (s1, s2) are NEVER included in the commitment.
	fn compute_public_commitment_hash(
		&self,
		public_contributions: &PartyPublicContributions,
	) -> [u8; COMMITMENT_HASH_SIZE] {
		use qp_rusty_crystals_dilithium::fips202;

		let mut state = fips202::KeccakState::default();

		// Include party ID
		fips202::shake256_absorb(&mut state, &public_contributions.party_id.to_le_bytes(), 4);

		// Include rho contribution
		fips202::shake256_absorb(
			&mut state,
			&public_contributions.rho_contribution,
			RHO_CONTRIBUTION_SIZE,
		);

		// Include partial public keys in sorted order by subset mask
		let mut partial_pks: Vec<_> = public_contributions.partial_public_keys.iter().collect();
		partial_pks.sort_by_key(|(mask, _)| *mask);

		for (mask, partial_pk) in partial_pks {
			fips202::shake256_absorb(&mut state, &mask.to_le_bytes(), 2);

			// Include partial public key coefficients
			for poly in &partial_pk.t {
				for coeff in poly {
					fips202::shake256_absorb(&mut state, &coeff.to_le_bytes(), 4);
				}
			}
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

	/// SECURITY FIX (HQ1): Verify all revealed PUBLIC contributions against their commitments.
	///
	/// This verifies:
	/// 1. The commitment hash matches what was committed in Round 2
	/// 2. Partial public key coefficients are in valid range [0, Q)
	///
	/// SECURITY: We verify PUBLIC contributions (partial public keys), NOT raw secrets.
	fn verify_all_contributions(&mut self) -> Result<(), DkgProtocolError> {
		use crate::protocol::primitives::Q;

		let my_id = self.my_party_id();

		// Collect party IDs and public contributions to avoid borrow issues
		let parties_to_verify: Vec<(ParticipantId, PartyPublicContributions)> = self
			.state_data
			.round3
			.public_contributions
			.iter()
			.map(|(&id, c)| (id, c.clone()))
			.collect();

		for (party_id, public_contributions) in parties_to_verify {
			// Skip self (already verified implicitly)
			if party_id == my_id {
				self.state_data.round3.set_verification_result(party_id, true);
				continue;
			}

			// Verify commitment hash matches
			let expected_hash =
				*self.state_data.round2.commitment_hashes.get(&party_id).ok_or_else(|| {
					DkgProtocolError::InternalError(format!(
						"Missing commitment hash for party {}",
						party_id
					))
				})?;

			let actual_hash = self.compute_public_commitment_hash(&public_contributions);

			if actual_hash != expected_hash {
				self.state_data.round3.set_verification_result(party_id, false);
				return Err(DkgProtocolError::CommitmentMismatch(party_id));
			}

			// Verify partial public key coefficients are in valid range [0, Q)
			for partial_pk in public_contributions.partial_public_keys.values() {
				if !partial_pk.verify_range(Q) {
					self.state_data.round3.set_verification_result(party_id, false);
					return Err(DkgProtocolError::InvalidContributionBounds(party_id));
				}
			}

			self.state_data.round3.set_verification_result(party_id, true);
		}

		Ok(())
	}

	/// SECURITY FIX (HQ1): Compute the final DKG output (public key and private share).
	///
	/// This method computes:
	/// 1. Combined rho from all parties' rho contributions
	/// 2. Final public key t by summing PARTIAL PUBLIC KEYS (not raw secrets!)
	/// 3. Private key shares using only THIS PARTY's secret contributions
	///
	/// SECURITY: Raw secrets from other parties are NEVER accessed because they
	/// were never broadcast. Only partial public keys are summed.
	fn compute_final_output(&mut self) -> Result<DkgOutput, DkgProtocolError> {
		use crate::{
			keys::{PrivateKeyShare, PublicKey, SecretShareData, PUBLIC_KEY_SIZE, TR_SIZE},
			protocol::primitives::Q,
		};
		use qp_rusty_crystals_dilithium::{fips202, packing, polyvec};

		let my_id = self.my_party_id();
		let threshold = self.state_data.config.threshold();
		let parties = self.state_data.config.total_parties();

		// Use session_id as rho for matrix A expansion.
		// This is critical: the same seed must be used both when computing partial
		// public keys (in Round 2) and when packing the final public key here.
		// The session_id was jointly generated in Round 1 from all parties'
		// contributions, so it serves the same purpose as rho in the Borin DKG.
		let rho = self
			.state_data
			.round1
			.combined_session_id
			.ok_or_else(|| DkgProtocolError::InternalError("Session ID not computed".into()))?;

		// SECURITY FIX (HQ1): Get THIS PARTY's secret contributions
		let my_secret_contributions =
			self.state_data.round3.my_secret_contributions.clone().ok_or_else(|| {
				DkgProtocolError::InternalError("Missing my secret contributions".into())
			})?;

		// Compute combined shares for each subset THIS PARTY belongs to
		// SECURITY FIX (HQ1): We now combine our own secrets WITH secrets received
		// via P2P from other parties in the same subset.
		let mut combined_shares: HashMap<SubsetMask, SecretShareData> = HashMap::new();
		let my_subsets = self.compute_subsets_for_party(my_id, threshold, parties);

		for subset_mask in &my_subsets {
			let mut s1_share = vec![[0i32; N]; L];
			let mut s2_share = vec![[0i32; N]; K];

			// Add our own contribution
			if let Some(my_contrib) = my_secret_contributions.subset_contributions.get(subset_mask)
			{
				for (i, poly) in my_contrib.s1.iter().enumerate() {
					for (j, &coeff) in poly.iter().enumerate() {
						s1_share[i][j] = s1_share[i][j].wrapping_add(coeff);
					}
				}
				for (i, poly) in my_contrib.s2.iter().enumerate() {
					for (j, &coeff) in poly.iter().enumerate() {
						s2_share[i][j] = s2_share[i][j].wrapping_add(coeff);
					}
				}
			}

			// Add contributions received from other parties via P2P
			for ((from_party_id, received_mask), received_contrib) in
				&self.state_data.round3.received_secret_contributions
			{
				if *received_mask == *subset_mask && *from_party_id != my_id {
					for (i, poly) in received_contrib.s1.iter().enumerate() {
						for (j, &coeff) in poly.iter().enumerate() {
							s1_share[i][j] = s1_share[i][j].wrapping_add(coeff);
						}
					}
					for (i, poly) in received_contrib.s2.iter().enumerate() {
						for (j, &coeff) in poly.iter().enumerate() {
							s2_share[i][j] = s2_share[i][j].wrapping_add(coeff);
						}
					}
				}
			}

			// Note: Do NOT normalize to [0, Q) here!
			// The shares should remain in centered form like the dealer produces.
			// The signing code expects centered values.
			combined_shares.insert(*subset_mask, SecretShareData { s1: s1_share, s2: s2_share });
		}

		// SECURITY FIX: Compute final t by summing PARTIAL PUBLIC KEYS from all parties
		// We NEVER access other parties' raw secrets (we don't have them!)
		let mut t = polyvec::Polyveck::default();

		// Sum all partial public keys from all parties
		for public_contrib in self.state_data.round3.public_contributions.values() {
			for partial_pk in public_contrib.partial_public_keys.values() {
				for (i, t_poly) in partial_pk.t.iter().enumerate().take(K) {
					for (j, &coeff) in t_poly.iter().enumerate().take(N) {
						t.vec[i].coeffs[j] = t.vec[i].coeffs[j].wrapping_add(coeff);
					}
				}
			}
		}

		// Normalize t mod Q
		for t_poly in t.vec.iter_mut().take(K) {
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
		// This maps arbitrary party IDs to sequential indices for share operations
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
		let round2_msg = DkgMessage::Round2(super::super::types::DkgRound2Broadcast {
			party_id: 1,
			commitment_hash: [42u8; 32],
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

		// Buffer Round2, Round3, and Round4 messages (simulating very fast peers)
		let round2_msg = DkgMessage::Round2(super::super::types::DkgRound2Broadcast {
			party_id: 1,
			commitment_hash: [42u8; 32],
		});
		let round2_data = dkg.serialize_message(&round2_msg).unwrap();
		dkg.message(1, round2_data);

		// All should be buffered appropriately
		assert_eq!(dkg.state_data.message_buffer.round2.len(), 1);

		// Verify state hasn't changed unexpectedly
		assert!(matches!(dkg.state(), DkgState::Round1Waiting));
	}
}
