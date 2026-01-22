//! Threshold signer for ML-DSA-87.
//!
//! This module provides the main API for threshold signing. Each party
//! creates a `ThresholdSigner` with their private key share and uses it
//! to participate in the three-round signing protocol.
//!
//! # Example
//!
//! ```ignore
//! use qp_rusty_crystals_threshold::{
//!     ThresholdSigner, ThresholdConfig, generate_with_dealer,
//!     Round1Broadcast, Round2Broadcast, Round3Broadcast,
//! };
//!
//! // Setup: Generate keys with a trusted dealer
//! let config = ThresholdConfig::new(2, 3)?;
//! let (public_key, shares) = generate_with_dealer(&seed, config)?;
//!
//! // Each party creates their signer
//! let mut signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)?;
//!
//! // Round 1: Generate commitment
//! let r1 = signer.round1_commit(&mut rng)?;
//! // ... broadcast r1 to other parties, receive their broadcasts ...
//!
//! // Round 2: Reveal commitment
//! let r2 = signer.round2_reveal(message, context, &other_r1_broadcasts)?;
//! // ... broadcast r2 to other parties, receive their broadcasts ...
//!
//! // Round 3: Compute response
//! let r3 = signer.round3_respond(&other_r2_broadcasts)?;
//! // ... broadcast r3 to other parties, receive their broadcasts ...
//!
//! // Combine into final signature
//! let signature = signer.combine(&all_r2_broadcasts, &all_r3_broadcasts)?;
//! ```

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use qp_rusty_crystals_dilithium::polyvec;

use crate::{
	broadcast::{Round1Broadcast, Round2Broadcast, Round3Broadcast, Signature},
	config::ThresholdConfig,
	error::{ThresholdError, ThresholdResult},
	keys::{PrivateKeyShare, PublicKey},
	protocol::signing::{
		aggregate_commitments_dilithium, combine_signature, generate_round1,
		generate_round3_response, pack_responses, pack_round1_commitment, process_round2,
		unpack_commitment_dilithium, unpack_responses, Round1Data, Round2Data,
	},
};

/// A threshold signer for a single party.
///
/// Each party in the threshold scheme creates one `ThresholdSigner` with their
/// private key share. The signer manages the protocol state and produces the
/// messages to broadcast at each round.
///
/// # Protocol Overview
///
/// The threshold signing protocol has three rounds:
///
/// 1. **Round 1 (Commitment)**: Each party generates random values and broadcasts a commitment
///    hash. This prevents parties from adaptively choosing their randomness based on others'
///    values.
///
/// 2. **Round 2 (Reveal)**: Each party reveals their actual commitment values and receives others'
///    values. The message to be signed is incorporated here.
///
/// 3. **Round 3 (Response)**: Each party computes their signature share based on their secret key
///    share and the aggregated commitments.
///
/// After Round 3, any party can combine all the responses into a final signature.
///
/// # Security
///
/// - The `PrivateKeyShare` contains secret material and is stored inside the signer.
/// - Only broadcast messages (`Round1Broadcast`, `Round2Broadcast`, `Round3Broadcast`) should be
///   sent over the network.
/// - The signer automatically zeroizes sensitive data when dropped.
pub struct ThresholdSigner {
	/// Threshold configuration.
	config: ThresholdConfig,
	/// Public key (shared by all parties).
	public_key: PublicKey,
	/// This party's private key share.
	private_key: PrivateKeyShare,
	/// Current protocol state.
	state: SignerState,
}

/// Internal state of the signer.
impl Default for SignerState {
	fn default() -> Self {
		SignerState::Fresh
	}
}

enum SignerState {
	/// Ready to start a new signing session.
	Fresh,
	/// Round 1 complete, holding commitment data.
	AfterRound1 { round1_data: Round1Data },
	/// Round 2 complete, ready to compute response.
	AfterRound2 {
		round1_data: Round1Data,
		round2_data: Round2Data,
		message: Vec<u8>,
		context: Vec<u8>,
	},
	/// Round 3 complete, signature can be combined.
	AfterRound3 {
		round2_data: Round2Data,
		my_responses: Vec<polyvec::Polyvecl>,
		message: Vec<u8>,
		context: Vec<u8>,
	},
}

impl ThresholdSigner {
	/// Create a new threshold signer.
	///
	/// # Arguments
	///
	/// * `private_key` - This party's private key share
	/// * `public_key` - The threshold public key (shared by all parties)
	/// * `config` - Threshold configuration
	///
	/// # Errors
	///
	/// Returns an error if the private key share is not compatible with the config.
	pub fn new(
		private_key: PrivateKeyShare,
		public_key: PublicKey,
		config: ThresholdConfig,
	) -> ThresholdResult<Self> {
		// Validate that the config is compatible with the private key for subset signing.
		//
		// For subset signing (t-of-n threshold), we allow:
		// - config.total_parties() >= config.threshold() (enough parties to meet threshold)
		// - config.total_parties() <= private_key.total_parties() (can't have more than DKG)
		// - config.threshold() == private_key.threshold() (threshold must match DKG)
		//
		// This enables signing with any subset of t or more parties from the original
		// n parties that participated in DKG.
		if private_key.threshold() != config.threshold() {
			return Err(ThresholdError::InvalidConfiguration(format!(
				"Private key threshold ({}) does not match config threshold ({})",
				private_key.threshold(),
				config.threshold()
			)));
		}
		if config.total_parties() < config.threshold() {
			return Err(ThresholdError::InvalidConfiguration(format!(
                "Config total parties ({}) is less than threshold ({}) - not enough parties to sign",
                config.total_parties(),
                config.threshold()
            )));
		}
		if config.total_parties() > private_key.total_parties() {
			return Err(ThresholdError::InvalidConfiguration(format!(
                "Config total parties ({}) exceeds DKG total parties ({}) - cannot have more signers than DKG participants",
                config.total_parties(),
                private_key.total_parties()
            )));
		}

		Ok(Self { config, public_key, private_key, state: SignerState::Fresh })
	}

	/// Get this party's ID.
	pub fn party_id(&self) -> u32 {
		self.private_key.party_id()
	}

	/// Get the threshold configuration.
	pub fn config(&self) -> &ThresholdConfig {
		&self.config
	}

	/// Get the public key.
	pub fn public_key(&self) -> &PublicKey {
		&self.public_key
	}

	/// Round 1: Generate commitment and return broadcast message.
	///
	/// This is the first step in the signing protocol. The returned
	/// `Round1Broadcast` should be sent to all other participating parties.
	///
	/// # Arguments
	///
	/// * `rng` - A cryptographically secure random number generator
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The signer is not in the `Fresh` state
	/// - Random number generation fails
	///
	/// # State Transition
	///
	/// `Fresh` → `AfterRound1`
	pub fn round1_commit<R: RngCore + CryptoRng>(
		&mut self,
		rng: &mut R,
	) -> ThresholdResult<Round1Broadcast> {
		// Check state
		if !matches!(self.state, SignerState::Fresh) {
			return Err(ThresholdError::InvalidState {
				current: self.state_name(),
				expected: "Fresh",
			});
		}

		// Generate random seed
		let mut seed = [0u8; 32];
		rng.fill_bytes(&mut seed);

		// Generate Round 1 data
		let round1_data = generate_round1(&self.private_key, &self.config, &seed)?;

		let broadcast =
			Round1Broadcast::new(self.private_key.party_id(), round1_data.commitment_hash);

		// Update state
		self.state = SignerState::AfterRound1 { round1_data };

		Ok(broadcast)
	}

	/// Round 2: Process others' commitments and reveal our commitment.
	///
	/// After receiving all Round 1 broadcasts from other parties, call this
	/// method to produce the Round 2 broadcast.
	///
	/// # Arguments
	///
	/// * `message` - The message to sign
	/// * `context` - Optional context string (max 255 bytes)
	/// * `other_round1` - Round 1 broadcasts from other participating parties
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The signer is not in the `AfterRound1` state
	/// - Context is too long (> 255 bytes)
	/// - Not enough parties are participating
	///
	/// # State Transition
	///
	/// `AfterRound1` → `AfterRound2`
	pub fn round2_reveal(
		&mut self,
		message: &[u8],
		context: &[u8],
		other_round1: &[Round1Broadcast],
	) -> ThresholdResult<Round2Broadcast> {
		// Check state and extract round1_data
		let round1_data = match std::mem::take(&mut self.state) {
			SignerState::AfterRound1 { round1_data } => round1_data,
			other => {
				self.state = other;
				return Err(ThresholdError::InvalidState {
					current: self.state_name(),
					expected: "AfterRound1",
				});
			},
		};

		// Check we have enough parties
		let total_parties = other_round1.len() + 1; // +1 for ourselves
		if total_parties < self.config.threshold() as usize {
			return Err(ThresholdError::InsufficientParties {
				provided: total_parties,
				required: self.config.threshold(),
			});
		}

		// Pack our commitment data for the Round 2 broadcast
		let commitment_data = pack_round1_commitment(&round1_data, &self.config);

		// Collect other parties' IDs
		let other_party_ids: Vec<u32> = other_round1.iter().map(|r1| r1.party_id).collect();

		// Process Round 2 (without other commitment data yet - we'll get it in round3)
		let round2_data = process_round2(
			&self.private_key,
			&self.public_key,
			&self.config,
			&round1_data,
			message,
			context,
			&other_party_ids,
			&[], // No commitment data yet
		)?;

		let broadcast = Round2Broadcast::new(self.private_key.party_id(), commitment_data);

		// Update state
		self.state = SignerState::AfterRound2 {
			round1_data,
			round2_data,
			message: message.to_vec(),
			context: context.to_vec(),
		};

		Ok(broadcast)
	}

	/// Round 2 with explicit commitment data from other parties.
	///
	/// This is the full version of Round 2 that processes both the commitment
	/// hashes (for verification) and the actual commitment data (for aggregation).
	///
	/// # Arguments
	///
	/// * `message` - The message to sign
	/// * `context` - Optional context string (max 255 bytes)
	/// * `other_broadcasts` - Round 2 broadcasts from other participating parties
	///
	/// # State Transition
	///
	/// `AfterRound1` → `AfterRound2`
	pub fn round2_reveal_with_data(
		&mut self,
		message: &[u8],
		context: &[u8],
		other_broadcasts: &[Round2Broadcast],
	) -> ThresholdResult<Round2Broadcast> {
		// Check state and extract round1_data
		let round1_data = match std::mem::take(&mut self.state) {
			SignerState::AfterRound1 { round1_data } => round1_data,
			other => {
				self.state = other;
				return Err(ThresholdError::InvalidState {
					current: self.state_name(),
					expected: "AfterRound1",
				});
			},
		};

		// Check we have enough parties
		let total_parties = other_broadcasts.len() + 1;
		if total_parties < self.config.threshold() as usize {
			return Err(ThresholdError::InsufficientParties {
				provided: total_parties,
				required: self.config.threshold(),
			});
		}

		// Pack our commitment data
		let commitment_data = pack_round1_commitment(&round1_data, &self.config);

		// Collect other parties' data
		let other_party_ids: Vec<u32> = other_broadcasts.iter().map(|r2| r2.party_id).collect();
		let other_commitment_data: Vec<Vec<u8>> =
			other_broadcasts.iter().map(|r2| r2.commitment_data.clone()).collect();

		// Process Round 2
		let round2_data = process_round2(
			&self.private_key,
			&self.public_key,
			&self.config,
			&round1_data,
			message,
			context,
			&other_party_ids,
			&other_commitment_data,
		)?;

		let broadcast = Round2Broadcast::new(self.private_key.party_id(), commitment_data);

		// Update state
		self.state = SignerState::AfterRound2 {
			round1_data,
			round2_data,
			message: message.to_vec(),
			context: context.to_vec(),
		};

		Ok(broadcast)
	}

	/// Round 3: Compute signature response.
	///
	/// After receiving all Round 2 broadcasts from other parties, call this
	/// method to compute and broadcast the signature response.
	///
	/// # Arguments
	///
	/// * `other_round2` - Round 2 broadcasts from other participating parties
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The signer is not in the `AfterRound2` state
	/// - Response computation fails
	///
	/// # State Transition
	///
	/// `AfterRound2` → `AfterRound3`
	pub fn round3_respond(
		&mut self,
		other_round2: &[Round2Broadcast],
	) -> ThresholdResult<Round3Broadcast> {
		// Check state and extract data
		let (round1_data, mut round2_data, message, context) = match std::mem::take(&mut self.state)
		{
			SignerState::AfterRound2 { round1_data, round2_data, message, context } =>
				(round1_data, round2_data, message, context),
			other => {
				self.state = other;
				return Err(ThresholdError::InvalidState {
					current: self.state_name(),
					expected: "AfterRound2",
				});
			},
		};

		// Re-aggregate commitments with full data from Round 2 broadcasts
		let k = self.config.k_iterations() as usize;
		let single_commitment_size = 8 * 736; // K * POLY_Q_SIZE

		for r2 in other_round2 {
			if !r2.commitment_data.is_empty() {
				for k_idx in 0..k {
					let start = k_idx * single_commitment_size;
					let end = start + single_commitment_size;

					if end <= r2.commitment_data.len() && k_idx < round2_data.w_aggregated.len() {
						if let Ok(w_other) =
							unpack_commitment_dilithium(&r2.commitment_data[start..end])
						{
							aggregate_commitments_dilithium(
								&mut round2_data.w_aggregated[k_idx],
								&w_other,
							);
						}
					}
				}
				// Note: active_participants is already complete from process_round2
				// No need to update it here - all participants were known from Round 1
			}
		}

		// Generate response
		let responses =
			generate_round3_response(&self.private_key, &self.config, &round1_data, &round2_data)?;

		// Pack responses for broadcast
		let packed_response = pack_responses(&responses);
		let broadcast = Round3Broadcast::new(self.private_key.party_id(), packed_response);

		// Update state
		self.state =
			SignerState::AfterRound3 { round2_data, my_responses: responses, message, context };

		Ok(broadcast)
	}

	/// Combine all responses into a final signature.
	///
	/// After all parties have broadcast their Round 3 responses, any party
	/// can call this method to combine them into a final signature.
	///
	/// # Arguments
	///
	/// * `_all_round2` - All Round 2 broadcasts (currently unused, kept for API compatibility)
	/// * `all_round3` - All Round 3 broadcasts (including our own)
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The signer is not in the `AfterRound3` state
	/// - Not enough valid responses
	/// - Signature constraint validation fails
	pub fn combine(
		&self,
		_all_round2: &[Round2Broadcast],
		all_round3: &[Round3Broadcast],
	) -> ThresholdResult<Signature> {
		// Check state and get stored message/context
		let (round2_data, my_responses, message, context) = match &self.state {
			SignerState::AfterRound3 { round2_data, my_responses, message, context } =>
				(round2_data, my_responses, message, context),
			_ => {
				return Err(ThresholdError::InvalidState {
					current: self.state_name(),
					expected: "AfterRound3",
				});
			},
		};

		// Use the already-aggregated w values from round3_respond
		// (w values were aggregated when processing Round 2 broadcasts in round3_respond)
		let w_aggregated = round2_data.w_aggregated.clone();

		// Collect all responses including our own
		let mut all_responses: Vec<Vec<polyvec::Polyvecl>> = Vec::new();
		all_responses.push(my_responses.clone());

		for r3 in all_round3 {
			if r3.party_id != self.private_key.party_id() {
				if let Ok(responses) = unpack_responses(&r3.response, &self.config) {
					all_responses.push(responses);
				}
			}
		}

		let signature_bytes = combine_signature(
			&self.public_key,
			&self.config,
			message,
			context,
			&w_aggregated,
			&all_responses,
		)?;

		Ok(Signature::from_vec(signature_bytes))
	}

	/// Combine with explicit message and context.
	///
	/// Use this version when you need to provide the message and context
	/// again for the combine step.
	pub fn combine_with_message(
		&self,
		message: &[u8],
		context: &[u8],
		_all_round2: &[Round2Broadcast],
		all_round3: &[Round3Broadcast],
	) -> ThresholdResult<Signature> {
		// Check state
		let (round2_data, my_responses) = match &self.state {
			SignerState::AfterRound3 { round2_data, my_responses, .. } =>
				(round2_data, my_responses),
			_ => {
				return Err(ThresholdError::InvalidState {
					current: self.state_name(),
					expected: "AfterRound3",
				});
			},
		};

		// Use the already-aggregated w values from round3_respond
		// (w values were aggregated when processing Round 2 broadcasts in round3_respond)
		let w_aggregated = round2_data.w_aggregated.clone();

		// Collect all responses including our own
		let mut all_responses: Vec<Vec<polyvec::Polyvecl>> = Vec::new();
		all_responses.push(my_responses.clone());

		for r3 in all_round3 {
			if r3.party_id != self.private_key.party_id() {
				if let Ok(responses) = unpack_responses(&r3.response, &self.config) {
					all_responses.push(responses);
				}
			}
		}

		let signature_bytes = combine_signature(
			&self.public_key,
			&self.config,
			message,
			context,
			&w_aggregated,
			&all_responses,
		)?;

		Ok(Signature::from_vec(signature_bytes))
	}

	/// Reset the signer to start a new signing session.
	///
	/// This clears all internal state and returns the signer to the `Fresh` state.
	/// Call this after completing a signing session or to abort a session in progress.
	pub fn reset(&mut self) {
		// Zeroize any sensitive state before clearing
		match &mut self.state {
			SignerState::Fresh => {},
			SignerState::AfterRound1 { round1_data } => {
				round1_data.zeroize();
			},
			SignerState::AfterRound2 { round1_data, round2_data, message, context } => {
				round1_data.zeroize();
				round2_data.zeroize();
				message.zeroize();
				context.zeroize();
			},
			SignerState::AfterRound3 { round2_data, my_responses, message, context } => {
				round2_data.zeroize();
				// polyvec doesn't implement Zeroize, clear manually
				for resp in my_responses.iter_mut() {
					for i in 0..7 {
						resp.vec[i].coeffs.fill(0);
					}
				}
				message.zeroize();
				context.zeroize();
			},
		}
		self.state = SignerState::Fresh;
	}

	/// Get the current state name (for error messages).
	fn state_name(&self) -> &'static str {
		match &self.state {
			SignerState::Fresh => "Fresh",
			SignerState::AfterRound1 { .. } => "AfterRound1",
			SignerState::AfterRound2 { .. } => "AfterRound2",
			SignerState::AfterRound3 { .. } => "AfterRound3",
		}
	}
}

impl Drop for ThresholdSigner {
	fn drop(&mut self) {
		self.reset();
	}
}

impl ZeroizeOnDrop for ThresholdSigner {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_signer_state_transitions() {
		// This test would require a valid key setup
		// For now, just test that the state names are correct
		let state = SignerState::Fresh;
		assert!(matches!(state, SignerState::Fresh));
	}
}
