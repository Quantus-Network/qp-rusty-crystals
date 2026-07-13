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
//! // Round 1: Generate commitment (seed must be cryptographically random)
//! let round1_seed: [u8; 32] = get_random_seed();
//! let r1 = signer.round1_commit_with_seed(&round1_seed)?;
//! // ... broadcast r1 to other parties, receive their broadcasts ...
//!
//! // Round 2: Reveal commitment
//! let r2 = signer.round2_reveal(message, context, &other_r1_broadcasts)?;
//! // ... broadcast r2 to other parties, receive their broadcasts ...
//!
//! // Round 3: Compute response (verifies commitments before aggregating)
//! let r3 = signer.round3_respond(&other_r1_broadcasts, &other_r2_broadcasts)?;
//! // ... broadcast r3 to other parties, receive their broadcasts ...
//!
//! // Combine into final signature
//! let signature = signer.combine(&all_r2_broadcasts, &all_r3_broadcasts)?;
//! ```

use alloc::{collections::BTreeSet, format, string::ToString, vec::Vec};
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
		unpack_commitment_dilithium, unpack_responses, verify_commitment_hash, Round1Data,
		Round2Data,
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

/// Current phase of the signing protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SigningPhase {
	/// Ready to start a new signing session.
	#[default]
	Fresh,
	/// Round 1 complete, holding commitment data.
	AfterRound1,
	/// Round 2 complete, ready to compute response.
	AfterRound2,
	/// Round 3 complete, signature can be combined.
	AfterRound3,
}

impl Zeroize for SigningPhase {
	fn zeroize(&mut self) {
		*self = SigningPhase::Fresh;
	}
}

/// Internal state of the signer.
///
/// Uses a flat struct with Option fields instead of an enum with associated data.
/// This design:
/// - Avoids `mem::take` which would lose data on validation errors
/// - Enables proper `ZeroizeOnDrop` - all fields are zeroized when dropped
/// - Keeps data persistent across phases until explicitly cleared
#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct SignerState {
	/// Current phase of the protocol.
	phase: SigningPhase,
	/// Round 1 data (commitment values, hyperball samples).
	round1_data: Option<Round1Data>,
	/// Round 2 data (aggregated commitments, active participants).
	round2_data: Option<Round2Data>,
	/// Message being signed.
	message: Option<Vec<u8>>,
	/// Context for the signature.
	context: Option<Vec<u8>>,
	/// Our computed responses (for Round 3).
	my_responses: Option<Vec<polyvec::Polyvecl>>,
}

impl SignerState {
	/// Verify Fresh phase (for starting round 1).
	fn expect_fresh(&self) -> ThresholdResult<()> {
		if self.phase != SigningPhase::Fresh {
			return Err(ThresholdError::InvalidState {
				current: self.phase_name(),
				expected: "Fresh",
			});
		}
		Ok(())
	}

	/// Verify AfterRound1 phase and return round1_data.
	fn expect_round1(&self) -> ThresholdResult<&Round1Data> {
		if self.phase != SigningPhase::AfterRound1 {
			return Err(ThresholdError::InvalidState {
				current: self.phase_name(),
				expected: "AfterRound1",
			});
		}
		self.round1_data.as_ref().ok_or(ThresholdError::InvalidState {
			current: self.phase_name(),
			expected: "AfterRound1",
		})
	}

	/// Verify AfterRound3 phase and return (round2_data, my_responses, message, context).
	#[allow(clippy::type_complexity)]
	fn expect_round3(&self) -> ThresholdResult<(&Round2Data, &[polyvec::Polyvecl], &[u8], &[u8])> {
		if self.phase != SigningPhase::AfterRound3 {
			return Err(ThresholdError::InvalidState {
				current: self.phase_name(),
				expected: "AfterRound3",
			});
		}
		let err =
			|| ThresholdError::InvalidState { current: self.phase_name(), expected: "AfterRound3" };
		Ok((
			self.round2_data.as_ref().ok_or_else(err)?,
			self.my_responses.as_ref().ok_or_else(err)?,
			self.message.as_ref().ok_or_else(err)?,
			self.context.as_ref().ok_or_else(err)?,
		))
	}

	/// Get the current phase name (for error messages).
	fn phase_name(&self) -> &'static str {
		match self.phase {
			SigningPhase::Fresh => "Fresh",
			SigningPhase::AfterRound1 => "AfterRound1",
			SigningPhase::AfterRound2 => "AfterRound2",
			SigningPhase::AfterRound3 => "AfterRound3",
		}
	}
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
	/// Returns an error if the private key share is not compatible with the config,
	/// or if the public key's TR does not match the private key's TR.
	pub fn new(
		private_key: PrivateKeyShare,
		public_key: PublicKey,
		config: ThresholdConfig,
	) -> ThresholdResult<Self> {
		// Validate public key TR matches private key TR.
		// This prevents "poisoned" public keys from causing commitment hash mismatches
		// during threshold signing (Round 1 uses private_key.tr(), verification uses
		// public_key.tr()).
		if public_key.tr() != private_key.tr() {
			return Err(ThresholdError::InvalidConfiguration(
				"Public key TR does not match private key TR - possible key mismatch or corrupted public key".to_string()
			));
		}

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

		Ok(Self { config, public_key, private_key, state: SignerState::default() })
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

	/// Get the DKG participants list.
	///
	/// Returns the original participant set from DKG, used to validate
	/// that signing participants are a valid subset.
	pub fn dkg_participants(&self) -> &crate::participants::ParticipantList {
		self.private_key.dkg_participants()
	}

	/// Round 1: Generate our commitment from a provided seed.
	///
	/// This is a no_std compatible version that takes a pre-generated random seed
	/// instead of an RNG. The seed MUST be cryptographically random and unique
	/// for each signing session.
	///
	/// # Arguments
	///
	/// * `seed` - A 32-byte cryptographically random seed
	///
	/// # Errors
	///
	/// Returns an error if the signer is not in the `Fresh` state.
	///
	/// # State Transition
	///
	/// `Fresh` → `AfterRound1`
	///
	/// # Security Warning
	///
	/// The seed MUST be generated from a cryptographically secure source.
	/// Reusing seeds across signing sessions will compromise security.
	pub fn round1_commit_with_seed(
		&mut self,
		ssid: &[u8; 32],
		seed: &[u8; 32],
	) -> ThresholdResult<Round1Broadcast> {
		self.state.expect_fresh()?;

		// Generate Round 1 data
		let round1_data = generate_round1(ssid, &self.private_key, &self.config, seed)?;

		let broadcast =
			Round1Broadcast::new(*ssid, self.private_key.party_id(), round1_data.commitment_hash);

		// Update state
		self.state.round1_data = Some(round1_data);
		self.state.phase = SigningPhase::AfterRound1;

		Ok(broadcast)
	}

	/// Round 2: Generate our commitment reveal.
	///
	/// After receiving all Round 1 broadcasts from other parties, call this
	/// method to produce our Round 2 broadcast.
	///
	/// # Arguments
	///
	/// * `message` - The message to sign
	/// * `context` - Optional context string (max 255 bytes)
	/// * `other_round1` - Round 1 broadcasts from other participating parties
	///
	/// # Caller Responsibility
	///
	/// **Important:** This method does not validate that Round 1 broadcasts come from
	/// parties that participated in the original DKG. The caller must ensure that
	/// `other_round1` contains only broadcasts from parties whose IDs exist in the
	/// DKG participant set (i.e., parties that hold valid key shares).
	///
	/// Passing broadcasts with unknown `party_id` values will cause `round3_respond()`
	/// to fail with an `InvalidConfiguration` error during share recovery.
	///
	/// For network usage, use
	/// [`DilithiumSignProtocol`](crate::signing_protocol::DilithiumSignProtocol) which handles
	/// participant validation automatically.
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
		ssid: &[u8; 32],
		message: &[u8],
		context: &[u8],
		other_round1: &[Round1Broadcast],
	) -> ThresholdResult<Round2Broadcast> {
		// Validate inputs first (before state check to give better errors)
		// The scheme requires EXACTLY threshold parties (not more, not fewer).
		// See signing_protocol.rs documentation for details.
		let total_parties = other_round1.len() + 1; // +1 for ourselves
		let threshold = self.config.threshold() as usize;
		if total_parties != threshold {
			return Err(ThresholdError::WrongPartyCount {
				provided: total_parties,
				required: self.config.threshold(),
			});
		}

		// Check state and get round1_data
		let round1_data = self.state.expect_round1()?;

		// Pack our commitment data for the Round 2 broadcast
		let commitment_data = pack_round1_commitment(round1_data, &self.config);

		// Collect other parties' IDs
		let other_party_ids: Vec<u32> = other_round1.iter().map(|r1| r1.party_id).collect();

		// Process Round 2 - sets up our own commitments
		let round2_data = process_round2(
			&self.private_key,
			&self.public_key,
			&self.config,
			round1_data,
			message,
			context,
			&other_party_ids,
		)?;

		let broadcast = Round2Broadcast::new(*ssid, self.private_key.party_id(), commitment_data);

		// Update state
		self.state.round2_data = Some(round2_data);
		self.state.message = Some(message.to_vec());
		self.state.context = Some(context.to_vec());
		self.state.phase = SigningPhase::AfterRound2;

		Ok(broadcast)
	}

	/// Round 3: Compute signature response.
	///
	/// After receiving all Round 1 and Round 2 broadcasts from other parties, call this
	/// method to verify commitments and compute the signature response.
	///
	/// # Arguments
	///
	/// * `other_round1` - Round 1 broadcasts from other parties (for commitment verification)
	/// * `other_round2` - Round 2 broadcasts from other participating parties
	///
	/// # Caller Responsibility
	///
	/// **Important:** This method does not validate that broadcasts come from parties
	/// that participated in the original DKG. The caller must ensure that all broadcasts
	/// are from parties whose IDs exist in the DKG participant set.
	///
	/// Broadcasts with unknown `party_id` values will cause share recovery to fail
	/// with an `InvalidConfiguration` error.
	///
	/// For network usage, use
	/// [`DilithiumSignProtocol`](crate::signing_protocol::DilithiumSignProtocol) which handles
	/// participant validation automatically.
	///
	/// # Security
	///
	/// This function verifies that each party's Round 2 commitment data matches their
	/// Round 1 commitment hash BEFORE aggregating. This prevents rushing adversary attacks.
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The signer is not in the `AfterRound2` state
	/// - Response computation fails
	/// - Any party's commitment verification fails
	/// - Any party ID is not in the DKG participant set
	///
	/// # State Transition
	///
	/// `AfterRound2` → `AfterRound3`
	pub fn round3_respond(
		&mut self,
		ssid: &[u8; 32],
		other_round1: &[Round1Broadcast],
		other_round2: &[Round2Broadcast],
	) -> ThresholdResult<Round3Broadcast> {
		// Validate inputs first (before state mutation)
		let k = self.config.k_iterations() as usize;
		let single_commitment_size = 8 * 736; // K * POLY_Q_SIZE
		let expected_len = k * single_commitment_size;

		// Reject duplicate reveals up front: replaying one party's Round 2 broadcast
		// must never be counted twice, or the aggregate (and thus the challenge
		// material for the response) would be silently corrupted.
		let mut seen_parties: BTreeSet<u32> = BTreeSet::new();

		for r2 in other_round2 {
			if !seen_parties.insert(r2.party_id) {
				return Err(ThresholdError::DuplicateBroadcast { party_id: r2.party_id });
			}

			// Empty commitment_data is NOT allowed - every participant must contribute.
			// Allowing empty data would let an attacker bypass commitment binding.
			if r2.commitment_data.is_empty() {
				return Err(ThresholdError::InvalidCommitmentData {
					party_id: r2.party_id,
					reason:
						"Empty commitment data is not allowed - every participant must contribute"
							.to_string(),
				});
			}

			// Find matching Round 1 broadcast
			let r1 = other_round1
				.iter()
				.find(|r1| r1.party_id == r2.party_id)
				.ok_or(ThresholdError::MissingBroadcast { party_id: r2.party_id })?;

			// Verify commitment hash (using SSID instead of tr)
			if !verify_commitment_hash(ssid, r2.party_id, &r2.commitment_data, &r1.commitment_hash)
			{
				return Err(ThresholdError::CommitmentMismatch {
					party_id: r2.party_id,
					message: "Round 2 commitment data does not match Round 1 commitment hash"
						.to_string(),
				});
			}

			// Validate data length
			if r2.commitment_data.len() != expected_len {
				return Err(ThresholdError::InvalidCommitmentData {
					party_id: r2.party_id,
					reason: format!(
						"Commitment data length {} does not match expected {} for k={}",
						r2.commitment_data.len(),
						expected_len,
						k
					),
				});
			}
		}

		// Check state
		if self.state.phase != SigningPhase::AfterRound2 {
			return Err(ThresholdError::InvalidState {
				current: self.state.phase_name(),
				expected: "AfterRound2",
			});
		}

		// Aggregate commitments without mutating persistent state until every reveal
		// is validated and unpacked. Two properties are enforced here:
		//
		// 1. The reveal set must be *exactly* the participants recorded during Round 2
		//    — no missing, no extra, no duplicate parties. Duplicates were rejected
		//    above; combined with the exact-count and all-expected-present checks
		//    below, this pins the reveal set to the session set (an unexpected party
		//    would force either a duplicate or a missing expected party).
		// 2. Every reveal is fully validated *before* the first write to persistent
		//    state (validate-then-commit). A malformed-but-hash-bound reveal therefore
		//    leaves `w_aggregated` untouched, so the signer stays in a clean
		//    AfterRound2 state that a corrected retry can aggregate exactly once
		//    (rather than double-counting earlier reveals).
		{
			let me = self.private_key.party_id();
			let round2_data =
				self.state.round2_data.as_mut().ok_or(ThresholdError::InvalidState {
					current: "AfterRound2", // phase already validated above
					expected: "AfterRound2",
				})?;

			// Exactly one reveal per other participant recorded at Round 2.
			let expected_others = round2_data.active_participants.len().saturating_sub(1);
			if other_round2.len() != expected_others {
				return Err(ThresholdError::WrongPartyCount {
					provided: other_round2.len() + 1,
					required: round2_data.active_participants.len() as u32,
				});
			}
			for other in round2_data.active_participants.others(me) {
				if !seen_parties.contains(&other) {
					return Err(ThresholdError::MissingBroadcast { party_id: other });
				}
			}

			// Pass 1 (validate): unpack every chunk of every reveal, holding at most
			// one transient Polyveck at a time. No persistent state is touched, so a
			// failure here is a clean rejection. This deliberately avoids cloning the
			// whole existing aggregate as a scratch buffer: for large k_iterations
			// (e.g. k=1600 for 4-of-6) that clone roughly doubled peak memory during
			// Round 3 (tens of MB), whereas re-unpacking in the commit pass below
			// costs only a second run of cheap bit-unpacking.
			for r2 in other_round2 {
				for k_idx in 0..k {
					let start = k_idx * single_commitment_size;
					let end = start + single_commitment_size;

					unpack_commitment_dilithium(&r2.commitment_data[start..end]).map_err(
						|e| ThresholdError::InvalidCommitmentData {
							party_id: r2.party_id,
							reason: format!(
								"Commitment passed hash check but failed to unpack (k={}): {}",
								k_idx, e
							),
						},
					)?;
				}
			}

			// Pass 2 (commit): aggregate directly into persistent state, in place.
			// Unpacking is deterministic over the same bytes, so after pass 1
			// succeeded it cannot fail here. A failure would indicate a logic bug;
			// rather than panicking, it is handled defensively below.
			let mut commit_failed = false;
			'commit: for r2 in other_round2 {
				for (k_idx, agg) in round2_data.w_aggregated.iter_mut().take(k).enumerate() {
					let start = k_idx * single_commitment_size;
					let end = start + single_commitment_size;

					match unpack_commitment_dilithium(&r2.commitment_data[start..end]) {
						Ok(w_other) => aggregate_commitments_dilithium(agg, &w_other),
						Err(_) => {
							commit_failed = true;
							break 'commit;
						},
					}
				}
			}
			if commit_failed {
				// Defensive, believed unreachable: the same bytes unpacked
				// successfully in pass 1. The aggregate may now be partially
				// mutated, so returning an error alone would let a retry
				// double-aggregate the committed reveals. Reset the signing
				// session instead: the caller must restart from Round 1, which
				// re-derives a clean aggregate.
				self.state = SignerState::default();
				return Err(ThresholdError::InvalidData(
					"Round 3 aggregation failed after validation (logic bug); \
					 signing session reset — restart from Round 1"
						.to_string(),
				));
			}
		}

		// Get immutable references for response generation
		let round1_data = self.state.round1_data.as_ref().ok_or(ThresholdError::InvalidState {
			current: "AfterRound2", // phase already validated above
			expected: "AfterRound2",
		})?;
		let round2_data = self.state.round2_data.as_ref().ok_or(ThresholdError::InvalidState {
			current: "AfterRound2", // phase already validated above
			expected: "AfterRound2",
		})?;

		// Generate response
		let responses =
			generate_round3_response(&self.private_key, &self.config, round1_data, round2_data)?;

		// Pack responses for broadcast
		let packed_response = pack_responses(&responses);
		let broadcast = Round3Broadcast::new(*ssid, self.private_key.party_id(), packed_response);

		// Update state - clear round1_data as it's no longer needed
		// (dropping the Option zeroizes its contents via ZeroizeOnDrop).
		self.state.my_responses = Some(responses);
		self.state.round1_data = None;
		self.state.phase = SigningPhase::AfterRound3;

		Ok(broadcast)
	}

	/// Collect all Round 3 responses with duplicate detection.
	///
	/// This helper extracts the shared logic between `combine` and `combine_with_message`.
	///
	/// # Note
	///
	/// This method accepts any `party_id` in the broadcasts and does not validate
	/// participant membership. The caller is responsible for filtering broadcasts
	/// to include only authorized participants before calling `combine()`.
	fn collect_responses(
		&self,
		my_responses: &[polyvec::Polyvecl],
		all_round3: &[Round3Broadcast],
	) -> ThresholdResult<Vec<Vec<polyvec::Polyvecl>>> {
		let mut all_responses: Vec<Vec<polyvec::Polyvecl>> = Vec::new();
		let mut seen_parties: BTreeSet<u32> = BTreeSet::new();

		// Add our own response first
		all_responses.push(my_responses.to_vec());
		seen_parties.insert(self.private_key.party_id());

		for r3 in all_round3 {
			if r3.party_id == self.private_key.party_id() {
				continue; // Skip our own
			}

			// Check for duplicates (M3: duplicate Round 3 should error, not silently overwrite)
			if !seen_parties.insert(r3.party_id) {
				return Err(ThresholdError::DuplicateBroadcast { party_id: r3.party_id });
			}

			let responses = unpack_responses(&r3.response, &self.config).map_err(|e| {
				ThresholdError::InvalidSignatureShareData {
					party_id: r3.party_id,
					reason: format!("Failed to unpack Round 3 response: {}", e),
				}
			})?;
			all_responses.push(responses);
		}

		Ok(all_responses)
	}

	/// Combine all responses into a final signature.
	///
	/// After all parties have broadcast their Round 3 responses, any party
	/// can call this method to combine them into a final signature.
	///
	/// # Arguments
	///
	/// * `ssid` - Session identifier for this signing session
	/// * `_all_round2` - All Round 2 broadcasts (currently unused, kept for API compatibility)
	/// * `all_round3` - All Round 3 broadcasts from participating parties
	///
	/// # Caller Responsibility
	///
	/// **Important:** This method does not validate that Round 3 broadcasts come from
	/// authorized participants. The caller must ensure that `all_round3` contains only
	/// broadcasts from parties that:
	/// 1. Are part of the agreed signing set
	/// 2. Participated in Round 1 and Round 2
	///
	/// For network usage, use
	/// [`DilithiumSignProtocol`](crate::signing_protocol::DilithiumSignProtocol) which handles
	/// participant validation automatically.
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The signer is not in the `AfterRound3` state
	/// - Not enough valid responses
	/// - Signature constraint validation fails
	/// - Duplicate Round 3 broadcast from same party
	pub fn combine(
		&self,
		_all_round2: &[Round2Broadcast],
		all_round3: &[Round3Broadcast],
	) -> ThresholdResult<Signature> {
		let (round2_data, my_responses, message, context) = self.state.expect_round3()?;

		let all_responses = self.collect_responses(my_responses, all_round3)?;

		let signature_bytes = combine_signature(
			&self.public_key,
			&self.config,
			message,
			context,
			&round2_data.w_aggregated,
			&all_responses,
		)?;

		Ok(Signature::from_vec(signature_bytes))
	}

	/// Combine with explicit message and context.
	///
	/// Use this version when you need to provide the message and context
	/// again for the combine step.
	///
	/// # Arguments
	///
	/// * `message` - The message that was signed
	/// * `context` - The context string used during signing
	/// * `_all_round2` - All Round 2 broadcasts (currently unused, kept for API compatibility)
	/// * `all_round3` - All Round 3 broadcasts from participating parties
	///
	/// # Caller Responsibility
	///
	/// **Important:** This method does not validate that Round 3 broadcasts come from
	/// authorized participants. The caller must ensure that `all_round3` contains only
	/// broadcasts from parties that are part of the agreed signing set.
	///
	/// For network usage, use
	/// [`DilithiumSignProtocol`](crate::signing_protocol::DilithiumSignProtocol) which handles
	/// participant validation automatically.
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - The signer is not in the `AfterRound3` state
	/// - Not enough valid responses
	/// - Signature constraint validation fails
	/// - Duplicate Round 3 broadcast from same party
	pub fn combine_with_message(
		&self,
		message: &[u8],
		context: &[u8],
		_all_round2: &[Round2Broadcast],
		all_round3: &[Round3Broadcast],
	) -> ThresholdResult<Signature> {
		let (round2_data, my_responses, bound_message, bound_context) =
			self.state.expect_round3()?;

		// Round 3 responses are bound to the message/context captured in Round 2.
		// Combining against anything else would silently yield an invalid signature,
		// so reject the mismatch instead of proceeding.
		if message != bound_message || context != bound_context {
			return Err(ThresholdError::InvalidData(
				"combine_with_message message/context does not match the values bound in round 2"
					.to_string(),
			));
		}

		let all_responses = self.collect_responses(my_responses, all_round3)?;

		let signature_bytes = combine_signature(
			&self.public_key,
			&self.config,
			bound_message,
			bound_context,
			&round2_data.w_aggregated,
			&all_responses,
		)?;

		Ok(Signature::from_vec(signature_bytes))
	}
}

// `state` (SignerState) and `private_key` (PrivateKeyShare) both implement
// ZeroizeOnDrop, so their secret material is zeroized via field-by-field drop.
impl ZeroizeOnDrop for ThresholdSigner {}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::participants::ParticipantList;

	#[test]
	fn test_signer_state_transitions() {
		// This test would require a valid key setup
		// For now, just test that the phase names are correct
		let state = SignerState::default();
		assert!(matches!(state.phase, SigningPhase::Fresh));
	}

	#[test]
	fn test_signer_rejects_mismatched_public_key_tr() {
		use crate::keys::{PrivateKeyShare, PublicKey, PUBLIC_KEY_SIZE, TR_SIZE};
		use alloc::collections::BTreeMap;

		// Create a private key share with a specific TR
		let private_tr = [0x42u8; TR_SIZE];
		let dkg_participants = ParticipantList::new(&[0, 1, 2]).unwrap();
		let private_key = PrivateKeyShare::new(
			0,         // party_id
			3,         // total_parties
			2,         // threshold
			[0u8; 32], // key
			[0u8; 32], // rho
			private_tr,
			BTreeMap::new(), // shares (empty is fine for this test)
			dkg_participants,
		);

		// Create a public key - from_bytes computes TR = SHAKE256(bytes),
		// which will NOT match our private key's TR (0x42 repeated)
		let pk_bytes = [0u8; PUBLIC_KEY_SIZE];
		let public_key = PublicKey::from_bytes(&pk_bytes).unwrap();

		// The public key's TR is SHAKE256([0u8; PUBLIC_KEY_SIZE]), not [0x42; TR_SIZE]
		assert_ne!(public_key.tr(), &private_tr);

		// ThresholdSigner::new should reject this mismatched key pair
		let config = ThresholdConfig::new(2, 3).unwrap();
		let result = ThresholdSigner::new(private_key, public_key, config);

		match result {
			Err(ThresholdError::InvalidConfiguration(msg)) => {
				assert!(msg.contains("TR"), "Error should mention TR mismatch, got: {}", msg);
			},
			Err(e) => panic!("Expected InvalidConfiguration error, got: {:?}", e),
			Ok(_) => panic!("Should reject public key with TR not matching private key TR"),
		}
	}

	/// The direct signer must enforce the ML-DSA `MAX_MESSAGE_SIZE` bound before
	/// hashing/cloning the message, matching the higher-level
	/// `DilithiumSignProtocol` guard. Without the check, `round2_reveal` would
	/// hash an oversized buffer and retain it in state to produce a signature
	/// that verification then rejects.
	#[test]
	fn test_round2_reveal_rejects_oversized_message() {
		use qp_rusty_crystals_dilithium::ml_dsa_87::MAX_MESSAGE_SIZE;

		use crate::generate_with_dealer;

		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[7u8; 32], config).unwrap();

		let mut s0 = ThresholdSigner::new(shares[0].clone(), pk.clone(), config).unwrap();
		let mut s1 = ThresholdSigner::new(shares[1].clone(), pk.clone(), config).unwrap();

		let ssid = [0u8; 32];
		let _r1_0 = s0.round1_commit_with_seed(&ssid, &[1u8; 32]).unwrap();
		let r1_1 = s1.round1_commit_with_seed(&ssid, &[2u8; 32]).unwrap();

		// One byte over the ML-DSA limit: rejected before any expensive work.
		let oversized = alloc::vec![0u8; MAX_MESSAGE_SIZE + 1];
		let err = s0
			.round2_reveal(&ssid, &oversized, b"", core::slice::from_ref(&r1_1))
			.expect_err("oversized message must be rejected");
		assert!(
			matches!(err, ThresholdError::MessageTooLong { length } if length == MAX_MESSAGE_SIZE + 1),
			"expected MessageTooLong, got {err:?}"
		);

		// A normal-sized message is still accepted (state advances to Round 2).
		let ok = s0.round2_reveal(&ssid, b"hello", b"", core::slice::from_ref(&r1_1));
		assert!(ok.is_ok(), "in-bounds message must still be accepted: {ok:?}");
	}

	/// Regression test for the validate-then-commit property of
	/// `round3_respond` (preserved across the removal of the full aggregate
	/// clone): a reveal that passes the commitment-hash check but fails to
	/// unpack must be rejected *without* mutating `w_aggregated`, so a
	/// corrected retry produces exactly the same response as a signer that
	/// never saw the malformed attempt.
	#[test]
	fn test_round3_malformed_reveal_leaves_state_clean_for_retry() {
		use crate::{
			broadcast::{Round1Broadcast, Round2Broadcast},
			generate_with_dealer,
			protocol::signing::compute_commitment_hash,
		};

		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[9u8; 32], config).unwrap();

		let mut s0 = ThresholdSigner::new(shares[0].clone(), pk.clone(), config).unwrap();
		let mut s1 = ThresholdSigner::new(shares[1].clone(), pk.clone(), config).unwrap();
		// Control signer: identical to s0 (same share, same seeds) but never
		// fed the malformed reveal.
		let mut c0 = ThresholdSigner::new(shares[0].clone(), pk.clone(), config).unwrap();

		let ssid = [0x5Au8; 32];
		let r1_0 = s0.round1_commit_with_seed(&ssid, &[1u8; 32]).unwrap();
		let r1_1 = s1.round1_commit_with_seed(&ssid, &[2u8; 32]).unwrap();
		let r1_c = c0.round1_commit_with_seed(&ssid, &[1u8; 32]).unwrap();
		assert_eq!(r1_0, r1_c, "control signer must mirror s0 exactly");

		let msg = b"atomicity";
		let ctx = b"";
		s0.round2_reveal(&ssid, msg, ctx, core::slice::from_ref(&r1_1)).unwrap();
		c0.round2_reveal(&ssid, msg, ctx, core::slice::from_ref(&r1_1)).unwrap();
		let r2_1 = s1.round2_reveal(&ssid, msg, ctx, core::slice::from_ref(&r1_0)).unwrap();

		// Forge a malformed-but-hash-bound reveal from party 1: correct length,
		// bound to a matching (forged) Round 1 hash, but every 23-bit
		// coefficient is 2^23 - 1 >= Q, so unpacking fails.
		let k = config.k_iterations() as usize;
		let garbage = alloc::vec![0xFFu8; k * 8 * 736];
		let forged_hash = compute_commitment_hash(&ssid, 1, &garbage);
		let fake_r1 = Round1Broadcast::new(ssid, 1, forged_hash);
		let fake_r2 = Round2Broadcast::new(ssid, 1, garbage);

		let err = s0
			.round3_respond(&ssid, core::slice::from_ref(&fake_r1), core::slice::from_ref(&fake_r2))
			.expect_err("hash-bound but malformed reveal must be rejected");
		assert!(
			matches!(err, ThresholdError::InvalidCommitmentData { party_id: 1, .. }),
			"expected InvalidCommitmentData for party 1, got {err:?}"
		);

		// The corrected retry must succeed and match the control signer's
		// response byte-for-byte: any residue from the failed attempt (e.g. a
		// partially-applied aggregate) would change the challenge material.
		let r3_retry = s0
			.round3_respond(&ssid, core::slice::from_ref(&r1_1), core::slice::from_ref(&r2_1))
			.expect("corrected retry must succeed after a rejected reveal");
		let r3_control = c0
			.round3_respond(&ssid, core::slice::from_ref(&r1_1), core::slice::from_ref(&r2_1))
			.expect("control signer round 3");
		assert_eq!(
			r3_retry, r3_control,
			"retry after rejected reveal must match a signer that never saw it"
		);
	}
}
