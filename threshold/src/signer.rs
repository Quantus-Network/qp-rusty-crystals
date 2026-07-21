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

use alloc::{
	collections::{BTreeMap, BTreeSet},
	format,
	string::ToString,
	vec::Vec,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use qp_rusty_crystals_dilithium::polyvec;

use crate::{
	broadcast::{Round1Broadcast, Round2Broadcast, Round3Broadcast, Signature},
	config::ThresholdConfig,
	error::{ThresholdError, ThresholdResult},
	keys::{PrivateKeyShare, PublicKey},
	participants::ParticipantId,
	protocol::signing::{
		aggregate_commitments_dilithium, combine_signature, generate_round1,
		generate_round3_response, pack_responses, pack_round1_commitment, process_round2,
		unpack_commitment_dilithium, unpack_responses, verify_commitment_hash, Round1Data,
		Round2Data,
	},
};

/// Packed size in bytes of one commitment (one `Polyveck` of K polynomials,
/// 736 bytes each in the 23-bit encoding). Round 2 commitment data is
/// `k_iterations` of these, concatenated.
pub(crate) const SINGLE_COMMITMENT_SIZE: usize = 8 * 736; // K * POLY_Q_SIZE

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

	/// Verify AfterRound2 phase and return (round1_data, round2_data).
	fn expect_round2(&self) -> ThresholdResult<(&Round1Data, &Round2Data)> {
		if self.phase != SigningPhase::AfterRound2 {
			return Err(ThresholdError::InvalidState {
				current: self.phase_name(),
				expected: "AfterRound2",
			});
		}
		let err =
			|| ThresholdError::InvalidState { current: self.phase_name(), expected: "AfterRound2" };
		Ok((self.round1_data.as_ref().ok_or_else(err)?, self.round2_data.as_ref().ok_or_else(err)?))
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

		// Cross-field consistency of the share itself. Borsh import enforces
		// the same invariants, but the signer is the last construction
		// boundary before the state machine trusts this metadata: without
		// these checks a malformed share runs rounds 1-2 and fails only at
		// Round 3 share recovery - a late error for a missing party_id, or an
		// out-of-bounds panic in translated_subset_masks when
		// dkg_participants outnumber total_parties.
		if private_key.dkg_participants().len() != private_key.total_parties() as usize {
			return Err(ThresholdError::InvalidConfiguration(format!(
				"Private key dkg_participants length ({}) does not match its total parties ({})",
				private_key.dkg_participants().len(),
				private_key.total_parties()
			)));
		}
		if private_key.dkg_index().is_none() {
			return Err(ThresholdError::InvalidConfiguration(format!(
				"Private key party_id ({}) is not in its dkg_participants list",
				private_key.party_id()
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
		// Validate inputs first (before state check to give better errors).
		//
		// The ML-DSA message/context bounds must be enforced *before*
		// `pack_round1_commitment` below: packing allocates and serializes
		// k_iterations * SINGLE_COMMITMENT_SIZE bytes (~9.4 MB for 4-of-6),
		// and a request that can never yield a verifiable signature must not
		// be able to force that work. `process_round2` re-checks these bounds
		// as defense in depth.
		crate::error::validate_message(message)?;
		crate::error::validate_context(context)?;

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
		let mut round2_data = process_round2(
			&self.private_key,
			&self.public_key,
			&self.config,
			round1_data,
			message,
			context,
			&other_party_ids,
		)?;

		// Freeze the peers' Round 1 commitment hashes now, at the moment we
		// reveal our own Round 2 commitment. Round 3 verifies reveals against
		// this map instead of a caller-supplied Round 1 set, so a peer cannot
		// substitute a Round 1 hash chosen after observing honest reveals
		// (the commit-reveal anti-rushing property). A duplicate peer party ID
		// is already rejected while building `active_participants` above.
		round2_data.round1_commitments =
			other_round1.iter().map(|r1| (r1.party_id, r1.commitment_hash)).collect();

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
		let k = self.config.k_iterations() as usize;

		// The peers' Round 1 commitment hashes were frozen when we revealed our
		// own Round 2 commitment (see `round2_reveal`). Verifying reveals
		// against that stored map — rather than the caller-supplied
		// `other_round1` — is what preserves the commit-reveal anti-rushing
		// property: a peer cannot substitute a Round 1 hash chosen after
		// observing honest reveals. This requires AfterRound2, so grab the
		// frozen map first.
		if self.state.phase != SigningPhase::AfterRound2 {
			return Err(ThresholdError::InvalidState {
				current: self.state.phase_name(),
				expected: "AfterRound2",
			});
		}
		let stored_commitments = {
			let round2_data =
				self.state.round2_data.as_ref().ok_or(ThresholdError::InvalidState {
					current: "AfterRound2", // phase already validated above
					expected: "AfterRound2",
				})?;
			round2_data.round1_commitments.clone()
		};

		// Validate all reveals against the frozen Round 1 commitments before
		// touching any state (duplicates, sizes, hash binding).
		let seen_parties = Self::validate_reveals_against_commitments(
			ssid,
			&stored_commitments,
			other_round1,
			other_round2,
			k,
		)?;

		// Aggregate commitments without mutating persistent state until every reveal
		// is validated and unpacked. Two properties are enforced here:
		//
		// 1. The reveal set must be *exactly* the participants recorded during Round 2 — no
		//    missing, no extra, no duplicate parties (see `check_reveal_set_exact`).
		// 2. Every reveal is fully validated *before* the first write to persistent state
		//    (validate-then-commit; see `validate_reveals_unpack` / `aggregate_reveals`). A
		//    malformed-but-hash-bound reveal therefore leaves `w_aggregated` untouched, so the
		//    signer stays in a clean AfterRound2 state that a corrected retry can aggregate exactly
		//    once (rather than double-counting earlier reveals).
		{
			let me = self.private_key.party_id();
			let round2_data =
				self.state.round2_data.as_mut().ok_or(ThresholdError::InvalidState {
					current: "AfterRound2", // phase already validated above
					expected: "AfterRound2",
				})?;

			Self::check_reveal_set_exact(round2_data, me, other_round2, &seen_parties)?;
			Self::validate_reveals_unpack(other_round2, k)?;

			if Self::aggregate_reveals(round2_data, other_round2, k).is_err() {
				// Defensive, believed unreachable: the same bytes unpacked
				// successfully in `validate_reveals_unpack`. The aggregate may now
				// be partially mutated, so returning an error alone would let a
				// retry double-aggregate the committed reveals. Reset the signing
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

		// Generate the response from the committed aggregate.
		let (round1_data, round2_data) = self.state.expect_round2()?;
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

	/// Validate Round 2 reveals against the Round 1 commitment hashes that were
	/// frozen during `round2_reveal`: reject duplicate reveals, empty or
	/// mis-sized commitment data, reveals from a party we recorded no Round 1
	/// commitment for, and reveals whose data does not hash to the frozen
	/// Round 1 commitment. Touches no state; returns the set of revealing
	/// party IDs for the exact-set check.
	///
	/// `stored_commitments` is the authoritative source (captured before this
	/// party revealed its own commitment). The caller-supplied `other_round1`
	/// is accepted only as defense in depth: if it carries a Round 1 hash for a
	/// revealing party, that hash must equal the frozen one, otherwise the
	/// caller is attempting to substitute a post-hoc commitment and the reveal
	/// is rejected. This is what stops a rushing peer from choosing its
	/// commitment after seeing honest reveals.
	///
	/// Rejecting duplicates up front matters because replaying one party's
	/// Round 2 broadcast must never be counted twice, or the aggregate (and
	/// thus the challenge material for the response) would be silently
	/// corrupted.
	fn validate_reveals_against_commitments(
		ssid: &[u8; 32],
		stored_commitments: &BTreeMap<ParticipantId, [u8; 32]>,
		other_round1: &[Round1Broadcast],
		other_round2: &[Round2Broadcast],
		k: usize,
	) -> ThresholdResult<BTreeSet<u32>> {
		let expected_len = k * SINGLE_COMMITMENT_SIZE;
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

			// The Round 1 hash frozen during round2_reveal is authoritative.
			// A reveal from a party we recorded no Round 1 commitment for
			// cannot be bound and is rejected.
			let committed_hash = stored_commitments
				.get(&r2.party_id)
				.ok_or(ThresholdError::MissingBroadcast { party_id: r2.party_id })?;

			// Defense in depth: a Round 1 broadcast supplied to Round 3 for a
			// revealing party must agree with the frozen hash. A mismatch is a
			// rushing attempt (a commitment hash chosen after observing honest
			// reveals) and is rejected outright.
			if let Some(supplied) = other_round1.iter().find(|r1| r1.party_id == r2.party_id) {
				if &supplied.commitment_hash != committed_hash {
					return Err(ThresholdError::CommitmentMismatch {
						party_id: r2.party_id,
						message: "Round 1 commitment hash supplied to round 3 does not match \
						          the hash committed during round 2"
							.to_string(),
					});
				}
			}

			// Verify commitment hash against the frozen Round 1 hash (using
			// SSID instead of tr).
			if !verify_commitment_hash(ssid, r2.party_id, &r2.commitment_data, committed_hash) {
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

		Ok(seen_parties)
	}

	/// Check that the reveal set is *exactly* the other participants recorded
	/// during Round 2 — no missing, no extra. Duplicates were already rejected
	/// while building `seen_parties`; combined with the exact-count and
	/// all-expected-present checks here, this pins the reveal set to the
	/// session set (an unexpected party would force either a duplicate or a
	/// missing expected party).
	fn check_reveal_set_exact(
		round2_data: &Round2Data,
		me: u32,
		other_round2: &[Round2Broadcast],
		seen_parties: &BTreeSet<u32>,
	) -> ThresholdResult<()> {
		let expected_others = round2_data.active_participants.len().saturating_sub(1);
		if other_round2.len() != expected_others {
			return Err(ThresholdError::RevealSetMismatch {
				provided: other_round2.len() + 1,
				expected: round2_data.active_participants.len() as u32,
			});
		}
		for other in round2_data.active_participants.others(me) {
			if !seen_parties.contains(&other) {
				return Err(ThresholdError::MissingBroadcast { party_id: other });
			}
		}
		Ok(())
	}

	/// Validation pass of the aggregation: unpack every chunk of every reveal,
	/// holding at most one transient `Polyveck` at a time, and discard the
	/// results. No persistent state is touched, so a failure here is a clean
	/// rejection.
	///
	/// This deliberately avoids cloning the whole existing aggregate as a
	/// scratch buffer: for large k_iterations (e.g. k=1600 for 4-of-6) that
	/// clone roughly doubled peak memory during Round 3 (tens of MB), whereas
	/// re-unpacking in [`Self::aggregate_reveals`] costs only a second run of
	/// cheap bit-unpacking.
	fn validate_reveals_unpack(other_round2: &[Round2Broadcast], k: usize) -> ThresholdResult<()> {
		for r2 in other_round2 {
			for k_idx in 0..k {
				let start = k_idx * SINGLE_COMMITMENT_SIZE;
				let end = start + SINGLE_COMMITMENT_SIZE;

				unpack_commitment_dilithium(&r2.commitment_data[start..end]).map_err(|e| {
					ThresholdError::InvalidCommitmentData {
						party_id: r2.party_id,
						reason: format!(
							"Commitment passed hash check but failed to unpack (k={}): {}",
							k_idx, e
						),
					}
				})?;
			}
		}
		Ok(())
	}

	/// Commit pass of the aggregation: aggregate every reveal directly into
	/// `round2_data.w_aggregated`, in place. Unpacking is deterministic over
	/// the same bytes, so after [`Self::validate_reveals_unpack`] succeeded
	/// this cannot fail. `Err` indicates a logic bug and means the aggregate
	/// may be partially mutated — the caller must poison the session rather
	/// than allow a retry.
	fn aggregate_reveals(
		round2_data: &mut Round2Data,
		other_round2: &[Round2Broadcast],
		k: usize,
	) -> Result<(), ()> {
		for r2 in other_round2 {
			for (k_idx, agg) in round2_data.w_aggregated.iter_mut().take(k).enumerate() {
				let start = k_idx * SINGLE_COMMITMENT_SIZE;
				let end = start + SINGLE_COMMITMENT_SIZE;

				match unpack_commitment_dilithium(&r2.commitment_data[start..end]) {
					Ok(w_other) => aggregate_commitments_dilithium(agg, &w_other),
					Err(_) => return Err(()),
				}
			}
		}
		Ok(())
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
		all_round2: &[Round2Broadcast],
		all_round3: &[Round3Broadcast],
	) -> ThresholdResult<Signature> {
		let (_, _, bound_message, bound_context) = self.state.expect_round3()?;

		// Round 3 responses are bound to the message/context captured in Round 2.
		// Combining against anything else would silently yield an invalid signature,
		// so reject the mismatch instead of proceeding.
		if message != bound_message || context != bound_context {
			return Err(ThresholdError::InvalidData(
				"combine_with_message message/context does not match the values bound in round 2"
					.to_string(),
			));
		}

		// Identical to `combine` once the binding check has passed.
		self.combine(all_round2, all_round3)
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
		// which will NOT match our private key's TR (0x42 repeated). The
		// bytes must have a nonzero t1 region to pass import validation.
		let pk_bytes = [0x37u8; PUBLIC_KEY_SIZE];
		let public_key = PublicKey::from_bytes(&pk_bytes).unwrap();

		// The public key's TR is SHAKE256(pk_bytes), not [0x42; TR_SIZE]
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

	/// Security review: `ThresholdSigner::new` is the construction boundary
	/// for locally supplied share material, so it must reject shares whose
	/// metadata is not mutually consistent rather than let the signing state
	/// machine run rounds 1-2 and fail (or panic out-of-bounds in
	/// `translated_subset_masks`) only at Round 3 share recovery.
	#[test]
	fn test_signer_rejects_share_with_inconsistent_metadata() {
		use crate::{generate_with_dealer, keys::PrivateKeyShare};

		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[9u8; 32], config).unwrap();
		let good = &shares[0];

		// party_id missing from dkg_participants: passes the TR and threshold
		// checks, then Round 3 recovery would fail late with
		// "Party not found in DKG participants".
		let tampered = PrivateKeyShare::new(
			99,
			good.total_parties(),
			good.threshold(),
			[0u8; 32],
			*good.rho(),
			*good.tr(),
			good.shares().clone(),
			good.dkg_participants().clone(),
		);
		assert!(
			ThresholdSigner::new(tampered, pk.clone(), config).is_err(),
			"signer must reject a share whose party_id is not in dkg_participants"
		);

		// dkg_participants larger than the claimed total_parties: signing-set
		// masks built over dkg indices can then exceed the participant count,
		// which panics in translated_subset_masks instead of erroring.
		let config22 = ThresholdConfig::new(2, 2).unwrap();
		let (pk22, shares22) = generate_with_dealer(&[10u8; 32], config22).unwrap();
		let good22 = &shares22[0];
		let oversized_list = ParticipantList::new(&[0, 1, 2]).unwrap();
		let tampered = PrivateKeyShare::new(
			good22.party_id(),
			good22.total_parties(),
			good22.threshold(),
			[0u8; 32],
			*good22.rho(),
			*good22.tr(),
			good22.shares().clone(),
			oversized_list,
		);
		assert!(
			ThresholdSigner::new(tampered, pk22.clone(), config22).is_err(),
			"signer must reject a share whose dkg_participants exceed total_parties"
		);
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

	/// Security review: `round3_respond` must bind each peer's Round 2 reveal
	/// to the Round 1 commitment hash that was frozen when *this* party
	/// revealed in Round 2, not to a caller-supplied Round 1 set. Otherwise a
	/// rushing peer can send a placeholder Round 1 hash, observe the honest
	/// party's revealed commitment, then hand `round3_respond` a fresh,
	/// mutually-consistent (Round 1 hash, Round 2 data) pair chosen after the
	/// fact — defeating the commit-reveal anti-rushing property.
	#[test]
	fn test_round3_binds_reveal_to_round1_hash_seen_in_round2() {
		use crate::{
			broadcast::Round1Broadcast, generate_with_dealer,
			protocol::signing::compute_commitment_hash,
		};

		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, shares) = generate_with_dealer(&[11u8; 32], config).unwrap();

		let mut s0 = ThresholdSigner::new(shares[0].clone(), pk.clone(), config).unwrap();
		let mut s1 = ThresholdSigner::new(shares[1].clone(), pk.clone(), config).unwrap();

		let ssid = [0x7Cu8; 32];
		let msg = b"anti-rushing";
		let ctx = b"";

		let r1_0 = s0.round1_commit_with_seed(&ssid, &[1u8; 32]).unwrap();

		// The genuine party-1 commitment: a valid, well-formed Round 1/Round 2
		// pair the attacker will present to s0 only in Round 3.
		let r1_1_genuine = s1.round1_commit_with_seed(&ssid, &[2u8; 32]).unwrap();
		let r2_1_genuine = s1.round2_reveal(&ssid, msg, ctx, core::slice::from_ref(&r1_0)).unwrap();

		// In Round 1, the attacker instead sent s0 a *placeholder* commitment
		// hash for party 1 — distinct from the genuine one it later reveals.
		let placeholder_hash = compute_commitment_hash(&ssid, 1, b"placeholder-commitment");
		assert_ne!(
			placeholder_hash, r1_1_genuine.commitment_hash,
			"placeholder must differ from the genuine commitment"
		);
		let r1_1_placeholder = Round1Broadcast::new(ssid, 1, placeholder_hash);

		// s0 reveals its Round 2 commitment having seen only the placeholder.
		s0.round2_reveal(&ssid, msg, ctx, core::slice::from_ref(&r1_1_placeholder))
			.unwrap();

		// The attack: hand Round 3 the genuine, self-consistent pair. Because
		// s0 froze the placeholder hash in Round 2, the genuine reveal no
		// longer matches, so the rushing attempt is rejected.
		let err = s0
			.round3_respond(
				&ssid,
				core::slice::from_ref(&r1_1_genuine),
				core::slice::from_ref(&r2_1_genuine),
			)
			.expect_err("reveal not matching the round-2-frozen commitment must be rejected");
		assert!(
			matches!(err, ThresholdError::CommitmentMismatch { party_id: 1, .. }),
			"expected CommitmentMismatch for party 1, got {err:?}"
		);
	}

	/// Regression test for the validate-then-commit property of
	/// `round3_respond` (preserved across the removal of the full aggregate
	/// clone): a reveal that passes the commitment-hash check but fails to
	/// unpack must be rejected *without* poisoning the session, so the signer
	/// stays in a clean `AfterRound2` state and a repeated attempt is rejected
	/// identically rather than double-counting or resetting.
	///
	/// Under the commit-reveal binding fix, the only way to reach the
	/// unpack-failure path with a hash-bound reveal is for the malformed
	/// commitment to be the one frozen in Round 2 — a peer that committed to
	/// garbage in Round 1. (A peer that committed to valid data but reveals
	/// different data is caught earlier as a `CommitmentMismatch`.)
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

		let ssid = [0x5Au8; 32];
		let _r1_0 = s0.round1_commit_with_seed(&ssid, &[1u8; 32]).unwrap();

		// Party 1 commits (in Round 1) to malformed data: correct length, but
		// every 23-bit coefficient is 2^23 - 1 >= Q, so unpacking fails. The
		// commitment hash is over that same garbage, so the later reveal is
		// genuinely hash-bound to what s0 freezes in Round 2.
		let k = config.k_iterations() as usize;
		let garbage = alloc::vec![0xFFu8; k * 8 * 736];
		let garbage_hash = compute_commitment_hash(&ssid, 1, &garbage);
		let r1_1 = Round1Broadcast::new(ssid, 1, garbage_hash);
		let r2_1 = Round2Broadcast::new(ssid, 1, garbage);

		let msg = b"atomicity";
		let ctx = b"";
		s0.round2_reveal(&ssid, msg, ctx, core::slice::from_ref(&r1_1)).unwrap();

		// The reveal passes the hash check (it matches the frozen commitment)
		// but fails to unpack, and is rejected in the validation pass before
		// the aggregate is touched.
		let err = s0
			.round3_respond(&ssid, core::slice::from_ref(&r1_1), core::slice::from_ref(&r2_1))
			.expect_err("hash-bound but malformed reveal must be rejected");
		assert!(
			matches!(err, ThresholdError::InvalidCommitmentData { party_id: 1, .. }),
			"expected InvalidCommitmentData for party 1, got {err:?}"
		);

		// The failed attempt neither advanced nor reset the session: the signer
		// stays in AfterRound2 and rejects a repeated attempt identically,
		// proving the aggregate was not partially mutated.
		assert_eq!(
			s0.state.phase,
			SigningPhase::AfterRound2,
			"a rejected reveal must leave the session in a clean AfterRound2 state"
		);
		let err_again = s0
			.round3_respond(&ssid, core::slice::from_ref(&r1_1), core::slice::from_ref(&r2_1))
			.expect_err("repeated malformed reveal must be rejected identically");
		assert!(
			matches!(err_again, ThresholdError::InvalidCommitmentData { party_id: 1, .. }),
			"expected InvalidCommitmentData for party 1 on retry, got {err_again:?}"
		);
	}
}
