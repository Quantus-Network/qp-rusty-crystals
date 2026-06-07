//! State structures for the DKG protocol.
//!
//! This module contains the state machine that drives the 4-round DKG protocol
//! for threshold Dilithium (ML-DSA-87).
//!
//! # Protocol Overview
//!
//! The DKG proceeds through 4 rounds:
//!
//! 1. **Round 1 (Commit)**: Each party broadcasts a commitment to their randomness and sends
//!    encrypted shared secrets to other parties in their subsets.
//!
//! 2. **Round 2 (Reveal)**: Each party broadcasts their revealed randomness. Other parties verify
//!    it matches the Round 1 commitment.
//!
//! 3. **Round 3 (Partial PK)**: Using the combined randomness, each party computes their secret
//!    share contributions and broadcasts commitments to their partial public keys.
//!
//! 4. **Round 4 (PK Reveal)**: Each party broadcasts their partial public keys. All parties verify
//!    and combine them to produce the final threshold public key.
//!
//! # State Machine
//!
//! ```text
//! Initialized -> Round1 -> Round2 -> Round3 -> Round4 -> Complete
//!     |            |         |         |         |
//!     +------------+---------+---------+---------+-----> Failed
//! ```
//!
//! # Security: Zeroization
//!
//! The state struct implements `Zeroize` and `Drop` to ensure that sensitive cryptographic
//! material (randomness, shared secrets, secret key contributions) is securely erased from
//! memory when the protocol completes or is dropped. This uses a flat struct design with
//! Option fields, which allows proper `ZeroizeOnDrop` without the issues of enum-based
//! state machines that require `mem::take`.
//!
//! Sensitive fields that are zeroized include:
//!
//! - `my_randomness` - the party's random contribution
//! - `my_shared_secrets` / `shared_secrets` - shared secrets for subset derivation
//! - `my_contributions` - secret key shares (s1, s2 polynomials)

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
	keys::{PrivateKeyShare, PublicKey},
	participants::ParticipantId,
};

use super::protocol::DkgError;

use super::types::{
	DkgConfig, PartialPublicKey, Round1Broadcast, Round2Broadcast, Round3Broadcast,
	Round4Broadcast, SubsetContribution, SubsetMask, TranscriptSigner, RANDOMNESS_SIZE,
	SHARED_SECRET_SIZE,
};

/// Current phase of the DKG protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DkgPhase {
	/// Initial state before the protocol starts.
	#[default]
	Initialized,
	/// Round 1: Commitment phase.
	Round1,
	/// Round 2: Reveal phase.
	Round2,
	/// Round 3: Partial PK commitment phase.
	Round3,
	/// Round 4: Partial PK reveal and aggregation phase.
	Round4,
	/// Protocol completed successfully.
	Complete,
	/// Protocol failed with an error.
	Failed,
}

impl DkgPhase {
	/// Get the phase name for error messages.
	pub fn name(&self) -> &'static str {
		match self {
			DkgPhase::Initialized => "Initialized",
			DkgPhase::Round1 => "Round1",
			DkgPhase::Round2 => "Round2",
			DkgPhase::Round3 => "Round3",
			DkgPhase::Round4 => "Round4",
			DkgPhase::Complete => "Complete",
			DkgPhase::Failed => "Failed",
		}
	}
}

/// Final output of the DKG protocol.
///
/// Contains the threshold public key (shared by all parties) and this party's
/// private key share (unique to this party).
#[derive(Debug, Clone)]
pub struct DkgOutput {
	/// The threshold public key, identical for all parties.
	pub public_key: PublicKey,
	/// This party's private key share for threshold signing.
	pub private_share: PrivateKeyShare,
}

/// State machine for the DKG protocol.
///
/// Uses a flat struct with Option fields instead of an enum with associated data.
/// This design:
/// - Avoids `mem::take` which would lose data on validation errors
/// - Enables proper `ZeroizeOnDrop` - all fields are zeroized when dropped
/// - Keeps data persistent across phases until explicitly cleared
///
/// # Usage
///
/// ```ignore
/// use qp_rusty_crystals_threshold::keygen::dkg::{DkgState, DkgConfig};
///
/// // Create initial state
/// let state = DkgState::new(config);
///
/// // Drive protocol with poke() and message() calls
/// loop {
///     match state.poke(&mut rng) {
///         Action::SendBroadcast(data) => { /* broadcast to all */ }
///         Action::SendPrivate(to, data) => { /* send to specific party */ }
///         Action::Wait => { /* wait for messages */ }
///         Action::Complete => break,
///     }
/// }
/// ```
pub struct DkgState<S: TranscriptSigner> {
	/// Current phase of the protocol.
	pub phase: DkgPhase,

	/// Protocol configuration (persists across all phases).
	pub config: Option<DkgConfig<S>>,

	// ========================================================================
	// Round 1 data
	// ========================================================================
	/// This party's random contribution.
	pub my_randomness: Option<[u8; RANDOMNESS_SIZE]>,
	/// Hash commitment to `my_randomness`.
	pub my_commitment: Option<[u8; 32]>,
	/// Shared secrets for each subset this party is leader of.
	pub my_shared_secrets: Option<BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>>,
	/// Round 1 broadcasts received from other parties.
	pub round1_broadcasts: Option<BTreeMap<ParticipantId, Round1Broadcast>>,
	/// Shared secrets received from other parties (subset leaders).
	pub received_shared_secrets: Option<BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>>,

	// ========================================================================
	// Round 2 data
	// ========================================================================
	/// Combined shared secrets for each subset (my + received).
	pub shared_secrets: Option<BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>>,
	/// Round 2 broadcasts received from other parties.
	pub round2_broadcasts: Option<BTreeMap<ParticipantId, Round2Broadcast>>,

	// ========================================================================
	// Round 3 data
	// ========================================================================
	/// Global randomness derived from all parties' contributions.
	pub global_randomness: Option<Vec<u8>>,
	/// Public matrix seed (rho) derived from global randomness.
	pub rho: Option<[u8; 32]>,
	/// This party's secret contributions for each subset.
	pub my_contributions: Option<BTreeMap<SubsetMask, SubsetContribution>>,
	/// This party's partial public keys for each subset.
	pub my_partial_pks: Option<BTreeMap<SubsetMask, PartialPublicKey>>,
	/// Commitments to this party's partial public keys.
	pub my_pk_commitments: Option<BTreeMap<SubsetMask, [u8; 32]>>,
	/// Round 3 broadcasts received from other parties.
	pub round3_broadcasts: Option<BTreeMap<ParticipantId, Round3Broadcast>>,

	// ========================================================================
	// Round 4 data
	// ========================================================================
	/// Round 4 broadcasts received from other parties.
	pub round4_broadcasts: Option<BTreeMap<ParticipantId, Round4Broadcast>>,

	// ========================================================================
	// Terminal states
	// ========================================================================
	/// DKG output (when Complete).
	pub output: Option<Box<DkgOutput>>,
	/// Error message (when Failed).
	pub error_message: Option<String>,

	// ========================================================================
	// Flags
	// ========================================================================
	/// Whether this party has sent its broadcast for the current round.
	pub broadcast_sent: bool,
	/// Whether this party has sent its private messages (Round 1 only).
	pub privates_sent: bool,
}

impl<S: TranscriptSigner> Default for DkgState<S> {
	fn default() -> Self {
		Self {
			phase: DkgPhase::Initialized,
			config: None,
			my_randomness: None,
			my_commitment: None,
			my_shared_secrets: None,
			round1_broadcasts: None,
			received_shared_secrets: None,
			shared_secrets: None,
			round2_broadcasts: None,
			global_randomness: None,
			rho: None,
			my_contributions: None,
			my_partial_pks: None,
			my_pk_commitments: None,
			round3_broadcasts: None,
			round4_broadcasts: None,
			output: None,
			error_message: None,
			broadcast_sent: false,
			privates_sent: false,
		}
	}
}

impl<S: TranscriptSigner> fmt::Debug for DkgState<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("DkgState")
			.field("phase", &self.phase)
			.field("broadcast_sent", &self.broadcast_sent)
			.field("privates_sent", &self.privates_sent)
			.finish()
	}
}

impl<S: TranscriptSigner> Zeroize for DkgState<S> {
	fn zeroize(&mut self) {
		// Zeroize sensitive randomness
		if let Some(ref mut r) = self.my_randomness {
			r.zeroize();
		}
		self.my_randomness = None;

		// Zeroize shared secrets
		if let Some(ref mut secrets) = self.my_shared_secrets {
			for secret in secrets.values_mut() {
				secret.zeroize();
			}
		}
		self.my_shared_secrets = None;

		if let Some(ref mut secrets) = self.received_shared_secrets {
			for secret in secrets.values_mut() {
				secret.zeroize();
			}
		}
		self.received_shared_secrets = None;

		if let Some(ref mut secrets) = self.shared_secrets {
			for secret in secrets.values_mut() {
				secret.zeroize();
			}
		}
		self.shared_secrets = None;

		// Zeroize global randomness
		if let Some(ref mut gr) = self.global_randomness {
			gr.zeroize();
		}
		self.global_randomness = None;

		// Zeroize contributions (contain secret polynomials)
		if let Some(ref mut contributions) = self.my_contributions {
			for contribution in contributions.values_mut() {
				contribution.zeroize();
			}
		}
		self.my_contributions = None;

		// Clear non-sensitive data
		self.my_commitment = None;
		self.round1_broadcasts = None;
		self.round2_broadcasts = None;
		self.rho = None;
		self.my_partial_pks = None;
		self.my_pk_commitments = None;
		self.round3_broadcasts = None;
		self.round4_broadcasts = None;
		self.config = None;
		self.output = None;
		self.error_message = None;
		self.broadcast_sent = false;
		self.privates_sent = false;
		self.phase = DkgPhase::Initialized;
	}
}

impl<S: TranscriptSigner> Drop for DkgState<S> {
	fn drop(&mut self) {
		self.zeroize();
	}
}

impl<S: TranscriptSigner> ZeroizeOnDrop for DkgState<S> {}

impl<S: TranscriptSigner> DkgState<S> {
	/// Create a new DKG state machine in the `Initialized` state.
	///
	/// The protocol will begin when `poke()` is called.
	pub fn new(config: DkgConfig<S>) -> Self {
		Self {
			phase: DkgPhase::Initialized,
			config: Some(config),
			my_randomness: None,
			my_commitment: None,
			my_shared_secrets: None,
			round1_broadcasts: None,
			received_shared_secrets: None,
			shared_secrets: None,
			round2_broadcasts: None,
			global_randomness: None,
			rho: None,
			my_contributions: None,
			my_partial_pks: None,
			my_pk_commitments: None,
			round3_broadcasts: None,
			round4_broadcasts: None,
			output: None,
			error_message: None,
			broadcast_sent: false,
			privates_sent: false,
		}
	}

	/// Check if the protocol has completed successfully.
	pub fn is_complete(&self) -> bool {
		self.phase == DkgPhase::Complete
	}

	/// Check if the protocol has failed.
	pub fn is_failed(&self) -> bool {
		self.phase == DkgPhase::Failed
	}

	/// Get the list of all participants from the config.
	///
	/// Returns `None` if the protocol is in a terminal state (Complete or Failed).
	pub fn all_participants(&self) -> Option<&[ParticipantId]> {
		if self.phase == DkgPhase::Complete || self.phase == DkgPhase::Failed {
			return None;
		}
		self.config.as_ref().map(|c| c.all_participants.as_slice())
	}

	/// Get this party's ID from the config.
	///
	/// Returns `None` if the protocol is in a terminal state (Complete or Failed).
	pub fn my_party_id(&self) -> Option<ParticipantId> {
		if self.phase == DkgPhase::Complete || self.phase == DkgPhase::Failed {
			return None;
		}
		self.config.as_ref().map(|c| c.my_party_id)
	}

	// ========================================================================
	// Phase expectation helpers
	// ========================================================================

	/// Verify Initialized phase and return config reference.
	pub fn expect_initialized(&self) -> Result<&DkgConfig<S>, DkgError> {
		if self.phase != DkgPhase::Initialized {
			return Err(DkgError::InvalidState(format!(
				"expected Initialized, got {}",
				self.phase.name()
			)));
		}
		self.config
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Initialized phase but no config".into()))
	}

	/// Verify Round1 phase and return config reference.
	pub fn expect_round1(&self) -> Result<&DkgConfig<S>, DkgError> {
		if self.phase != DkgPhase::Round1 {
			return Err(DkgError::InvalidState(format!(
				"expected Round1, got {}",
				self.phase.name()
			)));
		}
		self.config
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round1 phase but no config".into()))
	}

	/// Verify Round2 phase and return config reference.
	pub fn expect_round2(&self) -> Result<&DkgConfig<S>, DkgError> {
		if self.phase != DkgPhase::Round2 {
			return Err(DkgError::InvalidState(format!(
				"expected Round2, got {}",
				self.phase.name()
			)));
		}
		self.config
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round2 phase but no config".into()))
	}

	/// Verify Round3 phase and return config reference.
	pub fn expect_round3(&self) -> Result<&DkgConfig<S>, DkgError> {
		if self.phase != DkgPhase::Round3 {
			return Err(DkgError::InvalidState(format!(
				"expected Round3, got {}",
				self.phase.name()
			)));
		}
		self.config
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round3 phase but no config".into()))
	}

	/// Verify Round4 phase and return config reference.
	pub fn expect_round4(&self) -> Result<&DkgConfig<S>, DkgError> {
		if self.phase != DkgPhase::Round4 {
			return Err(DkgError::InvalidState(format!(
				"expected Round4, got {}",
				self.phase.name()
			)));
		}
		self.config
			.as_ref()
			.ok_or_else(|| DkgError::InvalidState("Round4 phase but no config".into()))
	}
}

/// Check if all broadcasts received.
pub fn all_broadcasts_received<T>(
	received: &BTreeMap<ParticipantId, T>,
	all_participants: &[ParticipantId],
	my_party_id: ParticipantId,
) -> bool {
	let expected_count = all_participants.len() - 1;
	let actual_count = received.keys().filter(|&&p| p != my_party_id).count();
	actual_count >= expected_count
}

/// Check if all private messages received.
pub fn all_private_messages_received(
	received_secrets: &BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	my_shared_secrets: &BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	my_subsets: &[SubsetMask],
) -> bool {
	for &subset in my_subsets {
		if !received_secrets.contains_key(&subset) && !my_shared_secrets.contains_key(&subset) {
			return false;
		}
	}
	true
}
