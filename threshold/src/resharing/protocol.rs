//! Resharing Protocol State Machine.
//!
//! This module implements the resharing protocol using the poke/message pattern
//! compatible with NEAR MPC's `run_protocol` infrastructure.
//!
//! See `resharing/mod.rs` for a full description of the cryptographic protocol.
//! In short:
//!
//! - **Round 1 (Commitments)**: Each old committee member that is the designated dealer for one or
//!   more old RSS subsets broadcasts hash commitments to the per-subset sub-shares `r_{I→J}` they
//!   will deliver in Round 2. Sub-shares are derived deterministically from `s_I^old`, so all
//!   members of `I` can independently recompute and verify these commitments.
//! - **Round 2 (Reveal)**: Each designated dealer privately delivers `r_{I→J}` to every member of
//!   new subset `J`.
//! - **Round 3 (Verification)**: Each new committee member verifies received sub-shares against the
//!   broadcast commitments, sums them into new shares `s_J^new`, and broadcasts a commitment to
//!   each computed `s_J^new` so the members of `J` can cross-verify. Old committee members file
//!   dealer accusations if any broadcast commitment fails their independent recomputation.
//!
//! # State Machine
//!
//! ```text
//! Round1Generate -> Round1Waiting -> Round2Generate -> Round2Waiting
//!     -> Round3Generate -> Round3Waiting -> Combining -> Done
//! ```

use alloc::{
	collections::BTreeMap,
	format,
	string::{String, ToString},
	vec,
	vec::Vec,
};
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use qp_rusty_crystals_dilithium::fips202;

use crate::{
	keys::{PrivateKeyShare, SecretShareData},
	participants::ParticipantId,
};

use super::types::{
	DealerAccusation, NewShareData, ResharingConfig, ResharingMessage, ResharingOutput,
	ResharingRound1Broadcast, ResharingRound2Message, ResharingRound3Broadcast, SubsetMask,
	SubsetPair, COMMITMENT_HASH_SIZE, K, L, N,
};

/// ML-DSA-87 prime modulus.
const Q: i32 = 8380417;

/// Eta bound for ML-DSA-87 share sampling.
const ETA: i32 = 2;

/// Domain separator for the per-subset PRF seed.
const SUBSET_SEED_DOMAIN: &[u8] = b"resharing-subset-prf-v2";
/// Domain separator for sub-share commitments.
const COMMIT_DOMAIN: &[u8] = b"resharing-commit-v2";
/// Domain separator for new share commitments (Round 3).
const NEW_SHARE_COMMIT_DOMAIN: &[u8] = b"resharing-new-share-commit-v2";

// ============================================================================
// Action Enum
// ============================================================================

/// Actions returned by the protocol's `poke` method.
#[derive(Debug, Clone)]
pub enum Action<T> {
	/// Do nothing, waiting for more messages from other participants.
	Wait,
	/// Send a message to all other participants (broadcast).
	SendMany(Vec<u8>),
	/// Send a private message to a specific participant.
	SendPrivate(ParticipantId, Vec<u8>),
	/// The protocol has completed, returning the output.
	Return(T),
}

// ============================================================================
// Protocol Error
// ============================================================================

/// Errors that can occur during the resharing protocol.
#[derive(Debug, Clone)]
pub enum ResharingProtocolError {
	/// The protocol is in an invalid state for the requested operation.
	InvalidState(String),
	/// A message was received from an unknown party.
	UnknownParty(ParticipantId),
	/// A duplicate message was received from a party.
	DuplicateMessage(ParticipantId),
	/// Commitment verification failed for a party.
	CommitmentMismatch(ParticipantId),
	/// Share verification failed.
	ShareVerificationFailed(String),
	/// Serialization error.
	SerializationError(String),
	/// A party reported failure (or was accused as a dealer).
	PartyFailure(Vec<ParticipantId>),
	/// Not enough parties participated.
	InsufficientParties {
		/// The minimum number of parties required.
		required: usize,
		/// The number of parties that actually participated.
		received: usize,
	},
	/// Internal error.
	InternalError(String),
	/// A malformed message was received from a party.
	MalformedMessage {
		/// The party that sent the malformed message.
		from: ParticipantId,
		/// Reason for the failure.
		reason: String,
	},
}

impl fmt::Display for ResharingProtocolError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			ResharingProtocolError::InvalidState(s) => write!(f, "Invalid state: {}", s),
			ResharingProtocolError::UnknownParty(p) => write!(f, "Unknown party: {}", p),
			ResharingProtocolError::DuplicateMessage(p) => {
				write!(f, "Duplicate message from party: {}", p)
			},
			ResharingProtocolError::CommitmentMismatch(p) => {
				write!(f, "Commitment mismatch for party: {}", p)
			},
			ResharingProtocolError::ShareVerificationFailed(s) => {
				write!(f, "Share verification failed: {}", s)
			},
			ResharingProtocolError::SerializationError(s) => {
				write!(f, "Serialization error: {}", s)
			},
			ResharingProtocolError::PartyFailure(parties) => {
				write!(f, "Party failure: {:?}", parties)
			},
			ResharingProtocolError::InsufficientParties { required, received } => {
				write!(f, "Insufficient parties: required {}, received {}", required, received)
			},
			ResharingProtocolError::InternalError(s) => write!(f, "Internal error: {}", s),
			ResharingProtocolError::MalformedMessage { from, reason } => {
				write!(f, "Malformed message from party {}: {}", from, reason)
			},
		}
	}
}

// ============================================================================
// Protocol State
// ============================================================================

/// Current state of the resharing protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ResharingState {
	/// Generating Round 1 message (commitments to per-subset sub-shares).
	Round1Generate,
	/// Waiting for Round 1 messages from old committee members.
	Round1Waiting,
	/// Generating Round 2 messages (private sub-share reveals).
	Round2Generate,
	/// Waiting for Round 2 messages (receiving sub-shares).
	Round2Waiting,
	/// Generating Round 3 message (verification commitments + accusations).
	Round3Generate,
	/// Waiting for Round 3 messages.
	Round3Waiting,
	/// Combining shares and finalizing.
	Combining,
	/// Protocol completed successfully.
	Done,
	/// Protocol failed.
	Failed(String),
}

// ============================================================================
// Resharing Protocol
// ============================================================================

/// The main resharing protocol state machine.
pub struct ResharingProtocol {
	config: ResharingConfig,
	state: ResharingState,
	#[allow(dead_code)] // reserved for future per-session nonce mixing
	seed: [u8; 32],

	/// Old subset masks (from the existing share's stored shares), in canonical
	/// (BTreeMap) order. Indexed by `old_subset_index`.
	old_subset_order: Vec<SubsetMask>,
	/// New subset masks for the new committee, in canonical order. Indexed by
	/// `new_subset_index`. Used to assign per-old-subset "residual" new subsets.
	new_subset_order: Vec<SubsetMask>,

	/// Pre-computed sub-shares we are responsible for dealing.
	/// Keyed by `(old_subset, new_subset)`.
	my_subshares: BTreeMap<SubsetPair, NewShareData>,
	/// Our Round 1 broadcast (commitments for subsets we deal).
	my_round1: Option<ResharingRound1Broadcast>,
	/// Round 1 broadcasts received from other old committee members.
	round1_broadcasts: BTreeMap<ParticipantId, ResharingRound1Broadcast>,

	/// Round 2 messages we have queued to send (each addressed to a specific recipient).
	pending_round2: Vec<ResharingRound2Message>,
	/// Index of the next pending Round 2 message to emit.
	round2_sent_count: usize,
	/// Round 2 messages we received, keyed by sender.
	/// Each value is the merged set of `(I, J) -> r` from that sender.
	round2_messages: BTreeMap<ParticipantId, ResharingRound2Message>,

	/// Round 3 broadcasts.
	round3_broadcasts: BTreeMap<ParticipantId, ResharingRound3Broadcast>,

	/// Computed new shares: `new_subset -> s_J^new`. Populated in Round 3.
	new_shares: BTreeMap<SubsetMask, NewShareData>,
	/// Final output (cached so `take_output` can return it after Combining).
	completed_output: Option<ResharingOutput>,
}

impl ResharingProtocol {
	/// Create a new resharing protocol instance.
	pub fn new(config: ResharingConfig, seed: [u8; 32]) -> Self {
		let old_subset_order = compute_old_subset_order(&config);
		let new_subset_order = compute_new_subset_order(&config);
		Self {
			config,
			state: ResharingState::Round1Generate,
			seed,
			old_subset_order,
			new_subset_order,
			my_subshares: BTreeMap::new(),
			my_round1: None,
			round1_broadcasts: BTreeMap::new(),
			pending_round2: Vec::new(),
			round2_sent_count: 0,
			round2_messages: BTreeMap::new(),
			round3_broadcasts: BTreeMap::new(),
			new_shares: BTreeMap::new(),
			completed_output: None,
		}
	}

	/// Get the current protocol state.
	pub fn state(&self) -> &ResharingState {
		&self.state
	}

	/// Get this party's ID.
	pub fn my_party_id(&self) -> ParticipantId {
		self.config.my_party_id
	}

	/// Get the configuration.
	pub fn config(&self) -> &ResharingConfig {
		&self.config
	}

	/// Take the completed output from the protocol.
	pub fn take_output(&mut self) -> Option<ResharingOutput> {
		if matches!(self.state, ResharingState::Done) {
			self.completed_output.take()
		} else {
			None
		}
	}

	/// Check if the protocol has completed successfully.
	pub fn is_done(&self) -> bool {
		matches!(self.state, ResharingState::Done)
	}

	/// Check if the protocol has failed.
	pub fn is_failed(&self) -> bool {
		matches!(self.state, ResharingState::Failed(_))
	}

	fn serialize_message(msg: &ResharingMessage) -> Result<Vec<u8>, ResharingProtocolError> {
		bincode::serialize(msg).map_err(|e| {
			ResharingProtocolError::SerializationError(format!("Failed to serialize: {}", e))
		})
	}

	fn deserialize_message(data: &[u8]) -> Result<ResharingMessage, ResharingProtocolError> {
		bincode::deserialize(data).map_err(|e| {
			ResharingProtocolError::SerializationError(format!("Failed to deserialize: {}", e))
		})
	}

	/// Advance the protocol state machine.
	pub fn poke(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		match &self.state {
			ResharingState::Round1Generate => self.handle_round1_generate(),
			ResharingState::Round1Waiting => self.handle_round1_waiting(),
			ResharingState::Round2Generate => self.handle_round2_generate(),
			ResharingState::Round2Waiting => self.handle_round2_waiting(),
			ResharingState::Round3Generate => self.handle_round3_generate(),
			ResharingState::Round3Waiting => self.handle_round3_waiting(),
			ResharingState::Combining => self.handle_combining(),
			ResharingState::Done =>
				Err(ResharingProtocolError::InvalidState("Protocol already completed".to_string())),
			ResharingState::Failed(reason) =>
				Err(ResharingProtocolError::InvalidState(format!("Protocol failed: {}", reason))),
		}
	}

	/// Handle an incoming message from another party.
	pub fn message(
		&mut self,
		from: ParticipantId,
		data: Vec<u8>,
	) -> Result<(), ResharingProtocolError> {
		if matches!(self.state, ResharingState::Done | ResharingState::Failed(_)) {
			return Ok(());
		}

		let msg = match Self::deserialize_message(&data) {
			Ok(m) => m,
			Err(e) =>
				return Err(ResharingProtocolError::MalformedMessage { from, reason: e.to_string() }),
		};

		if msg.party_id() != from {
			return Ok(());
		}

		match msg {
			ResharingMessage::Round1(broadcast) => self.handle_round1_message(from, broadcast),
			ResharingMessage::Round2(m) => self.handle_round2_message(from, m),
			ResharingMessage::Round3(broadcast) => self.handle_round3_message(from, broadcast),
		}

		Ok(())
	}

	// ========================================================================
	// Round 1: Commitments
	// ========================================================================

	fn handle_round1_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Only old committee members participate in Round 1.
		if !self.config.role.is_old_committee() {
			self.state = ResharingState::Round2Waiting;
			return Ok(Action::Wait);
		}

		self.compute_my_subshares()?;
		let commitments = self.commit_to_my_subshares();

		let broadcast = ResharingRound1Broadcast { party_id: self.config.my_party_id, commitments };
		self.my_round1 = Some(broadcast.clone());
		self.round1_broadcasts.insert(self.config.my_party_id, broadcast.clone());

		// Pre-build the per-recipient Round 2 messages so we can stream them in
		// later pokes without re-deriving anything.
		self.build_pending_round2_messages();

		let data = Self::serialize_message(&ResharingMessage::Round1(broadcast))?;
		self.state = ResharingState::Round1Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round1_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.have_enough_round1() {
			self.state = ResharingState::Round2Generate;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round1_message(&mut self, from: ParticipantId, broadcast: ResharingRound1Broadcast) {
		if !matches!(self.state, ResharingState::Round1Generate | ResharingState::Round1Waiting) {
			return;
		}
		if !self.config.old_participants.contains(from) {
			return;
		}
		if self.round1_broadcasts.contains_key(&from) {
			return;
		}
		self.round1_broadcasts.insert(from, broadcast);
	}

	fn have_enough_round1(&self) -> bool {
		// We need a Round 1 broadcast from every party that is a designated dealer for at
		// least one old subset. With the assumption that `old_participants ==
		// dkg_participants` this is exactly the set of old committee members that own at
		// least one subset. Conservative requirement: all old participants.
		self.round1_broadcasts.len() >= self.config.old_participants.len()
	}

	// ========================================================================
	// Round 2: Private Reveal
	// ========================================================================

	fn handle_round2_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Old-only parties without dealer responsibilities and new-only parties simply
		// wait for inbound traffic.
		if !self.config.role.is_old_committee() || self.pending_round2.is_empty() {
			self.state = ResharingState::Round2Waiting;
			return self.poke();
		}

		self.state = ResharingState::Round2Waiting;
		self.send_next_round2_message()
	}

	fn handle_round2_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Old-committee dealers continue to drain pending Round 2 messages.
		if self.config.role.is_old_committee() && self.round2_sent_count < self.pending_round2.len()
		{
			return self.send_next_round2_message();
		}

		// New committee members proceed to Round 3 once they have received from every
		// expected dealer.
		if self.config.role.is_new_committee() && self.have_all_expected_round2() {
			self.state = ResharingState::Round3Generate;
			return self.poke();
		}

		// Old-only parties advance to Round 3 generation (they will broadcast accusations
		// only).
		if !self.config.role.is_new_committee() &&
			self.round2_sent_count >= self.pending_round2.len()
		{
			self.state = ResharingState::Round3Generate;
			return self.poke();
		}

		Ok(Action::Wait)
	}

	fn send_next_round2_message(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.round2_sent_count >= self.pending_round2.len() {
			return Ok(Action::Wait);
		}
		let msg = &self.pending_round2[self.round2_sent_count];
		let to_party = msg.to_party_id;
		let data = Self::serialize_message(&ResharingMessage::Round2(msg.clone()))?;
		self.round2_sent_count += 1;
		Ok(Action::SendPrivate(to_party, data))
	}

	fn handle_round2_message(&mut self, from: ParticipantId, msg: ResharingRound2Message) {
		if matches!(self.state, ResharingState::Done | ResharingState::Failed(_)) {
			return;
		}
		if !self.config.role.is_new_committee() {
			return;
		}
		if !self.config.old_participants.contains(from) {
			return;
		}
		if msg.to_party_id != self.config.my_party_id {
			return;
		}
		// Reject duplicates from the same dealer.
		if self.round2_messages.contains_key(&from) {
			return;
		}
		self.round2_messages.insert(from, msg);
	}

	fn have_all_expected_round2(&self) -> bool {
		// Expected senders = the set of designated dealers for each old subset.
		let expected: BTreeMap<ParticipantId, ()> =
			self.designated_dealer_set().into_iter().map(|p| (p, ())).collect();
		expected.keys().all(|d| self.round2_messages.contains_key(d))
	}

	fn designated_dealer_set(&self) -> Vec<ParticipantId> {
		let mut set: alloc::collections::BTreeSet<ParticipantId> =
			alloc::collections::BTreeSet::new();
		for &i_mask in &self.old_subset_order {
			if let Some(d) = self.designated_dealer_for(i_mask) {
				set.insert(d);
			}
		}
		set.into_iter().collect()
	}

	// ========================================================================
	// Round 3: Verification + Accusations
	// ========================================================================

	fn handle_round3_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		let mut accusations: Vec<DealerAccusation> = Vec::new();
		let mut share_commitments: BTreeMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]> =
			BTreeMap::new();
		let mut success = true;
		let mut error_message: Option<String> = None;

		// Old committee members independently recompute every commitment for every old
		// subset they belong to and accuse the dealer if the dealer's commitment differs
		// from their independent computation.
		if self.config.role.is_old_committee() {
			match self.collect_accusations() {
				Ok(a) => accusations = a,
				Err(e) => {
					success = false;
					error_message = Some(e.to_string());
				},
			}
		}

		// New committee members verify privately-received sub-shares against the
		// broadcast commitments, sum them into new subset shares, and commit.
		if self.config.role.is_new_committee() && success {
			match self.verify_and_aggregate_new_shares() {
				Ok(commits) => share_commitments = commits,
				Err(e) => {
					success = false;
					error_message = Some(e.to_string());
				},
			}
		}

		let broadcast = ResharingRound3Broadcast {
			party_id: self.config.my_party_id,
			share_commitments,
			accusations,
			success,
			error_message,
		};
		self.round3_broadcasts.insert(self.config.my_party_id, broadcast.clone());
		let data = Self::serialize_message(&ResharingMessage::Round3(broadcast))?;
		self.state = ResharingState::Round3Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round3_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.have_all_round3() {
			self.state = ResharingState::Combining;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round3_message(&mut self, from: ParticipantId, broadcast: ResharingRound3Broadcast) {
		if matches!(self.state, ResharingState::Done | ResharingState::Failed(_)) {
			return;
		}
		if !self.config.all_participants().contains(&from) {
			return;
		}
		if self.round3_broadcasts.contains_key(&from) {
			return;
		}
		self.round3_broadcasts.insert(from, broadcast);
	}

	fn have_all_round3(&self) -> bool {
		// Round 3 has contributions from BOTH old and new committee members
		// (old members file accusations; new members commit to new shares),
		// so we need broadcasts from every party that is in either committee.
		let union = self.config.all_participants();
		union.iter().all(|p| self.round3_broadcasts.contains_key(p))
	}

	// ========================================================================
	// Combining
	// ========================================================================

	fn handle_combining(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Surface any explicit failure flags from Round 3.
		let failed_parties: Vec<ParticipantId> = self
			.round3_broadcasts
			.iter()
			.filter(|(_, b)| !b.success)
			.map(|(id, _)| *id)
			.collect();
		if !failed_parties.is_empty() {
			let reason = format!("Parties reported failure: {:?}", failed_parties);
			self.state = ResharingState::Failed(reason);
			return Err(ResharingProtocolError::PartyFailure(failed_parties));
		}

		// Surface any dealer accusations.
		let mut accused: alloc::collections::BTreeSet<ParticipantId> =
			alloc::collections::BTreeSet::new();
		for broadcast in self.round3_broadcasts.values() {
			for accusation in &broadcast.accusations {
				accused.insert(accusation.dealer);
			}
		}
		if !accused.is_empty() {
			let accused_vec: Vec<ParticipantId> = accused.into_iter().collect();
			let reason = format!("Dealers accused of misbehavior: {:?}", accused_vec);
			self.state = ResharingState::Failed(reason);
			return Err(ResharingProtocolError::PartyFailure(accused_vec));
		}

		// New committee members must agree on every shared new subset.
		self.verify_new_share_consistency()?;

		let output = self.build_output()?;
		self.completed_output = Some(output.clone());
		self.state = ResharingState::Done;
		Ok(Action::Return(output))
	}

	// ========================================================================
	// Cryptographic Helpers
	// ========================================================================

	/// Pre-compute every sub-share `r_{I→J}` we are responsible for dealing.
	fn compute_my_subshares(&mut self) -> Result<(), ResharingProtocolError> {
		let existing = self.config.existing_share.as_ref().ok_or_else(|| {
			ResharingProtocolError::InternalError("Missing existing share".to_string())
		})?;
		let shares = existing.shares();
		let new_subsets = self.new_subset_order.clone();
		let n_new = new_subsets.len();
		if n_new == 0 {
			return Err(ResharingProtocolError::InternalError(
				"No new subsets to deal to".to_string(),
			));
		}

		for (i_idx, &i_mask) in self.old_subset_order.clone().iter().enumerate() {
			// Only compute for subsets where we are the designated dealer.
			if self.designated_dealer_for(i_mask) != Some(self.config.my_party_id) {
				continue;
			}
			let s_i = shares.get(&i_mask).ok_or_else(|| {
				ResharingProtocolError::InternalError(format!(
					"Designated dealer for subset {:b} but no share data",
					i_mask
				))
			})?;
			let residual_idx = i_idx % n_new;
			let subshares = derive_subshares(i_mask, s_i, &new_subsets, residual_idx);
			for (j_idx, j_mask) in new_subsets.iter().enumerate() {
				self.my_subshares.insert((i_mask, *j_mask), subshares[j_idx].clone());
			}
		}
		Ok(())
	}

	/// Compute hash commitments to every sub-share we will deal.
	fn commit_to_my_subshares(&self) -> BTreeMap<SubsetPair, [u8; COMMITMENT_HASH_SIZE]> {
		let mut out = BTreeMap::new();
		for (pair, share) in &self.my_subshares {
			out.insert(*pair, commit_subshare(pair.0, pair.1, share));
		}
		out
	}

	/// Build the per-recipient Round 2 messages we will emit one-by-one in `poke`.
	fn build_pending_round2_messages(&mut self) {
		let mut by_recipient: BTreeMap<ParticipantId, BTreeMap<SubsetPair, NewShareData>> =
			BTreeMap::new();
		for (pair, share) in &self.my_subshares {
			let j_mask = pair.1;
			for (idx, party) in self.config.new_participants.iter().enumerate() {
				if (j_mask & (1 << idx)) != 0 {
					by_recipient.entry(party).or_default().insert(*pair, share.clone());
				}
			}
		}
		for (recipient, contributions) in by_recipient {
			self.pending_round2.push(ResharingRound2Message {
				from_party_id: self.config.my_party_id,
				to_party_id: recipient,
				contributions,
			});
		}
	}

	/// Find the designated dealer for an old subset: the lowest-ID old
	/// participant that is a member of the subset.
	///
	/// Bit positions in `i_mask` correspond to indices in the (sorted)
	/// `old_participants` list, so the dealer is the party at the lowest
	/// set bit. Works for every party — in particular NewOnly parties that
	/// don't hold an `existing_share`.
	fn designated_dealer_for(&self, i_mask: SubsetMask) -> Option<ParticipantId> {
		for (bit, party) in self.config.old_participants.iter().enumerate() {
			if (i_mask & (1 << bit)) != 0 {
				return Some(party);
			}
		}
		None
	}

	/// Old committee post-Round-1 verification: re-derive sub-shares for every old
	/// subset we belong to, compare against the dealer's broadcast commitments, and
	/// produce accusations for any mismatches.
	fn collect_accusations(&self) -> Result<Vec<DealerAccusation>, ResharingProtocolError> {
		let existing = self.config.existing_share.as_ref().ok_or_else(|| {
			ResharingProtocolError::InternalError("Missing existing share".to_string())
		})?;
		let shares = existing.shares();
		let new_subsets = &self.new_subset_order;
		let n_new = new_subsets.len();
		if n_new == 0 {
			return Ok(Vec::new());
		}

		let mut accusations = Vec::new();
		for (i_idx, &i_mask) in self.old_subset_order.iter().enumerate() {
			let dealer = match self.designated_dealer_for(i_mask) {
				Some(d) => d,
				None => continue,
			};
			// Skip subsets we are not in (we can't recompute their secret share data).
			let s_i = match shares.get(&i_mask) {
				Some(s) => s,
				None => continue,
			};
			// We don't accuse ourselves.
			if dealer == self.config.my_party_id {
				continue;
			}
			let dealer_broadcast = self.round1_broadcasts.get(&dealer).ok_or_else(|| {
				ResharingProtocolError::InternalError(format!(
					"Missing Round 1 broadcast from designated dealer {} for subset {:b}",
					dealer, i_mask
				))
			})?;
			let residual_idx = i_idx % n_new;
			let expected = derive_subshares(i_mask, s_i, new_subsets, residual_idx);
			for (j_idx, &j_mask) in new_subsets.iter().enumerate() {
				let expected_commit = commit_subshare(i_mask, j_mask, &expected[j_idx]);
				match dealer_broadcast.commitments.get(&(i_mask, j_mask)) {
					Some(c) if *c == expected_commit => {},
					_ => {
						accusations.push(DealerAccusation {
							dealer,
							old_subset: i_mask,
							new_subset: j_mask,
						});
					},
				}
			}
		}
		Ok(accusations)
	}

	/// New committee post-Round-2 work: verify each received `r_{I→J}` against the
	/// matching Round 1 commitment, then sum them into `s_J^new` and produce a
	/// commitment per new subset we are in.
	fn verify_and_aggregate_new_shares(
		&mut self,
	) -> Result<BTreeMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]>, ResharingProtocolError> {
		let my_idx =
			self.config.new_participants.index_of(self.config.my_party_id).ok_or_else(|| {
				ResharingProtocolError::InternalError("not in new committee".into())
			})?;

		// Collect every (I, J, dealer, r) we expect to use.
		let new_subsets = &self.new_subset_order;
		let mut s_new: BTreeMap<SubsetMask, NewShareData> = BTreeMap::new();
		for &j_mask in new_subsets {
			if (j_mask & (1 << my_idx)) == 0 {
				continue;
			}
			s_new.insert(j_mask, NewShareData::new());
		}

		for &i_mask in &self.old_subset_order {
			let dealer = match self.designated_dealer_for(i_mask) {
				Some(d) => d,
				None =>
					return Err(ResharingProtocolError::ShareVerificationFailed(format!(
						"no designated dealer found for old subset {:b}",
						i_mask
					))),
			};
			let dealer_r1 = self.round1_broadcasts.get(&dealer).ok_or_else(|| {
				ResharingProtocolError::ShareVerificationFailed(format!(
					"missing Round 1 commitment from dealer {} for subset {:b}",
					dealer, i_mask
				))
			})?;
			let dealer_r2 = self.round2_messages.get(&dealer).ok_or_else(|| {
				ResharingProtocolError::ShareVerificationFailed(format!(
					"missing Round 2 message from dealer {} for subset {:b}",
					dealer, i_mask
				))
			})?;
			for &j_mask in new_subsets {
				if (j_mask & (1 << my_idx)) == 0 {
					continue;
				}
				let r = dealer_r2.contributions.get(&(i_mask, j_mask)).ok_or_else(|| {
					ResharingProtocolError::ShareVerificationFailed(format!(
						"dealer {} did not deliver r_{{{:b}->{:b}}}",
						dealer, i_mask, j_mask
					))
				})?;
				let expected_commit = commit_subshare(i_mask, j_mask, r);
				let dealer_commit =
					dealer_r1.commitments.get(&(i_mask, j_mask)).ok_or_else(|| {
						ResharingProtocolError::ShareVerificationFailed(format!(
							"dealer {} did not commit to r_{{{:b}->{:b}}}",
							dealer, i_mask, j_mask
						))
					})?;
				if *dealer_commit != expected_commit {
					return Err(ResharingProtocolError::ShareVerificationFailed(format!(
						"dealer {} sent r_{{{:b}->{:b}}} that doesn't match their commitment",
						dealer, i_mask, j_mask
					)));
				}
				let acc = s_new.get_mut(&j_mask).unwrap();
				add_share_into(acc, r);
			}
		}

		// Reduce mod Q and stash.
		let mut commitments = BTreeMap::new();
		for (j_mask, mut share) in s_new {
			reduce_share_mod_q(&mut share);
			commitments.insert(j_mask, commit_new_share(j_mask, &share));
			self.new_shares.insert(j_mask, share);
		}
		Ok(commitments)
	}

	/// All members of new subset J must produce identical `s_J^new` (and thus identical
	/// commitments). Cross-verify that.
	fn verify_new_share_consistency(&self) -> Result<(), ResharingProtocolError> {
		let mut by_subset: BTreeMap<SubsetMask, Vec<(ParticipantId, [u8; COMMITMENT_HASH_SIZE])>> =
			BTreeMap::new();
		for (party, broadcast) in &self.round3_broadcasts {
			for (j_mask, commit) in &broadcast.share_commitments {
				by_subset.entry(*j_mask).or_default().push((*party, *commit));
			}
		}
		for (j_mask, commits) in &by_subset {
			if commits.len() < 2 {
				continue;
			}
			let first = commits[0].1;
			for (party, commit) in &commits[1..] {
				if *commit != first {
					return Err(ResharingProtocolError::ShareVerificationFailed(format!(
						"members of new subset {:b} disagree: party {} differs from party {}",
						j_mask, party, commits[0].0
					)));
				}
			}
		}
		Ok(())
	}

	fn build_output(&self) -> Result<ResharingOutput, ResharingProtocolError> {
		if !self.config.role.is_new_committee() {
			return Ok(ResharingOutput {
				private_share: None,
				public_key: self.config.public_key.clone(),
				new_config: self.config.new_config(),
			});
		}
		let new_share = self.build_private_key_share()?;
		Ok(ResharingOutput {
			private_share: Some(new_share),
			public_key: self.config.public_key.clone(),
			new_config: self.config.new_config(),
		})
	}

	fn build_private_key_share(&self) -> Result<PrivateKeyShare, ResharingProtocolError> {
		let mut shares_data: BTreeMap<u16, SecretShareData> = BTreeMap::new();
		for (j_mask, share) in &self.new_shares {
			shares_data
				.insert(*j_mask, SecretShareData { s1: share.s1.clone(), s2: share.s2.clone() });
		}

		let (rho, tr) = if let Some(ref existing) = self.config.existing_share {
			(*existing.rho(), *existing.tr())
		} else {
			let pk_bytes = self.config.public_key.as_bytes();
			let mut rho = [0u8; 32];
			rho.copy_from_slice(&pk_bytes[..32]);
			(rho, *self.config.public_key.tr())
		};

		// Derive `party_key` from the actual share polynomials so it carries real
		// entropy (mirrors the C3 fix in the DKG path).
		let mut party_key = [0u8; 32];
		{
			let mut h = fips202::KeccakState::default();
			fips202::shake256_absorb(&mut h, b"reshare-party-key-v2", 20);
			fips202::shake256_absorb(&mut h, &rho, 32);
			fips202::shake256_absorb(&mut h, &self.config.my_party_id.to_le_bytes(), 4);
			let mut buf: Vec<u8> = Vec::new();
			for (j_mask, share) in &self.new_shares {
				buf.clear();
				buf.extend_from_slice(&j_mask.to_le_bytes());
				for poly in &share.s1 {
					for c in poly {
						buf.extend_from_slice(&c.to_le_bytes());
					}
				}
				for poly in &share.s2 {
					for c in poly {
						buf.extend_from_slice(&c.to_le_bytes());
					}
				}
				fips202::shake256_absorb(&mut h, &buf, buf.len());
			}
			fips202::shake256_finalize(&mut h);
			fips202::shake256_squeeze(&mut party_key, 32, &mut h);
		}

		Ok(PrivateKeyShare::new(
			self.config.my_party_id,
			self.config.new_participants.len() as u32,
			self.config.new_threshold,
			party_key,
			rho,
			tr,
			shares_data,
			self.config.new_participants.clone(),
		))
	}
}

// ============================================================================
// Free Functions: subset enumeration and sub-share derivation
// ============================================================================

/// Canonical enumeration of all old RSS subsets: every `k_old`-subset of the
/// `n_old` old committee positions. **Identical for every party**, so the
/// `i_idx` used to pick a residual `J` in `derive_subshares` is consistent
/// across all parties — without this consistency, dealers' commitments would
/// not match the verifiers' independent recomputations.
fn compute_old_subset_order(config: &ResharingConfig) -> Vec<SubsetMask> {
	let n = config.old_participants.len();
	let k = n - config.old_threshold as usize + 1;
	generate_subset_masks(n, k)
}

fn compute_new_subset_order(config: &ResharingConfig) -> Vec<SubsetMask> {
	let n = config.new_participants.len();
	let k = n - config.new_threshold as usize + 1;
	generate_subset_masks(n, k)
}

/// Enumerate subset masks of size `k` over `n` bits in canonical (numerically
/// ascending) order using Gosper's hack.
fn generate_subset_masks(n: usize, k: usize) -> Vec<SubsetMask> {
	if k == 0 || k > n {
		return Vec::new();
	}
	let mut out = Vec::new();
	let max_val: u32 = 1u32 << n;
	let mut mask: u32 = (1u32 << k) - 1;
	while mask < max_val {
		out.push(mask as SubsetMask);
		let c = mask & mask.wrapping_neg();
		let r = mask + c;
		mask = (((r ^ mask) >> 2) / c) | r;
	}
	out
}

/// Derive sub-shares `r_{I→J}` for every new subset `J` such that
/// `Σ_J r_{I→J} = s_I` (mod Q), where `s_I` is the (η-bounded) old subset
/// share. The sub-share for `new_subsets[residual_idx]` absorbs the sum
/// adjustment; all others are sampled deterministically η-bounded from a PRF
/// seeded by `s_I` and the subset masks.
fn derive_subshares(
	i_mask: SubsetMask,
	s_i: &SecretShareData,
	new_subsets: &[SubsetMask],
	residual_idx: usize,
) -> Vec<NewShareData> {
	debug_assert!(new_subsets.len() > residual_idx);
	let mut out: Vec<NewShareData> = (0..new_subsets.len()).map(|_| NewShareData::new()).collect();

	// Build a PRF seed from (domain || I_mask || s1 || s2). All members of subset I
	// know `s_i` and so derive the same seed.
	let prf_seed = build_subset_seed(i_mask, s_i);

	// Track running sums to compute the residual.
	let mut sum_s1: Vec<[i32; N]> = vec![[0i32; N]; L];
	let mut sum_s2: Vec<[i32; N]> = vec![[0i32; N]; K];

	for (j_idx, &j_mask) in new_subsets.iter().enumerate() {
		if j_idx == residual_idx {
			continue;
		}
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, &prf_seed, prf_seed.len());
		fips202::shake256_absorb(&mut state, &j_mask.to_le_bytes(), 2);
		fips202::shake256_finalize(&mut state);

		for poly in out[j_idx].s1.iter_mut() {
			sample_eta_poly(&mut state, poly);
		}
		for poly in out[j_idx].s2.iter_mut() {
			sample_eta_poly(&mut state, poly);
		}
		add_share_into_sum(&mut sum_s1, &mut sum_s2, &out[j_idx]);
	}

	// Residual: r_{I→J_residual} = s_I - Σ.
	let residual = &mut out[residual_idx];
	for (poly_idx, poly) in residual.s1.iter_mut().enumerate() {
		for (coeff_idx, c) in poly.iter_mut().enumerate() {
			let s = s_i.s1[poly_idx][coeff_idx];
			let r = sum_s1[poly_idx][coeff_idx];
			*c = mod_q(s.wrapping_sub(r));
		}
	}
	for (poly_idx, poly) in residual.s2.iter_mut().enumerate() {
		for (coeff_idx, c) in poly.iter_mut().enumerate() {
			let s = s_i.s2[poly_idx][coeff_idx];
			let r = sum_s2[poly_idx][coeff_idx];
			*c = mod_q(s.wrapping_sub(r));
		}
	}
	out
}

fn build_subset_seed(i_mask: SubsetMask, s_i: &SecretShareData) -> [u8; 64] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, SUBSET_SEED_DOMAIN, SUBSET_SEED_DOMAIN.len());
	fips202::shake256_absorb(&mut state, &i_mask.to_le_bytes(), 2);
	let mut buf: Vec<u8> = Vec::new();
	for poly in &s_i.s1 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf, buf.len());
	}
	for poly in &s_i.s2 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf, buf.len());
	}
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; 64];
	fips202::shake256_squeeze(&mut out, 64, &mut state);
	out
}

fn sample_eta_poly(state: &mut fips202::KeccakState, poly: &mut [i32; N]) {
	let bound: i32 = 2 * ETA + 1;
	let cutoff: i32 = (256 / bound) * bound;
	for c in poly.iter_mut() {
		let mut buf = [0u8; 1];
		loop {
			fips202::shake256_squeeze(&mut buf, 1, state);
			let b = buf[0] as i32;
			if b < cutoff {
				*c = (b % bound) - ETA;
				break;
			}
		}
	}
}

fn commit_subshare(
	i_mask: SubsetMask,
	j_mask: SubsetMask,
	r: &NewShareData,
) -> [u8; COMMITMENT_HASH_SIZE] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, COMMIT_DOMAIN, COMMIT_DOMAIN.len());
	fips202::shake256_absorb(&mut state, &i_mask.to_le_bytes(), 2);
	fips202::shake256_absorb(&mut state, &j_mask.to_le_bytes(), 2);
	let mut buf: Vec<u8> = Vec::new();
	for poly in &r.s1 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf, buf.len());
	}
	for poly in &r.s2 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf, buf.len());
	}
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; COMMITMENT_HASH_SIZE];
	fips202::shake256_squeeze(&mut out, COMMITMENT_HASH_SIZE, &mut state);
	out
}

fn commit_new_share(j_mask: SubsetMask, share: &NewShareData) -> [u8; COMMITMENT_HASH_SIZE] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, NEW_SHARE_COMMIT_DOMAIN, NEW_SHARE_COMMIT_DOMAIN.len());
	fips202::shake256_absorb(&mut state, &j_mask.to_le_bytes(), 2);
	let mut buf: Vec<u8> = Vec::new();
	for poly in &share.s1 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf, buf.len());
	}
	for poly in &share.s2 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf, buf.len());
	}
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; COMMITMENT_HASH_SIZE];
	fips202::shake256_squeeze(&mut out, COMMITMENT_HASH_SIZE, &mut state);
	out
}

fn add_share_into(acc: &mut NewShareData, r: &NewShareData) {
	for (a, b) in acc.s1.iter_mut().zip(r.s1.iter()) {
		for (ac, bc) in a.iter_mut().zip(b.iter()) {
			*ac = ac.wrapping_add(*bc);
		}
	}
	for (a, b) in acc.s2.iter_mut().zip(r.s2.iter()) {
		for (ac, bc) in a.iter_mut().zip(b.iter()) {
			*ac = ac.wrapping_add(*bc);
		}
	}
}

fn add_share_into_sum(sum_s1: &mut [[i32; N]], sum_s2: &mut [[i32; N]], r: &NewShareData) {
	for (a, b) in sum_s1.iter_mut().zip(r.s1.iter()) {
		for (ac, bc) in a.iter_mut().zip(b.iter()) {
			*ac = ac.wrapping_add(*bc);
		}
	}
	for (a, b) in sum_s2.iter_mut().zip(r.s2.iter()) {
		for (ac, bc) in a.iter_mut().zip(b.iter()) {
			*ac = ac.wrapping_add(*bc);
		}
	}
}

fn reduce_share_mod_q(share: &mut NewShareData) {
	for poly in share.s1.iter_mut() {
		for c in poly.iter_mut() {
			*c = mod_q(*c);
		}
	}
	for poly in share.s2.iter_mut() {
		for c in poly.iter_mut() {
			*c = mod_q(*c);
		}
	}
}

#[inline]
fn mod_q(x: i32) -> i32 {
	let r = x % Q;
	if r < 0 {
		r + Q
	} else {
		r
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_generate_subset_masks() {
		let s = generate_subset_masks(3, 2);
		assert_eq!(s, vec![0b011, 0b101, 0b110]);

		let s = generate_subset_masks(4, 2);
		assert_eq!(s.len(), 6);
		// Canonical ascending order.
		for i in 1..s.len() {
			assert!(s[i - 1] < s[i]);
		}

		let s = generate_subset_masks(5, 3);
		assert_eq!(s.len(), 10);
		for i in 1..s.len() {
			assert!(s[i - 1] < s[i]);
		}
	}

	#[test]
	fn test_generate_subset_masks_edge_cases() {
		assert!(generate_subset_masks(0, 0).is_empty());
		assert!(generate_subset_masks(3, 0).is_empty());
		assert!(generate_subset_masks(3, 4).is_empty());
		assert_eq!(generate_subset_masks(4, 4), vec![0b1111]);
	}

	#[test]
	fn test_subset_seed_is_deterministic_for_same_share() {
		let s = SecretShareData { s1: vec![[3i32; N]; L], s2: vec![[5i32; N]; K] };
		assert_eq!(build_subset_seed(0b011, &s), build_subset_seed(0b011, &s));
	}

	#[test]
	fn test_derive_subshares_sums_to_original_share() {
		let s = SecretShareData { s1: vec![[1i32; N]; L], s2: vec![[2i32; N]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		for residual_idx in 0..new_subsets.len() {
			let subshares = derive_subshares(0b011, &s, &new_subsets, residual_idx);
			let mut sum_s1 = vec![[0i64; N]; L];
			let mut sum_s2 = vec![[0i64; N]; K];
			for sub in &subshares {
				for (a, b) in sum_s1.iter_mut().zip(sub.s1.iter()) {
					for (ac, bc) in a.iter_mut().zip(b.iter()) {
						*ac += *bc as i64;
					}
				}
				for (a, b) in sum_s2.iter_mut().zip(sub.s2.iter()) {
					for (ac, bc) in a.iter_mut().zip(b.iter()) {
						*ac += *bc as i64;
					}
				}
			}
			for (poly_idx, poly) in sum_s1.iter().enumerate() {
				for (c_idx, &v) in poly.iter().enumerate() {
					let expected = s.s1[poly_idx][c_idx] as i64;
					let q = Q as i64;
					assert_eq!((v % q + q) % q, (expected % q + q) % q);
				}
			}
			for (poly_idx, poly) in sum_s2.iter().enumerate() {
				for (c_idx, &v) in poly.iter().enumerate() {
					let expected = s.s2[poly_idx][c_idx] as i64;
					let q = Q as i64;
					assert_eq!((v % q + q) % q, (expected % q + q) % q);
				}
			}
		}
	}

	#[test]
	fn test_derive_subshares_is_deterministic() {
		let s = SecretShareData { s1: vec![[1i32; N]; L], s2: vec![[2i32; N]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let a = derive_subshares(0b011, &s, &new_subsets, 0);
		let b = derive_subshares(0b011, &s, &new_subsets, 0);
		for (x, y) in a.iter().zip(b.iter()) {
			assert_eq!(x.s1, y.s1);
			assert_eq!(x.s2, y.s2);
		}
	}

	#[test]
	fn test_commit_subshare_distinguishes_inputs() {
		let r1 = NewShareData { s1: vec![[1i32; N]; L], s2: vec![[2i32; N]; K] };
		let r2 = NewShareData { s1: vec![[1i32; N]; L], s2: vec![[3i32; N]; K] };
		let c1 = commit_subshare(0b011, 0b101, &r1);
		let c2 = commit_subshare(0b011, 0b101, &r2);
		assert_ne!(c1, c2);
		// Different subsets should also differ.
		let c3 = commit_subshare(0b011, 0b110, &r1);
		assert_ne!(c1, c3);
	}

	#[test]
	fn test_resharing_state_transitions() {
		assert_ne!(ResharingState::Round1Generate, ResharingState::Round1Waiting);
		assert_ne!(ResharingState::Round2Generate, ResharingState::Round2Waiting);
		assert_ne!(ResharingState::Round3Generate, ResharingState::Round3Waiting);
		assert_ne!(ResharingState::Combining, ResharingState::Done);
	}

	#[test]
	fn test_action_variants() {
		let wait: Action<()> = Action::Wait;
		let send_many: Action<()> = Action::SendMany(vec![1, 2, 3]);
		let send_private: Action<()> = Action::SendPrivate(42, vec![4, 5, 6]);
		let ret: Action<i32> = Action::Return(123);

		match wait {
			Action::Wait => {},
			_ => panic!("Expected Wait"),
		}
		match send_many {
			Action::SendMany(data) => assert_eq!(data, vec![1, 2, 3]),
			_ => panic!("Expected SendMany"),
		}
		match send_private {
			Action::SendPrivate(to, data) => {
				assert_eq!(to, 42);
				assert_eq!(data, vec![4, 5, 6]);
			},
			_ => panic!("Expected SendPrivate"),
		}
		match ret {
			Action::Return(val) => assert_eq!(val, 123),
			_ => panic!("Expected Return"),
		}
	}

	#[test]
	fn test_mod_q() {
		assert_eq!(mod_q(0), 0);
		assert_eq!(mod_q(1), 1);
		assert_eq!(mod_q(Q - 1), Q - 1);
		assert_eq!(mod_q(Q), 0);
		assert_eq!(mod_q(Q + 1), 1);
		assert_eq!(mod_q(-1), Q - 1);
		assert_eq!(mod_q(-Q), 0);
		assert_eq!(mod_q(-Q - 1), Q - 1);
	}

	#[test]
	fn test_subshares_for_disjoint_share_data_diverge() {
		// Two different `s_I^old` values must produce different sub-share splits
		// (otherwise an attacker who saw them couldn't distinguish secrets).
		let s_a = SecretShareData { s1: vec![[1i32; N]; L], s2: vec![[2i32; N]; K] };
		let s_b = SecretShareData { s1: vec![[3i32; N]; L], s2: vec![[5i32; N]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let a = derive_subshares(0b011, &s_a, &new_subsets, 0);
		let b = derive_subshares(0b011, &s_b, &new_subsets, 0);
		// Even the *first* sub-share (which is sampled, not residual) must differ
		// because the PRF seed depends on `s_i`.
		assert_ne!(a[1].s1, b[1].s1);
	}

	#[test]
	fn test_subshares_independent_per_old_subset() {
		// Different old subsets sharing the same `s_I^old` value must still produce
		// different sub-shares, because the PRF seed mixes `i_mask`.
		let s = SecretShareData { s1: vec![[1i32; N]; L], s2: vec![[2i32; N]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let a = derive_subshares(0b011, &s, &new_subsets, 0);
		let b = derive_subshares(0b101, &s, &new_subsets, 0);
		// The *non-residual* sub-shares are PRF outputs keyed on (s, i_mask, j_mask),
		// so they must differ.
		assert_ne!(a[1].s1, b[1].s1);
	}

	#[test]
	fn test_round1_broadcast_does_not_leak_subshares() {
		// Sanity: a Round 1 broadcast carries hash commitments and nothing else.
		// In particular it must not contain any plaintext NewShareData fields.
		let mut commitments = BTreeMap::new();
		commitments.insert((0b011u16, 0b101u16), [9u8; COMMITMENT_HASH_SIZE]);
		let r1 = ResharingRound1Broadcast { party_id: 7, commitments };
		// The struct only has `party_id` (u32) and `commitments` (BTreeMap of hashes).
		// If anyone ever adds back leaky plaintext fields, this test should be
		// updated alongside the security review.
		assert_eq!(r1.party_id, 7);
		assert_eq!(r1.commitments.len(), 1);
	}

	#[test]
	fn test_protocol_error_display() {
		let err = ResharingProtocolError::InvalidState("test".to_string());
		assert!(err.to_string().contains("Invalid state"));

		let err = ResharingProtocolError::UnknownParty(42);
		assert!(err.to_string().contains("42"));

		let err = ResharingProtocolError::InsufficientParties { required: 3, received: 2 };
		assert!(err.to_string().contains("3"));
		assert!(err.to_string().contains("2"));
	}
}
