//! Protocol implementation for the Mithril DKG.

use alloc::{
	collections::BTreeMap,
	format,
	string::{String, ToString},
	vec,
	vec::Vec,
};
use core::{fmt, mem};

use rand::{CryptoRng, RngCore};

use crate::{
	config::ThresholdConfig,
	keys::{PrivateKeyShare, PublicKey, SecretShareData},
	participants::ParticipantList,
};

use super::{
	state::{
		all_broadcasts_received, all_private_messages_received, MithrilDkgOutput, MithrilDkgState,
		MithrilRound1State, MithrilRound2State, MithrilRound3State, MithrilRound4State,
	},
	types::{
		compute_partial_output_hash, compute_signing_message, compute_transcript_hash,
		derive_subset_contribution, h_commit, h_commit_pk, h_keygen, h_seed, MithrilDkgConfig,
		MithrilDkgMessage, MithrilRound1Broadcast, MithrilRound1Private, MithrilRound2Broadcast,
		MithrilRound3Broadcast, MithrilRound4Broadcast, PartialPublicKey, ParticipantId,
		SubsetContribution, SubsetMask, TranscriptSigner, RANDOMNESS_SIZE,
		SHARED_SECRET_SIZE,
	},
};

use qp_rusty_crystals_dilithium::fips202;

const ETA: i32 = 2; // ML-DSA-87 eta parameter

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during the DKG protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MithrilDkgError {
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
}

impl fmt::Display for MithrilDkgError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidState(msg) => write!(f, "invalid state: {}", msg),
			Self::CommitmentMismatch { party_id } =>
				write!(f, "commitment mismatch from party {}", party_id),
			Self::PkCommitmentMismatch { party_id, subset } =>
				write!(f, "PK commitment mismatch from party {} for subset {:b}", party_id, subset),
			Self::PkVerificationFailed { party_id, subset } =>
				write!(f, "PK verification failed from party {} for subset {:b}", party_id, subset),
			Self::SignatureVerificationFailed { party_id } =>
				write!(f, "signature verification failed from party {}", party_id),
			Self::MissingData(msg) => write!(f, "missing data: {}", msg),
			Self::InvalidMessage(msg) => write!(f, "invalid message: {}", msg),
			Self::InternalError(msg) => write!(f, "internal error: {}", msg),
			Self::MalformedMessage { from, reason } =>
				write!(f, "malformed message from party {}: {}", from, reason),
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
/// - `SendMany`: Broadcast the data to all other participants
/// - `SendPrivate`: Send the data to a specific participant via secure channel
/// - `Return`: The DKG is complete, the output contains the keys
///
/// `Return` carries a boxed [`MithrilDkgOutput`] because the output is ~2.8 KB
/// (full Dilithium key material) and inlining it would balloon every other
/// variant. See `clippy::large_enum_variant`.
#[derive(Debug)]
pub enum MithrilAction {
	/// Wait for more messages before proceeding.
	Wait,
	/// Broadcast data to all other participants.
	SendMany(Vec<u8>),
	/// Send data privately to a specific participant.
	SendPrivate(ParticipantId, Vec<u8>),
	/// DKG is complete, return the output.
	Return(Box<MithrilDkgOutput>),
}

// ============================================================================
// Protocol Implementation
// ============================================================================

/// The main DKG protocol state machine.
///
/// This implements the 4-round Mithril DKG protocol. Create an instance with
/// [`MithrilDkg::new`], then repeatedly call [`MithrilDkg::poke`] and
/// [`MithrilDkg::message`] to drive the protocol.
///
/// # Example
///
/// ```ignore
/// let config = MithrilDkgConfig::new(...)?;
/// let mut dkg = MithrilDkg::new(config, rng);
///
/// loop {
///     match dkg.poke()? {
///         MithrilAction::Wait => { /* wait for messages */ }
///         MithrilAction::SendMany(data) => { /* broadcast to all */ }
///         MithrilAction::SendPrivate(to, data) => { /* send to one party */ }
///         MithrilAction::Return(output) => {
///             // DKG complete!
///             return Ok(output);
///         }
///     }
///     // When messages arrive: dkg.message(from, data);
/// }
/// ```
pub struct MithrilDkg<S: TranscriptSigner, R: RngCore + CryptoRng> {
	state: MithrilDkgState<S>,
	rng: R,
	pending_privates: Vec<(ParticipantId, Vec<u8>)>,
}

impl<S: TranscriptSigner, R: RngCore + CryptoRng> MithrilDkg<S, R> {
	/// Create a new DKG instance.
	///
	/// # Arguments
	/// * `config` - The DKG configuration including threshold, participants, and signing keys
	/// * `rng` - A cryptographically secure random number generator
	pub fn new(config: MithrilDkgConfig<S>, rng: R) -> Self {
		Self { state: MithrilDkgState::new(config), rng, pending_privates: Vec::new() }
	}

	/// Advance the protocol state machine.
	///
	/// Call this method repeatedly to drive the protocol forward. It returns
	/// an action that the caller should perform (broadcast, send private, wait,
	/// or return the final output).
	///
	/// # Returns
	/// * `Ok(MithrilAction)` - The action to perform
	/// * `Err(MithrilDkgError)` - If the protocol encounters an error
	pub fn poke(&mut self) -> Result<MithrilAction, MithrilDkgError> {
		if let Some((to, data)) = self.pending_privates.pop() {
			return Ok(MithrilAction::SendPrivate(to, data));
		}

		match &self.state {
			MithrilDkgState::Initialized(_) => self.start_round1(),
			MithrilDkgState::Round1(_) => self.process_round1(),
			MithrilDkgState::Round2(_) => self.process_round2(),
			MithrilDkgState::Round3(_) => self.process_round3(),
			MithrilDkgState::Round4(_) => self.process_round4(),
			MithrilDkgState::Complete(output) => Ok(MithrilAction::Return(output.clone())),
			MithrilDkgState::Failed(msg) => Err(MithrilDkgError::InvalidState(msg.clone())),
		}
	}

	/// Process an incoming message from another party.
	///
	/// Call this method when a message is received from another DKG participant.
	/// Messages with sender mismatches or for wrong rounds are ignored with `Ok(())`.
	///
	/// # Arguments
	/// * `from` - The party ID of the sender
	/// * `data` - The serialized message bytes
	///
	/// # Errors
	///
	/// Returns `Err(MithrilDkgError::MalformedMessage)` if the message cannot be
	/// deserialized. This allows callers to detect and log malformed messages.
	///
	/// # Returns
	///
	/// * `Ok(())` - Message was processed (or legitimately ignored)
	/// * `Err(_)` - Message was malformed and could not be deserialized
	pub fn message(&mut self, from: ParticipantId, data: Vec<u8>) -> Result<(), MithrilDkgError> {
		let msg: MithrilDkgMessage = match bincode::deserialize(&data) {
			Ok(m) => m,
			Err(e) => {
				return Err(MithrilDkgError::MalformedMessage { from, reason: e.to_string() });
			},
		};

		match (&mut self.state, msg) {
			(MithrilDkgState::Round1(state), MithrilDkgMessage::Round1Broadcast(broadcast)) =>
				if broadcast.party_id == from {
					state.received_broadcasts.insert(from, broadcast);
				},
			(MithrilDkgState::Round1(state), MithrilDkgMessage::Round1Private(private)) =>
				if private.from_party_id == from {
					state
						.received_shared_secrets
						.insert(private.subset_mask, private.shared_secret);
				},
			(MithrilDkgState::Round2(state), MithrilDkgMessage::Round2Broadcast(broadcast)) =>
				if broadcast.party_id == from {
					state.received_broadcasts.insert(from, broadcast);
				},
			(MithrilDkgState::Round3(state), MithrilDkgMessage::Round3Broadcast(broadcast)) =>
				if broadcast.party_id == from {
					state.received_broadcasts.insert(from, broadcast);
				},
			(MithrilDkgState::Round4(state), MithrilDkgMessage::Round4Broadcast(broadcast)) =>
				if broadcast.party_id == from {
					state.received_broadcasts.insert(from, broadcast);
				},
			_ => {},
		}

		Ok(())
	}

	// ========================================================================
	// Round 1
	// ========================================================================

	fn start_round1(&mut self) -> Result<MithrilAction, MithrilDkgError> {
		let config =
			match mem::replace(&mut self.state, MithrilDkgState::Failed("transitioning".into())) {
				MithrilDkgState::Initialized(c) => c,
				_ => return Err(MithrilDkgError::InvalidState("expected Initialized".into())),
			};

		let mut my_randomness = [0u8; RANDOMNESS_SIZE];
		self.rng.fill_bytes(&mut my_randomness);

		let my_commitment = h_commit(config.my_party_id, &my_randomness);

		let mut my_shared_secrets = BTreeMap::new();
		for subset in config.my_leader_subsets() {
			let mut secret = [0u8; SHARED_SECRET_SIZE];
			self.rng.fill_bytes(&mut secret);
			my_shared_secrets.insert(subset, secret);
		}

		self.state = MithrilDkgState::Round1(MithrilRound1State {
			config,
			my_randomness,
			my_commitment,
			my_shared_secrets,
			received_broadcasts: BTreeMap::new(),
			received_shared_secrets: BTreeMap::new(),
			broadcast_sent: false,
			privates_sent: false,
		});

		self.poke()
	}

	fn process_round1(&mut self) -> Result<MithrilAction, MithrilDkgError> {
		let state = match &mut self.state {
			MithrilDkgState::Round1(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round1".into())),
		};

		if !state.broadcast_sent {
			let broadcast = MithrilRound1Broadcast {
				party_id: state.config.my_party_id,
				commitment: state.my_commitment,
			};
			let msg = MithrilDkgMessage::Round1Broadcast(broadcast);
			let data = bincode::serialize(&msg)
				.map_err(|e| MithrilDkgError::InternalError(e.to_string()))?;
			state.broadcast_sent = true;
			return Ok(MithrilAction::SendMany(data));
		}

		if !state.privates_sent {
			for (&subset, &secret) in &state.my_shared_secrets {
				let parties = state.config.get_parties_in_subset(subset);
				for &party in &parties {
					if party != state.config.my_party_id {
						let private = MithrilRound1Private {
							from_party_id: state.config.my_party_id,
							subset_mask: subset,
							shared_secret: secret,
						};
						let msg = MithrilDkgMessage::Round1Private(private);
						let data = bincode::serialize(&msg)
							.map_err(|e| MithrilDkgError::InternalError(e.to_string()))?;
						self.pending_privates.push((party, data));
					}
				}
			}

			if let MithrilDkgState::Round1(s) = &mut self.state {
				s.privates_sent = true;
			}

			if let Some((to, data)) = self.pending_privates.pop() {
				return Ok(MithrilAction::SendPrivate(to, data));
			}
		}

		let state = match &self.state {
			MithrilDkgState::Round1(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round1".into())),
		};

		let all_broadcasts = all_broadcasts_received(
			&state.received_broadcasts,
			&state.config.all_participants,
			state.config.my_party_id,
		);
		let my_subsets = state.config.my_subsets();
		let all_privates = all_private_messages_received(
			&state.received_shared_secrets,
			&state.my_shared_secrets,
			&my_subsets,
		);

		if all_broadcasts && all_privates {
			self.transition_to_round2()?;
			return self.poke();
		}

		Ok(MithrilAction::Wait)
	}

	fn transition_to_round2(&mut self) -> Result<(), MithrilDkgError> {
		let old_state =
			mem::replace(&mut self.state, MithrilDkgState::Failed("transitioning".into()));

		let state = match old_state {
			MithrilDkgState::Round1(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round1".into())),
		};

		let mut shared_secrets = state.my_shared_secrets;
		for (subset, secret) in state.received_shared_secrets {
			shared_secrets.insert(subset, secret);
		}

		self.state = MithrilDkgState::Round2(MithrilRound2State {
			config: state.config,
			my_randomness: state.my_randomness,
			round1_broadcasts: state.received_broadcasts,
			shared_secrets,
			received_broadcasts: BTreeMap::new(),
			broadcast_sent: false,
		});

		Ok(())
	}

	// ========================================================================
	// Round 2
	// ========================================================================

	fn process_round2(&mut self) -> Result<MithrilAction, MithrilDkgError> {
		let state = match &mut self.state {
			MithrilDkgState::Round2(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round2".into())),
		};

		if !state.broadcast_sent {
			let broadcast = MithrilRound2Broadcast {
				party_id: state.config.my_party_id,
				randomness: state.my_randomness,
			};
			let msg = MithrilDkgMessage::Round2Broadcast(broadcast);
			let data = bincode::serialize(&msg)
				.map_err(|e| MithrilDkgError::InternalError(e.to_string()))?;
			state.broadcast_sent = true;
			return Ok(MithrilAction::SendMany(data));
		}

		let state = match &self.state {
			MithrilDkgState::Round2(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round2".into())),
		};

		let all_broadcasts = all_broadcasts_received(
			&state.received_broadcasts,
			&state.config.all_participants,
			state.config.my_party_id,
		);

		if all_broadcasts {
			// Verify commitments
			for (&party_id, broadcast) in &state.received_broadcasts {
				let expected = state.round1_broadcasts.get(&party_id).ok_or_else(|| {
					MithrilDkgError::MissingData(format!("missing Round 1 from party {}", party_id))
				})?;
				let actual = h_commit(party_id, &broadcast.randomness);
				if actual != expected.commitment {
					return Err(MithrilDkgError::CommitmentMismatch { party_id });
				}
			}

			self.transition_to_round3()?;
			return self.poke();
		}

		Ok(MithrilAction::Wait)
	}

	fn transition_to_round3(&mut self) -> Result<(), MithrilDkgError> {
		let old_state =
			mem::replace(&mut self.state, MithrilDkgState::Failed("transitioning".into()));

		let state = match old_state {
			MithrilDkgState::Round2(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round2".into())),
		};

		// Compute global randomness
		let mut all_randomness: Vec<_> = state.received_broadcasts.iter().collect();
		let my_broadcast = MithrilRound2Broadcast {
			party_id: state.config.my_party_id,
			randomness: state.my_randomness,
		};
		all_randomness.push((&state.config.my_party_id, &my_broadcast));
		all_randomness.sort_by_key(|(id, _)| *id);

		let mut global_randomness = Vec::with_capacity(all_randomness.len() * RANDOMNESS_SIZE);
		for (_, broadcast) in &all_randomness {
			global_randomness.extend_from_slice(&broadcast.randomness);
		}

		let rho = h_seed(&global_randomness);

		// Compute contributions for leader subsets
		let my_leader_subsets = state.config.my_leader_subsets();
		let mut my_contributions = BTreeMap::new();
		let mut my_partial_pks = BTreeMap::new();
		let mut my_pk_commitments = BTreeMap::new();

		for &subset in &my_leader_subsets {
			if let Some(&shared_secret) = state.shared_secrets.get(&subset) {
				let seed = h_keygen(subset, &shared_secret, &global_randomness);
				let contribution = derive_subset_contribution(&seed, ETA);
				let partial_pk = compute_partial_pk(&rho, &contribution, subset);
				let pk_commitment = h_commit_pk(subset, &partial_pk);

				my_contributions.insert(subset, contribution);
				my_partial_pks.insert(subset, partial_pk);
				my_pk_commitments.insert(subset, pk_commitment);
			}
		}

		// Compute contributions for non-leader subsets
		for &subset in &state.config.my_subsets() {
			if let alloc::collections::btree_map::Entry::Vacant(e) = my_contributions.entry(subset)
			{
				if let Some(&shared_secret) = state.shared_secrets.get(&subset) {
					let seed = h_keygen(subset, &shared_secret, &global_randomness);
					let contribution = derive_subset_contribution(&seed, ETA);
					e.insert(contribution);
				}
			}
		}

		// Reconstruct broadcasts including our own
		let mut round1_broadcasts = state.round1_broadcasts;
		round1_broadcasts.insert(
			state.config.my_party_id,
			MithrilRound1Broadcast {
				party_id: state.config.my_party_id,
				commitment: h_commit(state.config.my_party_id, &state.my_randomness),
			},
		);

		let mut round2_broadcasts = state.received_broadcasts;
		round2_broadcasts.insert(state.config.my_party_id, my_broadcast);

		self.state = MithrilDkgState::Round3(MithrilRound3State {
			config: state.config,
			round1_broadcasts,
			round2_broadcasts,
			shared_secrets: state.shared_secrets,
			global_randomness,
			rho,
			my_partial_pks,
			my_contributions,
			my_pk_commitments,
			received_broadcasts: BTreeMap::new(),
			broadcast_sent: false,
		});

		Ok(())
	}

	// ========================================================================
	// Round 3
	// ========================================================================

	fn process_round3(&mut self) -> Result<MithrilAction, MithrilDkgError> {
		let state = match &mut self.state {
			MithrilDkgState::Round3(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round3".into())),
		};

		if !state.broadcast_sent {
			let broadcast = MithrilRound3Broadcast {
				party_id: state.config.my_party_id,
				partial_pk_commitments: state.my_pk_commitments.clone(),
			};
			let msg = MithrilDkgMessage::Round3Broadcast(broadcast);
			let data = bincode::serialize(&msg)
				.map_err(|e| MithrilDkgError::InternalError(e.to_string()))?;
			state.broadcast_sent = true;
			return Ok(MithrilAction::SendMany(data));
		}

		let state = match &self.state {
			MithrilDkgState::Round3(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round3".into())),
		};

		let all_broadcasts = all_broadcasts_received(
			&state.received_broadcasts,
			&state.config.all_participants,
			state.config.my_party_id,
		);

		if all_broadcasts {
			self.transition_to_round4()?;
			return self.poke();
		}

		Ok(MithrilAction::Wait)
	}

	fn transition_to_round4(&mut self) -> Result<(), MithrilDkgError> {
		let old_state =
			mem::replace(&mut self.state, MithrilDkgState::Failed("transitioning".into()));

		let state = match old_state {
			MithrilDkgState::Round3(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round3".into())),
		};

		let mut round3_broadcasts = state.received_broadcasts;
		round3_broadcasts.insert(
			state.config.my_party_id,
			MithrilRound3Broadcast {
				party_id: state.config.my_party_id,
				partial_pk_commitments: state.my_pk_commitments.clone(),
			},
		);

		self.state = MithrilDkgState::Round4(MithrilRound4State {
			config: state.config,
			round1_broadcasts: state.round1_broadcasts,
			round2_broadcasts: state.round2_broadcasts,
			round3_broadcasts,
			shared_secrets: state.shared_secrets,
			global_randomness: state.global_randomness,
			rho: state.rho,
			my_partial_pks: state.my_partial_pks,
			my_contributions: state.my_contributions,
			received_broadcasts: BTreeMap::new(),
			broadcast_sent: false,
		});

		Ok(())
	}

	// ========================================================================
	// Round 4
	// ========================================================================

	fn process_round4(&mut self) -> Result<MithrilAction, MithrilDkgError> {
		let state = match &mut self.state {
			MithrilDkgState::Round4(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round4".into())),
		};

		if !state.broadcast_sent {
			// Per Mithril paper DKGRound4 lines 11-16: Non-leaders MUST verify
			// PK commitments BEFORE signing the transcript. This ensures we don't
			// sign a transcript containing invalid commitments from malicious leaders.
			for &subset in &state.config.my_subsets() {
				let leader_id = state.config.get_leader(subset).ok_or_else(|| {
					MithrilDkgError::InternalError(format!("no leader for subset {:b}", subset))
				})?;
				if leader_id != state.config.my_party_id {
					// I'm not the leader for this subset - verify the leader's commitment
					if let Some(contribution) = state.my_contributions.get(&subset) {
						// Compute my expected partial PK
						let expected_pk = compute_partial_pk(&state.rho, contribution, subset);
						let expected_commitment = h_commit_pk(subset, &expected_pk);

						// Get the leader's commitment from Round 3
						let round3 = state.round3_broadcasts.get(&leader_id).ok_or_else(|| {
							MithrilDkgError::MissingData(format!(
								"missing Round 3 from leader {} for subset {:b}",
								leader_id, subset
							))
						})?;

						let leader_commitment =
							round3.partial_pk_commitments.get(&subset).ok_or_else(|| {
								MithrilDkgError::MissingData(format!(
									"missing PK commitment from leader {} for subset {:b}",
									leader_id, subset
								))
							})?;

						if *leader_commitment != expected_commitment {
							return Err(MithrilDkgError::PkCommitmentMismatch {
								party_id: leader_id,
								subset,
							});
						}
					}
				}
			}

			let transcript_hash = compute_transcript_hash(
				&state.round1_broadcasts,
				&state.round2_broadcasts,
				&state.round3_broadcasts,
			);
			let partial_output_hash = compute_partial_output_hash(&state.my_partial_pks);
			let signing_message = compute_signing_message(&transcript_hash, &partial_output_hash);
			let signature = state.config.my_signer.sign(&signing_message);

			let broadcast = MithrilRound4Broadcast {
				party_id: state.config.my_party_id,
				partial_public_keys: state.my_partial_pks.clone(),
				transcript_signature: signature.as_ref().to_vec(),
			};
			let msg = MithrilDkgMessage::Round4Broadcast(broadcast);
			let data = bincode::serialize(&msg)
				.map_err(|e| MithrilDkgError::InternalError(e.to_string()))?;
			state.broadcast_sent = true;
			return Ok(MithrilAction::SendMany(data));
		}

		let state = match &self.state {
			MithrilDkgState::Round4(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round4".into())),
		};

		let all_broadcasts = all_broadcasts_received(
			&state.received_broadcasts,
			&state.config.all_participants,
			state.config.my_party_id,
		);

		if all_broadcasts {
			self.complete()?;
			return self.poke();
		}

		Ok(MithrilAction::Wait)
	}

	fn complete(&mut self) -> Result<(), MithrilDkgError> {
		let old_state =
			mem::replace(&mut self.state, MithrilDkgState::Failed("transitioning".into()));

		let state = match old_state {
			MithrilDkgState::Round4(s) => s,
			_ => return Err(MithrilDkgError::InvalidState("expected Round4".into())),
		};

		let transcript_hash = compute_transcript_hash(
			&state.round1_broadcasts,
			&state.round2_broadcasts,
			&state.round3_broadcasts,
		);

		// Collect and verify partial PKs
		let mut all_partial_pks: BTreeMap<SubsetMask, PartialPublicKey> = BTreeMap::new();

		for (subset, pk) in &state.my_partial_pks {
			all_partial_pks.insert(*subset, pk.clone());
		}

		for (&party_id, broadcast) in &state.received_broadcasts {
			let partial_output_hash = compute_partial_output_hash(&broadcast.partial_public_keys);
			let signing_message = compute_signing_message(&transcript_hash, &partial_output_hash);

			let public_key =
				state.config.participant_public_keys.get(&party_id).ok_or_else(|| {
					MithrilDkgError::MissingData(format!(
						"missing public key for party {}",
						party_id
					))
				})?;

			// Verify transcript signature
			if !S::verify_bytes(public_key, &signing_message, &broadcast.transcript_signature) {
				return Err(MithrilDkgError::SignatureVerificationFailed { party_id });
			}

			// Verify PK commitments
			let round3 = state.round3_broadcasts.get(&party_id).ok_or_else(|| {
				MithrilDkgError::MissingData(format!("missing Round 3 from party {}", party_id))
			})?;

			for (&subset, pk) in &broadcast.partial_public_keys {
				let expected = round3.partial_pk_commitments.get(&subset).ok_or_else(|| {
					MithrilDkgError::MissingData(format!(
						"missing PK commitment from party {} for subset {:b}",
						party_id, subset
					))
				})?;
				let actual = h_commit_pk(subset, pk);
				if actual != *expected {
					return Err(MithrilDkgError::PkCommitmentMismatch { party_id, subset });
				}

				// Verify PK if we have the shared secret
				if let Some(&shared_secret) = state.shared_secrets.get(&subset) {
					let seed = h_keygen(subset, &shared_secret, &state.global_randomness);
					let expected_contribution = derive_subset_contribution(&seed, ETA);
					let expected_pk =
						compute_partial_pk(&state.rho, &expected_contribution, subset);
					if pk.t != expected_pk.t {
						return Err(MithrilDkgError::PkVerificationFailed { party_id, subset });
					}
				}

				all_partial_pks.insert(subset, pk.clone());
			}
		}

		// Combine partial PKs to get final public key
		let public_key = combine_partial_pks(&state.rho, &all_partial_pks)?;

		// Build private key share
		let private_share = build_private_share(&state, &public_key)?;

		self.state =
			MithrilDkgState::Complete(Box::new(MithrilDkgOutput { public_key, private_share }));

		Ok(())
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

fn compute_partial_pk(
	rho: &[u8; 32],
	contribution: &SubsetContribution,
	subset_mask: SubsetMask,
) -> PartialPublicKey {
	let t = crate::protocol::partial_pk::compute_partial_pk_t(
		rho,
		&contribution.s1,
		&contribution.s2,
	);
	PartialPublicKey { subset_mask, t }
}

fn combine_partial_pks(
	rho: &[u8; 32],
	partial_pks: &BTreeMap<SubsetMask, PartialPublicKey>,
) -> Result<PublicKey, MithrilDkgError> {
	Ok(crate::protocol::partial_pk::pack_combined_pk(
		rho,
		partial_pks.values().map(|pk| &pk.t),
	))
}

fn build_private_share<S: TranscriptSigner>(
	state: &MithrilRound4State<S>,
	public_key: &PublicKey,
) -> Result<PrivateKeyShare, MithrilDkgError> {
	let dkg_participants = ParticipantList::new(&state.config.all_participants)
		.ok_or_else(|| MithrilDkgError::InternalError("invalid participants".into()))?;

	let mut combined_shares: BTreeMap<SubsetMask, SecretShareData> = BTreeMap::new();
	for (subset_mask, contribution) in &state.my_contributions {
		combined_shares.insert(
			*subset_mask,
			SecretShareData { s1: contribution.s1.clone(), s2: contribution.s2.clone() },
		);
	}

	// Derive `party_key` from the actual secret share polynomials so that this byte
	// string carries real entropy, not just a hash of the public `rho` and `party_id`.
	// We still mix in `rho` and `party_id` for domain separation, but the security of
	// `party_key` now depends on knowing the secret subset shares.
	let mut party_key = [0u8; 32];
	{
		let mut h = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut h, b"dkg-party-key-v2", 16);
		fips202::shake256_absorb(&mut h, &state.rho, 32);
		fips202::shake256_absorb(&mut h, &state.config.my_party_id.to_le_bytes(), 4);
		let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
		for (subset_mask, contribution) in &state.my_contributions {
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
			fips202::shake256_absorb(&mut h, &buf, buf.len());
		}
		fips202::shake256_finalize(&mut h);
		fips202::shake256_squeeze(&mut party_key, 32, &mut h);
	}

	// Use the TR from the public key (tr = H(pk))
	let tr = *public_key.tr();

	Ok(PrivateKeyShare::new(
		state.config.my_party_id,
		state.config.total_parties(),
		state.config.threshold(),
		party_key,
		state.rho,
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
/// * `rng` - Random number generator (will be cloned for each party)
///
/// # Returns
/// A vector of `MithrilDkgOutput` structs, one for each party, containing
/// the shared public key and each party's private key share.
///
/// # Example
///
/// ```ignore
/// let signers: Vec<MySigner> = (0..3).map(|id| MySigner::new(id)).collect();
/// let public_keys: Vec<_> = signers.iter().map(|s| s.public_key()).collect();
/// let rng = rand::rngs::StdRng::seed_from_u64(42);
///
/// let outputs = run_local_mithril_dkg(2, 3, signers, public_keys, rng)?;
/// // All parties have the same public key
/// assert_eq!(outputs[0].public_key, outputs[1].public_key);
/// ```
pub fn run_local_mithril_dkg<S, R>(
	threshold: u32,
	total_parties: u32,
	signers: Vec<S>,
	public_keys: Vec<S::PublicKey>,
	rng: R,
) -> Result<Vec<MithrilDkgOutput>, MithrilDkgError>
where
	S: TranscriptSigner + Clone,
	R: RngCore + CryptoRng + Clone,
{
	let threshold_config = ThresholdConfig::new(threshold, total_parties)
		.map_err(|e| MithrilDkgError::InternalError(e.to_string()))?;

	let participants: Vec<ParticipantId> = (0..total_parties).collect();

	let mut pk_map: BTreeMap<ParticipantId, S::PublicKey> = BTreeMap::new();
	for (i, pk) in public_keys.into_iter().enumerate() {
		pk_map.insert(i as ParticipantId, pk);
	}

	let mut dkgs: Vec<MithrilDkg<S, R>> = signers
		.into_iter()
		.enumerate()
		.map(|(i, signer)| {
			let config = MithrilDkgConfig::new(
				threshold_config,
				i as ParticipantId,
				participants.clone(),
				signer,
				pk_map.clone(),
			)
			.unwrap();
			MithrilDkg::new(config, rng.clone())
		})
		.collect();

	let mut outputs: Vec<Option<MithrilDkgOutput>> = vec![None; total_parties as usize];
	let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> =
		vec![Vec::new(); total_parties as usize];

	let mut iterations = 0;
	const MAX_ITERATIONS: usize = 1000;

	while outputs.iter().any(|o| o.is_none()) {
		iterations += 1;
		if iterations > MAX_ITERATIONS {
			return Err(MithrilDkgError::InternalError("DKG did not complete in time".into()));
		}

		// Deliver pending messages
		for party_id in 0..total_parties as usize {
			let messages = mem::take(&mut pending_messages[party_id]);
			for (from, data) in messages {
				dkgs[party_id].message(from, data)?;
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
					MithrilAction::Wait => {},
					MithrilAction::SendMany(data) => {
						made_progress = true;
						let from = party_id as ParticipantId;
						for (other, pending) in pending_messages.iter_mut().enumerate() {
							if other != party_id {
								pending.push((from, data.clone()));
							}
						}
					},
					MithrilAction::SendPrivate(to, data) => {
						made_progress = true;
						let from = party_id as ParticipantId;
						pending_messages[to as usize].push((from, data));
					},
					MithrilAction::Return(output) => {
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
	use rand::SeedableRng;

	#[derive(Clone, Debug)]
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
	fn test_mithril_dkg_2_of_3() {
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let rng = rand::rngs::StdRng::seed_from_u64(42);

		let result = run_local_mithril_dkg(2, 3, signers, public_keys, rng);

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

	#[test]
	fn test_mithril_dkg_eta_bounded() {
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let rng = rand::rngs::StdRng::seed_from_u64(123);

		let outputs = run_local_mithril_dkg(2, 3, signers, public_keys, rng).unwrap();

		for (party_id, output) in outputs.iter().enumerate() {
			let shares = output.private_share.shares();
			for (subset_mask, share) in shares {
				for (poly_idx, poly) in share.s1.iter().enumerate() {
					for (coeff_idx, &coeff) in poly.iter().enumerate() {
						assert!(
							coeff >= -ETA && coeff <= ETA,
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
							coeff >= -ETA && coeff <= ETA,
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
	fn test_mithril_dkg_with_dilithium_signing() {
		use qp_rusty_crystals_dilithium::{
			ml_dsa_87::{Keypair, PublicKey, SecretKey, SIGNBYTES},
			SensitiveBytes32,
		};

		#[derive(Clone)]
		struct DilithiumSigner {
			sk: SecretKey,
			pk: PublicKey,
		}

		impl std::fmt::Debug for DilithiumSigner {
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
			signers.push(DilithiumSigner { sk: keypair.secret.clone(), pk: keypair.public });
		}

		let rng = rand::rngs::StdRng::seed_from_u64(456);
		let outputs = run_local_mithril_dkg(2, 3, signers, public_keys, rng).unwrap();

		// Verify DKG succeeded
		assert_eq!(outputs.len(), 3);

		// All parties should have the same public key
		let pk0 = outputs[0].public_key.as_bytes();
		for output in &outputs[1..] {
			assert_eq!(pk0, output.public_key.as_bytes());
		}

		// Verify η-bounded shares
		for output in &outputs {
			for (_, share) in output.private_share.shares() {
				for poly in &share.s1 {
					for &coeff in poly {
						assert!(coeff >= -ETA && coeff <= ETA);
					}
				}
				for poly in &share.s2 {
					for &coeff in poly {
						assert!(coeff >= -ETA && coeff <= ETA);
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
	fn test_mithril_dkg_rejects_bad_signature() {
		// A signer that produces bad signatures for party 2
		#[derive(Clone, Debug)]
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

		let rng = rand::rngs::StdRng::seed_from_u64(789);

		let mut dkgs: Vec<MithrilDkg<BadSigner, _>> = signers
			.into_iter()
			.enumerate()
			.map(|(i, signer)| {
				let config = MithrilDkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer,
					pk_map.clone(),
				)
				.unwrap();
				MithrilDkg::new(config, rng.clone())
			})
			.collect();

		let mut outputs: Vec<Option<MithrilDkgOutput>> = vec![None; 3];
		let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); 3];
		let mut errors: Vec<Option<MithrilDkgError>> = vec![None; 3];

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
						Ok(MithrilAction::Wait) => {},
						Ok(MithrilAction::SendMany(data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							for (other, pending) in pending_messages.iter_mut().enumerate() {
								if other != party_id {
									pending.push((from, data.clone()));
								}
							}
						},
						Ok(MithrilAction::SendPrivate(to, data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							pending_messages[to as usize].push((from, data));
						},
						Ok(MithrilAction::Return(output)) => {
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
		let has_sig_error = errors.iter().any(|e| {
			matches!(e, Some(MithrilDkgError::SignatureVerificationFailed { party_id: 2 }))
		});

		// Print debug info
		for (party_id, error) in errors.iter().enumerate() {
			if let Some(e) = error {
				println!("Party {} got error: {:?}", party_id, e);
			}
		}
		for (party_id, output) in outputs.iter().enumerate() {
			if output.is_some() {
				println!("Party {} completed successfully", party_id);
			}
		}

		assert!(has_sig_error, "At least one honest party should reject party 2's bad signature");
	}

	/// Test that DKG rejects bad randomness commitment (Round 2 reveal doesn't match Round 1
	/// commit).
	#[test]
	fn test_mithril_dkg_rejects_bad_commitment() {
		// We'll intercept and modify party 2's Round 2 message to have wrong randomness
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();

		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let participants: Vec<ParticipantId> = (0..3).collect();

		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		for (i, pk) in public_keys.into_iter().enumerate() {
			pk_map.insert(i as ParticipantId, pk);
		}

		let rng = rand::rngs::StdRng::seed_from_u64(555);

		let mut dkgs: Vec<MithrilDkg<TestSigner, _>> = signers
			.into_iter()
			.enumerate()
			.map(|(i, signer)| {
				let config = MithrilDkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer,
					pk_map.clone(),
				)
				.unwrap();
				MithrilDkg::new(config, rng.clone())
			})
			.collect();

		let mut outputs: Vec<Option<MithrilDkgOutput>> = vec![None; 3];
		let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); 3];
		let mut errors: Vec<Option<MithrilDkgError>> = vec![None; 3];

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
						if let Ok(msg) = bincode::deserialize::<MithrilDkgMessage>(&data) {
							if let MithrilDkgMessage::Round2Broadcast(mut r2) = msg {
								// Corrupt the randomness
								r2.randomness[0] ^= 0xFF;
								let tampered = MithrilDkgMessage::Round2Broadcast(r2);
								data = bincode::serialize(&tampered).unwrap();
							}
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
						Ok(MithrilAction::Wait) => {},
						Ok(MithrilAction::SendMany(data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							for (other, pending) in pending_messages.iter_mut().enumerate() {
								if other != party_id {
									pending.push((from, data.clone()));
								}
							}
						},
						Ok(MithrilAction::SendPrivate(to, data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							pending_messages[to as usize].push((from, data));
						},
						Ok(MithrilAction::Return(output)) => {
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
			.any(|e| matches!(e, Some(MithrilDkgError::CommitmentMismatch { party_id: 2 })));

		assert!(has_commitment_error, "At least one party should reject party 2's bad commitment");
	}

	/// Test that non-leaders detect tampered PK commitments in Round 4 before signing.
	/// Per Mithril paper DKGRound4 lines 11-16: non-leaders verify PK commitments BEFORE signing.
	#[test]
	fn test_mithril_dkg_rejects_bad_pk_commitment() {
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

		let rng = rand::rngs::StdRng::seed_from_u64(888);

		let mut dkgs: Vec<MithrilDkg<TestSigner, _>> = signers
			.into_iter()
			.enumerate()
			.map(|(i, signer)| {
				let config = MithrilDkgConfig::new(
					threshold_config,
					i as ParticipantId,
					participants.clone(),
					signer,
					pk_map.clone(),
				)
				.unwrap();
				MithrilDkg::new(config, rng.clone())
			})
			.collect();

		let mut outputs: Vec<Option<MithrilDkgOutput>> = vec![None; 3];
		let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> = vec![Vec::new(); 3];
		let mut errors: Vec<Option<MithrilDkgError>> = vec![None; 3];

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
						if let Ok(msg) = bincode::deserialize::<MithrilDkgMessage>(&data) {
							if let MithrilDkgMessage::Round3Broadcast(mut r3) = msg {
								// Corrupt a PK commitment for subset 0b101 where party 2 is a
								// member
								if let Some(commitment) = r3.partial_pk_commitments.get_mut(&0b101)
								{
									commitment[0] ^= 0xFF;
								}
								let tampered = MithrilDkgMessage::Round3Broadcast(r3);
								data = bincode::serialize(&tampered).unwrap();
							}
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
						Ok(MithrilAction::Wait) => {},
						Ok(MithrilAction::SendMany(data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							for (other, pending) in pending_messages.iter_mut().enumerate() {
								if other != party_id {
									pending.push((from, data.clone()));
								}
							}
						},
						Ok(MithrilAction::SendPrivate(to, data)) => {
							made_progress = true;
							let from = party_id as ParticipantId;
							pending_messages[to as usize].push((from, data));
						},
						Ok(MithrilAction::Return(output)) => {
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
				Some(MithrilDkgError::PkCommitmentMismatch { party_id: 0, subset: 0b101 })
			),
			"Party 2 should detect party 0's bad PK commitment for subset 0b101, got: {:?}",
			party2_error
		);
	}

	/// Test DKG with 3-of-5 threshold.
	#[test]
	fn test_mithril_dkg_3_of_5() {
		let signers: Vec<TestSigner> = (0..5).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..5).collect();
		let rng = rand::rngs::StdRng::seed_from_u64(12345);

		let outputs = run_local_mithril_dkg(3, 5, signers, public_keys, rng).unwrap();

		assert_eq!(outputs.len(), 5);

		// All parties should have the same public key
		let pk0 = outputs[0].public_key.as_bytes();
		for output in &outputs[1..] {
			assert_eq!(pk0, output.public_key.as_bytes());
		}

		// Verify η-bounded shares
		for output in &outputs {
			for (_, share) in output.private_share.shares() {
				for poly in &share.s1 {
					for &coeff in poly {
						assert!(coeff >= -ETA && coeff <= ETA);
					}
				}
				for poly in &share.s2 {
					for &coeff in poly {
						assert!(coeff >= -ETA && coeff <= ETA);
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
	fn test_mithril_dkg_subset_share_consistency() {
		let signers: Vec<TestSigner> = (0..3).map(|id| TestSigner { id }).collect();
		let public_keys: Vec<u32> = (0..3).collect();
		let rng = rand::rngs::StdRng::seed_from_u64(777);

		let outputs = run_local_mithril_dkg(2, 3, signers, public_keys, rng).unwrap();

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
	fn test_mithril_dkg_config_validation() {
		let threshold_config = ThresholdConfig::new(2, 3).unwrap();
		let mut pk_map: BTreeMap<ParticipantId, u32> = BTreeMap::new();
		pk_map.insert(0, 0);
		pk_map.insert(1, 1);
		pk_map.insert(2, 2);

		// Valid config should work
		let result = MithrilDkgConfig::new(
			threshold_config,
			0,
			vec![0, 1, 2],
			TestSigner { id: 0 },
			pk_map.clone(),
		);
		assert!(result.is_ok());

		// Wrong participant count
		let result = MithrilDkgConfig::new(
			threshold_config,
			0,
			vec![0, 1], // Only 2 participants but config says 3
			TestSigner { id: 0 },
			pk_map.clone(),
		);
		assert!(result.is_err());

		// Party not in participants
		let result = MithrilDkgConfig::new(
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
		let result = MithrilDkgConfig::new(
			threshold_config,
			0,
			vec![0, 1, 2],
			TestSigner { id: 0 },
			incomplete_pk_map,
		);
		assert!(result.is_err());
	}
}
