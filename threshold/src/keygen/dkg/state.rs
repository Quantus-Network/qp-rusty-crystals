//! State structures for the Mithril DKG protocol.
//!
//! These are internal state structures used by the DKG state machine.
//! They track the progress through each round and store intermediate values.

#![allow(missing_docs)] // Internal state structures don't need public docs

use std::collections::{BTreeMap, HashMap};

use crate::keys::{PrivateKeyShare, PublicKey};

use super::types::{
	MithrilDkgConfig, MithrilRound1Broadcast, MithrilRound2Broadcast, MithrilRound3Broadcast,
	MithrilRound4Broadcast, PartialPublicKey, ParticipantId, SubsetContribution, SubsetMask,
	TranscriptSigner, RANDOMNESS_SIZE, SHARED_SECRET_SIZE,
};

/// State for Round 1.
pub struct MithrilRound1State<S: TranscriptSigner> {
	pub config: MithrilDkgConfig<S>,
	pub my_randomness: [u8; RANDOMNESS_SIZE],
	pub my_commitment: [u8; 32],
	pub my_shared_secrets: BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	pub received_broadcasts: HashMap<ParticipantId, MithrilRound1Broadcast>,
	pub received_shared_secrets: BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	pub broadcast_sent: bool,
	pub privates_sent: bool,
}

impl<S: TranscriptSigner> std::fmt::Debug for MithrilRound1State<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("MithrilRound1State")
			.field("my_party_id", &self.config.my_party_id)
			.field("received_broadcasts", &self.received_broadcasts.len())
			.field("received_shared_secrets", &self.received_shared_secrets.len())
			.field("broadcast_sent", &self.broadcast_sent)
			.field("privates_sent", &self.privates_sent)
			.finish()
	}
}

/// State for Round 2.
pub struct MithrilRound2State<S: TranscriptSigner> {
	pub config: MithrilDkgConfig<S>,
	pub my_randomness: [u8; RANDOMNESS_SIZE],
	pub round1_broadcasts: HashMap<ParticipantId, MithrilRound1Broadcast>,
	pub shared_secrets: BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	pub received_broadcasts: HashMap<ParticipantId, MithrilRound2Broadcast>,
	pub broadcast_sent: bool,
}

impl<S: TranscriptSigner> std::fmt::Debug for MithrilRound2State<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("MithrilRound2State")
			.field("my_party_id", &self.config.my_party_id)
			.field("received_broadcasts", &self.received_broadcasts.len())
			.field("broadcast_sent", &self.broadcast_sent)
			.finish()
	}
}

/// State for Round 3.
pub struct MithrilRound3State<S: TranscriptSigner> {
	pub config: MithrilDkgConfig<S>,
	pub round1_broadcasts: HashMap<ParticipantId, MithrilRound1Broadcast>,
	pub round2_broadcasts: HashMap<ParticipantId, MithrilRound2Broadcast>,
	pub shared_secrets: BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	pub global_randomness: Vec<u8>,
	pub rho: [u8; 32],
	pub my_partial_pks: BTreeMap<SubsetMask, PartialPublicKey>,
	pub my_contributions: BTreeMap<SubsetMask, SubsetContribution>,
	pub my_pk_commitments: BTreeMap<SubsetMask, [u8; 32]>,
	pub received_broadcasts: HashMap<ParticipantId, MithrilRound3Broadcast>,
	pub broadcast_sent: bool,
}

impl<S: TranscriptSigner> std::fmt::Debug for MithrilRound3State<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("MithrilRound3State")
			.field("my_party_id", &self.config.my_party_id)
			.field("my_partial_pks", &self.my_partial_pks.len())
			.field("received_broadcasts", &self.received_broadcasts.len())
			.field("broadcast_sent", &self.broadcast_sent)
			.finish()
	}
}

/// State for Round 4.
pub struct MithrilRound4State<S: TranscriptSigner> {
	pub config: MithrilDkgConfig<S>,
	pub round1_broadcasts: HashMap<ParticipantId, MithrilRound1Broadcast>,
	pub round2_broadcasts: HashMap<ParticipantId, MithrilRound2Broadcast>,
	pub round3_broadcasts: HashMap<ParticipantId, MithrilRound3Broadcast>,
	pub shared_secrets: BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	pub global_randomness: Vec<u8>,
	pub rho: [u8; 32],
	pub my_partial_pks: BTreeMap<SubsetMask, PartialPublicKey>,
	pub my_contributions: BTreeMap<SubsetMask, SubsetContribution>,
	pub received_broadcasts: HashMap<ParticipantId, MithrilRound4Broadcast>,
	pub broadcast_sent: bool,
}

impl<S: TranscriptSigner> std::fmt::Debug for MithrilRound4State<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("MithrilRound4State")
			.field("my_party_id", &self.config.my_party_id)
			.field("received_broadcasts", &self.received_broadcasts.len())
			.field("broadcast_sent", &self.broadcast_sent)
			.finish()
	}
}

/// Final output.
#[derive(Debug, Clone)]
pub struct MithrilDkgOutput {
	pub public_key: PublicKey,
	pub private_share: PrivateKeyShare,
}

/// DKG state machine.
pub enum MithrilDkgState<S: TranscriptSigner> {
	Initialized(MithrilDkgConfig<S>),
	Round1(MithrilRound1State<S>),
	Round2(MithrilRound2State<S>),
	Round3(MithrilRound3State<S>),
	Round4(MithrilRound4State<S>),
	Complete(MithrilDkgOutput),
	Failed(String),
}

impl<S: TranscriptSigner> std::fmt::Debug for MithrilDkgState<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Initialized(_) => write!(f, "Initialized"),
			Self::Round1(s) => write!(f, "Round1({:?})", s),
			Self::Round2(s) => write!(f, "Round2({:?})", s),
			Self::Round3(s) => write!(f, "Round3({:?})", s),
			Self::Round4(s) => write!(f, "Round4({:?})", s),
			Self::Complete(_) => write!(f, "Complete"),
			Self::Failed(msg) => write!(f, "Failed({})", msg),
		}
	}
}

impl<S: TranscriptSigner> MithrilDkgState<S> {
	pub fn new(config: MithrilDkgConfig<S>) -> Self {
		MithrilDkgState::Initialized(config)
	}

	pub fn is_complete(&self) -> bool {
		matches!(self, MithrilDkgState::Complete(_))
	}

	pub fn is_failed(&self) -> bool {
		matches!(self, MithrilDkgState::Failed(_))
	}

	pub fn output(&self) -> Option<&MithrilDkgOutput> {
		match self {
			MithrilDkgState::Complete(output) => Some(output),
			_ => None,
		}
	}
}

/// Check if all broadcasts received.
pub fn all_broadcasts_received<T>(
	received: &HashMap<ParticipantId, T>,
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
