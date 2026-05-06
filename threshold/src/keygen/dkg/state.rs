//! State structures for the Mithril DKG protocol.
//!
//! This module contains the state machine that drives the 4-round Mithril DKG protocol.
//! The protocol follows the Mithril paper's distributed key generation scheme for
//! threshold Dilithium (ML-DSA-87).
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

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;

use crate::{
	keys::{PrivateKeyShare, PublicKey},
	participants::ParticipantId,
};

use super::types::{
	MithrilDkgConfig, MithrilRound1Broadcast, MithrilRound2Broadcast, MithrilRound3Broadcast,
	MithrilRound4Broadcast, PartialPublicKey, SubsetContribution, SubsetMask, TranscriptSigner,
	RANDOMNESS_SIZE, SHARED_SECRET_SIZE,
};

/// State for Round 1 (Commitment phase).
///
/// In this round, each party:
/// - Generates random values and computes a commitment
/// - Sends encrypted shared secrets to subset leaders
/// - Waits for commitments from all other parties
pub struct MithrilRound1State<S: TranscriptSigner> {
	/// Protocol configuration.
	pub config: MithrilDkgConfig<S>,
	/// This party's random contribution.
	pub my_randomness: [u8; RANDOMNESS_SIZE],
	/// Hash commitment to `my_randomness`.
	pub my_commitment: [u8; 32],
	/// Shared secrets for each subset this party belongs to.
	pub my_shared_secrets: BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	/// Round 1 broadcasts received from other parties.
	pub received_broadcasts: BTreeMap<ParticipantId, MithrilRound1Broadcast>,
	/// Shared secrets received from other parties.
	pub received_shared_secrets: BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	/// Whether this party has sent its broadcast.
	pub broadcast_sent: bool,
	/// Whether this party has sent its private messages.
	pub privates_sent: bool,
}

impl<S: TranscriptSigner> fmt::Debug for MithrilRound1State<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MithrilRound1State")
			.field("my_party_id", &self.config.my_party_id)
			.field("received_broadcasts", &self.received_broadcasts.len())
			.field("received_shared_secrets", &self.received_shared_secrets.len())
			.field("broadcast_sent", &self.broadcast_sent)
			.field("privates_sent", &self.privates_sent)
			.finish()
	}
}

/// State for Round 2 (Reveal phase).
///
/// In this round, each party:
/// - Broadcasts their randomness revealed from Round 1
/// - Verifies other parties' revealed values match their commitments
pub struct MithrilRound2State<S: TranscriptSigner> {
	/// Protocol configuration.
	pub config: MithrilDkgConfig<S>,
	/// This party's randomness (carried from Round 1).
	pub my_randomness: [u8; RANDOMNESS_SIZE],
	/// Round 1 broadcasts from all parties.
	pub round1_broadcasts: BTreeMap<ParticipantId, MithrilRound1Broadcast>,
	/// Combined shared secrets for each subset.
	pub shared_secrets: BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	/// Round 2 broadcasts received from other parties.
	pub received_broadcasts: BTreeMap<ParticipantId, MithrilRound2Broadcast>,
	/// Whether this party has sent its broadcast.
	pub broadcast_sent: bool,
}

impl<S: TranscriptSigner> fmt::Debug for MithrilRound2State<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MithrilRound2State")
			.field("my_party_id", &self.config.my_party_id)
			.field("received_broadcasts", &self.received_broadcasts.len())
			.field("broadcast_sent", &self.broadcast_sent)
			.finish()
	}
}

/// State for Round 3 (Partial PK Commitment phase).
///
/// In this round, each party:
/// - Derives the global randomness from all parties' contributions
/// - Computes their secret share contributions for each subset
/// - Broadcasts commitments to their partial public keys
pub struct MithrilRound3State<S: TranscriptSigner> {
	/// Protocol configuration.
	pub config: MithrilDkgConfig<S>,
	/// Round 1 broadcasts from all parties.
	pub round1_broadcasts: BTreeMap<ParticipantId, MithrilRound1Broadcast>,
	/// Round 2 broadcasts from all parties.
	pub round2_broadcasts: BTreeMap<ParticipantId, MithrilRound2Broadcast>,
	/// Combined shared secrets for each subset.
	pub shared_secrets: BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	/// Global randomness derived from all parties.
	pub global_randomness: Vec<u8>,
	/// Public matrix seed (rho) derived from global randomness.
	pub rho: [u8; 32],
	/// This party's partial public keys for each subset.
	pub my_partial_pks: BTreeMap<SubsetMask, PartialPublicKey>,
	/// This party's secret contributions for each subset.
	pub my_contributions: BTreeMap<SubsetMask, SubsetContribution>,
	/// Commitments to this party's partial public keys.
	pub my_pk_commitments: BTreeMap<SubsetMask, [u8; 32]>,
	/// Round 3 broadcasts received from other parties.
	pub received_broadcasts: BTreeMap<ParticipantId, MithrilRound3Broadcast>,
	/// Whether this party has sent its broadcast.
	pub broadcast_sent: bool,
}

impl<S: TranscriptSigner> fmt::Debug for MithrilRound3State<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MithrilRound3State")
			.field("my_party_id", &self.config.my_party_id)
			.field("my_partial_pks", &self.my_partial_pks.len())
			.field("received_broadcasts", &self.received_broadcasts.len())
			.field("broadcast_sent", &self.broadcast_sent)
			.finish()
	}
}

/// State for Round 4 (Partial PK Reveal phase).
///
/// In this round, each party:
/// - Broadcasts their partial public keys
/// - Verifies other parties' partial PKs match their Round 3 commitments
/// - Signs the transcript for accountability
/// - Combines all partial PKs into the final threshold public key
pub struct MithrilRound4State<S: TranscriptSigner> {
	/// Protocol configuration.
	pub config: MithrilDkgConfig<S>,
	/// Round 1 broadcasts from all parties.
	pub round1_broadcasts: BTreeMap<ParticipantId, MithrilRound1Broadcast>,
	/// Round 2 broadcasts from all parties.
	pub round2_broadcasts: BTreeMap<ParticipantId, MithrilRound2Broadcast>,
	/// Round 3 broadcasts from all parties.
	pub round3_broadcasts: BTreeMap<ParticipantId, MithrilRound3Broadcast>,
	/// Combined shared secrets for each subset.
	pub shared_secrets: BTreeMap<SubsetMask, [u8; SHARED_SECRET_SIZE]>,
	/// Global randomness derived from all parties.
	pub global_randomness: Vec<u8>,
	/// Public matrix seed (rho).
	pub rho: [u8; 32],
	/// This party's partial public keys for each subset.
	pub my_partial_pks: BTreeMap<SubsetMask, PartialPublicKey>,
	/// This party's secret contributions for each subset.
	pub my_contributions: BTreeMap<SubsetMask, SubsetContribution>,
	/// Round 4 broadcasts received from other parties.
	pub received_broadcasts: BTreeMap<ParticipantId, MithrilRound4Broadcast>,
	/// Whether this party has sent its broadcast.
	pub broadcast_sent: bool,
}

impl<S: TranscriptSigner> fmt::Debug for MithrilRound4State<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MithrilRound4State")
			.field("my_party_id", &self.config.my_party_id)
			.field("received_broadcasts", &self.received_broadcasts.len())
			.field("broadcast_sent", &self.broadcast_sent)
			.finish()
	}
}

/// Final output of the DKG protocol.
///
/// Contains the threshold public key (shared by all parties) and this party's
/// private key share (unique to this party).
#[derive(Debug, Clone)]
pub struct MithrilDkgOutput {
	/// The threshold public key, identical for all parties.
	pub public_key: PublicKey,
	/// This party's private key share for threshold signing.
	pub private_share: PrivateKeyShare,
}

/// State machine for the Mithril DKG protocol.
///
/// This enum represents the current state of a party in the DKG protocol.
/// The protocol progresses through states: `Initialized` -> `Round1` -> `Round2`
/// -> `Round3` -> `Round4` -> `Complete`, or may transition to `Failed` from
/// any state if an error occurs.
///
/// # Usage
///
/// ```ignore
/// use qp_rusty_crystals_threshold::keygen::dkg::{MithrilDkgState, MithrilDkgConfig};
///
/// // Create initial state
/// let state = MithrilDkgState::new(config);
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
///
/// # Note on Memory Layout
///
/// `Complete` carries a boxed `MithrilDkgOutput` because the output is ~2.8 KB
/// (full Dilithium key material), and inlining it would force every other
/// variant — and every callsite holding a `MithrilDkgState` — to reserve that
/// space. See `clippy::large_enum_variant`.
pub enum MithrilDkgState<S: TranscriptSigner> {
	/// Initial state before the protocol starts.
	Initialized(MithrilDkgConfig<S>),
	/// Round 1: Commitment phase.
	Round1(MithrilRound1State<S>),
	/// Round 2: Reveal phase.
	Round2(MithrilRound2State<S>),
	/// Round 3: Partial PK commitment phase.
	Round3(MithrilRound3State<S>),
	/// Round 4: Partial PK reveal and aggregation phase.
	Round4(MithrilRound4State<S>),
	/// Protocol completed successfully.
	Complete(Box<MithrilDkgOutput>),
	/// Protocol failed with an error message.
	Failed(String),
}

impl<S: TranscriptSigner> fmt::Debug for MithrilDkgState<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
	/// Create a new DKG state machine in the `Initialized` state.
	///
	/// The protocol will begin when `poke()` is called.
	pub fn new(config: MithrilDkgConfig<S>) -> Self {
		MithrilDkgState::Initialized(config)
	}

	/// Check if the protocol has completed successfully.
	pub fn is_complete(&self) -> bool {
		matches!(self, MithrilDkgState::Complete(_))
	}

	/// Check if the protocol has failed.
	pub fn is_failed(&self) -> bool {
		matches!(self, MithrilDkgState::Failed(_))
	}

	/// Get the DKG output if the protocol has completed successfully.
	///
	/// Returns `Some(&MithrilDkgOutput)` if the protocol is in the `Complete` state,
	/// `None` otherwise.
	pub fn output(&self) -> Option<&MithrilDkgOutput> {
		match self {
			MithrilDkgState::Complete(output) => Some(output.as_ref()),
			_ => None,
		}
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
