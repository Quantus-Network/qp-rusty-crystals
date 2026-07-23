//! Resharing Protocol State Machine.
//!
//! This module implements the resharing protocol using the poke/message pattern
//! compatible with NEAR MPC's `run_protocol` infrastructure.
//!
//! See `resharing/mod.rs` for a full description of the cryptographic protocol.
//! In short:
//!
//! - **Round 1 (Entropy commitment / Ready)**: Old committee members commit to fresh entropy. The
//!   commitment doubles as a *Ready* signal for active-set selection.
//! - **Act proposal**: The session leader (lowest-ID new committee member) proposes the active set
//!   `Act` of old members that will participate: all old members once everyone has committed (fast
//!   path), or the committed subset after the caller closes the ready window
//!   ([`ResharingProtocol::close_ready_window`]). Every party checks `Act` is a subset of the old
//!   committee with `|Act| >= t_old`, which guarantees every old RSS subset intersects `Act`.
//! - **Round 2 (Entropy reveal)**: Active old committee members reveal entropy. All parties compute
//!   the public session seed from the active members' reveals after checking the commitments.
//! - **Round 3 (Sub-share commitments)**: Each designated dealer (lowest-ID member of `I ∩ Act`)
//!   broadcasts hash commitments to deterministic sub-shares `r_{I→J}` derived from `s_I^old` and
//!   the public session seed. Other active members of the same subset recompute and verify those
//!   commitments before Round 4.
//! - **Round 4 (Private delivery)**: Dealers privately deliver `r_{I→J}` to new committee members.
//! - **Round 5 (Verification)**: New committee members verify received sub-shares, sum them into
//!   new shares `s_J^new`, and broadcast commitments so each new subset can cross-verify.
//!
//! The SSID binds every message to the resharing configuration and session nonce for replay
//! protection. The entropy commit-reveal provides public per-session randomization and pre-reveal
//! unpredictability, not post-compromise forward secrecy: a recorded transcript plus later access
//! to old subset shares is enough to recompute deterministic sub-share derivation.
//!
//! # State Machine
//!
//! ```text
//! Round1Generate -> Round1Waiting -> Round2Generate -> Round2Waiting
//!     -> Round3Generate -> Round3Waiting -> Combining -> Done
//! ```
//!
//! The Act proposal is emitted and consumed within `Round1Waiting` / `Round2Waiting`; parties
//! do not advance past those states until they know `Act`.

use alloc::{
	collections::{BTreeMap, BTreeSet},
	format,
	string::{String, ToString},
	vec::Vec,
};
use core::fmt;

use qp_rusty_crystals_dilithium::{
	fips202,
	params::{ETA, K, L, N, Q, TAU},
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
	keys::{PrivateKeyShare, SecretShareData},
	participants::ParticipantId,
};

use super::types::{
	compute_accept_hash, compute_resharing_ssid, NewShareData, ResharingAccept,
	ResharingActProposal, ResharingCertificate, ResharingConfig, ResharingMessage, ResharingOutput,
	ResharingRound1EntropyCommitment, ResharingRound2EntropyReveal, ResharingRound3Broadcast,
	ResharingRound4Message, ResharingRound5Broadcast, ResharingSignerConfig, SubsetMask,
	SubsetPair, COMMITMENT_HASH_SIZE, ENTROPY_SIZE, RESHARING_PROTOCOL_VERSION,
	RESHARING_SSID_SIZE, RESHARING_SUITE_ML_DSA_87, SUBSHARE_COEFF_BOUND,
};
use crate::keygen::dkg::TranscriptSigner;

/// Domain separator for the per-subset PRF seed (includes public session seed for randomization).
const SUBSET_SEED_DOMAIN: &[u8] = b"resharing-subset-prf-v3";

/// Domain separator for bounded conditional splitting noise.
/// v5: "coset" hiding noise — per dealer, per coefficient, sample `m` i.i.d.
/// sparse-ternary deltas (intensity `≈ 0.49 / S_old`) and subtract the *balanced
/// split of their sum* (`add_mean_subtracted_noise`). This integer zero-sum noise
/// has the uniform negative correlation `Cov(N_j,N_k) = −σ²/m` of the a-posteriori
/// coset Gaussian, so recovered-partial variance tracks keygen for *every* recovery
/// pattern.
/// v4 used an O(m) telescoping cycle (`δ_i − δ_{i−1}`): only *banded* correlation,
/// so non-contiguous recovery patterns failed to cancel and the partial norm
/// overshot (4-of-6 ~1.29× vs ~1.16× here).
/// v3 used fixed centered-binomial deltas (over-injected noise, growing the
/// recovered-partial norm linearly in the old-committee size).
const BOUNDED_SPLIT_DOMAIN: &[u8] = b"resharing-bounded-split-v5";

/// Per-coefficient probability scale for the sparse-ternary split noise, as a
/// 256-denominator numerator: a single dealer draws `±1` with probability
/// `≈ 0.49 / S_old` each (and `0` otherwise) for each of the `m` deltas, before
/// the balanced mean subtraction in `add_mean_subtracted_noise`.
///
/// # Why `1/S_old`
///
/// Each new subset share is `s_J^new = Σ_{I} r_{I→J}`, a sum over all `S_old`
/// old RSS subsets. With per-dealer noise variance `≈ σ²_keygen / S_old`, the
/// aggregated noise variance over the `S_old` dealers is `≈ σ²_keygen`: the new
/// shares are distributed like a *fresh* keygen short secret sharing (Mithril
/// "Efficient Threshold ML-DSA", §3.3 *a posteriori* sharing — a discrete
/// Gaussian over the sum-`s` coset). This keeps the recovered-partial norm under
/// the keygen envelope `B` while preserving keygen-level key hiding.
///
/// The `0.49` constant (= `(0.7)²`, i.e. `σ_split = 0.7·σ_keygen/√S_old`) is
/// tuned by Monte-Carlo (`scripts/compute_hyperball_params.py`) so the
/// aggregated hiding σ stays ≈ `σ_keygen = √2` across supported committees.
const SPLIT_NOISE_NUM_X256: u32 = 125; // round(0.49 * 256)

const COMMIT_DOMAIN: &[u8] = b"resharing-commit-v3";

const NEW_SHARE_COMMIT_DOMAIN: &[u8] = b"resharing-new-share-commit-v3";

/// Domain separator for entropy commitment.
const ENTROPY_COMMIT_DOMAIN: &[u8] = b"resharing-entropy-commit-v1";

/// Domain separator for the session transcript hash (Round 6 acceptance).
const TRANSCRIPT_DOMAIN: &[u8] = b"resharing-transcript-v1";

/// Domain separator for session seed derivation.
const SESSION_SEED_DOMAIN: &[u8] = b"resharing-session-seed-v1";

/// Maximum resharing message size in bytes (2 MB).
/// This limits the size of serialized resharing protocol messages.
/// Larger configurations (e.g., 4-of-6) require more space due to
/// the number of subset pairs: for (t,n), there are C(n, n-t+1)² pairs.
pub const MAX_RESHARING_MESSAGE_SIZE: usize = 2 * 1024 * 1024;

// ============================================================================
// Action Enum
// ============================================================================

/// Actions returned by the protocol's `poke` method.
///
/// `Debug` is implemented manually (rather than derived) so that the
/// [`SendPrivate`](Action::SendPrivate) transport bytes — which carry the
/// serialized Round 4 sub-shares — are never rendered. A derived formatter
/// would print the raw `Vec<u8>`, persisting share material into any log or
/// trace that includes `{:?}` output. Only the recipient and payload length
/// are shown.
#[derive(Clone)]
pub enum Action<T> {
	/// Do nothing, waiting for more messages from other participants.
	Wait,
	/// Send a message to all other participants (broadcast).
	/// Requires authenticated delivery (integrity).
	SendMany(Vec<u8>),
	/// Send a private message to a specific participant.
	///
	/// # ⚠️ Security Requirement
	///
	/// This message contains **secret share material** and **MUST** be transmitted
	/// over an authenticated-encrypted channel. The protocol does not encrypt
	/// this data; the transport layer must provide:
	/// - **Confidentiality**: Only the recipient can read the message
	/// - **Authenticity**: Recipient can verify the sender's identity
	/// - **Integrity**: Message cannot be modified in transit
	///
	/// Sending this message over an unencrypted channel exposes secret shares
	/// to eavesdroppers and compromises the security of the threshold scheme.
	///
	/// The payload is a [`Zeroizing`] buffer so the plaintext sub-shares are
	/// wiped from heap memory when the caller drops it after transmission.
	SendPrivate(ParticipantId, Zeroizing<Vec<u8>>),
	/// The protocol has completed, returning the output.
	Return(T),
}

impl<T: fmt::Debug> fmt::Debug for Action<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Action::Wait => f.write_str("Wait"),
			// Broadcast payloads are public, but the serialized bytes are noise in
			// a log; show only the length for consistency with SendPrivate.
			Action::SendMany(data) =>
				f.debug_tuple("SendMany").field(&format_args!("{} bytes", data.len())).finish(),
			// The payload is the serialized Round 4 private message (plaintext
			// sub-shares). Never render the bytes; keep the recipient and length
			// for diagnostics.
			Action::SendPrivate(to, data) => f
				.debug_struct("SendPrivate")
				.field("to", to)
				.field("payload", &format_args!("<{} bytes redacted>", data.len()))
				.finish(),
			Action::Return(output) => f.debug_tuple("Return").field(output).finish(),
		}
	}
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
	/// A dealer failed to deliver valid Round 4 data (logged for debugging, not used for blame).
	DealerDeliveryFailed {
		/// The dealer that failed to deliver.
		dealer: ParticipantId,
		/// Description of what was missing or invalid.
		reason: String,
	},
	/// Serialization error.
	SerializationError(String),
	/// Protocol aborted due to a failure (no specific party blamed).
	ProtocolAborted(String),
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
			ResharingProtocolError::DealerDeliveryFailed { dealer, reason } => {
				write!(f, "Dealer {} failed to deliver: {}", dealer, reason)
			},
			ResharingProtocolError::SerializationError(s) => {
				write!(f, "Serialization error: {}", s)
			},
			ResharingProtocolError::ProtocolAborted(reason) => {
				write!(f, "Protocol aborted: {}", reason)
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
///
/// # Protocol Rounds (session-randomized protocol with active-set liveness)
///
/// - **Round 1**: Entropy commitment / Ready (old committee broadcasts `H(entropy)`)
/// - **Act proposal**: Leader proposes the active set of ready old members (within the Round 1/2
///   waiting states)
/// - **Round 2**: Entropy reveal (active members reveal entropy, session seed computed)
/// - **Round 3**: Sub-share commitments (designated dealers broadcast `H(r_{I→J})`)
/// - **Round 4**: Private delivery (dealers send `r_{I→J}` to new committee)
/// - **Round 5**: Verification (share commitments, partial PKs)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResharingState {
	/// Generating Round 1 message (entropy commitment / Ready).
	Round1Generate,
	/// Waiting for the active-set proposal (and, as leader, for Ready signals).
	Round1Waiting,
	/// Generating Round 2 message (entropy reveal, active members only).
	Round2Generate,
	/// Waiting for Round 2 messages from active old committee members.
	Round2Waiting,
	/// Generating Round 3 message (commitments to per-subset sub-shares).
	Round3Generate,
	/// Waiting for Round 3 messages from old committee members.
	Round3Waiting,
	/// Generating Round 4 messages (private sub-share reveals).
	Round4Generate,
	/// Waiting for Round 4 messages (receiving sub-shares).
	Round4Waiting,
	/// Generating Round 5 message (verification commitments).
	Round5Generate,
	/// Waiting for Round 5 messages.
	Round5Waiting,
	/// Combining shares and finalizing.
	Combining,
	/// Generating the Round 6 acceptance signature (new committee members).
	AcceptGenerate,
	/// Waiting for Round 6 acceptance signatures from all new committee members.
	AcceptWaiting,
	/// Protocol completed successfully.
	Done,
	/// Protocol failed.
	Failed(String),
}

// ============================================================================
// Resharing Protocol
// ============================================================================

/// The main resharing protocol state machine.
///
/// Generic over `S`, the long-term-key signature scheme used for transcript
/// acceptance (Round 6). See [`TranscriptSigner`] and [`ResharingSignerConfig`].
pub struct ResharingProtocol<S: TranscriptSigner> {
	config: ResharingConfig,
	signer_config: ResharingSignerConfig<S>,
	state: ResharingState,

	/// Session identifier (SSID) for this resharing session.
	/// Computed from old/new committee configs + public key + session nonce.
	/// Included in all messages to prevent cross-session replay attacks.
	ssid: [u8; RESHARING_SSID_SIZE],

	/// Monotonic handoff counter for this public key (included in the SSID).
	epoch: u64,

	/// Seed for entropy generation (provided by caller).
	seed: [u8; 32],

	/// Old subset masks (from the existing share's stored shares), in canonical
	/// (BTreeMap) order. Indexed by `old_subset_index`.
	old_subset_order: Vec<SubsetMask>,
	/// New subset masks for the new committee, in canonical order. Indexed by
	/// `new_subset_index`. Used to assign per-old-subset "residual" new subsets.
	new_subset_order: Vec<SubsetMask>,

	// ========================================================================
	// Round 1-2: Entropy commit-reveal (public session randomization)
	// ========================================================================
	/// This party's generated entropy (old committee members only).
	my_entropy: Option<[u8; ENTROPY_SIZE]>,
	/// Round 1 entropy commitments received from old committee members.
	/// A commitment doubles as that member's *Ready* signal.
	round1_entropy_commits: BTreeMap<ParticipantId, [u8; COMMITMENT_HASH_SIZE]>,
	/// Round 2 entropy reveals received from active old committee members.
	round2_entropy_reveals: BTreeMap<ParticipantId, [u8; ENTROPY_SIZE]>,
	/// Session seed computed from the active set's entropy contributions
	/// (computed after Round 2).
	session_seed: Option<[u8; 32]>,

	// ========================================================================
	// Active-set selection (Ready-round liveness)
	// ========================================================================
	/// The agreed active set `Act`: old committee members that contribute
	/// entropy and deal sub-shares. Sorted. Set by the leader when proposing,
	/// or by receiving a valid `ActProposal`.
	active_set: Option<Vec<ParticipantId>>,
	/// Set by [`Self::close_ready_window`] on the leader: propose `Act` from
	/// the Ready signals received so far instead of waiting for the full old
	/// committee.
	ready_window_closed: bool,
	/// Set by [`Self::set_expected_active_set`]: the old committee members the
	/// transport layer expects to be reachable. When set, the leader proposes
	/// `Act` as soon as every expected member has committed, without waiting
	/// for the full old committee or a `close_ready_window` timeout.
	expected_active_set: Option<Vec<ParticipantId>>,

	// ========================================================================
	// Round 3-4: Sub-share commitment and delivery
	// ========================================================================
	/// Pre-computed sub-shares we are responsible for dealing.
	/// Keyed by `(old_subset, new_subset)`.
	my_subshares: BTreeMap<SubsetPair, NewShareData>,
	/// Our Round 3 broadcast (commitments for subsets we deal).
	my_round3: Option<ResharingRound3Broadcast>,
	/// Round 3 broadcasts received from other old committee members.
	round3_broadcasts: BTreeMap<ParticipantId, ResharingRound3Broadcast>,

	/// Round 4 messages we have queued to send (each addressed to a specific recipient).
	pending_round4: Vec<ResharingRound4Message>,
	/// Index of the next pending Round 4 message to emit.
	round4_sent_count: usize,
	/// Round 4 messages we received, keyed by sender.
	/// Each value is the merged set of `(I, J) -> r` from that sender.
	round4_messages: BTreeMap<ParticipantId, ResharingRound4Message>,

	// ========================================================================
	// Round 5: Verification
	// ========================================================================
	/// Round 5 broadcasts.
	round5_broadcasts: BTreeMap<ParticipantId, ResharingRound5Broadcast>,

	/// Computed new shares: `new_subset -> s_J^new`. Populated in Round 5.
	new_shares: BTreeMap<SubsetMask, NewShareData>,
	/// Final output (cached so `take_output` can return it after Combining).
	completed_output: Option<ResharingOutput>,

	// ========================================================================
	// Round 6: Signed transcript acceptance
	// ========================================================================
	/// Transcript hash computed after all Combining checks pass.
	transcript_hash: Option<[u8; COMMITMENT_HASH_SIZE]>,
	/// Acceptance signatures received (and our own), keyed by sender. Raw
	/// bytes; verified against our own transcript hash in `AcceptWaiting`.
	accepts: BTreeMap<ParticipantId, Vec<u8>>,
}

impl<S: TranscriptSigner> Drop for ResharingProtocol<S> {
	fn drop(&mut self) {
		self.zeroize_session_secrets();
	}
}

impl<S: TranscriptSigner> ResharingProtocol<S> {
	/// Securely erase all session secrets and intermediate share material.
	///
	/// Called automatically on successful completion and again on drop. The
	/// completed output (if any) is preserved until [`Self::take_output`].
	fn zeroize_session_secrets(&mut self) {
		self.seed.zeroize();
		if let Some(ref mut entropy) = self.my_entropy {
			entropy.zeroize();
		}
		self.my_entropy = None;
		if let Some(ref mut seed) = self.session_seed {
			seed.zeroize();
		}
		self.session_seed = None;
		// NewShareData implements ZeroizeOnDrop; clearing the maps drops values.
		self.my_subshares.clear();
		self.new_shares.clear();
		self.pending_round4.clear();
		self.round4_messages.clear();
		self.config.zeroize_existing_share();
		// Explicitly zeroize the transcript signer (this party's long-term
		// authentication key). `ZeroizeOnDrop` is only a marker trait, so
		// relying on the signer's own Drop would leave erasure to downstream
		// implementer discipline; calling `zeroize()` makes it an invariant.
		// Safe here: the signer is only used for the Round 6 acceptance
		// signature, which has already been produced by the time this runs
		// (successful completion or drop).
		self.signer_config.my_signer.zeroize();
	}

	/// Whether the old committee share has been erased from the config.
	///
	/// After a successful handoff, old committee members should have `true`.
	pub fn old_share_erased(&self) -> bool {
		self.config.existing_share().is_none()
	}

	/// Create a new resharing protocol instance.
	///
	/// The config must be created using `ResharingConfig::new_for_old_member` (for old committee
	/// members with an existing share) or `ResharingConfig::new_for_new_member` (for new-only
	/// members without a share). The config contains the existing share if applicable.
	///
	/// # Arguments
	///
	/// * `config` - The resharing configuration (includes existing_share for old members)
	/// * `signer_config` - This party's long-term-key signer plus the new committee's verifying
	///   keys, used for Round 6 transcript acceptance
	/// * `seed` - 32 bytes of cryptographic randomness for this party's entropy contribution
	/// * `session_nonce` - Unique nonce for SSID computation (prevents cross-session replay)
	/// * `epoch` - Monotonic handoff counter for this public key (0 for the first resharing after
	///   keygen; the transport layer should increment for each subsequent handoff)
	pub fn new(
		config: ResharingConfig,
		signer_config: ResharingSignerConfig<S>,
		seed: [u8; 32],
		session_nonce: &[u8; 32],
		epoch: u64,
	) -> Self {
		let old_participants: Vec<_> = config.old_participants().iter().collect();
		let new_participants: Vec<_> = config.new_participants().iter().collect();
		let ssid = compute_resharing_ssid(
			RESHARING_PROTOCOL_VERSION,
			RESHARING_SUITE_ML_DSA_87,
			epoch,
			config.old_threshold(),
			config.old_participants().len() as u32,
			&old_participants,
			config.new_threshold(),
			config.new_participants().len() as u32,
			&new_participants,
			config.public_key(),
			session_nonce,
		);
		let old_subset_order = compute_old_subset_order(&config);
		let new_subset_order = compute_new_subset_order(&config);
		Self {
			config,
			signer_config,
			state: ResharingState::Round1Generate,
			ssid,
			epoch,
			seed,
			old_subset_order,
			new_subset_order,
			my_entropy: None,
			round1_entropy_commits: BTreeMap::new(),
			round2_entropy_reveals: BTreeMap::new(),
			session_seed: None,
			active_set: None,
			ready_window_closed: false,
			expected_active_set: None,
			my_subshares: BTreeMap::new(),
			my_round3: None,
			round3_broadcasts: BTreeMap::new(),
			pending_round4: Vec::new(),
			round4_sent_count: 0,
			round4_messages: BTreeMap::new(),
			round5_broadcasts: BTreeMap::new(),
			new_shares: BTreeMap::new(),
			completed_output: None,
			transcript_hash: None,
			accepts: BTreeMap::new(),
		}
	}

	/// Get the session identifier (SSID) for this resharing session.
	///
	/// The SSID uniquely identifies this session and is included in all messages
	/// to prevent cross-session replay attacks.
	pub fn ssid(&self) -> &[u8; RESHARING_SSID_SIZE] {
		&self.ssid
	}

	/// The handoff epoch baked into the SSID for this session.
	pub fn epoch(&self) -> u64 {
		self.epoch
	}

	/// Get the current protocol state.
	pub fn state(&self) -> &ResharingState {
		&self.state
	}

	/// Get this party's ID.
	pub fn my_party_id(&self) -> ParticipantId {
		self.config.my_party_id()
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

	/// Recover the old committee share from a session that did not complete.
	///
	/// Dropping the protocol erases every session secret, **including the old
	/// share held in the config**. A session that failed or stalled before the
	/// Round 6 certificate was produced has generated no replacement share, so
	/// a caller that moved its only live copy of the old share into
	/// [`ResharingConfig`] MUST call this before dropping the failed protocol,
	/// or the old key material is lost and no retry is possible.
	///
	/// Returns `None` for new-only parties, and after successful completion
	/// (the share is erased at finalize; the new share from
	/// [`Self::take_output`] is then the only live key material).
	///
	/// Recovering the share renders the session unable to continue, so an
	/// in-flight session is marked failed.
	pub fn take_existing_share(&mut self) -> Option<PrivateKeyShare> {
		let share = self.config.take_existing_share();
		if share.is_some() &&
			!matches!(self.state, ResharingState::Done | ResharingState::Failed(_))
		{
			self.state = ResharingState::Failed(
				"old share recovered by caller before completion".to_string(),
			);
		}
		share
	}

	/// Check if the protocol has completed successfully.
	pub fn is_done(&self) -> bool {
		matches!(self.state, ResharingState::Done)
	}

	/// Check if the protocol has failed.
	pub fn is_failed(&self) -> bool {
		matches!(self.state, ResharingState::Failed(_))
	}

	/// The session leader: the lowest-ID new committee member.
	///
	/// The leader proposes the active set `Act`. New committee members must all
	/// be online for resharing to succeed (they receive the new shares), so the
	/// leader is always reachable in a viable session.
	pub fn leader(&self) -> ParticipantId {
		self.config
			.new_participants()
			.get(0)
			.expect("new committee is non-empty (validated)")
	}

	/// The agreed active set `Act`, once known.
	///
	/// `None` until the leader's proposal is made (leader) or received
	/// (everyone else). Sorted.
	pub fn active_set(&self) -> Option<&[ParticipantId]> {
		self.active_set.as_deref()
	}

	/// Close the Ready window (leader only): propose the active set from the
	/// Ready signals (Round 1 entropy commitments) received so far, instead of
	/// waiting for the full old committee.
	///
	/// Call this on the leader after a transport-level timeout when some old
	/// committee members appear offline. The next `poke()` broadcasts the
	/// proposal if at least `t_old` old members are ready, and aborts with
	/// [`ResharingProtocolError::InsufficientParties`] otherwise.
	///
	/// Idempotent; a no-op if the active set has already been proposed.
	pub fn close_ready_window(&mut self) -> Result<(), ResharingProtocolError> {
		if self.config.my_party_id() != self.leader() {
			return Err(ResharingProtocolError::InvalidState(format!(
				"only the session leader ({}) can close the ready window",
				self.leader()
			)));
		}
		if self.active_set.is_some() {
			return Ok(());
		}
		if !matches!(
			self.state,
			ResharingState::Round1Generate |
				ResharingState::Round1Waiting |
				ResharingState::Round2Generate |
				ResharingState::Round2Waiting
		) {
			return Err(ResharingProtocolError::InvalidState(format!(
				"cannot close ready window in state {:?}",
				self.state
			)));
		}
		self.ready_window_closed = true;
		Ok(())
	}

	/// Declare which old committee members the transport layer expects to be
	/// reachable (leader only). The leader then proposes the active set as
	/// soon as every expected member has sent its Round 1 commitment, instead
	/// of waiting for the full old committee or a `close_ready_window`
	/// timeout.
	///
	/// Use this when the transport topology makes some old members
	/// *structurally* unreachable — e.g. NEAR MPC's resharing mesh spans only
	/// the new participant set, so old-only members can never connect and the
	/// fast path (all old members ready) would stall forever.
	///
	/// This is deterministic where `close_ready_window` is timing-dependent:
	/// commitments from members outside the expected set are still accepted
	/// (and included in `Act`) if they arrive before the proposal, so this
	/// never excludes a live member, and safety is unaffected — every party
	/// still validates the proposed `Act` and reveals only after holding all
	/// of `Act`'s commitments.
	///
	/// Call before or during Rounds 1-2, on the leader. Requires
	/// `expected ⊆ old committee` and `|expected| ≥ t_old`.
	pub fn set_expected_active_set(
		&mut self,
		expected: &[ParticipantId],
	) -> Result<(), ResharingProtocolError> {
		if self.config.my_party_id() != self.leader() {
			return Err(ResharingProtocolError::InvalidState(format!(
				"only the session leader ({}) can set the expected active set",
				self.leader()
			)));
		}
		if self.active_set.is_some() {
			return Ok(());
		}
		let mut expected: Vec<ParticipantId> = expected.to_vec();
		expected.sort_unstable();
		expected.dedup();
		if !expected.iter().all(|p| self.config.old_participants().contains(*p)) {
			return Err(ResharingProtocolError::InvalidState(
				"expected active set must be a subset of the old committee".to_string(),
			));
		}
		if expected.len() < self.config.old_threshold() as usize {
			return Err(ResharingProtocolError::InsufficientParties {
				required: self.config.old_threshold() as usize,
				received: expected.len(),
			});
		}
		self.expected_active_set = Some(expected);
		Ok(())
	}

	/// Whether `party` is in the agreed active set. `false` until `Act` is known.
	fn is_active(&self, party: ParticipantId) -> bool {
		self.active_set.as_ref().is_some_and(|act| act.binary_search(&party).is_ok())
	}

	/// Leader-side active-set proposal.
	///
	/// Returns `Some(SendMany(..))` when this party is the leader and the
	/// proposal is due: every old committee member has sent its Round 1
	/// commitment (fast path), every *expected* member has committed (when
	/// [`Self::set_expected_active_set`] was called), or the caller closed
	/// the ready window. Aborts with `InsufficientParties` if the window was
	/// closed with fewer than `t_old` ready members.
	fn maybe_propose_act(
		&mut self,
	) -> Result<Option<Action<ResharingOutput>>, ResharingProtocolError> {
		if self.active_set.is_some() || self.config.my_party_id() != self.leader() {
			return Ok(None);
		}
		let have_all = self.round1_entropy_commits.len() >= self.config.old_participants().len();
		let have_expected = self.expected_active_set.as_ref().is_some_and(|expected| {
			expected.iter().all(|p| self.round1_entropy_commits.contains_key(p))
		});
		if !have_all && !have_expected && !self.ready_window_closed {
			return Ok(None);
		}

		// BTreeMap keys iterate in sorted order, so `act` is sorted.
		let act: Vec<ParticipantId> = self.round1_entropy_commits.keys().copied().collect();
		let required = self.config.old_threshold() as usize;
		if act.len() < required {
			let err = ResharingProtocolError::InsufficientParties { required, received: act.len() };
			self.state = ResharingState::Failed(err.to_string());
			return Err(err);
		}

		let proposal = ResharingActProposal {
			ssid: self.ssid,
			party_id: self.config.my_party_id(),
			active_set: act.clone(),
		};
		self.active_set = Some(act);
		let data = Self::serialize_message(&ResharingMessage::ActProposal(proposal))?;
		Ok(Some(Action::SendMany(data)))
	}

	fn serialize_message(msg: &ResharingMessage) -> Result<Vec<u8>, ResharingProtocolError> {
		borsh::to_vec(msg).map_err(|e| {
			ResharingProtocolError::SerializationError(format!("Failed to serialize: {}", e))
		})
	}

	fn deserialize_message(data: &[u8]) -> Result<ResharingMessage, ResharingProtocolError> {
		if data.len() > MAX_RESHARING_MESSAGE_SIZE {
			return Err(ResharingProtocolError::SerializationError(format!(
				"Message size {} exceeds maximum {}",
				data.len(),
				MAX_RESHARING_MESSAGE_SIZE
			)));
		}
		borsh::from_slice(data).map_err(|e| {
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
			ResharingState::Round4Generate => self.handle_round4_generate(),
			ResharingState::Round4Waiting => self.handle_round4_waiting(),
			ResharingState::Round5Generate => self.handle_round5_generate(),
			ResharingState::Round5Waiting => self.handle_round5_waiting(),
			ResharingState::Combining => self.handle_combining(),
			ResharingState::AcceptGenerate => self.handle_accept_generate(),
			ResharingState::AcceptWaiting => self.handle_accept_waiting(),
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
		// Round 4 frames carry plaintext sub-shares. Take ownership into a
		// zeroizing wrapper immediately so the buffer is wiped on every
		// return path (ignored, malformed, wrong session, or processed) —
		// dropping the frame unwiped would leave share material in freed
		// allocator memory.
		let data = Zeroizing::new(data);
		if matches!(self.state, ResharingState::Done | ResharingState::Failed(_)) {
			return Ok(());
		}

		// Ignore messages from self
		if from == self.config.my_party_id() {
			return Ok(());
		}

		// Ignore messages from non-participants (neither old nor new committee)
		let all_participants = self.config.all_participants();
		if !all_participants.contains(&from) {
			log::warn!(
				"Resharing: Ignoring message from non-participant {} (not in {:?})",
				from,
				all_participants
			);
			return Ok(());
		}

		let msg = match Self::deserialize_message(&data) {
			Ok(m) => m,
			Err(e) =>
				return Err(ResharingProtocolError::MalformedMessage { from, reason: e.to_string() }),
		};

		// Verify SSID matches for all message types to prevent cross-session replay
		if msg.ssid() != &self.ssid {
			log::warn!(
				"Resharing: Rejecting message from {} - SSID mismatch (cross-session replay attempt?)",
				from
			);
			return Ok(()); // SSID mismatch, silently ignore (not an error, likely cross-session)
		}

		if msg.party_id() != from {
			return Ok(());
		}

		match msg {
			ResharingMessage::Round1(m) => self.handle_round1_message(from, m),
			ResharingMessage::Round2(m) => self.handle_round2_message(from, m),
			ResharingMessage::Round3(broadcast) => self.handle_round3_message(from, broadcast),
			ResharingMessage::Round4(m) => self.handle_round4_message(from, m),
			ResharingMessage::Round5(broadcast) => self.handle_round5_message(from, broadcast),
			ResharingMessage::ActProposal(m) => self.handle_act_proposal(from, m),
			ResharingMessage::Accept(m) => self.handle_accept_message(from, m),
		}

		Ok(())
	}

	// ========================================================================
	// Active-set proposal handling
	// ========================================================================

	fn handle_act_proposal(&mut self, from: ParticipantId, msg: ResharingActProposal) {
		// Parties beyond the Round 1-2 waiting states already know Act;
		// anything arriving later is a stale duplicate.
		if !matches!(
			self.state,
			ResharingState::Round1Generate |
				ResharingState::Round1Waiting |
				ResharingState::Round2Generate |
				ResharingState::Round2Waiting
		) {
			return;
		}
		if from != self.leader() {
			log::warn!("Resharing: ignoring Act proposal from non-leader {}", from);
			return;
		}

		// Validate: strictly sorted (thus unique), subset of the old committee,
		// at least t_old members. An invalid proposal from the genuine leader is
		// unrecoverable (no valid session can proceed), so fail fast rather than
		// stalling until a transport timeout.
		let act = &msg.active_set;
		let sorted_unique = act.windows(2).all(|w| w[0] < w[1]);
		let all_old = act.iter().all(|p| self.config.old_participants().contains(*p));
		let enough = act.len() >= self.config.old_threshold() as usize;
		if act.is_empty() || !sorted_unique || !all_old || !enough {
			self.state = ResharingState::Failed(format!(
				"invalid Act proposal from leader {}: {:?} (t_old = {})",
				from,
				act,
				self.config.old_threshold()
			));
			return;
		}

		match &self.active_set {
			None => self.active_set = Some(msg.active_set),
			Some(existing) if *existing == msg.active_set => {}, // duplicate, ignore
			Some(_) => {
				// Two different proposals from the leader: equivocation.
				self.state = ResharingState::Failed(format!(
					"leader {} equivocated on the Act proposal",
					from
				));
			},
		}
	}

	// ========================================================================
	// Round 1: Entropy Commitment (Session Randomization)
	// ========================================================================

	fn handle_round1_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Only old committee members participate in Round 1 (entropy commitment).
		// New-only parties skip directly to Round 2 waiting.
		if !self.config.role().is_old_committee() {
			self.state = ResharingState::Round2Waiting;
			return Ok(Action::Wait);
		}

		// Generate entropy from the seed provided at construction
		let entropy = self.generate_entropy();
		self.my_entropy = Some(entropy);

		// Compute commitment: H("resharing-entropy-commit-v1" || entropy)
		let commitment = commit_entropy(&entropy);
		self.round1_entropy_commits.insert(self.config.my_party_id(), commitment);

		let broadcast = ResharingRound1EntropyCommitment {
			ssid: self.ssid,
			party_id: self.config.my_party_id(),
			commitment,
		};
		let data = Self::serialize_message(&ResharingMessage::Round1(broadcast))?;
		self.state = ResharingState::Round1Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round1_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// If we are the leader, propose the active set once it is due.
		if let Some(action) = self.maybe_propose_act()? {
			return Ok(action);
		}
		// Advance only once the active set is agreed AND we hold a Round 1
		// commitment from every Act member. Our Round 2 reveal must not be
		// broadcast while any Act member's entropy is still unfixed: a
		// malicious leader could otherwise list a colluding member that
		// commits only after observing honest reveals, choosing its entropy
		// adaptively to bias the session seed. (An Act member that never
		// commits stalls the session, like any active party going silent;
		// abort on a transport timeout and restart without it.)
		if self.have_act_commitments() {
			self.state = ResharingState::Round2Generate;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round1_message(
		&mut self,
		from: ParticipantId,
		msg: ResharingRound1EntropyCommitment,
	) {
		// Accept Round 1 messages during Round 1 or Round 2 (for late arrivals)
		if !matches!(
			self.state,
			ResharingState::Round1Generate |
				ResharingState::Round1Waiting |
				ResharingState::Round2Generate |
				ResharingState::Round2Waiting
		) {
			return;
		}
		// Only old committee members send entropy commitments
		if !self.config.old_participants().contains(from) {
			return;
		}
		// Ignore duplicates
		if self.round1_entropy_commits.contains_key(&from) {
			return;
		}
		self.round1_entropy_commits.insert(from, msg.commitment);
	}

	/// Round 1 commitment present for every active-set member. `false` until
	/// the active set is known.
	fn have_act_commitments(&self) -> bool {
		match &self.active_set {
			Some(act) => act.iter().all(|p| self.round1_entropy_commits.contains_key(p)),
			None => false,
		}
	}

	/// Entropy data (Round 1 commitment + Round 2 reveal) present for every
	/// active-set member. `false` until the active set is known.
	fn have_act_entropy_data(&self) -> bool {
		match &self.active_set {
			Some(act) => act.iter().all(|p| {
				self.round1_entropy_commits.contains_key(p) &&
					self.round2_entropy_reveals.contains_key(p)
			}),
			None => false,
		}
	}

	/// Generate this party's entropy contribution from the constructor seed.
	fn generate_entropy(&self) -> [u8; ENTROPY_SIZE] {
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, b"resharing-entropy-derive-v1");
		fips202::shake256_absorb(&mut state, &self.seed);
		fips202::shake256_absorb(&mut state, &self.config.my_party_id().to_le_bytes());
		fips202::shake256_finalize(&mut state);
		let mut entropy = [0u8; ENTROPY_SIZE];
		fips202::shake256_squeeze(&mut entropy, &mut state);
		entropy
	}

	// ========================================================================
	// Round 2: Entropy Reveal (Public Session Seed)
	// ========================================================================

	fn handle_round2_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Only *active* old committee members reveal entropy. New-only parties
		// and old members outside the active set observe from Round 2 waiting.
		if !self.is_active(self.config.my_party_id()) {
			self.state = ResharingState::Round2Waiting;
			return Ok(Action::Wait);
		}

		let entropy = self.my_entropy.ok_or_else(|| {
			ResharingProtocolError::InternalError("Missing entropy for Round 2".to_string())
		})?;

		// Store our own reveal
		self.round2_entropy_reveals.insert(self.config.my_party_id(), entropy);

		let broadcast = ResharingRound2EntropyReveal {
			ssid: self.ssid,
			party_id: self.config.my_party_id(),
			entropy,
		};
		let data = Self::serialize_message(&ResharingMessage::Round2(broadcast))?;
		self.state = ResharingState::Round2Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round2_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// A new-only leader collects Ready signals from this state; propose the
		// active set once it is due.
		if let Some(action) = self.maybe_propose_act()? {
			return Ok(action);
		}
		if self.have_act_entropy_data() {
			// Verify the active set's reveals match their commitments and
			// compute the session seed.
			self.verify_entropy_and_compute_session_seed()?;
			self.state = ResharingState::Round3Generate;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round2_message(&mut self, from: ParticipantId, msg: ResharingRound2EntropyReveal) {
		// Accept Round 2 messages from protocol start through Round 3. The
		// window includes `Round1Generate`: a party that lags past the ready
		// window (and is excluded from Act) drains its inbound backlog before
		// its first poke, while still in the initial state. Reveals are only
		// *used* after `have_act_entropy_data` confirms the matching Round 1
		// commitment, so early acceptance cannot bypass the commit-reveal
		// binding; Act membership already fixes every contributor's commitment
		// before any honest reveal is sent.
		if !matches!(
			self.state,
			ResharingState::Round1Generate |
				ResharingState::Round1Waiting |
				ResharingState::Round2Generate |
				ResharingState::Round2Waiting |
				ResharingState::Round3Generate |
				ResharingState::Round3Waiting
		) {
			return;
		}
		// Only old committee members send entropy reveals
		if !self.config.old_participants().contains(from) {
			return;
		}
		// Ignore duplicates
		if self.round2_entropy_reveals.contains_key(&from) {
			return;
		}
		self.round2_entropy_reveals.insert(from, msg.entropy);
	}

	/// Verify the active set's entropy reveals match their commitments and
	/// compute the session seed.
	///
	/// Only active-set members contribute: the set of contributors must be
	/// agreed by every party (it determines the seed), and `Act` is exactly
	/// the agreed set. Reveals from non-active members (e.g. a late Round 1
	/// commitment excluded from `Act`) are ignored.
	fn verify_entropy_and_compute_session_seed(&mut self) -> Result<(), ResharingProtocolError> {
		let act = self.active_set.clone().ok_or_else(|| {
			ResharingProtocolError::InternalError(
				"Computing session seed before active set is agreed".to_string(),
			)
		})?;

		// Verify each active member's reveal matches its commitment.
		for &party_id in &act {
			let entropy = self.round2_entropy_reveals.get(&party_id).ok_or_else(|| {
				ResharingProtocolError::InternalError(format!(
					"Missing entropy reveal from active party {} during verification",
					party_id
				))
			})?;
			let expected_commit = commit_entropy(entropy);
			let actual_commit = self.round1_entropy_commits.get(&party_id).ok_or_else(|| {
				ResharingProtocolError::InternalError(format!(
					"Missing entropy commitment from active party {} during verification",
					party_id
				))
			})?;
			if expected_commit != *actual_commit {
				return Err(ResharingProtocolError::CommitmentMismatch(party_id));
			}
		}

		// Compute session seed: SHAKE256("resharing-session-seed-v1" || ssid || party_id_1 ||
		// entropy_1 || ...) over active members in sorted order (Act is sorted). The SSID is
		// included so that even if parties reuse entropy seeds across different resharing
		// sessions, the session_seed (and thus the sub-share derivation) will differ.
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, SESSION_SEED_DOMAIN);
		fips202::shake256_absorb(&mut state, &self.ssid);
		for &party_id in &act {
			let entropy = self.round2_entropy_reveals.get(&party_id).expect("checked above");
			fips202::shake256_absorb(&mut state, &party_id.to_le_bytes());
			fips202::shake256_absorb(&mut state, entropy);
		}
		fips202::shake256_finalize(&mut state);
		let mut session_seed = [0u8; 32];
		fips202::shake256_squeeze(&mut session_seed, &mut state);
		self.session_seed = Some(session_seed);

		Ok(())
	}

	// ========================================================================
	// Round 3: Sub-Share Commitments
	// ========================================================================

	fn handle_round3_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Only active old committee members deal in Round 3. New-only parties
		// and old members outside the active set wait for Round 4 traffic.
		if !self.is_active(self.config.my_party_id()) {
			self.state = ResharingState::Round4Waiting;
			return Ok(Action::Wait);
		}

		// Compute sub-shares using the public session seed for per-session randomization.
		self.compute_my_subshares()?;
		let commitments = self.commit_to_my_subshares();

		let broadcast = ResharingRound3Broadcast {
			ssid: self.ssid,
			party_id: self.config.my_party_id(),
			commitments,
		};
		self.my_round3 = Some(broadcast.clone());
		self.round3_broadcasts.insert(self.config.my_party_id(), broadcast.clone());

		// Pre-build the per-recipient Round 4 messages so we can stream them in
		// later pokes without re-deriving anything.
		self.build_pending_round4_messages();

		let data = Self::serialize_message(&ResharingMessage::Round3(broadcast))?;
		self.state = ResharingState::Round3Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round3_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.have_enough_round3() {
			// Security halt: if a peer dealer's Round-3 commitment does not match the
			// deterministic sub-shares we can recompute, abort *before* dealing our own
			// Round-4 private shares — delivering them into a committee that contains a
			// cheating dealer would leak share material.
			//
			// Unlike the Round-5 abort (which is broadcast to peers via `success =
			// false`), this is a deliberate *silent* local halt: the safe response is
			// simply to withhold our Round-4 messages, so we do not warn peers. We set
			// `Failed` so the state is terminal and observable via `is_failed()`
			// (matching the Round-5 abort), and rely on the transport/runner to surface
			// the returned `Err` as a global abort. New-only members, now receiving no
			// Round-4 shares, detect the stall via their own transport timeout.
			// (Confirmed in near-mpc: the aborting node's `poke()` Err propagates out of
			// `run_protocol`, while waiting nodes hit the 120s
			// `perform_leader_centric_computation` timeout.)
			if let Err(e) = self.verify_peer_dealer_commitments() {
				self.state = ResharingState::Failed(e.to_string());
				return Err(e);
			}
			self.state = ResharingState::Round4Generate;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round3_message(&mut self, from: ParticipantId, broadcast: ResharingRound3Broadcast) {
		// Accept Round 3 messages from protocol start through Round 4: a slow
		// party excluded from Act can receive dealers' broadcasts while still
		// in the Round 1-2 states (see `handle_round2_message`). The broadcasts
		// are hash commitments, verified later against deterministic
		// recomputation (old-subset peers) or delivered sub-shares (recipients),
		// so early acceptance is harmless.
		if !matches!(
			self.state,
			ResharingState::Round1Generate |
				ResharingState::Round1Waiting |
				ResharingState::Round2Generate |
				ResharingState::Round2Waiting |
				ResharingState::Round3Generate |
				ResharingState::Round3Waiting |
				ResharingState::Round4Generate |
				ResharingState::Round4Waiting
		) {
			return;
		}
		if !self.config.old_participants().contains(from) {
			return;
		}
		if self.round3_broadcasts.contains_key(&from) {
			return;
		}
		self.round3_broadcasts.insert(from, broadcast);
	}

	fn have_enough_round3(&self) -> bool {
		// We need a Round 3 broadcast from every active member. Every designated
		// dealer is active by construction (dealers are chosen from `I ∩ Act`),
		// and active non-dealers broadcast an empty commitment map, so this is
		// both sufficient and satisfiable with offline non-active members.
		match &self.active_set {
			Some(act) => act.iter().all(|p| self.round3_broadcasts.contains_key(p)),
			None => false,
		}
	}

	/// Old-subset peer verification for Round 3 dealer commitments.
	///
	/// Every member of an old RSS subset knows the same `s_I^old`. If the
	/// designated dealer for `I` is another party, this party can recompute the
	/// deterministic sub-shares and verify the dealer committed to exactly those
	/// values before any Round 4 private delivery occurs.
	/// Resolve the designated dealer for old subset `i_mask` and borrow its Round-3
	/// commitment broadcast. Shared by `verify_peer_dealer_commitments` (Round-3 peer
	/// check) and `verify_and_aggregate_new_shares` (Round-5 aggregation) so the
	/// dealer lookup, the Round-3 broadcast lookup, and their error messages live in
	/// one place.
	fn dealer_round3_for(
		&self,
		i_mask: SubsetMask,
	) -> Result<(ParticipantId, &ResharingRound3Broadcast), ResharingProtocolError> {
		let dealer = self.designated_dealer_for(i_mask).ok_or_else(|| {
			ResharingProtocolError::ShareVerificationFailed(format!(
				"no designated dealer found for old subset {:b}",
				i_mask
			))
		})?;
		let dealer_r3 = self.round3_broadcasts.get(&dealer).ok_or_else(|| {
			ResharingProtocolError::DealerDeliveryFailed {
				dealer,
				reason: format!("missing Round 3 commitment for subset {:b}", i_mask),
			}
		})?;
		Ok((dealer, dealer_r3))
	}

	fn verify_peer_dealer_commitments(&self) -> Result<(), ResharingProtocolError> {
		if !self.config.role().is_old_committee() {
			return Ok(());
		}

		let existing = self.config.existing_share().ok_or_else(|| {
			ResharingProtocolError::InternalError("Missing existing share".to_string())
		})?;
		let session_seed = self.session_seed.ok_or_else(|| {
			ResharingProtocolError::InternalError("Missing session seed".to_string())
		})?;

		for (&i_mask, s_i) in existing.shares() {
			// We never verify our own commitments, so skip before fetching the Round 3
			// broadcast — a designated dealer that is us need not have recorded its own
			// broadcast for this peer check (and a missing peer broadcast is a real
			// error, handled by `dealer_round3_for`).
			if self.designated_dealer_for(i_mask) == Some(self.config.my_party_id()) {
				continue;
			}
			let (dealer, dealer_r3) = self.dealer_round3_for(i_mask)?;

			let expected_subshares = derive_subshares_with_session_seed(
				i_mask,
				s_i,
				&self.new_subset_order,
				&session_seed,
				self.old_subset_order.len(),
			);

			for (j_mask, expected_share) in
				self.new_subset_order.iter().zip(expected_subshares.iter())
			{
				let expected_commit = commit_subshare(i_mask, *j_mask, expected_share);
				let actual_commit =
					dealer_r3.commitments.get(&(i_mask, *j_mask)).ok_or_else(|| {
						ResharingProtocolError::DealerDeliveryFailed {
							dealer,
							reason: format!("did not commit to r_{{{:b}->{:b}}}", i_mask, j_mask),
						}
					})?;

				if *actual_commit != expected_commit {
					return Err(ResharingProtocolError::ShareVerificationFailed(format!(
						"dealer {} commitment mismatch for r_{{{:b}->{:b}}}",
						dealer, i_mask, j_mask
					)));
				}
			}
		}

		Ok(())
	}

	// ========================================================================
	// Round 4: Private Sub-Share Reveal
	// ========================================================================

	fn handle_round4_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Old-only parties without dealer responsibilities and new-only parties simply
		// wait for inbound traffic.
		if !self.config.role().is_old_committee() || self.pending_round4.is_empty() {
			self.state = ResharingState::Round4Waiting;
			return self.poke();
		}

		self.state = ResharingState::Round4Waiting;
		self.send_next_round4_message()
	}

	fn handle_round4_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Old-committee dealers continue to drain pending Round 4 messages.
		if self.config.role().is_old_committee() &&
			self.round4_sent_count < self.pending_round4.len()
		{
			return self.send_next_round4_message();
		}

		// New committee members proceed to Round 5 once they have received from every
		// expected dealer.
		if self.config.role().is_new_committee() && self.have_all_expected_round4() {
			self.state = ResharingState::Round5Generate;
			return self.poke();
		}

		// Old-only parties advance to Round 5 generation (they broadcast success/failure status).
		if !self.config.role().is_new_committee() &&
			self.round4_sent_count >= self.pending_round4.len()
		{
			self.state = ResharingState::Round5Generate;
			return self.poke();
		}

		Ok(Action::Wait)
	}

	fn send_next_round4_message(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.round4_sent_count >= self.pending_round4.len() {
			return Ok(Action::Wait);
		}
		let msg = &self.pending_round4[self.round4_sent_count];
		let to_party = msg.to_party_id;
		// Round 4 frames carry plaintext sub-shares, so serialize into an
		// exactly pre-sized zeroizing buffer: `borsh::to_vec`'s incremental
		// growth would free unwiped intermediate blocks still holding share
		// coefficients, and a plain payload Vec would leave them in allocator
		// memory once the transport drops it.
		let wire = ResharingMessage::Round4(msg.clone());
		let len = borsh::object_length(&wire).map_err(|e| {
			ResharingProtocolError::SerializationError(format!("Failed to serialize: {}", e))
		})?;
		let mut data = Zeroizing::new(Vec::with_capacity(len));
		borsh::to_writer(&mut *data, &wire).map_err(|e| {
			ResharingProtocolError::SerializationError(format!("Failed to serialize: {}", e))
		})?;
		self.round4_sent_count += 1;
		Ok(Action::SendPrivate(to_party, data))
	}

	fn handle_round4_message(&mut self, from: ParticipantId, msg: ResharingRound4Message) {
		if matches!(self.state, ResharingState::Done | ResharingState::Failed(_)) {
			return;
		}
		if !self.config.role().is_new_committee() {
			return;
		}
		if !self.config.old_participants().contains(from) {
			return;
		}
		if msg.to_party_id != self.config.my_party_id() {
			return;
		}
		// Reject duplicates from the same dealer.
		if self.round4_messages.contains_key(&from) {
			return;
		}
		self.round4_messages.insert(from, msg);
	}

	fn have_all_expected_round4(&self) -> bool {
		// Expected senders = the set of designated dealers for each old subset.
		let expected: BTreeMap<ParticipantId, ()> =
			self.designated_dealer_set().into_iter().map(|p| (p, ())).collect();
		expected.keys().all(|d| self.round4_messages.contains_key(d))
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
	// Round 5: Verification
	// ========================================================================

	fn handle_round5_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		let mut share_commitments: BTreeMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]> =
			BTreeMap::new();
		let mut success = true;
		let mut error_message: Option<String> = None;

		// New committee members verify privately-received sub-shares against the
		// broadcast commitments, sum them into new subset shares, and commit.
		if self.config.role().is_new_committee() {
			match self.verify_and_aggregate_new_shares() {
				Ok(commits) => match self.verify_stored_new_share_norms() {
					Ok(()) => match self.verify_recovered_partial_norms() {
						Ok(()) => share_commitments = commits,
						Err(e) => {
							success = false;
							error_message = Some(e.to_string());
						},
					},
					Err(e) => {
						success = false;
						error_message = Some(e.to_string());
					},
				},
				Err(e) => {
					success = false;
					error_message = Some(e.to_string());
				},
			}
		}

		// Compute partial public-key contributions `t_J = A·s1_J + s2_J mod Q`
		// for every new subset we hold. These are summed and checked against the
		// original public key in Combining; this catches a malicious dealer that
		// lies about a residual `r_{I→J}` in a size-1 old subset, where there is
		// no peer in the old subset to cross-verify the commitment.
		let partial_pks = if self.config.role().is_new_committee() && success {
			self.compute_my_partial_pks()
		} else {
			BTreeMap::new()
		};

		let broadcast = ResharingRound5Broadcast {
			ssid: self.ssid,
			party_id: self.config.my_party_id(),
			share_commitments,
			partial_pks,
			success,
			error_message,
		};
		self.round5_broadcasts.insert(self.config.my_party_id(), broadcast.clone());
		let data = Self::serialize_message(&ResharingMessage::Round5(broadcast))?;
		self.state = ResharingState::Round5Waiting;
		Ok(Action::SendMany(data))
	}

	fn handle_round5_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		if self.have_all_round5() {
			self.state = ResharingState::Combining;
			self.poke()
		} else {
			Ok(Action::Wait)
		}
	}

	fn handle_round5_message(&mut self, from: ParticipantId, broadcast: ResharingRound5Broadcast) {
		if matches!(self.state, ResharingState::Done | ResharingState::Failed(_)) {
			return;
		}
		if !self.config.all_participants().contains(&from) {
			return;
		}
		if self.round5_broadcasts.contains_key(&from) {
			return;
		}
		// Note: partial_pks shape is validated during deserialization (BorshDeserialize impl)
		self.round5_broadcasts.insert(from, broadcast);
	}

	/// The Round 5 senders this session actually depends on: active old
	/// members (status) plus new committee members (new-share commitments +
	/// partial PKs). `None` until the active set is agreed.
	///
	/// This is the outer trust boundary for Round 5 consumption. Every
	/// consumer of `round5_broadcasts` filters senders through it:
	/// completion ([`Self::have_all_round5`]), the failure-abort scan in
	/// Combining, and the transcript hash use exactly this set, while the
	/// Combining share-data checks ([`Self::verify_new_share_consistency`],
	/// [`Self::verify_public_key_preservation`]) restrict further to new
	/// committee members, a subset of this set. Together these ensure a
	/// broadcast from an old member excluded from `Act` never influences the
	/// outcome — the protocol's liveness promise is that it proceeds without
	/// such members, and honoring their failure reports (or hard-failing on
	/// their poisoned share data) would let a single excluded (e.g.
	/// compromised, being-rotated-out) member abort every session. Any new
	/// consumer of `round5_broadcasts` must apply the same filtering.
	fn required_round5_senders(&self) -> Option<alloc::collections::BTreeSet<ParticipantId>> {
		let act = self.active_set.as_ref()?;
		Some(act.iter().copied().chain(self.config.new_participants().iter()).collect())
	}

	fn have_all_round5(&self) -> bool {
		// Old members outside the active set may be offline, so they are not
		// required for completion. Their buffered broadcasts (if any) are
		// also not honored by the Combining failure scan, not included in
		// the transcript hash, and not read by the Combining share-data
		// checks (which restrict further, to new committee members). Any new
		// consumer of `round5_broadcasts` must apply one of those filters —
		// see `required_round5_senders` for the enumeration and rationale.
		let Some(required) = self.required_round5_senders() else { return false };
		required.iter().all(|p| self.round5_broadcasts.contains_key(p))
	}

	// ========================================================================
	// Combining
	// ========================================================================

	fn handle_combining(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		// Check if any *required* party reported failure - abort without
		// attribution. The scan is restricted to the same sender set that
		// gates Round 5 completion and the transcript hash: an old member
		// excluded from the active set is exactly the party the session must
		// be able to proceed without, so its failure report must not be able
		// to abort the session (and other parties may not even have received
		// it, so honoring it would also make parties diverge).
		let required = self.required_round5_senders().ok_or_else(|| {
			ResharingProtocolError::InternalError(
				"Combining reached before active set is agreed".to_string(),
			)
		})?;
		let failed_parties: Vec<ParticipantId> = self
			.round5_broadcasts
			.iter()
			.filter(|(id, b)| required.contains(id) && !b.success)
			.map(|(id, _)| *id)
			.collect();

		if !failed_parties.is_empty() {
			let reason =
				format!("Protocol aborted: {} parties reported failure", failed_parties.len());
			self.state = ResharingState::Failed(reason.clone());
			return Err(ResharingProtocolError::ProtocolAborted(reason));
		}

		// New committee members must agree on every shared new subset.
		self.verify_new_share_consistency()?;

		// Verify the resharing preserved the public key invariant. This catches
		// a malicious dealer that lies about a residual `r_{I→J}`.
		self.verify_public_key_preservation()?;

		// All checks passed: fix the transcript hash and move to the signed
		// acceptance round.
		self.transcript_hash = Some(self.compute_transcript_hash()?);
		self.state = ResharingState::AcceptGenerate;
		self.poke()
	}

	// ========================================================================
	// Round 6: Signed Transcript Acceptance
	// ========================================================================

	/// Hash of everything that determines the session outcome: the active set,
	/// the session seed, every active member's Round 3 dealer commitments, and
	/// every *required* Round 5 broadcast (active old members + new committee).
	///
	/// Broadcasts from parties outside the required sets (e.g. a non-active
	/// old observer's Round 5 status) are deliberately excluded: not every
	/// party is guaranteed to have received them, and including them would
	/// make honest parties disagree on the hash.
	fn compute_transcript_hash(
		&self,
	) -> Result<[u8; COMMITMENT_HASH_SIZE], ResharingProtocolError> {
		let act = self.active_set.as_ref().ok_or_else(|| {
			ResharingProtocolError::InternalError(
				"Computing transcript hash before active set is agreed".to_string(),
			)
		})?;
		let session_seed = self.session_seed.as_ref().ok_or_else(|| {
			ResharingProtocolError::InternalError(
				"Computing transcript hash before session seed".to_string(),
			)
		})?;

		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, TRANSCRIPT_DOMAIN);
		fips202::shake256_absorb(&mut state, &self.ssid);
		fips202::shake256_absorb(&mut state, &(act.len() as u32).to_le_bytes());
		for &p in act {
			fips202::shake256_absorb(&mut state, &p.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, session_seed);

		// Round 3 dealer commitments from active members, in Act (sorted) order.
		// (`round3_broadcasts` includes our own broadcast.)
		for &p in act {
			let broadcast = self.round3_broadcasts.get(&p);
			let broadcast = broadcast.ok_or_else(|| {
				ResharingProtocolError::InternalError(format!(
					"Missing Round 3 broadcast from active party {} for transcript",
					p
				))
			})?;
			let bytes = borsh::to_vec(broadcast).map_err(|e| {
				ResharingProtocolError::SerializationError(format!(
					"Failed to serialize Round 3 broadcast for transcript: {}",
					e
				))
			})?;
			fips202::shake256_absorb(&mut state, &(bytes.len() as u32).to_le_bytes());
			fips202::shake256_absorb(&mut state, &bytes);
		}

		// Required Round 5 broadcasts: active old members + new committee, in
		// sorted order (the same set that gates `have_all_round5` and the
		// Combining failure scan).
		let required = self.required_round5_senders().ok_or_else(|| {
			ResharingProtocolError::InternalError(
				"Computing transcript hash before active set is agreed".to_string(),
			)
		})?;
		for p in required {
			let broadcast = self.round5_broadcasts.get(&p).ok_or_else(|| {
				ResharingProtocolError::InternalError(format!(
					"Missing Round 5 broadcast from required party {} for transcript",
					p
				))
			})?;
			let bytes = borsh::to_vec(broadcast).map_err(|e| {
				ResharingProtocolError::SerializationError(format!(
					"Failed to serialize Round 5 broadcast for transcript: {}",
					e
				))
			})?;
			fips202::shake256_absorb(&mut state, &(bytes.len() as u32).to_le_bytes());
			fips202::shake256_absorb(&mut state, &bytes);
		}

		fips202::shake256_finalize(&mut state);
		let mut out = [0u8; COMMITMENT_HASH_SIZE];
		fips202::shake256_squeeze(&mut out, &mut state);
		Ok(out)
	}

	fn handle_accept_generate(
		&mut self,
	) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		let transcript_hash = self.transcript_hash.ok_or_else(|| {
			ResharingProtocolError::InternalError(
				"AcceptGenerate reached without a transcript hash".to_string(),
			)
		})?;

		// Only new committee members attest: they are the parties that verified
		// and now hold the reshared key material. Old-only parties observe.
		if !self.config.role().is_new_committee() {
			self.state = ResharingState::AcceptWaiting;
			return self.handle_accept_waiting();
		}

		let active_set = self.active_set.clone().ok_or_else(|| {
			ResharingProtocolError::InternalError(
				"AcceptGenerate reached without an agreed active set".to_string(),
			)
		})?;
		// ParticipantList iterates in sorted order, giving the canonical
		// (strictly ascending) committee encoding the acceptance hash binds.
		let new_committee: Vec<ParticipantId> = self.config.new_participants().iter().collect();
		let accept_hash =
			compute_accept_hash(&self.ssid, &transcript_hash, &active_set, &new_committee);
		let signature = self.signer_config.my_signer.sign(&accept_hash);
		let my_id = self.config.my_party_id();
		self.accepts.insert(my_id, signature.as_ref().to_vec());

		let msg = ResharingAccept {
			ssid: self.ssid,
			party_id: my_id,
			signature: signature.as_ref().to_vec(),
		};
		let data = Self::serialize_message(&ResharingMessage::Accept(msg))?;
		self.state = ResharingState::AcceptWaiting;
		Ok(Action::SendMany(data))
	}

	fn handle_accept_waiting(&mut self) -> Result<Action<ResharingOutput>, ResharingProtocolError> {
		let transcript_hash = self.transcript_hash.ok_or_else(|| {
			ResharingProtocolError::InternalError(
				"AcceptWaiting reached without a transcript hash".to_string(),
			)
		})?;

		// Need an acceptance from every new committee member.
		let new_participants: Vec<ParticipantId> = self.config.new_participants().iter().collect();
		if !new_participants.iter().all(|p| self.accepts.contains_key(p)) {
			return Ok(Action::Wait);
		}

		let active_set = self.active_set.clone().ok_or_else(|| {
			ResharingProtocolError::InternalError(
				"AcceptWaiting reached without an agreed active set".to_string(),
			)
		})?;

		// Verify every signature against *our own* transcript hash. A signer
		// that observed a different transcript (dealer equivocation, tampered
		// broadcast) produces a signature that fails here, and we abort.
		let accept_hash =
			compute_accept_hash(&self.ssid, &transcript_hash, &active_set, &new_participants);
		for p in &new_participants {
			let pk = self.signer_config.verifying_keys.get(p).ok_or_else(|| {
				ResharingProtocolError::InternalError(format!(
					"Missing verifying key for new committee member {} (validated at config)",
					p
				))
			})?;
			let sig = self.accepts.get(p).expect("presence checked above");
			if !S::verify_bytes(pk, &accept_hash, sig) {
				let reason = format!(
					"invalid transcript acceptance from party {} — transcript disagreement \
					 or forged signature",
					p
				);
				self.state = ResharingState::Failed(reason.clone());
				return Err(ResharingProtocolError::ShareVerificationFailed(reason));
			}
		}

		let certificate = ResharingCertificate {
			ssid: self.ssid,
			active_set,
			new_committee: new_participants,
			transcript_hash,
			accepts: self.accepts.clone(),
		};

		let output = self.build_output(certificate)?;
		self.zeroize_session_secrets();
		self.completed_output = Some(output.clone());
		self.state = ResharingState::Done;
		Ok(Action::Return(output))
	}

	fn handle_accept_message(&mut self, from: ParticipantId, msg: ResharingAccept) {
		if matches!(self.state, ResharingState::Done | ResharingState::Failed(_)) {
			return;
		}
		// Only new committee members attest.
		if !self.config.new_participants().contains(from) {
			return;
		}
		// First message wins; duplicates ignored (matches other rounds).
		if self.accepts.contains_key(&from) {
			return;
		}
		// Signature verification is deferred to `AcceptWaiting`, where our own
		// transcript hash is known. Accepts can legitimately arrive earlier
		// (e.g. while we are still draining Round 5 traffic).
		self.accepts.insert(from, msg.signature);
	}

	// ========================================================================
	// Cryptographic Helpers
	// ========================================================================

	/// Pre-compute every sub-share `r_{I→J}` we are responsible for dealing.
	/// Uses the public session seed for per-session randomization.
	fn compute_my_subshares(&mut self) -> Result<(), ResharingProtocolError> {
		let existing = self.config.existing_share().ok_or_else(|| {
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

		// Get session seed for deterministic per-session PRF derivation.
		let session_seed = self.session_seed.ok_or_else(|| {
			ResharingProtocolError::InternalError("Missing session seed".to_string())
		})?;

		for &i_mask in self.old_subset_order.clone().iter() {
			// Only compute for subsets where we are the designated dealer.
			if self.designated_dealer_for(i_mask) != Some(self.config.my_party_id()) {
				continue;
			}
			let s_i = shares.get(&i_mask).ok_or_else(|| {
				ResharingProtocolError::InternalError(format!(
					"Designated dealer for subset {:b} but no share data",
					i_mask
				))
			})?;
			let mut subshares = derive_subshares_with_session_seed(
				i_mask,
				s_i,
				&new_subsets,
				&session_seed,
				self.old_subset_order.len(),
			);
			// Move each sub-share out with `mem::take` rather than
			// `into_iter()`: consuming the Vec by value skips the elements'
			// zeroizing drops, freeing the backing buffer with the raw
			// coefficients still in it. Taking leaves zeros in the slots,
			// which the Vec's (zeroizing) element drops then wipe redundantly.
			for (j_mask, subshare) in new_subsets.iter().zip(subshares.iter_mut()) {
				self.my_subshares.insert((i_mask, *j_mask), core::mem::take(subshare));
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

	/// Build the per-recipient Round 4 messages we will emit one-by-one in `poke`.
	///
	/// Self-deals (when this party is also a member of `J`) are inserted directly
	/// into `round4_messages`; only outbound messages are queued in `pending_round4`.
	/// This mirrors the DKG pattern (`process_round1` skips self) and removes the
	/// implicit "network must loopback SendPrivate(self, _)" requirement.
	fn build_pending_round4_messages(&mut self) {
		let mut by_recipient: BTreeMap<ParticipantId, BTreeMap<SubsetPair, NewShareData>> =
			BTreeMap::new();
		for (pair, share) in &self.my_subshares {
			let j_mask = pair.1;
			for (idx, party) in self.config.new_participants().iter().enumerate() {
				if (j_mask & (1 << idx)) != 0 {
					by_recipient.entry(party).or_default().insert(*pair, share.clone());
				}
			}
		}
		let me = self.config.my_party_id();
		for (recipient, contributions) in by_recipient {
			let msg = ResharingRound4Message {
				ssid: self.ssid,
				from_party_id: me,
				to_party_id: recipient,
				contributions,
			};
			if recipient == me {
				self.round4_messages.insert(me, msg);
			} else {
				self.pending_round4.push(msg);
			}
		}
	}

	/// Find the designated dealer for an old subset: the lowest-ID *active*
	/// old participant that is a member of the subset (`min(I ∩ Act)`).
	///
	/// Bit positions in `i_mask` correspond to indices in the (sorted)
	/// `old_participants` list. Works for every party — in particular NewOnly
	/// parties that don't hold an `existing_share`.
	///
	/// The active-set rule `|Act| >= t_old` guarantees `I ∩ Act` is non-empty
	/// for every old subset `I` (which has `n_old - t_old + 1` members), so
	/// once `Act` is agreed this returns `Some` for every valid subset. All
	/// members of `I` hold the same `s_I^old` and the sub-share derivation is
	/// deterministic, so any of them produces identical sub-shares — dealer
	/// identity affects only message routing, not the derived values.
	///
	/// Returns `None` before the active set is agreed; all call sites run
	/// after Round 2 completes, which requires `Act`.
	fn designated_dealer_for(&self, i_mask: SubsetMask) -> Option<ParticipantId> {
		self.active_set.as_ref()?;
		for (bit, party) in self.config.old_participants().iter().enumerate() {
			if (i_mask & (1 << bit)) != 0 && self.is_active(party) {
				return Some(party);
			}
		}
		None
	}

	/// New committee post-Round-4 work: verify each received `r_{I→J}` against the
	/// matching Round 3 commitment, then sum them into `s_J^new` and produce a
	/// commitment per new subset we are in.
	fn verify_and_aggregate_new_shares(
		&mut self,
	) -> Result<BTreeMap<SubsetMask, [u8; COMMITMENT_HASH_SIZE]>, ResharingProtocolError> {
		let my_idx =
			self.config.new_participants().index_of(self.config.my_party_id()).ok_or_else(
				|| ResharingProtocolError::InternalError("not in new committee".into()),
			)?;

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
			let (dealer, dealer_r3) = self.dealer_round3_for(i_mask)?;
			let dealer_r4 = self.round4_messages.get(&dealer).ok_or_else(|| {
				ResharingProtocolError::DealerDeliveryFailed {
					dealer,
					reason: format!("missing Round 4 message for subset {:b}", i_mask),
				}
			})?;
			for &j_mask in new_subsets {
				if (j_mask & (1 << my_idx)) == 0 {
					continue;
				}
				let r = dealer_r4.contributions.get(&(i_mask, j_mask)).ok_or_else(|| {
					ResharingProtocolError::DealerDeliveryFailed {
						dealer,
						reason: format!("did not deliver r_{{{:b}->{:b}}}", i_mask, j_mask),
					}
				})?;

				// Check coefficient bounds to defend against malicious dealers injecting
				// large coefficients that could push signing partials beyond hyperball bounds.
				if !r.coefficients_within_bound(SUBSHARE_COEFF_BOUND) {
					return Err(ResharingProtocolError::DealerDeliveryFailed {
						dealer,
						reason: format!(
							"r_{{{:b}->{:b}}} has coefficient exceeding bound {} (max: {})",
							i_mask,
							j_mask,
							SUBSHARE_COEFF_BOUND,
							r.max_abs_coefficient()
						),
					});
				}

				let expected_commit = commit_subshare(i_mask, j_mask, r);
				let dealer_commit =
					dealer_r3.commitments.get(&(i_mask, j_mask)).ok_or_else(|| {
						ResharingProtocolError::DealerDeliveryFailed {
							dealer,
							reason: format!("did not commit to r_{{{:b}->{:b}}}", i_mask, j_mask),
						}
					})?;
				if *dealer_commit != expected_commit {
					return Err(ResharingProtocolError::DealerDeliveryFailed {
						dealer,
						reason: format!(
							"sent r_{{{:b}->{:b}}} that doesn't match commitment",
							i_mask, j_mask
						),
					});
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

	/// Check that every signing partial this new party may later recover stays
	/// inside the partial-secret norm envelope assumed by the Threshold ML-DSA
	/// signing proof for the new configuration.
	///
	/// The signing proof relies on the norm of the challenge-shifted partial
	/// secret being small. A malicious dealer can preserve the aggregate public key
	/// while adding bounded zero-sum noise across new RSS subsets, so Round 5 also
	/// validates the recovered partials that would be used by signing.
	///
	/// # Which bound
	///
	/// The Threshold ML-DSA proof (Mithril, "Efficient Threshold ML-DSA", §3.2-3.4)
	/// requires the challenge-shifted recovered partial `(c·u1/ν, c·u2)` to satisfy
	/// `‖(c·u1/ν, c·u2)‖₂ ≤ B` with overwhelming probability over the challenge `c`,
	/// where `B` is the partial-secret norm bound from §3.4:
	///
	/// ```text
	/// B = 1.3 · √τ · √(n·(k + ℓ/ν²)) · √Var(U(−η,η)) · √⌈C(N, T−1)/T⌉
	/// ```
	///
	/// This is the bound the hyperball radii `(r, r')` are derived from via
	/// `r'² ≥ r² + B² + 2rB/φ` (Lemma 2.4 / §3.4); it is *not* `r'` itself. The
	/// randomness radius `r' ≈ 6·10⁵` is roughly two to three orders of magnitude
	/// larger than `B`, so comparing against `r'` does not enforce the proof's
	/// condition. We therefore compare against `B` directly.
	///
	/// # Challenge factor
	///
	/// The shift to bound is `c·u`. For a `SampleInBall` challenge with `τ` nonzero
	/// `±1` coefficients, `E_c[‖c·u‖₂²] = τ·‖u‖₂²`, so `‖c·u‖₂ ≈ √τ·‖u‖₂` (the
	/// Gaussian heuristic used to define `B`; see Mithril footnote 3). We use the
	/// `√τ` factor here rather than the worst-case `‖c‖₁ = τ` factor so that the
	/// quantity compared and the bound `B` use the same convention.
	fn verify_recovered_partial_norms(&self) -> Result<(), ResharingProtocolError> {
		let my_idx =
			self.config.new_participants().index_of(self.config.my_party_id()).ok_or_else(
				|| ResharingProtocolError::InternalError("not in new committee".into()),
			)?;

		let threshold = self.config.new_threshold();
		let parties = self.config.new_participants().len() as u32;
		// `get_hyperball_params` also validates that the new configuration is
		// supported; we use its `nu` for the weighted norm and ignore `(r, r')`.
		let (_, _, nu) = crate::protocol::signing::get_hyperball_params(threshold, parties)
			.ok_or_else(|| {
				ResharingProtocolError::ShareVerificationFailed(format!(
					"no hyperball parameters for new configuration ({}, {})",
					threshold, parties
				))
			})?;

		let bound = partial_secret_norm_bound(threshold, parties, nu);

		// Sharing patterns depend only on `(threshold, parties)`, so compute them once
		// and reuse across every signing set rather than re-deriving them per mask.
		let sharing_patterns =
			crate::protocol::secret_sharing::compute_sharing_patterns(threshold, parties)
				.map_err(|e| ResharingProtocolError::ShareVerificationFailed(e.into()))?;

		for signing_mask in generate_subset_masks(parties as usize, threshold as usize) {
			if (signing_mask & (1 << my_idx)) == 0 {
				continue;
			}

			let weighted_norm =
				self.recovered_partial_weighted_norm(&sharing_patterns, signing_mask, my_idx, nu)?;
			let challenge_bound = weighted_norm * (TAU as f64).sqrt();
			if challenge_bound > bound {
				let signing_set = self.config.new_participants().ids_from_mask(signing_mask);
				return Err(ResharingProtocolError::ShareVerificationFailed(format!(
					"recovered partial for signing set {:?} exceeds partial-secret norm \
					 bound: sqrt(tau) * weighted_norm = {:.0}, B = {:.0}",
					signing_set, challenge_bound, bound
				)));
			}
		}

		Ok(())
	}

	/// Per-subset stored-share norm guard (`B_G` analog).
	///
	/// Before checking recovered signing partials (which sum several stored
	/// subset shares and where zero-sum inflation can partially cancel), verify
	/// each individual aggregated new subset share `s_J^new` is within the
	/// single-share norm envelope. Defense in depth against attacks that
	/// inflate individual stored shares while arranging cancellation in the
	/// specific combinations the recovered-partial check sums.
	fn verify_stored_new_share_norms(&self) -> Result<(), ResharingProtocolError> {
		let threshold = self.config.new_threshold();
		let parties = self.config.new_participants().len() as u32;
		let (_, _, nu) = crate::protocol::signing::get_hyperball_params(threshold, parties)
			.ok_or_else(|| {
				ResharingProtocolError::ShareVerificationFailed(format!(
					"no hyperball parameters for new configuration ({}, {})",
					threshold, parties
				))
			})?;

		let bound = stored_subset_share_norm_bound(threshold, parties, nu);

		for (&j_mask, share) in &self.new_shares {
			let weighted_norm = single_share_weighted_norm(share, nu);
			if weighted_norm > bound {
				return Err(ResharingProtocolError::ShareVerificationFailed(format!(
					"stored new subset share {:b} exceeds single-share norm bound: \
					 weighted_norm = {:.0}, B_G = {:.0}",
					j_mask, weighted_norm, bound
				)));
			}
		}

		Ok(())
	}

	fn recovered_partial_weighted_norm(
		&self,
		sharing_patterns: &[Vec<u16>],
		signing_mask: SubsetMask,
		my_idx: usize,
		nu: f64,
	) -> Result<f64, ResharingProtocolError> {
		let threshold = self.config.new_threshold();
		let parties = self.config.new_participants().len() as u32;

		// Same perm build + pattern translation that signing-time recovery uses, so
		// the guard provably checks the exact share combination RSSRecover will sum.
		let translated_masks = crate::protocol::secret_sharing::translated_subset_masks(
			sharing_patterns,
			signing_mask,
			my_idx,
			threshold,
			parties,
		)
		.map_err(ResharingProtocolError::ShareVerificationFailed)?;

		let mut s1_acc = [[0i64; N as usize]; L];
		let mut s2_acc = [[0i64; N as usize]; K];

		for translated in translated_masks {
			let share = self.new_shares.get(&translated).ok_or_else(|| {
				ResharingProtocolError::ShareVerificationFailed(format!(
					"missing new subset share {:b} while checking signing set {:b}",
					translated, signing_mask
				))
			})?;

			for (acc_poly, share_poly) in s1_acc.iter_mut().zip(share.s1.iter()) {
				for (acc, &coeff) in acc_poly.iter_mut().zip(share_poly.iter()) {
					*acc += center_mod_q(coeff) as i64;
				}
			}
			for (acc_poly, share_poly) in s2_acc.iter_mut().zip(share.s2.iter()) {
				for (acc, &coeff) in acc_poly.iter_mut().zip(share_poly.iter()) {
					*acc += center_mod_q(coeff) as i64;
				}
			}
		}

		let s1_sq: f64 = s1_acc
			.iter()
			.flat_map(|poly| poly.iter())
			.map(|&c| {
				let x = c as f64;
				x * x
			})
			.sum();
		let s2_sq: f64 = s2_acc
			.iter()
			.flat_map(|poly| poly.iter())
			.map(|&c| {
				let x = c as f64;
				x * x
			})
			.sum();

		Ok((s1_sq / (nu * nu) + s2_sq).sqrt())
	}

	/// All members of new subset J must produce identical `s_J^new` (and thus identical
	/// commitments). Cross-verify that.
	///
	/// Only considers broadcasts from new committee members (the only honest
	/// producers of share commitments), and within those, only commitments
	/// for subsets the sender belongs to.
	fn verify_new_share_consistency(&self) -> Result<(), ResharingProtocolError> {
		let mut by_subset: BTreeMap<SubsetMask, Vec<(ParticipantId, [u8; COMMITMENT_HASH_SIZE])>> =
			BTreeMap::new();
		for (party, broadcast) in &self.round5_broadcasts {
			// Round 5 broadcasts are buffered from any participant (an
			// observer catching up may store them before Act is known), but
			// only new committee members contribute share commitments. Skip
			// everyone else before any content check, so a non-required
			// sender's broadcast cannot influence the outcome.
			if !self.config.new_participants().contains(*party) {
				continue;
			}
			for (j_mask, commit) in &broadcast.share_commitments {
				// Only accept commitments from parties that are in this new subset
				if self.config.new_participants().is_in_mask(*party, *j_mask) {
					by_subset.entry(*j_mask).or_default().push((*party, *commit));
				} else {
					log::warn!(
						"Ignoring share commitment from party {} for new_subset {:b}: \
						 party not in subset",
						party,
						j_mask
					);
				}
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

	/// Extract `rho` (matrix-A seed). Old/Both parties take it from their existing
	/// share; NewOnly parties extract it from the public key prefix.
	fn derive_rho(&self) -> [u8; 32] {
		if let Some(existing) = self.config.existing_share() {
			*existing.rho()
		} else {
			let mut rho = [0u8; 32];
			rho.copy_from_slice(&self.config.public_key().as_bytes()[..32]);
			rho
		}
	}

	/// Compute `t_J = A·s1_J^new + s2_J^new mod Q` for every new subset we hold.
	fn compute_my_partial_pks(&self) -> BTreeMap<SubsetMask, [[i32; N as usize]; K]> {
		let rho = self.derive_rho();
		self.new_shares
			.iter()
			.map(|(j_mask, share)| {
				let t =
					crate::protocol::partial_pk::compute_partial_pk_t(&rho, &share.s1, &share.s2);
				(*j_mask, t)
			})
			.collect()
	}

	/// Cross-check the broadcast partial PKs and sum them to confirm the
	/// resharing reconstructs the original public key.
	///
	/// Only considers broadcasts from new committee members (the only honest
	/// producers of partial PKs), and within those, only contributions for
	/// subsets the sender belongs to.
	fn verify_public_key_preservation(&self) -> Result<(), ResharingProtocolError> {
		// The public key is the sum of exactly one partial PK per canonical new subset
		// (`new_subset_order`). Any other `j_mask` is not part of that sum, so we must
		// reject it outright rather than fold it in: otherwise a new committee member could
		// inject an extra term keyed by a non-canonical superset mask that still contains
		// its own index bit (e.g. the full-committee mask) with an attacker-chosen
		// `t_partial`, and use it to cancel a public-key deviation introduced by corrupted
		// residuals — making this invariant check pass on a broken reshare.
		let allowed_masks: BTreeSet<SubsetMask> = self.new_subset_order.iter().copied().collect();

		let mut canonical: BTreeMap<SubsetMask, [[i32; N as usize]; K]> = BTreeMap::new();
		for (party, broadcast) in &self.round5_broadcasts {
			// Skip broadcasts from senders outside the new committee BEFORE
			// the non-canonical-mask hard reject below. Round 5 broadcasts
			// are buffered from any participant, so without this filter an
			// old member excluded from the active set — whose broadcast the
			// session must be able to proceed without — could abort every
			// session by sending success=true with a single poisoned mask,
			// and only on the parties that happened to receive it.
			if !self.config.new_participants().contains(*party) {
				if !broadcast.partial_pks.is_empty() {
					log::warn!(
						"Ignoring partial PKs from party {}: not a new committee member",
						party
					);
				}
				continue;
			}
			for (j_mask, t_partial) in &broadcast.partial_pks {
				// Reject partial PKs keyed by any mask that is not a canonical new subset.
				// An honest party never broadcasts one; a malicious party could use it to
				// smuggle a compensating term into the public-key sum.
				if !allowed_masks.contains(j_mask) {
					return Err(ResharingProtocolError::ShareVerificationFailed(format!(
						"party {} broadcast a partial PK for non-canonical subset {:b}",
						party, j_mask
					)));
				}
				// Only accept partial PKs from parties that are in this new subset
				if !self.config.new_participants().is_in_mask(*party, *j_mask) {
					log::warn!(
						"Ignoring partial PK from party {} for new_subset {:b}: \
						 party not in subset",
						party,
						j_mask
					);
					continue;
				}
				match canonical.get(j_mask) {
					None => {
						canonical.insert(*j_mask, *t_partial);
					},
					Some(existing) =>
						if existing != t_partial {
							return Err(ResharingProtocolError::ShareVerificationFailed(format!(
								"members of new subset {:b} disagree on partial PK t_J",
								j_mask
							)));
						},
				}
			}
		}
		for j_mask in &self.new_subset_order {
			if !canonical.contains_key(j_mask) {
				return Err(ResharingProtocolError::ShareVerificationFailed(format!(
					"missing partial PK contribution for new subset {:b}",
					j_mask
				)));
			}
		}
		let rho = self.derive_rho();
		// Reject partial PKs with non-canonical coefficients. An attacker-supplied
		// coefficient near i32::MAX would otherwise overflow the i32 accumulation
		// inside `pack_combined_pk` (panic in debug, silent wrap in release).
		let recovered = crate::protocol::partial_pk::pack_combined_pk(&rho, canonical.values())
			.map_err(|_| {
				ResharingProtocolError::ShareVerificationFailed(
					"a Round 5 partial public key contains out-of-range coefficients".to_string(),
				)
			})?;
		if recovered.as_bytes() != self.config.public_key().as_bytes() {
			return Err(ResharingProtocolError::ShareVerificationFailed(
				"recovered public key does not match the original — a dealer corrupted at \
				 least one sub-share contribution"
					.to_string(),
			));
		}
		Ok(())
	}

	fn build_output(
		&self,
		certificate: ResharingCertificate,
	) -> Result<ResharingOutput, ResharingProtocolError> {
		if !self.config.role().is_new_committee() {
			return Ok(ResharingOutput {
				private_share: None,
				public_key: self.config.public_key().clone(),
				new_config: self.config.new_config(),
				certificate,
			});
		}
		let new_share = self.build_private_key_share()?;
		Ok(ResharingOutput {
			private_share: Some(new_share),
			public_key: self.config.public_key().clone(),
			new_config: self.config.new_config(),
			certificate,
		})
	}

	fn build_private_key_share(&self) -> Result<PrivateKeyShare, ResharingProtocolError> {
		let mut shares_data: BTreeMap<u16, SecretShareData> = BTreeMap::new();
		for (j_mask, share) in &self.new_shares {
			// Convert from Vec to fixed-size arrays
			let mut s1_arr = [[0i32; N as usize]; L];
			for (i, poly) in share.s1.iter().enumerate().take(L) {
				s1_arr[i] = *poly;
			}
			let mut s2_arr = [[0i32; N as usize]; K];
			for (i, poly) in share.s2.iter().enumerate().take(K) {
				s2_arr[i] = *poly;
			}
			shares_data.insert(*j_mask, SecretShareData { s1: s1_arr, s2: s2_arr });
		}

		let rho = self.derive_rho();
		let tr = if let Some(existing) = self.config.existing_share() {
			*existing.tr()
		} else {
			*self.config.public_key().tr()
		};

		// Derive `party_key` from the actual share polynomials so it carries real
		// entropy (mirrors the C3 fix in the DKG path).
		let mut party_key = [0u8; 32];
		{
			let mut h = fips202::KeccakState::default();
			fips202::shake256_absorb(&mut h, b"reshare-party-key-v2");
			fips202::shake256_absorb(&mut h, &rho);
			fips202::shake256_absorb(&mut h, &self.config.my_party_id().to_le_bytes());
			// The linearization buffer holds raw secret share coefficients, so
			// it must be a zeroizing container (a plain Vec freed after
			// `clear()` leaves the coefficients in allocator memory) and it
			// must be allocated at full size up front (growing mid-fill would
			// free an unwiped intermediate block).
			const SUBSET_BYTES: usize = 2 + (L + K) * N as usize * core::mem::size_of::<i32>();
			let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(SUBSET_BYTES));
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
				fips202::shake256_absorb(&mut h, &buf);
			}
			fips202::shake256_finalize(&mut h);
			fips202::shake256_squeeze(&mut party_key, &mut h);
		}

		Ok(PrivateKeyShare::new(
			self.config.my_party_id(),
			self.config.new_participants().len() as u32,
			self.config.new_threshold(),
			party_key,
			rho,
			tr,
			shares_data,
			self.config.new_participants().clone(),
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
	let n = config.old_participants().len();
	let k = n - config.old_threshold() as usize + 1;
	generate_subset_masks(n, k)
}

fn compute_new_subset_order(config: &ResharingConfig) -> Vec<SubsetMask> {
	let n = config.new_participants().len();
	let k = n - config.new_threshold() as usize + 1;
	generate_subset_masks(n, k)
}

/// Binomial coefficient `C(n, k)`. Inputs are tiny here (`n ≤ MAX_PARTIES`), so
/// the naive multiplicative form cannot overflow `u64`.
fn binomial(n: u32, k: u32) -> u64 {
	if k > n {
		return 0;
	}
	let k = core::cmp::min(k, n - k) as u64;
	let mut result: u64 = 1;
	for i in 0..k {
		result = result * (n as u64 - i) / (i + 1);
	}
	result
}

/// Partial-secret norm bound `B` from the Threshold ML-DSA proof (Mithril §3.4).
///
/// ```text
/// B = 1.3 · √τ · √(n·(k + ℓ/ν²)) · √Var(U(−η,η)) · √⌈C(N, T−1)/T⌉
/// ```
///
/// `B` bounds the challenge-shifted recovered partial `‖(c·u1/ν, c·u2)‖₂` that
/// the hyperball rejection-sampling analysis requires (and that the radii
/// `(r, r')` are derived from). It is calibrated to a *fresh keygen* partial:
/// a sum of `⌈C(N, T−1)/T⌉` base subset shares whose coefficients are
/// `η`-bounded with per-coefficient variance `Var(U(−η,η)) = η(η+1)/3`.
///
/// `1.3` is the `≈13·σ` Gaussian tail factor on `‖c·u‖`, and `√τ` is the
/// challenge amplification (`E_c[‖c·u‖₂²] = τ·‖u‖₂²`); both follow Mithril §3.4
/// and footnote 3.
fn partial_secret_norm_bound(threshold: u32, parties: u32, nu: f64) -> f64 {
	let num_secrets = {
		let c = binomial(parties, threshold - 1) as f64;
		(c / threshold as f64).ceil()
	};
	partial_secret_norm_bound_with_num_secrets(threshold, parties, nu, num_secrets)
}

/// Norm bound for a single stored RSS subset share (`B_G` analog).
///
/// Uses the same Mithril §3.4 calibration as [`partial_secret_norm_bound`], but
/// with `num_secrets = 1` because each stored subset share aggregates one base
/// secret's worth of material rather than the `⌈C(N,T−1)/T⌉` shares summed at
/// signing recovery time.
fn stored_subset_share_norm_bound(threshold: u32, parties: u32, nu: f64) -> f64 {
	partial_secret_norm_bound_with_num_secrets(threshold, parties, nu, 1.0)
}

fn partial_secret_norm_bound_with_num_secrets(
	threshold: u32,
	parties: u32,
	nu: f64,
	num_secrets: f64,
) -> f64 {
	let n = N as f64;
	let dim = n * (K as f64 + L as f64 / (nu * nu));
	let var_eta = ETA as f64 * (ETA as f64 + 1.0) / 3.0;
	let base = 1.3 * (TAU as f64).sqrt() * (dim * var_eta * num_secrets).sqrt();
	base * resharing_norm_enlargement(threshold, parties)
}

fn single_share_weighted_norm(share: &NewShareData, nu: f64) -> f64 {
	let s1_sq: f64 = share
		.s1
		.iter()
		.flat_map(|poly| poly.iter())
		.map(|&c| {
			let x = center_mod_q(c) as f64;
			x * x
		})
		.sum();
	let s2_sq: f64 = share
		.s2
		.iter()
		.flat_map(|poly| poly.iter())
		.map(|&c| {
			let x = center_mod_q(c) as f64;
			x * x
		})
		.sum();
	(s1_sq / (nu * nu) + s2_sq).sqrt()
}

/// Per-config enlargement factor `κ` applied to the keygen-calibrated bound `B`.
///
/// Honest resharing inflates the recovered-partial norm past the keygen `B`. With
/// the v5 mean-subtracted coset splitter (sparse-ternary deltas scaled `∝ 1/S_old`
/// minus their balanced mean, see `derive_subshares_with_session_seed` /
/// `add_mean_subtracted_noise`) the steady-state overshoot is ~0.78–1.16× across
/// committees `2 ≤ T ≤ N ≤ 6`, instead of the `~√S_old` growth of the old fixed-CBD
/// splitter (2-of-3: 1.22×, 3-of-5: 2.61×, 4-of-6: 4.50×).
///
/// To accept honest reshares we enlarge `B → κ·B` *and* the hyperball radii
/// `(r, r') → (κ·r, κ·r')` together (see `get_hyperball_params`). Scaling all of
/// `(B, r, r')` by a common `κ` is scale-invariant in the radius condition
/// `r'² = r² + B² + 2rB/φ`, so the per-sample rejection leakage `ε` is unchanged.
/// The signing-query budget `Q_s = 1/(K·ε)` is *not* preserved, though: the larger
/// ball lowers per-iteration acceptance (the radius nears ML-DSA-87's fixed
/// verification ceilings), so `K` grows — and with `ε` fixed, `Q_s` falls by that
/// same `K` factor (e.g. `(3,5)` K 35→60 at κ=1.15). Configs whose overshoot is
/// below 1 keep κ = 1 and pay nothing. See `config.rs` for `K` and SECURITY_PROOF.md
/// ("Bound `B` … and `Q_s`") for the bit-loss table.
///
/// This is only possible while the enlarged radius stays under ML-DSA-87's fixed
/// verification ceiling (`‖z₁‖∞ < γ1 − β`), which caps κ at ≈1.5×. The κ below were
/// re-derived for the **v5 mean-subtracted ("coset") splitter** from the *measured*
/// honest overshoot (Rust `test_recovered_partial_variance_*`, fixed point over all
/// signing sets). v5's uniform negative correlation lowered every overshoot vs v4:
///
/// - `(2,2)`: overshoot 0.780× → κ = 1.00, K = 4.   (reshare within base `B`: a
/// - `(2,3)`: overshoot 0.810× → κ = 1.00, K = 5.    reshared committee signs with exactly the same
///   params as a fresh keygen committee — no enlargement, no `Q_s` cost.)
/// - `(2,4)`: overshoot 0.961× → κ = 1.10, K = 10.
/// - `(3,5)`: overshoot 1.012× → κ = 1.15, K = 60.  (was κ=1.30/K=227 under v4 — v5 recovers ~1.9
///   bits of `Q_s`.)
/// - `(4,6)`: overshoot 1.163× → κ = 1.25, K = 1600.  (Enabled by enlargement: this `K` taxes
///   *every* `(4,6)` signature, ~15 MB/signature, Q_s ≈ 2^28.2 ≈ 300M queries. Required for the
///   `near-mpc` 4-of-6 committee shape. Removing this tax (back to κ=1 / K=350) is future work:
///   budget the per-reshare noise intensity down for a bounded reshare count, or draw a single
///   collaborative coset-Gaussian sample (one extra MPC round) for keygen-level hiding at κ=1.)
///
/// The `(4,6)` overshoot 1.163× is extremely stable (1.153–1.163 across 8 seeds, the
/// recovered-partial norm concentrates), so κ=1.25 carries a ~7.5% margin against a
/// worst-case that barely moves.
///
/// Exposed (re-exported at `resharing::resharing_norm_enlargement`) for analysis and
/// testing: the recovered-partial regression tests assert that the measured honest
/// overshoot stays `≤ κ`, the exact margin this guard enlargement provides.
pub fn resharing_norm_enlargement(threshold: u32, parties: u32) -> f64 {
	match (threshold, parties) {
		// Re-derived for the v5 mean-subtracted coset splitter: kappa = measured honest
		// overshoot (+ ~7-15% margin where >1). Scaling (r,r') by the same kappa keeps
		// per-sample leakage eps fixed (get_hyperball_params); K sets Q_s = 1/(K*eps).
		(2, 4) => 1.10, // overshoot 0.961x
		(3, 5) => 1.15, // overshoot 1.012x
		(4, 6) => 1.25, // overshoot 1.163x (enabled for near-mpc; K = 1600)
		// (2,2) 0.780x, (2,3) 0.810x: comfortably below base B, reshare at kappa = 1.
		_ => 1.0,
	}
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

/// Derive bounded sub-shares `r_{I→J}` for every new subset `J` such that
/// `Σ_J r_{I→J} = s_I` (mod Q).
///
/// Earlier versions sampled all but one sub-share as η-bounded values and let
/// one residual absorb the full difference. That preserves the secret, but the
/// residual can become a full-ring value and cause recovered signing partials
/// to leave the hyperball proof regime after repeated resharings.
///
/// This splitter first distributes the centered coefficient of `s_I` as evenly
/// as possible across all new subsets, then adds deterministic zero-sum noise via
/// *balanced mean subtraction* (`add_mean_subtracted_noise`: sample `m` i.i.d.
/// deltas, subtract the balanced split of their sum). The integer sum of the
/// outputs is exactly the centered representative of `s_I`, hence the modular sum
/// is `s_I`. (Older `v4` used an `O(m)` telescoping cycle `delta_i − delta_{i−1}`;
/// its banded correlation overshot for non-contiguous recovery patterns.)
///
/// # Fresh re-sharing (noise intensity)
///
/// The deltas are sparse-ternary with intensity `≈ 0.49 / S_old` (see
/// `split_noise_threshold`). Because each new share `s_J^new = Σ_I r_{I→J}` sums
/// contributions from all `S_old = num_old_subsets` old subsets, scaling each
/// dealer's noise as `1/S_old` makes the *aggregated* new-share noise land at the
/// keygen level. The new shares are then distributed like a fresh keygen secret
/// sharing (Mithril §3.3 *a posteriori* sharing), so recovered signing partials
/// stay under the keygen norm envelope `B` instead of growing with the committee.
fn derive_subshares_with_session_seed(
	i_mask: SubsetMask,
	s_i: &SecretShareData,
	new_subsets: &[SubsetMask],
	session_seed: &[u8; 32],
	num_old_subsets: usize,
) -> Vec<NewShareData> {
	debug_assert!(!new_subsets.is_empty());
	let mut out: Vec<NewShareData> = (0..new_subsets.len()).map(|_| NewShareData::new()).collect();

	// Build a PRF seed from (domain || session_seed || I_mask || s1 || s2).
	// All members of subset I know `s_i` and have computed the same session_seed,
	// so they derive the same PRF seed.
	let prf_seed = build_subset_seed_with_session(i_mask, s_i, session_seed);
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, BOUNDED_SPLIT_DOMAIN);
	fips202::shake256_absorb(&mut state, &prf_seed);
	for &j_mask in new_subsets {
		fips202::shake256_absorb(&mut state, &j_mask.to_le_bytes());
	}
	fips202::shake256_finalize(&mut state);

	let m = new_subsets.len();

	for poly_idx in 0..L {
		for coeff_idx in 0..N as usize {
			balanced_split_coeff(
				s_i.s1[poly_idx][coeff_idx],
				&mut out,
				true,
				poly_idx,
				coeff_idx,
				&mut state,
			);
		}
	}
	for poly_idx in 0..K {
		for coeff_idx in 0..N as usize {
			balanced_split_coeff(
				s_i.s2[poly_idx][coeff_idx],
				&mut out,
				false,
				poly_idx,
				coeff_idx,
				&mut state,
			);
		}
	}

	// Add integer zero-sum hiding noise via *balanced mean subtraction*. For each
	// coefficient we sample `m` i.i.d. sparse-ternary deltas and subtract the
	// balanced split of their sum (`add_mean_subtracted_noise`), giving
	// `N_j = δ_j − balanced(Σδ)_j` with `Σ_j N_j = 0`, so the exact integer secret
	// identity is preserved.
	//
	// Unlike the v4 telescoping cycle, this yields the *uniform* negative
	// correlation `Cov(N_j,N_k) = −σ²/m` of the a-posteriori coset Gaussian, so
	// `Var(Σ_{J∈pattern} N_J) = σ²·|pattern|·(1 − |pattern|/m)` matches the keygen
	// conditional partial variance for *every* recovery pattern — the overshoot no
	// longer depends on the (arbitrary) subset ordering. Hiding holds because the
	// noise is PRF-derived and keyed to `(session_seed, i_mask, s_i)`.
	//
	// The per-subset deltas are sparse-ternary with intensity `≈ 0.49/S_old`
	// (`split_noise_threshold`): each dealer injects only `1/S_old` of the keygen
	// noise, so the aggregated noise across the `S_old` dealers in
	// `s_J^new = Σ_I r_{I→J}` reaches the keygen level.
	let noise_t = split_noise_threshold(num_old_subsets);
	let mut deltas = vec![0i32; m];
	for poly_idx in 0..L {
		for coeff_idx in 0..N as usize {
			for d in deltas.iter_mut() {
				*d = sample_split_noise_coeff(&mut state, noise_t);
			}
			add_mean_subtracted_noise(&deltas, &mut out, true, poly_idx, coeff_idx, &mut state);
		}
	}
	for poly_idx in 0..K {
		for coeff_idx in 0..N as usize {
			for d in deltas.iter_mut() {
				*d = sample_split_noise_coeff(&mut state, noise_t);
			}
			add_mean_subtracted_noise(&deltas, &mut out, false, poly_idx, coeff_idx, &mut state);
		}
	}
	out
}

/// Add integer zero-sum hiding noise to one coefficient across all `m` new subset
/// shares, using *balanced mean subtraction*. Given i.i.d. deltas `δ_0..δ_{m-1}`,
/// subtract the balanced split of their sum so `N_j = δ_j − balanced(Σδ)_j` sums to
/// exactly zero. This reproduces the a-posteriori coset Gaussian's uniform negative
/// correlation (`Cov(N_j,N_k) = −σ²/m`), unlike the old telescoping cycle's banded
/// correlation. Consumes one PRF draw for the remainder offset, so it stays
/// deterministic and identical across all members of the old subset.
fn add_mean_subtracted_noise(
	deltas: &[i32],
	out: &mut [NewShareData],
	is_s1: bool,
	poly_idx: usize,
	coeff_idx: usize,
	state: &mut fips202::Shake256State,
) {
	let m = out.len();
	let m_i32 = m as i32;
	let total: i32 = deltas.iter().sum();
	let base = total.div_euclid(m_i32);
	let remainder = total.rem_euclid(m_i32) as usize;
	let offset = sample_uniform_usize(state, m);

	for (j_idx, share) in out.iter_mut().enumerate() {
		let gets_remainder = ((j_idx + m - offset) % m) < remainder;
		let sub = base + if gets_remainder { 1 } else { 0 };
		let noise = deltas[j_idx] - sub;
		if is_s1 {
			share.s1[poly_idx][coeff_idx] += noise;
		} else {
			share.s2[poly_idx][coeff_idx] += noise;
		}
	}
}

fn balanced_split_coeff(
	coeff: i32,
	out: &mut [NewShareData],
	is_s1: bool,
	poly_idx: usize,
	coeff_idx: usize,
	state: &mut fips202::Shake256State,
) {
	let m = out.len();
	let centered = center_mod_q(coeff);
	let m_i32 = m as i32;
	let base = centered.div_euclid(m_i32);
	let remainder = centered.rem_euclid(m_i32) as usize;
	let offset = sample_uniform_usize(state, m);

	for (j_idx, share) in out.iter_mut().enumerate() {
		let gets_remainder = ((j_idx + m - offset) % m) < remainder;
		let value = base + if gets_remainder { 1 } else { 0 };
		if is_s1 {
			share.s1[poly_idx][coeff_idx] = value;
		} else {
			share.s2[poly_idx][coeff_idx] = value;
		}
	}
}

#[inline]
fn center_mod_q(coeff: i32) -> i32 {
	let reduced = mod_q(coeff);
	if reduced > Q / 2 {
		reduced - Q
	} else {
		reduced
	}
}

/// Byte threshold `T` for the sparse-ternary split-noise sampler, given the
/// number of old RSS subsets `S_old`. Each delta is `+1` for PRF byte `< T`,
/// `-1` for `< 2T`, else `0`, so `P(±1) = T/256 ≈ 0.49 / S_old` each.
///
/// Computed with integer arithmetic (no float, `no_std`-friendly) as
/// `round(SPLIT_NOISE_NUM_X256 / S_old)`, clamped to `[1, 127]` so the three
/// bands always fit in a byte and noise never fully vanishes.
fn split_noise_threshold(num_old_subsets: usize) -> u32 {
	let s = num_old_subsets.max(1) as u32;
	// round(125 / s) = (125 + s/2) / s
	let t = (SPLIT_NOISE_NUM_X256 + s / 2) / s;
	t.clamp(1, 127)
}

/// Sample one sparse-ternary split-noise delta in `{-1, 0, +1}` from the PRF
/// stream, with `P(+1) = P(-1) = threshold / 256`. Consumes exactly one PRF byte
/// per coefficient, so it is deterministic and stream-aligned across all parties
/// (every member of an old subset derives identical sub-shares).
fn sample_split_noise_coeff(state: &mut fips202::Shake256State, threshold: u32) -> i32 {
	let mut buf = [0u8; 1];
	fips202::shake256_squeeze(&mut buf, state);
	let b = buf[0] as u32;
	if b < threshold {
		1
	} else if b < 2 * threshold {
		-1
	} else {
		0
	}
}

fn sample_uniform_usize(state: &mut fips202::Shake256State, upper: usize) -> usize {
	if upper <= 1 {
		return 0;
	}
	let cutoff = (256 / upper) * upper;
	let mut buf = [0u8; 1];
	loop {
		fips202::shake256_squeeze(&mut buf, state);
		let b = buf[0] as usize;
		if b < cutoff {
			return b % upper;
		}
	}
}

/// Build subset seed incorporating the public session seed.
fn build_subset_seed_with_session(
	i_mask: SubsetMask,
	s_i: &SecretShareData,
	session_seed: &[u8; 32],
) -> [u8; 64] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, SUBSET_SEED_DOMAIN);
	// Mix in session seed for per-session randomization.
	fips202::shake256_absorb(&mut state, session_seed);
	fips202::shake256_absorb(&mut state, &i_mask.to_le_bytes());
	// Holds raw old-share coefficients: zeroizing, pre-sized to one
	// polynomial so it never reallocates mid-fill.
	let mut buf: Zeroizing<Vec<u8>> =
		Zeroizing::new(Vec::with_capacity(N as usize * core::mem::size_of::<i32>()));
	for poly in &s_i.s1 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	for poly in &s_i.s2 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; 64];
	fips202::shake256_squeeze(&mut out, &mut state);
	out
}

/// Compute commitment to entropy: H("resharing-entropy-commit-v1" || entropy).
fn commit_entropy(entropy: &[u8; ENTROPY_SIZE]) -> [u8; COMMITMENT_HASH_SIZE] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, ENTROPY_COMMIT_DOMAIN);
	fips202::shake256_absorb(&mut state, entropy);
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; COMMITMENT_HASH_SIZE];
	fips202::shake256_squeeze(&mut out, &mut state);
	out
}

fn commit_subshare(
	i_mask: SubsetMask,
	j_mask: SubsetMask,
	r: &NewShareData,
) -> [u8; COMMITMENT_HASH_SIZE] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, COMMIT_DOMAIN);
	fips202::shake256_absorb(&mut state, &i_mask.to_le_bytes());
	fips202::shake256_absorb(&mut state, &j_mask.to_le_bytes());
	// Holds raw sub-share coefficients: zeroizing, pre-sized to one
	// polynomial so it never reallocates mid-fill.
	let mut buf: Zeroizing<Vec<u8>> =
		Zeroizing::new(Vec::with_capacity(N as usize * core::mem::size_of::<i32>()));
	for poly in &r.s1 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	for poly in &r.s2 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; COMMITMENT_HASH_SIZE];
	fips202::shake256_squeeze(&mut out, &mut state);
	out
}

fn commit_new_share(j_mask: SubsetMask, share: &NewShareData) -> [u8; COMMITMENT_HASH_SIZE] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, NEW_SHARE_COMMIT_DOMAIN);
	fips202::shake256_absorb(&mut state, &j_mask.to_le_bytes());
	// Holds raw new-share coefficients: zeroizing, pre-sized to one
	// polynomial so it never reallocates mid-fill.
	let mut buf: Zeroizing<Vec<u8>> =
		Zeroizing::new(Vec::with_capacity(N as usize * core::mem::size_of::<i32>()));
	for poly in &share.s1 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	for poly in &share.s2 {
		buf.clear();
		for c in poly {
			buf.extend_from_slice(&c.to_le_bytes());
		}
		fips202::shake256_absorb(&mut state, &buf);
	}
	fips202::shake256_finalize(&mut state);
	let mut out = [0u8; COMMITMENT_HASH_SIZE];
	fips202::shake256_squeeze(&mut out, &mut state);
	out
}

fn add_share_into(acc: &mut NewShareData, r: &NewShareData) {
	// Bounded conditional sub-shares are small for supported n <= 6 configurations,
	// so accumulation cannot overflow i32 before the final mod-Q reduction.
	for (a, b) in acc.s1.iter_mut().zip(r.s1.iter()) {
		for (ac, bc) in a.iter_mut().zip(b.iter()) {
			*ac += *bc;
		}
	}
	for (a, b) in acc.s2.iter_mut().zip(r.s2.iter()) {
		for (ac, bc) in a.iter_mut().zip(b.iter()) {
			*ac += *bc;
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

	/// Test SSID for use in unit tests.
	const TEST_SSID: [u8; RESHARING_SSID_SIZE] = [0xABu8; RESHARING_SSID_SIZE];

	/// Minimal transcript signer for unit tests: "signature" = party_id || hash.
	#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
	pub(crate) struct TestSigner {
		pub id: u32,
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

	/// Build a `ResharingSignerConfig<TestSigner>` covering `participants`.
	fn test_signer_config(my_id: u32, participants: &[u32]) -> ResharingSignerConfig<TestSigner> {
		let keys: BTreeMap<u32, u32> = participants.iter().map(|&p| (p, p)).collect();
		ResharingSignerConfig::new(TestSigner { id: my_id }, keys, participants)
			.expect("keys cover participants")
	}

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
		let s = SecretShareData { s1: [[3i32; N as usize]; L], s2: [[5i32; N as usize]; K] };
		let session_seed = [42u8; 32];
		assert_eq!(
			build_subset_seed_with_session(0b011, &s, &session_seed),
			build_subset_seed_with_session(0b011, &s, &session_seed)
		);
	}

	#[test]
	fn test_derive_subshares_sums_to_original_share() {
		let s = SecretShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let subshares = derive_subshares_with_session_seed(
			0b011,
			&s,
			&new_subsets,
			&session_seed,
			new_subsets.len(),
		);
		let mut sum_s1: Vec<[i64; N as usize]> = vec![[0i64; N as usize]; L];
		let mut sum_s2: Vec<[i64; N as usize]> = vec![[0i64; N as usize]; K];
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

	#[test]
	fn test_derive_subshares_are_bounded_for_small_inputs() {
		let s = SecretShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let subshares = derive_subshares_with_session_seed(
			0b011,
			&s,
			&new_subsets,
			&session_seed,
			new_subsets.len(),
		);
		let max_expected = 1 + (new_subsets.len() as i32 - 1) * ETA as i32;

		for sub in &subshares {
			for poly in &sub.s1 {
				for &coeff in poly {
					assert!(
						coeff.abs() <= max_expected,
						"s1 coefficient {} exceeded {}",
						coeff,
						max_expected
					);
				}
			}
			for poly in &sub.s2 {
				for &coeff in poly {
					assert!(
						coeff.abs() <= max_expected,
						"s2 coefficient {} exceeded {}",
						coeff,
						max_expected
					);
				}
			}
		}
	}

	#[test]
	fn test_derive_subshares_handles_centered_mod_q_inputs() {
		let s = SecretShareData { s1: [[Q - 1; N as usize]; L], s2: [[Q - 2; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let subshares = derive_subshares_with_session_seed(
			0b011,
			&s,
			&new_subsets,
			&session_seed,
			new_subsets.len(),
		);

		let mut sum_s1: Vec<[i64; N as usize]> = vec![[0i64; N as usize]; L];
		let mut sum_s2: Vec<[i64; N as usize]> = vec![[0i64; N as usize]; K];
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

		let q = Q as i64;
		for poly in &sum_s1 {
			for &v in poly {
				assert_eq!((v % q + q) % q, (Q - 1) as i64);
			}
		}
		for poly in &sum_s2 {
			for &v in poly {
				assert_eq!((v % q + q) % q, (Q - 2) as i64);
			}
		}
	}

	#[test]
	fn test_derive_subshares_is_deterministic() {
		let s = SecretShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let a = derive_subshares_with_session_seed(
			0b011,
			&s,
			&new_subsets,
			&session_seed,
			new_subsets.len(),
		);
		let b = derive_subshares_with_session_seed(
			0b011,
			&s,
			&new_subsets,
			&session_seed,
			new_subsets.len(),
		);
		for (x, y) in a.iter().zip(b.iter()) {
			assert_eq!(x.s1, y.s1);
			assert_eq!(x.s2, y.s2);
		}
	}

	#[test]
	fn test_commit_subshare_distinguishes_inputs() {
		let r1 = NewShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let r2 = NewShareData { s1: [[1i32; N as usize]; L], s2: [[3i32; N as usize]; K] };
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
		let send_private: Action<()> = Action::SendPrivate(42, Zeroizing::new(vec![4, 5, 6]));
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
				assert_eq!(*data, vec![4, 5, 6]);
			},
			_ => panic!("Expected SendPrivate"),
		}
		match ret {
			Action::Return(val) => assert_eq!(val, 123),
			_ => panic!("Expected Return"),
		}
	}

	/// Build a 2-of-3 old-committee protocol for party 1, returning the
	/// protocol and a copy of party 1's original share.
	fn share_recovery_fixture() -> (ResharingProtocol<TestSigner>, PrivateKeyShare) {
		let config = crate::ThresholdConfig::new(2, 3).expect("valid config");
		let (public_key, shares) =
			crate::keygen::generate_with_dealer(&[8u8; 32], config).expect("keygen");
		let original = shares[1].clone();
		let resharing_config = ResharingConfig::new(
			Some(shares[1].clone()),
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			1,
			public_key,
		)
		.expect("valid resharing config");
		let protocol = ResharingProtocol::new(
			resharing_config,
			test_signer_config(1, &[0, 1, 2]),
			[1u8; 32],
			&[2u8; 32],
			0,
		);
		(protocol, original)
	}

	/// A session that fails before Round 6 certification has produced no
	/// replacement share, so the old committee member must be able to recover
	/// their share for a retry instead of losing it when the failed protocol
	/// is dropped.
	#[test]
	fn failed_session_allows_old_share_recovery() {
		let (mut protocol, original) = share_recovery_fixture();

		// A peer-induced abort: e.g. leader equivocation or verification failure.
		protocol.state = ResharingState::Failed("attacker stalled the session".to_string());

		let recovered = protocol
			.take_existing_share()
			.expect("failed session must preserve the old share for retry");
		assert_eq!(recovered, original, "recovered share must be intact");
		// The protocol no longer holds the share; dropping it is now safe.
		assert!(protocol.old_share_erased());
	}

	/// Recovering the share from an in-flight (stalled) session must also work,
	/// and must render the session terminal: it cannot continue without the
	/// share, and a later poke must not resurrect it.
	#[test]
	fn share_recovery_marks_in_flight_session_failed() {
		let (mut protocol, original) = share_recovery_fixture();

		// Session stalled mid-protocol (e.g. transport timeout while waiting).
		let recovered =
			protocol.take_existing_share().expect("stalled session must yield the share");
		assert_eq!(recovered, original);
		assert!(protocol.is_failed(), "session must be terminal after share recovery");
	}

	/// After a successful handoff the old share is erased at finalize; the
	/// recovery path must not bypass that erasure.
	#[test]
	fn share_recovery_returns_none_after_successful_completion() {
		let (mut protocol, _original) = share_recovery_fixture();

		// Mirror the finalize order: erase session secrets, then mark Done.
		protocol.zeroize_session_secrets();
		protocol.state = ResharingState::Done;

		assert!(protocol.take_existing_share().is_none());
		assert!(protocol.is_done(), "recovery attempt must not disturb a completed session");
	}

	/// The `SendPrivate` payload carries the borsh-serialized Round 4 message,
	/// which contains plaintext sub-share coefficients. Its `Debug` output must
	/// never expose those secret bytes, otherwise any downstream `{:?}` logging
	/// persists share material outside the encrypted transport path.
	#[test]
	fn send_private_debug_does_not_leak_subshares() {
		// A recognizable coefficient whose little-endian bytes are all 0xAB
		// (== 171 decimal), so the serialized payload contains long runs of
		// the exact form a derived `Debug` on `Vec<u8>` would print.
		let marker = [0xABu8; 4];
		let coeff = i32::from_le_bytes(marker);
		let contribution =
			NewShareData { s1: [[coeff; N as usize]; L], s2: [[coeff; N as usize]; K] };
		let mut contributions = BTreeMap::new();
		contributions.insert((0b011, 0b101), contribution);
		let msg = ResharingRound4Message {
			// Non-marker ssid so the sanity check below matches sub-share
			// bytes, not session metadata.
			ssid: [0x11u8; RESHARING_SSID_SIZE],
			from_party_id: 1,
			to_party_id: 3,
			contributions,
		};
		let data = borsh::to_vec(&ResharingMessage::Round4(msg)).unwrap();

		// Sanity: the sub-share coefficients really are inside the payload.
		assert!(
			data.windows(marker.len()).any(|w| w == marker),
			"test setup: sub-share bytes not present in serialized payload"
		);

		let action: Action<()> = Action::SendPrivate(3, Zeroizing::new(data));
		let rendered = format!("{action:?}");

		// A derived `Debug` renders the payload as `[.., 171, 171, ..]`; the
		// redacting impl must emit no run of the secret bytes.
		assert!(
			!rendered.contains("171, 171"),
			"SendPrivate Debug leaked raw sub-share bytes: {rendered}"
		);
		// Still useful for debugging: recipient visible, payload redacted.
		assert!(rendered.contains("to: 3"), "recipient should stay visible: {rendered}");
		assert!(rendered.contains("redacted"), "payload should be redacted: {rendered}");
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
		let s_a = SecretShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let s_b = SecretShareData { s1: [[3i32; N as usize]; L], s2: [[5i32; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let a = derive_subshares_with_session_seed(
			0b011,
			&s_a,
			&new_subsets,
			&session_seed,
			new_subsets.len(),
		);
		let b = derive_subshares_with_session_seed(
			0b011,
			&s_b,
			&new_subsets,
			&session_seed,
			new_subsets.len(),
		);
		// The bounded split includes PRF-derived zero-sum noise keyed by `s_i`,
		// so shares for different old secrets must differ.
		assert_ne!(a[1].s1, b[1].s1);
	}

	#[test]
	fn test_subshares_independent_per_old_subset() {
		// Different old subsets sharing the same `s_I^old` value must still produce
		// different sub-shares, because the PRF seed mixes `i_mask`.
		let s = SecretShareData { s1: [[1i32; N as usize]; L], s2: [[2i32; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let a = derive_subshares_with_session_seed(
			0b011,
			&s,
			&new_subsets,
			&session_seed,
			new_subsets.len(),
		);
		let b = derive_subshares_with_session_seed(
			0b101,
			&s,
			&new_subsets,
			&session_seed,
			new_subsets.len(),
		);
		// The bounded split includes PRF-derived zero-sum noise keyed on `i_mask`,
		// so shares for different old subsets must differ.
		assert_ne!(a[1].s1, b[1].s1);
	}

	#[test]
	fn test_round3_broadcast_does_not_leak_subshares() {
		// Sanity: a Round 3 broadcast carries hash commitments and nothing else.
		// In particular it must not contain any plaintext NewShareData fields.
		let mut commitments = BTreeMap::new();
		commitments.insert((0b011u16, 0b101u16), [9u8; COMMITMENT_HASH_SIZE]);
		let r3 = ResharingRound3Broadcast { ssid: TEST_SSID, party_id: 7, commitments };
		// The struct only has `ssid`, `party_id` (u32) and `commitments` (BTreeMap of hashes).
		// If anyone ever adds back leaky plaintext fields, this test should be
		// updated alongside the security review.
		assert_eq!(r3.party_id, 7);
		assert_eq!(r3.commitments.len(), 1);
	}

	#[test]
	fn test_old_subset_peer_verifies_dealer_round3_commitments() {
		let config = crate::ThresholdConfig::new(2, 3).expect("valid config");
		let (public_key, shares) =
			crate::keygen::generate_with_dealer(&[8u8; 32], config).expect("keygen");
		let resharing_config = ResharingConfig::new(
			Some(shares[1].clone()),
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			1,
			public_key,
		)
		.expect("valid resharing config");
		let mut protocol = ResharingProtocol::new(
			resharing_config,
			test_signer_config(1, &[0, 1, 2]),
			[1u8; 32],
			&[2u8; 32],
			0,
		);
		let session_seed = [9u8; 32];
		protocol.session_seed = Some(session_seed);
		// Model the post-Act state: the full old committee is active.
		protocol.active_set = Some(vec![0, 1, 2]);

		let i_mask = 0b011u16;
		let s_i = shares[0].shares().get(&i_mask).expect("old subset share");
		let subshares = derive_subshares_with_session_seed(
			i_mask,
			s_i,
			&protocol.new_subset_order,
			&session_seed,
			protocol.old_subset_order.len(),
		);
		let mut commitments = BTreeMap::new();
		for (j_mask, subshare) in protocol.new_subset_order.iter().zip(subshares.iter()) {
			commitments.insert((i_mask, *j_mask), commit_subshare(i_mask, *j_mask, subshare));
		}

		protocol.round3_broadcasts.insert(
			0,
			ResharingRound3Broadcast {
				ssid: protocol.ssid,
				party_id: 0,
				commitments: commitments.clone(),
			},
		);
		assert!(protocol.verify_peer_dealer_commitments().is_ok());

		let target_j = protocol.new_subset_order[0];
		let mut tampered = subshares[0].clone();
		tampered.s2[0][0] += 1;
		commitments.insert((i_mask, target_j), commit_subshare(i_mask, target_j, &tampered));
		protocol
			.round3_broadcasts
			.insert(0, ResharingRound3Broadcast { ssid: protocol.ssid, party_id: 0, commitments });

		let err = protocol
			.verify_peer_dealer_commitments()
			.expect_err("old subset peer must reject tampered commitment");
		assert!(err.to_string().contains("commitment mismatch"), "unexpected error: {}", err);
	}

	#[test]
	fn test_recovered_partial_norm_guard_rejects_pk_preserving_zero_sum_noise() {
		let config = crate::ThresholdConfig::new(2, 3).expect("valid config");
		let (public_key, shares) =
			crate::keygen::generate_with_dealer(&[7u8; 32], config).expect("keygen");
		let resharing_config = ResharingConfig::new(
			Some(shares[1].clone()),
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			1,
			public_key,
		)
		.expect("valid resharing config");
		let mut protocol = ResharingProtocol::new(
			resharing_config,
			test_signer_config(1, &[0, 1, 2]),
			[1u8; 32],
			&[2u8; 32],
			0,
		);

		// This models a bounded zero-sum reshaping attack: +delta on one new RSS
		// subset and -delta on another preserves the aggregate public key, and each
		// individual subset is still within SUBSHARE_COEFF_BOUND. It nevertheless
		// makes some recovered signing partials too large for the existing hyperball
		// proof envelope.
		let mut plus = NewShareData::new();
		let mut minus = NewShareData::new();
		for poly in plus.s2.iter_mut() {
			for coeff in poly.iter_mut() {
				*coeff = 450;
			}
		}
		for poly in minus.s2.iter_mut() {
			for coeff in poly.iter_mut() {
				*coeff = -450;
			}
		}
		assert!(plus.coefficients_within_bound(SUBSHARE_COEFF_BOUND));
		assert!(minus.coefficients_within_bound(SUBSHARE_COEFF_BOUND));

		protocol.new_shares.insert(0b011, plus);
		protocol.new_shares.insert(0b110, minus);

		let err = protocol
			.verify_recovered_partial_norms()
			.expect_err("oversized recovered partial must be rejected");
		assert!(
			err.to_string().contains("exceeds partial-secret norm bound"),
			"unexpected error: {}",
			err
		);
	}

	#[test]
	fn test_public_key_preservation_rejects_non_canonical_mask() {
		// Regression test (security review): `verify_public_key_preservation` must reject a
		// Round 5 broadcast that carries a partial PK keyed by a mask outside the canonical
		// `new_subset_order`. Otherwise a malicious new committee member could inject an
		// extra term keyed by a superset mask that still contains its own index bit (e.g.
		// the full-committee mask) with an attacker-chosen `t_partial`, and use it to cancel
		// a public-key deviation introduced by corrupted residuals — passing the invariant
		// check on a broken reshare.
		let config = crate::ThresholdConfig::new(2, 3).expect("valid config");
		let (public_key, shares) =
			crate::keygen::generate_with_dealer(&[13u8; 32], config).expect("keygen");
		let resharing_config = ResharingConfig::new(
			Some(shares[0].clone()),
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			1,
			public_key,
		)
		.expect("valid resharing config");
		let protocol = ResharingProtocol::new(
			resharing_config,
			test_signer_config(0, &[0, 1, 2]),
			[1u8; 32],
			&[2u8; 32],
			0,
		);

		// With new n = 3, threshold = 2, the canonical subsets are the size-2 masks
		// {0b011, 0b101, 0b110}. The full-committee mask 0b111 is never canonical, yet it
		// contains party 0's index bit, so the old `is_in_mask` gate would have accepted it.
		let full_mask: SubsetMask = 0b111;
		assert!(
			!protocol.new_subset_order.contains(&full_mask),
			"full-committee mask must not be a canonical subset"
		);
		assert!(protocol.config.new_participants().is_in_mask(0, full_mask));

		let mut protocol = protocol;
		let mut partial_pks: BTreeMap<SubsetMask, [[i32; N as usize]; K]> = BTreeMap::new();
		partial_pks.insert(full_mask, [[7i32; N as usize]; K]);
		protocol.round5_broadcasts.insert(
			0,
			ResharingRound5Broadcast {
				ssid: protocol.ssid,
				party_id: 0,
				share_commitments: BTreeMap::new(),
				partial_pks,
				success: true,
				error_message: None,
			},
		);

		let err = protocol
			.verify_public_key_preservation()
			.expect_err("non-canonical partial PK mask must be rejected");
		assert!(err.to_string().contains("non-canonical subset"), "unexpected error: {}", err);
	}

	/// Companion to the test above (security review follow-up): the
	/// non-canonical-mask hard reject only applies to new committee members.
	/// A sender outside the new committee (e.g. an old member excluded from
	/// the active set) never contributes partial PKs honestly, so its
	/// broadcast must be skipped entirely — otherwise a poisoned mask from a
	/// party the session is promised to proceed without would abort every
	/// session, and only on the parties that happened to receive it.
	#[test]
	fn test_public_key_preservation_ignores_poisoned_mask_from_non_member() {
		let config = crate::ThresholdConfig::new(2, 3).expect("valid config");
		let (public_key, shares) =
			crate::keygen::generate_with_dealer(&[13u8; 32], config).expect("keygen");
		// Old committee {0,1,2}, new committee {0,1,3}: party 2 is OldOnly.
		let resharing_config = ResharingConfig::new(
			Some(shares[0].clone()),
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 3],
			0,
			public_key,
		)
		.expect("valid resharing config");
		let mut protocol = ResharingProtocol::new(
			resharing_config,
			test_signer_config(0, &[0, 1, 2, 3]),
			[1u8; 32],
			&[2u8; 32],
			0,
		);

		let full_mask: SubsetMask = 0b111;
		assert!(!protocol.new_subset_order.contains(&full_mask));

		let mut partial_pks: BTreeMap<SubsetMask, [[i32; N as usize]; K]> = BTreeMap::new();
		partial_pks.insert(full_mask, [[7i32; N as usize]; K]);
		protocol.round5_broadcasts.insert(
			2, // not a new committee member
			ResharingRound5Broadcast {
				ssid: protocol.ssid,
				party_id: 2,
				share_commitments: BTreeMap::new(),
				partial_pks,
				success: true,
				error_message: None,
			},
		);

		// The poisoned broadcast must be skipped: verification then fails
		// only because this bare setup has no partial PK data at all — not
		// with the non-canonical hard reject.
		let err = protocol
			.verify_public_key_preservation()
			.expect_err("bare setup has no partial PK contributions");
		assert!(
			!err.to_string().contains("non-canonical"),
			"poisoned mask from a non-member must be ignored, got: {}",
			err
		);
		assert!(
			err.to_string().contains("missing partial PK contribution"),
			"unexpected error: {}",
			err
		);
	}

	/// Regression test (security review): a Round 5 failure report from an old
	/// member that was excluded from the active set must not abort the
	/// session. Liveness is defined over `Act ∪ new_participants`
	/// (`have_all_round5`, transcript hash), so the failure-abort scan in
	/// Combining must use the same sender set — otherwise a single excluded
	/// (offline-then-recovered, leaving, or compromised) old member could
	/// deny completion of every resharing session.
	///
	/// The excluded member's broadcast also carries a partial PK keyed by a
	/// non-canonical mask: before the sender filter in
	/// `verify_public_key_preservation`, that was a second independent abort
	/// vector (the non-canonical hard reject ran before any membership
	/// check).
	#[test]
	fn test_combining_ignores_failure_from_excluded_old_member() {
		let mut protocol = combining_protocol_with_round5_failure_from(Some(2));

		let err = protocol.poke().expect_err("bare combining state cannot fully verify");
		assert!(
			!matches!(err, ResharingProtocolError::ProtocolAborted(_)),
			"excluded old member's failure report must not abort the session, got: {}",
			err
		);
		assert!(
			!err.to_string().contains("non-canonical"),
			"excluded old member's poisoned partial PK mask must be ignored, got: {}",
			err
		);
		// With the excluded member's broadcast ignored, Combining proceeds to
		// share verification, which fails on this bare test setup for lack of
		// partial PK data — proving neither abort path was taken.
		assert!(
			matches!(err, ResharingProtocolError::ShareVerificationFailed(_)),
			"unexpected error: {}",
			err
		);
	}

	/// Companion to the test above: a failure report from a *required* Round 5
	/// sender (here an active old member) must still abort.
	#[test]
	fn test_combining_aborts_on_failure_from_required_party() {
		let mut protocol = combining_protocol_with_round5_failure_from(Some(1));

		let err = protocol.poke().expect_err("failure from required party must abort");
		assert!(
			matches!(err, ResharingProtocolError::ProtocolAborted(_)),
			"active member's failure report must abort the session, got: {}",
			err
		);
	}

	/// Security review follow-up: the excluded member reports `success = true`
	/// and its only anomaly is a partial PK keyed by a non-canonical mask.
	/// With no failure bit in play, the only way that broadcast could
	/// influence Combining is through a consumer scanning the full
	/// `round5_broadcasts` map — the property under test is that no such
	/// consumer exists. Combining must sail past both the failure scan and
	/// the share-data checks without tripping the non-canonical hard reject.
	#[test]
	fn test_combining_ignores_poisoned_mask_from_excluded_old_member() {
		let mut protocol = combining_protocol_with_round5_failure_from(None);

		let err = protocol.poke().expect_err("bare combining state cannot fully verify");
		assert!(
			!matches!(err, ResharingProtocolError::ProtocolAborted(_)),
			"nothing reported failure, so nothing may abort, got: {}",
			err
		);
		assert!(
			!err.to_string().contains("non-canonical"),
			"excluded old member's poisoned partial PK mask must be ignored, got: {}",
			err
		);
		// The only remaining error on this bare setup is the ordinary lack of
		// genuine partial PK data.
		assert!(
			err.to_string().contains("missing partial PK contribution"),
			"unexpected error: {}",
			err
		);
	}

	/// Build a protocol poised at Combining with active set {0, 1} out of old
	/// committee {0, 1, 2} and new committee {0, 1, 3}. All Round 5 senders
	/// report success except `failure_from` (if any). The excluded old
	/// member (2) additionally smuggles a partial PK keyed by a
	/// non-canonical mask, which must be ignored, not hard-rejected.
	fn combining_protocol_with_round5_failure_from(
		failure_from: Option<ParticipantId>,
	) -> ResharingProtocol<TestSigner> {
		let config = crate::ThresholdConfig::new(2, 3).expect("valid config");
		let (public_key, shares) =
			crate::keygen::generate_with_dealer(&[21u8; 32], config).expect("keygen");
		let resharing_config = ResharingConfig::new(
			Some(shares[0].clone()),
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 3],
			0,
			public_key,
		)
		.expect("valid resharing config");
		let mut protocol = ResharingProtocol::new(
			resharing_config,
			test_signer_config(0, &[0, 1, 2, 3]),
			[1u8; 32],
			&[2u8; 32],
			0,
		);

		// Old member 2 is excluded from the active set.
		protocol.active_set = Some(vec![0, 1]);

		// Round 5 broadcasts: everyone reports success except `failure_from`
		// (if any). The excluded old member (2) also carries a poisoned
		// non-canonical partial PK mask.
		for party in [0u32, 1, 2, 3] {
			let success = failure_from != Some(party);
			let mut partial_pks: BTreeMap<SubsetMask, [[i32; N as usize]; K]> = BTreeMap::new();
			if party == 2 {
				let full_mask: SubsetMask = 0b111;
				assert!(
					!protocol.new_subset_order.contains(&full_mask),
					"full-committee mask must not be a canonical subset"
				);
				partial_pks.insert(full_mask, [[7i32; N as usize]; K]);
			}
			protocol.round5_broadcasts.insert(
				party,
				ResharingRound5Broadcast {
					ssid: protocol.ssid,
					party_id: party,
					share_commitments: BTreeMap::new(),
					partial_pks,
					success,
					error_message: (!success).then(|| "forged failure".to_string()),
				},
			);
		}

		protocol.state = ResharingState::Combining;
		protocol
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

	#[test]
	fn test_new_share_data_coefficients_within_bound() {
		let mut share = NewShareData::new();
		// All zeros - should pass any positive bound
		assert!(share.coefficients_within_bound(1));
		assert!(share.coefficients_within_bound(SUBSHARE_COEFF_BOUND));

		// Set one coefficient to exactly the bound
		share.s1[0][0] = SUBSHARE_COEFF_BOUND;
		assert!(share.coefficients_within_bound(SUBSHARE_COEFF_BOUND));
		assert!(!share.coefficients_within_bound(SUBSHARE_COEFF_BOUND - 1));

		// Set one coefficient to exceed the bound
		share.s1[0][0] = SUBSHARE_COEFF_BOUND + 1;
		assert!(!share.coefficients_within_bound(SUBSHARE_COEFF_BOUND));

		// Negative coefficients
		share.s1[0][0] = -SUBSHARE_COEFF_BOUND;
		assert!(share.coefficients_within_bound(SUBSHARE_COEFF_BOUND));
		share.s1[0][0] = -SUBSHARE_COEFF_BOUND - 1;
		assert!(!share.coefficients_within_bound(SUBSHARE_COEFF_BOUND));
	}

	#[test]
	fn test_new_share_data_max_abs_coefficient() {
		let mut share = NewShareData::new();
		assert_eq!(share.max_abs_coefficient(), 0);

		share.s1[0][0] = 100;
		assert_eq!(share.max_abs_coefficient(), 100);

		share.s2[3][128] = -200;
		assert_eq!(share.max_abs_coefficient(), 200);

		share.s1[L - 1][N as usize - 1] = 500;
		assert_eq!(share.max_abs_coefficient(), 500);
	}

	/// A malicious dealer can set a coefficient to `i32::MIN`, whose magnitude
	/// (2_147_483_648) is not representable as a positive `i32`. `i32::abs()`
	/// would panic on it in overflow-checking builds and wrap back to
	/// `i32::MIN` (still negative) in release builds, letting the oversized
	/// coefficient pass the `> bound` check. The fixed helpers use
	/// `unsigned_abs()` and must reject it in every build profile.
	#[test]
	fn test_coefficients_within_bound_rejects_i32_min() {
		let mut share = NewShareData::new();
		share.s1[0][0] = i32::MIN;
		assert!(
			!share.coefficients_within_bound(SUBSHARE_COEFF_BOUND),
			"i32::MIN coefficient must be rejected, not silently accepted"
		);
		// The diagnostic must report the true magnitude without overflowing.
		assert_eq!(share.max_abs_coefficient(), 2_147_483_648u32);

		// The same edge case in s2.
		let mut share = NewShareData::new();
		share.s2[K - 1][N as usize - 1] = i32::MIN;
		assert!(!share.coefficients_within_bound(SUBSHARE_COEFF_BOUND));
		assert_eq!(share.max_abs_coefficient(), 2_147_483_648u32);
	}

	#[test]
	fn test_honest_subshares_within_bound() {
		// Verify that honestly-derived sub-shares are well within the coefficient bound
		let s = SecretShareData { s1: [[100i32; N as usize]; L], s2: [[50i32; N as usize]; K] };
		let new_subsets = generate_subset_masks(3, 2);
		let session_seed = [42u8; 32];
		let subshares = derive_subshares_with_session_seed(
			0b011,
			&s,
			&new_subsets,
			&session_seed,
			new_subsets.len(),
		);

		for (i, share) in subshares.iter().enumerate() {
			let max_coeff = share.max_abs_coefficient();
			assert!(
				share.coefficients_within_bound(SUBSHARE_COEFF_BOUND),
				"Honestly-derived subshare {} has max coeff {} exceeding bound {}",
				i,
				max_coeff,
				SUBSHARE_COEFF_BOUND
			);
			// For input coefficients of ~100 and m=3, expected max is ~35 + noise ≈ 40
			// Should be well under 100, let alone 500
			assert!(
				max_coeff < 100,
				"Subshare {} has unexpectedly large max coeff {}",
				i,
				max_coeff
			);
		}
	}
}
