//! Resharing (Committee Handoff) for Threshold ML-DSA-87.
//!
//! This module implements resharing functionality that allows changing the
//! participant set while preserving the same public key. This is essential
//! for production deployments where nodes may join, leave, or be replaced.
//!
//! # ⚠️ Transport Security Requirement
//!
//! **CRITICAL**: Round 4 messages ([`Action::SendPrivate`]) contain secret share material
//! in plaintext and **MUST** be transmitted over an authenticated-encrypted channel.
//! This protocol does not provide its own encryption layer.
//!
//! - `Action::SendMany` (Rounds 1, 2, 3, 5, 6): Requires authenticated broadcast (integrity)
//! - `Action::SendPrivate` (Round 4): **Requires authenticated encryption** (confidentiality +
//!   integrity)
//!
//! If `SendPrivate` messages are sent unencrypted, an eavesdropper can recover sub-shares
//! and potentially reconstruct secret key material.
//!
//! # Overview
//!
//! Resharing uses **distributed per-subset re-sharing** with replay protection and public session
//! randomization:
//!
//! ## Protocol Rounds (session-randomized protocol with active-set liveness)
//!
//! - **Round 1**: Entropy commitment / Ready - old committee broadcasts `H(entropy)`
//! - **Act proposal**: The session leader (lowest-ID new committee member) proposes the active set
//!   `Act` of ready old members. All old members once everyone commits (fast path), or the
//!   committed subset after [`ResharingProtocol::close_ready_window`] — requires `|Act| >= t_old`,
//!   so resharing succeeds even when up to `n_old - t_old` old members are offline
//! - **Round 2**: Entropy reveal - active members reveal entropy and a public session seed is
//!   computed
//! - **Round 3**: Sub-share commitments - designated dealers broadcast `H(r_{I→J})`
//! - **Round 4**: Private delivery - dealers send `r_{I→J}` to new committee (**secure channel**)
//! - **Round 5**: Verification - share commitments, partial PKs
//! - **Round 6**: Signed transcript acceptance - new committee members sign the transcript hash
//!   (bound together with the `active_set` and `new_committee`) using their long-term keys
//!   ([`TranscriptSigner`]); the collected signatures form a publicly verifiable
//!   [`ResharingCertificate`]
//!
//! For each old RSS subset `I` (a `k_old`-subset of the old committee whose members all hold the
//! η-bounded share `s_I^old`), the lowest-ID *active* member of `I` (the "designated dealer"
//! `D_I = min(I ∩ Act)`) re-shares `s_I^old` to the new committee. Because `|Act| >= t_old` and
//! `|I| = n_old - t_old + 1`, every old subset has a live dealer; all members of `I` hold the
//! same `s_I^old` and derivation is deterministic, so dealer identity does not affect the
//! derived values:
//!
//! 1. `D_I` deterministically derives sub-shares `r_{I→J}` for every new RSS subset `J`, such that
//!    `Σ_J r_{I→J} = s_I^old`. The derivation incorporates the public session seed from Rounds 1-2
//!    so fresh entropy produces a different deterministic split.
//! 2. `D_I` broadcasts a hash commitment to each `r_{I→J}` (Round 3) and privately delivers
//!    `r_{I→J}` to every member of new subset `J` (Round 4, **over secure channel**).
//! 3. New committee members verify each received `r_{I→J}` against `D_I`'s commitment, sum `s_J^new
//!    = Σ_I r_{I→J}` for each new subset `J` containing them, and broadcast a commitment to
//!    `s_J^new` (Round 5) so the membership of `J` can cross-verify consistency.
//!
//! Because `Σ_J s_J^new = Σ_J Σ_I r_{I→J} = Σ_I s_I^old = s_total`, the
//! secret (and hence the public key `t = A·s1 + s2`) is preserved.
//!
//! # Security Properties
//!
//! - **Secrecy of `s`**: No party — not even the designated dealers — ever reconstructs the full
//!   secret `s`. Each `D_I` only handles `s_I^old`, which they already had.
//! - **Replay protection**: Each message includes an SSID derived from the protocol version, suite
//!   ID, handoff epoch, old/new committees, the public key, and a session nonce. Messages with a
//!   different SSID are ignored.
//! - **Session randomization**: Rounds 1-2 commit to and reveal fresh entropy before deriving a
//!   public session seed, making sub-share splits unpredictable before reveal and different across
//!   fresh sessions. This is not post-compromise forward secrecy: a recorded transcript plus later
//!   compromise of old subset shares lets an attacker recompute the deterministic sub-shares.
//! - **Confidentiality of share contributions**: Rounds 1-3 only broadcast hash commitments; Round
//!   4 sub-shares travel privately (**caller must provide secure channel**).
//! - **Cheating-dealer detection**: New subset members cross-verify computed `s_J^new` values;
//!   public-key invariant verification catches inconsistent dealing.
//! - **Public key preservation**: `t = A·s1 + s2` is unchanged.
//! - **Transcript agreement + attestation**: Round 6 acceptance signatures are verified by every
//!   party against its own transcript hash, so completion implies all parties observed identical
//!   broadcasts (equivocation causes an abort). The signed hash also binds the certificate's
//!   `active_set` and `new_committee` fields directly, so a third party holding only the
//!   certificate (and the new committee's verifying keys) authenticates the transcript hash, the
//!   named active old members, and the attested new committee; neither field can be rewritten
//!   without invalidating the signatures, and the certificate itself names the complete set of
//!   required acceptors.
//!
//! # Proactive Security Model
//!
//! Resharing provides **mobile/snapshot adversary protection**, not permanent-compromise recovery:
//!
//! - **What resharing provides**: If an attacker exfiltrates `t-1` share files but later loses
//!   access to those devices, resharing invalidates the stolen shares. The attacker must compromise
//!   `t` current shares to sign — they "start over."
//!
//! - **What resharing does NOT provide**: If the attacker permanently controls `t-1` devices that
//!   remain in the new committee, those devices receive fresh shares. The attacker remains one
//!   compromise away from threshold, not `t` away.
//!
//! - **To recover from persistent compromise**: Remove compromised parties from `new_participants`.
//!   Excluded parties receive no new shares and cannot sign in the new epoch.
//!
//! This matches the standard proactive secret sharing model: security holds if fewer than `t`
//! parties are compromised in any single epoch, with proper old-state erasure between epochs.
//!
//! The protocol erases its own session state at finalize: on successful completion it zeroizes
//! the seed, entropy, session seed, derived and received sub-shares, and the old share held in
//! its config (check via `ResharingProtocol::old_share_erased`). Callers remain responsible for
//! erasing their own copies of the old share (key files, keystore entries).
//!
//! # Why Custom Protocol?
//!
//! Existing resharing protocols (CHURP, MPSS) are designed for Shamir polynomial
//! secret sharing. Our implementation uses Replicated Secret Sharing (RSS) with
//! subset-indexed additive shares, requiring a custom approach.
//!
//! # Usage
//!
//! ```ignore
//! use qp_rusty_crystals_threshold::resharing::{
//!     ResharingConfig, ResharingProtocol, ResharingSignerConfig, Action,
//! };
//! use rand::RngCore;
//!
//! // Generate fresh entropy for this party's session-randomization contribution.
//! let mut seed = [0u8; 32];
//! rand::rngs::OsRng.fill_bytes(&mut seed);
//!
//! // Generate or receive a unique session nonce shared by this resharing session.
//! let mut session_nonce = [0u8; 32];
//! rand::rngs::OsRng.fill_bytes(&mut session_nonce);
//!
//! // Configure resharing
//! let config = ResharingConfig::new(
//!     old_threshold,
//!     old_participants,
//!     new_threshold,
//!     new_participants,
//!     my_party_id,
//!     public_key,
//! )?;
//!
//! // Long-term-key signer (e.g. Ed25519) + new committee's verifying keys for Round 6.
//! let signer_config = ResharingSignerConfig::new(my_signer, verifying_keys, &new_participants)?;
//!
//! // Old committee members pass Some(existing_share); new-only parties pass None.
//! // `epoch` is a monotonic handoff counter for this key (0 = first resharing).
//! let mut protocol = ResharingProtocol::new(config, signer_config, seed, &session_nonce, epoch)?;
//!
//! loop {
//!     match protocol.poke()? {
//!         Action::Wait => { /* wait for messages */ }
//!         Action::SendMany(data) => { /* broadcast to all */ }
//!         // ⚠️ MUST use authenticated-encrypted channel for SendPrivate!
//!         Action::SendPrivate(to, data) => { /* send to specific party over secure channel */ }
//!         Action::Return(output) => {
//!             // Resharing complete!
//!             let new_share = output.private_share;
//!             let certificate = output.certificate; // publicly verifiable
//!             break;
//!         }
//!     }
//!     // When messages arrive: protocol.message(from, data);
//! }
//! ```

mod protocol;
mod types;

// Re-export public types
pub use types::{
	compute_accept_hash, compute_resharing_ssid, NewShareData, ResharingAccept,
	ResharingActProposal, ResharingCertificate, ResharingConfig, ResharingMessage, ResharingOutput,
	ResharingRole, ResharingRound1EntropyCommitment, ResharingRound2EntropyReveal,
	ResharingRound3Broadcast, ResharingRound4Message, ResharingRound5Broadcast,
	ResharingSignerConfig, SubsetMask, SubsetPair, ENTROPY_SIZE, MAX_ACCEPT_SIGNATURE_LEN,
	MAX_ERROR_MESSAGE_LEN, RESHARING_PROTOCOL_VERSION, RESHARING_SSID_SIZE,
	RESHARING_SUITE_ML_DSA_87, SUBSHARE_COEFF_BOUND,
};

// Re-export the long-term-key signing trait used for Round 6 acceptance, so
// integrators don't need to reach into the DKG module.
pub use crate::keygen::dkg::TranscriptSigner;

pub use protocol::{
	resharing_norm_enlargement, Action, ResharingProtocol, ResharingProtocolError, ResharingState,
};
