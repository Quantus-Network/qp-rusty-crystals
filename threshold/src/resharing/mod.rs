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
//! - `Action::SendMany` (Rounds 1, 2, 3, 5): Requires authenticated broadcast (integrity)
//! - `Action::SendPrivate` (Round 4): **Requires authenticated encryption** (confidentiality +
//!   integrity)
//!
//! If `SendPrivate` messages are sent unencrypted, an eavesdropper can recover sub-shares
//! and potentially reconstruct secret key material.
//!
//! # Overview
//!
//! Resharing uses **distributed per-subset re-sharing** with **forward secrecy**:
//!
//! ## Protocol Rounds (5-round forward-secrecy protocol)
//!
//! - **Round 1**: Entropy commitment - old committee broadcasts `H(entropy)` for forward secrecy
//! - **Round 2**: Entropy reveal - old committee reveals entropy, session seed computed
//! - **Round 3**: Sub-share commitments - designated dealers broadcast `H(r_{I→J})`
//! - **Round 4**: Private delivery - dealers send `r_{I→J}` to new committee (**secure channel**)
//! - **Round 5**: Verification - share commitments, partial PKs, accusations
//!
//! For each old RSS subset `I` (a `k_old`-subset of the old committee whose members all hold the
//! η-bounded share `s_I^old`), the lowest-ID member of `I` (the "designated dealer" `D_I`)
//! re-shares `s_I^old` to the new committee:
//!
//! 1. `D_I` deterministically derives sub-shares `r_{I→J}` for every new RSS subset `J`, such that
//!    `Σ_J r_{I→J} = s_I^old`. The derivation incorporates the session seed (from Rounds 1-2) for
//!    forward secrecy.
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
//! - **Forward secrecy**: Even if old shares are later compromised, an attacker cannot reconstruct
//!   the randomness used to derive new shares because the session seed includes fresh entropy
//!   contributions from all old committee members.
//! - **Confidentiality of share contributions**: Rounds 1-3 only broadcast hash commitments; Round
//!   4 sub-shares travel privately (**caller must provide secure channel**).
//! - **Cheating-dealer detection**: Old subset members cross-verify dealers' commitments; new
//!   subset members cross-verify computed `s_J^new` values.
//! - **Public key preservation**: `t = A·s1 + s2` is unchanged.
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
//!     ResharingConfig, ResharingProtocol, Action,
//! };
//! use rand::RngCore;
//!
//! // Generate fresh entropy for this party
//! let mut seed = [0u8; 32];
//! rand::rngs::OsRng.fill_bytes(&mut seed);
//!
//! // Configure resharing
//! let config = ResharingConfig::new(
//!     old_threshold,
//!     old_participants,
//!     new_threshold,
//!     new_participants,
//!     my_party_id,
//!     my_private_share,  // None if joining as new party
//! )?;
//!
//! // Create and run the protocol with fresh entropy
//! let mut protocol = ResharingProtocol::new(config, seed);
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
	compute_resharing_ssid, NewShareData, ResharingConfig, ResharingMessage, ResharingOutput,
	ResharingRole, ResharingRound1EntropyCommitment, ResharingRound2EntropyReveal,
	ResharingRound3Broadcast, ResharingRound4Message, ResharingRound5Broadcast, SubsetMask,
	SubsetPair, ENTROPY_SIZE, RESHARING_SSID_SIZE,
};

pub use protocol::{Action, ResharingProtocol, ResharingProtocolError, ResharingState};
