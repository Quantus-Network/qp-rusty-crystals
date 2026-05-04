//! Resharing (Committee Handoff) for Threshold ML-DSA-87.
//!
//! This module implements resharing functionality that allows changing the
//! participant set while preserving the same public key. This is essential
//! for production deployments where nodes may join, leave, or be replaced.
//!
//! # ⚠️ Transport Security Requirement
//!
//! **CRITICAL**: Round 2 messages ([`Action::SendPrivate`]) contain secret share material
//! in plaintext and **MUST** be transmitted over an authenticated-encrypted channel.
//! This protocol does not provide its own encryption layer.
//!
//! - `Action::SendMany` (Rounds 1, 3): Requires authenticated broadcast (integrity)
//! - `Action::SendPrivate` (Round 2): **Requires authenticated encryption** (confidentiality +
//!   integrity)
//!
//! If `SendPrivate` messages are sent unencrypted, an eavesdropper can recover sub-shares
//! and potentially reconstruct secret key material.
//!
//! # Overview
//!
//! Resharing uses **distributed per-subset re-sharing**: for each old RSS subset
//! `I` (a `k_old`-subset of the old committee whose members all hold the
//! η-bounded share `s_I^old`), the lowest-ID member of `I` (the "designated
//! dealer" `D_I`) re-shares `s_I^old` to the new committee:
//!
//! 1. `D_I` deterministically derives sub-shares `r_{I→J}` for every new RSS subset `J`, such that
//!    `Σ_J r_{I→J} = s_I^old` (so reassembling all sub-shares for `I` reconstructs only the *old*
//!    subset share, not the full secret).
//! 2. `D_I` broadcasts a hash commitment to each `r_{I→J}` (Round 1) and privately delivers
//!    `r_{I→J}` to every member of new subset `J` (Round 2, **over secure channel**).
//! 3. New committee members verify each received `r_{I→J}` against `D_I`'s commitment, sum `s_J^new
//!    = Σ_I r_{I→J}` for each new subset `J` containing them, and broadcast a commitment to
//!    `s_J^new` (Round 3) so the membership of `J` can cross-verify consistency. Other members of
//!    the same old subset `I` independently recompute `r_{I→J}` and accuse `D_I` if any commitment
//!    is wrong.
//!
//! Because `Σ_J s_J^new = Σ_J Σ_I r_{I→J} = Σ_I s_I^old = s_total`, the
//! secret (and hence the public key `t = A·s1 + s2`) is preserved.
//!
//! # Security Properties
//!
//! - **Secrecy of `s`**: No party — not even the designated dealers — ever reconstructs the full
//!   secret `s`. Each `D_I` only handles `s_I^old`, which they already had.
//! - **Confidentiality of share contributions**: Round 1 broadcasts only hash commitments (hiding
//!   under SHAKE256 when committed values come from a high-entropy distribution); Round 2
//!   sub-shares travel privately (**caller must provide secure channel**).
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
//! // Create and run the protocol
//! let mut protocol = ResharingProtocol::new(config);
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
	DealerAccusation, NewShareData, ResharingConfig, ResharingMessage, ResharingOutput,
	ResharingRole, ResharingRound1Broadcast, ResharingRound2Message, ResharingRound3Broadcast,
	SubsetMask, SubsetPair,
};

pub use protocol::{Action, ResharingProtocol, ResharingProtocolError, ResharingState};
