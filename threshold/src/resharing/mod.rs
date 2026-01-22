//! Resharing (Committee Handoff) for Threshold ML-DSA-87.
//!
//! This module implements resharing functionality that allows changing the
//! participant set while preserving the same public key. This is essential
//! for production deployments where nodes may join, leave, or be replaced.
//!
//! # Overview
//!
//! Resharing consists of four phases:
//! 1. **Blinded Reconstruction**: Threshold of old committee members reconstruct the secret in
//!    blinded form
//! 2. **Re-dealing**: Generate fresh RSS shares for the new committee structure
//! 3. **Distribution**: Send new shares to new committee members
//! 4. **Verification**: New committee verifies share consistency
//!
//! # Why Custom Protocol?
//!
//! Existing resharing protocols (CHURP, MPSS) are designed for Shamir polynomial
//! secret sharing. Our implementation uses Replicated Secret Sharing (RSS) with
//! subset-indexed additive shares, requiring a custom approach.
//!
//! # Security Properties
//!
//! - **Secrecy**: The secret is never exposed in clear during resharing
//! - **Consistency**: All honest parties end up with shares of the same secret
//! - **Freshness**: Old shares become useless after resharing completes
//! - **Public Key Preservation**: The public key `t = A·s1 + s2` remains unchanged
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
//! let mut protocol = ResharingProtocol::new(config, seed)?;
//!
//! loop {
//!     match protocol.poke()? {
//!         Action::Wait => { /* wait for messages */ }
//!         Action::SendMany(data) => { /* broadcast to all */ }
//!         Action::SendPrivate(to, data) => { /* send to specific party */ }
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
	ResharingConfig, ResharingMessage, ResharingOutput, ResharingRole, ResharingRound1Broadcast,
	ResharingRound2Message, ResharingRound3Broadcast,
};

pub use protocol::{Action, ResharingProtocol, ResharingProtocolError, ResharingState};
