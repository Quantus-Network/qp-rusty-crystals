//! Key generation for threshold ML-DSA-87.
//!
//! This module provides methods for generating threshold key shares.
//! Two approaches are available:
//!
//! 1. **Trusted Dealer** - A single party generates all shares
//! 2. **Distributed Key Generation (DKG)** - Parties collaboratively generate shares
//!
//! # Trusted Dealer
//!
//! The `generate_with_dealer` function generates all key shares from a single
//! seed. This requires trusting the dealer (the entity running this function)
//! not to retain the shares or the seed.
//!
//! ```ignore
//! use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig};
//!
//! let config = ThresholdConfig::new(2, 3)?;
//! let seed = [0u8; 32]; // Use a cryptographically secure random seed!
//!
//! let (public_key, shares) = generate_with_dealer(&seed, config)?;
//!
//! // Distribute shares[0] to party 0, shares[1] to party 1, etc.
//! // Each party should securely store their share and delete it from the dealer.
//! ```
//!
//! # Distributed Key Generation (DKG)
//!
//! The DKG protocol allows parties to collaboratively generate key shares
//! without any single party knowing the complete secret. This is the
//! recommended approach for production deployments.
//!
//! ```ignore
//! use qp_rusty_crystals_threshold::keygen::dkg::{DilithiumDkg, DkgConfig, Action};
//! use rand::rngs::OsRng;
//!
//! // Each party runs this independently
//! let config = DkgConfig::new(threshold_config, my_party_id, all_participants)?;
//! let mut dkg = DilithiumDkg::new(config, OsRng);
//!
//! loop {
//!     match dkg.poke()? {
//!         Action::Wait => { /* wait for messages */ }
//!         Action::SendMany(data) => { /* broadcast to all */ }
//!         Action::SendPrivate(to, data) => { /* send to specific party */ }
//!         Action::Return(output) => {
//!             // DKG complete!
//!             let public_key = output.public_key;
//!             let my_share = output.private_share;
//!             break;
//!         }
//!     }
//!     // When messages arrive: dkg.message(from, data);
//! }
//! ```
//!
//! The DKG protocol follows the poke/message pattern used by NEAR MPC,
//! making it compatible with NEAR's `run_protocol` infrastructure.

mod dealer;
pub mod dkg;

pub use dealer::generate_with_dealer;
