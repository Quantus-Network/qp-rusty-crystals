//! Key generation for threshold ML-DSA-87.
//!
//! This module provides methods for generating threshold key shares.
//! Currently, only trusted dealer key generation is implemented.
//! Distributed key generation (DKG) may be added in the future.
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
//! # Future: Distributed Key Generation
//!
//! A future version may include DKG protocols that allow parties to generate
//! their shares without a trusted dealer. The API would look like:
//!
//! ```ignore
//! // Each party runs this independently
//! let dkg = DistributedKeyGen::new(party_id, config);
//! let r1 = dkg.round1(&mut rng)?;
//! // ... exchange messages ...
//! let r2 = dkg.round2(&other_r1)?;
//! // ... exchange messages ...
//! let (public_key, my_share) = dkg.finalize(&other_r2)?;
//! ```

mod dealer;

pub use dealer::generate_with_dealer;
