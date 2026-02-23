//! Distributed Key Generation (DKG) for threshold ML-DSA-87.
//!
//! This module implements a 4-round DKG protocol that allows parties to
//! collaboratively generate threshold key shares without a trusted dealer.
//!
//! # Protocol Overview
//!
//! The DKG protocol consists of 4 rounds:
//!
//! 1. **Round 1 - Session ID**: Each party contributes random bytes to form a unique session ID,
//!    preventing replay attacks.
//!
//! 2. **Round 2 - Commitment**: Each party generates random contributions for each subset they
//!    belong to and broadcasts a hash commitment.
//!
//! 3. **Round 3 - Reveal**: Each party reveals their contributions. Others verify that the revealed
//!    data matches the committed hash.
//!
//! 4. **Round 4 - Confirmation**: Each party computes their final shares and the public key, then
//!    broadcasts a confirmation with the public key hash to ensure consensus.
//!
//! # Usage
//!
//! ```ignore
//! use qp_rusty_crystals_threshold::{
//!     ThresholdConfig,
//!     keygen::dkg::{DilithiumDkg, DkgConfig, Action},
//! };
//! use rand::rngs::OsRng;
//!
//! // Create configuration
//! let threshold_config = ThresholdConfig::new(2, 3)?;
//! let dkg_config = DkgConfig::new(threshold_config, my_party_id, vec![0, 1, 2])?;
//!
//! // Create DKG instance
//! let mut dkg = DilithiumDkg::new(dkg_config, OsRng);
//!
//! // Run the protocol
//! loop {
//!     match dkg.poke()? {
//!         Action::Wait => {
//!             // Wait for messages from other parties
//!         }
//!         Action::SendMany(data) => {
//!             // Broadcast to all other parties
//!             for party in other_parties {
//!                 send(party, data.clone());
//!             }
//!         }
//!         Action::SendPrivate(party, data) => {
//!             // Send privately to specific party
//!             send(party, data);
//!         }
//!         Action::Return(output) => {
//!             // DKG complete!
//!             let public_key = output.public_key;
//!             let my_share = output.private_share;
//!             break;
//!         }
//!     }
//!
//!     // When a message arrives from another party:
//!     // dkg.message(from_party_id, received_data);
//! }
//! ```
//!
//! # Compatibility
//!
//! The DKG produces `PrivateKeyShare` and `PublicKey` types that are fully
//! compatible with the existing threshold signing protocol. Shares generated
//! by DKG can be used directly with `ThresholdSigner`.
//!
//! # Security
//!
//! - Each party contributes randomness, so no single party controls the key
//! - Commitment scheme prevents parties from adapting contributions based on others
//! - Consensus verification ensures all parties agree on the public key
//! - Session ID prevents replay attacks across different DKG runs
//!
//! # NEAR MPC Compatibility
//!
//! The `DilithiumDkg` struct follows the poke/message pattern used by NEAR's
//! `threshold-signatures` crate, making it compatible with NEAR MPC's
//! `run_protocol` infrastructure.

mod protocol;
mod state;
mod types;

// Re-export public types
pub use protocol::{Action, DilithiumDkg, DkgProtocolError};
pub use state::{DkgState, DkgStateData};
pub use types::{
	DkgConfig, DkgMessage, DkgOutput, DkgRound1Broadcast, DkgRound2Broadcast, DkgRound3Broadcast,
	DkgRound4Broadcast, ParticipantId, PartyContributions, SubsetContribution, SubsetMask,
};

/// Convenience function to run a complete local DKG for testing.
///
/// This function simulates the DKG protocol with all parties running locally.
/// It's useful for testing but should not be used in production where parties
/// are on separate machines.
///
/// # Arguments
/// * `threshold` - Minimum parties required to sign (t)
/// * `total_parties` - Total number of parties (n)
/// * `seed` - Seed for deterministic randomness (for testing)
///
/// # Returns
/// A vector of `DkgOutput` structs, one for each party.
///
/// # Example
///
/// ```ignore
/// use qp_rusty_crystals_threshold::keygen::dkg::run_local_dkg;
///
/// let outputs = run_local_dkg(2, 3, [0u8; 32]).unwrap();
/// assert_eq!(outputs.len(), 3);
/// ```
pub fn run_local_dkg(
	threshold: u32,
	total_parties: u32,
	seed: [u8; 32],
) -> Result<Vec<DkgOutput>, DkgProtocolError> {
	use crate::config::ThresholdConfig;

	let threshold_config = ThresholdConfig::new(threshold, total_parties)
		.map_err(|e| DkgProtocolError::InternalError(e.to_string()))?;

	let participants: Vec<ParticipantId> = (0..total_parties).collect();

	// Create DKG instances for each party
	let mut dkgs: Vec<DilithiumDkg> = participants
		.iter()
		.enumerate()
		.map(|(i, &party_id)| {
			let config = DkgConfig::new(threshold_config, party_id, participants.clone()).unwrap();
			// Each party gets a different seed
			let mut party_seed = seed;
			party_seed[0] = party_seed[0].wrapping_add(i as u8);
			DilithiumDkg::new(config, party_seed)
		})
		.collect();

	let mut outputs: Vec<Option<DkgOutput>> = vec![None; total_parties as usize];
	let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> =
		vec![Vec::new(); total_parties as usize];

	// Run until all parties complete
	let mut iterations = 0;
	const MAX_ITERATIONS: usize = 1000;

	while outputs.iter().any(|o| o.is_none()) {
		iterations += 1;
		if iterations > MAX_ITERATIONS {
			return Err(DkgProtocolError::InternalError("DKG did not complete in time".into()));
		}

		// Deliver pending messages
		for party_id in 0..total_parties as usize {
			let messages = std::mem::take(&mut pending_messages[party_id]);
			for (from, data) in messages {
				dkgs[party_id].message(from, data);
			}
		}

		// Poke each party
		for party_id in 0..total_parties as usize {
			if outputs[party_id].is_some() {
				continue;
			}

			match dkgs[party_id].poke()? {
				Action::Wait => {},
				Action::SendMany(data) => {
					let from = party_id as ParticipantId;
					for (other, pending) in pending_messages.iter_mut().enumerate() {
						if other != party_id {
							pending.push((from, data.clone()));
						}
					}
				},
				Action::SendPrivate(to, data) => {
					let from = party_id as ParticipantId;
					pending_messages[to as usize].push((from, data));
				},
				Action::Return(output) => {
					outputs[party_id] = Some(output);
				},
			}
		}
	}

	Ok(outputs.into_iter().map(|o| o.unwrap()).collect())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_local_dkg_2_of_3() {
		let outputs = run_local_dkg(2, 3, [42u8; 32]).unwrap();

		assert_eq!(outputs.len(), 3);

		// All parties should have the same public key
		let pk0 = outputs[0].public_key.as_bytes();
		let pk1 = outputs[1].public_key.as_bytes();
		let pk2 = outputs[2].public_key.as_bytes();

		assert_eq!(pk0, pk1);
		assert_eq!(pk1, pk2);

		// Each party should have correct metadata
		for (i, output) in outputs.iter().enumerate() {
			assert_eq!(output.private_share.party_id(), i as u32);
			assert_eq!(output.private_share.threshold(), 2);
			assert_eq!(output.private_share.total_parties(), 3);
		}
	}

	#[test]
	fn test_local_dkg_3_of_5() {
		let outputs = run_local_dkg(3, 5, [123u8; 32]).unwrap();

		assert_eq!(outputs.len(), 5);

		// All parties should have the same public key
		let pk0 = outputs[0].public_key.as_bytes();
		for output in &outputs[1..] {
			assert_eq!(pk0, output.public_key.as_bytes());
		}
	}

	#[test]
	fn test_local_dkg_deterministic() {
		// Same seed should produce same keys
		let outputs1 = run_local_dkg(2, 3, [1u8; 32]).unwrap();
		let outputs2 = run_local_dkg(2, 3, [1u8; 32]).unwrap();

		assert_eq!(outputs1[0].public_key.as_bytes(), outputs2[0].public_key.as_bytes());
	}

	#[test]
	fn test_local_dkg_different_seeds() {
		// Different seeds should produce different keys
		let outputs1 = run_local_dkg(2, 3, [1u8; 32]).unwrap();
		let outputs2 = run_local_dkg(2, 3, [2u8; 32]).unwrap();

		assert_ne!(outputs1[0].public_key.as_bytes(), outputs2[0].public_key.as_bytes());
	}

	/// Test that DKG-generated keys work with ThresholdSigner for signing
	#[test]
	fn test_dkg_signing_integration() {
		use crate::{verify_signature, ThresholdConfig, ThresholdSigner};

		// Run DKG to generate keys
		let dkg_outputs = run_local_dkg(2, 3, [99u8; 32]).unwrap();

		// All parties should have the same public key
		let public_key = dkg_outputs[0].public_key.clone();
		for output in &dkg_outputs[1..] {
			assert_eq!(public_key.as_bytes(), output.public_key.as_bytes());
		}

		let config = ThresholdConfig::new(2, 3).unwrap();
		let message = b"Test message for DKG signing";
		let context = b"test-context";

		// Retry signing up to 100 times (rejection sampling may fail)
		let mut success = false;
		for _ in 0..100 {
			// Create fresh signers for each attempt
			let mut signers: Vec<ThresholdSigner> = dkg_outputs
				.iter()
				.take(2)
				.map(|output| {
					ThresholdSigner::new(output.private_share.clone(), public_key.clone(), config)
						.unwrap()
				})
				.collect();

			let mut rng = rand::thread_rng();

			// Round 1: Generate commitments
			let r1_broadcasts: Vec<_> =
				signers.iter_mut().map(|s| s.round1_commit(&mut rng).unwrap()).collect();

			// Round 2: Reveal commitments
			let r2_broadcasts: Vec<_> = signers
				.iter_mut()
				.enumerate()
				.map(|(i, s)| {
					let others: Vec<_> =
						r1_broadcasts.iter().filter(|r| r.party_id != i as u32).cloned().collect();
					s.round2_reveal(message, context, &others).unwrap()
				})
				.collect();

			// Round 3: Compute responses
			let r3_broadcasts: Vec<_> = signers
				.iter_mut()
				.enumerate()
				.map(|(i, s)| {
					let others: Vec<_> =
						r2_broadcasts.iter().filter(|r| r.party_id != i as u32).cloned().collect();
					s.round3_respond(&others).unwrap()
				})
				.collect();

			// Try to combine signature (may fail due to rejection sampling)
			if let Ok(signature) =
				signers[0].combine_with_message(message, context, &r2_broadcasts, &r3_broadcasts)
			{
				// Verify signature
				assert!(
					verify_signature(&public_key, message, context, &signature),
					"Signature from DKG-generated keys should verify"
				);
				success = true;
				break;
			}
		}

		assert!(success, "Signing with DKG keys should succeed within 100 attempts");
	}
}
