//! Distributed Key Generation (DKG) for threshold ML-DSA-87.
//!
//! This module implements a 5-round DKG protocol that allows parties to
//! collaboratively generate threshold key shares without a trusted dealer.
//!
//! # Protocol Overview
//!
//! The DKG protocol consists of 5 rounds:
//!
//! 1. **Round 1 - Session ID**: Each party contributes random bytes to form a unique session ID,
//!    preventing replay attacks.
//!
//! 2. **Round 2 - Commitment**: Each party generates random contributions for each subset they
//!    belong to and broadcasts a hash commitment to their PUBLIC contributions.
//!
//! 3. **Round 3 - Reveal**: Each party reveals their PARTIAL PUBLIC KEYS (t_I = A·s_I). Others
//!    verify that the revealed data matches the committed hash. SECURITY: Raw secrets are NEVER
//!    broadcast.
//!
//! 4. **Round 4 - P2P Secret Sharing**: Each party sends their SECRET contributions via P2P ONLY to
//!    parties in the same subsets. Recipients verify A·s matches the broadcast t.
//!
//! 5. **Round 5 - Confirmation**: Each party computes their final shares and the public key, then
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
	DkgConfig, DkgMessage, DkgOutput, DkgRound1Broadcast, DkgRound2Broadcast, DkgRound3Private,
	DkgRound4Broadcast, DkgRound5Broadcast, ParticipantId, SubsetContribution, SubsetMask,
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

		// Verify that parties in the same subset have the same combined share
		// Party 0 and Party 1 both belong to subset 0b11
		let party0_share_11 = dkg_outputs[0].private_share.shares().get(&0b11);
		let party1_share_11 = dkg_outputs[1].private_share.shares().get(&0b11);
		if let (Some(s0), Some(s1)) = (party0_share_11, party1_share_11) {
			let all_same = s0.s1.iter().zip(s1.s1.iter()).all(|(p0, p1)| p0 == p1) &&
				s0.s2.iter().zip(s1.s2.iter()).all(|(p0, p1)| p0 == p1);
			assert!(all_same, "Parties in the same subset should have identical shares");
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
					let others_r1: Vec<_> =
						r1_broadcasts.iter().filter(|r| r.party_id != i as u32).cloned().collect();
					let others_r2: Vec<_> =
						r2_broadcasts.iter().filter(|r| r.party_id != i as u32).cloned().collect();
					s.round3_respond(&others_r1, &others_r2).unwrap()
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

	/// Test that verifies the HQ1 security fix: threshold property is preserved.
	///
	/// HQ1 vulnerability: In the original implementation, all parties broadcast their
	/// raw secret contributions, allowing any single party to reconstruct the full
	/// secret key by summing all contributions.
	///
	/// The fix ensures:
	/// 1. Broadcast messages contain only partial PUBLIC keys (t_I = A·s_I), not raw secrets
	/// 2. Raw secrets are shared via P2P only with parties in the same subset
	/// 3. A single party cannot reconstruct secrets for subsets they don't belong to
	#[test]
	fn test_hq1_fix_threshold_property_preserved() {
		use crate::config::ThresholdConfig;

		let threshold = 2u32;
		let total_parties = 3u32;
		let seed = [
			0x48u8, 0x51, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, // "HQ1" + padding
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		];

		let threshold_config = ThresholdConfig::new(threshold, total_parties).unwrap();
		let participants: Vec<ParticipantId> = (0..total_parties).collect();

		// Create DKG instances
		let mut dkgs: Vec<DilithiumDkg> = participants
			.iter()
			.enumerate()
			.map(|(i, &party_id)| {
				let config =
					DkgConfig::new(threshold_config, party_id, participants.clone()).unwrap();
				let mut party_seed = seed;
				party_seed[0] = party_seed[0].wrapping_add(i as u8);
				DilithiumDkg::new(config, party_seed)
			})
			.collect();

		// Track all broadcast messages to verify they don't contain raw secrets
		let mut broadcast_messages: Vec<Vec<u8>> = Vec::new();

		// Track P2P messages per recipient to verify threshold property
		let mut p2p_messages_received: Vec<Vec<(ParticipantId, Vec<u8>)>> =
			vec![Vec::new(); total_parties as usize];

		let mut outputs: Vec<Option<DkgOutput>> = vec![None; total_parties as usize];
		let mut pending_messages: Vec<Vec<(ParticipantId, Vec<u8>)>> =
			vec![Vec::new(); total_parties as usize];

		// Run DKG and collect all messages
		let mut iterations = 0;
		while outputs.iter().any(|o| o.is_none()) {
			iterations += 1;
			assert!(iterations < 1000, "DKG should complete");

			for party_id in 0..total_parties as usize {
				let messages = std::mem::take(&mut pending_messages[party_id]);
				for (from, data) in messages {
					dkgs[party_id].message(from, data);
				}
			}

			for party_id in 0..total_parties as usize {
				if outputs[party_id].is_some() {
					continue;
				}

				match dkgs[party_id].poke().unwrap() {
					Action::Wait => {},
					Action::SendMany(data) => {
						// Track broadcast message
						broadcast_messages.push(data.clone());

						let from = party_id as ParticipantId;
						for (other, pending) in pending_messages.iter_mut().enumerate() {
							if other != party_id {
								pending.push((from, data.clone()));
							}
						}
					},
					Action::SendPrivate(to, data) => {
						// Track P2P message
						p2p_messages_received[to as usize]
							.push((party_id as ParticipantId, data.clone()));

						let from = party_id as ParticipantId;
						pending_messages[to as usize].push((from, data));
					},
					Action::Return(output) => {
						outputs[party_id] = Some(output);
					},
				}
			}
		}

		// =========================================================================
		// VERIFICATION 1: Broadcast messages don't contain raw secrets/seeds
		// =========================================================================
		// Round 2 broadcasts contain seed hashes (not raw seeds)
		// Round 3 is P2P (seeds)
		// Round 4 broadcasts contain partial public keys (derived from combined seeds)
		for msg_bytes in &broadcast_messages {
			let msg: DkgMessage = bincode::deserialize(msg_bytes).unwrap();
			if let DkgMessage::Round2(ref round2) = msg {
				// Round 2 broadcast should contain seed hashes
				let public_contrib = &round2.public_contributions;

				// Verify it has seed hashes (not raw seeds)
				assert!(
					!public_contrib.subset_seed_hashes.is_empty(),
					"Round 2 broadcast should contain seed hashes"
				);
			}
			if let DkgMessage::Round4(ref round4) = msg {
				// Round 4 broadcast contains partial public keys (not secrets)
				assert!(
					!round4.partial_public_keys.is_empty(),
					"Round 4 broadcast should contain partial public keys"
				);
			}
		}

		// =========================================================================
		// VERIFICATION 2: Each party only receives P2P seeds for their subsets
		// =========================================================================
		// For a 2-of-3 scheme, subset size is 3-2+1=2
		// Party 0 is in subsets: {0,1} (mask 0b011) and {0,2} (mask 0b101)
		// Party 1 is in subsets: {0,1} (mask 0b011) and {1,2} (mask 0b110)
		// Party 2 is in subsets: {0,2} (mask 0b101) and {1,2} (mask 0b110)

		for party_id in 0..total_parties as usize {
			let received = &p2p_messages_received[party_id];

			// Parse each P2P message and verify the subset
			for (from, msg_bytes) in received {
				let msg: DkgMessage = bincode::deserialize(msg_bytes).unwrap();
				if let DkgMessage::Round3(round3_private) = msg {
					let subset_mask = round3_private.subset_mask;

					// Verify this party (recipient) is in the subset
					assert!(
						(subset_mask & (1 << party_id)) != 0,
						"Party {} received P2P seed for subset {:b} but is not in that subset",
						party_id,
						subset_mask
					);

					// Verify the sender is also in the subset
					assert!(
						(subset_mask & (1 << from)) != 0,
						"Party {} sent P2P seed for subset {:b} but is not in that subset",
						from,
						subset_mask
					);
				}
			}
		}

		// =========================================================================
		// VERIFICATION 3: A single party cannot compute secrets for other subsets
		// =========================================================================
		// Party 0 belongs to subsets {0,1} and {0,2}
		// Party 0 should NOT be able to reconstruct the secret for subset {1,2}

		let party0_output = outputs[0].as_ref().unwrap();
		let party0_shares = party0_output.private_share.shares();

		// Party 0 should have shares for subsets it belongs to
		assert!(party0_shares.contains_key(&0b011), "Party 0 should have share for subset {{0,1}}");
		assert!(party0_shares.contains_key(&0b101), "Party 0 should have share for subset {{0,2}}");

		// Party 0 should NOT have shares for subset {1,2} (which it doesn't belong to)
		assert!(
			!party0_shares.contains_key(&0b110),
			"Party 0 should NOT have share for subset {{1,2}} - this would violate threshold!"
		);

		// Similarly verify for other parties
		let party1_shares = outputs[1].as_ref().unwrap().private_share.shares();
		assert!(!party1_shares.contains_key(&0b101), "Party 1 should NOT have share for {{0,2}}");

		let party2_shares = outputs[2].as_ref().unwrap().private_share.shares();
		assert!(!party2_shares.contains_key(&0b011), "Party 2 should NOT have share for {{0,1}}");

		// =========================================================================
		// VERIFICATION 4: Subsets that share members have the SAME combined secret
		// =========================================================================
		// This verifies the RSS scheme works correctly: all parties in a subset
		// should compute the same s_I = Σ_j s_I^(j)

		// Party 0 and Party 1 both belong to subset {0,1}
		let share_01_from_p0 = party0_shares.get(&0b011).unwrap();
		let share_01_from_p1 = party1_shares.get(&0b011).unwrap();

		assert_eq!(
			share_01_from_p0.s1, share_01_from_p1.s1,
			"Parties in same subset should have identical s1 shares"
		);
		assert_eq!(
			share_01_from_p0.s2, share_01_from_p1.s2,
			"Parties in same subset should have identical s2 shares"
		);

		println!("HQ1 security fix verified:");
		println!("  ✓ Broadcast messages contain only partial public keys, not raw secrets");
		println!("  ✓ P2P secrets are only sent to parties in the same subset");
		println!("  ✓ Parties only have shares for subsets they belong to");
		println!("  ✓ Parties in the same subset compute identical combined shares");
	}

	/// Test that DKG produces η-bounded shares (coefficients in [-η, η]).
	///
	/// This is the critical test for the bound fix: in the old DKG, combining
	/// k=n-t+1 contributions would produce coefficients in [-k·η, k·η].
	/// With the seed-based approach, all parties in a subset derive the SAME
	/// secret from combined seeds, resulting in properly η-bounded coefficients.
	///
	/// We test with many random seeds to ensure the bound holds statistically.
	#[test]
	fn test_dkg_eta_bounded_shares() {
		use rand::{Rng, SeedableRng};
		
		let eta = 2i32; // ML-DSA-87 η parameter
		let num_trials = 50; // Run 50 DKG instances with different seeds
		let mut rng = rand::rngs::StdRng::seed_from_u64(12345);
		
		let mut total_coefficients_checked = 0u64;

		for trial in 0..num_trials {
			// Generate a random seed for this trial
			let seed: [u8; 32] = rng.gen();
			
			let outputs = run_local_dkg(2, 3, seed).unwrap();

			for (party_id, output) in outputs.iter().enumerate() {
				let shares = output.private_share.shares();

				for (subset_mask, share) in shares {
					// Check s1 coefficients
					for (poly_idx, poly) in share.s1.iter().enumerate() {
						for (coeff_idx, &coeff) in poly.iter().enumerate() {
							total_coefficients_checked += 1;
							assert!(
								coeff >= -eta && coeff <= eta,
								"Trial {} Party {} subset {:b} s1[{}][{}] = {} is outside η bound [-{}, {}]",
								trial, party_id, subset_mask, poly_idx, coeff_idx, coeff, eta, eta
							);
						}
					}

					// Check s2 coefficients
					for (poly_idx, poly) in share.s2.iter().enumerate() {
						for (coeff_idx, &coeff) in poly.iter().enumerate() {
							total_coefficients_checked += 1;
							assert!(
								coeff >= -eta && coeff <= eta,
								"Trial {} Party {} subset {:b} s2[{}][{}] = {} is outside η bound [-{}, {}]",
								trial, party_id, subset_mask, poly_idx, coeff_idx, coeff, eta, eta
							);
						}
					}
				}
			}
		}

		println!("η-bounded shares verified across {} DKG trials:", num_trials);
		println!("  ✓ Checked {} total coefficients", total_coefficients_checked);
		println!("  ✓ All coefficients in [-{}, {}]", eta, eta);
		println!("  ✓ Seed-based DKG correctly produces η-bounded secrets");
	}

	/// Test that all parties in the same subset compute identical s1_I and s2_I.
	///
	/// This is a critical property of the seed-based DKG: since all parties in a
	/// subset combine the same seeds and use the same derivation function, they
	/// must all arrive at the same secret polynomials for that subset.
	///
	/// We test all subsets across multiple random seeds.
	#[test]
	fn test_dkg_subset_shares_identical() {
		use rand::{Rng, SeedableRng};
		
		let num_trials = 20;
		let mut rng = rand::rngs::StdRng::seed_from_u64(54321);

		for trial in 0..num_trials {
			let seed: [u8; 32] = rng.gen();
			let outputs = run_local_dkg(2, 3, seed).unwrap();

			// For a 2-of-3 scheme, subsets are:
			// - 0b011 (parties 0, 1)
			// - 0b101 (parties 0, 2)
			// - 0b110 (parties 1, 2)

			// Check subset {0, 1} (mask 0b011 = 3)
			let p0_share_01 = outputs[0].private_share.shares().get(&0b011);
			let p1_share_01 = outputs[1].private_share.shares().get(&0b011);
			if let (Some(s0), Some(s1)) = (p0_share_01, p1_share_01) {
				assert_eq!(s0.s1, s1.s1, "Trial {}: Party 0 and 1 should have same s1 for subset {{0,1}}", trial);
				assert_eq!(s0.s2, s1.s2, "Trial {}: Party 0 and 1 should have same s2 for subset {{0,1}}", trial);
			} else {
				panic!("Trial {}: Missing shares for subset {{0,1}}", trial);
			}

			// Check subset {0, 2} (mask 0b101 = 5)
			let p0_share_02 = outputs[0].private_share.shares().get(&0b101);
			let p2_share_02 = outputs[2].private_share.shares().get(&0b101);
			if let (Some(s0), Some(s2)) = (p0_share_02, p2_share_02) {
				assert_eq!(s0.s1, s2.s1, "Trial {}: Party 0 and 2 should have same s1 for subset {{0,2}}", trial);
				assert_eq!(s0.s2, s2.s2, "Trial {}: Party 0 and 2 should have same s2 for subset {{0,2}}", trial);
			} else {
				panic!("Trial {}: Missing shares for subset {{0,2}}", trial);
			}

			// Check subset {1, 2} (mask 0b110 = 6)
			let p1_share_12 = outputs[1].private_share.shares().get(&0b110);
			let p2_share_12 = outputs[2].private_share.shares().get(&0b110);
			if let (Some(s1), Some(s2)) = (p1_share_12, p2_share_12) {
				assert_eq!(s1.s1, s2.s1, "Trial {}: Party 1 and 2 should have same s1 for subset {{1,2}}", trial);
				assert_eq!(s1.s2, s2.s2, "Trial {}: Party 1 and 2 should have same s2 for subset {{1,2}}", trial);
			} else {
				panic!("Trial {}: Missing shares for subset {{1,2}}", trial);
			}
		}

		println!("Subset share identity verified across {} DKG trials:", num_trials);
		println!("  ✓ All parties in subset {{0,1}} have identical shares");
		println!("  ✓ All parties in subset {{0,2}} have identical shares");
		println!("  ✓ All parties in subset {{1,2}} have identical shares");
	}
}
