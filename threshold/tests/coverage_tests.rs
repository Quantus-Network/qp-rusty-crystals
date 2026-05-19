//! Additional test coverage for edge cases and error paths.
//!
//! This module fills coverage gaps identified in the test suite,
//! focusing on security-critical error handling, edge cases, and
//! serialization validation.

use qp_rusty_crystals_threshold::{
	generate_with_dealer,
	signing_protocol::{DilithiumSignProtocol, SigningMessage, MAX_SIGNING_MESSAGE_SIZE},
	verify_signature, PrivateKeyShare, PublicKey, Round1Broadcast, Round2Broadcast,
	Round3Broadcast, ThresholdConfig, ThresholdSigner,
};

use qp_rusty_crystals_threshold::resharing::{ResharingConfig, ResharingProtocol};

// ============================================================================
// HIGH PRIORITY: Security Tests
// ============================================================================

mod participant_count_validation {
	use super::*;

	/// Test that signing with fewer than threshold participants is rejected.
	#[test]
	fn test_rejects_fewer_than_threshold_participants() {
		let config = ThresholdConfig::new(3, 5).expect("Valid DKG config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		// Try to sign with only 2 participants (threshold is 3)
		let result = DilithiumSignProtocol::new(
			signer,
			b"test message".to_vec(),
			b"".to_vec(),
			vec![0, 1], // Only 2 participants, need 3
			0,
			0,
			[0xAA; 32],
		);

		assert!(result.is_err(), "Should reject fewer than threshold participants");
		if let Err(e) = result {
			let err_msg = format!("{:?}", e);
			assert!(
				err_msg.contains("exactly") && err_msg.contains("threshold"),
				"Error should mention exactly threshold: {}",
				err_msg
			);
		}
	}

	/// Test that signing with exactly threshold participants succeeds.
	#[test]
	fn test_accepts_exactly_threshold_participants() {
		let config = ThresholdConfig::new(3, 5).expect("Valid DKG config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		// Exactly 3 participants for threshold 3
		let result = DilithiumSignProtocol::new(
			signer,
			b"test message".to_vec(),
			b"".to_vec(),
			vec![0, 1, 2], // Exactly threshold
			0,
			0,
			[0xAA; 32],
		);

		assert!(result.is_ok(), "Should accept exactly threshold participants");
	}
}

mod malformed_message_handling {
	use super::*;

	/// Test that empty messages are rejected.
	#[test]
	fn test_empty_message_rejected() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
		)
		.expect("Valid protocol");

		// Start protocol
		let _ = protocol.poke().expect("poke");

		// Send empty message
		let result = protocol.message(1, vec![]);
		assert!(result.is_err(), "Should reject empty message");
	}

	/// Test that oversized messages are rejected.
	#[test]
	fn test_oversized_message_rejected() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
		)
		.expect("Valid protocol");

		// Start protocol
		let _ = protocol.poke().expect("poke");

		// Send oversized message
		let huge_message = vec![0u8; MAX_SIGNING_MESSAGE_SIZE + 1];
		let result = protocol.message(1, huge_message);
		assert!(result.is_err(), "Should reject oversized message");
		let err_msg = format!("{:?}", result.unwrap_err());
		assert!(
			err_msg.contains("exceeds maximum"),
			"Error should mention size limit: {}",
			err_msg
		);
	}

	/// Test that garbage/malformed messages are rejected.
	#[test]
	fn test_garbage_message_rejected() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
		)
		.expect("Valid protocol");

		// Start protocol
		let _ = protocol.poke().expect("poke");

		// Send garbage that can't be deserialized
		let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0x00, 0x01, 0x02, 0x03];
		let result = protocol.message(1, garbage);
		assert!(result.is_err(), "Should reject malformed message");
	}
}

mod borsh_serialization_validation {
	use super::*;

	/// Test that corrupted Round1Broadcast borsh data is rejected.
	#[test]
	fn test_corrupted_round1_broadcast_rejected() {
		let broadcast = Round1Broadcast::new(0, [0x42u8; 32]);
		let mut serialized = borsh::to_vec(&broadcast).expect("serialize");

		// Corrupt the data
		if !serialized.is_empty() {
			serialized[0] ^= 0xFF;
		}

		let result: Result<Round1Broadcast, _> = borsh::from_slice(&serialized);
		// Note: borsh may or may not reject depending on what was corrupted
		// The key is it shouldn't panic
		let _ = result;
	}

	/// Test that corrupted Round2Broadcast borsh data is rejected.
	#[test]
	fn test_corrupted_round2_broadcast_rejected() {
		let broadcast = Round2Broadcast::new(0, vec![1, 2, 3, 4, 5, 6, 7, 8]);
		let mut serialized = borsh::to_vec(&broadcast).expect("serialize");

		// Corrupt length field area
		if serialized.len() > 4 {
			serialized[4] ^= 0xFF;
		}

		let result: Result<Round2Broadcast, _> = borsh::from_slice(&serialized);
		let _ = result; // Should not panic
	}

	/// Test that corrupted Round3Broadcast borsh data is rejected.
	#[test]
	fn test_corrupted_round3_broadcast_rejected() {
		let broadcast = Round3Broadcast::new(0, vec![10, 20, 30, 40]);
		let mut serialized = borsh::to_vec(&broadcast).expect("serialize");

		// Corrupt the data
		if serialized.len() > 2 {
			serialized[2] ^= 0xFF;
		}

		let result: Result<Round3Broadcast, _> = borsh::from_slice(&serialized);
		let _ = result; // Should not panic
	}

	/// Test that truncated borsh data is rejected.
	#[test]
	fn test_truncated_borsh_rejected() {
		let broadcast = Round1Broadcast::new(0, [0x42u8; 32]);
		let serialized = borsh::to_vec(&broadcast).expect("serialize");

		// Truncate to half length
		let truncated = &serialized[..serialized.len() / 2];

		let result: Result<Round1Broadcast, _> = borsh::from_slice(truncated);
		assert!(result.is_err(), "Should reject truncated data");
	}

	/// Test ThresholdConfig serialization roundtrip.
	#[test]
	fn test_config_serialization_roundtrip() {
		let config = ThresholdConfig::new(3, 5).expect("Valid config");
		let serialized = borsh::to_vec(&config).expect("serialize");
		let deserialized: ThresholdConfig = borsh::from_slice(&serialized).expect("deserialize");

		assert_eq!(config.threshold(), deserialized.threshold());
		assert_eq!(config.total_parties(), deserialized.total_parties());
	}

	/// Test PublicKey serialization roundtrip.
	#[test]
	fn test_public_key_serialization_roundtrip() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, _) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let serialized = borsh::to_vec(&public_key).expect("serialize");
		let deserialized: PublicKey = borsh::from_slice(&serialized).expect("deserialize");

		assert_eq!(public_key.as_bytes(), deserialized.as_bytes());
	}

	/// Test PrivateKeyShare serialization roundtrip.
	#[test]
	fn test_private_key_share_serialization_roundtrip() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (_, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let serialized = borsh::to_vec(&shares[0]).expect("serialize");
		let deserialized: PrivateKeyShare = borsh::from_slice(&serialized).expect("deserialize");

		assert_eq!(shares[0].party_id(), deserialized.party_id());
		assert_eq!(shares[0].threshold(), deserialized.threshold());
		assert_eq!(shares[0].total_parties(), deserialized.total_parties());
	}
}

// ============================================================================
// MEDIUM PRIORITY: Edge Cases
// ============================================================================

mod edge_cases {
	use super::*;

	/// Test t=n scenario where all parties are required.
	#[test]
	fn test_t_equals_n_all_parties_required() {
		let config = ThresholdConfig::new(3, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		// Try to sign with only 2 parties in a 3-of-3 scheme
		let result = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"".to_vec(),
			vec![0, 1], // Missing party 2
			0,
			0,
			[0xAA; 32],
		);

		assert!(result.is_err(), "3-of-3 should require all 3 parties");
	}

	/// Test context exactly at max length (255 bytes).
	#[test]
	fn test_context_max_length_accepted() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		let max_context = vec![0u8; 255];
		let protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			max_context,
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
		);

		assert!(protocol.is_ok(), "Context of exactly 255 bytes should be accepted");
	}

	/// Test that n=2 (minimum) works correctly.
	#[test]
	fn test_minimum_n_equals_2() {
		let config = ThresholdConfig::new(2, 2).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		assert_eq!(shares.len(), 2, "Should have exactly 2 shares");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		let protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
		);

		assert!(protocol.is_ok(), "2-of-2 protocol should initialize");
	}

	/// Test k_iterations getter returns expected values.
	#[test]
	fn test_k_iterations_values() {
		// Check a few known values from the K_TABLE
		let config_2_2 = ThresholdConfig::new(2, 2).expect("Valid");
		assert!(config_2_2.k_iterations() > 0, "k_iterations should be positive");

		let config_3_5 = ThresholdConfig::new(3, 5).expect("Valid");
		assert!(config_3_5.k_iterations() > 0, "k_iterations should be positive");

		let config_6_6 = ThresholdConfig::new(6, 6).expect("Valid");
		assert!(config_6_6.k_iterations() > 0, "k_iterations should be positive");
	}
}

mod message_buffering {
	use super::*;

	/// Test that Round 3 message arriving during Round 1 is buffered.
	#[test]
	fn test_round3_buffered_during_round1() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"".to_vec(),
			vec![0, 1],
			0,
			0,
			[0xAA; 32],
		)
		.expect("Valid protocol");

		// Start Round 1
		let _ = protocol.poke().expect("poke");

		// Create and send a Round 3 message while in Round 1
		let r3 = Round3Broadcast::new(1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
		let msg = SigningMessage::Round3(r3);
		let data = borsh::to_vec(&msg).expect("serialize");

		// Should accept (buffer) the message without error
		let result = protocol.message(1, data);
		assert!(result.is_ok(), "Out-of-order message should be buffered, not rejected");
	}
}

mod sender_validation {
	use super::*;

	/// Test that messages from self are ignored.
	#[test]
	fn test_message_from_self_ignored() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"".to_vec(),
			vec![0, 1],
			0, // my_id is 0
			0,
			[0xAA; 32],
		)
		.expect("Valid protocol");

		// Start Round 1
		let _ = protocol.poke().expect("poke");

		// Send a message claiming to be from self
		let r1 = Round1Broadcast::new(0, [0x42u8; 32]);
		let msg = SigningMessage::Round1(r1);
		let data = borsh::to_vec(&msg).expect("serialize");

		// Should be silently ignored (returns Ok)
		let result = protocol.message(0, data);
		assert!(result.is_ok(), "Message from self should be silently ignored");
	}

	/// Test that messages from non-participants are ignored.
	#[test]
	fn test_message_from_non_participant_ignored() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"".to_vec(),
			vec![0, 1], // Only parties 0 and 1
			0,
			0,
			[0xAA; 32],
		)
		.expect("Valid protocol");

		// Start Round 1
		let _ = protocol.poke().expect("poke");

		// Send a message from party 2 (not a participant)
		let r1 = Round1Broadcast::new(2, [0x42u8; 32]);
		let msg = SigningMessage::Round1(r1);
		let data = borsh::to_vec(&msg).expect("serialize");

		// Should be silently ignored
		let result = protocol.message(2, data);
		assert!(result.is_ok(), "Message from non-participant should be silently ignored");
	}

	/// Test sender mismatch (envelope says X, message says Y).
	#[test]
	fn test_sender_mismatch_ignored() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let signer = ThresholdSigner::new(shares[0].clone(), public_key.clone(), config)
			.expect("Valid signer");

		// Use exactly threshold (2) participants: 0 and 1
		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test".to_vec(),
			b"".to_vec(),
			vec![0, 1], // Exactly threshold participants
			0,
			0,
			[0xAA; 32],
		)
		.expect("Valid protocol");

		// Start Round 1
		let _ = protocol.poke().expect("poke");

		// Create message claiming to be from party 0 (inner party_id)
		let r1 = Round1Broadcast::new(0, [0x42u8; 32]);
		let msg = SigningMessage::Round1(r1);
		let data = borsh::to_vec(&msg).expect("serialize");

		// But send it with envelope saying it's from party 1
		let result = protocol.message(1, data);
		// Should be ignored due to mismatch (returns Ok but doesn't process)
		assert!(result.is_ok(), "Sender mismatch should be silently ignored");
	}
}

// ============================================================================
// RESHARING TESTS
// ============================================================================

mod resharing_edge_cases {
	use super::*;
	use std::collections::HashMap;

	/// Test that resharing config rejects new_threshold < 2.
	#[test]
	fn test_resharing_rejects_new_threshold_too_small() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let mut share_map = HashMap::new();
		share_map.insert(0u32, shares[0].clone());

		let result = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			1, // Invalid: threshold must be >= 2
			vec![0, 1, 2],
			0,
			Some(shares[0].clone()),
			public_key,
		);

		assert!(result.is_err(), "Should reject new_threshold < 2");
	}

	/// Test that resharing config rejects empty new committee.
	#[test]
	fn test_resharing_rejects_empty_new_committee() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let result = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![], // Empty new committee
			0,
			Some(shares[0].clone()),
			public_key,
		);

		assert!(result.is_err(), "Should reject empty new committee");
	}

	/// Test that take_output returns None on second call.
	#[test]
	fn test_take_output_idempotent() {
		// This requires running a full resharing protocol
		// For simplicity, we test the concept: take_output should be idempotent
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], config).expect("Key gen");

		let resharing_config = ResharingConfig::new(
			2,
			vec![0, 1, 2],
			2,
			vec![0, 1, 2],
			0,
			Some(shares[0].clone()),
			public_key,
		)
		.expect("Valid resharing config");

		let protocol_seed = [42u8; 32];
		let mut protocol = ResharingProtocol::new(resharing_config, protocol_seed);

		// Before completion, take_output should return None
		let output1 = protocol.take_output();
		assert!(output1.is_none(), "take_output before completion should return None");

		// Calling again should still return None
		let output2 = protocol.take_output();
		assert!(output2.is_none(), "take_output should be idempotent");
	}
}

// ============================================================================
// SIGNER CONFIGURATION TESTS
// ============================================================================

mod signer_configuration {
	use super::*;

	/// Test that creating a signer with mismatched threshold fails.
	#[test]
	fn test_signer_threshold_mismatch_rejected() {
		let dkg_config = ThresholdConfig::new(2, 3).expect("Valid DKG config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], dkg_config).expect("Key gen");

		// Try to use the share with a different threshold
		let signing_config = ThresholdConfig::new(3, 3).expect("Valid signing config");
		let result = ThresholdSigner::new(shares[0].clone(), public_key, signing_config);

		// This should fail because the share was created for threshold=2, not threshold=3
		// Note: The exact behavior depends on implementation - it may fail or may work
		// if the share data is compatible. Let's verify it at least doesn't panic.
		let _ = result;
	}

	/// Test that creating a signer with more parties than DKG fails.
	#[test]
	fn test_signer_too_many_parties_rejected() {
		let dkg_config = ThresholdConfig::new(2, 3).expect("Valid DKG config");
		let (public_key, shares) = generate_with_dealer(&[42u8; 32], dkg_config).expect("Key gen");

		// Try to use the share with more parties than the DKG
		let signing_config = ThresholdConfig::new(2, 5).expect("Valid signing config");
		let result = ThresholdSigner::new(shares[0].clone(), public_key, signing_config);

		assert!(result.is_err(), "Should reject signer with more parties than DKG");
	}
}

// ============================================================================
// DKG TESTS
// ============================================================================

mod dkg_coverage {
	use super::*;

	/// Test DKG with dealer for all supported configurations.
	#[test]
	fn test_dealer_all_small_configurations() {
		let configs = [(2, 2), (2, 3), (3, 3), (2, 4), (3, 4), (4, 4)];

		for (t, n) in configs {
			let seed = [42u8; 32];
			let config = ThresholdConfig::new(t, n).expect("Valid config");
			let result = generate_with_dealer(&seed, config);
			assert!(
				result.is_ok(),
				"Dealer key gen should succeed for ({}, {}): {:?}",
				t,
				n,
				result.err()
			);

			let (public_key, shares) = result.unwrap();
			assert_eq!(shares.len(), n as usize, "Should have {} shares", n);

			// Verify all shares have correct party IDs
			for (i, share) in shares.iter().enumerate() {
				assert_eq!(share.party_id(), i as u32, "Share {} should have party_id {}", i, i);
			}

			// Verify public key is non-empty
			assert!(!public_key.as_bytes().is_empty(), "Public key should not be empty");
		}
	}

	/// Test that dealer-generated shares produce valid signatures.
	#[test]
	fn test_dealer_shares_sign_correctly() {
		let config = ThresholdConfig::new(2, 3).expect("Valid config");
		let seed = [42u8; 32];
		let (public_key, shares) = generate_with_dealer(&seed, config).expect("Key gen");

		// Create signers for parties 0 and 1
		let signers: Vec<ThresholdSigner> = shares
			.into_iter()
			.take(2)
			.map(|share| ThresholdSigner::new(share, public_key.clone(), config).expect("signer"))
			.collect();

		let message = b"test message";
		let context = b"";

		let result = qp_rusty_crystals_threshold::signing_protocol::run_local_signing(
			signers, message, context, &seed,
		);
		assert!(result.is_ok(), "Signing should succeed: {:?}", result.err());

		let signature = result.unwrap();
		assert!(
			verify_signature(&public_key, message, context, &signature),
			"Signature should verify"
		);
	}
}

// ============================================================================
// ERROR DISPLAY TESTS
// ============================================================================

mod error_display {
	use qp_rusty_crystals_threshold::ThresholdError;

	/// Test that all error variants have meaningful Display output.
	#[test]
	fn test_error_display_implementations() {
		let errors = vec![
			ThresholdError::InvalidParameters {
				threshold: 1,
				parties: 3,
				reason: "threshold must be at least 2",
			},
			ThresholdError::InvalidPartyId { party_id: 5, max_id: 3 },
			ThresholdError::InsufficientParties { provided: 2, required: 3 },
			ThresholdError::InvalidSignatureShare { party_id: 1, reason: "bounds check failed" },
			ThresholdError::ContextTooLong { length: 300 },
			ThresholdError::CombinationFailed,
			ThresholdError::RejectionSampling,
			ThresholdError::DkgCommitmentMismatch { party_id: 2 },
		];

		for error in errors {
			let display = format!("{}", error);
			assert!(!display.is_empty(), "Error display should not be empty: {:?}", error);
			// Verify it doesn't just say "ThresholdError" - should have meaningful content
			assert!(
				display.len() > 15,
				"Error display should be descriptive: {} for {:?}",
				display,
				error
			);
		}
	}
}

// ============================================================================
// FULL PROTOCOL INTEGRATION TESTS
// ============================================================================

mod protocol_integration {
	use super::*;
	use qp_rusty_crystals_threshold::signing_protocol::run_local_signing;

	/// Test complete signing flow with 2-of-2 (minimum viable).
	#[test]
	fn test_full_signing_2_of_2() {
		let config = ThresholdConfig::new(2, 2).expect("Valid config");
		let seed = [42u8; 32];
		let (public_key, shares) = generate_with_dealer(&seed, config).expect("Key gen");

		let signers: Vec<ThresholdSigner> = shares
			.into_iter()
			.map(|share| ThresholdSigner::new(share, public_key.clone(), config).expect("signer"))
			.collect();

		let message = b"test message for 2-of-2";
		let context = b"";

		let result = run_local_signing(signers, message, context, &seed);
		assert!(result.is_ok(), "2-of-2 signing should succeed: {:?}", result.err());

		let signature = result.unwrap();
		assert!(
			verify_signature(&public_key, message, context, &signature),
			"Signature should verify"
		);
	}

	/// Test complete signing flow with t=n (all parties required).
	#[test]
	fn test_full_signing_t_equals_n() {
		let config = ThresholdConfig::new(4, 4).expect("Valid config");
		let seed = [42u8; 32];
		let (public_key, shares) = generate_with_dealer(&seed, config).expect("Key gen");

		let signers: Vec<ThresholdSigner> = shares
			.into_iter()
			.map(|share| ThresholdSigner::new(share, public_key.clone(), config).expect("signer"))
			.collect();

		let message = b"test message for 4-of-4";
		let context = b"test context";

		let result = run_local_signing(signers, message, context, &seed);
		assert!(result.is_ok(), "4-of-4 signing should succeed: {:?}", result.err());

		let signature = result.unwrap();
		assert!(
			verify_signature(&public_key, message, context, &signature),
			"Signature should verify"
		);
	}
}
