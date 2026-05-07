//! Tests for `ThresholdSigner` state machine behavior.
//!
//! These tests verify the signer's state transitions and error handling.
//! End-to-end signing tests are in `integration_tests.rs`.
//! Key generation tests are in the `keygen/dealer.rs` module.

use qp_rusty_crystals_threshold::{
	generate_with_dealer, Round1Broadcast, Round2Broadcast, ThresholdConfig, ThresholdSigner,
};

/// Helper to create test signers for state machine tests.
fn create_test_signer() -> ThresholdSigner {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("key generation");
	ThresholdSigner::new(shares[0].clone(), public_key, config).expect("signer creation")
}

/// Test Round 1 commitment generation produces valid output.
#[test]
fn test_round1_commit() {
	let mut signer = create_test_signer();
	let mut rng = rand::thread_rng();

	let r1 = signer.round1_commit(&mut rng).expect("round1");

	assert_eq!(r1.party_id, 0);
	assert_eq!(r1.commitment_hash.len(), 32);
}

/// Test state machine enforcement - can't call round2 before round1.
#[test]
fn test_state_machine_round2_before_round1() {
	let mut signer = create_test_signer();

	let result = signer.round2_reveal(b"message", b"context", &[]);
	assert!(result.is_err(), "round2 should fail without prior round1");
}

/// Test state machine enforcement - can't call round1 twice.
#[test]
fn test_state_machine_round1_twice() {
	let mut signer = create_test_signer();
	let mut rng = rand::thread_rng();

	let _r1 = signer.round1_commit(&mut rng).expect("round1");

	let result = signer.round1_commit(&mut rng);
	assert!(result.is_err(), "round1 should fail when called twice");
}

/// Test that tampering with Round 2 commitment data is detected (HQ2).
///
/// This test verifies the fix for the rushing adversary attack where a malicious
/// party could alter their commitment data after seeing others' commitments.
#[test]
fn test_commitment_tampering_detected() {
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let seed = [42u8; 32];
	let (public_key, shares) = generate_with_dealer(&seed, config).expect("key generation");

	// Create signers for all 3 parties
	let mut signers: Vec<_> = shares
		.iter()
		.map(|share| ThresholdSigner::new(share.clone(), public_key.clone(), config).unwrap())
		.collect();

	let mut rng = rand::thread_rng();
	let message = b"test message";
	let context = b"test context";

	// Round 1: All parties generate commitments
	let r1_broadcasts: Vec<Round1Broadcast> =
		signers.iter_mut().map(|s| s.round1_commit(&mut rng).unwrap()).collect();

	// Round 2: All parties reveal commitments
	let mut r2_broadcasts: Vec<Round2Broadcast> = signers
		.iter_mut()
		.enumerate()
		.map(|(i, s)| {
			let others: Vec<_> =
				r1_broadcasts.iter().filter(|r| r.party_id != i as u32).cloned().collect();
			s.round2_reveal(message, context, &others).unwrap()
		})
		.collect();

	// ATTACK: Party 1 tampers with their commitment data after broadcasting
	// This simulates a rushing adversary trying to change their values
	if !r2_broadcasts[1].commitment_data.is_empty() {
		// Flip some bits in the commitment data
		r2_broadcasts[1].commitment_data[0] ^= 0xFF;
		r2_broadcasts[1].commitment_data[1] ^= 0xFF;
	}

	// Round 3: Party 0 tries to process the tampered data
	// This should fail because the tampered R2 data doesn't match the R1 hash
	let others_r1: Vec<_> = r1_broadcasts.iter().filter(|r| r.party_id != 0).cloned().collect();
	let others_r2: Vec<_> = r2_broadcasts.iter().filter(|r| r.party_id != 0).cloned().collect();

	let result = signers[0].round3_respond(&others_r1, &others_r2);

	assert!(result.is_err(), "round3_respond should detect tampered commitment data");

	// Verify it's specifically a commitment mismatch error
	let err = result.unwrap_err();
	let err_str = format!("{}", err);
	assert!(
		err_str.contains("ommitment") && err_str.contains("mismatch"),
		"Error should indicate commitment mismatch, got: {}",
		err_str
	);
}

/// Test signer reset allows restarting the protocol.
#[test]
fn test_signer_reset() {
	let mut signer = create_test_signer();
	let mut rng = rand::thread_rng();

	let _r1 = signer.round1_commit(&mut rng).expect("round1");
	signer.reset();

	// Should be able to call round1 again after reset
	let _r1 = signer.round1_commit(&mut rng).expect("round1 after reset");
}

/// Test state machine enforcement - can't call round3 before round2.
#[test]
fn test_state_machine_round3_before_round2() {
	let mut signer = create_test_signer();
	let mut rng = rand::thread_rng();

	let _r1 = signer.round1_commit(&mut rng).expect("round1");

	let result = signer.round3_respond(&[], &[]);
	assert!(result.is_err(), "round3 should fail without prior round2");
}

/// Test state machine enforcement - can't call combine before round3.
#[test]
fn test_state_machine_combine_before_round3() {
	let mut signer = create_test_signer();
	let mut rng = rand::thread_rng();

	let _r1 = signer.round1_commit(&mut rng).expect("round1");

	let result = signer.combine(&[], &[]);
	assert!(result.is_err(), "combine should fail without completing round3");
}

mod borsh_tests {
	use super::*;
	use qp_rusty_crystals_threshold::{Round1Broadcast, Round2Broadcast, Round3Broadcast};

	#[test]
	fn test_round1_broadcast_serialization() {
		let broadcast = Round1Broadcast::new(0, [42u8; 32]);
		let bytes = borsh::to_vec(&broadcast).expect("serialize");
		let recovered: Round1Broadcast = borsh::from_slice(&bytes).expect("deserialize");
		assert_eq!(broadcast, recovered);
	}

	#[test]
	fn test_round2_broadcast_serialization() {
		let broadcast = Round2Broadcast::new(1, vec![1, 2, 3, 4, 5]);
		let bytes = borsh::to_vec(&broadcast).expect("serialize");
		let recovered: Round2Broadcast = borsh::from_slice(&bytes).expect("deserialize");
		assert_eq!(broadcast, recovered);
	}

	#[test]
	fn test_round3_broadcast_serialization() {
		let broadcast = Round3Broadcast::new(2, vec![6, 7, 8, 9, 10]);
		let bytes = borsh::to_vec(&broadcast).expect("serialize");
		let recovered: Round3Broadcast = borsh::from_slice(&bytes).expect("deserialize");
		assert_eq!(broadcast, recovered);
	}

	#[test]
	fn test_config_serialization() {
		let config = ThresholdConfig::new(2, 3).expect("valid config");
		let bytes = borsh::to_vec(&config).expect("serialize");
		let recovered: ThresholdConfig = borsh::from_slice(&bytes).expect("deserialize");
		assert_eq!(config.threshold(), recovered.threshold());
		assert_eq!(config.total_parties(), recovered.total_parties());
	}
}

/// Tests for DilithiumSignProtocol party management.
mod party_management_tests {
	use qp_rusty_crystals_threshold::{
		generate_with_dealer, signing_protocol::DilithiumSignProtocol, ThresholdConfig,
		ThresholdSigner,
	};

	/// Test that waiting_for() returns correct parties in Round1Waiting state.
	#[test]
	fn test_waiting_for_round1() {
		let config = ThresholdConfig::new(2, 3).expect("valid config");
		let seed = [42u8; 32];
		let (public_key, shares) = generate_with_dealer(&seed, config).expect("key generation");

		let signer =
			ThresholdSigner::new(shares[0].clone(), public_key.clone(), config).expect("signer");

		let mut protocol = DilithiumSignProtocol::new(
			signer,
			b"test message".to_vec(),
			b"context".to_vec(),
			vec![0, 1, 2],
			0, // my_id
			0, // leader_id
		);

		// Generate our Round 1
		let _ = protocol.poke().expect("poke");

		// Now in Round1Waiting, should be waiting for parties 1 and 2
		let waiting = protocol.waiting_for();
		assert_eq!(waiting.len(), 2);
		assert!(waiting.contains(&1));
		assert!(waiting.contains(&2));
	}
}
