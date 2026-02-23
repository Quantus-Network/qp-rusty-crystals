//! Tests for `ThresholdSigner` state machine behavior.
//!
//! These tests verify the signer's state transitions and error handling.
//! End-to-end signing tests are in `integration_tests.rs`.
//! Key generation tests are in the `keygen/dealer.rs` module.

use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig, ThresholdSigner};

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

	let result = signer.round3_respond(&[]);
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

#[cfg(feature = "serde")]
mod serde_tests {
	use super::*;
	use qp_rusty_crystals_threshold::{Round1Broadcast, Round2Broadcast, Round3Broadcast};

	#[test]
	fn test_round1_broadcast_serialization() {
		let broadcast = Round1Broadcast::new(0, [42u8; 32]);
		let json = serde_json::to_string(&broadcast).expect("serialize");
		let recovered: Round1Broadcast = serde_json::from_str(&json).expect("deserialize");
		assert_eq!(broadcast, recovered);
	}

	#[test]
	fn test_round2_broadcast_serialization() {
		let broadcast = Round2Broadcast::new(1, vec![1, 2, 3, 4, 5]);
		let json = serde_json::to_string(&broadcast).expect("serialize");
		let recovered: Round2Broadcast = serde_json::from_str(&json).expect("deserialize");
		assert_eq!(broadcast, recovered);
	}

	#[test]
	fn test_round3_broadcast_serialization() {
		let broadcast = Round3Broadcast::new(2, vec![6, 7, 8, 9, 10]);
		let json = serde_json::to_string(&broadcast).expect("serialize");
		let recovered: Round3Broadcast = serde_json::from_str(&json).expect("deserialize");
		assert_eq!(broadcast, recovered);
	}

	#[test]
	fn test_config_serialization() {
		let config = ThresholdConfig::new(2, 3).expect("valid config");
		let json = serde_json::to_string(&config).expect("serialize");
		let recovered: ThresholdConfig = serde_json::from_str(&json).expect("deserialize");
		assert_eq!(config.threshold(), recovered.threshold());
		assert_eq!(config.total_parties(), recovered.total_parties());
	}
}
