//! Integration tests for the new threshold signing API.
//!
//! These tests demonstrate and validate the `ThresholdSigner` API,
//! which provides a cleaner interface for threshold signing.

use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig, ThresholdSigner};

/// Test basic key generation with the new API.
#[test]
fn test_key_generation() {
    let config = ThresholdConfig::new(2, 3).expect("valid config");
    let seed = [42u8; 32];

    let (public_key, shares) = generate_with_dealer(&seed, config).expect("key generation");

    assert_eq!(shares.len(), 3);
    assert_eq!(shares[0].party_id(), 0);
    assert_eq!(shares[1].party_id(), 1);
    assert_eq!(shares[2].party_id(), 2);

    // All shares should have the same threshold and total_parties
    for share in &shares {
        assert_eq!(share.threshold(), 2);
        assert_eq!(share.total_parties(), 3);
    }

    // Public key should be valid
    assert_eq!(public_key.as_bytes().len(), 2592);
}

/// Test creating signers from shares.
#[test]
fn test_signer_creation() {
    let config = ThresholdConfig::new(2, 3).expect("valid config");
    let seed = [42u8; 32];

    let (public_key, shares) = generate_with_dealer(&seed, config).expect("key generation");

    // Create signers for all parties
    let signers: Vec<_> = shares
        .into_iter()
        .map(|share| ThresholdSigner::new(share, public_key.clone(), config))
        .collect::<Result<_, _>>()
        .expect("signer creation");

    assert_eq!(signers.len(), 3);
    assert_eq!(signers[0].party_id(), 0);
    assert_eq!(signers[1].party_id(), 1);
    assert_eq!(signers[2].party_id(), 2);
}

/// Test Round 1 commitment generation.
#[test]
fn test_round1_commit() {
    let config = ThresholdConfig::new(2, 3).expect("valid config");
    let seed = [42u8; 32];

    let (public_key, shares) = generate_with_dealer(&seed, config).expect("key generation");

    let mut signer = ThresholdSigner::new(shares[0].clone(), public_key, config).expect("signer");

    let mut rng = rand::thread_rng();
    let r1 = signer.round1_commit(&mut rng).expect("round1");

    assert_eq!(r1.party_id, 0);
    // Commitment hash should be 32 bytes
    assert_eq!(r1.commitment_hash.len(), 32);
}

/// Test that Round 1 produces different commitments with different randomness.
#[test]
fn test_round1_randomness() {
    let config = ThresholdConfig::new(2, 3).expect("valid config");
    let seed = [42u8; 32];

    let (public_key, shares) = generate_with_dealer(&seed, config).expect("key generation");

    let mut signer1 =
        ThresholdSigner::new(shares[0].clone(), public_key.clone(), config).expect("signer");
    let mut signer2 = ThresholdSigner::new(shares[0].clone(), public_key, config).expect("signer");

    let mut rng = rand::thread_rng();
    let r1_a = signer1.round1_commit(&mut rng).expect("round1");
    let r1_b = signer2.round1_commit(&mut rng).expect("round1");

    // Different random seeds should produce different commitments
    assert_ne!(r1_a.commitment_hash, r1_b.commitment_hash);
}

/// Test state machine enforcement - can't call round2 before round1.
#[test]
fn test_state_machine_round2_before_round1() {
    let config = ThresholdConfig::new(2, 3).expect("valid config");
    let seed = [42u8; 32];

    let (public_key, shares) = generate_with_dealer(&seed, config).expect("key generation");

    let mut signer = ThresholdSigner::new(shares[0].clone(), public_key, config).expect("signer");

    // Try to call round2 without round1 - should fail
    let result = signer.round2_reveal(b"message", b"context", &[]);
    assert!(result.is_err());
}

/// Test state machine enforcement - can't call round1 twice.
#[test]
fn test_state_machine_round1_twice() {
    let config = ThresholdConfig::new(2, 3).expect("valid config");
    let seed = [42u8; 32];

    let (public_key, shares) = generate_with_dealer(&seed, config).expect("key generation");

    let mut signer = ThresholdSigner::new(shares[0].clone(), public_key, config).expect("signer");

    let mut rng = rand::thread_rng();
    let _r1 = signer.round1_commit(&mut rng).expect("round1");

    // Try to call round1 again - should fail
    let result = signer.round1_commit(&mut rng);
    assert!(result.is_err());
}

/// Test signer reset.
#[test]
fn test_signer_reset() {
    let config = ThresholdConfig::new(2, 3).expect("valid config");
    let seed = [42u8; 32];

    let (public_key, shares) = generate_with_dealer(&seed, config).expect("key generation");

    let mut signer = ThresholdSigner::new(shares[0].clone(), public_key, config).expect("signer");

    let mut rng = rand::thread_rng();
    let _r1 = signer.round1_commit(&mut rng).expect("round1");

    // Reset the signer
    signer.reset();

    // Should be able to call round1 again after reset
    let _r1 = signer.round1_commit(&mut rng).expect("round1 after reset");
}

/// Test deterministic key generation.
#[test]
fn test_deterministic_keygen() {
    let config = ThresholdConfig::new(2, 3).expect("valid config");
    let seed = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32];

    let (pk1, _shares1) = generate_with_dealer(&seed, config).expect("keygen 1");
    let (pk2, _shares2) = generate_with_dealer(&seed, config).expect("keygen 2");

    // Same seed should produce same public key
    assert_eq!(pk1.as_bytes(), pk2.as_bytes());
}

/// Test that different seeds produce different keys.
#[test]
fn test_different_seeds_different_keys() {
    let config = ThresholdConfig::new(2, 3).expect("valid config");
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];

    let (pk1, _) = generate_with_dealer(&seed1, config).expect("keygen 1");
    let (pk2, _) = generate_with_dealer(&seed2, config).expect("keygen 2");

    // Different seeds should produce different public keys
    assert_ne!(pk1.as_bytes(), pk2.as_bytes());
}

// Full end-to-end signing tests are now in integration_tests.rs

#[cfg(feature = "serde")]
mod serde_tests {
    use super::*;

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
