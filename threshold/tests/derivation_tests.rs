//! Integration tests for Dilithium key derivation.
//!
//! These tests verify that:
//! 1. DKG contributions are deterministic and unique per party
//! 2. Derived keys can be used for threshold signing
//! 3. The full derivation + signing flow works end-to-end

use qp_rusty_crystals_threshold::{
	derive_dkg_contribution, derive_tweak, generate_with_dealer, verify_signature, DerivedKeyId,
	PrivateKeyShare, ThresholdConfig, ThresholdSigner,
};
use std::collections::HashMap;

/// Helper to create test shares using dealer-based generation
fn create_test_shares(seed: [u8; 32], threshold: u32, total: u32) -> Vec<PrivateKeyShare> {
	let config = ThresholdConfig::new(threshold, total).expect("valid config");
	let (_public_key, shares) = generate_with_dealer(&seed, config).expect("keygen succeeds");
	shares
}

/// Test that derive_tweak produces deterministic results
#[test]
fn test_tweak_derivation_deterministic() {
	let tweak1 = derive_tweak("alice.near", "ethereum");
	let tweak2 = derive_tweak("alice.near", "ethereum");
	assert_eq!(tweak1, tweak2, "Same inputs should produce same tweak");
}

/// Test that different accounts produce different tweaks
#[test]
fn test_tweak_derivation_account_isolation() {
	let tweak_alice = derive_tweak("alice.near", "ethereum");
	let tweak_bob = derive_tweak("bob.near", "ethereum");
	assert_ne!(tweak_alice, tweak_bob, "Different accounts should produce different tweaks");
}

/// Test that different paths produce different tweaks
#[test]
fn test_tweak_derivation_path_isolation() {
	let tweak_eth = derive_tweak("alice.near", "ethereum");
	let tweak_btc = derive_tweak("alice.near", "bitcoin");
	assert_ne!(tweak_eth, tweak_btc, "Different paths should produce different tweaks");
}

/// Test that DKG contributions are deterministic for the same share + tweak
#[test]
fn test_dkg_contribution_deterministic() {
	let shares = create_test_shares([42u8; 32], 2, 3);
	let tweak = derive_tweak("alice.near", "ethereum");

	let contribution1 = derive_dkg_contribution(&shares[0], &tweak);
	let contribution2 = derive_dkg_contribution(&shares[0], &tweak);

	assert_eq!(contribution1, contribution2, "Same share + tweak should produce same contribution");
}

/// Test that different parties produce different DKG contributions
#[test]
fn test_dkg_contribution_party_isolation() {
	let shares = create_test_shares([42u8; 32], 2, 3);
	let tweak = derive_tweak("alice.near", "ethereum");

	let contribution0 = derive_dkg_contribution(&shares[0], &tweak);
	let contribution1 = derive_dkg_contribution(&shares[1], &tweak);
	let contribution2 = derive_dkg_contribution(&shares[2], &tweak);

	assert_ne!(
		contribution0, contribution1,
		"Different parties should produce different contributions"
	);
	assert_ne!(
		contribution1, contribution2,
		"Different parties should produce different contributions"
	);
	assert_ne!(
		contribution0, contribution2,
		"Different parties should produce different contributions"
	);
}

/// Test that different tweaks produce different DKG contributions
#[test]
fn test_dkg_contribution_tweak_isolation() {
	let shares = create_test_shares([42u8; 32], 2, 3);
	let tweak_eth = derive_tweak("alice.near", "ethereum");
	let tweak_btc = derive_tweak("alice.near", "bitcoin");

	let contribution_eth = derive_dkg_contribution(&shares[0], &tweak_eth);
	let contribution_btc = derive_dkg_contribution(&shares[0], &tweak_btc);

	assert_ne!(
		contribution_eth, contribution_btc,
		"Different tweaks should produce different contributions"
	);
}

/// Test that different master keys produce different DKG contributions
#[test]
fn test_dkg_contribution_key_isolation() {
	let shares_a = create_test_shares([1u8; 32], 2, 3);
	let shares_b = create_test_shares([2u8; 32], 2, 3);
	let tweak = derive_tweak("alice.near", "ethereum");

	let contribution_a = derive_dkg_contribution(&shares_a[0], &tweak);
	let contribution_b = derive_dkg_contribution(&shares_b[0], &tweak);

	assert_ne!(
		contribution_a, contribution_b,
		"Different master keys should produce different contributions"
	);
}

/// Test DerivedKeyId creation and equality
#[test]
fn test_derived_key_id() {
	let id1 = DerivedKeyId::from_account_path(0, "alice.near", "ethereum");
	let id2 = DerivedKeyId::from_account_path(0, "alice.near", "ethereum");
	let id3 = DerivedKeyId::from_account_path(0, "bob.near", "ethereum");
	let id4 = DerivedKeyId::from_account_path(1, "alice.near", "ethereum");

	assert_eq!(id1, id2, "Same inputs should produce same ID");
	assert_ne!(id1, id3, "Different accounts should produce different IDs");
	assert_ne!(id1, id4, "Different domains should produce different IDs");
}

/// Test that DerivedKeyId can be used as HashMap key
#[test]
fn test_derived_key_id_as_hashmap_key() {
	let mut map: HashMap<DerivedKeyId, String> = HashMap::new();

	let id1 = DerivedKeyId::from_account_path(0, "alice.near", "ethereum");
	let id2 = DerivedKeyId::from_account_path(0, "bob.near", "ethereum");

	map.insert(id1.clone(), "alice_eth_key".to_string());
	map.insert(id2.clone(), "bob_eth_key".to_string());

	assert_eq!(map.get(&id1), Some(&"alice_eth_key".to_string()));
	assert_eq!(map.get(&id2), Some(&"bob_eth_key".to_string()));

	// Lookup with freshly created ID should work
	let id1_fresh = DerivedKeyId::from_account_path(0, "alice.near", "ethereum");
	assert_eq!(map.get(&id1_fresh), Some(&"alice_eth_key".to_string()));
}

/// Simulate the full derived key generation flow:
/// 1. Each party derives their DKG contribution from master share + tweak
/// 2. Use contributions as seeds for deterministic DKG
/// 3. Verify all parties get the same public key
/// 4. Sign with derived shares
#[test]
fn test_derived_key_generation_and_signing() {
	// Step 1: Create master shares (simulating initial DKG)
	let master_seed = [42u8; 32];
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let (master_pubkey, master_shares) =
		generate_with_dealer(&master_seed, config).expect("master keygen");

	// Step 2: Derive DKG contributions for a derived key
	let tweak = derive_tweak("alice.near", "ethereum");

	let contributions: Vec<[u8; 32]> = master_shares
		.iter()
		.map(|share| derive_dkg_contribution(share, &tweak))
		.collect();

	// Verify contributions are unique per party
	assert_ne!(contributions[0], contributions[1]);
	assert_ne!(contributions[1], contributions[2]);
	assert_ne!(contributions[0], contributions[2]);

	// Step 3: Use combined contributions as seed for derived key generation
	// In real implementation, this would be done through DKG protocol
	// Here we simulate by XORing contributions (real impl uses DKG)
	let mut derived_seed = [0u8; 32];
	for contribution in &contributions {
		for (i, byte) in contribution.iter().enumerate() {
			derived_seed[i] ^= byte;
		}
	}

	// Generate derived key shares
	let (derived_pubkey, derived_shares) =
		generate_with_dealer(&derived_seed, config).expect("derived keygen");

	// Step 4: Verify derived key is different from master key
	assert_ne!(
		master_pubkey.as_bytes(),
		derived_pubkey.as_bytes(),
		"Derived key should differ from master key"
	);

	// Step 5: Sign with derived shares (with retry for rejection sampling)
	let message = b"Hello from derived key!";
	let context = b"test-context";

	let mut signature = None;
	for attempt in 0..100 {
		// Create signers for threshold subset (2 of 3)
		let mut signers: Vec<ThresholdSigner> = derived_shares
			.iter()
			.take(2)
			.map(|share| {
				ThresholdSigner::new(share.clone(), derived_pubkey.clone(), config).unwrap()
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

		// Try to combine signature
		if let Ok(sig) =
			signers[0].combine_with_message(message, context, &r2_broadcasts, &r3_broadcasts)
		{
			signature = Some(sig);
			if attempt > 0 {
				println!("Signing succeeded on attempt {}", attempt + 1);
			}
			break;
		}
	}

	let signature = signature.expect("Signing should succeed within 100 attempts");

	// Step 6: Verify signature with derived public key
	assert!(
		verify_signature(&derived_pubkey, message, context, &signature),
		"Signature should verify with derived public key"
	);

	// Verify signature does NOT verify with master public key
	assert!(
		!verify_signature(&master_pubkey, message, context, &signature),
		"Signature should NOT verify with master public key"
	);
}

/// Test that the same tweak always produces the same derived key
#[test]
fn test_derived_key_determinism() {
	let master_seed = [42u8; 32];
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let (_master_pubkey, master_shares) =
		generate_with_dealer(&master_seed, config).expect("master keygen");

	let tweak = derive_tweak("alice.near", "ethereum");

	// First derivation
	let contributions1: Vec<[u8; 32]> = master_shares
		.iter()
		.map(|share| derive_dkg_contribution(share, &tweak))
		.collect();

	// Second derivation (should be identical)
	let contributions2: Vec<[u8; 32]> = master_shares
		.iter()
		.map(|share| derive_dkg_contribution(share, &tweak))
		.collect();

	assert_eq!(contributions1, contributions2, "DKG contributions should be deterministic");

	// Derive keys with same seed should produce same result
	let mut derived_seed1 = [0u8; 32];
	for contribution in &contributions1 {
		for (i, byte) in contribution.iter().enumerate() {
			derived_seed1[i] ^= byte;
		}
	}

	let mut derived_seed2 = [0u8; 32];
	for contribution in &contributions2 {
		for (i, byte) in contribution.iter().enumerate() {
			derived_seed2[i] ^= byte;
		}
	}

	assert_eq!(derived_seed1, derived_seed2, "Derived seeds should be identical");

	let (derived_pubkey1, _) =
		generate_with_dealer(&derived_seed1, config).expect("derived keygen");
	let (derived_pubkey2, _) =
		generate_with_dealer(&derived_seed2, config).expect("derived keygen");

	assert_eq!(
		derived_pubkey1.as_bytes(),
		derived_pubkey2.as_bytes(),
		"Derived public keys should be identical"
	);
}

/// Test multiple derived keys for the same account
#[test]
fn test_multiple_derived_keys_per_account() {
	let master_seed = [42u8; 32];
	let config = ThresholdConfig::new(2, 3).expect("valid config");
	let (_master_pubkey, master_shares) =
		generate_with_dealer(&master_seed, config).expect("master keygen");

	let paths = ["ethereum", "bitcoin", "solana", "near"];
	let mut derived_pubkeys = Vec::new();

	for path in &paths {
		let tweak = derive_tweak("alice.near", path);

		// Derive contributions
		let contributions: Vec<[u8; 32]> = master_shares
			.iter()
			.map(|share| derive_dkg_contribution(share, &tweak))
			.collect();

		// Combine into seed
		let mut derived_seed = [0u8; 32];
		for contribution in &contributions {
			for (i, byte) in contribution.iter().enumerate() {
				derived_seed[i] ^= byte;
			}
		}

		// Generate derived key
		let (derived_pubkey, _) =
			generate_with_dealer(&derived_seed, config).expect("derived keygen");
		derived_pubkeys.push(derived_pubkey);
	}

	// Verify all derived keys are unique
	for i in 0..derived_pubkeys.len() {
		for j in (i + 1)..derived_pubkeys.len() {
			assert_ne!(
				derived_pubkeys[i].as_bytes(),
				derived_pubkeys[j].as_bytes(),
				"Derived keys for {} and {} should be different",
				paths[i],
				paths[j]
			);
		}
	}
}
