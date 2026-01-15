//! Integration tests for threshold ML-DSA implementation
//!
//! These tests validate the complete end-to-end threshold signature protocol
//! using the new ThresholdSigner API.

use std::time::{Duration, Instant};

use qp_rusty_crystals_threshold::{
	generate_with_dealer, keygen::dkg::run_local_dkg, verify_signature, ThresholdConfig,
	ThresholdSigner,
};

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
	data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Run the complete threshold signing protocol using the new API.
/// Returns Ok(signature_bytes) on success or Err(message) on failure.
fn run_threshold_protocol_new_api(
	threshold: u8,
	total_parties: u8,
	seed: &[u8; 32],
	message: &[u8],
	context: &[u8],
) -> Result<Vec<u8>, String> {
	let config = ThresholdConfig::new(threshold, total_parties)
		.map_err(|e| format!("Config error: {:?}", e))?;

	let (public_key, shares) =
		generate_with_dealer(seed, config).map_err(|e| format!("Key generation error: {:?}", e))?;

	// Create signers for the first `threshold` parties (active signers)
	let mut signers: Vec<ThresholdSigner> = shares
		.into_iter()
		.take(threshold as usize)
		.map(|share| ThresholdSigner::new(share, public_key.clone(), config))
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Signer creation error: {:?}", e))?;

	let mut rng = rand::thread_rng();

	// Round 1: All active parties generate commitments
	let r1_broadcasts: Vec<_> = signers
		.iter_mut()
		.map(|s| s.round1_commit(&mut rng))
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Round 1 error: {:?}", e))?;

	// Round 2: All active parties reveal their commitments
	let r2_broadcasts: Vec<_> = signers
		.iter_mut()
		.enumerate()
		.map(|(i, s)| {
			let others: Vec<_> =
				r1_broadcasts.iter().filter(|r| r.party_id != i as u8).cloned().collect();
			s.round2_reveal(message, context, &others)
		})
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Round 2 error: {:?}", e))?;

	// Round 3: All active parties compute their responses
	let r3_broadcasts: Vec<_> = signers
		.iter_mut()
		.enumerate()
		.map(|(i, s)| {
			let others: Vec<_> =
				r2_broadcasts.iter().filter(|r| r.party_id != i as u8).cloned().collect();
			s.round3_respond(&others)
		})
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Round 3 error: {:?}", e))?;

	// Combine: Any party can combine (we use party 0)
	let signature = signers[0]
		.combine(&r2_broadcasts, &r3_broadcasts)
		.map_err(|e| format!("Combine error: {:?}", e))?;

	// Verify the signature
	if !verify_signature(&public_key, message, context, &signature) {
		return Err("Signature verification failed".to_string());
	}

	Ok(signature.as_bytes().to_vec())
}

/// Run threshold signing protocol using DKG-generated keys.
fn run_threshold_protocol_with_dkg(
	threshold: u8,
	total_parties: u8,
	seed: &[u8; 32],
	message: &[u8],
	context: &[u8],
) -> Result<Vec<u8>, String> {
	let config = ThresholdConfig::new(threshold, total_parties)
		.map_err(|e| format!("Config error: {:?}", e))?;

	// Run DKG to generate keys
	let dkg_outputs = run_local_dkg(threshold, total_parties, *seed)
		.map_err(|e| format!("DKG error: {:?}", e))?;

	let public_key = dkg_outputs[0].public_key.clone();

	// Create signers for the first `threshold` parties (active signers)
	let mut signers: Vec<ThresholdSigner> = dkg_outputs
		.into_iter()
		.take(threshold as usize)
		.map(|output| ThresholdSigner::new(output.private_share, public_key.clone(), config))
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Signer creation error: {:?}", e))?;

	let mut rng = rand::thread_rng();

	// Round 1: All active parties generate commitments
	let r1_broadcasts: Vec<_> = signers
		.iter_mut()
		.map(|s| s.round1_commit(&mut rng))
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Round 1 error: {:?}", e))?;

	// Round 2: All active parties reveal their commitments
	let r2_broadcasts: Vec<_> = signers
		.iter_mut()
		.enumerate()
		.map(|(i, s)| {
			let others: Vec<_> =
				r1_broadcasts.iter().filter(|r| r.party_id != i as u8).cloned().collect();
			s.round2_reveal(message, context, &others)
		})
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Round 2 error: {:?}", e))?;

	// Round 3: All active parties compute their responses
	let r3_broadcasts: Vec<_> = signers
		.iter_mut()
		.enumerate()
		.map(|(i, s)| {
			let others: Vec<_> =
				r2_broadcasts.iter().filter(|r| r.party_id != i as u8).cloned().collect();
			s.round3_respond(&others)
		})
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Round 3 error: {:?}", e))?;

	// Combine: Any party can combine (we use party 0)
	let signature = signers[0]
		.combine(&r2_broadcasts, &r3_broadcasts)
		.map_err(|e| format!("Combine error: {:?}", e))?;

	// Verify the signature
	if !verify_signature(&public_key, message, context, &signature) {
		return Err("Signature verification failed".to_string());
	}

	Ok(signature.as_bytes().to_vec())
}

// ============================================================================
// Deterministic Tests (using fixed seeds - should always pass with retries)
// ============================================================================

#[test]
fn test_2_of_2_deterministic() {
	println!("\n=== 2-of-2 DETERMINISTIC TEST ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message = b"test message";
	let context: &[u8] = b"";

	let max_attempts = 50;
	for attempt in 0..max_attempts {
		match run_threshold_protocol_new_api(2, 2, &seed, message, context) {
			Ok(signature) => {
				println!(
					"✅ 2-of-2 deterministic: Signature created and verified on attempt {}!",
					attempt + 1
				);
				println!("   Signature length: {} bytes", signature.len());
				println!(
					"   Signature[0..32]: {}",
					hex_encode(&signature[..32.min(signature.len())])
				);
				return;
			},
			Err(e) =>
				if attempt < 5 || attempt % 10 == 0 {
					println!("   Attempt {} failed: {}", attempt + 1, e);
				},
		}
	}
	panic!("❌ 2-of-2 deterministic failed after {} attempts", max_attempts);
}

#[test]
fn test_2_of_3_deterministic() {
	println!("\n=== 2-of-3 DETERMINISTIC TEST ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message = b"test message for 2-of-3";
	let context: &[u8] = b"";

	let max_attempts = 100;
	for attempt in 0..max_attempts {
		match run_threshold_protocol_new_api(2, 3, &seed, message, context) {
			Ok(signature) => {
				println!(
					"✅ 2-of-3 deterministic: Signature created and verified on attempt {}!",
					attempt + 1
				);
				println!("   Signature length: {} bytes", signature.len());
				return;
			},
			Err(e) =>
				if attempt < 5 || attempt % 20 == 0 {
					println!("   Attempt {} failed: {}", attempt + 1, e);
				},
		}
	}
	panic!("❌ 2-of-3 deterministic failed after {} attempts", max_attempts);
}

#[test]
fn test_3_of_5_deterministic() {
	println!("\n=== 3-of-5 DETERMINISTIC TEST ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message = b"test message for 3-of-5";
	let context: &[u8] = b"";

	let max_attempts = 200;
	for attempt in 0..max_attempts {
		match run_threshold_protocol_new_api(3, 5, &seed, message, context) {
			Ok(signature) => {
				println!(
					"✅ 3-of-5 deterministic: Signature created and verified on attempt {}!",
					attempt + 1
				);
				println!("   Signature length: {} bytes", signature.len());
				return;
			},
			Err(e) =>
				if attempt < 5 || attempt % 20 == 0 {
					println!("   Attempt {} failed: {}", attempt + 1, e);
				},
		}
	}
	panic!("❌ 3-of-5 deterministic failed after {} attempts", max_attempts);
}

// ============================================================================
// Randomized Tests (using random seeds - may need retries due to rejection sampling)
// ============================================================================

#[test]
fn test_2_of_2_random() {
	println!("\n=== 2-of-2 RANDOM TEST ===\n");

	use rand::RngCore;

	let max_attempts = 10;

	for attempt in 1..=max_attempts {
		let mut seed = [0u8; 32];
		rand::thread_rng().fill_bytes(&mut seed);

		let message = b"random test message";
		let context: &[u8] = b"";

		match run_threshold_protocol_new_api(2, 2, &seed, message, context) {
			Ok(signature) => {
				println!(
					"✅ 2-of-2 random: Signature created and verified on attempt {}!",
					attempt
				);
				println!("   Signature length: {} bytes", signature.len());
				return;
			},
			Err(e) => {
				println!("   Attempt {} failed: {}", attempt, e);
			},
		}
	}

	panic!("❌ 2-of-2 random failed after {} attempts", max_attempts);
}

#[test]
fn test_2_of_3_random() {
	println!("\n=== 2-of-3 RANDOM TEST ===\n");

	use rand::RngCore;

	let max_attempts = 10;

	for attempt in 1..=max_attempts {
		let mut seed = [0u8; 32];
		rand::thread_rng().fill_bytes(&mut seed);

		let message = b"random test message for 2-of-3";
		let context: &[u8] = b"";

		match run_threshold_protocol_new_api(2, 3, &seed, message, context) {
			Ok(signature) => {
				println!(
					"✅ 2-of-3 random: Signature created and verified on attempt {}!",
					attempt
				);
				println!("   Signature length: {} bytes", signature.len());
				return;
			},
			Err(e) => {
				println!("   Attempt {} failed: {}", attempt, e);
			},
		}
	}

	panic!("❌ 2-of-3 random failed after {} attempts", max_attempts);
}

#[test]
fn test_3_of_5_random() {
	println!("\n=== 3-of-5 RANDOM TEST ===\n");

	use rand::RngCore;

	// 3-of-5 has lower success probability, need more attempts
	let max_attempts = 50;

	for attempt in 1..=max_attempts {
		let mut seed = [0u8; 32];
		rand::thread_rng().fill_bytes(&mut seed);

		let message = b"random test message for 3-of-5";
		let context: &[u8] = b"";

		match run_threshold_protocol_new_api(3, 5, &seed, message, context) {
			Ok(signature) => {
				println!(
					"✅ 3-of-5 random: Signature created and verified on attempt {}!",
					attempt
				);
				println!("   Signature length: {} bytes", signature.len());
				return;
			},
			Err(e) => {
				println!("   Attempt {} failed: {}", attempt, e);
			},
		}
	}

	panic!("❌ 3-of-5 random failed after {} attempts", max_attempts);
}

// ============================================================================
// Context and Message Variation Tests
// ============================================================================

#[test]
fn test_with_context() {
	println!("\n=== TEST WITH CONTEXT ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message = b"message with context";
	let context = b"my-application-context";

	let max_attempts = 50;
	for _attempt in 0..max_attempts {
		match run_threshold_protocol_new_api(2, 2, &seed, message, context) {
			Ok(signature) => {
				println!("✅ With context: Signature created and verified!");
				println!("   Context: {:?}", String::from_utf8_lossy(context));
				println!("   Signature length: {} bytes", signature.len());
				return;
			},
			Err(_) => continue,
		}
	}
	panic!("❌ With context test failed after {} attempts", max_attempts);
}

#[test]
fn test_empty_message() {
	println!("\n=== TEST EMPTY MESSAGE ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message: &[u8] = b"";
	let context: &[u8] = b"";

	let max_attempts = 50;
	for _attempt in 0..max_attempts {
		match run_threshold_protocol_new_api(2, 2, &seed, message, context) {
			Ok(signature) => {
				println!("✅ Empty message: Signature created and verified!");
				println!("   Signature length: {} bytes", signature.len());
				return;
			},
			Err(_) => continue,
		}
	}
	panic!("❌ Empty message test failed after {} attempts", max_attempts);
}

#[test]
fn test_long_message() {
	println!("\n=== TEST LONG MESSAGE ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	// Create a 10KB message
	let message: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();
	let context: &[u8] = b"";

	let max_attempts = 50;
	for _attempt in 0..max_attempts {
		match run_threshold_protocol_new_api(2, 2, &seed, &message, context) {
			Ok(signature) => {
				println!("✅ Long message (10KB): Signature created and verified!");
				println!("   Message length: {} bytes", message.len());
				println!("   Signature length: {} bytes", signature.len());
				return;
			},
			Err(_) => continue,
		}
	}
	panic!("❌ Long message test failed after {} attempts", max_attempts);
}

// ============================================================================
// Verification Tests
// ============================================================================

#[test]
fn test_signature_verification_with_wrong_message() {
	println!("\n=== TEST WRONG MESSAGE VERIFICATION ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let config = ThresholdConfig::new(2, 2).expect("Valid config");
	let (public_key, _) = generate_with_dealer(&seed, config).expect("Key gen");

	let message = b"original message";
	let context: &[u8] = b"";

	// Get a valid signature first
	let max_attempts = 50;
	let mut signature = None;
	for _ in 0..max_attempts {
		if let Ok(sig) = run_threshold_protocol_new_api(2, 2, &seed, message, context) {
			signature = Some(sig);
			break;
		}
	}

	let signature = signature.expect("Should get a valid signature");
	let sig = qp_rusty_crystals_threshold::Signature::from_bytes(&signature)
		.expect("Valid signature bytes");

	// Verify with wrong message should fail
	let wrong_message = b"wrong message";
	let is_valid = verify_signature(&public_key, wrong_message, context, &sig);

	if is_valid {
		panic!("❌ Signature should NOT verify with wrong message!");
	} else {
		println!("✅ Correctly rejected signature with wrong message");
	}
}

#[test]
fn test_signature_verification_with_wrong_context() {
	println!("\n=== TEST WRONG CONTEXT VERIFICATION ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let config = ThresholdConfig::new(2, 2).expect("Valid config");
	let (public_key, _) = generate_with_dealer(&seed, config).expect("Key gen");

	let message = b"test message";
	let context = b"correct-context";

	// Get a valid signature first
	let max_attempts = 50;
	let mut signature = None;
	for _ in 0..max_attempts {
		if let Ok(sig) = run_threshold_protocol_new_api(2, 2, &seed, message, context) {
			signature = Some(sig);
			break;
		}
	}

	let signature = signature.expect("Should get a valid signature");
	let sig = qp_rusty_crystals_threshold::Signature::from_bytes(&signature)
		.expect("Valid signature bytes");

	// Verify with wrong context should fail
	let wrong_context = b"wrong-context";
	let is_valid = verify_signature(&public_key, message, wrong_context, &sig);

	if is_valid {
		panic!("❌ Signature should NOT verify with wrong context!");
	} else {
		println!("✅ Correctly rejected signature with wrong context");
	}
}

// ============================================================================
// Comprehensive Matrix Test
// ============================================================================

#[test]
fn test_threshold_matrix() {
	println!("\n=== THRESHOLD MATRIX TEST (Dealer) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message = b"matrix test message";
	let context: &[u8] = b"";

	// Test configurations: (threshold, total_parties, max_attempts)
	// max_attempts is the number of full protocol retries
	// k_iterations (from config) is parallel attempts within each protocol run
	let configs: [(u8, u8, u32); 21] = [
		// n = 2
		(2, 2, 50),
		// n = 3
		(2, 3, 100),
		(3, 3, 150),
		// n = 4
		(2, 4, 100),
		(3, 4, 200),
		(4, 4, 250),
		// n = 5
		(2, 5, 100),
		(3, 5, 300),
		(4, 5, 500),
		(5, 5, 400),
		// n = 6
		(2, 6, 100),
		(3, 6, 400),
		(4, 6, 700),
		(5, 6, 800),
		(6, 6, 600),
		// n = 7 (EXPERIMENTAL - k_iterations are estimates)
		(2, 7, 200),
		(3, 7, 500),
		(4, 7, 1000),
		(5, 7, 1500),
		(6, 7, 1200),
		(7, 7, 800),
	];

	let mut passed = 0;
	let mut failed = 0;
	let mut total_time = Duration::ZERO;

	for (threshold, total_parties, max_attempts) in configs.iter() {
		let start = Instant::now();
		let mut success = false;
		let mut final_attempt = 0;

		for attempt in 0..(*max_attempts) {
			// let attempt_start = Instant::now();
			match run_threshold_protocol_new_api(
				*threshold,
				*total_parties,
				&seed,
				message,
				context,
			) {
				Ok(_) => {
					final_attempt = attempt + 1;
					success = true;
					break;
				},
				Err(_e) => {
					// Log every 10th attempt or first few
					// if attempt < 5 || attempt % 10 == 0 {
					//     println!(
					//         "  {}-of-{} attempt {} failed in {:.2?}: {:?}",
					//         threshold, total_parties, attempt + 1, attempt_start.elapsed(), e
					//     );
					// }
				},
			}
		}

		let elapsed = start.elapsed();
		total_time += elapsed;

		if success {
			println!(
				"✅ {}-of-{}: PASSED (attempt {}, {:.2?})",
				threshold, total_parties, final_attempt, elapsed
			);
			passed += 1;
		} else {
			println!(
				"❌ {}-of-{}: FAILED after {} attempts ({:.2?})",
				threshold, total_parties, max_attempts, elapsed
			);
			failed += 1;
		}
	}

	println!("\n=== MATRIX RESULTS ===");
	println!("Passed: {}", passed);
	println!("Failed: {}", failed);
	println!("Total time: {:.2?}", total_time);

	assert_eq!(failed, 0, "Some threshold configurations failed");
}

/// Test threshold signing with DKG-generated keys across multiple configurations.
#[test]
fn test_threshold_matrix_dkg() {
	println!("\n=== THRESHOLD MATRIX TEST (DKG) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = (i as u8).wrapping_add(100); // Different seed than dealer test
	}

	let message = b"matrix test message with dkg";
	let context: &[u8] = b"";

	// Test configurations: (threshold, total_parties, max_attempts)
	// Using same configs as dealer test
	let configs: [(u8, u8, u32); 21] = [
		// n = 2
		(2, 2, 50),
		// n = 3
		(2, 3, 100),
		(3, 3, 150),
		// n = 4
		(2, 4, 100),
		(3, 4, 200),
		(4, 4, 250),
		// n = 5
		(2, 5, 100),
		(3, 5, 300),
		(4, 5, 500),
		(5, 5, 400),
		// n = 6
		(2, 6, 100),
		(3, 6, 400),
		(4, 6, 700),
		(5, 6, 800),
		(6, 6, 600),
		// n = 7 (EXPERIMENTAL - k_iterations are estimates)
		(2, 7, 200),
		(3, 7, 500),
		(4, 7, 1000),
		(5, 7, 1500),
		(6, 7, 1200),
		(7, 7, 800),
	];

	let mut passed = 0;
	let mut failed = 0;
	let mut total_time = Duration::ZERO;

	for (threshold, total_parties, max_attempts) in configs.iter() {
		let start = Instant::now();
		let mut success = false;
		let mut final_attempt = 0;

		for attempt in 0..(*max_attempts) {
			match run_threshold_protocol_with_dkg(
				*threshold,
				*total_parties,
				&seed,
				message,
				context,
			) {
				Ok(_) => {
					final_attempt = attempt + 1;
					success = true;
					break;
				},
				Err(_e) => {
					// Rejection sampling may require multiple attempts
				},
			}
		}

		let elapsed = start.elapsed();
		total_time += elapsed;

		if success {
			println!(
				"✅ {}-of-{}: PASSED (attempt {}, {:.2?})",
				threshold, total_parties, final_attempt, elapsed
			);
			passed += 1;
		} else {
			println!(
				"❌ {}-of-{}: FAILED after {} attempts ({:.2?})",
				threshold, total_parties, max_attempts, elapsed
			);
			failed += 1;
		}
	}

	println!("\n=== DKG MATRIX RESULTS ===");
	println!("Passed: {}", passed);
	println!("Failed: {}", failed);
	println!("Total time: {:.2?}", total_time);

	assert_eq!(failed, 0, "Some threshold configurations failed with DKG");
}

/// Test that configuration validation works for n up to 7
#[test]
fn test_config_validation_extended() {
	use qp_rusty_crystals_threshold::ThresholdConfig;

	// All these should succeed (n <= 7)
	let valid_configs = [(2, 7), (7, 7)];

	for (t, n) in valid_configs {
		let result = ThresholdConfig::new(t, n);
		assert!(
			result.is_ok(),
			"Config ({}, {}) should be valid but got error: {:?}",
			t,
			n,
			result.err()
		);
	}

	// n = 8 should fail
	let result = ThresholdConfig::new(2, 8);
	assert!(result.is_err(), "Config (2, 8) should be invalid");
}

/// Test key generation with extended party counts
#[test]
fn test_keygen_extended() {
	use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig};

	let seed = [42u8; 32];

	// Test extended configurations (n = 7)
	let configs = [(2, 7), (4, 7), (7, 7)];

	for (t, n) in configs {
		let config = ThresholdConfig::new(t, n).expect("Config should be valid");
		let result = generate_with_dealer(&seed, config);

		assert!(
			result.is_ok(),
			"Key generation for ({}, {}) should succeed: {:?}",
			t,
			n,
			result.err()
		);

		let (public_key, shares) = result.unwrap();

		assert_eq!(shares.len(), n as usize, "Should have {} shares", n);
		assert!(!public_key.as_bytes().is_empty(), "Public key should not be empty");

		for (i, share) in shares.iter().enumerate() {
			assert_eq!(share.party_id(), i as u8);
			assert_eq!(share.threshold(), t);
			assert_eq!(share.total_parties(), n);
		}
	}
}

// ============================================================================
// Subset Signing Tests
// ============================================================================

/// Run threshold signing with a SUBSET of DKG participants.
/// This tests the core subset signing feature needed for NEAR MPC integration.
///
/// # Arguments
/// * `dkg_threshold` - The threshold from DKG (t)
/// * `dkg_total` - Total parties from DKG (n)
/// * `signing_parties` - Which party IDs participate in signing (must be >= threshold)
fn run_subset_signing(
	dkg_threshold: u8,
	dkg_total: u8,
	signing_parties: &[u8],
	seed: &[u8; 32],
	message: &[u8],
	context: &[u8],
) -> Result<Vec<u8>, String> {
	// Create DKG config
	let dkg_config = ThresholdConfig::new(dkg_threshold, dkg_total)
		.map_err(|e| format!("DKG config error: {:?}", e))?;

	// Generate keys for all n parties
	let (public_key, all_shares) = generate_with_dealer(seed, dkg_config)
		.map_err(|e| format!("Key generation error: {:?}", e))?;

	// Create signing config with the actual number of signing parties
	// This is the key change: total_parties in signing config is the subset size,
	// but we use the DKG threshold
	let signing_total = signing_parties.len() as u8;
	let signing_config = ThresholdConfig::new(dkg_threshold, signing_total)
		.map_err(|e| format!("Signing config error: {:?}", e))?;

	// Select only the signing parties' shares
	let signing_shares: Vec<_> =
		signing_parties.iter().map(|&id| all_shares[id as usize].clone()).collect();

	// Create signers for the signing subset
	let mut signers: Vec<ThresholdSigner> = signing_shares
		.into_iter()
		.map(|share| ThresholdSigner::new(share, public_key.clone(), signing_config))
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Signer creation error: {:?}", e))?;

	let mut rng = rand::thread_rng();

	// Round 1: All signing parties generate commitments
	let r1_broadcasts: Vec<_> = signers
		.iter_mut()
		.map(|s| s.round1_commit(&mut rng))
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Round 1 error: {:?}", e))?;

	// Round 2: All signing parties reveal their commitments
	// Note: party_id in broadcasts is the ORIGINAL DKG party ID
	let r2_broadcasts: Vec<_> = signers
		.iter_mut()
		.enumerate()
		.map(|(i, s)| {
			let my_party_id = signing_parties[i];
			let others: Vec<_> =
				r1_broadcasts.iter().filter(|r| r.party_id != my_party_id).cloned().collect();
			s.round2_reveal(message, context, &others)
		})
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Round 2 error: {:?}", e))?;

	// Round 3: All signing parties compute their responses
	let r3_broadcasts: Vec<_> = signers
		.iter_mut()
		.enumerate()
		.map(|(i, s)| {
			let my_party_id = signing_parties[i];
			let others: Vec<_> =
				r2_broadcasts.iter().filter(|r| r.party_id != my_party_id).cloned().collect();
			s.round3_respond(&others)
		})
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Round 3 error: {:?}", e))?;

	// Combine: First signer combines
	let signature = signers[0]
		.combine(&r2_broadcasts, &r3_broadcasts)
		.map_err(|e| format!("Combine error: {:?}", e))?;

	// Verify the signature
	if !verify_signature(&public_key, message, context, &signature) {
		return Err("Signature verification failed".to_string());
	}

	Ok(signature.as_bytes().to_vec())
}

/// Test subset signing: 3 parties sign from 4-party DKG (parties 0, 1, 2)
#[test]
fn test_subset_signing_3_of_4_consecutive() {
	println!("\n=== SUBSET SIGNING TEST: 3 from 4 (consecutive) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = (i as u8).wrapping_add(50);
	}

	let message = b"subset signing test";
	let context: &[u8] = b"";

	// DKG with 4 parties, threshold 3
	// Sign with parties 0, 1, 2 (skip party 3)
	let signing_parties = [0u8, 1, 2];

	let max_attempts = 200;
	for attempt in 0..max_attempts {
		match run_subset_signing(3, 4, &signing_parties, &seed, message, context) {
			Ok(signature) => {
				println!(
					"✅ Subset signing (3 from 4, consecutive): Success on attempt {}!",
					attempt + 1
				);
				println!("   Signature length: {} bytes", signature.len());
				return;
			},
			Err(e) =>
				if attempt < 5 || attempt % 50 == 0 {
					println!("   Attempt {} failed: {}", attempt + 1, e);
				},
		}
	}
	panic!("❌ Subset signing (3 from 4, consecutive) failed after {} attempts", max_attempts);
}

/// Test subset signing: 3 parties sign from 4-party DKG (parties 0, 1, 3 - skipping party 2)
#[test]
fn test_subset_signing_3_of_4_non_consecutive() {
	println!("\n=== SUBSET SIGNING TEST: 3 from 4 (non-consecutive) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = (i as u8).wrapping_add(60);
	}

	let message = b"subset signing test non-consecutive";
	let context: &[u8] = b"";

	// DKG with 4 parties, threshold 3
	// Sign with parties 0, 1, 3 (skip party 2)
	let signing_parties = [0u8, 1, 3];

	let max_attempts = 200;
	for attempt in 0..max_attempts {
		match run_subset_signing(3, 4, &signing_parties, &seed, message, context) {
			Ok(signature) => {
				println!(
					"✅ Subset signing (3 from 4, non-consecutive): Success on attempt {}!",
					attempt + 1
				);
				println!("   Signature length: {} bytes", signature.len());
				return;
			},
			Err(e) =>
				if attempt < 5 || attempt % 50 == 0 {
					println!("   Attempt {} failed: {}", attempt + 1, e);
				},
		}
	}
	panic!("❌ Subset signing (3 from 4, non-consecutive) failed after {} attempts", max_attempts);
}

/// Test subset signing: 3 parties sign from 5-party DKG
#[test]
fn test_subset_signing_3_of_5() {
	println!("\n=== SUBSET SIGNING TEST: 3 from 5 ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = (i as u8).wrapping_add(70);
	}

	let message = b"subset signing test 3 of 5";
	let context: &[u8] = b"";

	// DKG with 5 parties, threshold 3
	// Sign with parties 0, 2, 4 (skipping parties 1 and 3)
	let signing_parties = [0u8, 2, 4];

	let max_attempts = 300;
	for attempt in 0..max_attempts {
		match run_subset_signing(3, 5, &signing_parties, &seed, message, context) {
			Ok(signature) => {
				println!("✅ Subset signing (3 from 5): Success on attempt {}!", attempt + 1);
				println!("   Signature length: {} bytes", signature.len());
				return;
			},
			Err(e) =>
				if attempt < 5 || attempt % 50 == 0 {
					println!("   Attempt {} failed: {}", attempt + 1, e);
				},
		}
	}
	panic!("❌ Subset signing (3 from 5) failed after {} attempts", max_attempts);
}

/// Test that validation correctly rejects invalid subset configurations
#[test]
fn test_subset_signing_validation() {
	println!("\n=== SUBSET SIGNING VALIDATION TEST ===\n");

	let seed = [42u8; 32];

	// Generate 4-party DKG with threshold 3
	let dkg_config = ThresholdConfig::new(3, 4).expect("Valid DKG config");
	let (public_key, all_shares) = generate_with_dealer(&seed, dkg_config).expect("Key generation");

	// Test 1: Creating signer with fewer than threshold parties should fail
	// Config with total_parties=2 but threshold=3 should be rejected
	let invalid_config = ThresholdConfig::new(3, 2);
	assert!(invalid_config.is_err(), "Config with total_parties < threshold should fail");

	// Test 2: Creating signer with more parties than DKG should fail
	// Config with total_parties=5 but keyshare has total_parties=4
	let oversized_config = ThresholdConfig::new(3, 5).expect("Config itself is valid");
	let result = ThresholdSigner::new(all_shares[0].clone(), public_key.clone(), oversized_config);
	assert!(result.is_err(), "Signer with more parties than DKG should fail");
	if let Err(e) = result {
		println!("✅ Correctly rejected oversized config: {:?}", e);
	}

	// Test 3: Creating signer with exactly threshold parties should succeed
	let valid_config = ThresholdConfig::new(3, 3).expect("Valid config");
	let result = ThresholdSigner::new(all_shares[0].clone(), public_key.clone(), valid_config);
	assert!(result.is_ok(), "Signer with exactly threshold parties should succeed");
	println!("✅ Correctly accepted signing config with {} parties", valid_config.total_parties());

	// Test 4: Creating signer with full DKG party count should succeed
	let full_config = ThresholdConfig::new(3, 4).expect("Valid config");
	let result = ThresholdSigner::new(all_shares[0].clone(), public_key.clone(), full_config);
	assert!(result.is_ok(), "Signer with full DKG party count should succeed");
	println!(
		"✅ Correctly accepted signing config with {} parties (full DKG)",
		full_config.total_parties()
	);
}
