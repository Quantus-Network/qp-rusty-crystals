//! Integration tests for threshold ML-DSA implementation.
//!
//! These tests validate the complete end-to-end threshold signature protocol
//! using the `ThresholdSigner` API with leader-based retry.

use std::time::{Duration, Instant};

use qp_rusty_crystals_threshold::{
	generate_with_dealer,
	keygen::dkg::run_local_dkg,
	signing_protocol::{run_local_signing, run_local_signing_with_stats},
	verify_signature, ThresholdConfig, ThresholdSigner,
};

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
	data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Run the complete threshold signing protocol using the 4-round protocol with leader-based retry.
/// Returns Ok(signature_bytes) on success or Err(message) on failure.
fn run_threshold_protocol_4_round(
	threshold: u32,
	total_parties: u32,
	seed: &[u8; 32],
	message: &[u8],
	context: &[u8],
) -> Result<Vec<u8>, String> {
	let config = ThresholdConfig::new(threshold, total_parties)
		.map_err(|e| format!("Config error: {:?}", e))?;

	let (public_key, shares) =
		generate_with_dealer(seed, config).map_err(|e| format!("Key generation error: {:?}", e))?;

	// Create signers for the first `threshold` parties (active signers)
	let signers: Vec<ThresholdSigner> = shares
		.into_iter()
		.take(threshold as usize)
		.map(|share| ThresholdSigner::new(share, public_key.clone(), config))
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Signer creation error: {:?}", e))?;

	// Run the 4-round signing protocol with leader-based retry
	let signature = run_local_signing(signers, message, context)
		.map_err(|e| format!("Signing error: {:?}", e))?;

	// Verify the signature
	if !verify_signature(&public_key, message, context, &signature) {
		return Err("Signature verification failed".to_string());
	}

	Ok(signature.as_bytes().to_vec())
}

// ============================================================================
// Deterministic Tests (using fixed seeds - 4-round protocol handles retries)
// ============================================================================

#[test]
fn test_2_of_2_deterministic() {
	println!("\n=== 2-of-2 DETERMINISTIC TEST (4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message = b"test message";
	let context: &[u8] = b"";

	let start = Instant::now();
	match run_threshold_protocol_4_round(2, 2, &seed, message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ 2-of-2 deterministic: Signature created and verified!");
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
			println!("   Signature[0..32]: {}", hex_encode(&signature[..32.min(signature.len())]));
		},
		Err(e) => {
			panic!("❌ 2-of-2 deterministic failed: {}", e);
		},
	}
}

#[test]
fn test_2_of_3_deterministic() {
	println!("\n=== 2-of-3 DETERMINISTIC TEST (4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message = b"test message for 2-of-3";
	let context: &[u8] = b"";

	let start = Instant::now();
	match run_threshold_protocol_4_round(2, 3, &seed, message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ 2-of-3 deterministic: Signature created and verified!");
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
		},
		Err(e) => {
			panic!("❌ 2-of-3 deterministic failed: {}", e);
		},
	}
}

#[test]
fn test_3_of_5_deterministic() {
	println!("\n=== 3-of-5 DETERMINISTIC TEST (4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message = b"test message for 3-of-5";
	let context: &[u8] = b"";

	let start = Instant::now();
	match run_threshold_protocol_4_round(3, 5, &seed, message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ 3-of-5 deterministic: Signature created and verified!");
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
		},
		Err(e) => {
			panic!("❌ 3-of-5 deterministic failed: {}", e);
		},
	}
}

// ============================================================================
// Randomized Tests (using random seeds - 4-round protocol handles retries)
// ============================================================================

#[test]
fn test_2_of_2_random() {
	println!("\n=== 2-of-2 RANDOM TEST (4-Round Protocol) ===\n");

	use rand::RngCore;

	let mut seed = [0u8; 32];
	rand::thread_rng().fill_bytes(&mut seed);

	let message = b"random test message";
	let context: &[u8] = b"";

	let start = Instant::now();
	match run_threshold_protocol_4_round(2, 2, &seed, message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ 2-of-2 random: Signature created and verified!");
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
		},
		Err(e) => {
			panic!("❌ 2-of-2 random failed: {}", e);
		},
	}
}

#[test]
fn test_2_of_3_random() {
	println!("\n=== 2-of-3 RANDOM TEST (4-Round Protocol) ===\n");

	use rand::RngCore;

	let mut seed = [0u8; 32];
	rand::thread_rng().fill_bytes(&mut seed);

	let message = b"random test message for 2-of-3";
	let context: &[u8] = b"";

	let start = Instant::now();
	match run_threshold_protocol_4_round(2, 3, &seed, message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ 2-of-3 random: Signature created and verified!");
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
		},
		Err(e) => {
			panic!("❌ 2-of-3 random failed: {}", e);
		},
	}
}

#[test]
fn test_3_of_5_random() {
	println!("\n=== 3-of-5 RANDOM TEST (4-Round Protocol) ===\n");

	use rand::RngCore;

	let mut seed = [0u8; 32];
	rand::thread_rng().fill_bytes(&mut seed);

	let message = b"random test message for 3-of-5";
	let context: &[u8] = b"";

	let start = Instant::now();
	match run_threshold_protocol_4_round(3, 5, &seed, message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ 3-of-5 random: Signature created and verified!");
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
		},
		Err(e) => {
			panic!("❌ 3-of-5 random failed: {}", e);
		},
	}
}

// ============================================================================
// Context and Message Variation Tests
// ============================================================================

#[test]
fn test_with_context() {
	println!("\n=== TEST WITH CONTEXT (4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message = b"message with context";
	let context = b"my-application-context";

	let start = Instant::now();
	match run_threshold_protocol_4_round(2, 2, &seed, message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ With context: Signature created and verified!");
			println!("   Context: {:?}", String::from_utf8_lossy(context));
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
		},
		Err(e) => {
			panic!("❌ With context test failed: {}", e);
		},
	}
}

#[test]
fn test_empty_message() {
	println!("\n=== TEST EMPTY MESSAGE (4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message: &[u8] = b"";
	let context: &[u8] = b"";

	let start = Instant::now();
	match run_threshold_protocol_4_round(2, 2, &seed, message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ Empty message: Signature created and verified!");
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
		},
		Err(e) => {
			panic!("❌ Empty message test failed: {}", e);
		},
	}
}

#[test]
fn test_long_message() {
	println!("\n=== TEST LONG MESSAGE (4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	// Create a 10KB message
	let message: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();
	let context: &[u8] = b"";

	let start = Instant::now();
	match run_threshold_protocol_4_round(2, 2, &seed, &message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ Long message (10KB): Signature created and verified!");
			println!("   Message length: {} bytes", message.len());
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
		},
		Err(e) => {
			panic!("❌ Long message test failed: {}", e);
		},
	}
}

// ============================================================================
// Verification Tests
// ============================================================================

#[test]
fn test_signature_verification_with_wrong_message() {
	println!("\n=== TEST WRONG MESSAGE VERIFICATION (4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let config = ThresholdConfig::new(2, 2).expect("Valid config");
	let (public_key, _) = generate_with_dealer(&seed, config).expect("Key gen");

	let message = b"original message";
	let context: &[u8] = b"";

	// Get a valid signature using 4-round protocol
	let signature = run_threshold_protocol_4_round(2, 2, &seed, message, context)
		.expect("Should get a valid signature");
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
	println!("\n=== TEST WRONG CONTEXT VERIFICATION (4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let config = ThresholdConfig::new(2, 2).expect("Valid config");
	let (public_key, _) = generate_with_dealer(&seed, config).expect("Key gen");

	let message = b"test message";
	let context = b"correct-context";

	// Get a valid signature using 4-round protocol
	let signature = run_threshold_protocol_4_round(2, 2, &seed, message, context)
		.expect("Should get a valid signature");
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
	println!("\n=== THRESHOLD MATRIX TEST (Dealer + 4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message = b"matrix test message";
	let context: &[u8] = b"";

	// Test configurations: (threshold, total_parties)
	// The 4-round protocol with leader-based retry handles rejection sampling internally,
	// so we no longer need external max_attempts loops.
	let configs: [(u32, u32); 21] = [
		// n = 2
		(2, 2),
		// n = 3
		(2, 3),
		(3, 3),
		// n = 4
		(2, 4),
		(3, 4),
		(4, 4),
		// n = 5
		(2, 5),
		(3, 5),
		(4, 5),
		(5, 5),
		// n = 6
		(2, 6),
		(3, 6),
		(4, 6),
		(5, 6),
		(6, 6),
		// n = 7 (EXPERIMENTAL - k_iterations are estimates)
		(2, 7),
		(3, 7),
		(4, 7),
		(5, 7),
		(6, 7),
		(7, 7),
	];

	let mut passed = 0;
	let mut failed = 0;
	let mut total_time = Duration::ZERO;
	let mut total_retries = 0u32;
	let mut max_retries = 0u32;

	println!("{:<10} {:<10} {:<10} {:<10}", "Config", "Status", "Time", "Retries");
	println!("{}", "-".repeat(45));

	for (threshold, total_parties) in configs.iter() {
		let start = Instant::now();

		// Generate keys with dealer
		let config = match ThresholdConfig::new(*threshold, *total_parties) {
			Ok(c) => c,
			Err(e) => {
				println!("❌ {}-of-{}: Config error: {:?}", threshold, total_parties, e);
				failed += 1;
				continue;
			},
		};

		let (public_key, shares) = match generate_with_dealer(&seed, config) {
			Ok(result) => result,
			Err(e) => {
				println!("❌ {}-of-{}: Keygen error: {:?}", threshold, total_parties, e);
				failed += 1;
				continue;
			},
		};

		// Create signers for threshold parties
		let signers: Vec<ThresholdSigner> = match shares
			.into_iter()
			.take(*threshold as usize)
			.map(|share| ThresholdSigner::new(share, public_key.clone(), config))
			.collect::<Result<Vec<_>, _>>()
		{
			Ok(s) => s,
			Err(e) => {
				println!("❌ {}-of-{}: Signer creation error: {:?}", threshold, total_parties, e);
				failed += 1;
				continue;
			},
		};

		// Run the 4-round signing protocol with leader-based retry
		match run_local_signing_with_stats(signers, message, context) {
			Ok((signature, stats)) => {
				// Verify the signature
				if verify_signature(&public_key, message, context, &signature) {
					let elapsed = start.elapsed();
					total_time += elapsed;
					total_retries += stats.retry_count;
					if stats.retry_count > max_retries {
						max_retries = stats.retry_count;
					}
					println!(
						"{:<10} {:<10} {:<10} {:<10}",
						format!("{}-of-{}", threshold, total_parties),
						"✅ PASSED",
						format!("{:.2?}", elapsed),
						stats.retry_count
					);
					passed += 1;
				} else {
					println!(
						"{:<10} {:<10} {:<10} {:<10}",
						format!("{}-of-{}", threshold, total_parties),
						"❌ VERIFY",
						"-",
						"-"
					);
					failed += 1;
				}
			},
			Err(e) => {
				let elapsed = start.elapsed();
				total_time += elapsed;
				println!(
					"{:<10} {:<10} {:<10} {:<10}",
					format!("{}-of-{}", threshold, total_parties),
					"❌ ERROR",
					format!("{:.2?}", elapsed),
					format!("{:?}", e)
				);
				failed += 1;
			},
		}
	}

	println!("\n=== MATRIX RESULTS ===");
	println!("Passed: {}", passed);
	println!("Failed: {}", failed);
	println!("Total time: {:.2?}", total_time);
	println!("Total retries: {}", total_retries);
	println!("Max retries (single config): {}", max_retries);
	if passed > 0 {
		println!("Avg retries per config: {:.2}", total_retries as f64 / passed as f64);
	}

	assert_eq!(failed, 0, "Some threshold configurations failed");
}

/// Test threshold signing with DKG-generated keys across multiple configurations.
#[test]
fn test_threshold_matrix_dkg() {
	println!("\n=== THRESHOLD MATRIX TEST (DKG + 4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = i as u8;
	}

	let message = b"DKG matrix test message";
	let context: &[u8] = b"dkg-test";

	// Test configurations: (threshold, total_parties)
	// The 4-round protocol with leader-based retry handles rejection sampling internally.
	let configs: [(u32, u32); 21] = [
		// n = 2
		(2, 2),
		// n = 3
		(2, 3),
		(3, 3),
		// n = 4
		(2, 4),
		(3, 4),
		(4, 4),
		// n = 5
		(2, 5),
		(3, 5),
		(4, 5),
		(5, 5),
		// n = 6
		(2, 6),
		(3, 6),
		(4, 6),
		(5, 6),
		(6, 6),
		// n = 7 (EXPERIMENTAL - k_iterations are estimates)
		(2, 7),
		(3, 7),
		(4, 7),
		(5, 7),
		(6, 7),
		(7, 7),
	];

	let mut passed = 0;
	let mut failed = 0;
	let mut total_time = Duration::ZERO;
	let mut total_retries = 0u32;
	let mut max_retries = 0u32;

	println!("{:<10} {:<10} {:<10} {:<10}", "Config", "Status", "Time", "Retries");
	println!("{}", "-".repeat(45));

	for (threshold, total_parties) in configs.iter() {
		let start = Instant::now();

		// Run DKG to generate keys
		let dkg_outputs = match run_local_dkg(*threshold, *total_parties, seed) {
			Ok(outputs) => outputs,
			Err(e) => {
				println!("❌ {}-of-{}: DKG error: {:?}", threshold, total_parties, e);
				failed += 1;
				continue;
			},
		};

		// Extract public key and create signers
		let public_key = dkg_outputs[0].public_key.clone();
		let config = match ThresholdConfig::new(*threshold, *total_parties) {
			Ok(c) => c,
			Err(e) => {
				println!("❌ {}-of-{}: Config error: {:?}", threshold, total_parties, e);
				failed += 1;
				continue;
			},
		};

		// Create signers for threshold parties
		let signers: Vec<ThresholdSigner> = match dkg_outputs
			.into_iter()
			.take(*threshold as usize)
			.map(|output| ThresholdSigner::new(output.private_share, public_key.clone(), config))
			.collect::<Result<Vec<_>, _>>()
		{
			Ok(s) => s,
			Err(e) => {
				println!("❌ {}-of-{}: Signer creation error: {:?}", threshold, total_parties, e);
				failed += 1;
				continue;
			},
		};

		// Run the 4-round signing protocol with leader-based retry
		match run_local_signing_with_stats(signers, message, context) {
			Ok((signature, stats)) => {
				// Verify the signature
				if verify_signature(&public_key, message, context, &signature) {
					let elapsed = start.elapsed();
					total_time += elapsed;
					total_retries += stats.retry_count;
					if stats.retry_count > max_retries {
						max_retries = stats.retry_count;
					}
					println!(
						"{:<10} {:<10} {:<10} {:<10}",
						format!("{}-of-{}", threshold, total_parties),
						"✅ PASSED",
						format!("{:.2?}", elapsed),
						stats.retry_count
					);
					passed += 1;
				} else {
					println!(
						"{:<10} {:<10} {:<10} {:<10}",
						format!("{}-of-{}", threshold, total_parties),
						"❌ VERIFY",
						"-",
						"-"
					);
					failed += 1;
				}
			},
			Err(e) => {
				let elapsed = start.elapsed();
				total_time += elapsed;
				println!(
					"{:<10} {:<10} {:<10} {:<10}",
					format!("{}-of-{}", threshold, total_parties),
					"❌ ERROR",
					format!("{:.2?}", elapsed),
					format!("{:?}", e)
				);
				failed += 1;
			},
		}
	}

	println!("\n=== MATRIX RESULTS (DKG) ===");
	println!("Passed: {}", passed);
	println!("Failed: {}", failed);
	println!("Total time: {:.2?}", total_time);
	println!("Total retries: {}", total_retries);
	println!("Max retries (single config): {}", max_retries);
	if passed > 0 {
		println!("Avg retries per config: {:.2}", total_retries as f64 / passed as f64);
	}

	assert_eq!(failed, 0, "Some DKG threshold configurations failed");
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
			assert_eq!(share.party_id(), i as u32);
			assert_eq!(share.threshold(), t);
			assert_eq!(share.total_parties(), n);
		}
	}
}

// ============================================================================
// Subset Signing Tests (4-Round Protocol)
// ============================================================================

/// Run threshold signing with a SUBSET of DKG participants using the 4-round protocol.
/// This tests the core subset signing feature needed for NEAR MPC integration.
///
/// # Arguments
/// * `dkg_threshold` - The threshold from DKG (t)
/// * `dkg_total` - Total parties from DKG (n)
/// * `signing_parties` - Which party IDs participate in signing (must be >= threshold)
fn run_subset_signing_4_round(
	dkg_threshold: u32,
	dkg_total: u32,
	signing_parties: &[u32],
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
	let signing_total = signing_parties.len() as u32;
	let signing_config = ThresholdConfig::new(dkg_threshold, signing_total)
		.map_err(|e| format!("Signing config error: {:?}", e))?;

	// Select only the signing parties' shares
	let signing_shares: Vec<_> =
		signing_parties.iter().map(|&id| all_shares[id as usize].clone()).collect();

	// Create signers for the signing subset
	let signers: Vec<ThresholdSigner> = signing_shares
		.into_iter()
		.map(|share| ThresholdSigner::new(share, public_key.clone(), signing_config))
		.collect::<Result<_, _>>()
		.map_err(|e| format!("Signer creation error: {:?}", e))?;

	// Run the 4-round signing protocol with leader-based retry
	let signature = run_local_signing(signers, message, context)
		.map_err(|e| format!("Signing error: {:?}", e))?;

	// Verify the signature
	if !verify_signature(&public_key, message, context, &signature) {
		return Err("Signature verification failed".to_string());
	}

	Ok(signature.as_bytes().to_vec())
}

/// Test subset signing: 3 parties sign from 4-party DKG (parties 0, 1, 2)
#[test]
fn test_subset_signing_3_of_4_consecutive() {
	println!("\n=== SUBSET SIGNING TEST: 3 from 4 (consecutive, 4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = (i as u8).wrapping_add(50);
	}

	let message = b"subset signing test";
	let context: &[u8] = b"";

	// DKG with 4 parties, threshold 3
	// Sign with parties 0, 1, 2 (skip party 3)
	let signing_parties = [0u32, 1, 2];

	let start = Instant::now();
	match run_subset_signing_4_round(3, 4, &signing_parties, &seed, message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ Subset signing (3 from 4, consecutive): Success!");
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
		},
		Err(e) => {
			panic!("❌ Subset signing (3 from 4, consecutive) failed: {}", e);
		},
	}
}

/// Test subset signing: 3 parties sign from 4-party DKG (parties 0, 1, 3 - skipping party 2)
#[test]
fn test_subset_signing_3_of_4_non_consecutive() {
	println!("\n=== SUBSET SIGNING TEST: 3 from 4 (non-consecutive, 4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = (i as u8).wrapping_add(60);
	}

	let message = b"subset signing test non-consecutive";
	let context: &[u8] = b"";

	// DKG with 4 parties, threshold 3
	// Sign with parties 0, 1, 3 (skip party 2)
	let signing_parties = [0u32, 1, 3];

	let start = Instant::now();
	match run_subset_signing_4_round(3, 4, &signing_parties, &seed, message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ Subset signing (3 from 4, non-consecutive): Success!");
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
		},
		Err(e) => {
			panic!("❌ Subset signing (3 from 4, non-consecutive) failed: {}", e);
		},
	}
}

/// Test subset signing: 3 parties sign from 5-party DKG
#[test]
fn test_subset_signing_3_of_5() {
	println!("\n=== SUBSET SIGNING TEST: 3 from 5 (4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for i in 0..32 {
		seed[i] = (i as u8).wrapping_add(70);
	}

	let message = b"subset signing test 3 of 5";
	let context: &[u8] = b"";

	// DKG with 5 parties, threshold 3
	// Sign with parties 0, 2, 4 (skipping parties 1 and 3)
	let signing_parties = [0u32, 2, 4];

	let start = Instant::now();
	match run_subset_signing_4_round(3, 5, &signing_parties, &seed, message, context) {
		Ok(signature) => {
			let elapsed = start.elapsed();
			println!("✅ Subset signing (3 from 5): Success!");
			println!("   Time: {:?}", elapsed);
			println!("   Signature length: {} bytes", signature.len());
		},
		Err(e) => {
			panic!("❌ Subset signing (3 from 5) failed: {}", e);
		},
	}
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
