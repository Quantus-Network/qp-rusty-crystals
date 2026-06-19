//! Integration tests for threshold ML-DSA implementation.
//!
//! These tests validate the complete end-to-end threshold signature protocol
//! using the `ThresholdSigner` API with leader-based retry.

use std::time::Instant;

use qp_rusty_crystals_threshold::{
	generate_with_dealer,
	keygen::dkg::{run_local_dkg, TranscriptSigner},
	signing_protocol::{run_local_signing, DilithiumSignProtocol, SignProtocolError},
	verify_signature, ParticipantId, Signature, ThresholdConfig, ThresholdSigner,
};

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
	data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Number of fresh signing attempts before giving up.
///
/// `run_local_signing` is a single attempt — it can abort when ML-DSA rejection
/// sampling happens to fail on that attempt. In production (NEAR MPC), the
/// application layer retries with a fresh `DilithiumSignProtocol` on a fresh
/// transport channel. We mirror that here so tests are not flaky on parameter
/// sets that frequently abort on the first attempt.
const MAX_EXTERNAL_ATTEMPTS: u32 = 100;

/// Whether a signing error is transient (a fresh attempt seed may succeed) or
/// permanent (deterministic, so retrying cannot help).
///
/// Only probabilistic signing aborts are worth retrying. Structural failures —
/// serialization/size limits, malformed messages, bad config, missing data —
/// are deterministic, so we surface them immediately instead of grinding
/// through every attempt. (This is what previously turned a message-size
/// regression into an ~8-minute "ERROR after 100 attempts" instead of an
/// instant failure.)
fn is_retryable_signing_error(err: &SignProtocolError) -> bool {
	matches!(err, SignProtocolError::SigningError(_) | SignProtocolError::ProtocolFailed(_))
}

/// Run `run_local_signing` with fresh per-attempt seeds, stopping early on
/// permanent (non-retryable) errors.
///
/// `make_signers` is called once per attempt to produce a fresh set of signers,
/// mirroring the "fresh protocol instance per attempt" pattern used by NEAR MPC.
fn sign_with_retries(
	make_signers: impl Fn() -> Vec<ThresholdSigner>,
	message: &[u8],
	context: &[u8],
	base_seed: &[u8; 32],
) -> Result<Signature, SignProtocolError> {
	let mut last_err = SignProtocolError::SigningError("no attempts made".to_string());
	for attempt in 0..MAX_EXTERNAL_ATTEMPTS {
		let mut attempt_seed = *base_seed;
		for (i, b) in attempt.to_le_bytes().iter().enumerate() {
			attempt_seed[i] ^= *b;
		}
		match run_local_signing(make_signers(), message, context, &attempt_seed) {
			Ok(signature) => return Ok(signature),
			Err(e) if is_retryable_signing_error(&e) => last_err = e,
			// Permanent/structural failure: retrying will not help.
			Err(e) => return Err(e),
		}
	}
	Err(last_err)
}

/// Run the complete threshold signing protocol using the 4-round protocol.
///
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

	// Validate signer creation once up front for a clean error message.
	shares
		.iter()
		.take(threshold as usize)
		.cloned()
		.map(|share| ThresholdSigner::new(share, public_key.clone(), config))
		.collect::<Result<Vec<_>, _>>()
		.map_err(|e| format!("Signer creation error: {:?}", e))?;

	let make_signers = || {
		shares
			.iter()
			.take(threshold as usize)
			.cloned()
			.map(|share| ThresholdSigner::new(share, public_key.clone(), config).unwrap())
			.collect::<Vec<_>>()
	};

	let signature = sign_with_retries(make_signers, message, context, seed)
		.map_err(|e| format!("Signing failed: {:?}", e))?;

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
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = i as u8;
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
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = i as u8;
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
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = i as u8;
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

	// Deterministic "random" seed for reproducibility
	let seed = [0x22u8; 32];

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

	// Deterministic "random" seed for reproducibility
	let seed = [0x23u8; 32];

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

	// Deterministic "random" seed for reproducibility
	let seed = [0x35u8; 32];

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
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = i as u8;
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
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = i as u8;
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
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = i as u8;
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
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = i as u8;
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
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = i as u8;
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
// THRESHOLD MATRIX TESTS (Dealer-based keygen)
//
// One #[test] per (threshold, total_parties) config so a failure pinpoints the
// exact config and the suite parallelizes across configs. The 4-of-6 case uses
// k_iterations=1600 (resharing-hardened) — a single signing is multi-second in
// release and slower in a debug build — but it runs in the default suite so the
// near-mpc 4-of-6 committee shape stays regression-covered.
// ============================================================================

/// Run dealer-based keygen + signing for a single config and assert success.
fn run_dealer_signing_test(threshold: u32, total_parties: u32) {
	let mut seed = [0u8; 32];
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = i as u8;
	}

	let message = b"matrix test message";
	let context: &[u8] = b"";

	let config = ThresholdConfig::new(threshold, total_parties)
		.unwrap_or_else(|e| panic!("{threshold}-of-{total_parties}: config error: {e:?}"));
	let (public_key, shares) = generate_with_dealer(&seed, config)
		.unwrap_or_else(|e| panic!("{threshold}-of-{total_parties}: keygen error: {e:?}"));

	// Validate signer creation once up front for a clean error message.
	shares
		.iter()
		.take(threshold as usize)
		.cloned()
		.map(|share| ThresholdSigner::new(share, public_key.clone(), config))
		.collect::<Result<Vec<_>, _>>()
		.unwrap_or_else(|e| panic!("{threshold}-of-{total_parties}: signer creation error: {e:?}"));

	let make_signers = || {
		shares
			.iter()
			.take(threshold as usize)
			.cloned()
			.map(|share| ThresholdSigner::new(share, public_key.clone(), config).unwrap())
			.collect::<Vec<_>>()
	};

	let signature = sign_with_retries(make_signers, message, context, &seed)
		.unwrap_or_else(|e| panic!("{threshold}-of-{total_parties}: signing failed: {e:?}"));
	assert!(
		verify_signature(&public_key, message, context, &signature),
		"{threshold}-of-{total_parties}: signature failed to verify",
	);
}

#[test]
fn test_dealer_sign_2_of_2() {
	run_dealer_signing_test(2, 2);
}

#[test]
fn test_dealer_sign_2_of_3() {
	run_dealer_signing_test(2, 3);
}

#[test]
fn test_dealer_sign_3_of_3() {
	run_dealer_signing_test(3, 3);
}

#[test]
fn test_dealer_sign_2_of_4() {
	run_dealer_signing_test(2, 4);
}

#[test]
fn test_dealer_sign_3_of_4() {
	run_dealer_signing_test(3, 4);
}

#[test]
fn test_dealer_sign_4_of_4() {
	run_dealer_signing_test(4, 4);
}

#[test]
fn test_dealer_sign_2_of_5() {
	run_dealer_signing_test(2, 5);
}

#[test]
fn test_dealer_sign_3_of_5() {
	run_dealer_signing_test(3, 5);
}

#[test]
fn test_dealer_sign_4_of_5() {
	run_dealer_signing_test(4, 5);
}

#[test]
fn test_dealer_sign_5_of_5() {
	run_dealer_signing_test(5, 5);
}

#[test]
fn test_dealer_sign_2_of_6() {
	run_dealer_signing_test(2, 6);
}

#[test]
fn test_dealer_sign_3_of_6() {
	run_dealer_signing_test(3, 6);
}

#[test]
fn test_dealer_sign_4_of_6() {
	run_dealer_signing_test(4, 6);
}

#[test]
fn test_dealer_sign_5_of_6() {
	run_dealer_signing_test(5, 6);
}

#[test]
fn test_dealer_sign_6_of_6() {
	run_dealer_signing_test(6, 6);
}

// ============================================================================
// THRESHOLD MATRIX TESTS (DKG-based keygen)
// ============================================================================

/// Simple test signer for DKG transcript signing.
#[derive(Clone, Debug)]
struct TestSigner {
	id: u32,
}

impl TranscriptSigner for TestSigner {
	type Signature = Vec<u8>;
	type PublicKey = u32;

	fn sign(&self, hash: &[u8; 32]) -> Self::Signature {
		let mut sig = vec![0u8; 36];
		sig[..4].copy_from_slice(&self.id.to_le_bytes());
		sig[4..36].copy_from_slice(hash);
		sig
	}

	fn verify(pk: &Self::PublicKey, hash: &[u8; 32], sig: &Self::Signature) -> bool {
		Self::verify_bytes(pk, hash, sig)
	}

	fn verify_bytes(pk: &Self::PublicKey, hash: &[u8; 32], sig: &[u8]) -> bool {
		if sig.len() < 36 {
			return false;
		}
		let sig_id = u32::from_le_bytes(sig[..4].try_into().unwrap());
		sig_id == *pk && &sig[4..36] == hash
	}

	fn public_key(&self) -> Self::PublicKey {
		self.id
	}
}

/// Run DKG-based keygen + signing for a single config and assert success.
fn run_dkg_signing_test(threshold: u32, total_parties: u32) {
	let seed = 12345u64;
	let message = b"DKG matrix test message";
	let context: &[u8] = b"dkg-test";

	let dkg_signers: Vec<TestSigner> = (0..total_parties).map(|id| TestSigner { id }).collect();
	let dkg_public_keys: Vec<u32> = (0..total_parties).collect();

	// Derive unique seed for this config.
	let mut dkg_seed = [0u8; 32];
	let config_id = seed + threshold as u64 * 100 + total_parties as u64;
	dkg_seed[..8].copy_from_slice(&config_id.to_le_bytes());

	let session_nonce = [0x42u8; 32];

	let dkg_outputs = run_local_dkg(
		threshold,
		total_parties,
		dkg_signers,
		dkg_public_keys,
		dkg_seed,
		&session_nonce,
	)
	.unwrap_or_else(|e| panic!("{threshold}-of-{total_parties}: DKG error: {e:?}"));

	let public_key = dkg_outputs[0].public_key.clone();
	let config = ThresholdConfig::new(threshold, total_parties)
		.unwrap_or_else(|e| panic!("{threshold}-of-{total_parties}: config error: {e:?}"));

	let dkg_outputs_taken: Vec<_> = dkg_outputs.into_iter().take(threshold as usize).collect();

	// Validate signer creation once up front for a clean error message.
	dkg_outputs_taken
		.iter()
		.cloned()
		.map(|output| ThresholdSigner::new(output.private_share, public_key.clone(), config))
		.collect::<Result<Vec<_>, _>>()
		.unwrap_or_else(|e| panic!("{threshold}-of-{total_parties}: signer creation error: {e:?}"));

	let mut session_seed = [0u8; 32];
	session_seed[..8].copy_from_slice(&seed.to_le_bytes());

	let make_signers = || {
		dkg_outputs_taken
			.iter()
			.cloned()
			.map(|output| {
				ThresholdSigner::new(output.private_share, public_key.clone(), config).unwrap()
			})
			.collect::<Vec<_>>()
	};

	let signature = sign_with_retries(make_signers, message, context, &session_seed)
		.unwrap_or_else(|e| panic!("{threshold}-of-{total_parties}: signing failed: {e:?}"));
	assert!(
		verify_signature(&public_key, message, context, &signature),
		"{threshold}-of-{total_parties}: signature failed to verify",
	);
}

#[test]
fn test_dkg_sign_2_of_2() {
	run_dkg_signing_test(2, 2);
}

#[test]
fn test_dkg_sign_2_of_3() {
	run_dkg_signing_test(2, 3);
}

#[test]
fn test_dkg_sign_3_of_3() {
	run_dkg_signing_test(3, 3);
}

#[test]
fn test_dkg_sign_2_of_4() {
	run_dkg_signing_test(2, 4);
}

#[test]
fn test_dkg_sign_3_of_4() {
	run_dkg_signing_test(3, 4);
}

#[test]
fn test_dkg_sign_4_of_4() {
	run_dkg_signing_test(4, 4);
}

#[test]
fn test_dkg_sign_2_of_5() {
	run_dkg_signing_test(2, 5);
}

#[test]
fn test_dkg_sign_3_of_5() {
	run_dkg_signing_test(3, 5);
}

#[test]
fn test_dkg_sign_4_of_5() {
	run_dkg_signing_test(4, 5);
}

#[test]
fn test_dkg_sign_5_of_5() {
	run_dkg_signing_test(5, 5);
}

#[test]
fn test_dkg_sign_2_of_6() {
	run_dkg_signing_test(2, 6);
}

#[test]
fn test_dkg_sign_3_of_6() {
	run_dkg_signing_test(3, 6);
}

#[test]
fn test_dkg_sign_4_of_6() {
	run_dkg_signing_test(4, 6);
}

#[test]
fn test_dkg_sign_5_of_6() {
	run_dkg_signing_test(5, 6);
}

#[test]
fn test_dkg_sign_6_of_6() {
	run_dkg_signing_test(6, 6);
}

/// Test that configuration validation works correctly
#[test]
fn test_config_validation_extended() {
	use qp_rusty_crystals_threshold::ThresholdConfig;

	// All these should succeed (n <= 6)
	let valid_configs = [(2, 6), (6, 6)];

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

	// n = 7 should fail (hyperball parameters not computed, K would be impractical)
	let result = ThresholdConfig::new(2, 7);
	assert!(result.is_err(), "Config (2, 7) should be invalid");

	// n = 8 should fail
	let result = ThresholdConfig::new(2, 8);
	assert!(result.is_err(), "Config (2, 8) should be invalid");
}

/// Test key generation with max supported party count (n=6)
#[test]
fn test_keygen_extended() {
	use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig};

	let seed = [42u8; 32];

	// Test max supported configurations (n = 6)
	let configs = [(2, 6), (4, 6), (6, 6)];

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

	// Validate signers can be created at least once.
	if let Err(e) = signing_shares
		.iter()
		.cloned()
		.map(|share| ThresholdSigner::new(share, public_key.clone(), signing_config))
		.collect::<Result<Vec<_>, _>>()
	{
		return Err(format!("Signer creation error: {:?}", e));
	}

	// Retry with derived per-attempt seeds — equivalent to NEAR MPC spawning
	// a fresh DilithiumSignProtocol per attempt with a fresh round1_seed.
	const MAX_EXTERNAL_ATTEMPTS: u32 = 100;
	let mut last_err = String::new();
	for attempt in 0..MAX_EXTERNAL_ATTEMPTS {
		let signers: Vec<ThresholdSigner> = signing_shares
			.iter()
			.cloned()
			.map(|share| ThresholdSigner::new(share, public_key.clone(), signing_config).unwrap())
			.collect();
		let mut attempt_seed = *seed;
		let bytes = attempt.to_le_bytes();
		for (i, b) in bytes.iter().enumerate() {
			attempt_seed[i] ^= *b;
		}
		match run_local_signing(signers, message, context, &attempt_seed) {
			Ok(signature) => {
				if !verify_signature(&public_key, message, context, &signature) {
					return Err("Signature verification failed".to_string());
				}
				return Ok(signature.as_bytes().to_vec());
			},
			Err(e) => {
				last_err = format!("{:?}", e);
				continue;
			},
		}
	}

	Err(format!(
		"Signing failed after {} attempts (last error: {})",
		MAX_EXTERNAL_ATTEMPTS, last_err
	))
}

/// Test subset signing: 3 parties sign from 4-party DKG (parties 0, 1, 2)
#[test]
fn test_subset_signing_3_of_4_consecutive() {
	println!("\n=== SUBSET SIGNING TEST: 3 from 4 (consecutive, 4-Round Protocol) ===\n");

	let mut seed = [0u8; 32];
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = (i as u8).wrapping_add(50);
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
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = (i as u8).wrapping_add(60);
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
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = (i as u8).wrapping_add(70);
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

/// Test that signing with MORE than threshold parties is correctly rejected.
///
/// The RSS scheme (RSSRecover algorithm) assumes exactly T active parties.
/// The `compute_sharing_patterns(T, parties)` function returns exactly T entries,
/// so the scheme fundamentally does not support more than T active participants.
#[test]
fn test_signing_rejects_more_than_threshold_parties() {
	println!("\n=== VERIFY REJECTION OF MORE THAN THRESHOLD PARTIES ===\n");

	let mut seed = [0u8; 32];
	for (i, byte) in seed.iter_mut().enumerate() {
		*byte = (i as u8).wrapping_add(80);
	}

	// DKG with 5 parties, threshold 3
	let dkg_config = ThresholdConfig::new(3, 5).expect("Valid DKG config");
	let (public_key, all_shares) = generate_with_dealer(&seed, dkg_config).expect("Key generation");

	// Attempt to sign with 4 parties (more than the threshold of 3)
	let signing_parties: Vec<ParticipantId> = vec![0, 1, 2, 3];
	let signing_config = ThresholdConfig::new(3, 4).expect("Valid signing config");

	let signer = ThresholdSigner::new(all_shares[0].clone(), public_key.clone(), signing_config)
		.expect("Valid signer");

	let result = DilithiumSignProtocol::new(
		signer,
		b"test message".to_vec(),
		b"".to_vec(),
		signing_parties,
		0, // my_participant_id
		0, // leader_id
		[0u8; 32],
		[0u8; 32], // attempt_nonce
	);

	assert!(result.is_err(), "Should reject more than threshold parties");
	if let Err(e) = result {
		let error_msg = format!("{:?}", e);
		assert!(
			error_msg.contains("exactly") && error_msg.contains("threshold"),
			"Error should mention 'exactly threshold': {}",
			error_msg
		);
		println!("✅ Correctly rejected 4 parties for threshold=3: {:?}", e);
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
