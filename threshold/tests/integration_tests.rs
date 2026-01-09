//! Integration tests for threshold ML-DSA implementation
//!
//! These tests validate the complete end-to-end threshold signature protocol
//! using the flow verified to match the Go reference implementation.

use qp_rusty_crystals_threshold::ml_dsa_87::{
    self, aggregate_commitments_dilithium, aggregate_responses, combine_from_parts, compute_mu,
    compute_responses_deterministic, verify_signature, Round1State, ThresholdConfig,
};

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Run the complete threshold signing protocol with deterministic seeds
/// This uses the exact flow verified to match Go in our deterministic tests
fn run_threshold_protocol_deterministic(
    threshold: u8,
    total_parties: u8,
    seed: &[u8; 32],
    party_rhops: &[[u8; 64]],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, String> {
    // Try multiple attempts with different nonce bases (like Go's retry loop)
    run_threshold_protocol_with_nonce(threshold, total_parties, seed, party_rhops, message, context, 0)
}

/// Run with a specific nonce base - allows retrying with different random values
fn run_threshold_protocol_with_nonce(
    threshold: u8,
    total_parties: u8,
    seed: &[u8; 32],
    party_rhops: &[[u8; 64]],
    message: &[u8],
    context: &[u8],
    nonce_base: u16,
) -> Result<Vec<u8>, String> {
    // Step 1: Generate threshold keys
    let config = ThresholdConfig::new(threshold, total_parties)
        .map_err(|e| format!("Config error: {:?}", e))?;

    let (pk, sks) = ml_dsa_87::generate_threshold_key(seed, &config)
        .map_err(|e| format!("Key generation error: {:?}", e))?;

    // For t < n, only the first `threshold` parties participate in signing
    // Active parties bitmask: first t parties (e.g., for 2-of-3: parties 0,1 -> bitmask 0b011 = 3)
    let act: u8 = (1u8 << threshold) - 1;

    // Step 2: Round 1 - Only ACTIVE parties generate commitments
    let mut round1_states = Vec::new();
    let mut round1_commitments = Vec::new();

    for party_id in 0..threshold {
        let rhop = &party_rhops[party_id as usize];
        let (commitment, state) =
            Round1State::new_with_rhoprime(&sks[party_id as usize], &config, rhop, nonce_base)
                .map_err(|e| format!("Party {} Round1 error: {:?}", party_id, e))?;

        round1_states.push(state);
        round1_commitments.push(commitment);
    }

    // Step 3: Aggregate w values from ACTIVE parties only
    // Start with party 0's w, then add other active parties
    let mut w_agg = round1_states[0].w.clone();
    for i in 1..threshold as usize {
        aggregate_commitments_dilithium(&mut w_agg, &round1_states[i].w);
    }

    // Prepare wfinals (single iteration for now)
    let wfinals = vec![w_agg.clone()];

    // Step 4: Compute mu
    let mu = compute_mu(&pk.tr, message, context);

    // Step 5: Round 3 - Each ACTIVE party computes their response
    let mut all_responses = Vec::new();
    for party_id in 0..threshold {
        let z = compute_responses_deterministic(
            &sks[party_id as usize],
            act,
            &mu,
            &wfinals,
            &round1_states[party_id as usize].hyperball_samples,
            &config,
        );

        // Check if response is valid (not all zeros)
        let is_valid = !z.is_empty() && z[0].vec[0].coeffs.iter().any(|&c| c != 0);
        if !is_valid {
            return Err(format!(
                "Party {} failed rejection sampling",
                party_id
            ));
        }

        all_responses.push(z);
    }

    // Step 6: Aggregate responses
    let mut z_agg = all_responses[0].clone();
    for i in 1..threshold as usize {
        aggregate_responses(&mut z_agg, &all_responses[i]);
    }

    // Step 7: Combine into final signature
    let (signature, ok) = combine_from_parts(&pk, message, context, &wfinals, &z_agg, &config);

    if !ok {
        return Err("Combine failed".to_string());
    }

    // Step 8: Verify the signature
    if !verify_signature(&pk, message, context, &signature) {
        return Err("Signature verification failed".to_string());
    }

    Ok(signature)
}

/// Generate deterministic rhop values for parties
fn generate_party_rhops(num_parties: u8, base_offset: u8) -> Vec<[u8; 64]> {
    let mut rhops = Vec::new();
    for party_id in 0..num_parties {
        let mut rhop = [0u8; 64];
        // Use wrapping arithmetic to avoid overflow
        let offset = base_offset.wrapping_add(party_id.wrapping_mul(100));
        for i in 0..64 {
            rhop[i] = (i as u8).wrapping_add(offset);
        }
        rhops.push(rhop);
    }
    rhops
}

// ============================================================================
// Deterministic Tests (using fixed seeds - should always pass)
// ============================================================================

#[test]
fn test_2_of_2_deterministic() {
    println!("\n=== 2-of-2 DETERMINISTIC TEST ===\n");

    // Use the exact same parameters as our verified deterministic tests
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }

    let party_rhops = generate_party_rhops(2, 100);
    let message = b"test message";
    let context: &[u8] = b"";

    match run_threshold_protocol_deterministic(2, 2, &seed, &party_rhops, message, context) {
        Ok(signature) => {
            println!("✅ 2-of-2 deterministic: Signature created and verified!");
            println!("   Signature length: {} bytes", signature.len());
            println!("   Signature[0..32]: {}", hex_encode(&signature[..32.min(signature.len())]));
        }
        Err(e) => {
            panic!("❌ 2-of-2 deterministic failed: {}", e);
        }
    }
}

#[test]
fn test_2_of_3_deterministic() {
    println!("\n=== 2-of-3 DETERMINISTIC TEST ===\n");

    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }

    let party_rhops = generate_party_rhops(3, 100);
    let message = b"test message for 2-of-3";
    let context: &[u8] = b"";

    // Try multiple nonce bases to handle rejection sampling (like Go's retry loop)
    let max_attempts = 100;
    for attempt in 0..max_attempts {
        match run_threshold_protocol_with_nonce(2, 3, &seed, &party_rhops, message, context, attempt) {
            Ok(signature) => {
                println!("✅ 2-of-3 deterministic: Signature created and verified on attempt {}!", attempt + 1);
                println!("   Signature length: {} bytes", signature.len());
                return;
            }
            Err(e) => {
                if attempt < 5 || attempt % 20 == 0 {
                    println!("   Attempt {} failed: {}", attempt + 1, e);
                }
            }
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

    let party_rhops = generate_party_rhops(5, 100);
    let message = b"test message for 3-of-5";
    let context: &[u8] = b"";

    // Try multiple nonce bases to handle rejection sampling (like Go's retry loop)
    let max_attempts = 200;
    for attempt in 0..max_attempts {
        match run_threshold_protocol_with_nonce(3, 5, &seed, &party_rhops, message, context, attempt) {
            Ok(signature) => {
                println!("✅ 3-of-5 deterministic: Signature created and verified on attempt {}!", attempt + 1);
                println!("   Signature length: {} bytes", signature.len());
                return;
            }
            Err(e) => {
                if attempt < 5 || attempt % 20 == 0 {
                    println!("   Attempt {} failed: {}", attempt + 1, e);
                }
            }
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
        // Generate random seed
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);

        // Generate random rhops
        let mut party_rhops = Vec::new();
        for _ in 0..2 {
            let mut rhop = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut rhop);
            party_rhops.push(rhop);
        }

        let message = b"random test message";
        let context: &[u8] = b"";

        match run_threshold_protocol_deterministic(2, 2, &seed, &party_rhops, message, context) {
            Ok(signature) => {
                println!(
                    "✅ 2-of-2 random: Signature created and verified on attempt {}!",
                    attempt
                );
                println!("   Signature length: {} bytes", signature.len());
                return;
            }
            Err(e) => {
                println!("   Attempt {} failed: {}", attempt, e);
            }
        }
    }

    panic!(
        "❌ 2-of-2 random failed after {} attempts",
        max_attempts
    );
}

#[test]
fn test_2_of_3_random() {
    println!("\n=== 2-of-3 RANDOM TEST ===\n");

    use rand::RngCore;

    let max_attempts = 10;

    for attempt in 1..=max_attempts {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);

        let mut party_rhops = Vec::new();
        for _ in 0..3 {
            let mut rhop = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut rhop);
            party_rhops.push(rhop);
        }

        let message = b"random test message for 2-of-3";
        let context: &[u8] = b"";

        match run_threshold_protocol_deterministic(2, 3, &seed, &party_rhops, message, context) {
            Ok(signature) => {
                println!(
                    "✅ 2-of-3 random: Signature created and verified on attempt {}!",
                    attempt
                );
                println!("   Signature length: {} bytes", signature.len());
                return;
            }
            Err(e) => {
                println!("   Attempt {} failed: {}", attempt, e);
            }
        }
    }

    panic!(
        "❌ 2-of-3 random failed after {} attempts",
        max_attempts
    );
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

        let mut party_rhops = Vec::new();
        for _ in 0..5 {
            let mut rhop = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut rhop);
            party_rhops.push(rhop);
        }

        let message = b"random test message for 3-of-5";
        let context: &[u8] = b"";

        match run_threshold_protocol_deterministic(3, 5, &seed, &party_rhops, message, context) {
            Ok(signature) => {
                println!(
                    "✅ 3-of-5 random: Signature created and verified on attempt {}!",
                    attempt
                );
                println!("   Signature length: {} bytes", signature.len());
                return;
            }
            Err(e) => {
                println!("   Attempt {} failed: {}", attempt, e);
            }
        }
    }

    panic!(
        "❌ 3-of-5 random failed after {} attempts",
        max_attempts
    );
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

    let party_rhops = generate_party_rhops(2, 100);
    let message = b"message with context";
    let context = b"my-application-context";

    match run_threshold_protocol_deterministic(2, 2, &seed, &party_rhops, message, context) {
        Ok(signature) => {
            println!("✅ With context: Signature created and verified!");
            println!("   Context: {:?}", String::from_utf8_lossy(context));
            println!("   Signature length: {} bytes", signature.len());
        }
        Err(e) => {
            panic!("❌ With context test failed: {}", e);
        }
    }
}

#[test]
fn test_empty_message() {
    println!("\n=== TEST EMPTY MESSAGE ===\n");

    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }

    let party_rhops = generate_party_rhops(2, 100);
    let message: &[u8] = b"";
    let context: &[u8] = b"";

    match run_threshold_protocol_deterministic(2, 2, &seed, &party_rhops, message, context) {
        Ok(signature) => {
            println!("✅ Empty message: Signature created and verified!");
            println!("   Signature length: {} bytes", signature.len());
        }
        Err(e) => {
            panic!("❌ Empty message test failed: {}", e);
        }
    }
}

#[test]
fn test_long_message() {
    println!("\n=== TEST LONG MESSAGE ===\n");

    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }

    let party_rhops = generate_party_rhops(2, 100);
    // Create a 10KB message
    let message: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();
    let context: &[u8] = b"";

    match run_threshold_protocol_deterministic(2, 2, &seed, &party_rhops, &message, context) {
        Ok(signature) => {
            println!("✅ Long message (10KB): Signature created and verified!");
            println!("   Message length: {} bytes", message.len());
            println!("   Signature length: {} bytes", signature.len());
        }
        Err(e) => {
            panic!("❌ Long message test failed: {}", e);
        }
    }
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
    let (pk, _) = ml_dsa_87::generate_threshold_key(&seed, &config).expect("Key gen");

    let party_rhops = generate_party_rhops(2, 100);
    let message = b"original message";
    let context: &[u8] = b"";

    let signature =
        run_threshold_protocol_deterministic(2, 2, &seed, &party_rhops, message, context)
            .expect("Signature creation should succeed");

    // Verify with wrong message should fail
    let wrong_message = b"wrong message";
    let is_valid = verify_signature(&pk, wrong_message, context, &signature);

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
    let (pk, _) = ml_dsa_87::generate_threshold_key(&seed, &config).expect("Key gen");

    let party_rhops = generate_party_rhops(2, 100);
    let message = b"test message";
    let context = b"correct-context";

    let signature =
        run_threshold_protocol_deterministic(2, 2, &seed, &party_rhops, message, context)
            .expect("Signature creation should succeed");

    // Verify with wrong context should fail
    let wrong_context = b"wrong-context";
    let is_valid = verify_signature(&pk, message, wrong_context, &signature);

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
    println!("\n=== THRESHOLD MATRIX TEST ===\n");

    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }

    let message = b"matrix test message";
    let context: &[u8] = b"";

    // Test configurations: (threshold, total_parties, max_attempts)
    // max_attempts is based on k_iterations from ThresholdConfig - higher k needs more retries
    // k_iterations values: 2-of-2=3, 2-of-3=4, 3-of-3=6, 2-of-4=4, 3-of-4=11, 4-of-4=14,
    //                      2-of-5=5, 3-of-5=26, 4-of-5=70, 5-of-5=35,
    //                      2-of-6=5, 3-of-6=39, 4-of-6=208, 5-of-6=295, 6-of-6=87
    let configs: [(u8, u8, u16); 15] = [
        (2, 2, 50),    // k=3
        (2, 3, 50),    // k=4
        (3, 3, 100),   // k=6
        (2, 4, 50),    // k=4
        (3, 4, 100),   // k=11
        (4, 4, 150),   // k=14
        (2, 5, 50),    // k=5
        (3, 5, 150),   // k=26
        (4, 5, 300),   // k=70
        (5, 5, 200),   // k=35
        (2, 6, 50),    // k=5
        (3, 6, 200),   // k=39
        (4, 6, 500),   // k=208
        (5, 6, 570),   // k=295 (use Go's max of 570)
        (6, 6, 400),   // k=87
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (threshold, total_parties, max_attempts) in configs.iter() {
        let party_rhops = generate_party_rhops(*total_parties, 100);

        let mut success = false;
        for nonce in 0..(*max_attempts) {
            match run_threshold_protocol_with_nonce(
                *threshold,
                *total_parties,
                &seed,
                &party_rhops,
                message,
                context,
                nonce,
            ) {
                Ok(_) => {
                    println!("✅ {}-of-{}: PASSED (attempt {})", threshold, total_parties, nonce + 1);
                    passed += 1;
                    success = true;
                    break;
                }
                Err(_) => {
                    // Continue trying
                }
            }
        }

        if !success {
            println!("❌ {}-of-{}: FAILED after {} attempts", threshold, total_parties, max_attempts);
            failed += 1;
        }
    }

    println!("\n=== MATRIX RESULTS ===");
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);

    assert_eq!(failed, 0, "Some threshold configurations failed");
}
