//! Deterministic Signature Combination test for threshold ML-DSA-87
//!
//! This test combines aggregated w and z values into a final signature and
//! compares the result with the Go reference implementation.
//!
//! Run with: cargo test --test test_signature_combine -- --nocapture
//!
//! The output should be compared byte-for-byte with the Go equivalent test.

use qp_rusty_crystals_threshold::ml_dsa_87::{
    self, aggregate_commitments_dilithium, aggregate_responses, combine_from_parts, compute_mu,
    compute_responses_deterministic, pack_responses, pack_w_to_buf, verify_signature,
    ThresholdConfig,
};

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_deterministic_signature_combine() {
    println!("=== RUST DETERMINISTIC SIGNATURE COMBINE TEST ===");
    println!();

    // Fixed seed for key generation (same as other tests)
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }

    // Fixed rhop for Party 0 (64 bytes)
    let mut rhop0 = [0u8; 64];
    for i in 0..64 {
        rhop0[i] = (i + 100) as u8;
    }

    // Fixed rhop for Party 1 (64 bytes)
    let mut rhop1 = [0u8; 64];
    for i in 0..64 {
        rhop1[i] = (i + 200) as u8;
    }

    println!("Key seed: {}", hex_encode(&seed));
    println!("Party 0 rhop: {}", hex_encode(&rhop0));
    println!("Party 1 rhop: {}", hex_encode(&rhop1));
    println!();

    // Generate threshold keys (2-of-2)
    let config = ThresholdConfig::new(2, 2).expect("Invalid config");
    let (pk, sks) =
        ml_dsa_87::generate_threshold_key(&seed, &config).expect("Key generation failed");

    println!("=== KEY GENERATION ===");
    println!(
        "Public key (first 64 bytes): {}",
        hex_encode(&pk.packed[..64])
    );
    println!();

    // Generate Round1 for both parties
    let (cmt0, state0) = ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop0, 0)
        .expect("Party 0 Round1 failed");
    let (cmt1, state1) = ml_dsa_87::Round1State::new_with_rhoprime(&sks[1], &config, &rhop1, 0)
        .expect("Party 1 Round1 failed");

    println!("=== ROUND 1 ===");
    println!("Party 0 commitment hash: {}", hex_encode(&cmt0));
    println!("Party 1 commitment hash: {}", hex_encode(&cmt1));
    println!();

    // Aggregate commitments (w values)
    println!("=== ROUND 2: AGGREGATION ===");
    let mut w_agg = state0.w.clone();
    aggregate_commitments_dilithium(&mut w_agg, &state1.w);

    println!(
        "Aggregated w[0][0][0..10]: {:?}",
        &w_agg.vec[0].coeffs[0..10]
    );

    // Compute mu
    let msg = b"test message";
    let ctx: &[u8] = b"";
    let mu = compute_mu(&pk.tr, msg, ctx);
    println!("mu: {}", hex_encode(&mu));
    println!();

    // Compute responses for both parties
    let act: u8 = 0b11;
    let wfinals = vec![w_agg.clone()];

    println!("=== ROUND 3: RESPONSE COMPUTATION ===");
    let z0 = compute_responses_deterministic(
        &sks[0],
        act,
        &mu,
        &wfinals,
        &state0.hyperball_samples,
        &config,
    );
    let z1 = compute_responses_deterministic(
        &sks[1],
        act,
        &mu,
        &wfinals,
        &state1.hyperball_samples,
        &config,
    );

    println!(
        "Party 0 z[0][0][0..10]: {:?}",
        &z0[0].vec[0].coeffs[0..10]
    );
    println!(
        "Party 1 z[0][0][0..10]: {:?}",
        &z1[0].vec[0].coeffs[0..10]
    );
    println!();

    // Aggregate responses
    println!("=== RESPONSE AGGREGATION ===");
    let mut z_agg = z0.clone();
    aggregate_responses(&mut z_agg, &z1);

    println!(
        "Aggregated z[0][0][0..10]: {:?}",
        &z_agg[0].vec[0].coeffs[0..10]
    );
    println!();

    // Pack for debugging
    let w_packed = pack_w_to_buf(&wfinals);
    let z_packed = pack_responses(&z_agg);

    println!("Aggregated w packed length: {} bytes", w_packed.len());
    if w_packed.len() >= 32 {
        println!("Aggregated w packed[0..32]: {}", hex_encode(&w_packed[..32]));
    }
    println!("Aggregated z packed length: {} bytes", z_packed.len());
    if z_packed.len() >= 32 {
        println!("Aggregated z packed[0..32]: {}", hex_encode(&z_packed[..32]));
    }
    println!();

    // Combine into signature
    println!("=== COMBINE ===");
    let (sig, ok) = combine_from_parts(&pk, msg, ctx, &wfinals, &z_agg, &config);

    if ok {
        println!("Signature created successfully!");
        println!("Signature length: {} bytes", sig.len());
        if sig.len() >= 32 {
            println!("Signature[0..32]: {}", hex_encode(&sig[..32]));
        }
        if sig.len() >= 64 {
            println!("Signature[32..64]: {}", hex_encode(&sig[32..64]));
        }

        // Verify signature
        let verified = verify_signature(&pk, msg, ctx, &sig);
        if verified {
            println!("✅ Signature VERIFIED!");
        } else {
            println!("❌ Signature verification FAILED!");
        }
    } else {
        println!("Combine failed (rejection sampling)");
    }

    println!();
    println!("=== END RUST DETERMINISTIC SIGNATURE COMBINE TEST ===");
}

#[test]
fn test_compare_signature_combine_with_go() {
    println!("\n=== COMPARISON WITH GO SIGNATURE COMBINE ===\n");

    // Expected values from Go test
    let go_sig_0_32 = "cfe38d488242ae0bad39e0981582bfb52c4af448d599eb394a92ecb320e1f9fa";
    let go_sig_32_64 = "f53d63de54be1c933656ef20f05c389d005f1def0320761276b623281ed45b02";
    let go_sig_len = 4627;

    // Generate with same params
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }
    let mut rhop0 = [0u8; 64];
    for i in 0..64 {
        rhop0[i] = (i + 100) as u8;
    }
    let mut rhop1 = [0u8; 64];
    for i in 0..64 {
        rhop1[i] = (i + 200) as u8;
    }

    let config = ThresholdConfig::new(2, 2).expect("Invalid config");
    let (pk, sks) =
        ml_dsa_87::generate_threshold_key(&seed, &config).expect("Key generation failed");

    // Generate Round1 for both parties
    let (_cmt0, state0) = ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop0, 0)
        .expect("Party 0 Round1 failed");
    let (_cmt1, state1) = ml_dsa_87::Round1State::new_with_rhoprime(&sks[1], &config, &rhop1, 0)
        .expect("Party 1 Round1 failed");

    // Aggregate w
    let mut w_agg = state0.w.clone();
    aggregate_commitments_dilithium(&mut w_agg, &state1.w);

    // Compute mu and responses
    let msg = b"test message";
    let ctx: &[u8] = b"";
    let mu = compute_mu(&pk.tr, msg, ctx);

    let act: u8 = 0b11;
    let wfinals = vec![w_agg.clone()];

    let z0 = compute_responses_deterministic(
        &sks[0],
        act,
        &mu,
        &wfinals,
        &state0.hyperball_samples,
        &config,
    );
    let z1 = compute_responses_deterministic(
        &sks[1],
        act,
        &mu,
        &wfinals,
        &state1.hyperball_samples,
        &config,
    );

    // Aggregate z
    let mut z_agg = z0.clone();
    aggregate_responses(&mut z_agg, &z1);

    // Combine
    let (sig, ok) = combine_from_parts(&pk, msg, ctx, &wfinals, &z_agg, &config);

    if ok {
        // Compare signature length
        println!("Signature length:");
        println!("  Go:   {}", go_sig_len);
        println!("  Rust: {}", sig.len());
        let len_match = sig.len() == go_sig_len;
        println!("  Match: {}", len_match);
        println!();

        // Compare signature bytes
        let rust_sig_0_32 = if sig.len() >= 32 {
            hex_encode(&sig[..32])
        } else {
            String::new()
        };
        let rust_sig_32_64 = if sig.len() >= 64 {
            hex_encode(&sig[32..64])
        } else {
            String::new()
        };

        println!("Signature[0..32]:");
        println!("  Go:   {}", go_sig_0_32);
        println!("  Rust: {}", rust_sig_0_32);
        let sig_0_32_match = rust_sig_0_32 == go_sig_0_32;
        println!("  Match: {}", sig_0_32_match);
        println!();

        println!("Signature[32..64]:");
        println!("  Go:   {}", go_sig_32_64);
        println!("  Rust: {}", rust_sig_32_64);
        let sig_32_64_match = rust_sig_32_64 == go_sig_32_64;
        println!("  Match: {}", sig_32_64_match);
        println!();

        // Verify
        let verified = verify_signature(&pk, msg, ctx, &sig);
        println!("Signature verification: {}", if verified { "✅ PASSED" } else { "❌ FAILED" });
        println!();

        // Summary
        println!("=== SUMMARY ===");
        if len_match && sig_0_32_match && sig_32_64_match && verified {
            println!("✅ ALL SIGNATURE VALUES MATCH AND VERIFICATION PASSED!");
        } else {
            println!("❌ SOME VALUES DO NOT MATCH OR VERIFICATION FAILED!");
            if !len_match {
                println!("  - Signature length mismatch");
            }
            if !sig_0_32_match {
                println!("  - Signature[0..32] mismatch");
            }
            if !sig_32_64_match {
                println!("  - Signature[32..64] mismatch");
            }
            if !verified {
                println!("  - Signature verification failed");
            }
        }
    } else {
        println!("=== SUMMARY ===");
        println!("❌ Combine failed - cannot compare with Go");
    }

    println!("\n=== END COMPARISON ===\n");
}
