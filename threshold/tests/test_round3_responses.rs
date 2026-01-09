//! Deterministic Round 3 Response computation test for threshold ML-DSA-87
//!
//! This test computes partial responses (z values) for each party and compares
//! them with the Go reference implementation using the library's exported functions.
//!
//! Run with: cargo test --test test_round3_responses -- --nocapture
//!
//! The output should be compared byte-for-byte with the Go equivalent test.

use qp_rusty_crystals_threshold::ml_dsa_87::{
    self, aggregate_commitments_dilithium, aggregate_responses, compute_mu,
    compute_responses_deterministic, pack_responses, ThresholdConfig,
};

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_deterministic_round3_responses() {
    println!("=== RUST DETERMINISTIC ROUND 3 RESPONSES TEST ===");
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

    // Aggregate commitments
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

    // Active parties bitmask (both parties 0 and 1 are active)
    let act: u8 = 0b11;

    // Prepare wfinals as a slice (single iteration for this test)
    let wfinals = vec![w_agg.clone()];

    // Compute responses for party 0
    println!("=== ROUND 3: RESPONSE COMPUTATION ===");
    println!("--- Party 0 Response ---");
    let z0 = compute_responses_deterministic(&sks[0], act, &mu, &wfinals, &state0.hyperball_samples, &config);

    if !z0.is_empty() && z0[0].vec[0].coeffs.iter().any(|&c| c != 0) {
        println!(
            "Party 0 z[0][0][0..10]: {:?}",
            &z0[0].vec[0].coeffs[0..10]
        );

        let z0_packed = pack_responses(&z0);
        println!("Party 0 z packed length: {} bytes", z0_packed.len());
        if z0_packed.len() >= 32 {
            println!("Party 0 z packed[0..32]: {}", hex_encode(&z0_packed[..32]));
        }
    } else {
        println!("Party 0: No valid response (rejection sampling)");
    }
    println!();

    // Compute responses for party 1
    println!("--- Party 1 Response ---");
    let z1 = compute_responses_deterministic(&sks[1], act, &mu, &wfinals, &state1.hyperball_samples, &config);

    if !z1.is_empty() && z1[0].vec[0].coeffs.iter().any(|&c| c != 0) {
        println!(
            "Party 1 z[0][0][0..10]: {:?}",
            &z1[0].vec[0].coeffs[0..10]
        );

        let z1_packed = pack_responses(&z1);
        println!("Party 1 z packed length: {} bytes", z1_packed.len());
        if z1_packed.len() >= 32 {
            println!("Party 1 z packed[0..32]: {}", hex_encode(&z1_packed[..32]));
        }
    } else {
        println!("Party 1: No valid response (rejection sampling)");
    }
    println!();

    // Aggregate responses
    println!("=== RESPONSE AGGREGATION ===");
    let z0_valid = !z0.is_empty() && z0[0].vec[0].coeffs.iter().any(|&c| c != 0);
    let z1_valid = !z1.is_empty() && z1[0].vec[0].coeffs.iter().any(|&c| c != 0);

    if z0_valid && z1_valid {
        let mut z_agg = z0.clone();
        aggregate_responses(&mut z_agg, &z1);

        println!(
            "Aggregated z[0][0][0..10]: {:?}",
            &z_agg[0].vec[0].coeffs[0..10]
        );

        let z_agg_packed = pack_responses(&z_agg);
        println!("Aggregated z packed length: {} bytes", z_agg_packed.len());
        if z_agg_packed.len() >= 32 {
            println!(
                "Aggregated z packed[0..32]: {}",
                hex_encode(&z_agg_packed[..32])
            );
        }
    } else {
        println!("Cannot aggregate - one or both parties failed rejection sampling");
    }

    println!();
    println!("=== END RUST DETERMINISTIC ROUND 3 RESPONSES TEST ===");
}

#[test]
fn test_compare_round3_responses_with_go() {
    println!("\n=== COMPARISON WITH GO ROUND 3 RESPONSES ===\n");

    // Expected values from Go test
    let go_z0: [i32; 10] = [
        8374620, 8343173, 8352147, 8378604, 86, 35222, 28659, 7482, 8522, 8372481,
    ];
    let go_z1: [i32; 10] = [
        14307, 20481, 8352817, 8323672, 8350406, 10499, 8362247, 3176, 8363712, 8351637,
    ];
    let go_z_agg: [i32; 10] = [
        8510, 8363654, 8324547, 8321859, 8350492, 45721, 10489, 10658, 8372234, 8343701,
    ];

    let go_z0_packed = "a516c817896e6e587180aaffa766770d90672c7eb6de07f081db0658f979bc32";
    let go_z1_packed = "1dc8f7ff7ad06b98da8d3b75d86f7dfa4688397f4141c80687903d2842837ce1";
    let go_z_agg_packed = "c2deb717843edae84b8ee57478d67407d7e7657df71fc8f6886b44783b7d3814";

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

    // Aggregate
    let mut w_agg = state0.w.clone();
    aggregate_commitments_dilithium(&mut w_agg, &state1.w);

    // Compute mu
    let msg = b"test message";
    let ctx: &[u8] = b"";
    let mu = compute_mu(&pk.tr, msg, ctx);

    let act: u8 = 0b11;
    let wfinals = vec![w_agg.clone()];

    // Compute responses
    let z0 = compute_responses_deterministic(&sks[0], act, &mu, &wfinals, &state0.hyperball_samples, &config);
    let z1 = compute_responses_deterministic(&sks[1], act, &mu, &wfinals, &state1.hyperball_samples, &config);

    // Compare Party 0 z values
    println!("Party 0 z[0][0..10]:");
    println!("  Go:   {:?}", go_z0);
    let rust_z0: Vec<i32> = if !z0.is_empty() {
        z0[0].vec[0].coeffs[0..10].to_vec()
    } else {
        vec![0; 10]
    };
    println!("  Rust: {:?}", rust_z0);
    let z0_match = rust_z0.iter().zip(go_z0.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", z0_match);
    println!();

    // Compare Party 1 z values
    println!("Party 1 z[0][0..10]:");
    println!("  Go:   {:?}", go_z1);
    let rust_z1: Vec<i32> = if !z1.is_empty() {
        z1[0].vec[0].coeffs[0..10].to_vec()
    } else {
        vec![0; 10]
    };
    println!("  Rust: {:?}", rust_z1);
    let z1_match = rust_z1.iter().zip(go_z1.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", z1_match);
    println!();

    // Aggregate and compare
    let z0_valid = !z0.is_empty() && z0[0].vec[0].coeffs.iter().any(|&c| c != 0);
    let z1_valid = !z1.is_empty() && z1[0].vec[0].coeffs.iter().any(|&c| c != 0);

    if z0_valid && z1_valid {
        let mut z_agg = z0.clone();
        aggregate_responses(&mut z_agg, &z1);

        println!("Aggregated z[0][0..10]:");
        println!("  Go:   {:?}", go_z_agg);
        let rust_z_agg: Vec<i32> = z_agg[0].vec[0].coeffs[0..10].to_vec();
        println!("  Rust: {:?}", rust_z_agg);
        let z_agg_match = rust_z_agg.iter().zip(go_z_agg.iter()).all(|(r, g)| *r == *g);
        println!("  Match: {}", z_agg_match);
        println!();

        // Compare packed responses
        let z0_packed = pack_responses(&z0);
        let z1_packed = pack_responses(&z1);
        let z_agg_packed = pack_responses(&z_agg);

        println!("Party 0 z packed[0..32]:");
        println!("  Go:   {}", go_z0_packed);
        let rust_z0_packed = if z0_packed.len() >= 32 {
            hex_encode(&z0_packed[..32])
        } else {
            String::new()
        };
        println!("  Rust: {}", rust_z0_packed);
        println!("  Match: {}", rust_z0_packed == go_z0_packed);
        println!();

        println!("Party 1 z packed[0..32]:");
        println!("  Go:   {}", go_z1_packed);
        let rust_z1_packed = if z1_packed.len() >= 32 {
            hex_encode(&z1_packed[..32])
        } else {
            String::new()
        };
        println!("  Rust: {}", rust_z1_packed);
        println!("  Match: {}", rust_z1_packed == go_z1_packed);
        println!();

        println!("Aggregated z packed[0..32]:");
        println!("  Go:   {}", go_z_agg_packed);
        let rust_z_agg_packed = if z_agg_packed.len() >= 32 {
            hex_encode(&z_agg_packed[..32])
        } else {
            String::new()
        };
        println!("  Rust: {}", rust_z_agg_packed);
        println!("  Match: {}", rust_z_agg_packed == go_z_agg_packed);
        println!();

        // Summary
        println!("=== SUMMARY ===");
        if z0_match && z1_match && z_agg_match {
            println!("✅ ALL Z VALUES MATCH!");
        } else {
            println!("❌ SOME Z VALUES DO NOT MATCH!");
            if !z0_match {
                println!("  - Party 0 z mismatch");
            }
            if !z1_match {
                println!("  - Party 1 z mismatch");
            }
            if !z_agg_match {
                println!("  - Aggregated z mismatch");
            }
        }

        if rust_z0_packed == go_z0_packed
            && rust_z1_packed == go_z1_packed
            && rust_z_agg_packed == go_z_agg_packed
        {
            println!("✅ ALL PACKED VALUES MATCH!");
        } else {
            println!("❌ SOME PACKED VALUES DO NOT MATCH!");
        }
    } else {
        println!("=== SUMMARY ===");
        println!("❌ Cannot compare - one or both parties failed rejection sampling");
        println!("  Party 0 valid: {}", z0_valid);
        println!("  Party 1 valid: {}", z1_valid);
    }

    println!("\n=== END COMPARISON ===\n");
}
