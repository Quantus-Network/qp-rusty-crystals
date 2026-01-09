//! Test w1 (decompose) computation to compare with Go implementation
//!
//! Run with: cargo test --test test_w1_computation -- --nocapture
//!
//! This test uses the library's decompose_go function and prints values
//! for comparison with Go.

use qp_rusty_crystals_threshold::ml_dsa_87::{self, decompose_go, ThresholdConfig};

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_w1_computation() {
    println!("\n=== RUST W1 (DECOMPOSE_GO) COMPUTATION TEST ===\n");

    // Test 1: Test decompose_go on known values
    println!("--- Test 1: decompose_go on known values ---");
    let test_values: Vec<u32> = vec![0, 1, 100, 1000, 261888, 523776, 1000000, 4190208, 8380416];
    for a in test_values {
        let (w0_plus_q, w1) = decompose_go(a);
        println!("decompose_go({}) -> w0plusQ={}, w1={}", a, w0_plus_q, w1);
    }

    // Test 2: Generate threshold keys and compute mu
    println!("\n--- Test 2: Full protocol context ---");

    let seed = [0u8; 32];
    let config = ThresholdConfig::new(2, 2).expect("Invalid config");

    let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config)
        .expect("Key generation failed");

    // Generate a Round1 commitment
    let mut party_seed = [0u8; 32];
    party_seed[0] = 1; // Make it different from key seed

    let round1_result = ml_dsa_87::Round1State::new(&sks[0], &config, &party_seed);
    match round1_result {
        Ok((commitment, _round1_state)) => {
            println!("Round1 commitment hash (32 bytes): {}", hex_encode(&commitment));
        }
        Err(e) => {
            println!("Round1 error: {:?}", e);
        }
    }

    // Print mu for reference
    let msg = b"hello";
    let ctx: &[u8] = b"";
    let mu = ml_dsa_87::compute_mu(&pk.tr, msg, ctx);
    println!("\nmu for msg='hello', ctx='': {}", hex_encode(&mu));

    // Test 3: Test decompose_go with a range of values to verify algorithm
    println!("\n--- Test 3: decompose_go verification ---");

    // Verify decompose satisfies: a = w1 * Alpha + (w0plusQ - Q) where Alpha = 2*Gamma2
    const ALPHA: u32 = 523776;
    const Q: u32 = 8380417;

    let mut verify_count = 0;
    let mut error_count = 0;
    for a in 0u32..1000 {
        let (w0_plus_q, w1) = decompose_go(a);
        let w0 = w0_plus_q as i64 - Q as i64;
        let mut reconstructed = w1 as i64 * ALPHA as i64 + w0;
        if reconstructed < 0 {
            reconstructed += Q as i64;
        }
        if reconstructed as u32 != a {
            println!("ERROR: decompose_go({}) -> w0plusQ={}, w1={}, reconstructed={}", a, w0_plus_q, w1, reconstructed);
            error_count += 1;
        } else {
            verify_count += 1;
        }
    }
    println!("Verified {} decompositions, {} errors", verify_count, error_count);

    // Test 4: Print specific values for cross-implementation comparison
    println!("\n--- Test 4: Values for Go comparison ---");
    let comparison_values: Vec<u32> = vec![
        0, 1, 127, 128, 255, 256,
        261887, 261888, 261889,  // Around Gamma2
        523775, 523776, 523777,  // Around Alpha
        4190208, 4190209,        // Around Q/2
        8380415, 8380416,        // Around Q-1
    ];
    for a in comparison_values {
        let (w0_plus_q, w1) = decompose_go(a);
        println!("decompose_go({}) -> w0plusQ={}, w1={}", a, w0_plus_q, w1);
    }

    println!("\n=== END RUST W1 (DECOMPOSE_GO) COMPUTATION TEST ===\n");
}

/// Test that decompose_go matches the expected formula
#[test]
fn test_decompose_go_formula() {
    println!("\n=== DECOMPOSE_GO FORMULA TEST ===\n");

    const ALPHA: u32 = 523776;
    const Q: u32 = 8380417;

    println!("Q = {}", Q);
    println!("Alpha = {}", ALPHA);

    // Test all values (this takes a while, so just test a sample)
    let mut errors = 0;
    for a in (0u32..Q).step_by(1000) {
        let (w0_plus_q, w1) = decompose_go(a);

        // Reconstruct: a = w1 * alpha + (w0plusQ - Q) (mod Q)
        let w0 = w0_plus_q as i64 - Q as i64;
        let mut reconstructed = (w1 as i64) * (ALPHA as i64) + w0;
        reconstructed = ((reconstructed % (Q as i64)) + (Q as i64)) % (Q as i64);

        if reconstructed as u32 != a {
            println!("MISMATCH at a={}: w0plusQ={}, w1={}, reconstructed={}", a, w0_plus_q, w1, reconstructed);
            errors += 1;
            if errors > 10 {
                println!("Too many errors, stopping...");
                break;
            }
        }
    }

    if errors == 0 {
        println!("✅ All sampled decompositions verified correctly!");
    } else {
        println!("❌ Found {} errors", errors);
    }

    println!("\n=== END DECOMPOSE_GO FORMULA TEST ===\n");
}
