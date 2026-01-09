//! Test mu computation to compare with Go implementation
//!
//! Run with: cargo test --test test_mu_computation -- --nocapture
//!
//! This test uses the library's compute_mu function and prints values
//! for comparison with Go.

use qp_rusty_crystals_threshold::ml_dsa_87::{self, compute_mu, ThresholdConfig};

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_mu_computation() {
    println!("\n=== RUST MU COMPUTATION TEST ===\n");

    // Use the same seed as Go test
    let seed = [0u8; 32];
    let config = ThresholdConfig::new(2, 2).expect("Invalid config");

    // Generate threshold keys to get tr
    let (pk, _sks) = ml_dsa_87::generate_threshold_key(&seed, &config)
        .expect("Key generation failed");

    let tr = pk.tr;

    println!("Seed (hex): {}", hex_encode(&seed));
    println!("tr (64 bytes): {}", hex_encode(&tr));

    // Test cases matching Go
    let test_cases: Vec<(&[u8], &[u8])> = vec![
        (b"hello", b""),
        (b"test message", b""),
        (b"test message", b"ctx"),
        (b"", b""),
    ];

    for (i, (msg, ctx)) in test_cases.iter().enumerate() {
        println!("\n--- Test case {} ---", i);
        println!("Message: {:?} (hex: {})", String::from_utf8_lossy(msg), hex_encode(msg));
        println!("Context: {:?} (hex: {})", String::from_utf8_lossy(ctx), hex_encode(ctx));

        // Use the library's compute_mu function
        let mu = compute_mu(&tr, msg, ctx);
        println!("mu (64 bytes): {}", hex_encode(&mu));
    }

    println!("\n=== END RUST MU COMPUTATION TEST ===\n");
}
