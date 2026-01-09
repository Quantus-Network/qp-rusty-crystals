//! Deterministic NTT test with 100 test vectors for cross-language comparison
//!
//! This test generates 100 deterministic polynomials and computes their NTT,
//! printing the raw NTT output for comparison with Go.
//!
//! Run with: cargo test --test test_ntt -- --nocapture
//!
//! The output should be compared byte-for-byte with the Go equivalent test.

use qp_rusty_crystals_dilithium::fips202;
use qp_rusty_crystals_dilithium::poly::Poly;
use qp_rusty_crystals_threshold::circl_ntt;

const N: usize = 256;
const Q: u32 = 8380417;
const TWO_Q: u32 = 2 * Q;

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_ntt_vectors() {
    println!("=== RUST NTT TEST VECTORS (100 tests) ===");
    println!();
    println!("Q = {}", Q);
    println!("2Q = {}", TWO_Q);
    println!();

    // Generate 100 deterministic test vectors
    for test_idx in 0..100 {
        // Create deterministic seed for this test (same as Go)
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed[i] = ((test_idx * 31 + i * 17) & 0xFF) as u8;
        }

        // Use SHAKE256 to expand seed into polynomial coefficients
        let mut keccak_state = fips202::KeccakState::default();
        fips202::shake256_absorb(&mut keccak_state, &seed, 32);
        fips202::shake256_finalize(&mut keccak_state);

        let mut poly = Poly::default();
        let mut coeff_bytes = [0u8; 3];

        for i in 0..N {
            fips202::shake256_squeeze(&mut coeff_bytes, 3, &mut keccak_state);
            // Convert 3 bytes to a value in [0, 2Q) to match NTT input requirements
            let val = (coeff_bytes[0] as u32
                | ((coeff_bytes[1] as u32) << 8)
                | ((coeff_bytes[2] as u32) << 16))
                % TWO_Q;
            poly.coeffs[i] = val as i32;
        }

        // Store original for comparison
        let original: Vec<i32> = poly.coeffs.to_vec();

        // Print input for first few tests
        if test_idx < 5 {
            println!("Test {}:", test_idx);
            println!("  Seed: {}", hex_encode(&seed));
            println!(
                "  Input[0..5]: [{}, {}, {}, {}, {}]",
                original[0], original[1], original[2], original[3], original[4]
            );
        }

        // Apply NTT using circl_ntt (the one used in threshold signing)
        circl_ntt::ntt(&mut poly);

        // Print NTT output for first few tests
        if test_idx < 5 {
            println!(
                "  NTT[0..5]: [{}, {}, {}, {}, {}]",
                poly.coeffs[0], poly.coeffs[1], poly.coeffs[2], poly.coeffs[3], poly.coeffs[4]
            );
            println!();
        }
    }

    // Print summary hash of all NTT results for quick comparison
    println!("=== SUMMARY HASHES ===");

    // Recompute all NTT results and hash them
    let mut hash_state = fips202::KeccakState::default();
    // We'll accumulate all NTT outputs into the hash

    for test_idx in 0..100 {
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed[i] = ((test_idx * 31 + i * 17) & 0xFF) as u8;
        }

        let mut keccak_state = fips202::KeccakState::default();
        fips202::shake256_absorb(&mut keccak_state, &seed, 32);
        fips202::shake256_finalize(&mut keccak_state);

        let mut poly = Poly::default();
        let mut coeff_bytes = [0u8; 3];

        for i in 0..N {
            fips202::shake256_squeeze(&mut coeff_bytes, 3, &mut keccak_state);
            let val = (coeff_bytes[0] as u32
                | ((coeff_bytes[1] as u32) << 8)
                | ((coeff_bytes[2] as u32) << 16))
                % TWO_Q;
            poly.coeffs[i] = val as i32;
        }

        // NTT
        circl_ntt::ntt(&mut poly);

        // Add NTT result to hash
        for i in 0..N {
            let coeff = poly.coeffs[i] as u32;
            let bytes = [
                coeff as u8,
                (coeff >> 8) as u8,
                (coeff >> 16) as u8,
                (coeff >> 24) as u8,
            ];
            fips202::shake256_absorb(&mut hash_state, &bytes, 4);
        }
    }

    fips202::shake256_finalize(&mut hash_state);
    let mut ntt_hash = [0u8; 32];
    fips202::shake256_squeeze(&mut ntt_hash, 32, &mut hash_state);

    println!("NTT hash (all 100 tests): {}", hex_encode(&ntt_hash));

    println!();
    println!("=== END RUST NTT TEST VECTORS ===");
}

/// Test to compare NTT output with Go expected values
#[test]
fn test_compare_ntt_with_go() {
    println!("\n=== COMPARISON WITH GO NTT OUTPUT ===\n");

    // Expected values from Go test (with 2Q range)
    let go_test_cases = [
        (
            "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
            [156433i32, 1825454, 8442193, 14748345, 11287394],
            [34192878i32, 47026680, 44968407, 49027275, 46916764],
        ),
        (
            "1f30415263748596a7b8c9daebfc0d1e2f405162738495a6b7c8d9eafb0c1d2e",
            [4959573, 15416291, 7660448, 13755773, 5360249],
            [38870014, 53159152, 48468507, 50515935, 36047152],
        ),
        (
            "3e4f60718293a4b5c6d7e8f90a1b2c3d4e5f708192a3b4c5d6e7f8091a2b3c4d",
            [5742374, 16411042, 5669877, 11616124, 7206223],
            [47885709, 56499195, 45017262, 60651930, 46417910],
        ),
        (
            "5d6e7f90a1b2c3d4e5f60718293a4b5c6d7e8fa0b1c2d3e4f5061728394a5b6c",
            [2478750, 334777, 1010257, 2915290, 6841962],
            [33951797, 42281305, 43071239, 59757239, 47947898],
        ),
        (
            "7c8d9eafc0d1e2f30415263748596a7b8c9daebfd0e1f2031425364758697a8b",
            [12717993, 8507564, 1299374, 9172355, 3223308],
            [44552799, 54729537, 55627810, 60991742, 46227185],
        ),
    ];

    let go_ntt_hash = "d1ccfc115eee00b846e01a8bd7a9477d18f6364181f2221c947d7c1a72bcac84";

    let mut all_match = true;

    for (test_idx, (expected_seed, expected_input, expected_ntt)) in go_test_cases.iter().enumerate()
    {
        // Generate with same seed
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed[i] = ((test_idx * 31 + i * 17) & 0xFF) as u8;
        }

        let rust_seed = hex_encode(&seed);

        // Generate polynomial
        let mut keccak_state = fips202::KeccakState::default();
        fips202::shake256_absorb(&mut keccak_state, &seed, 32);
        fips202::shake256_finalize(&mut keccak_state);

        let mut poly = Poly::default();
        let mut coeff_bytes = [0u8; 3];

        for i in 0..N {
            fips202::shake256_squeeze(&mut coeff_bytes, 3, &mut keccak_state);
            let val = (coeff_bytes[0] as u32
                | ((coeff_bytes[1] as u32) << 8)
                | ((coeff_bytes[2] as u32) << 16))
                % TWO_Q;
            poly.coeffs[i] = val as i32;
        }

        // Store input before NTT for display
        let rust_input: Vec<i32> = poly.coeffs[0..5].to_vec();

        // Check seed matches
        let seed_match = rust_seed == *expected_seed;

        // Check input matches (before NTT)
        let input_match = rust_input
            .iter()
            .zip(expected_input.iter())
            .all(|(r, e)| *r == *e);

        // Apply NTT
        circl_ntt::ntt(&mut poly);

        // Store NTT output for display
        let rust_ntt: Vec<i32> = poly.coeffs[0..5].to_vec();

        // Check NTT output matches
        let ntt_match = rust_ntt
            .iter()
            .zip(expected_ntt.iter())
            .all(|(r, e)| *r == *e);

        println!("Test {}:", test_idx);
        println!("  Seed match: {}", seed_match);
        println!(
            "  Input[0..5]: Go={:?}, Rust={:?}, Match={}",
            expected_input,
            rust_input,
            input_match
        );
        println!(
            "  NTT[0..5]: Go={:?}, Rust={:?}, Match={}",
            expected_ntt,
            rust_ntt,
            ntt_match
        );
        println!();

        if !seed_match || !input_match || !ntt_match {
            all_match = false;
        }
    }

    // Compute hash and compare
    let mut hash_state = fips202::KeccakState::default();

    for test_idx in 0..100 {
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed[i] = ((test_idx * 31 + i * 17) & 0xFF) as u8;
        }

        let mut keccak_state = fips202::KeccakState::default();
        fips202::shake256_absorb(&mut keccak_state, &seed, 32);
        fips202::shake256_finalize(&mut keccak_state);

        let mut poly = Poly::default();
        let mut coeff_bytes = [0u8; 3];

        for i in 0..N {
            fips202::shake256_squeeze(&mut coeff_bytes, 3, &mut keccak_state);
            let val = (coeff_bytes[0] as u32
                | ((coeff_bytes[1] as u32) << 8)
                | ((coeff_bytes[2] as u32) << 16))
                % TWO_Q;
            poly.coeffs[i] = val as i32;
        }

        circl_ntt::ntt(&mut poly);

        for i in 0..N {
            let coeff = poly.coeffs[i] as u32;
            let bytes = [
                coeff as u8,
                (coeff >> 8) as u8,
                (coeff >> 16) as u8,
                (coeff >> 24) as u8,
            ];
            fips202::shake256_absorb(&mut hash_state, &bytes, 4);
        }
    }

    fips202::shake256_finalize(&mut hash_state);
    let mut ntt_hash = [0u8; 32];
    fips202::shake256_squeeze(&mut ntt_hash, 32, &mut hash_state);

    let rust_ntt_hash = hex_encode(&ntt_hash);
    let hash_match = rust_ntt_hash == go_ntt_hash;

    println!("NTT hash (all 100 tests):");
    println!("  Go:   {}", go_ntt_hash);
    println!("  Rust: {}", rust_ntt_hash);
    println!("  Match: {}", hash_match);

    println!();
    println!("=== SUMMARY ===");
    if all_match && hash_match {
        println!("✅ ALL NTT VALUES MATCH! NTT implementation is compatible with Go.");
    } else {
        println!("❌ NTT VALUES DO NOT MATCH!");
    }

    println!("\n=== END COMPARISON ===\n");
}

/// Test NTT on actual share values from the threshold protocol
/// This tests the exact values that are stored in shares and converted to NTT
/// by generating shares with the same seed as the threshold tests
#[test]
fn test_ntt_on_share_values() {
    println!("\n=== NTT TEST ON ACTUAL SHARE VALUES ===\n");

    // Generate threshold keys with same seed as our other tests
    use qp_rusty_crystals_threshold::ml_dsa_87::{self, ThresholdConfig};

    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }

    let config = ThresholdConfig::new(2, 2).expect("Invalid config");
    let (_pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config)
        .expect("Key generation failed");

    // Get the actual share from party 0
    println!("Party 0 share keys: {:?}", sks[0].shares.keys().collect::<Vec<_>>());

    // For 2-of-2, party 0 should have share with key 1
    if let Some(share) = sks[0].shares.get(&1) {
        println!("\n--- Testing Party 0, Share key 1 ---");

        // Get the raw s1_share values (first polynomial)
        let raw_input: Vec<i32> = share.s1_share.vec[0].coeffs.to_vec();
        println!("Raw s1_share[0][0..10]: {:?}", &raw_input[0..10]);

        // Create a copy and apply NTT
        let mut poly_for_ntt = share.s1_share.vec[0].clone();
        circl_ntt::ntt(&mut poly_for_ntt);

        println!("After circl_ntt::ntt [0..10]: {:?}", &poly_for_ntt.coeffs[0..10]);

        // Expected Go values:
        // Go: Party 0 share[1] s1[0][0..5] (raw): [8380418 8380416 8380418 8380415 8380415]
        // Go: Party 0 s1h[0][0..5] (after NTT): [38736689 54470437 57962523 64648475 54489583]
        let go_raw: [i32; 5] = [8380418, 8380416, 8380418, 8380415, 8380415];
        let go_ntt: [i32; 5] = [38736689, 54470437, 57962523, 64648475, 54489583];

        println!("\nExpected Go raw[0..5]: {:?}", go_raw);
        println!("Expected Go NTT[0..5]: {:?}", go_ntt);

        // Check raw values match
        let raw_match = raw_input[0..5].iter().zip(go_raw.iter()).all(|(r, g)| *r == *g);
        println!("\nRaw values match Go: {}", raw_match);

        // Check NTT output matches
        let ntt_match = poly_for_ntt.coeffs[0..5].iter().zip(go_ntt.iter()).all(|(r, g)| *r == *g);
        println!("NTT output matches Go: {}", ntt_match);

        if !ntt_match {
            println!("\n❌ NTT MISMATCH DETECTED!");
            println!("This means the NTT of the same input produces different output.");
            println!("Rust NTT[0..5]: {:?}", &poly_for_ntt.coeffs[0..5]);
            println!("Go NTT[0..5]:   {:?}", go_ntt);
        }
    }

    // Also test party 1's share
    if let Some(share) = sks[1].shares.get(&2) {
        println!("\n--- Testing Party 1, Share key 2 ---");

        let raw_input: Vec<i32> = share.s1_share.vec[0].coeffs.to_vec();
        println!("Raw s1_share[0][0..10]: {:?}", &raw_input[0..10]);

        let mut poly_for_ntt = share.s1_share.vec[0].clone();
        circl_ntt::ntt(&mut poly_for_ntt);

        println!("After circl_ntt::ntt [0..10]: {:?}", &poly_for_ntt.coeffs[0..10]);

        // Expected Go values:
        // Go: Party 1 share[2] s1[0][0..5] (raw): [8380417 8380416 8380417 8380417 8380417]
        // Go: Party 1 s1h[0][0..5] (after NTT): [42728369 56127465 57699784 74241946 58884002]
        let go_raw: [i32; 5] = [8380417, 8380416, 8380417, 8380417, 8380417];
        let go_ntt: [i32; 5] = [42728369, 56127465, 57699784, 74241946, 58884002];

        println!("\nExpected Go raw[0..5]: {:?}", go_raw);
        println!("Expected Go NTT[0..5]: {:?}", go_ntt);

        let raw_match = raw_input[0..5].iter().zip(go_raw.iter()).all(|(r, g)| *r == *g);
        println!("\nRaw values match Go: {}", raw_match);

        let ntt_match = poly_for_ntt.coeffs[0..5].iter().zip(go_ntt.iter()).all(|(r, g)| *r == *g);
        println!("NTT output matches Go: {}", ntt_match);

        if !ntt_match {
            println!("\n❌ NTT MISMATCH DETECTED!");
            println!("Rust NTT[0..5]: {:?}", &poly_for_ntt.coeffs[0..5]);
            println!("Go NTT[0..5]:   {:?}", go_ntt);
        }
    }

    println!("\n=== END NTT TEST ON SHARE VALUES ===\n");
}
