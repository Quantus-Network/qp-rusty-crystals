//! Deterministic test to compare with Go output byte-by-byte
//!
//! Run with: cargo test --test test_deterministic -- --nocapture
//!
//! This test uses the exact same seed and rhop values as the Go test
//! to enable direct comparison of intermediate values.

use qp_rusty_crystals_threshold::ml_dsa_87::{
    self, compute_mu, decompose_go, ThresholdConfig,
};

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_deterministic() {
    println!("=== RUST DETERMINISTIC THRESHOLD TEST ===");
    println!();

    // Fixed seed for key generation (same as Go)
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }

    // Fixed rhop for Round1 (64 bytes, same as Go)
    let mut rhop = [0u8; 64];
    for i in 0..64 {
        rhop[i] = (i + 100) as u8;
    }

    println!("Key seed: {}", hex_encode(&seed));
    println!("rhop: {}", hex_encode(&rhop));
    println!();

    // Generate threshold keys
    let config = ThresholdConfig::new(2, 2).expect("Invalid config");

    let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config)
        .expect("Key generation failed");

    println!("=== KEY GENERATION ===");
    println!("Public key size: {} bytes", pk.packed.len());
    println!("Public key (first 64 bytes): {}", hex_encode(&pk.packed[..64]));
    println!("Public key (last 32 bytes): {}", hex_encode(&pk.packed[pk.packed.len()-32..]));
    println!();

    // Generate commitment using deterministic rhop
    println!("=== ROUND 1: COMMITMENT GENERATION ===");
    println!("Using rhop: {}", hex_encode(&rhop));
    println!("nonce: 0");
    println!();

    // Use the Round1State::new_with_rhoprime which takes rhop directly
    let round1_result = ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop, 0);

    match round1_result {
        Ok((commitment, state)) => {
            println!("--- Commitment ---");
            println!("commitment hash: {}", hex_encode(&commitment));
            println!();

            // Pack w for comparison
            let wbuf = state.pack_commitment_canonical(&config);
            println!("--- Packed w ---");
            println!("wbuf length: {} bytes", wbuf.len());
            if wbuf.len() >= 32 {
                println!("wbuf[0..32]: {}", hex_encode(&wbuf[..32]));
            }
            if wbuf.len() >= 64 {
                println!("wbuf[32..64]: {}", hex_encode(&wbuf[32..64]));
            }
            if wbuf.len() >= 96 {
                println!("wbuf[64..96]: {}", hex_encode(&wbuf[64..96]));
            }
            println!();

            // Print w coefficients directly from state
            println!("--- w coefficients ---");
            let w = &state.w;
            println!("w[0][0..10]: [{}, {}, {}, {}, {}, {}, {}, {}, {}, {}]",
                w.vec[0].coeffs[0], w.vec[0].coeffs[1], w.vec[0].coeffs[2],
                w.vec[0].coeffs[3], w.vec[0].coeffs[4], w.vec[0].coeffs[5],
                w.vec[0].coeffs[6], w.vec[0].coeffs[7], w.vec[0].coeffs[8],
                w.vec[0].coeffs[9]);
            println!();

            // Test decompose on w values
            println!("=== DECOMPOSE TEST ===");
            for i in 0..5 {
                let v = w.vec[0].coeffs[i] as u32;
                let (w0, w1) = decompose_go(v);
                println!("decompose(w[0][0][{}]={}) -> w0plusQ={}, w1={}", i, v, w0, w1);
            }
            println!();
        }
        Err(e) => {
            println!("Round1 failed: {:?}", e);
        }
    }

    // Test mu computation
    println!("=== MU COMPUTATION ===");
    let msg = b"test message";
    let ctx: &[u8] = b"";
    let mu = compute_mu(&pk.tr, msg, ctx);
    println!("msg: {:?}", String::from_utf8_lossy(msg));
    println!("ctx: {:?}", String::from_utf8_lossy(ctx));
    println!("mu: {}", hex_encode(&mu));

    println!();
    println!("=== END RUST DETERMINISTIC TEST ===");
}

/// Compare specific values with Go output
#[test]
fn test_compare_with_go() {
    println!("\n=== COMPARISON WITH GO OUTPUT ===\n");

    // Expected values from Go test
    let go_pk_first64 = "9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124adf69ff11fd4871c56ee2e2de51ac090254fcc1c5112207b7503173293a6b999";
    let go_pk_last32 = "e537bc41f374472eba222f57dd0205b164dc35929325b27a581ddcc3197c8317";
    let go_mu = "4469257d594bfde28941d500e7cbe7f927ee9f62ef9b248a74798e1454097ab4181b0fa7182dc5db7da874048ac6af8e8330f053d9a7040a9aa6df49578bbf5b";
    let go_commitment = "2f8e64fbbec8bc6e63c35b9ce314c60c1a1ea43d11f5e792cd93befdf63b447d";
    let go_wbuf_0_32 = "9dbe63b7dd294746af8abe6586380d656f78db6110c80eaaa2f0e7f6bbadd4dd";
    let go_w_coeffs = [6536861u32, 5487470, 4004124, 3011669, 5474406];

    // Generate with same params
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }
    let mut rhop = [0u8; 64];
    for i in 0..64 {
        rhop[i] = (i + 100) as u8;
    }

    let config = ThresholdConfig::new(2, 2).expect("Invalid config");
    let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config)
        .expect("Key generation failed");

    // Compare public key
    let rust_pk_first64 = hex_encode(&pk.packed[..64]);
    let rust_pk_last32 = hex_encode(&pk.packed[pk.packed.len()-32..]);

    println!("Public key (first 64 bytes):");
    println!("  Go:   {}", go_pk_first64);
    println!("  Rust: {}", rust_pk_first64);
    println!("  Match: {}", rust_pk_first64 == go_pk_first64);
    println!();

    println!("Public key (last 32 bytes):");
    println!("  Go:   {}", go_pk_last32);
    println!("  Rust: {}", rust_pk_last32);
    println!("  Match: {}", rust_pk_last32 == go_pk_last32);
    println!();

    // Compare mu
    let msg = b"test message";
    let ctx: &[u8] = b"";
    let mu = compute_mu(&pk.tr, msg, ctx);
    let rust_mu = hex_encode(&mu);

    println!("mu:");
    println!("  Go:   {}", go_mu);
    println!("  Rust: {}", rust_mu);
    println!("  Match: {}", rust_mu == go_mu);
    println!();

    // Compare Round1 commitment
    let round1_result = ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop, 0);
    if let Ok((commitment, state)) = round1_result {
        let rust_commitment = hex_encode(&commitment);
        println!("Commitment hash:");
        println!("  Go:   {}", go_commitment);
        println!("  Rust: {}", rust_commitment);
        println!("  Match: {}", rust_commitment == go_commitment);
        println!();

        // Debug: print the inputs to commitment hash
        println!("Commitment hash inputs:");
        println!("  tr (64 bytes): {}", hex_encode(&pk.tr));
        println!("  sk.id: {}", sks[0].id);

        // Compare wbuf (this is pack_commitment_canonical which packs multiple K iterations)
        let wbuf_canonical = state.pack_commitment_canonical(&config);
        println!("wbuf_canonical length: {} bytes", wbuf_canonical.len());
        if wbuf_canonical.len() >= 32 {
            let rust_wbuf = hex_encode(&wbuf_canonical[..32]);
            println!("wbuf_canonical[0..32]:");
            println!("  Go:   {}", go_wbuf_0_32);
            println!("  Rust: {}", rust_wbuf);
            println!("  Match: {}", rust_wbuf == go_wbuf_0_32);
            println!();
        }

        // The commitment hash uses pack_w_dilithium, not pack_commitment_canonical
        // Let's compute what the Rust commitment hash input actually looks like
        println!("Note: Go's wbuf for commitment is {} bytes", 17664);
        println!("      Rust's wbuf_canonical is {} bytes (K iterations)", wbuf_canonical.len());
        println!();

        // Compare w coefficients
        println!("w coefficients:");
        for i in 0..5 {
            let rust_coeff = state.w.vec[0].coeffs[i] as u32;
            let go_coeff = go_w_coeffs[i];
            println!("  w[0][0][{}]: Go={}, Rust={}, Match: {}", i, go_coeff, rust_coeff, rust_coeff == go_coeff);
        }
    } else {
        println!("Round1 failed!");
    }

    println!("\n=== END COMPARISON ===\n");
}
