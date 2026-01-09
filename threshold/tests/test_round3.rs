//! Deterministic Round 3 test for threshold ML-DSA-87
//!
//! This test runs the full protocol through Round 3 with fixed seeds and compares:
//! - Challenge polynomial c derivation
//! - Partial response z computation for each party
//! - Response aggregation z_final = z0 + z1
//!
//! Run with: cargo test --test test_round3 -- --nocapture
//!
//! The output should be compared byte-for-byte with the Go equivalent test.

use qp_rusty_crystals_dilithium::{fips202, params as dilithium_params, poly, polyvec};
use qp_rusty_crystals_threshold::ml_dsa_87::{
    self, aggregate_commitments_dilithium, compute_mu, veck_decompose_go, ThresholdConfig,
};

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_deterministic_round3() {
    println!("=== RUST DETERMINISTIC ROUND 3 TEST ===");
    println!();

    // Fixed seed for key generation (same as Go test)
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
    let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config).expect("Key generation failed");

    println!("=== KEY GENERATION ===");
    println!(
        "Public key (first 64 bytes): {}",
        hex_encode(&pk.packed[..64])
    );
    println!();

    // Generate commitments for both parties
    println!("=== ROUND 1 ===");
    let (cmt0, state0) =
        ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop0, 0).expect("Party 0 Round1 failed");
    let (cmt1, state1) =
        ml_dsa_87::Round1State::new_with_rhoprime(&sks[1], &config, &rhop1, 0).expect("Party 1 Round1 failed");

    println!("Party 0 commitment hash: {}", hex_encode(&cmt0));
    println!("Party 1 commitment hash: {}", hex_encode(&cmt1));
    println!();

    // Aggregate commitments
    println!("=== ROUND 2: AGGREGATION ===");
    let mut w_agg = state0.w.clone();
    aggregate_commitments_dilithium(&mut w_agg, &state1.w);

    let agg_coeffs: Vec<i32> = w_agg.vec[0].coeffs[0..10].to_vec();
    println!("Aggregated w[0][0][0..10]: {:?}", agg_coeffs);

    // Compute mu
    let msg = b"test message";
    let ctx: &[u8] = b"";
    let mu = compute_mu(&pk.tr, msg, ctx);
    println!("mu: {}", hex_encode(&mu));
    println!();

    // Decompose aggregated w and compute challenge
    println!("=== CHALLENGE COMPUTATION ===");
    let mut w0_dec = polyvec::Polyveck::default();
    let mut w1_dec = polyvec::Polyveck::default();
    veck_decompose_go(&w_agg, &mut w0_dec, &mut w1_dec);

    // Pack w1 for challenge computation
    let mut w1_packed = vec![0u8; dilithium_params::K * dilithium_params::POLYW1_PACKEDBYTES];
    polyvec::k_pack_w1(&mut w1_packed, &w1_dec);

    // Compute challenge c = H(mu || w1)
    let mut c_bytes = [0u8; dilithium_params::C_DASH_BYTES];
    let mut keccak_state = fips202::KeccakState::default();
    fips202::shake256_absorb(&mut keccak_state, &mu, 64);
    fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
    fips202::shake256_finalize(&mut keccak_state);
    fips202::shake256_squeeze(&mut c_bytes, dilithium_params::C_DASH_BYTES, &mut keccak_state);

    println!("c_tilde: {}", hex_encode(&c_bytes));

    // Derive challenge polynomial
    let mut c_poly = poly::Poly::default();
    poly::challenge(&mut c_poly, &c_bytes);

    let c_poly_coeffs: Vec<i32> = c_poly.coeffs[0..10].to_vec();
    println!("c_poly[0..10]: {:?}", c_poly_coeffs);
    println!();

    // Print recovered shares for debugging
    println!("=== RECOVERED SHARES (for debugging) ===");
    let _act: u8 = 0b11; // Both parties active

    // Debug: Print what shares each party has
    println!("Party 0 share keys: {:?}", sks[0].shares.keys().collect::<Vec<_>>());
    println!("Party 1 share keys: {:?}", sks[1].shares.keys().collect::<Vec<_>>());

    // Debug: Print raw share values before NTT for party 0, share key 1
    if let Some(share) = sks[0].shares.get(&1) {
        println!("Party 0 share[1] s1_share[0][0..5] (raw, before NTT): {:?}",
            &share.s1_share.vec[0].coeffs[0..5]);
        println!("Party 0 share[1] s2_share[0][0..5] (raw, before NTT): {:?}",
            &share.s2_share.vec[0].coeffs[0..5]);

        // Manually compute NTT to compare with recover_share_hardcoded
        let mut manual_ntt = share.s1_share.vec[0].clone();
        qp_rusty_crystals_threshold::circl_ntt::ntt(&mut manual_ntt);
        println!("Party 0 share[1] s1 after manual NTT[0..5]: {:?}",
            &manual_ntt.coeffs[0..5]);
    }
    // Debug: Print raw share values before NTT for party 1, share key 2
    if let Some(share) = sks[1].shares.get(&2) {
        println!("Party 1 share[2] s1_share[0][0..5] (raw, before NTT): {:?}",
            &share.s1_share.vec[0].coeffs[0..5]);
        println!("Party 1 share[2] s2_share[0][0..5] (raw, before NTT): {:?}",
            &share.s2_share.vec[0].coeffs[0..5]);

        // Manually compute NTT to compare with recover_share_hardcoded
        let mut manual_ntt = share.s1_share.vec[0].clone();
        qp_rusty_crystals_threshold::circl_ntt::ntt(&mut manual_ntt);
        println!("Party 1 share[2] s1 after manual NTT[0..5]: {:?}",
            &manual_ntt.coeffs[0..5]);
    }
    println!();

    // Recover shares for party 0
    println!("Calling recover_share_hardcoded for party 0:");
    println!("  party_id={}, active_parties=[0,1], threshold={}, parties={}",
        sks[0].id, config.base.threshold(), config.base.total_parties());
    let (s1h0, s2h0) = ml_dsa_87::secret_sharing::recover_share_hardcoded(
        &sks[0].shares,
        sks[0].id,
        &[0, 1],
        config.base.threshold(),
        config.base.total_parties(),
    )
    .expect("Failed to recover share for party 0");
    println!("  Result s1h0[0][0..5]: {:?}", &s1h0.vec[0].coeffs[0..5]);

    // Recover shares for party 1
    println!("Calling recover_share_hardcoded for party 1:");
    println!("  party_id={}, active_parties=[0,1], threshold={}, parties={}",
        sks[1].id, config.base.threshold(), config.base.total_parties());
    let (s1h1, s2h1) = ml_dsa_87::secret_sharing::recover_share_hardcoded(
        &sks[1].shares,
        sks[1].id,
        &[0, 1],
        config.base.threshold(),
        config.base.total_parties(),
    )
    .expect("Failed to recover share for party 1");
    println!("  Result s1h1[0][0..5]: {:?}", &s1h1.vec[0].coeffs[0..5]);
    println!();

    // Print s1h and s2h coefficients (they're in NTT domain)
    println!(
        "Party 0 s1h[0][0..5]: {:?}",
        &s1h0.vec[0].coeffs[0..5]
            .iter()
            .map(|&x| x as u32)
            .collect::<Vec<u32>>()
    );
    println!(
        "Party 0 s2h[0][0..5]: {:?}",
        &s2h0.vec[0].coeffs[0..5]
            .iter()
            .map(|&x| x as u32)
            .collect::<Vec<u32>>()
    );
    println!(
        "Party 1 s1h[0][0..5]: {:?}",
        &s1h1.vec[0].coeffs[0..5]
            .iter()
            .map(|&x| x as u32)
            .collect::<Vec<u32>>()
    );
    println!(
        "Party 1 s2h[0][0..5]: {:?}",
        &s2h1.vec[0].coeffs[0..5]
            .iter()
            .map(|&x| x as u32)
            .collect::<Vec<u32>>()
    );
    println!();

    // Print hyperball samples
    println!("=== HYPERBALL SAMPLES (stw) ===");
    if !state0.hyperball_samples.is_empty() {
        let stw0_samples: Vec<f64> = state0.hyperball_samples[0].get_samples(10);
        println!("Party 0 stw[0][0..10]: {:?}", stw0_samples);
    }
    if !state1.hyperball_samples.is_empty() {
        let stw1_samples: Vec<f64> = state1.hyperball_samples[0].get_samples(10);
        println!("Party 1 stw[0][0..10]: {:?}", stw1_samples);
    }
    println!();

    // Print individual w values
    println!("=== INDIVIDUAL W VALUES ===");
    println!(
        "Party 0 w[0][0][0..10]: {:?}",
        &state0.w.vec[0].coeffs[0..10].to_vec()
    );
    println!(
        "Party 1 w[0][0][0..10]: {:?}",
        &state1.w.vec[0].coeffs[0..10].to_vec()
    );

    println!();
    println!("=== END RUST DETERMINISTIC ROUND 3 TEST ===");
}

/// Test to compare Round 3 values with Go output
#[test]
fn test_compare_round3_with_go() {
    println!("\n=== COMPARISON WITH GO ROUND 3 OUTPUT ===\n");

    // Expected values from Go test
    let go_c_tilde = "cfe38d488242ae0bad39e0981582bfb52c4af448d599eb394a92ecb320e1f9faf53d63de54be1c933656ef20f05c389d005f1def0320761276b623281ed45b02";
    let go_c_poly: [i32; 10] = [1, 0, 0, 0, 1, 0, 0, 0, 0, -1]; // Note: Go shows 8380416 which is -1 mod Q

    // Go's recovered shares (in NTT domain)
    let go_s1h0: [u32; 5] = [38736689, 54470437, 57962523, 64648475, 54489583];
    let go_s2h0: [u32; 5] = [45706760, 54026276, 46927981, 62176715, 52949643];
    let go_s1h1: [u32; 5] = [42728369, 56127465, 57699784, 74241946, 58884002];
    let go_s2h1: [u32; 5] = [41227466, 49450040, 56054905, 64710293, 55636153];

    // Go's hyperball samples
    let go_stw0: [f64; 10] = [
        -5803.477699825563,
        -37236.98283236073,
        -28269.749422105582,
        -1801.7122862938559,
        87.64130885674653,
        35223.4659172419,
        28666.884593926916,
        7482.525113917906,
        8525.901686471578,
        -7939.43445497032,
    ];
    let go_stw1: [f64; 10] = [
        14314.672902764889,
        20494.15898066272,
        -27601.694164409317,
        -56736.68567668079,
        -30006.241929424035,
        10495.081096407966,
        -18195.656366966792,
        3165.158276431506,
        -16693.90281168132,
        -28757.406194987005,
    ];

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
    let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config).expect("Key generation failed");

    // Generate Round1 for both parties
    let (_cmt0, state0) =
        ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop0, 0).expect("Party 0 Round1 failed");
    let (_cmt1, state1) =
        ml_dsa_87::Round1State::new_with_rhoprime(&sks[1], &config, &rhop1, 0).expect("Party 1 Round1 failed");

    // Aggregate
    let mut w_agg = state0.w.clone();
    aggregate_commitments_dilithium(&mut w_agg, &state1.w);

    // Compute mu and challenge
    let msg = b"test message";
    let ctx: &[u8] = b"";
    let mu = compute_mu(&pk.tr, msg, ctx);

    let mut w0_dec = polyvec::Polyveck::default();
    let mut w1_dec = polyvec::Polyveck::default();
    veck_decompose_go(&w_agg, &mut w0_dec, &mut w1_dec);

    let mut w1_packed = vec![0u8; dilithium_params::K * dilithium_params::POLYW1_PACKEDBYTES];
    polyvec::k_pack_w1(&mut w1_packed, &w1_dec);

    let mut c_bytes = [0u8; dilithium_params::C_DASH_BYTES];
    let mut keccak_state = fips202::KeccakState::default();
    fips202::shake256_absorb(&mut keccak_state, &mu, 64);
    fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
    fips202::shake256_finalize(&mut keccak_state);
    fips202::shake256_squeeze(&mut c_bytes, dilithium_params::C_DASH_BYTES, &mut keccak_state);

    // Compare c_tilde
    let rust_c_tilde = hex_encode(&c_bytes);
    println!("c_tilde:");
    println!("  Go:   {}", go_c_tilde);
    println!("  Rust: {}", rust_c_tilde);
    let c_tilde_match = rust_c_tilde == go_c_tilde;
    println!("  Match: {}", c_tilde_match);
    println!();

    // Derive challenge polynomial and compare
    let mut c_poly = poly::Poly::default();
    poly::challenge(&mut c_poly, &c_bytes);

    println!("c_poly[0..10]:");
    println!("  Go:   {:?}", go_c_poly);
    let rust_c_poly: Vec<i32> = c_poly.coeffs[0..10].to_vec();
    println!("  Rust: {:?}", rust_c_poly);
    let c_poly_match = rust_c_poly
        .iter()
        .zip(go_c_poly.iter())
        .all(|(r, g)| *r == *g || (*r == dilithium_params::Q as i32 - 1 && *g == -1));
    println!("  Match: {}", c_poly_match);
    println!();

    // Recover shares and compare
    let (s1h0, s2h0) = ml_dsa_87::secret_sharing::recover_share_hardcoded(
        &sks[0].shares,
        sks[0].id,
        &[0, 1],
        config.base.threshold(),
        config.base.total_parties(),
    )
    .expect("Failed to recover share for party 0");

    let (s1h1, s2h1) = ml_dsa_87::secret_sharing::recover_share_hardcoded(
        &sks[1].shares,
        sks[1].id,
        &[0, 1],
        config.base.threshold(),
        config.base.total_parties(),
    )
    .expect("Failed to recover share for party 1");

    println!("Party 0 s1h[0][0..5]:");
    println!("  Go:   {:?}", go_s1h0);
    let rust_s1h0: Vec<u32> = s1h0.vec[0].coeffs[0..5]
        .iter()
        .map(|&x| x as u32)
        .collect();
    println!("  Rust: {:?}", rust_s1h0);
    let s1h0_match = rust_s1h0.iter().zip(go_s1h0.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", s1h0_match);
    println!();

    println!("Party 0 s2h[0][0..5]:");
    println!("  Go:   {:?}", go_s2h0);
    let rust_s2h0: Vec<u32> = s2h0.vec[0].coeffs[0..5]
        .iter()
        .map(|&x| x as u32)
        .collect();
    println!("  Rust: {:?}", rust_s2h0);
    let s2h0_match = rust_s2h0.iter().zip(go_s2h0.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", s2h0_match);
    println!();

    println!("Party 1 s1h[0][0..5]:");
    println!("  Go:   {:?}", go_s1h1);
    let rust_s1h1: Vec<u32> = s1h1.vec[0].coeffs[0..5]
        .iter()
        .map(|&x| x as u32)
        .collect();
    println!("  Rust: {:?}", rust_s1h1);
    let s1h1_match = rust_s1h1.iter().zip(go_s1h1.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", s1h1_match);
    println!();

    println!("Party 1 s2h[0][0..5]:");
    println!("  Go:   {:?}", go_s2h1);
    let rust_s2h1: Vec<u32> = s2h1.vec[0].coeffs[0..5]
        .iter()
        .map(|&x| x as u32)
        .collect();
    println!("  Rust: {:?}", rust_s2h1);
    let s2h1_match = rust_s2h1.iter().zip(go_s2h1.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", s2h1_match);
    println!();

    // Compare hyperball samples
    println!("Party 0 stw[0][0..10]:");
    println!("  Go:   {:?}", go_stw0);
    let rust_stw0: Vec<f64> = if !state0.hyperball_samples.is_empty() {
        state0.hyperball_samples[0].get_samples(10)
    } else {
        vec![0.0; 10]
    };
    println!("  Rust: {:?}", rust_stw0);
    // Allow small floating point differences
    let stw0_match = rust_stw0.iter().zip(go_stw0.iter()).all(|(r, g)| {
        (r - g).abs() < 0.001 || (r.abs() < 0.001 && g.abs() < 0.001)
    });
    println!("  Match (within tolerance): {}", stw0_match);
    println!();

    println!("Party 1 stw[0][0..10]:");
    println!("  Go:   {:?}", go_stw1);
    let rust_stw1: Vec<f64> = if !state1.hyperball_samples.is_empty() {
        state1.hyperball_samples[0].get_samples(10)
    } else {
        vec![0.0; 10]
    };
    println!("  Rust: {:?}", rust_stw1);
    let stw1_match = rust_stw1.iter().zip(go_stw1.iter()).all(|(r, g)| {
        (r - g).abs() < 0.001 || (r.abs() < 0.001 && g.abs() < 0.001)
    });
    println!("  Match (within tolerance): {}", stw1_match);
    println!();

    // Summary
    println!("=== SUMMARY ===");
    let all_match = c_tilde_match
        && c_poly_match
        && s1h0_match
        && s2h0_match
        && s1h1_match
        && s2h1_match
        && stw0_match
        && stw1_match;

    if all_match {
        println!("✅ ALL VALUES MATCH! Round 3 inputs are compatible with Go.");
    } else {
        println!("❌ SOME VALUES DO NOT MATCH!");
        if !c_tilde_match {
            println!("  - c_tilde mismatch");
        }
        if !c_poly_match {
            println!("  - c_poly mismatch");
        }
        if !s1h0_match {
            println!("  - Party 0 s1h mismatch");
        }
        if !s2h0_match {
            println!("  - Party 0 s2h mismatch");
        }
        if !s1h1_match {
            println!("  - Party 1 s1h mismatch");
        }
        if !s2h1_match {
            println!("  - Party 1 s2h mismatch");
        }
        if !stw0_match {
            println!("  - Party 0 hyperball samples mismatch");
        }
        if !stw1_match {
            println!("  - Party 1 hyperball samples mismatch");
        }
    }

    println!("\n=== END COMPARISON ===\n");

    // Don't assert yet - let's see what matches and what doesn't
    // assert!(all_match, "Round 3 values do not match Go reference");
}
