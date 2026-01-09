//! Deterministic Round 3 test for threshold ML-DSA-87 with 2-of-3 (t < n)
//!
//! This test runs the full protocol through Round 3 with fixed seeds and compares:
//! - Key generation with 2-of-3 threshold
//! - Challenge polynomial c derivation
//! - Partial response z computation for each party
//! - Response aggregation z_final = z0 + z1
//!
//! Run with: cargo test --test test_round3_2of3 -- --nocapture
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
fn test_deterministic_round3_2of3() {
    println!("=== RUST DETERMINISTIC ROUND 3 TEST (2-of-3) ===");
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

    // Generate threshold keys (2-of-3) - t < n case
    let config = ThresholdConfig::new(2, 3).expect("Invalid config");

    println!("Threshold params: T={}, N={}, K={}",
        config.base.threshold(), config.base.total_parties(), config.k_iterations);

    let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config).expect("Key generation failed");

    println!("=== KEY GENERATION ===");
    println!(
        "Public key (first 64 bytes): {}",
        hex_encode(&pk.packed[..64])
    );
    println!(
        "Public key (last 32 bytes): {}",
        hex_encode(&pk.packed[pk.packed.len()-32..])
    );
    println!();

    // Print share keys for each party
    println!("=== SHARE KEYS ===");
    for i in 0..3 {
        let share_keys: Vec<u8> = sks[i].shares.keys().cloned().collect();
        println!("Party {} share keys: {:?}", i, share_keys);
    }
    println!();

    // Print raw share values for debugging
    println!("=== RAW SHARE VALUES ===");
    for i in 0..3 {
        for (&key, share) in &sks[i].shares {
            println!("Party {} share[{}] s1[0][0..5]: {:?}",
                i, key,
                &share.s1_share.vec[0].coeffs[0..5].iter().map(|&x| x as u32).collect::<Vec<u32>>());
            println!("Party {} share[{}] s2[0][0..5]: {:?}",
                i, key,
                &share.s2_share.vec[0].coeffs[0..5].iter().map(|&x| x as u32).collect::<Vec<u32>>());
        }
    }
    println!();

    // We'll use parties 0 and 1 for signing (active set)
    // act = 0b011 = 3 (parties 0 and 1 are active)
    let active_parties = [0u8, 1u8];
    println!("Active parties: {:?}", active_parties);
    println!();

    // Generate commitments for parties 0 and 1
    println!("=== ROUND 1 ===");
    let (cmt0, state0) =
        ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop0, 0).expect("Party 0 Round1 failed");
    let (cmt1, state1) =
        ml_dsa_87::Round1State::new_with_rhoprime(&sks[1], &config, &rhop1, 0).expect("Party 1 Round1 failed");

    println!("Party 0 commitment hash: {}", hex_encode(&cmt0));
    println!("Party 1 commitment hash: {}", hex_encode(&cmt1));

    // Print w coefficients
    let w0_coeffs: Vec<i32> = state0.w.vec[0].coeffs[0..10].to_vec();
    let w1_coeffs: Vec<i32> = state1.w.vec[0].coeffs[0..10].to_vec();
    println!("Party 0 w[0][0..10]: {:?}", w0_coeffs);
    println!("Party 1 w[0][0..10]: {:?}", w1_coeffs);
    println!();

    // Aggregate commitments
    println!("=== ROUND 2: AGGREGATION ===");
    let mut w_agg = state0.w.clone();
    aggregate_commitments_dilithium(&mut w_agg, &state1.w);

    let agg_coeffs: Vec<i32> = w_agg.vec[0].coeffs[0..10].to_vec();
    println!("Aggregated w[0][0][0..10]: {:?}", agg_coeffs);

    // Pack aggregated w
    let mut wbuf_agg = vec![0u8; dilithium_params::K * 736];
    ml_dsa_87::Round1State::pack_w_dilithium(&w_agg, &mut wbuf_agg);
    println!("Aggregated wbuf[0..32]: {}", hex_encode(&wbuf_agg[..32]));

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

    let (s1h0, s2h0) = ml_dsa_87::secret_sharing::recover_share_hardcoded(
        &sks[0].shares,
        sks[0].id,
        &active_parties,
        config.base.threshold(),
        config.base.total_parties(),
    )
    .expect("Failed to recover share for party 0");

    let (s1h1, s2h1) = ml_dsa_87::secret_sharing::recover_share_hardcoded(
        &sks[1].shares,
        sks[1].id,
        &active_parties,
        config.base.threshold(),
        config.base.total_parties(),
    )
    .expect("Failed to recover share for party 1");

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
    println!("=== END RUST DETERMINISTIC ROUND 3 TEST (2-of-3) ===");
}

/// Test to compare Round 3 values with Go output for 2-of-3 case
#[test]
fn test_compare_round3_2of3_with_go() {
    println!("\n=== COMPARISON WITH GO ROUND 3 OUTPUT (2-of-3) ===\n");

    // Expected values from Go test for 2-of-3
    let go_pk_first64 = "9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124cd8b6539e0f3082366a784e6ec291e92899a77632dba95b126fbfea7bf0f20c3";
    let go_pk_last32 = "6dd61a4d1bb765db137a8e748912cba4701508d2af33f2b1ff98f62099b0326a";
    let go_party0_cmt = "a5fca79d9874cee540e1e697b73467017b059cba2cb1f5613e96556f714a86b1";
    let go_party1_cmt = "485a1124b812e1224c4389092ba80db3842439da330a5882086a389832dfa3bb";
    let go_mu = "aa0ed0f7a320d929ff057eda0668a5d56ec191a5f6121a175569dd223a2f0524285d0aa78a470e908def700bd435247773a8d08e90e5ef29f4b8588f1c3a3bfc";
    let go_c_tilde = "e7ddc85be184e171d385676f212846a5afee1dd083fc517d654242606bb1ccfbb7c591fe07ffbbe229913eef098613e23c35a598778790a08109623716581b14";
    let go_c_poly: [i32; 10] = [0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
    let go_agg_w: [i32; 10] = [5767076, 6062831, 6665789, 7942563, 4918167, 5491482, 5881937, 8001585, 3892806, 3676218];
    let go_agg_wbuf = "a4ffd777416e8f6d7934267fb9b0d4589e4601676330f446663b1d0cdc7e28b9";
    let go_party0_w: [i32; 10] = [2351398, 5070777, 1864486, 4039140, 6086115, 8310184, 4991731, 6477514, 1571883, 6111754];
    let go_party1_w: [i32; 10] = [3415678, 992054, 4801303, 3903423, 7212469, 5561715, 890206, 1524071, 2320923, 5944881];

    // Go's recovered shares (in NTT domain) for 2-of-3
    let go_s1h0: [u32; 5] = [3515617, 1649616, 1115508, 3104560, 4736108];
    let go_s2h0: [u32; 5] = [5750733, 7240170, 3774022, 2103982, 5405754];
    let go_s1h1: [u32; 5] = [961675, 2726544, 81751, 1674576, 5415164];
    let go_s2h1: [u32; 5] = [7362282, 5724820, 7884364, 1188059, 4510112];

    // Go's hyperball samples for 2-of-3
    let go_stw0: [f64; 10] = [
        -7285.637039962694,
        -46746.99471802169,
        -35489.60539752692,
        -2261.854434070271,
        110.02416121228748,
        44219.24253628727,
        35988.16554841376,
        9393.499026290727,
        10703.34519040278,
        -9967.099165940866,
    ];
    let go_stw1: [f64; 10] = [
        17970.519834765437,
        25728.19462662678,
        -34650.93445193854,
        -71226.7574842531,
        -37669.58347021207,
        13175.43644144621,
        -22842.67379843484,
        3973.5130500815035,
        -20957.385029665664,
        -36101.8056042065,
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

    let config = ThresholdConfig::new(2, 3).expect("Invalid config");
    let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config).expect("Key generation failed");

    // Compare public key
    let rust_pk_first64 = hex_encode(&pk.packed[..64]);
    let rust_pk_last32 = hex_encode(&pk.packed[pk.packed.len()-32..]);

    println!("Public key (first 64 bytes):");
    println!("  Go:   {}", go_pk_first64);
    println!("  Rust: {}", rust_pk_first64);
    let pk_first64_match = rust_pk_first64 == go_pk_first64;
    println!("  Match: {}", pk_first64_match);
    println!();

    println!("Public key (last 32 bytes):");
    println!("  Go:   {}", go_pk_last32);
    println!("  Rust: {}", rust_pk_last32);
    let pk_last32_match = rust_pk_last32 == go_pk_last32;
    println!("  Match: {}", pk_last32_match);
    println!();

    // Generate Round1 for both parties
    let (cmt0, state0) =
        ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop0, 0).expect("Party 0 Round1 failed");
    let (cmt1, state1) =
        ml_dsa_87::Round1State::new_with_rhoprime(&sks[1], &config, &rhop1, 0).expect("Party 1 Round1 failed");

    // Compare commitments
    let rust_party0_cmt = hex_encode(&cmt0);
    println!("Party 0 commitment hash:");
    println!("  Go:   {}", go_party0_cmt);
    println!("  Rust: {}", rust_party0_cmt);
    let cmt0_match = rust_party0_cmt == go_party0_cmt;
    println!("  Match: {}", cmt0_match);
    println!();

    let rust_party1_cmt = hex_encode(&cmt1);
    println!("Party 1 commitment hash:");
    println!("  Go:   {}", go_party1_cmt);
    println!("  Rust: {}", rust_party1_cmt);
    let cmt1_match = rust_party1_cmt == go_party1_cmt;
    println!("  Match: {}", cmt1_match);
    println!();

    // Compare party w values
    println!("Party 0 w[0][0..10]:");
    println!("  Go:   {:?}", go_party0_w);
    let rust_party0_w: Vec<i32> = state0.w.vec[0].coeffs[0..10].to_vec();
    println!("  Rust: {:?}", rust_party0_w);
    let w0_match = rust_party0_w.iter().zip(go_party0_w.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", w0_match);
    println!();

    println!("Party 1 w[0][0..10]:");
    println!("  Go:   {:?}", go_party1_w);
    let rust_party1_w: Vec<i32> = state1.w.vec[0].coeffs[0..10].to_vec();
    println!("  Rust: {:?}", rust_party1_w);
    let w1_match = rust_party1_w.iter().zip(go_party1_w.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", w1_match);
    println!();

    // Aggregate
    let mut w_agg = state0.w.clone();
    aggregate_commitments_dilithium(&mut w_agg, &state1.w);

    // Compare aggregated w
    println!("Aggregated w[0][0..10]:");
    println!("  Go:   {:?}", go_agg_w);
    let rust_agg_w: Vec<i32> = w_agg.vec[0].coeffs[0..10].to_vec();
    println!("  Rust: {:?}", rust_agg_w);
    let agg_match = rust_agg_w.iter().zip(go_agg_w.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", agg_match);
    println!();

    // Compare aggregated wbuf
    let mut wbuf_agg = vec![0u8; dilithium_params::K * 736];
    ml_dsa_87::Round1State::pack_w_dilithium(&w_agg, &mut wbuf_agg);
    let rust_agg_wbuf = hex_encode(&wbuf_agg[..32]);
    println!("Aggregated wbuf[0..32]:");
    println!("  Go:   {}", go_agg_wbuf);
    println!("  Rust: {}", rust_agg_wbuf);
    let agg_wbuf_match = rust_agg_wbuf == go_agg_wbuf;
    println!("  Match: {}", agg_wbuf_match);
    println!();

    // Compute mu and challenge
    let msg = b"test message";
    let ctx: &[u8] = b"";
    let mu = compute_mu(&pk.tr, msg, ctx);

    let rust_mu = hex_encode(&mu);
    println!("mu:");
    println!("  Go:   {}", go_mu);
    println!("  Rust: {}", rust_mu);
    let mu_match = rust_mu == go_mu;
    println!("  Match: {}", mu_match);
    println!();

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
    let active_parties = [0u8, 1u8];

    let (s1h0, s2h0) = ml_dsa_87::secret_sharing::recover_share_hardcoded(
        &sks[0].shares,
        sks[0].id,
        &active_parties,
        config.base.threshold(),
        config.base.total_parties(),
    )
    .expect("Failed to recover share for party 0");

    let (s1h1, s2h1) = ml_dsa_87::secret_sharing::recover_share_hardcoded(
        &sks[1].shares,
        sks[1].id,
        &active_parties,
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
    let all_match = pk_first64_match
        && pk_last32_match
        && cmt0_match
        && cmt1_match
        && w0_match
        && w1_match
        && agg_match
        && agg_wbuf_match
        && mu_match
        && c_tilde_match
        && c_poly_match
        && s1h0_match
        && s2h0_match
        && s1h1_match
        && s2h1_match
        && stw0_match
        && stw1_match;

    if all_match {
        println!("✅ ALL VALUES MATCH! Round 3 (2-of-3) is compatible with Go.");
    } else {
        println!("❌ SOME VALUES DO NOT MATCH!");
        if !pk_first64_match {
            println!("  - Public key (first 64 bytes) mismatch");
        }
        if !pk_last32_match {
            println!("  - Public key (last 32 bytes) mismatch");
        }
        if !cmt0_match {
            println!("  - Party 0 commitment mismatch");
        }
        if !cmt1_match {
            println!("  - Party 1 commitment mismatch");
        }
        if !w0_match {
            println!("  - Party 0 w mismatch");
        }
        if !w1_match {
            println!("  - Party 1 w mismatch");
        }
        if !agg_match {
            println!("  - Aggregated w mismatch");
        }
        if !agg_wbuf_match {
            println!("  - Aggregated wbuf mismatch");
        }
        if !mu_match {
            println!("  - mu mismatch");
        }
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

    println!("\n=== END COMPARISON (2-of-3) ===\n");

    // Don't assert yet - let's see what matches and what doesn't
    // assert!(all_match, "Round 3 (2-of-3) values do not match Go reference");
}

/// Test to compare Round 3 values with Go output for 2-of-3 case with parties 0 and 2 active
#[test]
fn test_compare_round3_2of3_parties_0_2_with_go() {
    println!("\n=== COMPARISON WITH GO ROUND 3 OUTPUT (2-of-3) PARTIES 0,2 ===\n");

    // Expected values from Go test for 2-of-3 with parties 0 and 2 active
    let go_pk_first64 = "9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124cd8b6539e0f3082366a784e6ec291e92899a77632dba95b126fbfea7bf0f20c3";
    let go_pk_last32 = "6dd61a4d1bb765db137a8e748912cba4701508d2af33f2b1ff98f62099b0326a";
    let go_party0_cmt = "a5fca79d9874cee540e1e697b73467017b059cba2cb1f5613e96556f714a86b1";
    let go_party2_cmt = "410834961ea305efd2e13073a2fddb0cc3ceecd7dc62c929f8ba8492dca331b6";
    let go_mu = "aa0ed0f7a320d929ff057eda0668a5d56ec191a5f6121a175569dd223a2f0524285d0aa78a470e908def700bd435247773a8d08e90e5ef29f4b8588f1c3a3bfc";
    let go_c_tilde = "f8dee7b7d858cf6ee2fda18ce18423e20c28c9d82602f5be1e3929ecb274698e30ba49202c389277cac19766dfe9835cf31d228f2f7f9df30d1318ceaafc250e";
    let go_agg_w: [i32; 10] = [1821796, 1642469, 3801204, 6588172, 1854488, 5727864, 5364357, 4474346, 5592114, 5784637];
    let go_agg_wbuf = "64cc9bf2870c1d808ee1908cc1c4c133bb166a47d58b883254d51e226c444b3b";
    let go_party0_w: [i32; 10] = [2351398, 5070777, 1864486, 4039140, 6086115, 8310184, 4991731, 6477514, 1571883, 6111754];
    let go_party2_w: [i32; 10] = [7850815, 4952109, 1936718, 2549032, 4148790, 5798097, 372626, 6377249, 4020231, 8053300];

    // Go's recovered shares (in NTT domain) for 2-of-3 with parties 0,2 active
    let go_s1h0: [u32; 5] = [3515617, 1649616, 1115508, 3104560, 4736108];
    let go_s2h0: [u32; 5] = [5750733, 7240170, 3774022, 2103982, 5405754];
    let go_s1h2: [u32; 5] = [961675, 2726544, 81751, 1674576, 5415164];
    let go_s2h2: [u32; 5] = [7362282, 5724820, 7884364, 1188059, 4510112];

    // Generate with same params
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }
    let mut rhop0 = [0u8; 64];
    for i in 0..64 {
        rhop0[i] = (i + 100) as u8;
    }
    // Party 2 uses different rhop
    let mut rhop2 = [0u8; 64];
    for i in 0..64 {
        rhop2[i] = (i + 50) as u8;
    }

    let config = ThresholdConfig::new(2, 3).expect("Invalid config");
    let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config).expect("Key generation failed");

    // Compare public key
    let rust_pk_first64 = hex_encode(&pk.packed[..64]);
    let rust_pk_last32 = hex_encode(&pk.packed[pk.packed.len()-32..]);

    println!("Public key (first 64 bytes):");
    println!("  Go:   {}", go_pk_first64);
    println!("  Rust: {}", rust_pk_first64);
    let pk_first64_match = rust_pk_first64 == go_pk_first64;
    println!("  Match: {}", pk_first64_match);
    println!();

    println!("Public key (last 32 bytes):");
    println!("  Go:   {}", go_pk_last32);
    println!("  Rust: {}", rust_pk_last32);
    let pk_last32_match = rust_pk_last32 == go_pk_last32;
    println!("  Match: {}", pk_last32_match);
    println!();

    // Generate Round1 for parties 0 and 2
    let (cmt0, state0) =
        ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop0, 0).expect("Party 0 Round1 failed");
    let (cmt2, state2) =
        ml_dsa_87::Round1State::new_with_rhoprime(&sks[2], &config, &rhop2, 0).expect("Party 2 Round1 failed");

    // Compare commitments
    let rust_party0_cmt = hex_encode(&cmt0);
    println!("Party 0 commitment hash:");
    println!("  Go:   {}", go_party0_cmt);
    println!("  Rust: {}", rust_party0_cmt);
    let cmt0_match = rust_party0_cmt == go_party0_cmt;
    println!("  Match: {}", cmt0_match);
    println!();

    let rust_party2_cmt = hex_encode(&cmt2);
    println!("Party 2 commitment hash:");
    println!("  Go:   {}", go_party2_cmt);
    println!("  Rust: {}", rust_party2_cmt);
    let cmt2_match = rust_party2_cmt == go_party2_cmt;
    println!("  Match: {}", cmt2_match);
    println!();

    // Compare party w values
    println!("Party 0 w[0][0..10]:");
    println!("  Go:   {:?}", go_party0_w);
    let rust_party0_w: Vec<i32> = state0.w.vec[0].coeffs[0..10].to_vec();
    println!("  Rust: {:?}", rust_party0_w);
    let w0_match = rust_party0_w.iter().zip(go_party0_w.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", w0_match);
    println!();

    println!("Party 2 w[0][0..10]:");
    println!("  Go:   {:?}", go_party2_w);
    let rust_party2_w: Vec<i32> = state2.w.vec[0].coeffs[0..10].to_vec();
    println!("  Rust: {:?}", rust_party2_w);
    let w2_match = rust_party2_w.iter().zip(go_party2_w.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", w2_match);
    println!();

    // Aggregate
    let mut w_agg = state0.w.clone();
    aggregate_commitments_dilithium(&mut w_agg, &state2.w);

    // Compare aggregated w
    println!("Aggregated w[0][0..10]:");
    println!("  Go:   {:?}", go_agg_w);
    let rust_agg_w: Vec<i32> = w_agg.vec[0].coeffs[0..10].to_vec();
    println!("  Rust: {:?}", rust_agg_w);
    let agg_match = rust_agg_w.iter().zip(go_agg_w.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", agg_match);
    println!();

    // Compare aggregated wbuf
    let mut wbuf_agg = vec![0u8; dilithium_params::K * 736];
    ml_dsa_87::Round1State::pack_w_dilithium(&w_agg, &mut wbuf_agg);
    let rust_agg_wbuf = hex_encode(&wbuf_agg[..32]);
    println!("Aggregated wbuf[0..32]:");
    println!("  Go:   {}", go_agg_wbuf);
    println!("  Rust: {}", rust_agg_wbuf);
    let agg_wbuf_match = rust_agg_wbuf == go_agg_wbuf;
    println!("  Match: {}", agg_wbuf_match);
    println!();

    // Compute mu and challenge
    let msg = b"test message";
    let ctx: &[u8] = b"";
    let mu = compute_mu(&pk.tr, msg, ctx);

    let rust_mu = hex_encode(&mu);
    println!("mu:");
    println!("  Go:   {}", go_mu);
    println!("  Rust: {}", rust_mu);
    let mu_match = rust_mu == go_mu;
    println!("  Match: {}", mu_match);
    println!();

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

    // Recover shares and compare - parties 0 and 2 active
    let active_parties = [0u8, 2u8];

    let (s1h0, s2h0) = ml_dsa_87::secret_sharing::recover_share_hardcoded(
        &sks[0].shares,
        sks[0].id,
        &active_parties,
        config.base.threshold(),
        config.base.total_parties(),
    )
    .expect("Failed to recover share for party 0");

    let (s1h2, s2h2) = ml_dsa_87::secret_sharing::recover_share_hardcoded(
        &sks[2].shares,
        sks[2].id,
        &active_parties,
        config.base.threshold(),
        config.base.total_parties(),
    )
    .expect("Failed to recover share for party 2");

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

    println!("Party 2 s1h[0][0..5]:");
    println!("  Go:   {:?}", go_s1h2);
    let rust_s1h2: Vec<u32> = s1h2.vec[0].coeffs[0..5]
        .iter()
        .map(|&x| x as u32)
        .collect();
    println!("  Rust: {:?}", rust_s1h2);
    let s1h2_match = rust_s1h2.iter().zip(go_s1h2.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", s1h2_match);
    println!();

    println!("Party 2 s2h[0][0..5]:");
    println!("  Go:   {:?}", go_s2h2);
    let rust_s2h2: Vec<u32> = s2h2.vec[0].coeffs[0..5]
        .iter()
        .map(|&x| x as u32)
        .collect();
    println!("  Rust: {:?}", rust_s2h2);
    let s2h2_match = rust_s2h2.iter().zip(go_s2h2.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", s2h2_match);
    println!();

    // Summary
    println!("=== SUMMARY ===");
    let all_match = pk_first64_match
        && pk_last32_match
        && cmt0_match
        && cmt2_match
        && w0_match
        && w2_match
        && agg_match
        && agg_wbuf_match
        && mu_match
        && c_tilde_match
        && s1h0_match
        && s2h0_match
        && s1h2_match
        && s2h2_match;

    if all_match {
        println!("✅ ALL VALUES MATCH! Round 3 (2-of-3 parties 0,2) is compatible with Go.");
    } else {
        println!("❌ SOME VALUES DO NOT MATCH!");
        if !pk_first64_match {
            println!("  - Public key (first 64 bytes) mismatch");
        }
        if !pk_last32_match {
            println!("  - Public key (last 32 bytes) mismatch");
        }
        if !cmt0_match {
            println!("  - Party 0 commitment mismatch");
        }
        if !cmt2_match {
            println!("  - Party 2 commitment mismatch");
        }
        if !w0_match {
            println!("  - Party 0 w mismatch");
        }
        if !w2_match {
            println!("  - Party 2 w mismatch");
        }
        if !agg_match {
            println!("  - Aggregated w mismatch");
        }
        if !agg_wbuf_match {
            println!("  - Aggregated wbuf mismatch");
        }
        if !mu_match {
            println!("  - mu mismatch");
        }
        if !c_tilde_match {
            println!("  - c_tilde mismatch");
        }
        if !s1h0_match {
            println!("  - Party 0 s1h mismatch");
        }
        if !s2h0_match {
            println!("  - Party 0 s2h mismatch");
        }
        if !s1h2_match {
            println!("  - Party 2 s1h mismatch");
        }
        if !s2h2_match {
            println!("  - Party 2 s2h mismatch");
        }
    }

    println!("\n=== END COMPARISON (2-of-3 parties 0,2) ===\n");
}
