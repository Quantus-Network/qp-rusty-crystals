//! Deterministic 2-party aggregation test for threshold ML-DSA-87
//!
//! This test runs Round1 for both parties with fixed seeds and compares:
//! - Party 0's w values
//! - Party 1's w values
//! - Aggregated w values (w0 + w1)
//! - Computed mu
//!
//! Run with: cargo test --test test_aggregation -- --nocapture
//!
//! The output should be compared byte-for-byte with the Go equivalent test.

use qp_rusty_crystals_threshold::ml_dsa_87::{
    self, aggregate_commitments_dilithium, compute_mu, ThresholdConfig,
};

/// Helper to encode bytes as hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_deterministic_aggregation() {
    println!("=== RUST DETERMINISTIC 2-PARTY AGGREGATION TEST ===");
    println!();

    // Fixed seed for key generation (same as Go test)
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = i as u8;
    }

    // Fixed rhop for Party 0 (64 bytes) - same as Go test
    let mut rhop0 = [0u8; 64];
    for i in 0..64 {
        rhop0[i] = (i + 100) as u8;
    }

    // Fixed rhop for Party 1 (64 bytes) - same as Go test
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
    let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config)
        .expect("Key generation failed");

    println!("=== KEY GENERATION ===");
    println!("Public key (first 64 bytes): {}", hex_encode(&pk.packed[..64]));
    println!("Public key (last 32 bytes): {}", hex_encode(&pk.packed[pk.packed.len()-32..]));
    println!();

    // Generate commitments for both parties using deterministic function
    println!("=== ROUND 1: PARTY 0 COMMITMENT ===");
    let round1_result_0 = ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop0, 0);
    let (cmt0, state0) = match round1_result_0 {
        Ok((cmt, state)) => (cmt, state),
        Err(e) => {
            println!("Party 0 Round1 failed: {:?}", e);
            panic!("Party 0 Round1 failed");
        }
    };

    println!("Party 0 commitment hash: {}", hex_encode(&cmt0));
    let wbuf0 = state0.pack_commitment_canonical(&config);
    println!("Party 0 wbuf length: {} bytes", wbuf0.len());
    if wbuf0.len() >= 32 {
        println!("Party 0 wbuf[0..32]: {}", hex_encode(&wbuf0[..32]));
    }
    // Print w coefficients
    let w0_coeffs: Vec<i32> = state0.w.vec[0].coeffs[0..10].to_vec();
    println!("Party 0 w[0][0..10]: {:?}", w0_coeffs);
    println!();

    println!("=== ROUND 1: PARTY 1 COMMITMENT ===");
    let round1_result_1 = ml_dsa_87::Round1State::new_with_rhoprime(&sks[1], &config, &rhop1, 0);
    let (cmt1, state1) = match round1_result_1 {
        Ok((cmt, state)) => (cmt, state),
        Err(e) => {
            println!("Party 1 Round1 failed: {:?}", e);
            panic!("Party 1 Round1 failed");
        }
    };

    println!("Party 1 commitment hash: {}", hex_encode(&cmt1));
    let wbuf1 = state1.pack_commitment_canonical(&config);
    println!("Party 1 wbuf length: {} bytes", wbuf1.len());
    if wbuf1.len() >= 32 {
        println!("Party 1 wbuf[0..32]: {}", hex_encode(&wbuf1[..32]));
    }
    // Print w coefficients
    let w1_coeffs: Vec<i32> = state1.w.vec[0].coeffs[0..10].to_vec();
    println!("Party 1 w[0][0..10]: {:?}", w1_coeffs);
    println!();

    // Now aggregate the commitments
    println!("=== AGGREGATION ===");

    // Print values before aggregation
    println!("Before aggregation - w0[0][0][0..10]: {:?}", state0.w.vec[0].coeffs[0..10].to_vec());
    println!("Before aggregation - w1[0][0][0..10]: {:?}", state1.w.vec[0].coeffs[0..10].to_vec());

    // Aggregate: wAgg = w0 + w1
    let mut w_agg = state0.w.clone();
    aggregate_commitments_dilithium(&mut w_agg, &state1.w);

    // Print aggregated values
    let agg_coeffs: Vec<i32> = w_agg.vec[0].coeffs[0..10].to_vec();
    println!("After aggregation - wAgg[0][0][0..10]: {:?}", agg_coeffs);

    // Pack aggregated w and print
    let mut wbuf_agg = vec![0u8; qp_rusty_crystals_dilithium::params::K * 736]; // K * PolyQSize
    ml_dsa_87::Round1State::pack_w_dilithium(&w_agg, &mut wbuf_agg);
    println!("Aggregated wbuf[0..32]: {}", hex_encode(&wbuf_agg[..32]));
    println!();

    // Compute mu for the signing
    println!("=== MU COMPUTATION ===");
    let msg = b"test message";
    let ctx: &[u8] = b"";

    let mu0 = compute_mu(&pk.tr, msg, ctx);
    // Both parties should have the same tr, so mu1 would be the same
    // (but we compute it anyway for verification)
    let mu1 = compute_mu(&pk.tr, msg, ctx);

    println!("msg: {:?}", String::from_utf8_lossy(msg));
    println!("ctx: {:?}", String::from_utf8_lossy(ctx));
    println!("Party 0 mu: {}", hex_encode(&mu0));
    println!("Party 1 mu: {}", hex_encode(&mu1));
    println!("mu match: {}", mu0 == mu1);
    println!();

    // Now decompose the aggregated w
    println!("=== DECOMPOSE AGGREGATED W ===");
    let mut w0_dec = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
    let mut w1_dec = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
    ml_dsa_87::veck_decompose_go(&w_agg, &mut w0_dec, &mut w1_dec);

    let w0_dec_coeffs: Vec<u32> = w0_dec.vec[0].coeffs[0..10].iter().map(|&x| x as u32).collect();
    let w1_dec_coeffs: Vec<u32> = w1_dec.vec[0].coeffs[0..10].iter().map(|&x| x as u32).collect();
    println!("w0 (low bits + Q) [0][0..10]: {:?}", w0_dec_coeffs);
    println!("w1 (high bits) [0][0..10]: {:?}", w1_dec_coeffs);

    // Pack w1 for challenge computation
    use qp_rusty_crystals_dilithium::{polyvec, params as dilithium_params};
    let mut w1_packed = vec![0u8; dilithium_params::K * dilithium_params::POLYW1_PACKEDBYTES];
    polyvec::k_pack_w1(&mut w1_packed, &w1_dec);
    println!("w1_packed length: {} bytes", w1_packed.len());
    println!("w1_packed[0..32]: {}", hex_encode(&w1_packed[..32]));
    println!();

    // Compute challenge c = H(mu || w1)
    println!("=== CHALLENGE COMPUTATION ===");
    use qp_rusty_crystals_dilithium::fips202;
    let mut c_bytes = [0u8; dilithium_params::C_DASH_BYTES];
    let mut keccak_state = fips202::KeccakState::default();
    fips202::shake256_absorb(&mut keccak_state, &mu0, 64);
    fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
    fips202::shake256_finalize(&mut keccak_state);
    fips202::shake256_squeeze(&mut c_bytes, dilithium_params::C_DASH_BYTES, &mut keccak_state);
    println!("c_tilde (challenge bytes): {}", hex_encode(&c_bytes));

    println!();
    println!("=== END RUST DETERMINISTIC 2-PARTY AGGREGATION TEST ===");
}

/// Test to compare specific values with Go output
#[test]
fn test_compare_aggregation_with_go() {
    println!("\n=== COMPARISON WITH GO AGGREGATION OUTPUT ===\n");

    // Expected values from Go test
    let go_pk_first64 = "9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124adf69ff11fd4871c56ee2e2de51ac090254fcc1c5112207b7503173293a6b999";
    let go_pk_last32 = "e537bc41f374472eba222f57dd0205b164dc35929325b27a581ddcc3197c8317";
    let go_party0_cmt = "2f8e64fbbec8bc6e63c35b9ce314c60c1a1ea43d11f5e792cd93befdf63b447d";
    let go_party1_cmt = "8579cf68d13620e2a25426367c07bcc1d57ecc3dab04dc5a23b4f90e5bf60a2b";
    let go_party0_wbuf = "9dbe63b7dd294746af8abe6586380d656f78db6110c80eaaa2f0e7f6bbadd4dd";
    let go_party1_wbuf = "8717c7b2df9c49199237a14fa49edfece33757cda2f02d9e61fcd7305e4f23a8";
    let go_party0_w = [6536861i32, 5487470, 4004124, 3011669, 5474406, 912545, 1603294, 484360, 7381674, 7859663];
    let go_party1_w = [4659079i32, 3784549, 4744486, 8194492, 7989828, 8158619, 3364301, 1505361, 8151454, 3957167];
    let go_agg_w = [2815523i32, 891602, 368193, 2825744, 5083817, 690747, 4967595, 1989721, 7152711, 3436413];
    let go_agg_wbuf = "23f62a69cd46906701c263952ad9dc5154ac322fb3b83c4724edbe379afcff45";
    let go_mu = "4469257d594bfde28941d500e7cbe7f927ee9f62ef9b248a74798e1454097ab4181b0fa7182dc5db7da874048ac6af8e8330f053d9a7040a9aa6df49578bbf5b";
    let go_w0_dec = [8577060u32, 8224467, 8224834, 8587281, 8226474, 8547388, 8634028, 8275034, 8200264, 8150398];
    let go_w1_dec = [5u32, 2, 1, 5, 10, 1, 9, 4, 14, 7];
    let go_w1_packed = "25511a497e939084b13c4921195a1e0d548fd9916af34ad3567b61b6494ecc2e";
    let go_c_tilde = "cfe38d488242ae0bad39e0981582bfb52c4af448d599eb394a92ecb320e1f9faf53d63de54be1c933656ef20f05c389d005f1def0320761276b623281ed45b02";

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

    // Generate Round1 for both parties
    let (cmt0, state0) = ml_dsa_87::Round1State::new_with_rhoprime(&sks[0], &config, &rhop0, 0)
        .expect("Party 0 Round1 failed");
    let (cmt1, state1) = ml_dsa_87::Round1State::new_with_rhoprime(&sks[1], &config, &rhop1, 0)
        .expect("Party 1 Round1 failed");

    // Compare Party 0 commitment
    let rust_party0_cmt = hex_encode(&cmt0);
    println!("Party 0 commitment hash:");
    println!("  Go:   {}", go_party0_cmt);
    println!("  Rust: {}", rust_party0_cmt);
    println!("  Match: {}", rust_party0_cmt == go_party0_cmt);
    println!();

    // Compare Party 1 commitment
    let rust_party1_cmt = hex_encode(&cmt1);
    println!("Party 1 commitment hash:");
    println!("  Go:   {}", go_party1_cmt);
    println!("  Rust: {}", rust_party1_cmt);
    println!("  Match: {}", rust_party1_cmt == go_party1_cmt);
    println!();

    // Compare Party 0 wbuf
    let wbuf0 = state0.pack_commitment_canonical(&config);
    let rust_party0_wbuf = hex_encode(&wbuf0[..32]);
    println!("Party 0 wbuf[0..32]:");
    println!("  Go:   {}", go_party0_wbuf);
    println!("  Rust: {}", rust_party0_wbuf);
    println!("  Match: {}", rust_party0_wbuf == go_party0_wbuf);
    println!();

    // Compare Party 1 wbuf
    let wbuf1 = state1.pack_commitment_canonical(&config);
    let rust_party1_wbuf = hex_encode(&wbuf1[..32]);
    println!("Party 1 wbuf[0..32]:");
    println!("  Go:   {}", go_party1_wbuf);
    println!("  Rust: {}", rust_party1_wbuf);
    println!("  Match: {}", rust_party1_wbuf == go_party1_wbuf);
    println!();

    // Compare Party 0 w coefficients
    println!("Party 0 w[0][0..10]:");
    println!("  Go:   {:?}", go_party0_w);
    let rust_party0_w: Vec<i32> = state0.w.vec[0].coeffs[0..10].to_vec();
    println!("  Rust: {:?}", rust_party0_w);
    let w0_match = rust_party0_w.iter().zip(go_party0_w.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", w0_match);
    println!();

    // Compare Party 1 w coefficients
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
    let mut wbuf_agg = vec![0u8; qp_rusty_crystals_dilithium::params::K * 736]; // K * PolyQSize
    ml_dsa_87::Round1State::pack_w_dilithium(&w_agg, &mut wbuf_agg);
    let rust_agg_wbuf = hex_encode(&wbuf_agg[..32]);
    println!("Aggregated wbuf[0..32]:");
    println!("  Go:   {}", go_agg_wbuf);
    println!("  Rust: {}", rust_agg_wbuf);
    println!("  Match: {}", rust_agg_wbuf == go_agg_wbuf);
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

    // Compare decompose
    let mut w0_dec = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
    let mut w1_dec = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
    ml_dsa_87::veck_decompose_go(&w_agg, &mut w0_dec, &mut w1_dec);

    println!("w0 (low bits + Q) [0][0..10]:");
    println!("  Go:   {:?}", go_w0_dec);
    let rust_w0_dec: Vec<u32> = w0_dec.vec[0].coeffs[0..10].iter().map(|&x| x as u32).collect();
    println!("  Rust: {:?}", rust_w0_dec);
    let w0_dec_match = rust_w0_dec.iter().zip(go_w0_dec.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", w0_dec_match);
    println!();

    println!("w1 (high bits) [0][0..10]:");
    println!("  Go:   {:?}", go_w1_dec);
    let rust_w1_dec: Vec<u32> = w1_dec.vec[0].coeffs[0..10].iter().map(|&x| x as u32).collect();
    println!("  Rust: {:?}", rust_w1_dec);
    let w1_dec_match = rust_w1_dec.iter().zip(go_w1_dec.iter()).all(|(r, g)| *r == *g);
    println!("  Match: {}", w1_dec_match);
    println!();

    // Compare w1 packed
    use qp_rusty_crystals_dilithium::{polyvec, params as dilithium_params};
    let mut w1_packed = vec![0u8; dilithium_params::K * dilithium_params::POLYW1_PACKEDBYTES];
    polyvec::k_pack_w1(&mut w1_packed, &w1_dec);
    let rust_w1_packed = hex_encode(&w1_packed[..32]);
    println!("w1_packed[0..32]:");
    println!("  Go:   {}", go_w1_packed);
    println!("  Rust: {}", rust_w1_packed);
    println!("  Match: {}", rust_w1_packed == go_w1_packed);
    println!();

    // Compare challenge
    use qp_rusty_crystals_dilithium::fips202;
    let mut c_bytes = [0u8; dilithium_params::C_DASH_BYTES];
    let mut keccak_state = fips202::KeccakState::default();
    fips202::shake256_absorb(&mut keccak_state, &mu, 64);
    fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
    fips202::shake256_finalize(&mut keccak_state);
    fips202::shake256_squeeze(&mut c_bytes, dilithium_params::C_DASH_BYTES, &mut keccak_state);
    let rust_c_tilde = hex_encode(&c_bytes);
    println!("c_tilde (challenge bytes):");
    println!("  Go:   {}", go_c_tilde);
    println!("  Rust: {}", rust_c_tilde);
    println!("  Match: {}", rust_c_tilde == go_c_tilde);
    println!();

    // Summary
    println!("=== SUMMARY ===");
    let all_match = rust_pk_first64 == go_pk_first64
        && rust_pk_last32 == go_pk_last32
        && rust_party0_cmt == go_party0_cmt
        && rust_party1_cmt == go_party1_cmt
        && rust_party0_wbuf == go_party0_wbuf
        && rust_party1_wbuf == go_party1_wbuf
        && w0_match
        && w1_match
        && agg_match
        && rust_agg_wbuf == go_agg_wbuf
        && rust_mu == go_mu
        && w0_dec_match
        && w1_dec_match
        && rust_w1_packed == go_w1_packed
        && rust_c_tilde == go_c_tilde;

    if all_match {
        println!("✅ ALL VALUES MATCH! Aggregation is compatible with Go.");
    } else {
        println!("❌ SOME VALUES DO NOT MATCH!");
    }

    println!("\n=== END COMPARISON ===\n");

    // Assert all values match
    assert!(all_match, "Aggregation values do not match Go reference");
}
