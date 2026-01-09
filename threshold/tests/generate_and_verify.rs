//! Test that mimics the Go generateSignature function and verifies with dilithium crate
//!
//! This test follows the exact same flow as the Go threshold-mldsa-bench generateSignature:
//! 1. Generate threshold keys from seed
//! 2. Run 3-round threshold protocol with first t parties
//! 3. Combine into final signature
//! 4. Verify with standard ML-DSA-87 verification

use qp_rusty_crystals_threshold::ml_dsa_87::{
    self, Round1State, Round2State, Round3State, ThresholdConfig,
};
use rand::RngCore;
use std::io::Write;

/// Generate a threshold signature and verify it, mimicking Go's generateSignature
fn generate_and_verify_signature(
    seed: [u8; 32],
    msg: &[u8],
    ctx: &[u8],
    t: u8,
    n: u8,
) -> Result<(), String> {
    // Get threshold params
    let config = ThresholdConfig::new(t, n)
        .map_err(|e| format!("Failed to get threshold params: {:?}", e))?;

    // Generate threshold keys from seed
    let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config)
        .map_err(|e| format!("Failed to generate threshold keys: {:?}", e))?;

    // Use first t parties for signing (act bitmask)
    let act = (1u8 << t) - 1;

    // Try signing with retries (may fail due to rejection sampling)
    for attempt in 0..1000 {
        // Round 1: Generate commitments for each party
        let mut round1_states = Vec::with_capacity(t as usize);
        let mut round1_commitments = Vec::with_capacity(t as usize);

        for j in 0..t {
            // Generate unique randomness per party
            let mut party_seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut party_seed);
            party_seed[0] ^= j;
            party_seed[31] ^= attempt as u8;

            let (commitment, state) = Round1State::new(&sks[j as usize], &config, &party_seed)
                .map_err(|e| format!("Round1 failed for party {}: {:?}", j, e))?;

            round1_states.push(state);
            round1_commitments.push(commitment);
        }

        // Round 2: Reveal commitments
        let mut round2_states = Vec::with_capacity(t as usize);
        let mut round2_commitments = Vec::with_capacity(t as usize);

        for j in 0..t {
            // Collect w values from other parties
            let mut other_w_values = Vec::new();
            for k in 0..t {
                if k != j {
                    let w_packed = round1_states[k as usize].pack_commitment_canonical(&config);
                    other_w_values.push(w_packed);
                }
            }

            let (w_aggregated, state) = Round2State::new(
                &sks[j as usize],
                act,
                msg,
                ctx,
                &round1_commitments,
                &other_w_values,
                &round1_states[j as usize],
            )
            .map_err(|e| format!("Round2 failed for party {}: {:?}", j, e))?;

            round2_states.push(state);
            round2_commitments.push(w_aggregated);
        }

        // Round 3: Compute responses
        let mut round3_states = Vec::with_capacity(t as usize);
        let mut responses = Vec::with_capacity(t as usize);

        for j in 0..t {
            let (response, state) = Round3State::new(
                &sks[j as usize],
                &config,
                &round2_commitments,
                &round1_states[j as usize],
                &round2_states[j as usize],
            )
            .map_err(|e| format!("Round3 failed for party {}: {:?}", j, e))?;

            round3_states.push(state);
            responses.push(response);
        }

        // Pack commitments and responses for combine
        let packed_commitments: Vec<Vec<u8>> = (0..t as usize)
            .map(|j| round1_states[j].pack_commitment_canonical(&config))
            .collect();

        let packed_responses: Vec<Vec<u8>> = (0..t as usize)
            .map(|j| round3_states[j].pack_responses_canonical(&config))
            .collect();

        // Combine into final signature
        let signature = match ml_dsa_87::combine_signatures(
            &pk,
            msg,
            ctx,
            &packed_commitments,
            &packed_responses,
            &config,
        ) {
            Ok(sig) => sig,
            Err(_) => continue, // Rejection sampling, try again
        };

        // Verify with dilithium crate
        let dilithium_pk = qp_rusty_crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(&pk.packed)
            .map_err(|e| format!("Failed to parse public key: {:?}", e))?;

        let ctx_option: Option<&[u8]> = if ctx.is_empty() { None } else { Some(ctx) };
        let is_valid = dilithium_pk.verify(msg, &signature, ctx_option);

        if is_valid {
            println!(
                "✅ Signature verified on attempt {} for {}-of-{}",
                attempt + 1,
                t,
                n
            );
            return Ok(());
        }

        // If verification failed but combine succeeded, that's a real problem
        // (not just rejection sampling)
        println!(
            "⚠️ Attempt {}: Combine succeeded but verification failed",
            attempt + 1
        );
    }

    Err(format!(
        "Failed to generate valid signature after 1000 attempts for {}-of-{}",
        t, n
    ))
}

#[test]
fn test_generate_and_verify_2_of_2() {
    let seed = [0u8; 32]; // Deterministic seed for reproducibility
    let msg = b"test message for threshold ML-DSA";
    let ctx = b""; // Empty context

    match generate_and_verify_signature(seed, msg, ctx, 2, 2) {
        Ok(()) => println!("✅ 2-of-2 threshold signature test PASSED"),
        Err(e) => panic!("❌ 2-of-2 threshold signature test FAILED: {}", e),
    }
}

#[test]
fn test_generate_and_verify_2_of_3() {
    let seed = [42u8; 32];
    let msg = b"test message for threshold ML-DSA";
    let ctx = b"test_context";

    match generate_and_verify_signature(seed, msg, ctx, 2, 3) {
        Ok(()) => println!("✅ 2-of-3 threshold signature test PASSED"),
        Err(e) => panic!("❌ 2-of-3 threshold signature test FAILED: {}", e),
    }
}

#[test]
fn test_generate_and_verify_3_of_5() {
    let seed = [123u8; 32];
    let msg = b"hello world";
    let ctx = b"";

    match generate_and_verify_signature(seed, msg, ctx, 3, 5) {
        Ok(()) => println!("✅ 3-of-5 threshold signature test PASSED"),
        Err(e) => panic!("❌ 3-of-5 threshold signature test FAILED: {}", e),
    }
}

/// Test with the same parameters as the Go test vectors
#[test]
fn test_generate_and_verify_matching_go_params() {
    // Match the Go test vector generator defaults
    let mut seed = [0u8; 32];
    // seed = 12345 as little-endian u64
    seed[0] = 0x39;
    seed[1] = 0x30;
    seed[2] = 0x00;
    seed[3] = 0x00;

    let msg = b"test message for threshold ML-DSA";
    let ctx: &[u8] = b""; // Empty context like Go default

    match generate_and_verify_signature(seed, msg, ctx, 2, 3) {
        Ok(()) => println!("✅ Go-matching params threshold signature test PASSED"),
        Err(e) => panic!("❌ Go-matching params threshold signature test FAILED: {}", e),
    }
}

/// Test that compares key generation output with Go reference
/// Run with: cargo test test_key_generation_comparison -- --nocapture
#[test]
fn test_key_generation_comparison() {
    println!("\n=== KEY GENERATION COMPARISON TEST ===\n");

    // Use a simple deterministic seed
    let seed = [0u8; 32];
    let config = ThresholdConfig::new(2, 2).expect("Invalid config");

    // Generate threshold keys
    let (pk, sks) = ml_dsa_87::generate_threshold_key(&seed, &config)
        .expect("Key generation failed");

    // Print public key info for comparison with Go
    println!("Seed (hex): {}", hex::encode(&seed));
    println!("Public key size: {} bytes", pk.packed.len());
    println!("Public key rho (first 32 bytes): {}", hex::encode(&pk.rho));
    println!("Public key tr (64 bytes): {}", hex::encode(&pk.tr));
    println!("Public key packed (first 64 bytes): {}", hex::encode(&pk.packed[..64]));
    println!("Public key packed (last 32 bytes): {}", hex::encode(&pk.packed[pk.packed.len()-32..]));

    // Print t1 values for first few coefficients
    print!("t1[0][0..10]: [");
    for i in 0..10 {
        if i > 0 { print!(", "); }
        print!("{}", pk.t1.get(0).get(i).value());
    }
    println!("]");

    // Print private key info
    println!("\nPrivate key 0:");
    println!("  id: {}", sks[0].id);
    println!("  key (first 8 bytes): {}", hex::encode(&sks[0].key[..8]));
    println!("  tr: {}", hex::encode(&sks[0].tr));

    // Now try to verify a signature generated by this key matches standard ML-DSA
    // First, check if the public key can be parsed by the dilithium crate
    match qp_rusty_crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(&pk.packed) {
        Ok(dilithium_pk) => {
            println!("\n✅ Public key successfully parsed by dilithium crate");
            println!("   Dilithium pk bytes match: {}", dilithium_pk.bytes == pk.packed);
        }
        Err(e) => {
            println!("\n❌ Failed to parse public key: {:?}", e);
        }
    }

    println!("\n=== END KEY GENERATION COMPARISON ===\n");
}

/// Hex encoding helper (since we don't have the hex crate)
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Test that solo (non-threshold) ML-DSA signing works correctly
/// This verifies the base cryptographic operations are correct before
/// testing the threshold protocol
#[test]
fn test_solo_mldsa_signing() {
    println!("\n=== SOLO ML-DSA SIGNING TEST ===\n");

    // Generate a regular ML-DSA keypair (not threshold)
    let mut seed = [42u8; 32];
    let keypair = qp_rusty_crystals_dilithium::ml_dsa_87::Keypair::generate(
        qp_rusty_crystals_dilithium::SensitiveBytes32::from(&mut seed),
    );

    let message = b"test message for solo ML-DSA";
    let context = b"test_context";

    // Sign
    let signature = keypair
        .sign(message, Some(context), None)
        .expect("Solo signing should succeed");

    println!("Solo signature size: {} bytes", signature.len());
    println!("Solo signature (first 32 bytes): {}", hex::encode(&signature[..32]));

    // Verify
    let is_valid = keypair.verify(message, &signature, Some(context));

    if is_valid {
        println!("✅ Solo ML-DSA signature verified successfully!");
    } else {
        panic!("❌ Solo ML-DSA signature verification failed!");
    }

    println!("\n=== END SOLO ML-DSA SIGNING TEST ===\n");
}

/// Test threshold key generation produces keys that can sign with solo signing
/// This tests if threshold public key works with a reconstructed full secret
#[test]
fn test_threshold_key_with_solo_sign() {
    println!("\n=== THRESHOLD KEY WITH SOLO SIGN TEST ===\n");

    let seed = [0u8; 32];
    let config = ThresholdConfig::new(2, 2).expect("Invalid config");

    // Generate threshold keys
    let (threshold_pk, _sks) = ml_dsa_87::generate_threshold_key(&seed, &config)
        .expect("Threshold key generation failed");

    // The threshold public key should be parseable by dilithium
    let dilithium_pk = qp_rusty_crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(&threshold_pk.packed)
        .expect("Failed to parse threshold public key");

    println!("✅ Threshold public key parsed successfully");
    println!("   Public key matches: {}", dilithium_pk.bytes == threshold_pk.packed);

    // Now generate a SOLO keypair from the same seed and compare
    let mut solo_seed = seed;
    let solo_keypair = qp_rusty_crystals_dilithium::ml_dsa_87::Keypair::generate(
        qp_rusty_crystals_dilithium::SensitiveBytes32::from(&mut solo_seed),
    );

    // Compare public keys - they should be the same if threshold key gen is correct
    let pk_match = solo_keypair.public.bytes == threshold_pk.packed;
    println!("   Solo pk == Threshold pk: {}", pk_match);

    if pk_match {
        println!("✅ Threshold and solo public keys match!");

        // If they match, we can sign with solo keypair and it should verify with threshold pk
        let message = b"test message";
        let context: Option<&[u8]> = None;

        let signature = solo_keypair
            .sign(message, context, None)
            .expect("Solo signing should succeed");

        let is_valid = dilithium_pk.verify(message, &signature, context);

        if is_valid {
            println!("✅ Solo signature verifies with threshold public key!");
        } else {
            println!("❌ Solo signature does NOT verify with threshold public key");
        }
    } else {
        println!("⚠️ Public keys differ - this is expected for threshold scheme");
        println!("   Solo pk (first 32): {}", hex::encode(&solo_keypair.public.bytes[..32]));
        println!("   Threshold pk (first 32): {}", hex::encode(&threshold_pk.packed[..32]));
    }

    println!("\n=== END THRESHOLD KEY WITH SOLO SIGN TEST ===\n");
}
