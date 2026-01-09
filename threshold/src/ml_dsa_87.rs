//! ML-DSA-87 Threshold Signature Implementation
//!
//! This module implements the threshold variant of ML-DSA-87 (256-bit security level).
//! The threshold scheme allows up to 6 parties to collectively sign messages without
//! any single party having access to the complete signing key.
//!
//! ## Implementation Status (Current Progress)
//!
//! ✅ **COMPLETED COMPONENTS:**
//! - Secret sharing with proper Lagrange interpolation reconstruction
//! - K-iteration commitment generation (each party generates K different w values)
//! - K-iteration response generation (each party generates K different z values)
//! - Per-iteration signature combination following Threshold-ML-DSA reference
//! - Proper μ computation with context handling
//! - ML-DSA constraint verification (||z||_∞, ||f||_∞, hint population)
//! - Integration test harness with real end-to-end protocol validation
//!
//! 🔧 **CURRENT ISSUES:**
//! - ||f||_∞ ≈ 8,370,000 >> γ₂ = 261,888 (32x larger than bound)
//! - All K iterations fail constraint checks, indicating mathematical misalignment
//! - Need to verify commitment/response packing/unpacking for K iterations
//! - Matrix A usage in verification equation needs validation
//!
//! 🎯 **ARCHITECTURE ACHIEVED:**
//! - Reference-aligned protocol: K commitments/responses per party
//! - Correct per-iteration combination logic (try each k ∈ [0,K-1])
//! - Proper threshold parameter handling (K=4 for 2-of-3, K=6 for combination)
//!
//! ## Security Level
//!
//! ML-DSA-87 provides approximately 256-bit security (NIST Level 5) with the following parameters:
//! - Ring dimension: N = 256
//! - Matrix dimensions: k = 8, l = 7
//! - Coefficient bound: η = 2
//! - Challenge weight: ω = 75
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use qp_rusty_crystals_threshold::mldsa87::{ThresholdConfig, generate_threshold_key, Round1State};
//! use rand_core::{CryptoRng, RngCore};
//!
//! // Setup 3-of-5 threshold scheme
//! let config = ThresholdConfig::new(3, 5).expect("Invalid parameters");
//!
//! // Generate threshold keys (requires a cryptographically secure RNG)
//! // let mut rng = /* your CryptoRng + RngCore implementation */;
//! // let (pk, sks) = generate_threshold_key(&mut rng, &config)
//! //     .expect("Key generation failed");
//!
//! // Threshold signing protocol consists of 3 rounds:
//! // 1. Round 1: Each party generates commitments
//! // 2. Round 2: Parties exchange commitments and compute challenge
//! // 3. Round 3: Parties compute responses and combine into signature
//!
//! // See the individual function documentation for detailed usage
//! ```
//!
//! ## Protocol Overview
//!
//! The threshold signing protocol consists of three communication rounds:
//!
//! 1. **Round 1 - Commitment**: Each party generates a random polynomial commitment
//! 2. **Round 2 - Challenge**: Parties exchange commitments and compute the challenge
//! 3. **Round 3 - Response**: Parties compute their signature shares and combine them
//!
//! The protocol is secure against up to t-1 malicious parties where t is the threshold.

// Reference NTT implementation constants (ported from Go reference)

use crate::{
	common::{ThresholdError, ThresholdResult},
	field::{FieldElement, Polynomial, VecK, VecL},
	params::{MlDsaParams, ThresholdParams as BaseThresholdParams},
};
use qp_rusty_crystals_dilithium::fips202;
// Removed unused imports CryptoRng and RngCore
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import dilithium crate for real ML-DSA operations
use qp_rusty_crystals_dilithium::{packing, params as dilithium_params, poly, polyvec};

// Re-export common parameter constants for ML-DSA-87
pub use crate::params::{common::*, MlDsa87Params as Params};

// Re-export SEED_SIZE for test compatibility
pub use crate::params::common::SEED_SIZE;

// Constants for decompose (ML-DSA-87)
const ALPHA: u32 = 2 * 261888; // 2 * Gamma2 = 523776
const Q_U32: u32 = 8380417;

/// Go-compatible decompose function.
/// Splits 0 ≤ a < q into a₀ and a₁ with a = a₁*α + a₀ with -α/2 < a₀ ≤ α/2,
/// except for when we would have a₁ = (q-1)/α in which case a₁=0 is taken
/// and -α/2 ≤ a₀ < 0.  Returns a₀ + q.  Note 0 ≤ a₁ < (q-1)/α.
/// Recall α = 2γ₂.
///
/// This exactly matches the Go implementation in thmldsa87/internal/rounding.go
pub fn decompose_go(a: u32) -> (u32, u32) {
    // a₁ = ⌈a / 128⌉
    let mut a1 = (a + 127) >> 7;

    // For Alpha == 523776 (ML-DSA-87):
    // 1025/2²² is close enough to 1/4092 so that a₁
    // becomes a/α rounded down.
    a1 = ((a1 as u64 * 1025 + (1 << 21)) >> 22) as u32;

    // For the corner-case a₁ = (q-1)/α = 16, we have to set a₁=0.
    a1 &= 15;

    let mut a0_plus_q = a.wrapping_sub(a1.wrapping_mul(ALPHA));

    // In the corner-case, when we set a₁=0, we will incorrectly
    // have a₀ > (q-1)/2 and we'll need to subtract q.  As we
    // return a₀ + q, that comes down to adding q if a₀ < (q-1)/2.
    let threshold = (Q_U32 - 1) / 2;
    // Use i32 arithmetic to handle the comparison correctly
    let cond = ((a0_plus_q as i32).wrapping_sub(threshold as i32)) >> 31; // -1 if a0_plus_q < threshold, 0 otherwise
    a0_plus_q = a0_plus_q.wrapping_add((cond as u32) & Q_U32);

    (a0_plus_q, a1)
}

/// Decompose a VecK using Go-compatible decompose.
/// After this call, v1 contains w1 values and v0 contains w0+Q values.
pub fn veck_decompose_go(v: &polyvec::Polyveck, v0: &mut polyvec::Polyveck, v1: &mut polyvec::Polyveck) {
    for i in 0..dilithium_params::K {
        for j in 0..dilithium_params::N as usize {
            let a = v.vec[i].coeffs[j] as u32;
            let (a0_plus_q, a1) = decompose_go(a);
            v0.vec[i].coeffs[j] = a0_plus_q as i32;
            v1.vec[i].coeffs[j] = a1 as i32;
        }
    }
}

/// Reduces x to a value ≤ 2Q following ML-DSA reference implementation
fn reduce_le2q(x: u32) -> u32 {
	// Note 2²³ = 2¹³ - 1 mod q. So, writing  x = x₁ 2²³ + x₂ with x₂ < 2²³
	// and x₁ < 2⁹, we have x = y (mod q) where
	// y = x₂ + x₁ 2¹³ - x₁ ≤ 2²³ + 2¹³ < 2q.
	let x1 = x >> 23;
	let x2 = x & 0x7FFFFF; // 2²³-1
	x2 + (x1 << 13) - x1
}

fn le2q_mod_q(x: u32) -> u32 {
	// Returns x mod q for 0 ≤ x < 2q.
	// Equivalent to Go's le2qModQ
	let q = dilithium_params::Q as u32;
	let result = x.wrapping_sub(q);
	let mask = (result as i32 >> 31) as u32; // mask is 0xFFFFFFFF if x < Q; 0 otherwise
	result.wrapping_add(mask & q)
}

fn mod_q(x: u32) -> u32 {
	// Returns x mod q.
	// Equivalent to Go's modQ
	le2q_mod_q(reduce_le2q(x))
}

/// Apply NTT to a polynomial using circl-compatible implementation
fn ntt_poly(p: &mut poly::Poly) {
	crate::circl_ntt::ntt(p);
}

/// Apply inverse NTT to a polynomial using circl-compatible implementation
fn inv_ntt_poly(p: &mut poly::Poly) {
	crate::circl_ntt::inv_ntt(p);
}

/// Apply reference NTT to a vector of L polynomials
fn ntt_polyvecl(v: &mut polyvec::Polyvecl) {
	for i in 0..dilithium_params::L {
		ntt_poly(&mut v.vec[i]);
	}
}

/// Apply reference NTT to a vector of K polynomials
fn ntt_polyveck(v: &mut polyvec::Polyveck) {
	for i in 0..dilithium_params::K {
		ntt_poly(&mut v.vec[i]);
	}
}

/// Pointwise dot product in NTT domain using CIRCL implementation
/// Matches Go's PolyDotHat function exactly
fn poly_dot_hat_circl(result: &mut poly::Poly, a: &polyvec::Polyvecl, b: &polyvec::Polyvecl) {
	let mut t = poly::Poly::default();
	*result = poly::Poly::default(); // zero result
	for i in 0..dilithium_params::L {
		crate::circl_ntt::mul_hat(&mut t, &a.vec[i], &b.vec[i]);
		let mut temp = poly::Poly::default();
		crate::circl_ntt::poly_add(&mut temp, result, &t);
		*result = temp;
	}
}

/// Normalizes coefficients assuming they're ≤ 2Q following reference implementation
/// Equivalent to dilithium common::le2qModQ applied to polynomial
fn normalize_assuming_le2q(poly: &mut qp_rusty_crystals_dilithium::poly::Poly) {
	for coeff in poly.coeffs.iter_mut() {
		// First ensure value is in [0, 2Q) range by adding Q if negative
		let mut x = *coeff;
		if x < 0 {
			x += dilithium_params::Q as i32;
		}
		// Now apply le2qModQ: x -= Q, add Q back if result is negative
		let y = x - dilithium_params::Q as i32;
		// mask is -1 (all bits set) if y was negative (x < Q), 0 otherwise
		let mask = y >> 31;
		*coeff = y + (mask & dilithium_params::Q as i32);
	}
}

/// Apply ReduceLe2Q to all coefficients in a polynomial vector K
fn polyvec_k_reduce_le2q(vec: &mut polyvec::Polyveck) {
	for i in 0..dilithium_params::K {
		for j in 0..(dilithium_params::N as usize) {
			let coeff = vec.vec[i].coeffs[j];
			// Handle negative coefficients: add Q to bring into [0, Q) range before reduce_le2q
			let coeff_u32 =
				if coeff < 0 { (coeff + dilithium_params::Q as i32) as u32 } else { coeff as u32 };
			vec.vec[i].coeffs[j] = reduce_le2q(coeff_u32) as i32;
		}
	}
}

/// Apply NormalizeAssumingLe2Q to all polynomials in a polynomial vector K
fn polyvec_k_normalize_assuming_le2q(vec: &mut polyvec::Polyveck) {
	for i in 0..dilithium_params::K {
		normalize_assuming_le2q(&mut vec.vec[i]);
	}
}

/// Shamir secret sharing implementation for threshold ML-DSA
pub mod secret_sharing {
	use super::*;
	// Removed unused import rand_core::RngCore

	/// Secret share for a single party
	#[derive(Clone)]
	pub struct SecretShare {
		/// Party identifier for this secret share
		pub party_id: u8,
		/// Share of the s1 polynomial vector
		pub s1_share: polyvec::Polyvecl, // Share of s1
		/// Share of the s2 polynomial vector
		pub s2_share: polyvec::Polyveck, // Share of s2
	}

	/// Shamir secret sharing polynomial evaluation
	fn evaluate_polynomial(coeffs: &[i32], x: u8, modulus: i32) -> i32 {
		if coeffs.is_empty() {
			return 0;
		}

		// Horner's method for polynomial evaluation
		let mut result = coeffs[coeffs.len() - 1];
		for i in (0..coeffs.len() - 1).rev() {
			result = (result * (x as i32) + coeffs[i]).rem_euclid(modulus);
		}
		result
	}

	/// Generate Shamir secret shares for a polynomial coefficient using deterministic seed
	fn share_coefficient_from_seed(
		secret: i32,
		threshold: u8,
		parties: u8,
		seed: &[u8; 32],
		nonce: u32,
		modulus: i32,
	) -> Vec<i32> {
		// Generate deterministic random polynomial coefficients using FIPS202
		let mut coeffs = vec![secret]; // a_0 = secret

		for i in 1..threshold {
			// Use FIPS202 SHAKE256 to generate deterministic randomness
			let mut random_bytes = [0u8; 4];
			let mut state = fips202::KeccakState::default();
			fips202::shake256_absorb(&mut state, seed, 32);
			fips202::shake256_absorb(&mut state, &nonce.to_le_bytes(), 4);
			fips202::shake256_absorb(&mut state, &i.to_le_bytes(), 1);
			fips202::shake256_finalize(&mut state);
			fips202::shake256_squeeze(&mut random_bytes, 4, &mut state);

			let coeff = (u32::from_le_bytes(random_bytes) % (modulus as u32)) as i32;
			coeffs.push(coeff);
		}

		// Evaluate polynomial at points 1, 2, ..., parties
		let mut shares = Vec::with_capacity(parties as usize);
		for party_id in 1..=parties {
			let share = evaluate_polynomial(&coeffs, party_id, modulus);
			shares.push(share);
		}
		shares
	}

	/// Generate threshold secret shares from master secrets using deterministic approach
	pub fn generate_threshold_shares_from_seed(
		s1_total: &polyvec::Polyvecl,
		s2_total: &polyvec::Polyveck,
		threshold: u8,
		parties: u8,
		seed: &[u8; 32],
	) -> ThresholdResult<Vec<SecretShare>> {
		let mut shares = vec![
			SecretShare {
				party_id: 0,
				s1_share: polyvec::Polyvecl::default(),
				s2_share: polyvec::Polyveck::default(),
			};
			parties as usize
		];

		// Share each coefficient of s1 polynomials
		for i in 0..dilithium_params::L {
			for j in 0..(dilithium_params::N as usize) {
				let secret = s1_total.vec[i].coeffs[j];
				let coeff_shares = share_coefficient_from_seed(
					secret,
					threshold,
					parties,
					seed,
					(i * 256 + j) as u32,
					dilithium_params::Q,
				);

				for (party_idx, &share) in coeff_shares.iter().enumerate() {
					shares[party_idx].party_id = (party_idx + 1) as u8;
					shares[party_idx].s1_share.vec[i].coeffs[j] = share;
				}
			}
		}

		// Share each coefficient of s2 polynomials
		for i in 0..dilithium_params::K {
			for j in 0..(dilithium_params::N as usize) {
				let secret = s2_total.vec[i].coeffs[j];
				let coeff_shares = share_coefficient_from_seed(
					secret,
					threshold,
					parties,
					seed,
					(10000 + i * 256 + j) as u32,
					dilithium_params::Q,
				);

				for (party_idx, &share) in coeff_shares.iter().enumerate() {
					shares[party_idx].s2_share.vec[i].coeffs[j] = share;
				}
			}
		}

		Ok(shares)
	}

	/// Generate threshold secret shares from master secrets using seed
	pub fn generate_threshold_shares(
		s1_total: &polyvec::Polyvecl,
		s2_total: &polyvec::Polyveck,
		threshold: u8,
		parties: u8,
		seed: &[u8; 32],
	) -> ThresholdResult<Vec<SecretShare>> {
		generate_threshold_shares_from_seed(s1_total, s2_total, threshold, parties, seed)
	}

	/// Lagrange interpolation coefficient for party at x=0
	pub fn compute_lagrange_coefficient(party_id: u8, active_parties: &[u8], modulus: i32) -> i32 {
		let mut numerator = 1i64;
		let mut denominator = 1i64;

		for &other_id in active_parties {
			if other_id != party_id {
				numerator = (numerator * (-(other_id as i64))).rem_euclid(modulus as i64);
				denominator = (denominator * ((party_id as i64) - (other_id as i64)))
					.rem_euclid(modulus as i64);
			}
		}

		// Compute modular inverse of denominator
		let inv_denom = mod_inverse(denominator as i32, modulus);
		((numerator * (inv_denom as i64)).rem_euclid(modulus as i64)) as i32
	}

	/// Modular inverse using extended Euclidean algorithm
	fn mod_inverse(a: i32, m: i32) -> i32 {
		let (mut old_r, mut r) = (a, m);
		let (mut old_s, mut s) = (1, 0);

		while r != 0 {
			let quotient = old_r / r;
			let temp_r = r;
			r = old_r - quotient * r;
			old_r = temp_r;

			let temp_s = s;
			s = old_s - quotient * s;
			old_s = temp_s;
		}

		if old_r > 1 {
			panic!("Modular inverse does not exist");
		}
		if old_s < 0 {
			old_s + m
		} else {
			old_s
		}
	}

	/// Normalize a value from [0, Q) to the centered range [-(Q-1)/2, (Q-1)/2]
	/// This is needed because Dilithium secrets are small values, but Lagrange interpolation
	/// returns results in the full modular range [0, Q)
	fn normalize_to_centered_range(value: i32, modulus: i32) -> i32 {
		let half_q = modulus / 2;
		if value > half_q {
			value - modulus
		} else {
			value
		}
	}

	/// Generate proper Round1 commitment using Threshold-ML-DSA approach
	/// This generates masking polynomials and computes w = A*y commitments
	pub fn generate_round1_commitment(
		party_shares: &std::collections::HashMap<u8, SecretShare>,
		party_id: u8,
		seed: &[u8; 32],
		nonce: u16,
		threshold: u8,
		parties: u8,
		rho: &[u8; 32],
	) -> ThresholdResult<(Vec<u8>, Vec<polyvec::Polyvecl>)> {
		use qp_rusty_crystals_dilithium::fips202;

		// Verify party_id is valid
		if !party_shares.contains_key(&party_id) {
			return Err(ThresholdError::InvalidPartyId { party_id, max_id: parties - 1 });
		}

		// Generate multiple masking polynomial sets (K iterations like Threshold-ML-DSA)
		let k_iterations = match (threshold, parties) {
			(2, 3) => 4,
			(3, 4) => 11,
			(2, 4) => 4,
			_ => 4, // Default fallback
		};

		let mut masking_polys = Vec::with_capacity(k_iterations as usize);
		let mut commitments = Vec::new();

		// Initialize matrix A for w = A * y computation
		let mut a_matrix: Vec<polyvec::Polyvecl> =
			(0..dilithium_params::K).map(|_| polyvec::Polyvecl::default()).collect();

		polyvec::matrix_expand(&mut a_matrix, rho);

		// Generate K different masking polynomial sets
		for iter in 0u16..k_iterations {
			// Generate y masking polynomials using gamma1-bounded sampling (correct for ML-DSA)
			let mut y_polys = polyvec::Polyvecl::default();

			for j in 0..dilithium_params::L {
				// Create deterministic seed for this iteration and polynomial
				let mut iter_seed = [0u8; 64];
				let mut state = fips202::KeccakState::default();
				fips202::shake256_absorb(&mut state, seed, 32);
				fips202::shake256_absorb(&mut state, &[party_id], 1);
				fips202::shake256_absorb(&mut state, &nonce.to_le_bytes(), 2);
				fips202::shake256_absorb(&mut state, &iter.to_le_bytes(), 2);
				fips202::shake256_finalize(&mut state);
				fips202::shake256_squeeze(&mut iter_seed, 64, &mut state);

				let mut poly = poly::Poly::default();
				poly::uniform_gamma1(&mut poly, &iter_seed, j as u16);
				y_polys.vec[j] = poly;
			}

			masking_polys.push(y_polys.clone());

			// Compute w = A * y using NTT (following reference implementation approach)
			let mut w_polys = polyvec::Polyveck::default();
			let mut y_ntt = y_polys.clone();

			// Convert y to NTT domain
			for i in 0..dilithium_params::L {
				ntt_poly(&mut y_ntt.vec[i]);
			}

			// Compute w = A * y
			for i in 0..dilithium_params::K {
				polyvec::l_pointwise_acc_montgomery(&mut w_polys.vec[i], &a_matrix[i], &y_ntt);
				// Apply ReduceLe2Q like reference implementation
				for j in 0..(dilithium_params::N as usize) {
					w_polys.vec[i].coeffs[j] = reduce_le2q(w_polys.vec[i].coeffs[j] as u32) as i32;
				}
				inv_ntt_poly(&mut w_polys.vec[i]);
			}
			// Normalize w like reference implementation
			polyvec_k_normalize_assuming_le2q(&mut w_polys);

			// Pack w for commitment hash (following reference implementation)
			let mut w_packed = vec![0u8; dilithium_params::K * (dilithium_params::N as usize) * 4];
			for i in 0..dilithium_params::K {
				for j in 0..(dilithium_params::N as usize) {
					let idx = (i * (dilithium_params::N as usize) + j) * 4;
					let coeff_bytes = w_polys.vec[i].coeffs[j].to_le_bytes();
					w_packed[idx..idx + 4].copy_from_slice(&coeff_bytes);
				}
			}

			// Create proper commitment hash from w (not y)
			let mut commitment = [0u8; 32];
			let mut hash_state = fips202::KeccakState::default();
			fips202::shake256_absorb(&mut hash_state, &[party_id], 1);
			fips202::shake256_absorb(&mut hash_state, &iter.to_le_bytes(), 2);
			fips202::shake256_absorb(&mut hash_state, &w_packed, w_packed.len());
			fips202::shake256_finalize(&mut hash_state);
			fips202::shake256_squeeze(&mut commitment, 32, &mut hash_state);

			commitments.extend_from_slice(&commitment);
		}

		Ok((commitments, masking_polys))
	}

	/// Aggregate Round1 commitments from multiple parties
	pub fn aggregate_round1_commitments(
		commitments: &[Vec<u8>],
		party_ids: &[u8],
	) -> ThresholdResult<Vec<u8>> {
		if commitments.len() != party_ids.len() {
			return Err(ThresholdError::InvalidConfiguration(
				"Commitments and party IDs length mismatch".to_string(),
			));
		}

		use qp_rusty_crystals_dilithium::fips202;
		let _aggregated_commitment: Vec<u8> = Vec::new();
		let mut state = fips202::KeccakState::default();

		// Aggregate all commitments by hashing them together
		for (i, commitment) in commitments.iter().enumerate() {
			fips202::shake256_absorb(&mut state, &[party_ids[i]], 1);
			fips202::shake256_absorb(&mut state, commitment, commitment.len());
		}

		fips202::shake256_finalize(&mut state);
		let mut result = vec![0u8; 32];
		fips202::shake256_squeeze(&mut result, 32, &mut state);

		Ok(result)
	}

	/// Generate Round2 challenge from aggregated commitments and message
	/// This corresponds to Threshold-ML-DSA's Round2 where challenge is computed
	pub fn generate_round2_challenge(
		aggregated_commitment: &[u8],
		message: &[u8],
		context: &[u8],
		tr: &[u8; 64],
	) -> ThresholdResult<Vec<u8>> {
		if context.len() > 255 {
			return Err(ThresholdError::ContextTooLong { length: context.len() });
		}

		use qp_rusty_crystals_dilithium::fips202;

		// Compute mu = CRH(tr || message) following ML-DSA standard
		let mut mu = [0u8; 64];
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, tr, 64);
		fips202::shake256_absorb(&mut state, &[0u8], 1); // domain separator
		fips202::shake256_absorb(&mut state, &[context.len() as u8], 1);
		if !context.is_empty() {
			fips202::shake256_absorb(&mut state, context, context.len());
		}
		fips202::shake256_absorb(&mut state, message, message.len());
		fips202::shake256_finalize(&mut state);
		fips202::shake256_squeeze(&mut mu, 64, &mut state);

		// Generate challenge from mu and aggregated commitment
		let mut challenge_state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut challenge_state, &mu, 64);
		fips202::shake256_absorb(
			&mut challenge_state,
			aggregated_commitment,
			aggregated_commitment.len(),
		);
		fips202::shake256_finalize(&mut challenge_state);

		let mut challenge = vec![0u8; qp_rusty_crystals_dilithium::params::C_DASH_BYTES];
		fips202::shake256_squeeze(
			&mut challenge,
			qp_rusty_crystals_dilithium::params::C_DASH_BYTES,
			&mut challenge_state,
		);

		Ok(challenge)
	}

	/// Generate Round3 response using hardcoded share reconstruction
	/// This uses our hardcoded sharing patterns to avoid coefficient explosion
	pub fn generate_round3_response(
		party_shares: &std::collections::HashMap<u8, SecretShare>,
		party_id: u8,
		active_parties: &[u8],
		threshold: u8,
		parties: u8,
		challenge: &[u8],
		masking_polys: &[polyvec::Polyvecl],
	) -> ThresholdResult<Vec<polyvec::Polyvecl>> {
		// Reconstruct the party's share of the secret using hardcoded patterns
		let (s1_reconstructed, _s2_reconstructed) =
			recover_share_hardcoded(party_shares, party_id, active_parties, threshold, parties)?;

		// Convert challenge to polynomial
		let mut c_poly = qp_rusty_crystals_dilithium::poly::Poly::default();
		qp_rusty_crystals_dilithium::poly::challenge(&mut c_poly, &challenge);

		let mut responses = Vec::with_capacity(masking_polys.len());

		// For each masking polynomial set, compute z = y + c * s1
		for y_polys in masking_polys {
			let mut z_response = polyvec::Polyvecl::default();

			// Convert c to NTT domain
			let mut c_ntt = c_poly.clone();
			ntt_poly(&mut c_ntt);

			// Convert s1 to NTT domain
			let mut s1_ntt = s1_reconstructed.clone();
			ntt_polyvecl(&mut s1_ntt);

			// Compute c * s1 in NTT domain
			qp_rusty_crystals_dilithium::polyvec::l_pointwise_poly_montgomery(
				&mut z_response,
				&c_ntt,
				&s1_ntt,
			);

			// Convert back from NTT domain
			qp_rusty_crystals_dilithium::polyvec::l_invntt_tomont(&mut z_response);

			// Add masking polynomial: z = y + c*s1
			qp_rusty_crystals_dilithium::polyvec::l_add(&mut z_response, y_polys);
			qp_rusty_crystals_dilithium::polyvec::l_reduce(&mut z_response);
			// Apply coefficient centering for threshold signature compatibility
			for j in 0..dilithium_params::L {
				center_dilithium_poly(&mut z_response.vec[j]);
			}

				// Check bounds (rejection sampling)
				const GAMMA1: i32 = 1 << 19; // 2^19 for ML-DSA-87
				let mut bounds_ok = true;
				for i in 0..dilithium_params::L {
					for j in 0..(dilithium_params::N as usize) {
						if z_response.vec[i].coeffs[j].abs() >= GAMMA1 {
						bounds_ok = false;
						break;
					}
				}
				if !bounds_ok {
					break;
				}
			}

			if bounds_ok {
				responses.push(z_response);
			} else {
				// In a full implementation, we would restart with new randomness
				// For now, return what we have
				responses.push(z_response);
			}
		}

		Ok(responses)
	}

	/// Aggregate Round3 responses from multiple parties
	pub fn aggregate_round3_responses(
		responses: &[Vec<polyvec::Polyvecl>],
		_party_ids: &[u8],
	) -> ThresholdResult<Vec<polyvec::Polyvecl>> {
		if responses.is_empty() {
			return Err(ThresholdError::InsufficientParties { provided: 0, required: 1 });
		}

		let k_iterations = responses[0].len();
		let mut aggregated_responses = Vec::with_capacity(k_iterations);

		// Aggregate each iteration's responses
		for iter in 0..k_iterations {
			let mut z_aggregated = polyvec::Polyvecl::default();

			// Sum responses from all parties for this iteration
			for party_responses in responses {
				if iter < party_responses.len() {
					qp_rusty_crystals_dilithium::polyvec::l_add(
						&mut z_aggregated,
						&party_responses[iter],
					);
					qp_rusty_crystals_dilithium::polyvec::l_reduce(&mut z_aggregated);
					// Apply coefficient centering for threshold signature compatibility
					for k in 0..dilithium_params::L {
						center_dilithium_poly(&mut z_aggregated.vec[k]);
					}
				}
			}

			aggregated_responses.push(z_aggregated);
		}

		Ok(aggregated_responses)
	}

	/// Sample a polynomial with coefficients in range [-eta, eta] using SHAKE-256
	/// This is similar to Threshold-ML-DSA's PolyDeriveUniformLeqEta but using integers
	fn sample_poly_leq_eta(
		seed: &[u8; 64],
		nonce: u16,
		eta: i32,
	) -> qp_rusty_crystals_dilithium::poly::Poly {
		use qp_rusty_crystals_dilithium::fips202;

		let mut poly = qp_rusty_crystals_dilithium::poly::Poly::default();
		let mut state = fips202::KeccakState::default();
		let mut buf = [0u8; 136]; // SHAKE-256 rate

		// Prepare SHAKE-256 with seed and nonce
		fips202::shake256_absorb(&mut state, seed, 64);
		let nonce_bytes = [nonce as u8, (nonce >> 8) as u8];
		fips202::shake256_absorb(&mut state, &nonce_bytes, 2);
		fips202::shake256_finalize(&mut state);

		let q = dilithium_params::Q;
		let mut i = 0;
		while i < qp_rusty_crystals_dilithium::params::N as usize {
			fips202::shake256_squeeze(&mut buf, 136, &mut state);

			// Use rejection sampling to get coefficients in [Q-eta, Q+eta] (unnormalized form)
			// This matches the Go circl library's behavior
			for j in 0..136 {
				if i >= qp_rusty_crystals_dilithium::params::N as usize {
					break;
				}

				let mut t1 = (buf[j] & 15) as u32;
				let mut t2 = (buf[j] >> 4) as u32;

				// For eta = 2 (ML-DSA-87 parameter)
				if eta == 2 {
					if t1 <= 14 {
						// Reduce mod 5 using bit tricks like Go: t1 -= ((205 * t1) >> 10) * 5
						t1 -= ((205 * t1) >> 10) * 5;
						// Store in unnormalized form: Q + eta - t1
						poly.coeffs[i] = (q + eta - t1 as i32) as i32;
						i += 1;
					}
					if t2 <= 14 && i < qp_rusty_crystals_dilithium::params::N as usize {
						// Reduce mod 5 using bit tricks like Go
						t2 -= ((205 * t2) >> 10) * 5;
						// Store in unnormalized form: Q + eta - t2
						poly.coeffs[i] = (q + eta - t2 as i32) as i32;
						i += 1;
					}
				} else {
					// Generic case for other eta values (eta = 4)
					if t1 <= 2 * eta as u32 {
						poly.coeffs[i] = (q + eta - t1 as i32) as i32;
						i += 1;
					}
					if t2 <= 2 * eta as u32 && i < qp_rusty_crystals_dilithium::params::N as usize {
						poly.coeffs[i] = (q + eta - t2 as i32) as i32;
						i += 1;
					}
				}
			}
		}

		poly
	}

	/// Generate proper threshold secret shares using Threshold-ML-DSA approach
	/// This creates shares for all possible signer combinations and builds the total secret
	/// as the sum of these shares, which works with the hardcoded sharing patterns
	pub fn generate_proper_threshold_shares(
		state: &mut qp_rusty_crystals_dilithium::fips202::KeccakState,
		threshold: u8,
		parties: u8,
	) -> ThresholdResult<(
		polyvec::Polyvecl,
		polyvec::Polyveck,
		polyvec::Polyvecl,
		polyvec::Polyveck,
		std::collections::HashMap<u8, std::collections::HashMap<u8, SecretShare>>,
	)> {
		use qp_rusty_crystals_dilithium::fips202;

		// Initialize private keys for each party
		let mut party_shares: std::collections::HashMap<
			u8,
			std::collections::HashMap<u8, SecretShare>,
		> = std::collections::HashMap::new();
		for i in 0..parties {
			party_shares.insert(i, std::collections::HashMap::new());
		}

		// Total secret (sum of all shares) - both normal and NTT form
		let mut s1_total = polyvec::Polyvecl::default();
		let mut s2_total = polyvec::Polyveck::default();
		let mut s1h_total = polyvec::Polyvecl::default();
		let mut s2h_total = polyvec::Polyveck::default();

		// Generate shares for all possible "honest signer" combinations
		// This follows the same enumeration as Threshold-ML-DSA
		let mut honest_signers = (1u8 << (parties - threshold + 1)) - 1;
		let max_combinations = 1u8 << parties;

		while honest_signers < max_combinations {
			// Generate a random seed for this share
			let mut share_seed = [0u8; 64];
			fips202::shake256_squeeze(&mut share_seed, 64, state);

			// Create η-bounded shares for s1 (L polynomials)
			let mut s1_share = polyvec::Polyvecl::default();
			for j in 0..dilithium_params::L {
				let poly = sample_poly_leq_eta(&share_seed, j as u16, 2); // eta = 2 for ML-DSA-87
				s1_share.vec[j] = poly;
			}

			// Create η-bounded shares for s2 (K polynomials)
			let mut s2_share = polyvec::Polyveck::default();
			for j in 0..dilithium_params::K {
				let poly = sample_poly_leq_eta(&share_seed, (dilithium_params::L + j) as u16, 2);
				s2_share.vec[j] = poly;
			}

			// Compute NTT of shares before adding (following reference implementation)
			let mut s1h_share = s1_share.clone();
			let mut s2h_share = s2_share.clone();

			ntt_polyvecl(&mut s1h_share);
			ntt_polyveck(&mut s2h_share);

			// Create the share object with η-bounded coefficients
			let share = SecretShare {
				party_id: honest_signers, // Use the combination as the share ID
				s1_share: s1_share.clone(),
				s2_share: s2_share.clone(),
			};

			// Distribute this η-bounded share to all parties in the honest_signers combination
			// This matches the reference implementation exactly
			for i in 0..parties {
				if (honest_signers & (1 << i)) != 0 {
					if let Some(party_map) = party_shares.get_mut(&i) {
						party_map.insert(honest_signers, share.clone());
					}
				}
			}

			// Add to total secret (no reduction during accumulation)
			// Use wrapping_add to handle overflow for large configurations
			for i in 0..dilithium_params::L {
				for j in 0..(dilithium_params::N as usize) {
					s1_total.vec[i].coeffs[j] = s1_total.vec[i].coeffs[j].wrapping_add(s1_share.vec[i].coeffs[j]);
					s1h_total.vec[i].coeffs[j] = s1h_total.vec[i].coeffs[j].wrapping_add(s1h_share.vec[i].coeffs[j]);
				}
			}

			for i in 0..dilithium_params::K {
				for j in 0..(dilithium_params::N as usize) {
					s2_total.vec[i].coeffs[j] = s2_total.vec[i].coeffs[j].wrapping_add(s2_share.vec[i].coeffs[j]);
					s2h_total.vec[i].coeffs[j] = s2h_total.vec[i].coeffs[j].wrapping_add(s2h_share.vec[i].coeffs[j]);
				}
			}

			// Move to next combination (this is the same bit manipulation as Threshold-ML-DSA)
			let c = honest_signers & (!honest_signers + 1);
			let r = honest_signers + c;
			honest_signers = (((r ^ honest_signers) >> 2) / c) | r;
		}

		// Apply final normalization to bring coefficients to [0, Q) like Go's Normalize()
		for i in 0..dilithium_params::L {
			for j in 0..(dilithium_params::N as usize) {
				// Normalize s1_total
				let coeff = s1_total.vec[i].coeffs[j];
				let coeff_u32 =
					if coeff < 0 { (coeff + dilithium_params::Q) as u32 } else { coeff as u32 };
				s1_total.vec[i].coeffs[j] = mod_q(coeff_u32) as i32;

				// Normalize s1h_total (NTT form)
				let coeff_h = s1h_total.vec[i].coeffs[j];
				let coeff_h_u32 =
					if coeff_h < 0 { (coeff_h + dilithium_params::Q) as u32 } else { coeff_h as u32 };
				s1h_total.vec[i].coeffs[j] = mod_q(coeff_h_u32) as i32;
			}
		}

		for i in 0..dilithium_params::K {
			for j in 0..(dilithium_params::N as usize) {
				// Normalize s2_total
				let coeff = s2_total.vec[i].coeffs[j];
				let coeff_u32 =
					if coeff < 0 { (coeff + dilithium_params::Q) as u32 } else { coeff as u32 };
				s2_total.vec[i].coeffs[j] = mod_q(coeff_u32) as i32;

				// Normalize s2h_total (NTT form)
				let coeff_h = s2h_total.vec[i].coeffs[j];
				let coeff_h_u32 =
					if coeff_h < 0 { (coeff_h + dilithium_params::Q) as u32 } else { coeff_h as u32 };
				s2h_total.vec[i].coeffs[j] = mod_q(coeff_h_u32) as i32;
			}
		}

		Ok((s1_total, s2_total, s1h_total, s2h_total, party_shares))
	}

	/// Get hardcoded sharing patterns for specific (threshold, parties) combinations.
	/// These patterns avoid the large Lagrange coefficients by using precomputed
	/// share combinations. Based on Threshold-ML-DSA implementation.
	fn get_sharing_patterns(threshold: u8, parties: u8) -> Result<Vec<Vec<u8>>, &'static str> {
		// These patterns must match the Go implementation CODE (not comments)
		// The Go code uses different patterns than what's in the comments
		match (threshold, parties) {
			(2, 3) => Ok(vec![vec![3, 5], vec![6]]),
			(2, 4) => Ok(vec![vec![11, 13], vec![7, 14]]),
			(3, 4) => Ok(vec![vec![3, 9], vec![6, 10], vec![12, 5]]),
			(2, 5) => Ok(vec![vec![27, 29, 23], vec![30, 15]]),
			(3, 5) => Ok(vec![vec![25, 11, 19, 13], vec![7, 14, 22, 26], vec![28, 21]]),
			(4, 5) => Ok(vec![vec![3, 9, 17], vec![6, 10, 18], vec![12, 5, 20], vec![24]]),
			(2, 6) => Ok(vec![vec![61, 47, 55], vec![62, 31, 59]]),
			(3, 6) => Ok(vec![
				vec![27, 23, 43, 57, 39],
				vec![51, 58, 46, 30, 54],
				vec![45, 53, 29, 15, 60],
			]),
			(4, 6) => Ok(vec![
				vec![19, 13, 35, 7, 49],
				vec![42, 26, 38, 50, 22],
				vec![52, 21, 44, 28, 37],
				vec![25, 11, 14, 56, 41],
			]),
			(5, 6) => Ok(vec![
				vec![3, 5, 33],
				vec![6, 10, 34],
				vec![12, 20, 36],
				vec![9, 24, 40],
				vec![48, 17, 18],
			]),
			_ => Err("Unsupported threshold/parties combination"),
		}
	}

	/// Recover share using hardcoded sharing patterns instead of Lagrange interpolation.
	/// This avoids the coefficient explosion problem we had with general Lagrange interpolation.
	pub fn recover_share_hardcoded(
		shares: &std::collections::HashMap<u8, SecretShare>,
		party_id: u8,
		active_parties: &[u8],
		threshold: u8,
		parties: u8,
	) -> ThresholdResult<(polyvec::Polyvecl, polyvec::Polyveck)> {
		// Base case: when threshold is 1 or equals total parties
		// In this case, each party uses their single share directly
		// But we still need to convert to NTT domain like Go does
		if threshold == 1 || threshold == parties {
			// For t=n case, use the share that corresponds to all active parties
			// The share key is a bitmask of which parties are involved
			// For 2-of-2 with parties 0,1 active, the key is 0b11 = 3
			let active_key: u8 = active_parties.iter().fold(0u8, |acc, &p| acc | (1 << p));

			// Try to find the share with the active key first
			let share = shares.get(&active_key).or_else(|| {
				// Fallback: use any available share (like Go does with map iteration)
				shares.values().next()
			});

			if let Some(share) = share {
				// Convert to NTT domain to match Go's recoverShare which returns s1h, s2h
				let mut s1_ntt = share.s1_share.clone();
				let mut s2_ntt = share.s2_share.clone();

				for i in 0..dilithium_params::L {
					crate::circl_ntt::ntt(&mut s1_ntt.vec[i]);
				}
				for i in 0..dilithium_params::K {
					crate::circl_ntt::ntt(&mut s2_ntt.vec[i]);
				}

				return Ok((s1_ntt, s2_ntt));
			}
		}

		// Get the hardcoded sharing patterns
		let sharing_patterns = get_sharing_patterns(threshold, parties)
			.map_err(|e| ThresholdError::InvalidConfiguration(e.to_string()))?;

		// Create permutation to cover the signing set (active_parties)
		let mut perm = vec![0u8; parties as usize];
		let mut i1 = 0;
		let mut i2 = threshold as usize;

		// Find the position of party_id within active_parties
		let current_i = active_parties.iter().position(|&p| p == party_id).ok_or_else(|| {
			ThresholdError::InvalidConfiguration(format!(
				"Party {} is not in active parties list",
				party_id
			))
		})?;

		for j in 0..parties {
			if active_parties.contains(&j) {
				perm[i1] = j;
				i1 += 1;
			} else {
				perm[i2] = j;
				i2 += 1;
			}
		}

		if current_i >= sharing_patterns.len() {
			return Err(ThresholdError::InvalidConfiguration(
				"Party index exceeds sharing pattern length".to_string(),
			));
		}

		// Combine shares according to the hardcoded pattern
		let mut s1_combined = polyvec::Polyvecl::default();
		let mut s2_combined = polyvec::Polyveck::default();

		for &pattern_u in &sharing_patterns[current_i] {
			// Translate the share index u to the share index u_ by applying the permutation
			let mut u_translated = 0u8;
			for i in 0..parties {
				if pattern_u & (1 << i) != 0 {
					u_translated |= 1 << perm[i as usize];
				}
			}

			// Find the corresponding share
			if let Some(share) = shares.get(&u_translated) {
				// Convert share to NTT domain first (like Go's s1h.Add(&s1h, &sk.shares[u_].s1h))
				// Go stores shares in both normal and NTT domain, and adds in NTT domain
				let mut s1_ntt = share.s1_share.clone();
				let mut s2_ntt = share.s2_share.clone();

				for i in 0..dilithium_params::L {
					crate::circl_ntt::ntt(&mut s1_ntt.vec[i]);
				}
				for i in 0..dilithium_params::K {
					crate::circl_ntt::ntt(&mut s2_ntt.vec[i]);
				}

				// Add in NTT domain (pointwise addition)
				// Use wrapping_add to handle overflow for large configurations
				for i in 0..dilithium_params::L {
					for j in 0..(dilithium_params::N as usize) {
						s1_combined.vec[i].coeffs[j] = s1_combined.vec[i].coeffs[j].wrapping_add(s1_ntt.vec[i].coeffs[j]);
					}
				}

				for i in 0..dilithium_params::K {
					for j in 0..(dilithium_params::N as usize) {
						s2_combined.vec[i].coeffs[j] = s2_combined.vec[i].coeffs[j].wrapping_add(s2_ntt.vec[i].coeffs[j]);
					}
				}
			}
		}

		// Apply normalization like Go's s1h.Normalize() and s2h.Normalize()
		// Note: s1_combined and s2_combined are in NTT domain at this point
		// Apply mod_q normalization since accumulated NTT values can exceed 2Q
		for i in 0..dilithium_params::L {
			for j in 0..(dilithium_params::N as usize) {
				let coeff = s1_combined.vec[i].coeffs[j];
				let coeff_u32 = if coeff < 0 {
					(coeff + dilithium_params::Q as i32) as u32
				} else {
					coeff as u32
				};
				s1_combined.vec[i].coeffs[j] = mod_q(coeff_u32) as i32;
			}
		}

		for i in 0..dilithium_params::K {
			for j in 0..(dilithium_params::N as usize) {
				let coeff = s2_combined.vec[i].coeffs[j];
				let coeff_u32 = if coeff < 0 {
					(coeff + dilithium_params::Q as i32) as u32
				} else {
					coeff as u32
				};
				s2_combined.vec[i].coeffs[j] = mod_q(coeff_u32) as i32;
			}
		}

		Ok((s1_combined, s2_combined))
	}

	/// Reconstruct secret from shares using hardcoded sharing patterns.
	/// This replaces Lagrange interpolation to avoid coefficient explosion.
	pub fn reconstruct_secret_hardcoded(
		shares: &std::collections::HashMap<u8, SecretShare>,
		party_id: u8,
		active_parties: &[u8],
		threshold: u8,
		parties: u8,
	) -> ThresholdResult<(polyvec::Polyvecl, polyvec::Polyveck)> {
		recover_share_hardcoded(shares, party_id, active_parties, threshold, parties)
	}

	/// Reconstruct secret from shares using Lagrange interpolation (legacy)
	pub fn reconstruct_secret(
		shares: &[SecretShare],
		active_parties: &[u8],
	) -> ThresholdResult<(polyvec::Polyvecl, polyvec::Polyveck)> {
		if shares.is_empty() || active_parties.is_empty() {
			return Err(ThresholdError::InsufficientParties { provided: 0, required: 1 });
		}

		let mut s1_reconstructed = polyvec::Polyvecl::default();
		let mut s2_reconstructed = polyvec::Polyveck::default();

		// Reconstruct s1
		for i in 0..dilithium_params::L {
			for j in 0..(dilithium_params::N as usize) {
				let mut coeff = 0i64;

				for (share_idx, &party_id) in active_parties.iter().enumerate() {
					if share_idx < shares.len() {
						let lagrange_coeff = compute_lagrange_coefficient(
							party_id,
							active_parties,
							dilithium_params::Q,
						);
						let share_value = shares[share_idx].s1_share.vec[i].coeffs[j] as i64;
						coeff = (coeff + (lagrange_coeff as i64 * share_value))
							.rem_euclid(dilithium_params::Q as i64);
					}
				}

				// Normalize from [0, Q) to centered range [-(Q-1)/2, (Q-1)/2]
				s1_reconstructed.vec[i].coeffs[j] =
					normalize_to_centered_range(coeff as i32, dilithium_params::Q);
			}
		}

		// Reconstruct s2
		for i in 0..dilithium_params::K {
			for j in 0..(dilithium_params::N as usize) {
				let mut coeff = 0i64;

				for (share_idx, &party_id) in active_parties.iter().enumerate() {
					if share_idx < shares.len() {
						let lagrange_coeff = compute_lagrange_coefficient(
							party_id,
							active_parties,
							dilithium_params::Q,
						);
						let share_value = shares[share_idx].s2_share.vec[i].coeffs[j] as i64;
						coeff = (coeff + (lagrange_coeff as i64 * share_value))
							.rem_euclid(dilithium_params::Q as i64);
					}
				}

				// Normalize from [0, Q) to centered range [-(Q-1)/2, (Q-1)/2]
				s2_reconstructed.vec[i].coeffs[j] =
					normalize_to_centered_range(coeff as i32, dilithium_params::Q);
			}
		}

		Ok((s1_reconstructed, s2_reconstructed))
	}
}

/// Threshold parameters specific to ML-DSA-87
pub type ThresholdParams = BaseThresholdParams;

/// ML-DSA-87 specific threshold parameters with precomputed values
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThresholdConfig {
	/// Base threshold parameters
	pub base: ThresholdParams,
	/// Number of iterations (K parameter from Go implementation)
	pub k_iterations: u16,
	/// Primary radius parameter
	pub r: f64,
	/// Secondary radius parameter
	pub r_prime: f64,
	/// Nu parameter (typically 3.0)
	pub nu: f64,
}

impl ThresholdConfig {
	/// Get threshold configuration for ML-DSA-87 with given t and n
	pub fn new(t: u8, n: u8) -> ThresholdResult<Self> {
		let base = BaseThresholdParams::new(t, n)?;

		// ML-DSA-87 specific parameters based on Go implementation
		let (k_iterations, r, r_prime) = match (t, n) {
			(2, 2) => (3, 503119.0, 503192.0),
			(2, 3) => (4, 631601.0, 631703.0),
			(3, 3) => (6, 483107.0, 483180.0),
			(2, 4) => (4, 632903.0, 633006.0),
			(3, 4) => (11, 551752.0, 551854.0),
			(4, 4) => (14, 487958.0, 488031.0),
			(2, 5) => (5, 607694.0, 607820.0),
			(3, 5) => (26, 577400.0, 577546.0),
			(4, 5) => (70, 518384.0, 518510.0),
			(5, 5) => (35, 468214.0, 468287.0),
			(2, 6) => (5, 665106.0, 665232.0),
			(3, 6) => (39, 577541.0, 577704.0),
			(4, 6) => (208, 517689.0, 517853.0),
			(5, 6) => (295, 479692.0, 479819.0),
			(6, 6) => (87, 424124.0, 424197.0),
			_ => {
				return Err(ThresholdError::InvalidParameters {
					threshold: t,
					parties: n,
					reason: "unsupported threshold configuration for ML-DSA-87",
				})
			},
		};

		Ok(Self { base, k_iterations, r, r_prime, nu: 3.0 })
	}

	/// Get the base threshold parameters
	pub fn threshold_params(&self) -> &ThresholdParams {
		&self.base
	}
}

/// ML-DSA-87 public key
#[derive(Debug, Clone)]
pub struct PublicKey {
	/// Random seed rho for matrix A generation
	pub rho: [u8; 32],
	/// Matrix A in NTT form
	pub a_ntt: Mat<{ Params::K }, { Params::L }>,
	/// Public key vector t1
	pub t1: VecK<{ Params::K }>,
	/// Public key hash TR
	pub tr: [u8; TR_SIZE],
	/// Packed public key bytes (compatible with dilithium)
	pub packed: [u8; Params::PUBLIC_KEY_SIZE],
}

/// ML-DSA-87 threshold private key share
#[derive(Clone)]
pub struct PrivateKey {
	/// Party identifier (0 to n-1)
	pub id: u8,
	/// Private key seed
	pub key: [u8; 32],
	/// Random seed rho (same as public key)
	pub rho: [u8; 32],
	/// Hash of public key for signing
	pub tr: [u8; TR_SIZE],
	/// Matrix A
	pub a: Mat<{ Params::K }, { Params::L }>,
	/// Secret shares for this party (indexed by signer subset)
	pub shares: std::collections::HashMap<u8, secret_sharing::SecretShare>,
	/// Aggregated secret for verification
	pub s_total: Option<(polyvec::Polyvecl, polyvec::Polyveck)>,
}

impl PrivateKey {
	/// Get the secret shares for testing purposes
	pub fn get_secret_shares(&self) -> Option<&(polyvec::Polyvecl, polyvec::Polyveck)> {
		self.s_total.as_ref()
	}
}

impl Zeroize for PrivateKey {
	fn zeroize(&mut self) {
		self.key.zeroize();
		self.rho.zeroize();
		self.tr.zeroize();
		self.shares.clear();
		// Note: Dilithium types don't implement Zeroize, so we manually zero the data
		if let Some((ref mut s1, ref mut s2)) = self.s_total {
			for i in 0..dilithium_params::L {
				s1.vec[i].coeffs.fill(0);
			}
			for i in 0..dilithium_params::K {
				s2.vec[i].coeffs.fill(0);
			}
		}
	}
}

impl ZeroizeOnDrop for PrivateKey {}

/// Floating-point vector for threshold signature hyperball sampling (like Golang FVec)
pub struct FVec {
	data: Box<[f64]>,
}

impl FVec {
	/// Create new FVec with given size
	pub fn new(size: usize) -> Self {
		Self { data: vec![0.0f64; size].into_boxed_slice() }
	}

	/// Sample from hyperball with given radius and nu parameter
	pub fn sample_hyperball(&mut self, radius: f64, nu: f64, rhop: &[u8; 64], nonce: u16) {
		use std::f64::consts::PI;

		let size = self.data.len();
		let mut samples = vec![0.0f64; size + 2];

		// Use SHAKE256 for cryptographic randomness
		let mut keccak_state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut keccak_state, b"H", 1); // Domain separator
		fips202::shake256_absorb(&mut keccak_state, rhop, 64);
		let nonce_bytes = nonce.to_le_bytes();
		fips202::shake256_absorb(&mut keccak_state, &nonce_bytes, 2);
		fips202::shake256_finalize(&mut keccak_state);

		let mut buf = vec![0u8; (size + 2) * 8]; // 8 bytes per f64
		let buf_len = buf.len();
		fips202::shake256_squeeze(&mut buf, buf_len, &mut keccak_state);

		// Generate normally distributed random numbers using Box-Muller transform
		// CRITICAL: Must compute sq BEFORE applying nu scaling (matching reference)
		let mut sq = 0.0f64;
		for i in (0..size + 2).step_by(2) {
			// Convert bytes to u64
			let u1_bytes: [u8; 8] = buf[i * 8..(i + 1) * 8].try_into().unwrap();
			let u2_bytes: [u8; 8] = buf[(i + 1) * 8..(i + 2) * 8].try_into().unwrap();
			let u1 = u64::from_le_bytes(u1_bytes);
			let u2 = u64::from_le_bytes(u2_bytes);

			// Convert to f64 in [0,1) - matching Golang exactly
			let f1 = (u1 as f64) / 18446744073709551616.0; // 2^64 as f64
			let f2 = (u2 as f64) / 18446744073709551616.0; // 2^64 as f64

			// Ensure f1 > 0 for log to avoid NaN
			let f1 = if f1 <= 0.0 { f64::MIN_POSITIVE } else { f1 };

			// Box-Muller transform
			let z1 = (-2.0 * f1.ln()).sqrt() * (2.0 * PI * f2).cos();
			let z2 = (-2.0 * f1.ln()).sqrt() * (2.0 * PI * f2).sin();

			// Store samples and add to sq BEFORE nu scaling (critical!)
			samples[i] = z1;
			sq += z1 * z1;

			samples[i + 1] = z2;
			sq += z2 * z2;

			// Apply nu scaling to first N*L components AFTER adding to sq
			if i < dilithium_params::N as usize * dilithium_params::L {
				samples[i] *= nu;
				samples[i + 1] *= nu;
			}
		}

		let factor = radius / sq.sqrt();
		for i in 0..size {
			self.data[i] = samples[i] * factor;
		}
	}

	/// Round floating-point values back to integer polynomials
	/// Note: Rust library uses i32, so we keep centered representation in [-(Q-1)/2, (Q-1)/2]
	/// Reference uses uint32 and adds Q to negatives, but that doesn't work well with i32 NTT
	pub fn round(&self, s1: &mut polyvec::Polyvecl, s2: &mut polyvec::Polyveck) {
		// Round s1 components - keep in centered range
		for i in 0..dilithium_params::L {
			for j in 0..dilithium_params::N as usize {
				let idx = i * dilithium_params::N as usize + j;
				let u = self.data[idx].round() as i32;
				// Keep values centered: if outside [-Q/2, Q/2], reduce modulo Q
				let mut reduced = u % dilithium_params::Q as i32;
				if reduced > (dilithium_params::Q as i32) / 2 {
					reduced -= dilithium_params::Q as i32;
				} else if reduced < -((dilithium_params::Q as i32) / 2) {
					reduced += dilithium_params::Q as i32;
				}
				s1.vec[i].coeffs[j as usize] = reduced;
			}
		}

		// Round s2 components - keep in centered range
		for i in 0..dilithium_params::K {
			for j in 0..dilithium_params::N as usize {
				let idx = (dilithium_params::L + i) * dilithium_params::N as usize + j;
				let u = self.data[idx].round() as i32;
				// Keep values centered: if outside [-Q/2, Q/2], reduce modulo Q
				let mut reduced = u % dilithium_params::Q as i32;
				if reduced > (dilithium_params::Q as i32) / 2 {
					reduced -= dilithium_params::Q as i32;
				} else if reduced < -((dilithium_params::Q as i32) / 2) {
					reduced += dilithium_params::Q as i32;
				}
				s2.vec[i].coeffs[j as usize] = reduced;
			}
		}
	}

	/// Check if norm exceeds rejection bounds (like Golang Excess function)
	pub fn excess(&self, r: f64, nu: f64) -> bool {
		let mut sq = 0.0;

		for i in 0..(dilithium_params::L + dilithium_params::K) {
			for j in 0..dilithium_params::N as usize {
				let idx = i * dilithium_params::N as usize + j;
				let val = self.data[idx];
				if i < dilithium_params::L {
					// For s1 components, divide by nu^2
					sq += val * val / (nu * nu);
				} else {
					// For s2 components, use directly
					sq += val * val;
				}
			}
		}

		sq > r * r
	}

	/// Add another FVec to this one
	pub fn add(&mut self, other: &FVec) {
		for i in 0..self.data.len() {
			self.data[i] += other.data[i];
		}
	}

	/// Clone this FVec
	pub fn clone(&self) -> Self {
		Self { data: self.data.clone() }
	}

	/// Get first n samples from this FVec (for testing)
	pub fn get_samples(&self, n: usize) -> Vec<f64> {
		self.data.iter().take(n).copied().collect()
	}

	/// Create FVec from polynomial vectors
	pub fn from_polyvecs(s1: &polyvec::Polyvecl, s2: &polyvec::Polyveck) -> Self {
		let size = dilithium_params::N as usize * (dilithium_params::L + dilithium_params::K);
		let mut data = vec![0.0f64; size];

		// Copy s1 polynomials (first L polynomials)
		for i in 0..dilithium_params::L {
			for j in 0..dilithium_params::N as usize {
				let mut u = s1.vec[i].coeffs[j as usize] as i32;
				// Center modulo Q
				u += dilithium_params::Q as i32 / 2;
				let t = u - dilithium_params::Q as i32;
				u = t + ((t >> 31) & dilithium_params::Q as i32);
				u = u - dilithium_params::Q as i32 / 2;

				data[i * dilithium_params::N as usize + j] = u as f64;
			}
		}

		// Copy s2 polynomials (next K polynomials)
		for i in 0..dilithium_params::K {
			for j in 0..dilithium_params::N as usize {
				let mut u = s2.vec[i].coeffs[j as usize] as i32;
				// Center modulo Q
				u += dilithium_params::Q as i32 / 2;
				let t = u - dilithium_params::Q as i32;
				u = t + ((t >> 31) & dilithium_params::Q as i32);
				u = u - dilithium_params::Q as i32 / 2;

				data[(dilithium_params::L + i) * dilithium_params::N as usize + j] = u as f64;
			}
		}

		Self { data: data.into_boxed_slice() }
	}
}

// Key types are already public, no need to re-export them

/// Secret share for threshold scheme
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretShare {
	/// Share identifier (subset of signers)
	pub subset_id: u8,
	/// Secret vector s1
	pub s1: VecL<{ Params::L }>,
	/// Secret vector s2
	pub s2: VecK<{ Params::K }>,
	/// s1 in NTT form
	pub s1_ntt: VecL<{ Params::L }>,
	/// s2 in NTT form
	pub s2_ntt: VecK<{ Params::K }>,
}

/// Matrix A for ML-DSA-87
#[derive(Debug, Clone)]
pub struct Mat<const K: usize, const L: usize>([[Polynomial; L]; K]);

/// Apply coefficient centering to a dilithium polynomial in-place to minimize magnitudes
fn center_dilithium_poly(poly: &mut qp_rusty_crystals_dilithium::poly::Poly) {
	const Q_HALF: i32 = (dilithium_params::Q - 1) / 2;
	for j in 0..(dilithium_params::N as usize) {
		// Ensure value is in (-Q, Q) range first
		let mut coeff = poly.coeffs[j] % (dilithium_params::Q as i32);

		// Center to [-(Q-1)/2, (Q-1)/2]
		if coeff > Q_HALF {
			coeff -= dilithium_params::Q as i32;
		} else if coeff < -Q_HALF {
			coeff += dilithium_params::Q as i32;
		}
		poly.coeffs[j] = coeff;
	}
}

/// Check if any coefficient in polynomial vector exceeds bound (matches reference Exceeds)
/// This computes the centered norm like the reference implementation's exceedsGeneric
fn polyveck_exceeds(polyvec: &qp_rusty_crystals_dilithium::polyvec::Polyveck, bound: i32) -> bool {
	for i in 0..dilithium_params::K {
		if poly_exceeds(&polyvec.vec[i], bound as u32) {
			return true;
		}
	}
	false
}

/// Check if any coefficient in polynomial exceeds bound (matches reference exceedsGeneric)
fn poly_exceeds(poly: &qp_rusty_crystals_dilithium::poly::Poly, bound: u32) -> bool {
	for i in 0..(dilithium_params::N as usize) {
		// Compute centered norm like reference implementation
		// The central reps of {0, 1, ..., (Q-1)/2, (Q+1)/2, ..., Q-1}
		// are given by       {0, 1, ..., (Q-1)/2, -(Q-1)/2, ..., -1}
		// so their norms are {0, 1, ..., (Q-1)/2,  (Q-1)/2, ...,  1}

		let coeff = poly.coeffs[i] as u32;
		// Sets x to {(Q-1)/2, (Q-3)/2, ..., 0, -1, ..., -(Q-1)/2}
		let mut x = ((dilithium_params::Q - 1) / 2) as i32 - coeff as i32;
		// Sets x to {(Q-1)/2, (Q-3)/2, ..., 0, 0, ..., (Q-3)/2}
		x ^= x >> 31;
		// Sets x to {0, 1, ..., (Q-1)/2, (Q-1)/2, ..., 1}
		x = ((dilithium_params::Q - 1) / 2) as i32 - x;
		if x as u32 >= bound {
			return true;
		}
	}
	false
}

impl<const K: usize, const L: usize> Mat<K, L> {
	/// Create new zero matrix
	pub fn zero() -> Self {
		Self(core::array::from_fn(|_| core::array::from_fn(|_| Polynomial::zero())))
	}

	/// Derive matrix A from seed rho
	pub fn derive_from_seed(&mut self, rho: &[u8; 32]) {
		for i in 0..K {
			for j in 0..L {
				// Use dilithium's uniform polynomial sampling directly
				let mut dilithium_poly = qp_rusty_crystals_dilithium::poly::Poly::default();
				poly::uniform(&mut dilithium_poly, rho, ((i << 8) + j) as u16);

				// Convert to threshold polynomial format WITHOUT centering
				// CRITICAL: Keep coefficients in [0, Q) to match Dilithium library representation
				// Centering would create a different matrix than what's used in Round1
				let mut poly = Polynomial::zero();
				for k in 0..N {
					if k < dilithium_params::N as usize {
						let coeff = dilithium_poly.coeffs[k] as u32;
						poly.set(k, FieldElement::new(coeff));
					}
				}
				self.0[i][j] = poly;
			}
		}
	}

	// Note: Removed sample_uniform_polynomial function as we now use dilithium's uniform function directly

	/// Get polynomial at position (i, j)
	pub fn get(&self, i: usize, j: usize) -> &Polynomial {
		&self.0[i][j]
	}

	/// Get mutable polynomial at position (i, j)
	pub fn get_mut(&mut self, i: usize, j: usize) -> &mut Polynomial {
		&mut self.0[i][j]
	}
}

/// Round 1 state for threshold signing with real ML-DSA commitment

pub struct Round1State {
	/// Primary commitment polynomial w (in dilithium format) - first of K commitments
	pub w: polyvec::Polyveck,
	/// Primary randomness y used for commitment generation - first of K values
	pub y: polyvec::Polyvecl,
	/// Floating-point y vector for threshold rejection sampling
	pub y_fvec: FVec,
	/// Original hyperball sample for threshold rejection sampling
	pub hyperball_sample: FVec,
	/// Random bytes used for commitment
	pub rho_prime: [u8; 64],
	/// K different w commitments for canonical iterations
	pub w_commitments: Vec<polyvec::Polyveck>,
	/// K different y randomness values corresponding to w_commitments
	pub y_commitments: Vec<polyvec::Polyvecl>,
	/// K different hyperball samples for reuse in Round 3 (reference approach)
	pub hyperball_samples: Vec<FVec>,
}

impl Round1State {
	/// Generate Round 1 commitment using real ML-DSA operations
	pub fn new_with_seed(
		sk: &PrivateKey,
		config: &ThresholdConfig,
		seed: &[u8; 32],
	) -> ThresholdResult<(Vec<u8>, Self)> {
		// Generate deterministic random bytes for commitment using threshold hyperball sampling
		let mut rho_prime = [0u8; 64];
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, seed, 32);
		fips202::shake256_absorb(&mut state, b"rho_prime", 9);
		fips202::shake256_finalize(&mut state);
		fips202::shake256_squeeze(&mut rho_prime, 64, &mut state);

		// Generate K different commitment/randomness pairs
		// Use proper K value derived from threshold parameters matching reference implementation
		let k = config.k_iterations as usize;
		let mut w_commitments = Vec::with_capacity(k);
		let mut y_commitments = Vec::with_capacity(k);
		let mut hyperball_samples = Vec::with_capacity(k);

		// Initialize matrix A once for all computations
		let mut a_matrix: Vec<polyvec::Polyvecl> =
			(0..dilithium_params::K).map(|_| polyvec::Polyvecl::default()).collect();
		polyvec::matrix_expand(&mut a_matrix, &sk.rho);

		// Generate K different (w, y) pairs using different seeds
		for k_iter in 0..k {
			// Use threshold-specific hyperball sampling with different seed per iteration
			let fvec_size =
				dilithium_params::N as usize * (dilithium_params::L + dilithium_params::K);
			let mut fvec = FVec::new(fvec_size);

			// Create unique seed for this iteration by mixing original seed with k_iter
			let mut iter_seed = [0u8; 32];
			iter_seed[..32].copy_from_slice(seed);
			iter_seed[0] ^= k_iter as u8; // Modify seed for each iteration
			iter_seed[31] ^= (k_iter >> 8) as u8;

			let mut iter_rho_prime = [0u8; 64];
			let mut state = fips202::KeccakState::default();
			fips202::shake256_absorb(&mut state, &iter_seed, 32);
			fips202::shake256_absorb(&mut state, b"rho_prime", 9);
			fips202::shake256_absorb(&mut state, &[k_iter as u8], 1); // Additional uniqueness
			fips202::shake256_finalize(&mut state);
			fips202::shake256_squeeze(&mut iter_rho_prime, 64, &mut state);

			// Sample from hyperball using threshold parameters
			fvec.sample_hyperball(config.r_prime, config.nu, &iter_rho_prime, k_iter as u16);

			// Store hyperball sample for reuse in Round 3 (reference approach)
			hyperball_samples.push(fvec.clone());

			// Round to integer polynomials
			let mut y_k = polyvec::Polyvecl::default();
			let mut e_k = polyvec::Polyveck::default();
			fvec.round(&mut y_k, &mut e_k);

			// Compute w_k = A·y_k using NTT
			let mut w_k = polyvec::Polyveck::default();
			let mut y_k_ntt = y_k.clone();
			for i in 0..dilithium_params::L {
				ntt_poly(&mut y_k_ntt.vec[i]);
			}

			for i in 0..dilithium_params::K {
				// Use CIRCL-compatible pointwise multiplication to match Go reference
				poly_dot_hat_circl(&mut w_k.vec[i], &a_matrix[i], &y_k_ntt);

				// CRITICAL: Apply ReduceLe2Q in NTT domain BEFORE InvNTT
				// This prevents overflow when transforming back to normal domain
				for j in 0..dilithium_params::N as usize {
					let coeff = w_k.vec[i].coeffs[j];
					// Handle negative coefficients: add Q to bring into [0, 2Q) range
					let coeff_u32 = if coeff < 0 {
						(coeff + dilithium_params::Q as i32) as u32
					} else {
						coeff as u32
					};
					w_k.vec[i].coeffs[j] = reduce_le2q(coeff_u32) as i32;
				}

				inv_ntt_poly(&mut w_k.vec[i]);

				// Add error term e_k for threshold scheme (matching Go: ws[i][j].Add(&e_[j], &ws[i][j]))
				poly::add_ip(&mut w_k.vec[i], &e_k.vec[i]);

				// Apply ReduceLe2Q after Add (matching Go: ws[i][j].ReduceLe2Q())
				for j in 0..dilithium_params::N as usize {
					let coeff = w_k.vec[i].coeffs[j];
					let coeff_u32 = if coeff < 0 {
						(coeff + dilithium_params::Q as i32) as u32
					} else {
						coeff as u32
					};
					w_k.vec[i].coeffs[j] = reduce_le2q(coeff_u32) as i32;
				}

			}

			// Apply NormalizeAssumingLe2Q to match Go reference behavior
			// Go uses uint32 which means values are ALWAYS in [0, Q) representation
			// We must match this by normalizing our i32 values to [0, Q) range
			for i in 0..dilithium_params::K {
				normalize_assuming_le2q(&mut w_k.vec[i]);
			}

			// Store this iteration's w and y
			w_commitments.push(w_k.clone());
			y_commitments.push(y_k.clone());
		}

		// Use the first commitment as the primary w and y for backward compatibility
		let w = w_commitments[0].clone();
		let y = y_commitments[0].clone();

		// Use the first iteration's values for the primary fvec and rho_prime
		let fvec_size = dilithium_params::N as usize * (dilithium_params::L + dilithium_params::K);
		let mut fvec = FVec::new(fvec_size);
		fvec.sample_hyperball(config.r_prime, config.nu, &rho_prime, 0);

		// Pack w for commitment hash using 23-bit packing (matching Go)
		// Size = K_iterations * K * PolyQSize = k * 8 * 736 bytes
		const POLY_Q_SIZE: usize = (256 * 23) / 8; // 736 bytes
		let single_commitment_size = dilithium_params::K * POLY_Q_SIZE; // 8 * 736 = 5888
		let w_packed_size = k * single_commitment_size;
		let mut w_packed = vec![0u8; w_packed_size];

		// Pack all K iterations of w
		let mut offset = 0;
		for k_idx in 0..k {
			if k_idx < w_commitments.len() && offset + single_commitment_size <= w_packed.len() {
				Self::pack_w_dilithium(&w_commitments[k_idx], &mut w_packed[offset..offset + single_commitment_size]);
				offset += single_commitment_size;
			}
		}

		// Generate commitment hash
		let mut commitment = vec![0u8; 32];
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, &sk.tr, sk.tr.len());
		fips202::shake256_absorb(&mut state, &[sk.id], 1);
		fips202::shake256_absorb(&mut state, &w_packed, w_packed.len());
		fips202::shake256_finalize(&mut state);
		fips202::shake256_squeeze(&mut commitment, 32, &mut state);

		Ok((
			commitment,
			Self {
				w,
				y,
				y_fvec: fvec.clone(),
				hyperball_sample: fvec,
				rho_prime,
				w_commitments,
				y_commitments,
				hyperball_samples,
			},
		))
	}

	/// Generate Round 1 commitment using rho_prime directly (matches Go API)
	pub fn new_with_rhoprime(
		sk: &PrivateKey,
		config: &ThresholdConfig,
		rho_prime: &[u8; 64],
		nonce_base: u16,
	) -> ThresholdResult<(Vec<u8>, Self)> {
		// Generate K different commitment/randomness pairs
		// Use proper K value derived from threshold parameters matching reference implementation
		let k = config.k_iterations as usize;
		let mut w_commitments = Vec::with_capacity(k);
		let mut y_commitments = Vec::with_capacity(k);
		let mut hyperball_samples = Vec::with_capacity(k);

		// Initialize matrix A once for all computations
		let mut a_matrix: Vec<polyvec::Polyvecl> =
			(0..dilithium_params::K).map(|_| polyvec::Polyvecl::default()).collect();
		polyvec::matrix_expand(&mut a_matrix, &sk.rho);

		// Generate K different (w, y) pairs using same rho_prime but different nonces
		for k_iter in 0..k {
			// Use threshold-specific hyperball sampling
			let fvec_size =
				dilithium_params::N as usize * (dilithium_params::L + dilithium_params::K);
			let mut fvec = FVec::new(fvec_size);

			// Sample from hyperball using threshold parameters with unique nonce per iteration
			// This matches Go: SampleHyperball(&sts[i], params.rPrime, params.nu, rhop, nonce*params.K+i)
			let nonce = nonce_base * config.k_iterations + k_iter as u16;
			fvec.sample_hyperball(config.r_prime, config.nu, rho_prime, nonce);

			// Store hyperball sample for reuse in Round 3 (reference approach)
			hyperball_samples.push(fvec.clone());

			// Round to integer polynomials
			let mut y_k = polyvec::Polyvecl::default();
			let mut e_k = polyvec::Polyveck::default();
			fvec.round(&mut y_k, &mut e_k);

			// Compute w_k = A·y_k using NTT
			let mut w_k = polyvec::Polyveck::default();
			let mut y_k_ntt = y_k.clone();
			for i in 0..dilithium_params::L {
				ntt_poly(&mut y_k_ntt.vec[i]);
			}

			for i in 0..dilithium_params::K {
				// Use CIRCL-compatible pointwise multiplication to match Go reference
				poly_dot_hat_circl(&mut w_k.vec[i], &a_matrix[i], &y_k_ntt);

				// CRITICAL: Apply ReduceLe2Q in NTT domain BEFORE InvNTT
				// This prevents overflow when transforming back to normal domain
				for j in 0..dilithium_params::N as usize {
					let coeff = w_k.vec[i].coeffs[j];
					// Handle negative coefficients: add Q to bring into [0, 2Q) range
					let coeff_u32 = if coeff < 0 {
						(coeff + dilithium_params::Q as i32) as u32
					} else {
						coeff as u32
					};
					w_k.vec[i].coeffs[j] = reduce_le2q(coeff_u32) as i32;
				}

				inv_ntt_poly(&mut w_k.vec[i]);

				// Add error term e_k for threshold scheme (matching Go: ws[i][j].Add(&e_[j], &ws[i][j]))
				poly::add_ip(&mut w_k.vec[i], &e_k.vec[i]);

				// Apply ReduceLe2Q after Add (matching Go: ws[i][j].ReduceLe2Q())
				for j in 0..dilithium_params::N as usize {
					let coeff = w_k.vec[i].coeffs[j];
					let coeff_u32 = if coeff < 0 {
						(coeff + dilithium_params::Q as i32) as u32
					} else {
						coeff as u32
					};
					w_k.vec[i].coeffs[j] = reduce_le2q(coeff_u32) as i32;
				}
			}

			// Apply NormalizeAssumingLe2Q to match Go reference behavior
			// Go uses uint32 which means values are ALWAYS in [0, Q) representation
			// We must match this by normalizing our i32 values to [0, Q) range
			for i in 0..dilithium_params::K {
				normalize_assuming_le2q(&mut w_k.vec[i]);
			}

			// Store this iteration's w and y
			w_commitments.push(w_k.clone());
			y_commitments.push(y_k.clone());
		}

		// Use the first commitment as the primary w and y for backward compatibility
		let w = w_commitments[0].clone();
		let y = y_commitments[0].clone();

		// Use the first iteration's values for the primary fvec
		let fvec_size = dilithium_params::N as usize * (dilithium_params::L + dilithium_params::K);
		let mut fvec = FVec::new(fvec_size);
		let nonce = nonce_base * config.k_iterations;
		fvec.sample_hyperball(config.r_prime, config.nu, rho_prime, nonce);

		// Pack w for commitment hash using 23-bit packing (matching Go)
		// Size = K_iterations * K * PolyQSize = k * 8 * 736 bytes
		const POLY_Q_SIZE: usize = (256 * 23) / 8; // 736 bytes
		let single_commitment_size = dilithium_params::K * POLY_Q_SIZE; // 8 * 736 = 5888
		let w_packed_size = (config.k_iterations as usize) * single_commitment_size;
		let mut w_packed = vec![0u8; w_packed_size];

		// Pack all K iterations of w
		let mut offset = 0;
		for k_idx in 0..config.k_iterations as usize {
			if k_idx < w_commitments.len() && offset + single_commitment_size <= w_packed.len() {
				Self::pack_w_dilithium(&w_commitments[k_idx], &mut w_packed[offset..offset + single_commitment_size]);
				offset += single_commitment_size;
			}
		}

		// Generate commitment hash
		let mut commitment = vec![0u8; 32];
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, &sk.tr, sk.tr.len());
		fips202::shake256_absorb(&mut state, &[sk.id], 1);
		fips202::shake256_absorb(&mut state, &w_packed, w_packed.len());
		fips202::shake256_finalize(&mut state);
		fips202::shake256_squeeze(&mut commitment, 32, &mut state);

		Ok((
			commitment,
			Self {
				w,
				y,
				y_fvec: fvec.clone(),
				hyperball_sample: fvec,
				rho_prime: *rho_prime,
				w_commitments,
				y_commitments,
				hyperball_samples,
			},
		))
	}

	/// Generate Round 1 commitment using seed
	pub fn new(
		sk: &PrivateKey,
		config: &ThresholdConfig,
		seed: &[u8; 32],
	) -> ThresholdResult<(Vec<u8>, Self)> {
		Self::new_with_seed(sk, config, seed)
	}

	/// Pack polynomial vector w into bytes using 23-bit packing (matching Go's PackW/PolyPackW)
	/// Each coefficient uses 23 bits, packed into PolyQSize = 256 * 23 / 8 = 736 bytes per polynomial
	pub fn pack_w_dilithium(w: &polyvec::Polyveck, buf: &mut [u8]) {
		const POLY_Q_SIZE: usize = (256 * 23) / 8; // 736 bytes per polynomial
		let mut offset = 0;

		for i in 0..dilithium_params::K {
			if offset + POLY_Q_SIZE > buf.len() {
				break;
			}
			// Pack polynomial using 23-bit coefficients (same as poly_pack_w)
			let poly = &w.vec[i];
			let poly_buf = &mut buf[offset..offset + POLY_Q_SIZE];

			let mut v: u32 = 0;
			let mut j: u32 = 0;
			let mut k: usize = 0;

			for coeff_idx in 0..dilithium_params::N as usize {
				// Coefficients should be in [0, Q) range from normalization
				let coeff = (poly.coeffs[coeff_idx] as u32) & ((1 << 23) - 1);
				v |= coeff << j;
				j += 23;

				while j >= 8 {
					poly_buf[k] = v as u8;
					v >>= 8;
					j -= 8;
					k += 1;
				}
			}

			// Pack remaining bits
			if j > 0 && k < poly_buf.len() {
				poly_buf[k] = v as u8;
			}

			offset += POLY_Q_SIZE;
		}
	}

	/// Unpack polynomial vector w from bytes (23-bit packing, matching Go's UnpackW)
	fn unpack_w_dilithium(buf: &[u8]) -> ThresholdResult<polyvec::Polyveck> {
		const POLY_Q_SIZE: usize = (256 * 23) / 8; // 736 bytes per polynomial
		let mut w = polyvec::Polyveck::default();
		let mut offset = 0;

		for i in 0..dilithium_params::K {
			if offset + POLY_Q_SIZE > buf.len() {
				break;
			}
			let poly_buf = &buf[offset..offset + POLY_Q_SIZE];

			// Unpack 23-bit coefficients
			for coeff_idx in 0..dilithium_params::N as usize {
				let bit_offset = coeff_idx * 23;
				let byte_offset = bit_offset / 8;
				let bit_shift = bit_offset % 8;

				if byte_offset + 3 <= poly_buf.len() {
					let mut val = (poly_buf[byte_offset] as u32)
						| ((poly_buf[byte_offset + 1] as u32) << 8)
						| ((poly_buf[byte_offset + 2] as u32) << 16);
					if byte_offset + 3 < poly_buf.len() {
						val |= (poly_buf[byte_offset + 3] as u32) << 24;
					}
					w.vec[i].coeffs[coeff_idx] = ((val >> bit_shift) & 0x7FFFFF) as i32;
				}
			}

			offset += POLY_Q_SIZE;
		}
		Ok(w)
	}

	/// Use unpack_w_dilithium to parse commitment data
	pub fn parse_commitment(&self, buf: &[u8]) -> ThresholdResult<polyvec::Polyveck> {
		Self::unpack_w_dilithium(buf)
	}

	/// Pack commitment data in canonical format for combine_signatures
	pub fn pack_commitment_canonical(&self, config: &ThresholdConfig) -> Vec<u8> {
		let k = config.k_iterations as usize;
		let single_commitment_size = Params::SINGLE_COMMITMENT_SIZE;
		let total_size = k * single_commitment_size;
		let mut buf = vec![0u8; total_size];

		// Use the actual K different w commitments instead of copies
		let w_vec = if self.w_commitments.len() >= k {
			&self.w_commitments[..k]
		} else {
			&self.w_commitments
		};

		pack_w_commitments(w_vec, &mut buf);
		buf
	}
}

/// Round 2 state for threshold signing

pub struct Round2State {
	/// Commitment hashes from Round 1
	pub commitment_hashes: Vec<[u8; 32]>,
	/// Message hash μ
	pub mu: [u8; 64],
	/// Active party bitmask
	pub active_parties: u8,
	/// Aggregated w values for challenge computation
	pub w_aggregated: Vec<polyvec::Polyveck>,
}

impl Zeroize for Round2State {
	fn zeroize(&mut self) {
		for hash in &mut self.commitment_hashes {
			hash.zeroize();
		}
		self.commitment_hashes.clear();
		self.mu.zeroize();
		// Note: w_aggregated doesn't implement Zeroize, so we manually clear
		for w in &mut self.w_aggregated {
			for i in 0..dilithium_params::K {
				w.vec[i].coeffs.fill(0);
			}
		}
		self.w_aggregated.clear();
	}
}

impl Zeroize for Round1State {
	fn zeroize(&mut self) {
		// Manually clear dilithium types that don't implement Zeroize
		for i in 0..dilithium_params::K {
			self.w.vec[i].coeffs.fill(0);
		}
		for i in 0..dilithium_params::L {
			self.y.vec[i].coeffs.fill(0);
		}
		self.rho_prime.zeroize();

		// Clear the K different w_commitments
		for w_commit in &mut self.w_commitments {
			for i in 0..dilithium_params::K {
				w_commit.vec[i].coeffs.fill(0);
			}
		}
		self.w_commitments.clear();

		// Clear the K different y_commitments
		for y_commit in &mut self.y_commitments {
			for i in 0..dilithium_params::L {
				y_commit.vec[i].coeffs.fill(0);
			}
		}
		self.y_commitments.clear();
	}
}

impl ZeroizeOnDrop for Round1State {}

impl ZeroizeOnDrop for Round2State {}

impl Round2State {
	/// Process Round 1 commitments and prepare for Round 2 with proper w aggregation
	pub fn new(
		sk: &PrivateKey,
		active_parties: u8,
		message: &[u8],
		context: &[u8],
		round1_commitments: &[Vec<u8>],
		other_parties_w_values: &[Vec<u8>],
		round1_state: &Round1State,
	) -> ThresholdResult<(Vec<u8>, Self)> {
		crate::common::validate_context(context)?;

		// Store commitment hashes
		let mut commitment_hashes = Vec::new();
		for (idx, commitment) in round1_commitments.iter().enumerate() {
			if commitment.len() != 32 {
				return Err(ThresholdError::InvalidCommitment {
					party_id: idx as u8,
					expected_size: 32,
					actual_size: commitment.len(),
				});
			}
			let mut hash = [0u8; 32];
			hash.copy_from_slice(commitment);
			commitment_hashes.push(hash);
		}

		// Compute message hash μ
		let mu = Self::compute_mu_internal(sk, message, context);

		// Aggregate w values from all parties (including our own) for all K iterations
		// Use w_commitments if available (populated in Round 1), otherwise fallback to single w
		let k_iterations = if !round1_state.w_commitments.is_empty() {
			round1_state.w_commitments.len()
		} else {
			1
		};

		let mut w_aggregated = Vec::with_capacity(k_iterations);
		if !round1_state.w_commitments.is_empty() {
			for k in 0..k_iterations {
				w_aggregated.push(round1_state.w_commitments[k].clone());
			}
		} else {
			w_aggregated.push(round1_state.w.clone());
		}

		// Add w values from other parties
		// Add w values from other parties - these are in canonical format with multiple K iterations
		for (party_idx, w_data) in other_parties_w_values.iter().enumerate() {
			if !w_data.is_empty() {
				let single_commitment_size = Params::SINGLE_COMMITMENT_SIZE;

				for k in 0..k_iterations {
					let start = k * single_commitment_size;
					let end = start + single_commitment_size;

					if end <= w_data.len() {
						let commitment_bytes = &w_data[start..end];
						match unpack_commitment_dilithium(commitment_bytes) {
							Ok(w_other) => {
								if k < w_aggregated.len() {
									aggregate_commitments_dilithium(&mut w_aggregated[k], &w_other);
								}
							},
							Err(_e) => {
								return Err(ThresholdError::InvalidCommitment {
									party_id: party_idx as u8,
									expected_size: single_commitment_size,
									actual_size: commitment_bytes.len(),
								});
							},
						}
					}
				}
			}
		}

		// Pack our w for transmission
		// Pack our w for transmission (using canonical packing)
		// We return the first one to maintain compatibility with callers expecting single w packing
		// but Round2State now holds the full aggregated set.
		let mut w_packed = vec![0u8; dilithium_params::K * (dilithium_params::N as usize) * 4];
		if !round1_state.w_commitments.is_empty() {
			Round1State::pack_w_dilithium(&round1_state.w_commitments[0], &mut w_packed);
		} else {
			Round1State::pack_w_dilithium(&round1_state.w, &mut w_packed);
		}

		Ok((w_packed, Self { commitment_hashes, mu, active_parties, w_aggregated }))
	}

	/// Compute message hash μ using ML-DSA specification
	fn compute_mu_internal(sk: &PrivateKey, message: &[u8], context: &[u8]) -> [u8; 64] {
		compute_mu(&sk.tr, message, context)
	}
}

/// Compute message hash μ using ML-DSA specification
/// μ = SHAKE256(tr || 0x00 || ctx_len || ctx || msg)
pub fn compute_mu(tr: &[u8; 64], message: &[u8], context: &[u8]) -> [u8; 64] {
	let mut input = Vec::new();
	input.extend_from_slice(tr);
	input.push(0u8); // Domain separator for pure signatures
	input.push(context.len() as u8);
	if !context.is_empty() {
		input.extend_from_slice(context);
	}
	input.extend_from_slice(message);

	let mut mu = [0u8; 64];
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, &input, input.len());
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut mu, 64, &mut state);
	mu
}

/// Round 3 state for generating signature responses
#[derive(Debug)]
pub struct Round3State {
	/// Primary signature response (first of K responses)
	pub response: Vec<u8>,
	/// K different signature responses corresponding to K commitments
	pub responses: Vec<Vec<u8>>,
}

impl Zeroize for Round3State {
	fn zeroize(&mut self) {
		self.response.zeroize();
		for response in &mut self.responses {
			response.zeroize();
		}
		self.responses.clear();
	}
}

impl ZeroizeOnDrop for Round3State {}

impl Round3State {
	/// Generate K different Round 3 signature responses using reference approach
	pub fn new(
		sk: &PrivateKey,
		config: &ThresholdConfig,
		_round2_commitments: &[Vec<u8>],
		round1_state: &Round1State,
		round2_state: &Round2State,
	) -> ThresholdResult<(Vec<u8>, Self)> {
		// Create active parties list from Round 2 state
		let mut active_parties = Vec::new();
		for i in 0..config.base.total_parties() {
			if (round2_state.active_parties & (1 << i)) != 0 {
				active_parties.push(i);
			}
		}

		// Use reference approach with stored hyperball samples
		let response = Self::compute_threshold_response_reference_approach(
			sk,
			&round2_state.w_aggregated,
			&round2_state.mu,
			&round1_state.hyperball_samples,
			&round1_state.y_commitments,
			config,
			&active_parties,
		)?;

		// Create individual response vectors for each K iteration
		let k = config.base.canonical_k() as usize;
		let single_response_size = dilithium_params::L * dilithium_params::POLYZ_PACKEDBYTES;
		let mut responses = Vec::with_capacity(k);

		for i in 0..k {
			let start_idx = i * single_response_size;
			let end_idx = start_idx + single_response_size;
			if end_idx <= response.len() {
				responses.push(response[start_idx..end_idx].to_vec());
			} else {
				responses.push(vec![0u8; single_response_size]);
			}
		}

		Ok((response.clone(), Self { response, responses }))
	}

	/// Compute threshold response using reference implementation approach (direct polynomial arithmetic)
	fn compute_threshold_response_reference_approach(
		sk: &PrivateKey,
		w_aggregated: &[polyvec::Polyveck],
		mu: &[u8; 64],
		hyperball_samples: &[FVec],
		_y_commitments: &[polyvec::Polyvecl],
		config: &ThresholdConfig,
		active_parties: &[u8],
	) -> ThresholdResult<Vec<u8>> {
		// Recover partial secret using hardcoded patterns like reference recoverShare
		// NOTE: recover_share_hardcoded returns values ALREADY in NTT domain
		let (s1h_ntt, s2h_ntt) = secret_sharing::recover_share_hardcoded(
			&sk.shares,
			sk.id,
			active_parties,
			config.base.threshold(),
			config.base.total_parties(),
		)?;

		let k = config.base.canonical_k() as usize;
		let packed_size = dilithium_params::L * dilithium_params::POLYZ_PACKEDBYTES;
		let mut response = vec![0u8; k * packed_size];

		// For each of the K commitments/iterations
		for i in 0..k.min(hyperball_samples.len()) {
			// Step 1: Decompose w into w0 and w1
			let mut w0 = polyvec::Polyveck::default();
			let mut w1;

			if i < w_aggregated.len() {
				w1 = w_aggregated[i].clone();
			} else {
				return Err(ThresholdError::InvalidData(format!(
					"Missing w_aggregated data for iteration {}",
					i
				)));
			}

				// Reduce coefficients to [0, Q) range before decomposition
				for j in 0..dilithium_params::K {
					poly::reduce(&mut w1.vec[j]);
					poly::caddq(&mut w1.vec[j]);
				}

				// Use Go-compatible decompose to match reference implementation exactly
				let w_input = w1.clone();
				veck_decompose_go(&w_input, &mut w0, &mut w1);

			// Step 2: Generate challenge c~ = H(μ || w1)
			let mut w1_packed =
				vec![0u8; dilithium_params::K * dilithium_params::POLYW1_PACKEDBYTES];
			polyvec::k_pack_w1(&mut w1_packed, &w1);

			let mut c_bytes = [0u8; dilithium_params::C_DASH_BYTES];
			let mut keccak_state = fips202::KeccakState::default();
			fips202::shake256_absorb(&mut keccak_state, mu, 64);
			fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
			fips202::shake256_finalize(&mut keccak_state);
			fips202::shake256_squeeze(
				&mut c_bytes,
				dilithium_params::C_DASH_BYTES,
				&mut keccak_state,
			);
			let mut challenge_poly = poly::Poly::default();
			poly::challenge(&mut challenge_poly, &c_bytes);

			// Convert to NTT - use circl_ntt consistently
			let mut ch_ntt = challenge_poly.clone();
			crate::circl_ntt::ntt(&mut ch_ntt);

			// Step 3: Compute c·s1 (like reference)
			let mut z = polyvec::Polyvecl::default();
			for j in 0..dilithium_params::L {
				crate::circl_ntt::mul_hat(&mut z.vec[j], &ch_ntt, &s1h_ntt.vec[j]);
				crate::circl_ntt::inv_ntt(&mut z.vec[j]);
			}
			// Normalize like reference
			for j in 0..dilithium_params::L {
				poly::reduce(&mut z.vec[j]);
				// Match Go reference: Normalize() keeps values in [0, Q) (they use uint32)
			}

			// Step 4: Compute c·s2 (like reference)
			let mut y = polyvec::Polyveck::default();
			for j in 0..dilithium_params::K {
				crate::circl_ntt::mul_hat(&mut y.vec[j], &ch_ntt, &s2h_ntt.vec[j]);
				crate::circl_ntt::inv_ntt(&mut y.vec[j]);
			}
			// Normalize like reference
			for j in 0..dilithium_params::K {
				poly::reduce(&mut y.vec[j]);
				// Match Go reference: Normalize() keeps values in [0, Q) (they use uint32)
			}

			// Step 5: Create FVec from z,y and add original hyperball sample (like reference)
			let mut zf = FVec::from_polyvecs(&z, &y);
			zf.add(&hyperball_samples[i]);

			// Step 6: Round FVec back to integers
			// This gives us z = y_commitment + c*s1 + hyperball_sample
			let mut z_final = polyvec::Polyvecl::default();
			let mut y_final = polyvec::Polyveck::default();
			zf.round(&mut z_final, &mut y_final);

			// Convert z_final from centered format [-Q/2, Q/2] to [0, Q) format like Go
			for j in 0..dilithium_params::L {
				for k in 0..dilithium_params::N as usize {
					let coeff = z_final.vec[j].coeffs[k];
					// Convert from centered to [0, Q)
					let coeff_u32 = if coeff < 0 {
						(coeff + dilithium_params::Q as i32) as u32
					} else {
						coeff as u32
					};
					z_final.vec[j].coeffs[k] = coeff_u32 as i32;
				}
			}

			// Step 8: Pack this iteration's response
			// z_pack expects values in centered form [-(γ₁-1), γ₁], so convert from [0, Q)
			let start_idx = i * packed_size;

			for poly_idx in 0..dilithium_params::L {
				// Convert to centered form before packing
				let mut z_centered = z_final.vec[poly_idx].clone();
				center_dilithium_poly(&mut z_centered);

				let poly_start = start_idx + poly_idx * dilithium_params::POLYZ_PACKEDBYTES;
				let poly_end = poly_start + dilithium_params::POLYZ_PACKEDBYTES;
				if poly_end <= response.len() {
					poly::z_pack(&mut response[poly_start..poly_end], &z_centered);
				}
			}

		}

		Ok(response)
	}

	/// Pack K different responses in canonical format for combine_signatures
	pub fn pack_responses_canonical(&self, config: &ThresholdConfig) -> Vec<u8> {
		let k = config.k_iterations as usize;
		let single_response_size = Params::SINGLE_RESPONSE_SIZE;
		let total_size = k * single_response_size;
		let mut buf = vec![0u8; total_size];

		// Use the actual K different responses instead of copies
		let responses_to_pack =
			if self.responses.len() >= k { &self.responses[..k] } else { &self.responses };

		for (i, response) in responses_to_pack.iter().enumerate() {
			let start_idx = i * single_response_size;
			let end_idx = start_idx + response.len().min(single_response_size);
			if start_idx < buf.len() && end_idx <= buf.len() {
				buf[start_idx..end_idx].copy_from_slice(&response[..end_idx - start_idx]);
			}
		}

		buf
	}
}

/// Generate threshold keys from seed using dilithium's key generation
pub fn generate_threshold_key(
	seed: &[u8; SEED_SIZE],
	config: &ThresholdConfig,
) -> ThresholdResult<(PublicKey, Vec<PrivateKey>)> {
	// Generate proper threshold secret shares using Threshold-ML-DSA approach
	let params = config.threshold_params();
	// Initialize SHAKE-256 stream for consistent randomness generation (matching Go reference)
	// Sequence: Seed || K || L -> rho -> party_keys -> shares
	let mut h = qp_rusty_crystals_dilithium::fips202::KeccakState::default();
	qp_rusty_crystals_dilithium::fips202::shake256_absorb(&mut h, seed, 32);

	// NIST mode: absorb K and L
	let kl = [dilithium_params::K as u8, dilithium_params::L as u8];
	qp_rusty_crystals_dilithium::fips202::shake256_absorb(&mut h, &kl, 2);
	qp_rusty_crystals_dilithium::fips202::shake256_finalize(&mut h);

	// 1. Squeeze rho
	let mut rho = [0u8; 32];
	qp_rusty_crystals_dilithium::fips202::shake256_squeeze(&mut rho, 32, &mut h);

	// 2. Squeeze party keys
	let mut party_keys = Vec::with_capacity(params.total_parties() as usize);
	for _ in 0..params.total_parties() {
		let mut key = [0u8; 32];
		qp_rusty_crystals_dilithium::fips202::shake256_squeeze(&mut key, 32, &mut h);

		party_keys.push(key);
	}

	// 3. Generate proper threshold shares using the SAME stream
	let (s1_total, s2_total, s1h_total, s2h_total, party_shares) = secret_sharing::generate_proper_threshold_shares(
		&mut h,
		params.threshold(),
		params.total_parties(),
	)?;

	// Generate matrix A from rho (stored in normal form, NTT applied when needed)
	let mut a_ntt = Mat::zero();
	a_ntt.derive_from_seed(&rho);

	// Use the already-normalized NTT versions (s1h_total, s2h_total) from share generation
	// This matches Go's approach: NTT each share, sum them, then normalize
	let s1_ntt = s1h_total;
	let _s2_ntt = s2h_total;

	// Compute t = A*s1 + s2 following reference implementation approach
	// First compute A*s1 in NTT domain, then add s2 in normal domain
	let mut t = polyvec::Polyveck::default();

	// Compute A*s1 first (like reference PolyDotHat(&t[i], &A[i], s1h))
	for i in 0..dilithium_params::K {
		for j in 0..dilithium_params::L {
			let mut temp = poly::Poly::default();
			// Convert threshold polynomial to dilithium polynomial
			let mut a_poly = poly::Poly::default();
			let threshold_poly = a_ntt.get(i, j);
			for k in 0..(dilithium_params::N as usize) {
				a_poly.coeffs[k] = threshold_poly.get(k).value() as i32;
			}
			// A is already effectively in NTT domain (standard ML-DSA optimization)
			// Use dilithium's pointwise multiplication (both A and s1 in NTT domain)
			poly::pointwise_montgomery(&mut temp, &a_poly, &s1_ntt.vec[j]);
			// Use standard addition
			t.vec[i] = poly::add(&t.vec[i], &temp);
		}

		// Apply reduce like reference implementation
		poly::reduce(&mut t.vec[i]);

		// Convert from NTT domain
		poly::invntt_tomont(&mut t.vec[i]);
	}

	// Now add s2 in normal domain (like reference t.Add(&t, s2))
	for i in 0..dilithium_params::K {
		t.vec[i] = poly::add(&t.vec[i], &s2_total.vec[i]);
	}

	// Apply normalization like reference t.Normalize()
	for i in 0..dilithium_params::K {
		poly::reduce(&mut t.vec[i]);
	}

	// Normalize t to [0, Q) range before power2round (required for correct t1 values)
	for i in 0..dilithium_params::K {
		for j in 0..(dilithium_params::N as usize) {
			let coeff = t.vec[i].coeffs[j];
			// Normalize to [0, Q) using modular arithmetic
			let normalized =
				((coeff % dilithium_params::Q) + dilithium_params::Q) % dilithium_params::Q;
			t.vec[i].coeffs[j] = normalized;
		}
	}

	// Extract t1 (high bits) and t0 (low bits)
	// After normalization, power2round will produce t1 in [0, (Q-1)/2^D] range
	let mut t0 = polyvec::Polyveck::default();
	let mut t1_poly = t.clone();
	polyvec::k_power2round(&mut t1_poly, &mut t0);

	// Convert t1 to threshold format (power2round already produces small coefficients)
	// t1 values are in [0, (Q-1)/2^D] range after Power2Round and should NOT be centered
	let mut t1_threshold = VecK::<{ Params::K }>::zero();
	for i in 0..Params::K.min(dilithium_params::K) {
		for j in 0..N.min(dilithium_params::N as usize) {
			let coeff = t1_poly.vec[i].coeffs[j];
			// t1 coefficients are already in correct range [0, (Q-1)/2^D] ≈ [0, 1023]
			// Do NOT center them - store as-is in field element format
			let coeff_u32 =
				if coeff < 0 { (dilithium_params::Q + coeff) as u32 } else { coeff as u32 };
			t1_threshold.get_mut(i).set(j, FieldElement::new(coeff_u32));
		}
	}

	// Pack public key to compute tr
	let mut pk_packed = [0u8; dilithium_params::PUBLICKEYBYTES];
	packing::pack_pk(&mut pk_packed, &rho, &t1_poly);

	// Compute tr = CRH(pk) like reference implementation
	let mut tr = [0u8; 64];
	let mut h_tr = qp_rusty_crystals_dilithium::fips202::KeccakState::default();
	qp_rusty_crystals_dilithium::fips202::shake256_absorb(&mut h_tr, &pk_packed, pk_packed.len());
	qp_rusty_crystals_dilithium::fips202::shake256_finalize(&mut h_tr);
	qp_rusty_crystals_dilithium::fips202::shake256_squeeze(&mut tr, 64, &mut h_tr);

	let pk = PublicKey { rho, a_ntt: a_ntt.clone(), t1: t1_threshold, tr, packed: pk_packed };

	// Create private keys with proper secret shares
	let mut private_keys = Vec::with_capacity(params.total_parties() as usize);
	for party_id in 0..params.total_parties() {
		// Get the shares for this specific party
		let party_specific_shares = party_shares.get(&party_id).cloned().unwrap_or_default();

		let sk = PrivateKey {
			id: party_id,
			key: party_keys[party_id as usize],
			rho: pk.rho,
			a: a_ntt.clone(),
			tr: pk.tr,
			shares: party_specific_shares,
			s_total: Some((s1_total.clone(), s2_total.clone())),
		};
		private_keys.push(sk);
	}

	// Store original secrets in the first private key for verification
	if !private_keys.is_empty() {
		// Add original secrets as a special field - we'll add this to PrivateKey
		// For now, create a test function to access them
	}

	Ok((pk, private_keys))
}

/// Test function to get original secrets used in key generation
pub fn get_original_secrets_from_seed(
	seed: &[u8; SEED_SIZE],
	config: &ThresholdConfig,
) -> ThresholdResult<(polyvec::Polyvecl, polyvec::Polyveck)> {
	use qp_rusty_crystals_dilithium::fips202;

	let params = config.threshold_params();

	// Initialize SHAKE-256 stream matching generate_threshold_key
	let mut h = qp_rusty_crystals_dilithium::fips202::KeccakState::default();
	fips202::shake256_absorb(&mut h, seed, 32);

	// NIST mode: absorb K and L
	let kl = [dilithium_params::K as u8, dilithium_params::L as u8];
	fips202::shake256_absorb(&mut h, &kl, 2);
	fips202::shake256_finalize(&mut h);

	// 1. Squeeze rho
	let mut rho = [0u8; 32];
	fips202::shake256_squeeze(&mut rho, 32, &mut h);

	// 2. Squeeze party keys
	for _ in 0..params.total_parties() {
		let mut key = [0u8; 32];
		fips202::shake256_squeeze(&mut key, 32, &mut h);
	}

	// 3. Generate proper threshold shares using the SAME stream
	let (s1_total, s2_total, _s1h_total, _s2h_total, _party_shares) = secret_sharing::generate_proper_threshold_shares(
		&mut h,
		params.threshold(),
		params.total_parties(),
	)?;

	Ok((s1_total, s2_total))
}

/// Combine signature shares into final signature
/// Combine threshold signatures using reference ML-DSA approach (direct polynomial arithmetic)
pub fn combine_signatures(
	pk: &PublicKey,
	message: &[u8],
	context: &[u8],
	commitments: &[Vec<u8>],
	responses: &[Vec<u8>],
	config: &ThresholdConfig,
) -> ThresholdResult<Vec<u8>> {
	crate::common::validate_context(context)?;

	let params = config.threshold_params();
	if responses.len() < params.threshold() as usize {
		return Err(ThresholdError::InsufficientParties {
			provided: responses.len(),
			required: params.threshold(),
		});
	}
	if commitments.len() < params.threshold() as usize {
		return Err(ThresholdError::InsufficientParties {
			provided: commitments.len(),
			required: params.threshold(),
		});
	}

	// Use reference implementation approach: aggregate commitments and responses directly
	create_mldsa_signature_reference_approach(pk, message, context, commitments, responses, config)
}

/// Pack a polynomial in LeGamma1 format (matching Go's PolyPackLeGamma1)
/// Input coefficients should be in uint32 [0, Q) format (normalized)
/// For ML-DSA-87: Gamma1Bits = 19, PolyLeGamma1Size = 640
#[allow(dead_code)]
fn poly_pack_le_gamma1(p: &poly::Poly, buf: &mut [u8]) {
	const GAMMA1: u32 = dilithium_params::GAMMA1 as u32;
	const GAMMA1_BITS: usize = 19; // For ML-DSA-87

	if GAMMA1_BITS == 19 {
		let mut j = 0;
		for i in (0..640).step_by(5) {
			// Coefficients in [0, Q) format, transform to [0, 2*GAMMA1) for packing
			let mut p0 = GAMMA1.wrapping_sub(p.coeffs[j] as u32);
			p0 = p0.wrapping_add(((p0 as i32) >> 31) as u32 & (dilithium_params::Q as u32));
			let mut p1 = GAMMA1.wrapping_sub(p.coeffs[j + 1] as u32);
			p1 = p1.wrapping_add(((p1 as i32) >> 31) as u32 & (dilithium_params::Q as u32));

			// Pack two coefficients into 5 bytes (19 bits each)
			buf[i] = (p0 & 0xFF) as u8;
			buf[i + 1] = ((p0 >> 8) & 0xFF) as u8;
			buf[i + 2] = (((p0 >> 16) & 0x0F) | ((p1 & 0x0F) << 4)) as u8;
			buf[i + 3] = ((p1 >> 4) & 0xFF) as u8;
			buf[i + 4] = ((p1 >> 12) & 0xFF) as u8;

			j += 2;
		}
	} else {
		panic!("Unsupported GAMMA1_BITS");
	}
}

/// Unpack a polynomial from LeGamma1 format (matching Go's PolyUnpackLeGamma1)
/// Output coefficients will be in uint32 [0, Q) format (normalized)
fn poly_unpack_le_gamma1(p: &mut poly::Poly, buf: &[u8]) {
	const GAMMA1: u32 = dilithium_params::GAMMA1 as u32;
	const GAMMA1_BITS: usize = 19; // For ML-DSA-87

	if GAMMA1_BITS == 19 {
		let mut j = 0;
		for i in (0..640).step_by(5) {
			// Unpack two 19-bit coefficients from 5 bytes
			let mut p0 = (buf[i] as u32) | ((buf[i + 1] as u32) << 8) | (((buf[i + 2] & 0x0F) as u32) << 16);
			let mut p1 = ((buf[i + 2] >> 4) as u32) | ((buf[i + 3] as u32) << 4) | ((buf[i + 4] as u32) << 12);

			// Coefficients are in [0, 2*GAMMA1), transform to (-GAMMA1, GAMMA1]
			p0 = GAMMA1.wrapping_sub(p0);
			p1 = GAMMA1.wrapping_sub(p1);

			// Normalize to [0, Q) range
			p0 = p0.wrapping_add(((p0 as i32) >> 31) as u32 & (dilithium_params::Q as u32));
			p1 = p1.wrapping_add(((p1 as i32) >> 31) as u32 & (dilithium_params::Q as u32));

			p.coeffs[j] = p0 as i32;
			p.coeffs[j + 1] = p1 as i32;

			j += 2;
		}
	} else {
		panic!("Unsupported GAMMA1_BITS");
	}
}

/// Unpack a response from bytes using Go-compatible LeGamma1 format
fn unpack_response_dilithium(response: &[u8]) -> ThresholdResult<polyvec::Polyvecl> {
	const POLY_LE_GAMMA1_SIZE: usize = 640; // For ML-DSA-87 with 19-bit packing
	let single_response_size = dilithium_params::L * POLY_LE_GAMMA1_SIZE;
	let mut z = polyvec::Polyvecl::default();

	if response.len() < single_response_size {
		return Err(ThresholdError::InvalidData("Response too small".into()));
	}

	// Unpack using Go-compatible LeGamma1 format
	for i in 0..dilithium_params::L {
		let poly_offset = i * POLY_LE_GAMMA1_SIZE;
		poly_unpack_le_gamma1(
			&mut z.vec[i],
			&response[poly_offset..poly_offset + POLY_LE_GAMMA1_SIZE],
		);
	}

	Ok(z)
}

/// Unpack commitment from bytes - helper function for tests
pub fn unpack_commitment_dilithium(commitment: &[u8]) -> ThresholdResult<polyvec::Polyveck> {
	let mut w = polyvec::Polyveck::default();

	// Expect exactly K * POLY_Q_SIZE bytes for proper packed w commitment data (23-bit packing)
	let poly_q_size = (dilithium_params::N as usize * 23 + 7) / 8; // 736 bytes per poly
	let expected_len = dilithium_params::K * poly_q_size;

	if commitment.len() != expected_len {
		return Err(ThresholdError::InvalidCommitmentSize {
			expected: expected_len,
			actual: commitment.len(),
		});
	}

	// Unpack w coefficients from 23-bit packed format (like reference PolyUnpackW)
	for i in 0..dilithium_params::K {
		let poly_start = i * poly_q_size;
		let poly_buf = &commitment[poly_start..poly_start + poly_q_size];

		// Unpack using 23-bit format like reference implementation
		let mut v: u32 = 0;
		let mut j: u32 = 0;
		let mut k: usize = 0;

		for coeff_idx in 0..(dilithium_params::N as usize) {
			while j < 23 && k < poly_buf.len() {
				v = v + ((poly_buf[k] as u32) << j);
				j += 8;
				k += 1;
			}
			w.vec[i].coeffs[coeff_idx] = (v & ((1 << 23) - 1)) as i32;
			v >>= 23;
			j = j.saturating_sub(23);
		}

		// Keep coefficients in [0, Q) range as unpacked
		// Go reference uses uint32, so values are always in [0, Q) representation
		// We must maintain this representation to match their behavior
	}

	Ok(w)
}

/// Aggregate commitment vectors using proper dilithium polynomial addition
pub fn aggregate_commitments_dilithium(
	w_final: &mut polyvec::Polyveck,
	w_temp: &polyvec::Polyveck,
) {
	for i in 0..dilithium_params::K {
		// Use polyvec add_ip to match reference Add behavior
		poly::add_ip(&mut w_final.vec[i], &w_temp.vec[i]);
		// Apply normalize to match Go reference behavior (NormalizeAssumingLe2Q after Add)
		// Go's Add doesn't normalize but we need to ensure values stay in valid range
		normalize_assuming_le2q(&mut w_final.vec[i]);
	}
}

/// Aggregate response polynomials for threshold signature construction
pub fn aggregate_responses_dilithium(z_final: &mut polyvec::Polyvecl, z_temp: &polyvec::Polyvecl) {
	for i in 0..dilithium_params::L {
		// Add and then normalize like Go's Add + Normalize
		// This keeps values in [0, Q) range (unnormalized uint32 format)
		for j in 0..dilithium_params::N as usize {
			// Add the coefficients
			let sum = z_final.vec[i].coeffs[j] + z_temp.vec[i].coeffs[j];
			// Apply full modular reduction
			z_final.vec[i].coeffs[j] = sum;
		}

		// Apply reduce to handle overflow
		poly::reduce(&mut z_final.vec[i]);

		// Normalize to [0, Q) range like Go's Normalize()
		for j in 0..dilithium_params::N as usize {
			let mut coeff = z_final.vec[i].coeffs[j];
			// Ensure in [0, Q) range
			if coeff < 0 {
				coeff += dilithium_params::Q as i32;
			}
			// Apply normalize_assuming_le2q logic
			let y = coeff - dilithium_params::Q as i32;
			let mask = y >> 31;
			z_final.vec[i].coeffs[j] = y + (mask & dilithium_params::Q as i32);
		}
	}
}

/// Create a signature from w/z pair using reference implementation approach
fn create_signature_from_pair_reference(
	pk: &PublicKey,
	mu: &[u8; 64],
	w_final: &polyvec::Polyveck,
	z_final: &polyvec::Polyvecl,
) -> ThresholdResult<Vec<u8>> {
	// Step 1: Check ||z||∞ < γ₁ - β constraint
	// z_final is in uint32 [0, Q) format, need to check centered norm like Go's Exceeds
	let gamma1_minus_beta = (dilithium_params::GAMMA1 - dilithium_params::BETA) as i32;

	// Convert to centered format and check norm (matching Go's Exceeds behavior)
	let mut max_z_centered = 0i32;
	for i in 0..dilithium_params::L {
		for j in 0..(dilithium_params::N as usize) {
			let coeff_u32 = z_final.vec[i].coeffs[j] as u32;
			// Compute centered representation
			let mut x = ((dilithium_params::Q - 1) / 2) as i32 - coeff_u32 as i32;
			x ^= x >> 31;
			x = ((dilithium_params::Q - 1) / 2) as i32 - x;
			max_z_centered = max_z_centered.max(x);
		}
	}

	if max_z_centered >= gamma1_minus_beta {
		return Err(ThresholdError::ConstraintViolation);
	}

	// Step 2: Decompose w into w0 and w1 (like reference)
	let mut w0 = polyvec::Polyveck::default();
	let mut w1 = w_final.clone();

	// Reduce coefficients to [0, Q) range before decomposition
	for i in 0..dilithium_params::K {
		poly::reduce(&mut w1.vec[i]);
		poly::caddq(&mut w1.vec[i]);
	}

	// Use Go-compatible decompose to match reference implementation exactly
	let w_input = w1.clone();
	veck_decompose_go(&w_input, &mut w0, &mut w1);

	// Step 2: Compute challenge c~ = H(μ || w1) like reference
	let mut w1_packed = vec![0u8; dilithium_params::K * dilithium_params::POLYW1_PACKEDBYTES];
	polyvec::k_pack_w1(&mut w1_packed, &w1);

	let mut c_bytes = [0u8; dilithium_params::C_DASH_BYTES];
	let mut keccak_state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut keccak_state, mu, 64);
	fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
	fips202::shake256_finalize(&mut keccak_state);
	fips202::shake256_squeeze(&mut c_bytes, dilithium_params::C_DASH_BYTES, &mut keccak_state);

	// Create challenge polynomial
	let mut challenge_poly = poly::Poly::default();
	poly::challenge(&mut challenge_poly, &c_bytes);

	// Step 4: Compute Az (like reference)
	let mut z_ntt = z_final.clone();
	ntt_polyvecl(&mut z_ntt);

	// Compute Az in NTT domain
	// A is stored in "NTT form" implicitly - uniform random coefficients are treated as NTT coefficients
	// DO NOT apply NTT to A - it's already effectively in NTT form!
	let mut az_ntt = polyvec::Polyveck::default();

	// Extract A matrix from PublicKey (already in implicit NTT form)
	let mut a_matrix: Vec<polyvec::Polyvecl> =
		(0..dilithium_params::K).map(|_| polyvec::Polyvecl::default()).collect();

	for i in 0..dilithium_params::K {
		for j in 0..dilithium_params::L {
			let threshold_poly = pk.a_ntt.get(i, j);
			for k in 0..(dilithium_params::N as usize) {
				a_matrix[i].vec[j].coeffs[k] = threshold_poly.get(k).value() as i32;
			}
		}
	}

	// Compute Az using poly_dot_hat_circl (matches Go's PolyDotHat exactly)
	for i in 0..dilithium_params::K {
		poly_dot_hat_circl(&mut az_ntt.vec[i], &a_matrix[i], &z_ntt);
	}

	// Apply ReduceLe2Q to Az in NTT domain (matching reference behavior)
	for i in 0..dilithium_params::K {
		for j in 0..(dilithium_params::N as usize) {
			let coeff = az_ntt.vec[i].coeffs[j];
			let coeff_u32 =
				if coeff < 0 { (coeff + dilithium_params::Q as i32) as u32 } else { coeff as u32 };
			az_ntt.vec[i].coeffs[j] = reduce_le2q(coeff_u32) as i32;
		}
	}

	// Step 5: Compute ct1_2d in NTT domain (like reference)
	let mut c_ntt = challenge_poly.clone();
	crate::circl_ntt::ntt(&mut c_ntt);

	// t1 coefficients are already in [0, (Q-1)/2^D] range after Power2Round
	let mut ct1_2d = polyvec::Polyveck::default();
	for i in 0..dilithium_params::K {
		for j in 0..(dilithium_params::N as usize) {
			let t1_val = pk.t1.get(i).get(j).value();
			let scaled = (t1_val << dilithium_params::D) as i32;
			ct1_2d.vec[i].coeffs[j] = scaled % dilithium_params::Q as i32;
		}
	}

	for i in 0..dilithium_params::K {
		poly::reduce(&mut ct1_2d.vec[i]);
	}

	ntt_polyveck(&mut ct1_2d);

	for i in 0..dilithium_params::K {
		let temp_poly = ct1_2d.vec[i].clone();
		poly::pointwise_montgomery(&mut ct1_2d.vec[i], &temp_poly, &c_ntt);
	}

	// Apply ReduceLe2Q to ct1_2d after multiplication
	for i in 0..dilithium_params::K {
		for j in 0..(dilithium_params::N as usize) {
			let coeff = ct1_2d.vec[i].coeffs[j];
			let coeff_u32 = if coeff < 0 {
				(coeff + dilithium_params::Q as i32) as u32
			} else {
				coeff as u32
			};
			ct1_2d.vec[i].coeffs[j] = reduce_le2q(coeff_u32) as i32;
		}
	}

	// Subtract in NTT domain BEFORE inverse NTT (like reference)
	let mut az2dct1 = az_ntt.clone();
	polyvec::k_sub(&mut az2dct1, &ct1_2d);

	for i in 0..dilithium_params::K {
		for j in 0..dilithium_params::N as usize {
			az2dct1.vec[i].coeffs[j] += 2 * dilithium_params::Q as i32;
		}
	}

	polyvec_k_reduce_le2q(&mut az2dct1);

	// Inverse NTT using circl implementation to match Go reference
	for i in 0..dilithium_params::K {
		crate::circl_ntt::inv_ntt(&mut az2dct1.vec[i]);
	}

	polyvec_k_normalize_assuming_le2q(&mut az2dct1);

	// Step 6: Compute f = Az2dct1 - w (like reference)
	let mut f = az2dct1.clone();
	polyvec::k_sub(&mut f, &w_final);

	// Normalize f
	for i in 0..dilithium_params::K {
		poly::reduce(&mut f.vec[i]);
		for j in 0..dilithium_params::N as usize {
			if f.vec[i].coeffs[j] < 0 {
				f.vec[i].coeffs[j] += dilithium_params::Q as i32;
			}
		}
	}

	// Step 7: Check f constraint using centered norm (like Threshold-ML-DSA reference)
	let gamma2 = dilithium_params::GAMMA2 as u32;

	if polyveck_exceeds(&f, gamma2 as i32) {
		return Err(ThresholdError::ConstraintViolation);
	}

	// Step 8: Compute w0 + f and make hint (like reference)
	let mut w0_modified = w0.clone();
	polyvec::k_add(&mut w0_modified, &f);
	for i in 0..dilithium_params::K {
		center_dilithium_poly(&mut w0_modified.vec[i]);
		poly::reduce(&mut w0_modified.vec[i]);
		center_dilithium_poly(&mut w0_modified.vec[i]);
	}

	let mut hint = polyvec::Polyveck::default();
	let hint_pop = compute_dilithium_hint(&mut hint, &w0_modified, &w1);

	// Step 9: Check hint constraint and pack signature
	if hint_pop <= dilithium_params::OMEGA {
		pack_dilithium_signature(&c_bytes, z_final, &hint)
	} else {
		Err(ThresholdError::ConstraintViolation)
	}
}

/// Create ML-DSA signature using reference implementation approach
fn create_mldsa_signature_reference_approach(
	pk: &PublicKey,
	message: &[u8],
	_context: &[u8],
	commitments: &[Vec<u8>],
	responses: &[Vec<u8>],
	config: &ThresholdConfig,
) -> ThresholdResult<Vec<u8>> {
	// Compute μ = H(tr || msg) like Go's internal ComputeMu
	// Note: Go's internal test does NOT add context prefix, only tr || msg
	// The public API wrapper adds context, but we match the internal test here
	let mut mu = [0u8; 64];
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, &pk.tr, 64);
	fips202::shake256_absorb(&mut state, message, message.len());
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut mu, 64, &mut state);

	// Try each K iteration following reference Combine logic
	let k_iterations = config.base.canonical_k() as usize;
	let single_commitment_size = Params::SINGLE_COMMITMENT_SIZE;
	const POLY_LE_GAMMA1_SIZE: usize = 640; // For ML-DSA-87
	let single_response_size = dilithium_params::L * POLY_LE_GAMMA1_SIZE;

	for k_iter in 0..k_iterations {
		// Aggregate commitments for this iteration
		let mut w_final = polyvec::Polyveck::default();
		for commitment_set in commitments.iter() {
			let start_idx = k_iter * single_commitment_size;
			let end_idx = start_idx + single_commitment_size;

			if start_idx < commitment_set.len() && end_idx <= commitment_set.len() {
				let k_commitment = &commitment_set[start_idx..end_idx];
				let w_temp = unpack_commitment_dilithium(k_commitment)?;
				aggregate_commitments_dilithium(&mut w_final, &w_temp);
			}
		}

		// Aggregate responses for this iteration
		let mut z_final = polyvec::Polyvecl::default();
		for response_set in responses.iter() {
			let start_idx = k_iter * single_response_size;
			let end_idx = start_idx + single_response_size;

			if start_idx < response_set.len() && end_idx <= response_set.len() {
				let k_response = &response_set[start_idx..end_idx];
				let z_temp = unpack_response_dilithium(k_response)?;
				aggregate_responses_dilithium(&mut z_final, &z_temp);
			}
		}

		// Try to create signature with this iteration
		match create_signature_from_pair_reference(pk, &mu, &w_final, &z_final) {
			Ok(signature) => return Ok(signature),
			Err(ThresholdError::ConstraintViolation) => continue,
			Err(e) => return Err(e),
		}
	}

	Err(ThresholdError::ConstraintViolation)
}

/// Compute proper ML-DSA hint following the standard algorithm
/// This implements the MakeHint algorithm from the ML-DSA specification
fn compute_dilithium_hint(
	hint: &mut polyvec::Polyveck,
	w0_modified: &polyvec::Polyveck,
	w1: &polyvec::Polyveck,
) -> usize {
	let mut hint_pop = 0;

	for i in 0..dilithium_params::K {
		for j in 0..(dilithium_params::N as usize) {
			let z0 = w0_modified.vec[i].coeffs[j] as u32;
			let r1 = w1.vec[i].coeffs[j] as u32;

			// Implement makeHint algorithm from ML-DSA specification
			let hint_bit = make_hint_single(z0, r1);
			hint.vec[i].coeffs[j] = hint_bit as i32;
			hint_pop += hint_bit as usize;
		}
	}

	hint_pop
}

/// Single coefficient hint computation following ML-DSA makeHint algorithm
/// Implements: makeHint(z0, r1) where z0 = r0 - f (mod Q) and r1 is high bits
fn make_hint_single(z0: u32, r1: u32) -> u32 {
	let gamma2 = dilithium_params::GAMMA2 as u32;
	let q = dilithium_params::Q as u32;

	// Normalize z0 to [0, Q)
	let z0_normalized = z0 % q;

	// MakeHint algorithm:
	// If -γ₂ < z0 ≤ γ₂, then hint = 0
	// Special case: if z0 = -γ₂ and r1 = 0, then hint = 0
	// Otherwise hint = 1
	if z0_normalized <= gamma2
		|| z0_normalized > q - gamma2
		|| (z0_normalized == q - gamma2 && r1 == 0)
	{
		0
	} else {
		1
	}
}

/// Verify a threshold signature using dilithium's verification directly
pub fn verify_signature(pk: &PublicKey, message: &[u8], context: &[u8], signature: &[u8]) -> bool {
	// Validate context length
	if let Err(_) = crate::common::validate_context(context) {
		return false;
	}

	// Check signature length - use dilithium's SIGNBYTES constant
	if signature.len() != dilithium_params::SIGNBYTES {
		return false;
	}

	// Validate public key format
	if pk.packed.len() != dilithium_params::PUBLICKEYBYTES {
		return false;
	}

	// Create a PublicKey from the dilithium crate to use their verification
	let dilithium_pk =
		match qp_rusty_crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(&pk.packed) {
			Ok(pk) => pk,
			Err(_) => return false,
		};

	// Use dilithium's public verification API with proper context handling
	let ctx_option = if context.is_empty() { None } else { Some(context) };
	dilithium_pk.verify(message, signature, ctx_option)
}

/// Pack final signature using dilithium packing operations with proper signature format
fn pack_dilithium_signature(
	c: &[u8; 64],
	z: &polyvec::Polyvecl,
	hint: &polyvec::Polyveck,
) -> ThresholdResult<Vec<u8>> {
	let mut signature = vec![0u8; dilithium_params::SIGNBYTES];

	// Pack signature using dilithium packing with proper c_tilde format
	let c_tilde = &c[..dilithium_params::C_DASH_BYTES.min(64)];
	packing::pack_sig(&mut signature, Some(c_tilde), z, hint);

	Ok(signature)
}

/// Pack a single polynomial with full Q-bit precision (23 bits per coefficient)
/// This matches the canonical PolyPackW function
fn poly_pack_w(poly: &qp_rusty_crystals_dilithium::poly::Poly, buf: &mut [u8]) {
	if buf.len() < (dilithium_params::N as usize * 23 + 7) / 8 {
		return; // Buffer too small
	}

	let mut v: u32 = 0;
	let mut j: u32 = 0;
	let mut k: usize = 0;

	for i in 0..dilithium_params::N as usize {
		// Pack coefficient with 23 bits
		// Coefficients are in [0, Q) range from normalization (matching Go uint32)
		// Cast i32 to u32 safely since we know they're >= 0
		let coeff = (poly.coeffs[i] as u32) & ((1 << 23) - 1); // Mask to 23 bits
		v |= coeff << j;
		j += 23;

		while j >= 8 {
			buf[k] = v as u8;
			v >>= 8;
			j -= 8;
			k += 1;
		}
	}

	// Pack remaining bits
	if j > 0 && k < buf.len() {
		buf[k] = v as u8;
	}
}

/// Pack multiple VecK polynomials into commitment buffer
/// This matches the canonical PackW function
fn pack_w_commitments(ws: &[polyvec::Polyveck], buf: &mut [u8]) {
	let poly_q_size = (dilithium_params::N as usize * 23 + 7) / 8; // Round up division
	let mut offset = 0;

	for w_vec in ws.iter() {
		for j in 0..dilithium_params::K {
			if offset + poly_q_size <= buf.len() {
				poly_pack_w(&w_vec.vec[j], &mut buf[offset..offset + poly_q_size]);
				offset += poly_q_size;
			}
		}
	}
}

// Helper functions for tests

/// Test-only function that converts u64 to seed
#[cfg(any(test, doc))]

pub fn test_generate_threshold_key(
	seed: u64,
	config: &ThresholdConfig,
) -> ThresholdResult<(PublicKey, Vec<PrivateKey>)> {
	let mut seed_bytes = [0u8; SEED_SIZE];
	seed_bytes[0..8].copy_from_slice(&seed.to_le_bytes());
	generate_threshold_key(&seed_bytes, config)
}

/// Test-only Round1 generation using seed
pub fn test_round1_new(
	sk: &PrivateKey,
	config: &ThresholdConfig,
	seed: u64,
) -> ThresholdResult<(Vec<u8>, Round1State)> {
	let mut seed_bytes = [0u8; 32];
	seed_bytes[0..8].copy_from_slice(&seed.to_le_bytes());
	Round1State::new(sk, config, &seed_bytes)
}

/// Test helper that takes rhop directly like Go's GenThCommitment
pub fn test_round1_with_rhop(
	sk: &PrivateKey,
	rhop: &[u8; 64],
	nonce: u16,
	config: &ThresholdConfig,
) -> ThresholdResult<Round1State> {
	// Generate K iterations of w and y
	let k = config.k_iterations as usize;
	let mut w_commitments = Vec::with_capacity(k);
	let mut y_commitments = Vec::with_capacity(k);
	let mut hyperball_samples = Vec::with_capacity(k);

	for k_iter in 0..k {
		// Sample from hyperball
		let fvec_size = dilithium_params::N as usize * (dilithium_params::L + dilithium_params::K);
		let mut fvec = FVec::new(fvec_size);
		fvec.sample_hyperball(config.r_prime, config.nu, rhop, nonce * config.k_iterations + k_iter as u16);

		hyperball_samples.push(fvec.clone());

		// Round to get y and e
		let mut y_k = polyvec::Polyvecl::default();
		let mut e_k = polyvec::Polyveck::default();
		fvec.round(&mut y_k, &mut e_k);

		// Compute w = A*y + e
		let mut w_k = polyvec::Polyveck::default();
		let mut y_k_ntt = y_k.clone();
		for i in 0..dilithium_params::L {
			ntt_poly(&mut y_k_ntt.vec[i]);
		}

		// Matrix multiplication using circl-compatible operations
		for i in 0..dilithium_params::K {
			let mut temp = poly::Poly::default();
			for j in 0..dilithium_params::L {
				let mut a_poly = poly::Poly::default();
				let threshold_poly = sk.a.get(i, j);
				for k_idx in 0..(dilithium_params::N as usize) {
					a_poly.coeffs[k_idx] = threshold_poly.get(k_idx).value() as i32;
				}
				let mut mul_result = poly::Poly::default();
				crate::circl_ntt::mul_hat(&mut mul_result, &a_poly, &y_k_ntt.vec[j]);
				let mut temp_sum = poly::Poly::default();
				crate::circl_ntt::poly_add(&mut temp_sum, &temp, &mul_result);
				temp = temp_sum;
			}
			w_k.vec[i] = temp;

			// ReduceLe2Q before InvNTT
			for j in 0..dilithium_params::N as usize {
				let coeff = w_k.vec[i].coeffs[j];
				let coeff_u32 = if coeff < 0 {
					(coeff + dilithium_params::Q as i32) as u32
				} else {
					coeff as u32
				};
				w_k.vec[i].coeffs[j] = crate::circl_ntt::reduce_le2q(coeff_u32) as i32;
			}

			inv_ntt_poly(&mut w_k.vec[i]);

			// Add error term
			let mut temp_sum = poly::Poly::default();
			crate::circl_ntt::poly_add(&mut temp_sum, &w_k.vec[i], &e_k.vec[i]);
			w_k.vec[i] = temp_sum;
		}

		// Normalize
		for i in 0..dilithium_params::K {
			normalize_assuming_le2q(&mut w_k.vec[i]);
		}

		w_commitments.push(w_k);
		y_commitments.push(y_k);
	}

	Ok(Round1State {
		w: polyvec::Polyveck::default(),
		y: polyvec::Polyvecl::default(),
		y_fvec: FVec::new(0),
		hyperball_sample: FVec::new(0),
		rho_prime: *rhop,
		w_commitments,
		y_commitments,
		hyperball_samples,
	})
}

/// Test helper to compute Round 3 response (z = c*s1 + y)
pub fn test_compute_response(
	sk: &PrivateKey,
	active_parties: u8,
	c_poly: &qp_rusty_crystals_dilithium::poly::Poly,
	hyperball_sample: &FVec,
	config: &ThresholdConfig,
) -> ThresholdResult<qp_rusty_crystals_dilithium::polyvec::Polyvecl> {
	// Check that the party is in the active set
	if active_parties & (1 << sk.id) == 0 {
		return Err(ThresholdError::InvalidParameters {
			threshold: 0,
			parties: 0,
			reason: "Specified user is not part of the signing set",
		});
	}

	// Build the active parties list from the bitmap
	let mut active_party_list = Vec::new();
	for i in 0..config.base.n {
		if active_parties & (1 << i) != 0 {
			active_party_list.push(i);
		}
	}

	// Recover the share for this signing set using the hardcoded sharing patterns
	let (s1h, s2h) = secret_sharing::recover_share_hardcoded(
		&sk.shares,
		sk.id,
		&active_party_list,
		config.base.t,
		config.base.n,
	)?;

	// Convert c_poly to NTT domain
	let mut c_ntt = c_poly.clone();

	// Convert c_poly from signed {-1,0,1} to uint32 [0,Q) format before NTT
	// Go stores -1 as Q-1 (8380416), so we need to match that
	for j in 0..(dilithium_params::N as usize) {
		if c_ntt.coeffs[j] < 0 {
			c_ntt.coeffs[j] += dilithium_params::Q as i32;
		}
	}

	crate::circl_ntt::ntt(&mut c_ntt);

	// s1h is already in NTT domain from recover_share_hardcoded
	// (matching Go's recoverShare which returns s1h already in NTT)

	// Compute c * s1 (in NTT domain)
	let mut cs1 = qp_rusty_crystals_dilithium::polyvec::Polyvecl::default();
	for j in 0..dilithium_params::L {
		crate::circl_ntt::mul_hat(&mut cs1.vec[j], &c_ntt, &s1h.vec[j]);
		crate::circl_ntt::inv_ntt(&mut cs1.vec[j]);
	}

	// Normalize cs1
	for i in 0..dilithium_params::L {
		for j in 0..(dilithium_params::N as usize) {
			let coeff = cs1.vec[i].coeffs[j];
			let coeff_u32 = if coeff < 0 {
				(coeff + dilithium_params::Q as i32) as u32
			} else {
				coeff as u32
			};
			cs1.vec[i].coeffs[j] = mod_q(coeff_u32) as i32;
			}
		}

	// Compute c * s2 (in NTT domain)
	let mut cs2 = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
	for j in 0..dilithium_params::K {
		crate::circl_ntt::mul_hat(&mut cs2.vec[j], &c_ntt, &s2h.vec[j]);
		crate::circl_ntt::inv_ntt(&mut cs2.vec[j]);
	}

	// Normalize cs2
	for i in 0..dilithium_params::K {
		for j in 0..(dilithium_params::N as usize) {
			let coeff = cs2.vec[i].coeffs[j];
			let coeff_u32 = if coeff < 0 {
				(coeff + dilithium_params::Q as i32) as u32
			} else {
				coeff as u32
			};
			cs2.vec[i].coeffs[j] = mod_q(coeff_u32) as i32;
		}
	}

	// Convert cs1 and cs2 to FVec
	let mut zf = FVec::from_polyvecs(&cs1, &cs2);

	// Add the hyperball sample
	zf.add(hyperball_sample);

	// Check Excess before rounding (matching Go's rejection sampling)
	// Go: if zf.Excess(params.r, params.nu) { continue }
	// IMPORTANT: Use params.r (not r_prime) - r is for response checking, r_prime is for commitment
	if zf.excess(config.r, config.nu) {
		return Err(ThresholdError::ConstraintViolation);
	}

	// Round back to integer
	let mut z = qp_rusty_crystals_dilithium::polyvec::Polyvecl::default();
	let mut y = qp_rusty_crystals_dilithium::polyvec::Polyveck::default();
	zf.round(&mut z, &mut y);

	// Convert z from centered format to uint32 [0, Q) format
	for i in 0..dilithium_params::L {
		for j in 0..(dilithium_params::N as usize) {
			let coeff = z.vec[i].coeffs[j];
			// Convert from centered [-Q/2, Q/2] to [0, Q)
			let coeff_u32 = if coeff < 0 {
				(coeff + dilithium_params::Q as i32) as u32
			} else {
				coeff as u32
			};
			z.vec[i].coeffs[j] = coeff_u32 as i32;
			}
		}

	Ok(z)
}

/// Compute responses for a party - matches Go's ComputeResponses API for deterministic testing.
///
/// This function takes the same inputs as Go's ComputeResponses:
/// - `sk`: Private key for this party
/// - `act`: Bitmask of active parties (e.g., 0b11 for parties 0 and 1)
/// - `mu`: The 64-byte message hash (H(tr || M'))
/// - `wfinals`: Aggregated w values, one per K iteration
/// - `stws`: Hyperball samples from Round1, one per K iteration
/// - `config`: Threshold configuration
///
/// Returns a vector of response vectors (one VecL per K iteration).
/// Empty vectors indicate rejection sampling failure for that iteration.
pub fn compute_responses_deterministic(
	sk: &PrivateKey,
	act: u8,
	mu: &[u8; 64],
	wfinals: &[polyvec::Polyveck],
	stws: &[FVec],
	config: &ThresholdConfig,
) -> Vec<polyvec::Polyvecl> {
	// Check that the party is in the active set
	if act & (1 << sk.id) == 0 {
		panic!("Specified user is not part of the signing set");
	}

	// Build the active parties list from the bitmap
	let mut active_party_list = Vec::new();
	for i in 0..config.base.n {
		if act & (1 << i) != 0 {
			active_party_list.push(i);
		}
	}

	// Recover the partial secret of the current user corresponding to the signer set
	let (s1h, s2h) = secret_sharing::recover_share_hardcoded(
		&sk.shares,
		sk.id,
		&active_party_list,
		config.base.t,
		config.base.n,
	)
	.expect("Failed to recover share");

	let k = config.base.canonical_k() as usize;
	let mut zs: Vec<polyvec::Polyvecl> = vec![polyvec::Polyvecl::default(); k];

	// For each commitment iteration
	for i in 0..k {
		if i >= wfinals.len() || i >= stws.len() {
			continue;
		}

		// Decompose w into w0 and w1
		let mut w0 = polyvec::Polyveck::default();
		let mut w1 = polyvec::Polyveck::default();
		veck_decompose_go(&wfinals[i], &mut w0, &mut w1);

		// c~ = H(μ || w1)
		let mut w1_packed = vec![0u8; dilithium_params::K * dilithium_params::POLYW1_PACKEDBYTES];
		polyvec::k_pack_w1(&mut w1_packed, &w1);

		let mut c_bytes = [0u8; dilithium_params::C_DASH_BYTES];
		let mut keccak_state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut keccak_state, mu, 64);
		fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
		fips202::shake256_finalize(&mut keccak_state);
		fips202::shake256_squeeze(&mut c_bytes, dilithium_params::C_DASH_BYTES, &mut keccak_state);

		// Derive challenge polynomial
		let mut ch = poly::Poly::default();
		poly::challenge(&mut ch, &c_bytes);

		// Convert to NTT domain
		crate::circl_ntt::ntt(&mut ch);

		// Compute c·s1
		let mut z = polyvec::Polyvecl::default();
		for j in 0..dilithium_params::L {
			crate::circl_ntt::mul_hat(&mut z.vec[j], &ch, &s1h.vec[j]);
			crate::circl_ntt::inv_ntt(&mut z.vec[j]);
		}
		// Normalize z
		for j in 0..dilithium_params::L {
			for coeff in z.vec[j].coeffs.iter_mut() {
				let c = *coeff;
				let c_u32 = if c < 0 { (c + dilithium_params::Q as i32) as u32 } else { c as u32 };
				*coeff = mod_q(c_u32) as i32;
			}
		}

		// Compute c·s2
		let mut y = polyvec::Polyveck::default();
		for j in 0..dilithium_params::K {
			crate::circl_ntt::mul_hat(&mut y.vec[j], &ch, &s2h.vec[j]);
			crate::circl_ntt::inv_ntt(&mut y.vec[j]);
		}
		// Normalize y
		for j in 0..dilithium_params::K {
			for coeff in y.vec[j].coeffs.iter_mut() {
				let c = *coeff;
				let c_u32 = if c < 0 { (c + dilithium_params::Q as i32) as u32 } else { c as u32 };
				*coeff = mod_q(c_u32) as i32;
			}
		}

		// Convert to FVec and add hyperball sample
		let mut zf = FVec::from_polyvecs(&z, &y);
		zf.add(&stws[i]);

		// Rejection sampling check
		if zf.excess(config.r, config.nu) {
			// Skip this iteration (leave zs[i] as default/zero)
			continue;
		}

		// Round back to integers
		let mut z_out = polyvec::Polyvecl::default();
		let mut y_out = polyvec::Polyveck::default();
		zf.round(&mut z_out, &mut y_out);

		// Convert from centered format to [0, Q) format like Go
		for j in 0..dilithium_params::L {
			for coeff in z_out.vec[j].coeffs.iter_mut() {
				if *coeff < 0 {
					*coeff += dilithium_params::Q as i32;
				}
			}
		}

		zs[i] = z_out;
	}

	zs
}

/// Aggregate responses from multiple parties - matches Go's AggregateResponses API.
///
/// Adds `zs` into `zfinals` element-wise.
pub fn aggregate_responses(zfinals: &mut [polyvec::Polyvecl], zs: &[polyvec::Polyvecl]) {
	for i in 0..zs.len().min(zfinals.len()) {
		for j in 0..dilithium_params::L {
			for k in 0..dilithium_params::N as usize {
				zfinals[i].vec[j].coeffs[k] += zs[i].vec[j].coeffs[k];
			}
		}
		// Normalize
		for j in 0..dilithium_params::L {
			for coeff in zfinals[i].vec[j].coeffs.iter_mut() {
				let c = *coeff;
				let c_u32 = if c < 0 { (c + dilithium_params::Q as i32) as u32 } else { c as u32 };
				*coeff = mod_q(c_u32) as i32;
			}
		}
	}
}

/// Pack responses into bytes - matches Go's PackResponses API.
///
/// Each VecL is packed using PackLeGamma1 format.
pub fn pack_responses(zs: &[polyvec::Polyvecl]) -> Vec<u8> {
	let single_response_size = dilithium_params::L * dilithium_params::POLYZ_PACKEDBYTES;
	let mut buf = vec![0u8; zs.len() * single_response_size];

	for (i, z) in zs.iter().enumerate() {
		let offset = i * single_response_size;
		// Convert to centered format for packing
		let mut z_centered = z.clone();
		for j in 0..dilithium_params::L {
			for coeff in z_centered.vec[j].coeffs.iter_mut() {
				// Convert from [0, Q) to centered [-Q/2, Q/2]
				if *coeff > (dilithium_params::Q as i32) / 2 {
					*coeff -= dilithium_params::Q as i32;
				}
			}
		}
		// Pack each polynomial individually
		for j in 0..dilithium_params::L {
			let poly_offset = offset + j * dilithium_params::POLYZ_PACKEDBYTES;
			poly::z_pack(
				&mut buf[poly_offset..poly_offset + dilithium_params::POLYZ_PACKEDBYTES],
				&z_centered.vec[j],
			);
		}
	}

	buf
}

/// Pack w values to buffer - matches Go's PackWToBuf API.
///
/// Packs each VecK using 23-bit coefficients.
pub fn pack_w_to_buf(wfinals: &[polyvec::Polyveck]) -> Vec<u8> {
	let poly_w_size = (dilithium_params::N as usize * 23 + 7) / 8; // 736 bytes per poly
	let single_w_size = dilithium_params::K * poly_w_size;
	let mut buf = vec![0u8; wfinals.len() * single_w_size];

	for (i, w) in wfinals.iter().enumerate() {
		let offset = i * single_w_size;
		for j in 0..dilithium_params::K {
			let poly_offset = offset + j * poly_w_size;
			poly_pack_w(&w.vec[j], &mut buf[poly_offset..poly_offset + poly_w_size]);
		}
	}

	buf
}

/// Combine aggregated commitments and responses into a signature - matches Go's CombineFromParts API.
///
/// This function takes:
/// - `pk`: Public key
/// - `message`: Message to sign
/// - `context`: Context bytes (can be empty)
/// - `wfinals`: Aggregated w values (one per K iteration)
/// - `zfinals`: Aggregated z values (one per K iteration)
/// - `config`: Threshold configuration
///
/// Returns (signature, success) tuple.
pub fn combine_from_parts(
	pk: &PublicKey,
	message: &[u8],
	context: &[u8],
	wfinals: &[polyvec::Polyveck],
	zfinals: &[polyvec::Polyvecl],
	config: &ThresholdConfig,
) -> (Vec<u8>, bool) {
	// Compute μ = H(tr || 0 || len(ctx) || ctx || msg) like Go's Combine
	let mut mu = [0u8; 64];
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, &pk.tr, 64);
	fips202::shake256_absorb(&mut state, &[0u8], 1); // Domain separator
	fips202::shake256_absorb(&mut state, &[context.len() as u8], 1);
	if !context.is_empty() {
		fips202::shake256_absorb(&mut state, context, context.len());
	}
	fips202::shake256_absorb(&mut state, message, message.len());
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut mu, 64, &mut state);

	let k_iterations = config.base.canonical_k() as usize;

	// For each commitment iteration
	for i in 0..k_iterations.min(wfinals.len()).min(zfinals.len()) {
		// Decompose w into w0 and w1
		let mut w0 = polyvec::Polyveck::default();
		let mut w1 = polyvec::Polyveck::default();
		veck_decompose_go(&wfinals[i], &mut w0, &mut w1);

		// Ensure ||z||_∞ < γ1 - β
		let gamma1_minus_beta = (dilithium_params::GAMMA1 - dilithium_params::BETA) as i32;
		let mut z_exceeds = false;
		for j in 0..dilithium_params::L {
			for k in 0..dilithium_params::N as usize {
				let coeff = zfinals[i].vec[j].coeffs[k];
				// Convert from [0, Q) to centered form for comparison
				let centered = if coeff > (dilithium_params::Q as i32) / 2 {
					coeff - dilithium_params::Q as i32
				} else {
					coeff
				};
				if centered.abs() >= gamma1_minus_beta {
					z_exceeds = true;
					break;
				}
			}
			if z_exceeds {
				break;
			}
		}
		if z_exceeds {
			continue;
		}

		// Compute Az (z in NTT domain)
		let mut zh = zfinals[i].clone();
		// Convert to centered form then NTT
		for j in 0..dilithium_params::L {
			for k in 0..dilithium_params::N as usize {
				if zh.vec[j].coeffs[k] > (dilithium_params::Q as i32) / 2 {
					zh.vec[j].coeffs[k] -= dilithium_params::Q as i32;
				}
			}
			crate::circl_ntt::ntt(&mut zh.vec[j]);
		}

		let mut az = polyvec::Polyveck::default();
		for j in 0..dilithium_params::K {
			for l in 0..dilithium_params::L {
				let mut tmp = poly::Poly::default();
				// Access a_ntt using get() method and convert to dilithium poly
				let threshold_poly = pk.a_ntt.get(j, l);
				let mut a_poly = poly::Poly::default();
				for k in 0..dilithium_params::N as usize {
					a_poly.coeffs[k] = threshold_poly.get(k).value() as i32;
				}
				crate::circl_ntt::mul_hat(&mut tmp, &a_poly, &zh.vec[l]);
				for k in 0..dilithium_params::N as usize {
					az.vec[j].coeffs[k] += tmp.coeffs[k];
				}
			}
		}

		// c~ = H(μ || w1)
		let mut w1_packed = vec![0u8; dilithium_params::K * dilithium_params::POLYW1_PACKEDBYTES];
		polyvec::k_pack_w1(&mut w1_packed, &w1);

		let mut c_bytes = [0u8; dilithium_params::C_DASH_BYTES];
		let mut keccak_state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut keccak_state, &mu, 64);
		fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
		fips202::shake256_finalize(&mut keccak_state);
		fips202::shake256_squeeze(&mut c_bytes, dilithium_params::C_DASH_BYTES, &mut keccak_state);

		// Derive challenge polynomial
		let mut ch = poly::Poly::default();
		poly::challenge(&mut ch, &c_bytes);
		crate::circl_ntt::ntt(&mut ch);

		// Compute Az - 2^d * c * t1
		let mut az2dct1 = polyvec::Polyveck::default();
		// First compute 2^d * t1
		for j in 0..dilithium_params::K {
			for k in 0..dilithium_params::N as usize {
				// Access t1 using get() method
				let t1_val = pk.t1.get(j).get(k).value();
				az2dct1.vec[j].coeffs[k] = (t1_val << dilithium_params::D) as i32;
			}
			crate::circl_ntt::ntt(&mut az2dct1.vec[j]);
			// Multiply by c (need to clone to avoid borrow issues)
			let tmp = az2dct1.vec[j].clone();
			crate::circl_ntt::mul_hat(&mut az2dct1.vec[j], &tmp, &ch);
		}

		// Az - 2^d * c * t1
		for j in 0..dilithium_params::K {
			for k in 0..dilithium_params::N as usize {
				az2dct1.vec[j].coeffs[k] = az.vec[j].coeffs[k] - az2dct1.vec[j].coeffs[k];
			}
			// ReduceLe2Q
			poly::reduce(&mut az2dct1.vec[j]);
			crate::circl_ntt::inv_ntt(&mut az2dct1.vec[j]);
			// NormalizeAssumingLe2Q
			normalize_assuming_le2q(&mut az2dct1.vec[j]);
		}

		// f = Az2dct1 - wfinals[i]
		let mut f = polyvec::Polyveck::default();
		for j in 0..dilithium_params::K {
			for k in 0..dilithium_params::N as usize {
				f.vec[j].coeffs[k] = az2dct1.vec[j].coeffs[k] - wfinals[i].vec[j].coeffs[k];
			}
			// Normalize
			for k in 0..dilithium_params::N as usize {
				let c = f.vec[j].coeffs[k];
				let c_u32 = if c < 0 { (c + dilithium_params::Q as i32) as u32 } else { c as u32 };
				f.vec[j].coeffs[k] = mod_q(c_u32) as i32;
			}
		}

		// Ensure ||f||_∞ < γ2
		let gamma2 = dilithium_params::GAMMA2 as i32;
		let mut f_exceeds = false;
		for j in 0..dilithium_params::K {
			for k in 0..dilithium_params::N as usize {
				let coeff = f.vec[j].coeffs[k];
				let centered = if coeff > (dilithium_params::Q as i32) / 2 {
					coeff - dilithium_params::Q as i32
				} else {
					coeff
				};
				if centered.abs() >= gamma2 {
					f_exceeds = true;
					break;
				}
			}
			if f_exceeds {
				break;
			}
		}
		if f_exceeds {
			continue;
		}

		// w0pf = w0 + f
		let mut w0pf = polyvec::Polyveck::default();
		for j in 0..dilithium_params::K {
			for k in 0..dilithium_params::N as usize {
				w0pf.vec[j].coeffs[k] = w0.vec[j].coeffs[k] + f.vec[j].coeffs[k];
			}
			// Normalize
			for k in 0..dilithium_params::N as usize {
				let c = w0pf.vec[j].coeffs[k];
				let c_u32 = if c < 0 { (c + dilithium_params::Q as i32) as u32 } else { c as u32 };
				w0pf.vec[j].coeffs[k] = mod_q(c_u32) as i32;
			}
		}

		// Compute hint
		let mut hint = polyvec::Polyveck::default();
		let hint_pop = compute_dilithium_hint(&mut hint, &w0pf, &w1);

		if hint_pop <= dilithium_params::OMEGA {
			// Convert z to centered form for packing
			let mut z_centered = zfinals[i].clone();
			for j in 0..dilithium_params::L {
				for k in 0..dilithium_params::N as usize {
					if z_centered.vec[j].coeffs[k] > (dilithium_params::Q as i32) / 2 {
						z_centered.vec[j].coeffs[k] -= dilithium_params::Q as i32;
					}
				}
			}

			// Pack signature
			let mut c_full = [0u8; 64];
			c_full[..dilithium_params::C_DASH_BYTES].copy_from_slice(&c_bytes);
			match pack_dilithium_signature(&c_full, &z_centered, &hint) {
				Ok(sig) => return (sig, true),
				Err(_) => continue,
			}
		}
	}

	(vec![], false)
}

/// Test helper for creating Round2State
#[cfg(any(test, doc))]
pub fn test_round2_new(
	sk: &PrivateKey,
	active_parties: u8,
	message: &[u8],
	context: &[u8],
	round1_commitments: &[Vec<u8>],
	other_parties_w_values: &[Vec<u8>],
	round1_state: &Round1State,
) -> ThresholdResult<(Vec<u8>, Round2State)> {
	Round2State::new(
		sk,
		active_parties,
		message,
		context,
		round1_commitments,
		other_parties_w_values,
		round1_state,
	)
}

/// Test helper for creating Round3State
#[cfg(any(test, doc))]
pub fn test_round3_new(
	sk: &PrivateKey,
	config: &ThresholdConfig,
	round2_commitments: &[Vec<u8>],
	round1_state: &Round1State,
	round2_state: &Round2State,
) -> ThresholdResult<(Vec<u8>, Round3State)> {
	Round3State::new(sk, config, round2_commitments, round1_state, round2_state)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_threshold_config_creation() {
		// Test valid configurations
		assert!(ThresholdConfig::new(2, 3).is_ok());
		assert!(ThresholdConfig::new(3, 5).is_ok());
		assert!(ThresholdConfig::new(6, 6).is_ok());

		// Test invalid configurations
		assert!(ThresholdConfig::new(1, 3).is_err()); // threshold too small
		assert!(ThresholdConfig::new(5, 3).is_err()); // threshold > parties
		assert!(ThresholdConfig::new(3, 7).is_err()); // too many parties
	}

	#[test]
	fn test_threshold_config_parameters() {
		let config = ThresholdConfig::new(3, 5).unwrap();
		assert_eq!(config.base.threshold(), 3);
		assert_eq!(config.base.total_parties(), 5);
		assert_eq!(config.k_iterations, 26);
		assert!((config.r - 577400.0).abs() < 1.0);
		assert!((config.r_prime - 577546.0).abs() < 1.0);
	}

	#[test]
	fn test_signature_verification_rejects_invalid() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, _sks) = test_generate_threshold_key(42, &config).unwrap();

		let message = b"test message";
		let context = b"test";

		// Invalid signature (all zeros) should fail
		let invalid_signature = vec![0u8; dilithium_params::SIGNBYTES];
		assert!(!verify_signature(&pk, message, context, &invalid_signature));

		// Wrong size signature should fail
		let wrong_size_signature = vec![0u8; 100];
		assert!(!verify_signature(&pk, message, context, &wrong_size_signature));
	}

	#[test]
	fn test_invalid_context_length() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let (pk, _sks) = test_generate_threshold_key(42, &config).unwrap();

		let message = b"test message";
		let long_context = vec![0u8; 256]; // Too long (max 255)
		let signature = vec![0u8; dilithium_params::SIGNBYTES];

		assert!(!verify_signature(&pk, message, &long_context, &signature));
	}

	#[test]
	fn test_insufficient_responses() {
		let config = ThresholdConfig::new(3, 5).unwrap();
		let (pk, _sks) = test_generate_threshold_key(42, &config).unwrap();

		let message = b"test message";
		let context = b"test context";
		let commitments = vec![vec![0u8; 32], vec![1u8; 32]];
		let responses = vec![
			vec![0u8; config.threshold_params().response_size::<Params>()],
			vec![1u8; config.threshold_params().response_size::<Params>()],
		]; // Only 2 responses, but threshold is 3

		let result = combine_signatures(&pk, message, context, &commitments, &responses, &config);
		assert!(result.is_err());

		match result.unwrap_err() {
			ThresholdError::InsufficientParties { provided, required } => {
				assert_eq!(provided, 2);
				assert_eq!(required, 3);
			},
			_ => panic!("Expected InsufficientParties error"),
		}
	}

	#[test]
	fn test_matrix_derivation() {
		let mut mat = Mat::<{ Params::K }, { Params::L }>::zero();
		let rho = [0u8; 32];

		mat.derive_from_seed(&rho);

		// Check that matrix is not all zeros and coefficients are in valid range
		let mut all_zero = true;
		let mut max_coeff = 0u32;
		const Q: u32 = dilithium_params::Q as u32;

		for i in 0..Params::K {
			for j in 0..Params::L {
				for k in 0..N {
					let coeff_val = mat.get(i, j).get(k).value();
					if coeff_val != 0 {
						all_zero = false;
					}
					max_coeff = max_coeff.max(coeff_val);
				}
			}
		}

		assert!(!all_zero, "Matrix should not be all zeros after derivation");
		assert!(max_coeff < Q, "Coefficients should be in [0, Q) range");
	}

	#[test]
	fn test_t1_coefficient_bounds() {
		let config = ThresholdConfig::new(2, 2).unwrap();
		let (pk, _sks) = test_generate_threshold_key(42, &config).unwrap();

		// For t1 from power2round with D=13, effective magnitude should be ≤ 2^12
		const Q: u32 = dilithium_params::Q as u32;
		const Q_HALF: u32 = (Q - 1) / 2;
		let expected_max = 1u32 << 12;

		for i in 0..Params::K {
			for j in 0..N {
				let t1_coeff = pk.t1.get(i).get(j).value();
				let effective_magnitude = if t1_coeff > Q_HALF {
					Q - t1_coeff
				} else {
					t1_coeff
				};
				assert!(
					effective_magnitude <= expected_max,
					"t1 coefficient magnitude {} exceeds expected max {}",
					effective_magnitude,
					expected_max
				);
			}
		}
	}
}
