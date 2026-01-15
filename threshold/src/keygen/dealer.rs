//! Trusted dealer key generation for threshold ML-DSA-87.
//!
//! This module implements key generation where a trusted dealer generates
//! all the key shares from a single seed. The dealer must be trusted not
//! to retain the shares or seed after distribution.

use std::collections::HashMap;

use qp_rusty_crystals_dilithium::{fips202, packing, poly, polyvec};

use crate::{
	config::ThresholdConfig,
	error::ThresholdResult,
	keys::{PrivateKeyShare, PublicKey, SecretShareData, PUBLIC_KEY_SIZE, TR_SIZE},
	protocol::primitives::{K, L, N, Q},
};

/// Generate threshold keys using a trusted dealer.
///
/// This function generates a public key and private key shares for all parties
/// from a single seed. The dealer (caller of this function) has access to all
/// shares and must be trusted to:
///
/// 1. Use a cryptographically secure random seed
/// 2. Securely distribute each share to its respective party
/// 3. Delete all shares and the seed after distribution
///
/// # Arguments
///
/// * `seed` - A 32-byte seed for deterministic key generation
/// * `config` - Threshold configuration specifying (t, n) parameters
///
/// # Returns
///
/// A tuple of (public_key, shares) where:
/// * `public_key` - The threshold public key, shared by all parties
/// * `shares` - Vector of private key shares, one per party (index = party_id)
///
/// # Example
///
/// ```ignore
/// use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig};
///
/// let config = ThresholdConfig::new(2, 3)?;
/// let seed = [0u8; 32]; // Use a secure random seed in practice!
///
/// let (public_key, shares) = generate_with_dealer(&seed, config)?;
///
/// assert_eq!(shares.len(), 3);
/// assert_eq!(shares[0].party_id(), 0);
/// assert_eq!(shares[1].party_id(), 1);
/// assert_eq!(shares[2].party_id(), 2);
/// ```
///
/// # Security Warning
///
/// **The seed and shares contain secret material.** After distributing shares
/// to the respective parties, ensure that:
///
/// - The seed is securely erased
/// - Each share is only accessible to its designated party
/// - The dealer does not retain copies of any shares
pub fn generate_with_dealer(
	seed: &[u8; 32],
	config: ThresholdConfig,
) -> ThresholdResult<(PublicKey, Vec<PrivateKeyShare>)> {
	let threshold = config.threshold();
	let parties = config.total_parties();

	// Initialize SHAKE-256 stream for deterministic randomness
	let mut h = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut h, seed, 32);

	// NIST mode: absorb K and L
	let kl = [K as u8, L as u8];
	fips202::shake256_absorb(&mut h, &kl, 2);
	fips202::shake256_finalize(&mut h);

	// 1. Squeeze rho (seed for matrix A)
	let mut rho = [0u8; 32];
	fips202::shake256_squeeze(&mut rho, 32, &mut h);

	// 2. Squeeze party keys
	let mut party_keys = Vec::with_capacity(parties as usize);
	for _ in 0..parties {
		let mut key = [0u8; 32];
		fips202::shake256_squeeze(&mut key, 32, &mut h);
		party_keys.push(key);
	}

	// 3. Generate threshold shares
	let (_s1_total, s2_total, s1h_total, party_shares) =
		generate_threshold_shares(&mut h, threshold, parties)?;

	// 4. Generate matrix A from rho
	let mut a_matrix: Vec<polyvec::Polyvecl> =
		(0..K).map(|_| polyvec::Polyvecl::default()).collect();
	polyvec::matrix_expand(&mut a_matrix, &rho);

	// 5. Compute t = A*s1 + s2
	let mut t = polyvec::Polyveck::default();

	for i in 0..K {
		for j in 0..L {
			let mut temp = poly::Poly::default();
			poly::pointwise_montgomery(&mut temp, &a_matrix[i].vec[j], &s1h_total.vec[j]);
			t.vec[i] = poly::add(&t.vec[i], &temp);
		}
		poly::reduce(&mut t.vec[i]);
		poly::invntt_tomont(&mut t.vec[i]);
	}

	// Add s2
	for i in 0..K {
		t.vec[i] = poly::add(&t.vec[i], &s2_total.vec[i]);
	}

	// Normalize t
	for i in 0..K {
		poly::reduce(&mut t.vec[i]);
		for j in 0..N {
			let coeff = t.vec[i].coeffs[j];
			let normalized = ((coeff % Q) + Q) % Q;
			t.vec[i].coeffs[j] = normalized;
		}
	}

	// 6. Extract t1 (high bits)
	let mut t0 = polyvec::Polyveck::default();
	let mut t1 = t.clone();
	polyvec::k_power2round(&mut t1, &mut t0);

	// 7. Pack public key
	let mut pk_packed = [0u8; PUBLIC_KEY_SIZE];
	packing::pack_pk(&mut pk_packed, &rho, &t1);

	// 8. Compute TR = SHAKE256(pk)
	let mut tr = [0u8; TR_SIZE];
	let mut h_tr = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut h_tr, &pk_packed, pk_packed.len());
	fips202::shake256_finalize(&mut h_tr);
	fips202::shake256_squeeze(&mut tr, TR_SIZE, &mut h_tr);

	// Create public key
	let public_key = PublicKey::new(pk_packed, tr);

	// 9. Create private key shares
	let mut private_keys = Vec::with_capacity(parties as usize);
	for party_id in 0..parties {
		let party_shares_map = party_shares.get(&party_id).cloned().unwrap_or_default();

		// Convert to SecretShareData format (u16 for subset masks to support up to 16 parties)
		let mut shares_data: HashMap<u16, SecretShareData> = HashMap::new();
		for (subset_id, share) in party_shares_map {
			let s1_data: Vec<[i32; 256]> = (0..L)
				.map(|i| {
					let mut arr = [0i32; 256];
					arr.copy_from_slice(&share.s1_share.vec[i].coeffs);
					arr
				})
				.collect();

			let s2_data: Vec<[i32; 256]> = (0..K)
				.map(|i| {
					let mut arr = [0i32; 256];
					arr.copy_from_slice(&share.s2_share.vec[i].coeffs);
					arr
				})
				.collect();

			shares_data.insert(subset_id, SecretShareData { s1: s1_data, s2: s2_data });
		}

		let sk = PrivateKeyShare::new(
			party_id,
			parties,
			threshold,
			party_keys[party_id as usize],
			rho,
			tr,
			shares_data,
		);
		private_keys.push(sk);
	}

	Ok((public_key, private_keys))
}

/// Internal secret share structure used during key generation.
#[derive(Clone)]
struct SecretShare {
	s1_share: polyvec::Polyvecl,
	s2_share: polyvec::Polyveck,
}

/// Generate threshold shares using the reference implementation approach.
fn generate_threshold_shares(
	state: &mut fips202::KeccakState,
	threshold: u8,
	parties: u8,
) -> ThresholdResult<(
	polyvec::Polyvecl,                      // s1_total
	polyvec::Polyveck,                      // s2_total
	polyvec::Polyvecl,                      // s1h_total (NTT form)
	HashMap<u8, HashMap<u16, SecretShare>>, // party_shares (u16 subset masks)
)> {
	// Initialize party shares
	let mut party_shares: HashMap<u8, HashMap<u16, SecretShare>> = HashMap::new();
	for i in 0..parties {
		party_shares.insert(i, HashMap::new());
	}

	// Total secrets
	let mut s1_total = polyvec::Polyvecl::default();
	let mut s2_total = polyvec::Polyveck::default();
	let mut s1h_total = polyvec::Polyvecl::default();

	// Generate shares for all possible "honest signer" combinations
	// Use u16 to support up to 16 parties
	let mut honest_signers: u16 = (1u16 << (parties - threshold + 1)) - 1;
	let max_combinations: u16 = 1u16 << parties;

	while honest_signers < max_combinations {
		// Generate random seed for this share
		let mut share_seed = [0u8; 64];
		fips202::shake256_squeeze(&mut share_seed, 64, state);

		// Create η-bounded shares for s1
		let mut s1_share = polyvec::Polyvecl::default();
		for j in 0..L {
			sample_poly_leq_eta(&mut s1_share.vec[j], &share_seed, j as u16, 2);
		}

		// Create η-bounded shares for s2
		let mut s2_share = polyvec::Polyveck::default();
		for j in 0..K {
			sample_poly_leq_eta(&mut s2_share.vec[j], &share_seed, (L + j) as u16, 2);
		}

		// Compute NTT of s1 share
		let mut s1h_share = s1_share.clone();
		for j in 0..L {
			crate::circl_ntt::ntt(&mut s1h_share.vec[j]);
		}

		// Create share object
		let share = SecretShare { s1_share: s1_share.clone(), s2_share: s2_share.clone() };

		// Distribute to all parties in this combination
		for i in 0..parties {
			if (honest_signers & (1 << i)) != 0 {
				if let Some(party_map) = party_shares.get_mut(&i) {
					party_map.insert(honest_signers, share.clone());
				}
			}
		}

		// Add to total
		for i in 0..L {
			for j in 0..N {
				s1_total.vec[i].coeffs[j] =
					s1_total.vec[i].coeffs[j].wrapping_add(s1_share.vec[i].coeffs[j]);
				s1h_total.vec[i].coeffs[j] =
					s1h_total.vec[i].coeffs[j].wrapping_add(s1h_share.vec[i].coeffs[j]);
			}
		}

		for i in 0..K {
			for j in 0..N {
				s2_total.vec[i].coeffs[j] =
					s2_total.vec[i].coeffs[j].wrapping_add(s2_share.vec[i].coeffs[j]);
			}
		}

		// Move to next combination
		let c = honest_signers & (!honest_signers + 1);
		let r = honest_signers + c;
		honest_signers = (((r ^ honest_signers) >> 2) / c) | r;
	}

	// Normalize totals
	for i in 0..L {
		for j in 0..N {
			let coeff = s1_total.vec[i].coeffs[j];
			let coeff_u32 = if coeff < 0 { (coeff + Q) as u32 } else { coeff as u32 };
			s1_total.vec[i].coeffs[j] = mod_q(coeff_u32) as i32;

			let coeff_h = s1h_total.vec[i].coeffs[j];
			let coeff_h_u32 = if coeff_h < 0 { (coeff_h + Q) as u32 } else { coeff_h as u32 };
			s1h_total.vec[i].coeffs[j] = mod_q(coeff_h_u32) as i32;
		}
	}

	for i in 0..K {
		for j in 0..N {
			let coeff = s2_total.vec[i].coeffs[j];
			let coeff_u32 = if coeff < 0 { (coeff + Q) as u32 } else { coeff as u32 };
			s2_total.vec[i].coeffs[j] = mod_q(coeff_u32) as i32;
		}
	}

	Ok((s1_total, s2_total, s1h_total, party_shares))
}

/// Sample a polynomial with coefficients in [-eta, eta].
fn sample_poly_leq_eta(p: &mut poly::Poly, seed: &[u8; 64], nonce: u16, eta: i32) {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, seed, 64);
	fips202::shake256_absorb(&mut state, &nonce.to_le_bytes(), 2);
	fips202::shake256_finalize(&mut state);

	let mut buf = [0u8; 512];
	fips202::shake256_squeeze(&mut buf, 512, &mut state);

	let mut idx = 0;
	for i in 0..N {
		loop {
			if idx >= buf.len() {
				// Need more random bytes
				fips202::shake256_squeeze(&mut buf, 512, &mut state);
				idx = 0;
			}

			let b = buf[idx] as i32;
			idx += 1;

			// Rejection sampling for uniform in [-eta, eta]
			let bound = 2 * eta + 1;
			if b < (256 / bound) * bound {
				p.coeffs[i] = (b % bound) - eta;
				break;
			}
		}
	}
}

/// Reduce x to a value ≤ 2Q.
fn reduce_le2q(x: u32) -> u32 {
	let x1 = x >> 23;
	let x2 = x & 0x7FFFFF;
	x2 + (x1 << 13) - x1
}

/// Returns x mod q for 0 ≤ x < 2q.
fn le2q_mod_q(x: u32) -> u32 {
	let q = Q as u32;
	let result = x.wrapping_sub(q);
	let mask = (result as i32 >> 31) as u32;
	result.wrapping_add(mask & q)
}

/// Returns x mod q.
fn mod_q(x: u32) -> u32 {
	le2q_mod_q(reduce_le2q(x))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_generate_with_dealer_2_of_3() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let seed = [42u8; 32];

		let result = generate_with_dealer(&seed, config);
		assert!(result.is_ok(), "Key generation should succeed");

		let (public_key, shares) = result.unwrap();

		// Check we got the right number of shares
		assert_eq!(shares.len(), 3);

		// Check party IDs
		for (i, share) in shares.iter().enumerate() {
			assert_eq!(share.party_id(), i as u8);
			assert_eq!(share.threshold(), 2);
			assert_eq!(share.total_parties(), 3);
		}

		// Check public key is valid size
		assert_eq!(public_key.as_bytes().len(), PUBLIC_KEY_SIZE);
	}

	#[test]
	fn test_generate_with_dealer_deterministic() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let seed = [123u8; 32];

		let (pk1, shares1) = generate_with_dealer(&seed, config).unwrap();
		let (pk2, shares2) = generate_with_dealer(&seed, config).unwrap();

		// Same seed should produce same keys
		assert_eq!(pk1.as_bytes(), pk2.as_bytes());
		assert_eq!(shares1.len(), shares2.len());
	}

	#[test]
	fn test_generate_with_dealer_different_seeds() {
		let config = ThresholdConfig::new(2, 3).unwrap();
		let seed1 = [1u8; 32];
		let seed2 = [2u8; 32];

		let (pk1, _) = generate_with_dealer(&seed1, config).unwrap();
		let (pk2, _) = generate_with_dealer(&seed2, config).unwrap();

		// Different seeds should produce different keys
		assert_ne!(pk1.as_bytes(), pk2.as_bytes());
	}

	#[test]
	fn test_all_valid_configs() {
		let configs = [
			(2, 2),
			(2, 3),
			(3, 3),
			(2, 4),
			(3, 4),
			(4, 4),
			(2, 5),
			(3, 5),
			(4, 5),
			(5, 5),
			(2, 6),
			(3, 6),
			(4, 6),
			(5, 6),
			(6, 6),
		];

		let seed = [0u8; 32];

		for (t, n) in configs {
			let config = ThresholdConfig::new(t, n).unwrap();
			let result = generate_with_dealer(&seed, config);
			assert!(result.is_ok(), "Key generation should succeed for ({}, {})", t, n);

			let (_, shares) = result.unwrap();
			assert_eq!(shares.len(), n as usize);
		}
	}
}
