//! Trusted dealer key generation for threshold ML-DSA-87.
//!
//! This module implements key generation where a trusted dealer generates
//! all the key shares from a single seed. The dealer must be trusted not
//! to retain the shares or seed after distribution.

use alloc::{collections::BTreeMap, vec::Vec};

use qp_rusty_crystals_dilithium::{
	fips202, packing,
	params::{K, L, Q},
	poly, polyvec,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
	config::ThresholdConfig,
	error::{ThresholdError, ThresholdResult},
	keys::{PrivateKeyShare, PublicKey, SecretShareData, PUBLIC_KEY_SIZE},
	participants::{ParticipantId, ParticipantList},
	protocol::primitives::{mod_q, NttAccumulatorL},
};

/// Domain separator for per-subset dealer share-seed derivation.
const DEALER_SUBSHARE_DOMAIN: &[u8] = b"threshold-dealer-subshare-v1";

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
///
/// # Coefficient Distribution
///
/// The reconstructed secret `s = (s1, s2)` is the sum of `C(n, n-t+1)` independent
/// η-bounded shares (η=2 for ML-DSA-87). This produces a wider coefficient distribution
/// than standard ML-DSA's single η-bounded secret:
///
/// - **Individual shares**: Each RSS subset share has η-bounded coefficients in `[-2, 2]`
/// - **Recovered partial**: Sum of up to `C(n, n-t+1)` shares, e.g., 10 subsets for 3-of-5
/// - **Distribution**: Approximately Gaussian with σ ≈ √(2·m·(m-1)) where m = #subsets
///
/// This coefficient growth is intrinsic to the Replicated Secret Sharing (RSS) design
/// and cannot be exploited by malicious participants: each subset share is derived
/// deterministically via `H_keygen(S, K_S, R)` using `uniform_eta`, guaranteeing
/// η-bounded coefficients regardless of adversarial input.
///
/// The hyperball sampling parameters are pre-computed to accommodate this wider
/// distribution with substantial safety margins (>99% headroom in tested configurations).
/// See `protocol::signing::get_hyperball_params` for the configuration-specific parameters.
pub fn generate_with_dealer(
	seed: &[u8; 32],
	config: ThresholdConfig,
) -> ThresholdResult<(PublicKey, Vec<PrivateKeyShare>)> {
	let threshold = config.threshold();
	let parties = config.total_parties();

	// Defensive check: ThresholdConfig::new enforces this, but guard against
	// future refactors that might construct configs differently.
	debug_assert!(
		parties <= crate::error::MAX_PARTIES,
		"total_parties {} exceeds MAX_PARTIES {}",
		parties,
		crate::error::MAX_PARTIES
	);

	// Initialize SHAKE-256 stream for deterministic randomness
	let mut h = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut h, seed);

	// NIST mode: absorb K and L
	let kl = [K as u8, L as u8];
	fips202::shake256_absorb(&mut h, &kl);

	// Bind the threshold policy (t, n) into the dealer's randomness. RSS
	// enumerates `C(n, n-t+1)` subsets, and `C(n, n-t+1) == C(n, t-1)`, so
	// distinct policies over the same `n` (e.g. 2-of-3 vs 3-of-3, or 3-of-5 vs
	// 4-of-5) enumerate the *same number* of subsets. Without this binding they
	// would consume an identical XOF stream (rho, party keys, subset seeds) and
	// sum to the same secret, producing an identical public key — letting an old
	// weaker coalition sign under a key that was "strengthened" by re-running
	// keygen with the same seed. Absorbing (t, n) makes rho and every downstream
	// value policy-specific, so the public keys can no longer collide.
	fips202::shake256_absorb(&mut h, &threshold.to_le_bytes());
	fips202::shake256_absorb(&mut h, &parties.to_le_bytes());
	fips202::shake256_finalize(&mut h);

	// 1. Squeeze rho (seed for matrix A)
	let mut rho = [0u8; 32];
	fips202::shake256_squeeze(&mut rho, &mut h);

	// 2. Squeeze party keys
	let mut party_keys = Vec::with_capacity(parties as usize);
	for _ in 0..parties {
		let mut key = [0u8; 32];
		fips202::shake256_squeeze(&mut key, &mut h);
		party_keys.push(key);
	}

	// 3. Generate threshold shares
	let (_s1_total, s2_total, s1h_total, party_shares) =
		generate_threshold_shares(&mut h, threshold, parties)?;

	// 4. Generate matrix A from rho
	let mut a_matrix: [polyvec::Polyvecl; K] =
		core::array::from_fn(|_| polyvec::Polyvecl::default());
	polyvec::matrix_expand(&mut a_matrix, &rho);

	// 5. Compute t = A*s1 + s2
	let mut t = polyvec::Polyveck::default();

	for (i, a_row) in a_matrix.iter().enumerate().take(K) {
		for (a_poly, s1h_poly) in a_row.vec.iter().zip(s1h_total.vec.iter()).take(L) {
			let mut temp = poly::Poly::default();
			poly::pointwise_montgomery(&mut temp, a_poly, s1h_poly);
			poly::add_ip(&mut t.vec[i], &temp);
		}
		poly::reduce(&mut t.vec[i]);
		poly::invntt_tomont(&mut t.vec[i]);
	}

	// Add s2
	for (t_poly, s2_poly) in t.vec.iter_mut().zip(s2_total.vec.iter()).take(K) {
		poly::add_ip(t_poly, s2_poly);
	}

	// Normalize t
	for t_poly in t.vec.iter_mut().take(K) {
		poly::reduce(t_poly);
		for coeff in t_poly.coeffs_mut().iter_mut() {
			let normalized = ((*coeff % Q) + Q) % Q;
			*coeff = normalized;
		}
	}

	// 6. Extract t1 (high bits)
	let mut t0 = polyvec::Polyveck::default();
	let mut t1 = t.clone();
	polyvec::k_power2round(&mut t1, &mut t0);

	// 7. Pack public key
	let mut pk_packed = [0u8; PUBLIC_KEY_SIZE];
	packing::pack_pk(&mut pk_packed, &rho, &t1);

	// Create public key (TR is computed internally)
	let public_key = PublicKey::new(pk_packed);

	// 8. Compute TR = SHAKE256(pk) for private key shares
	let tr = *public_key.tr();

	// 9. Create private key shares
	let mut private_keys = Vec::with_capacity(parties as usize);
	for party_id in 0..parties {
		let party_shares_map = party_shares.get(&party_id).cloned().ok_or_else(|| {
			ThresholdError::InvalidData(alloc::format!(
				"Missing shares for party {} during key generation",
				party_id
			))
		})?;

		// Convert to SecretShareData format (u16 for subset masks to support up to 16 parties)
		let mut shares_data: BTreeMap<u16, SecretShareData> = BTreeMap::new();
		for (subset_id, share) in party_shares_map {
			let mut s1_data = [[0i32; 256]; L];
			for (i, s1_item) in s1_data.iter_mut().enumerate() {
				s1_item.copy_from_slice(share.s1_share.vec[i].coeffs());
			}

			let mut s2_data = [[0i32; 256]; K];
			for (i, s2_item) in s2_data.iter_mut().enumerate() {
				s2_item.copy_from_slice(share.s2_share.vec[i].coeffs());
			}

			shares_data.insert(subset_id, SecretShareData { s1: s1_data, s2: s2_data });
		}

		// For dealer-generated keys, participants have sequential IDs (0, 1, 2, ..., n-1)
		let dkg_participants =
			ParticipantList::new(&(0..parties).map(|i| i as ParticipantId).collect::<Vec<_>>())
				.expect("sequential IDs are always valid");

		let sk = PrivateKeyShare::new(
			party_id,
			parties,
			threshold,
			party_keys[party_id as usize],
			rho,
			tr,
			shares_data,
			dkg_participants,
		);
		private_keys.push(sk);
	}

	Ok((public_key, private_keys))
}

/// Internal secret share structure used during key generation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SecretShare {
	s1_share: polyvec::Polyvecl,
	s2_share: polyvec::Polyveck,
}

/// Result type for threshold share generation containing:
/// - s1_total: Polyvecl
/// - s2_total: Polyveck
/// - s1h_total: Polyvecl (NTT form)
/// - party_shares: BTreeMap<u32, BTreeMap<u16, SecretShare>> (u16 subset masks)
type ThresholdSharesResult = (
	polyvec::Polyvecl,
	polyvec::Polyveck,
	polyvec::Polyvecl,
	BTreeMap<u32, BTreeMap<u16, SecretShare>>,
);

/// Generate threshold shares for all subset combinations.
fn generate_threshold_shares(
	state: &mut fips202::KeccakState,
	threshold: u32,
	parties: u32,
) -> ThresholdResult<ThresholdSharesResult> {
	// Initialize party shares
	let mut party_shares: BTreeMap<u32, BTreeMap<u16, SecretShare>> = BTreeMap::new();
	for i in 0..parties {
		party_shares.insert(i, BTreeMap::new());
	}

	// Total secrets (η-bounded, safe with i32)
	let mut s1_total = polyvec::Polyvecl::default();
	let mut s2_total = polyvec::Polyveck::default();

	// NTT-domain accumulator uses u64 to avoid overflow for large configurations.
	let mut s1h_acc = NttAccumulatorL::new();

	// Generate shares for all possible "honest signer" combinations
	// Use u16 to support up to 16 parties
	let mut honest_signers: u16 = (1u16 << (parties - threshold + 1)) - 1;
	let max_combinations: u16 = 1u16 << parties;

	while honest_signers < max_combinations {
		// Derive this subset's seed with explicit domain separation by subset
		// mask (and threshold config), rather than assigning raw XOF output to
		// masks purely by enumeration order. This binds each secret share to the
		// subset it belongs to, so the derivation cannot be reinterpreted for a
		// different subset/policy that happens to squeeze the stream in the same
		// order. `raw` keys the derivation; `honest_signers` is the subset mask.
		let mut raw = [0u8; 64];
		fips202::shake256_squeeze(&mut raw, state);

		let mut sh = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut sh, DEALER_SUBSHARE_DOMAIN);
		fips202::shake256_absorb(&mut sh, &raw);
		fips202::shake256_absorb(&mut sh, &threshold.to_le_bytes());
		fips202::shake256_absorb(&mut sh, &parties.to_le_bytes());
		fips202::shake256_absorb(&mut sh, &honest_signers.to_le_bytes());
		fips202::shake256_finalize(&mut sh);

		let mut share_seed = [0u8; 64];
		fips202::shake256_squeeze(&mut share_seed, &mut sh);
		raw.zeroize();

		// Create η-bounded shares for s1
		let mut s1_share = polyvec::Polyvecl::default();
		for (j, s1_poly) in s1_share.vec.iter_mut().enumerate().take(L) {
			poly::uniform_eta(s1_poly, &share_seed, j as u16);
		}

		// Create η-bounded shares for s2
		let mut s2_share = polyvec::Polyveck::default();
		for (j, s2_poly) in s2_share.vec.iter_mut().enumerate().take(K) {
			poly::uniform_eta(s2_poly, &share_seed, (L + j) as u16);
		}

		// The plaintext seed is no longer needed; wipe it rather than leaving it
		// on the stack until the next iteration overwrites (or drops) it.
		share_seed.zeroize();

		// Compute NTT of s1 share and accumulate
		let mut s1h_share = s1_share.clone();
		for s1h_poly in s1h_share.vec.iter_mut().take(L) {
			crate::circl_ntt::ntt(s1h_poly);
		}
		s1h_acc.add_polyvecl(&s1h_share);

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

		// Add η-bounded shares to totals.
		// η-bounded coefficients are in [-2, 2], so even with 6435 subsets (max for 15 parties),
		// the sum is bounded by ±12870, well within i32 range.
		for (total_poly, share_poly) in s1_total.vec.iter_mut().zip(s1_share.vec.iter()).take(L) {
			for (total_coeff, share_coeff) in
				total_poly.coeffs_mut().iter_mut().zip(share_poly.coeffs().iter())
			{
				*total_coeff += *share_coeff;
			}
		}

		for (total_poly, share_poly) in s2_total.vec.iter_mut().zip(s2_share.vec.iter()).take(K) {
			for (total_coeff, share_coeff) in
				total_poly.coeffs_mut().iter_mut().zip(share_poly.coeffs().iter())
			{
				*total_coeff += *share_coeff;
			}
		}

		// Move to next combination
		let c = honest_signers & (!honest_signers + 1);
		let r = honest_signers + c;
		honest_signers = (((r ^ honest_signers) >> 2) / c) | r;
	}

	// Finalize NTT accumulator (reduces mod Q)
	let s1h_total = s1h_acc.finalize();

	// Normalize s1_total (η-bounded sums)
	for total_poly in s1_total.vec.iter_mut().take(L) {
		for total_coeff in total_poly.coeffs_mut().iter_mut() {
			let coeff_u32 =
				if *total_coeff < 0 { (*total_coeff + Q) as u32 } else { *total_coeff as u32 };
			*total_coeff = mod_q(coeff_u32) as i32;
		}
	}

	// Normalize s2_total (η-bounded sums)
	for total_poly in s2_total.vec.iter_mut().take(K) {
		for total_coeff in total_poly.coeffs_mut().iter_mut() {
			let coeff_u32 =
				if *total_coeff < 0 { (*total_coeff + Q) as u32 } else { *total_coeff as u32 };
			*total_coeff = mod_q(coeff_u32) as i32;
		}
	}

	Ok((s1_total, s2_total, s1h_total, party_shares))
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
			assert_eq!(share.party_id(), i as u32);
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

	/// Distinct threshold policies over the same `n` that enumerate the *same
	/// number* of RSS subsets must not collide on the public key when generated
	/// from the same seed. `C(n, n-t+1) == C(n, t-1)`, so 2-of-3 and 3-of-3 both
	/// enumerate 3 subsets, and 3-of-5 and 4-of-5 both enumerate 10. Before the
	/// (t, n) binding fix these produced byte-identical public keys, letting an
	/// old weaker coalition sign under a "strengthened" key.
	#[test]
	fn test_distinct_policies_same_subset_count_differ() {
		let seed = [0x5Au8; 32];

		// Same n=3, equal subset counts (C(3,2)=C(3,1)=3).
		let (pk_2of3, _) =
			generate_with_dealer(&seed, ThresholdConfig::new(2, 3).unwrap()).unwrap();
		let (pk_3of3, _) =
			generate_with_dealer(&seed, ThresholdConfig::new(3, 3).unwrap()).unwrap();
		assert_ne!(
			pk_2of3.as_bytes(),
			pk_3of3.as_bytes(),
			"2-of-3 and 3-of-3 must not share a public key for the same seed"
		);

		// Same n=5, equal subset counts (C(5,3)=C(5,2)=10).
		let (pk_3of5, _) =
			generate_with_dealer(&seed, ThresholdConfig::new(3, 5).unwrap()).unwrap();
		let (pk_4of5, _) =
			generate_with_dealer(&seed, ThresholdConfig::new(4, 5).unwrap()).unwrap();
		assert_ne!(
			pk_3of5.as_bytes(),
			pk_4of5.as_bytes(),
			"3-of-5 and 4-of-5 must not share a public key for the same seed"
		);
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
