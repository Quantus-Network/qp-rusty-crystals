//! Secret sharing primitives for threshold ML-DSA-87.
//!
//! This module provides the secret share recovery functionality used in the
//! threshold signing protocol. It uses computed sharing patterns to avoid
//! the coefficient explosion problem with general Lagrange interpolation.
//!
//! Subset masks use u16 to support up to 16 parties (currently supporting n ≤ 12).

use std::collections::{HashMap, HashSet};

use qp_rusty_crystals_dilithium::{params as dilithium_params, polyvec};

use crate::{
	error::{ThresholdError, ThresholdResult},
	participants::{ParticipantId, ParticipantList},
	protocol::primitives::mod_q,
};

/// Secret share for a single party.
#[derive(Clone)]
pub struct SecretShare {
	/// Party identifier for this secret share.
	#[allow(dead_code)]
	pub party_id: u32,
	/// Share of the s1 polynomial vector.
	pub s1_share: polyvec::Polyvecl,
	/// Share of the s2 polynomial vector.
	pub s2_share: polyvec::Polyveck,
}

/// Compute sharing patterns for a (threshold, parties) configuration.
///
/// These patterns determine which subset shares each party position uses during
/// signing. The algorithm ensures:
/// 1. Every "honest signer" subset (size = n - t + 1) is assigned to exactly one position
/// 2. Position i only receives subsets that contain party i (in canonical ordering)
///
/// # Arguments
/// * `threshold` - The threshold value t (minimum parties to sign)
/// * `parties` - The total number of parties n
///
/// # Returns
/// A vector of t patterns, where patterns[i] contains the subset masks for position i.
pub(crate) fn compute_sharing_patterns(
	threshold: u32,
	parties: u32,
) -> Result<Vec<Vec<u16>>, &'static str> {
	if threshold < 2 {
		return Err("Threshold must be at least 2");
	}
	if threshold > parties {
		return Err("Threshold cannot exceed number of parties");
	}
	if parties > 16 {
		return Err("Maximum 16 parties supported");
	}

	let t = threshold as usize;
	let n = parties as usize;

	// Special case: t == n means all parties required
	// Only one subset: all parties (2^n - 1)
	if t == n {
		return Ok(vec![vec![(1u16 << n) - 1]]);
	}

	// Generate all subsets of size (n - t + 1) using Gosper's hack
	let subset_size = n - t + 1;
	let subsets = generate_subsets_of_size(n, subset_size);

	// Initialize patterns for each position
	let mut patterns: Vec<Vec<u16>> = vec![Vec::new(); t];
	let mut used: HashSet<u16> = HashSet::new();

	// Assign subsets to positions greedily:
	// Position i gets all unassigned subsets that contain party i
	for pos in 0..t {
		for &subset in &subsets {
			if !used.contains(&subset) && (subset & (1 << pos)) != 0 {
				patterns[pos].push(subset);
				used.insert(subset);
			}
		}
	}

	// Verify all subsets were assigned
	if used.len() != subsets.len() {
		return Err("Failed to assign all subsets to positions");
	}

	Ok(patterns)
}

/// Generate all subsets of exactly `size` elements from `n` elements.
/// Uses Gosper's hack to efficiently enumerate subsets.
fn generate_subsets_of_size(n: usize, size: usize) -> Vec<u16> {
	if size > n || size == 0 {
		return Vec::new();
	}

	let mut subsets = Vec::new();
	let max_val: u16 = 1 << n;

	// Start with the smallest subset of the given size
	let mut subset: u16 = (1 << size) - 1;

	while subset < max_val {
		subsets.push(subset);

		// Gosper's hack to get next subset of same size
		let c = subset & (!subset + 1); // lowest set bit
		let r = subset + c; // next higher number with same bits, except one moved left
		subset = (((r ^ subset) >> 2) / c) | r;
	}

	subsets
}

/// Recover share using computed sharing patterns instead of Lagrange interpolation.
///
/// This avoids the coefficient explosion problem with general Lagrange interpolation
/// by using share combinations computed at runtime.
///
/// # Arguments
///
/// * `shares` - Map of shares keyed by subset ID (bitmask based on DKG indices)
/// * `party_id` - The party ID recovering the share (arbitrary ID, e.g., NEAR participant ID)
/// * `active_parties` - List of active party IDs participating in signing (arbitrary IDs)
/// * `threshold` - The threshold value (t)
/// * `parties` - Total number of parties (n)
/// * `dkg_participants` - The participant list from DKG, mapping arbitrary IDs to indices
///
/// # Returns
///
/// A tuple of (s1_ntt, s2_ntt) representing the recovered secret shares in NTT domain.
pub fn recover_share(
	shares: &HashMap<u16, SecretShare>,
	party_id: ParticipantId,
	active_parties: &[ParticipantId],
	threshold: u32,
	parties: u32,
	dkg_participants: &ParticipantList,
) -> ThresholdResult<(polyvec::Polyvecl, polyvec::Polyveck)> {
	// Base case: when threshold equals total parties
	// In this case, each party uses their single share directly
	// But we still need to convert to NTT domain like Go does
	if threshold == parties {
		// For t=n case, use the share that corresponds to all active parties
		// The share key is a bitmask of which parties are involved (using DKG indices)
		// For 2-of-2 with parties at indices 0,1 active, the key is 0b11 = 3
		let active_key: u16 = active_parties.iter().fold(0u16, |acc, &p| {
			if let Some(idx) = dkg_participants.index_of(p) {
				acc | (1 << idx)
			} else {
				acc
			}
		});

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

	// Compute the sharing patterns dynamically
	let sharing_patterns = compute_sharing_patterns(threshold, parties)
		.map_err(|e| ThresholdError::InvalidConfiguration(e.to_string()))?;

	// Get the DKG index for my party_id
	let my_dkg_index = dkg_participants.index_of(party_id).ok_or_else(|| {
		ThresholdError::InvalidConfiguration(format!(
			"Party {} not found in DKG participants",
			party_id
		))
	})?;

	// Get DKG indices for all active parties
	let active_indices: Vec<usize> =
		active_parties.iter().filter_map(|&p| dkg_participants.index_of(p)).collect();

	// Create permutation to cover the signing set (using DKG indices)
	let mut perm = vec![0usize; parties as usize];
	let mut i1 = 0;
	let mut i2 = threshold as usize;

	// Find the position of my_dkg_index within active_indices (sorted)
	let mut sorted_active_indices = active_indices.clone();
	sorted_active_indices.sort();
	let current_i =
		sorted_active_indices
			.iter()
			.position(|&idx| idx == my_dkg_index)
			.ok_or_else(|| {
				ThresholdError::InvalidConfiguration(format!(
					"Party {} (index {}) is not in active parties list",
					party_id, my_dkg_index
				))
			})?;

	for j in 0..parties as usize {
		if sorted_active_indices.contains(&j) {
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
		// The permutation maps positions to DKG indices
		let mut u_translated = 0u16;
		for i in 0..parties as usize {
			if pattern_u & (1 << i) != 0 {
				u_translated |= 1 << (perm[i] as u16);
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
					s1_combined.vec[i].coeffs[j] =
						s1_combined.vec[i].coeffs[j].wrapping_add(s1_ntt.vec[i].coeffs[j]);
				}
			}

			for i in 0..dilithium_params::K {
				for j in 0..(dilithium_params::N as usize) {
					s2_combined.vec[i].coeffs[j] =
						s2_combined.vec[i].coeffs[j].wrapping_add(s2_ntt.vec[i].coeffs[j]);
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
			let coeff_u32 =
				if coeff < 0 { (coeff + dilithium_params::Q as i32) as u32 } else { coeff as u32 };
			s1_combined.vec[i].coeffs[j] = mod_q(coeff_u32) as i32;
		}
	}

	for i in 0..dilithium_params::K {
		for j in 0..(dilithium_params::N as usize) {
			let coeff = s2_combined.vec[i].coeffs[j];
			let coeff_u32 =
				if coeff < 0 { (coeff + dilithium_params::Q as i32) as u32 } else { coeff as u32 };
			s2_combined.vec[i].coeffs[j] = mod_q(coeff_u32) as i32;
		}
	}

	Ok((s1_combined, s2_combined))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_generate_subsets_of_size() {
		// C(4, 2) = 6 subsets of size 2
		let subsets = generate_subsets_of_size(4, 2);
		assert_eq!(subsets.len(), 6);

		// All should have exactly 2 bits set
		for s in &subsets {
			assert_eq!(s.count_ones(), 2);
		}

		// C(5, 3) = 10 subsets of size 3
		let subsets = generate_subsets_of_size(5, 3);
		assert_eq!(subsets.len(), 10);
	}

	#[test]
	fn test_compute_sharing_patterns_t_equals_n() {
		// When t = n, there should be exactly one pattern with all bits set
		let test_cases = [
			(2, 2, 0b11u16),
			(3, 3, 0b111u16),
			(6, 6, 0b111111u16),
			(8, 8, 0b11111111u16),
			(12, 12, 0b111111111111u16),
		];

		for (t, n, expected_mask) in test_cases {
			let patterns = compute_sharing_patterns(t as u32, n as u32).unwrap();
			assert_eq!(patterns.len(), 1, "t=n should have 1 position for ({}, {})", t, n);
			assert_eq!(patterns[0].len(), 1, "t=n should have 1 pattern for ({}, {})", t, n);
			assert_eq!(
				patterns[0][0], expected_mask,
				"Pattern mask mismatch for ({}, {}): expected {}, got {}",
				t, n, expected_mask, patterns[0][0]
			);
		}
	}

	#[test]
	fn test_compute_sharing_patterns_coverage() {
		// Test that all subsets are covered exactly once
		let test_cases = [(2, 3), (2, 4), (3, 5), (4, 6), (6, 12)];

		for (t, n) in test_cases {
			let patterns = compute_sharing_patterns(t as u32, n as u32).unwrap();

			// Should have t positions
			assert_eq!(
				patterns.len(),
				t as usize,
				"Should have {} positions for ({}, {})",
				t,
				t,
				n
			);

			// Collect all subsets from all positions
			let mut all_subsets: Vec<u16> = patterns.iter().flatten().copied().collect();
			let total_subsets = all_subsets.len();

			// Check no duplicates
			all_subsets.sort();
			all_subsets.dedup();
			assert_eq!(
				all_subsets.len(),
				total_subsets,
				"Duplicate subsets found for ({}, {})",
				t,
				n
			);

			// Each position i should only have subsets containing bit i
			for (pos, pos_patterns) in patterns.iter().enumerate() {
				for &subset in pos_patterns {
					assert!(
						(subset & (1 << pos)) != 0,
						"Position {} has subset {} which doesn't contain bit {} for ({}, {})",
						pos,
						subset,
						pos,
						t,
						n
					);
				}
			}
		}
	}

	#[test]
	fn test_compute_sharing_patterns_all_configs() {
		// Test that patterns can be computed for all valid configurations up to n=15
		// (n=16 would overflow u16 in the subset mask calculation)
		// Note: MAX_PARTIES is 7 for the public API, but secret sharing supports up to 15
		// internally
		for n in 2..=15u8 {
			for t in 2..=n {
				let result = compute_sharing_patterns(t as u32, n as u32);
				assert!(
					result.is_ok(),
					"Failed to compute pattern for ({}, {}): {:?}",
					t,
					n,
					result.err()
				);
			}
		}
	}

	#[test]
	fn test_invalid_sharing_patterns() {
		// Threshold too small
		let result = compute_sharing_patterns(1u32, 3u32);
		assert!(result.is_err());

		// Threshold > parties
		let result = compute_sharing_patterns(5u32, 3u32);
		assert!(result.is_err());

		// Too many parties
		let result = compute_sharing_patterns(2u32, 17u32);
		assert!(result.is_err());
	}
}
