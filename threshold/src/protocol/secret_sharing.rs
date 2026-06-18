//! Secret sharing primitives for threshold ML-DSA-87.
//!
//! This module provides the secret share recovery functionality used in the
//! threshold signing protocol. It uses computed sharing patterns to avoid
//! the coefficient explosion problem with general Lagrange interpolation.
//!
//! Subset masks use u16 to support up to 16 parties (currently supporting n ≤ 12).

use alloc::{
	collections::{BTreeMap, BTreeSet},
	format,
	string::String,
	vec,
	vec::Vec,
};

use qp_rusty_crystals_dilithium::{
	params::{K, L},
	polyvec,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
	error::{ThresholdError, ThresholdResult},
	participants::{ParticipantId, ParticipantList},
	protocol::primitives::{NttAccumulatorK, NttAccumulatorL},
};

/// Secret share for a single party.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretShare {
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
	use crate::error::MAX_PARTIES;

	if threshold < 2 {
		return Err("Threshold must be at least 2");
	}
	if threshold > parties {
		return Err("Threshold cannot exceed number of parties");
	}
	if parties > MAX_PARTIES {
		return Err("Number of parties exceeds MAX_PARTIES");
	}

	let t = threshold as usize;
	let n = parties as usize;

	// Generate all subsets of size (n - t + 1) using Gosper's hack
	// For t=n, this gives subsets of size 1 (single-bit masks)
	let subset_size = n - t + 1;
	let subsets = generate_subsets_of_size(n, subset_size);

	// Initialize patterns for each position
	let mut patterns: Vec<Vec<u16>> = vec![Vec::new(); t];
	let mut used: BTreeSet<u16> = BTreeSet::new();

	// Assign subsets to positions greedily:
	// Position i gets all unassigned subsets that contain party i
	for (pos, pattern) in patterns.iter_mut().enumerate().take(t) {
		for &subset in &subsets {
			if !used.contains(&subset) && (subset & (1 << pos)) != 0 {
				pattern.push(subset);
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
pub fn generate_subsets_of_size(n: usize, size: usize) -> Vec<u16> {
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

/// Build the share-recovery permutation for a signing set and translate the
/// recovering party's share patterns into subset masks over real participant
/// indices.
///
/// `signing_mask` is the signing set as a bitmask over participant indices
/// `0..parties` (exactly `threshold` bits set), and `my_index` is the recovering
/// party's own index. The returned masks are the subset shares that party sums to
/// reconstruct its recovered partial for this signing set.
///
/// This is the single source of truth for the permutation build + pattern
/// translation shared by [`recover_share`] (signing-time recovery) and the
/// resharing recovered-partial norm guard. Keeping one implementation guarantees
/// the guard checks the exact same share combination signing will use; two copies
/// could drift and silently defeat the guard's purpose.
pub(crate) fn translated_subset_masks(
	signing_mask: u16,
	my_index: usize,
	threshold: u32,
	parties: u32,
) -> Result<Vec<u16>, String> {
	let parties = parties as usize;
	let sharing_patterns = compute_sharing_patterns(threshold, parties as u32)?;

	// Active (signing-set) indices in ascending order.
	let active_indices: Vec<usize> =
		(0..parties).filter(|idx| (signing_mask & (1 << idx)) != 0).collect();

	let current_i = active_indices.iter().position(|&idx| idx == my_index).ok_or_else(|| {
		format!("party index {} is not in signing set {:b}", my_index, signing_mask)
	})?;

	if current_i >= sharing_patterns.len() {
		return Err(format!(
			"party slot {} exceeds sharing pattern count {}",
			current_i,
			sharing_patterns.len()
		));
	}

	// Permutation: active (signing-set) indices fill the first `threshold` slots in
	// ascending order, remaining indices fill the rest. Patterns are defined over
	// these permuted slots, so mapping a pattern bit `pos` to `perm[pos]` recovers
	// the real subset mask.
	let mut perm = vec![0usize; parties];
	let mut active_pos = 0usize;
	let mut inactive_pos = threshold as usize;
	for idx in 0..parties {
		if active_indices.contains(&idx) {
			perm[active_pos] = idx;
			active_pos += 1;
		} else {
			perm[inactive_pos] = idx;
			inactive_pos += 1;
		}
	}

	let translated = sharing_patterns[current_i]
		.iter()
		.map(|&pattern_u| {
			let mut mask = 0u16;
			for (pos, &mapped_idx) in perm.iter().enumerate().take(parties) {
				if (pattern_u & (1 << pos)) != 0 {
					mask |= 1 << mapped_idx;
				}
			}
			mask
		})
		.collect();

	Ok(translated)
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
	shares: &BTreeMap<u16, SecretShare>,
	party_id: ParticipantId,
	active_parties: &[ParticipantId],
	threshold: u32,
	parties: u32,
	dkg_participants: &ParticipantList,
) -> ThresholdResult<(polyvec::Polyvecl, polyvec::Polyveck)> {
	// Get the DKG index for my party_id
	let my_dkg_index = dkg_participants.index_of(party_id).ok_or_else(|| {
		ThresholdError::InvalidConfiguration(format!(
			"Party {} not found in DKG participants",
			party_id
		))
	})?;

	// Get DKG indices for all active parties - fail if any party is unknown
	let active_indices: Vec<usize> = active_parties
		.iter()
		.map(|&p| {
			dkg_participants.index_of(p).ok_or_else(|| {
				ThresholdError::InvalidConfiguration(format!(
					"Active party {} not found in DKG participants",
					p
				))
			})
		})
		.collect::<ThresholdResult<Vec<usize>>>()?;

	// Translate this party's share patterns into subset masks over DKG indices.
	// Shared with the resharing norm guard so both recover the identical shares.
	let signing_mask: u16 = active_indices.iter().fold(0u16, |mask, &idx| mask | (1 << idx));
	let translated_masks = translated_subset_masks(signing_mask, my_dkg_index, threshold, parties)
		.map_err(ThresholdError::InvalidConfiguration)?;

	// Use NTT accumulators to avoid i32 overflow for large configurations.
	// After NTT, coefficients are bounded by 18*Q. For large subset counts,
	// the sum can exceed i32::MAX.
	let mut s1_acc = NttAccumulatorL::new();
	let mut s2_acc = NttAccumulatorK::new();

	for &u_translated in &translated_masks {
		// Find the corresponding share - MUST exist for correct recovery
		let share = shares.get(&u_translated).ok_or_else(|| {
			ThresholdError::InvalidConfiguration(format!(
				"Missing required share for subset mask 0x{:04x}",
				u_translated
			))
		})?;

		// Convert share to NTT domain and accumulate
		let mut s1_ntt = share.s1_share.clone();
		let mut s2_ntt = share.s2_share.clone();

		for s1_poly in s1_ntt.vec.iter_mut().take(L) {
			crate::circl_ntt::ntt(s1_poly);
		}
		for s2_poly in s2_ntt.vec.iter_mut().take(K) {
			crate::circl_ntt::ntt(s2_poly);
		}

		// Accumulate in u64 to avoid overflow
		s1_acc.add_polyvecl(&s1_ntt);
		s2_acc.add_polyveck(&s2_ntt);
	}

	// Finalize accumulators (reduces mod Q)
	let s1_combined = s1_acc.finalize();
	let s2_combined = s2_acc.finalize();

	Ok((s1_combined, s2_combined))
}

#[cfg(test)]
mod tests {
	use alloc::string::ToString;

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
		// When t = n, each party gets their single-party subset
		// For n parties, there are n positions, each with one pattern (single bit set)
		// Limited to MAX_PARTIES=6
		let test_cases = [(2, 2), (3, 3), (4, 4), (5, 5), (6, 6)];

		for (t, n) in test_cases {
			let patterns = compute_sharing_patterns(t as u32, n as u32).unwrap();
			assert_eq!(patterns.len(), n, "t=n should have {} positions for ({}, {})", n, t, n);

			// Each position i should have exactly one pattern: (1 << i)
			for (i, pattern) in patterns.iter().enumerate() {
				assert_eq!(
					pattern.len(),
					1,
					"Position {} should have 1 pattern for ({}, {})",
					i,
					t,
					n
				);
				let expected_mask = 1u16 << i;
				assert_eq!(
					pattern[0], expected_mask,
					"Position {} pattern mismatch for ({}, {}): expected {}, got {}",
					i, t, n, expected_mask, pattern[0]
				);
			}
		}
	}

	#[test]
	fn test_compute_sharing_patterns_coverage() {
		use crate::error::MAX_PARTIES;
		// Test all valid configurations up to MAX_PARTIES
		// Verifies correctness properties for each (t, n) pair
		for n in 2..=MAX_PARTIES as usize {
			for t in 2..=n {
				let patterns = compute_sharing_patterns(t as u32, n as u32).unwrap();

				// Should have t positions
				assert_eq!(patterns.len(), t, "Should have {} positions for ({}, {})", t, t, n);

				// Collect all subsets from all positions
				let mut all_subsets: Vec<u16> = patterns.iter().flatten().copied().collect();
				let total_subsets = all_subsets.len();

				// Verify total count matches C(n, n-t+1)
				let subset_size = n - t + 1;
				let expected_count = binomial(n, subset_size);
				assert_eq!(
					total_subsets, expected_count,
					"Total subsets {} != C({}, {}) = {} for ({}, {})",
					total_subsets, n, subset_size, expected_count, t, n
				);

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

				// Each subset should have exactly (n - t + 1) bits set
				for &subset in &all_subsets {
					assert_eq!(
						(subset as u32).count_ones() as usize,
						subset_size,
						"Subset {} has wrong number of bits for ({}, {})",
						subset,
						t,
						n
					);
				}

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
	}

	/// Compute binomial coefficient C(n, k)
	fn binomial(n: usize, k: usize) -> usize {
		if k > n {
			return 0;
		}
		if k == 0 || k == n {
			return 1;
		}
		// Use the multiplicative formula to avoid overflow
		let k = k.min(n - k); // Take advantage of symmetry
		let mut result = 1;
		for i in 0..k {
			result = result * (n - i) / (i + 1);
		}
		result
	}

	#[test]
	fn test_invalid_sharing_patterns() {
		// Threshold too small
		let result = compute_sharing_patterns(1u32, 3u32);
		assert!(result.is_err());

		// Threshold > parties
		let result = compute_sharing_patterns(5u32, 3u32);
		assert!(result.is_err());

		// Too many parties (exceeds MAX_PARTIES=6)
		let result = compute_sharing_patterns(2u32, 7u32);
		assert!(result.is_err());
	}

	#[test]
	fn test_recover_share_rejects_unknown_active_party() {
		use crate::participants::ParticipantList;
		use alloc::collections::BTreeMap;

		// Create DKG participants: [10, 20, 30]
		let dkg_participants = ParticipantList::new(&[10, 20, 30]).unwrap();

		// Empty shares map (we'll fail before needing shares)
		let shares: BTreeMap<u16, SecretShare> = BTreeMap::new();

		// Active parties include party 99 which is NOT in dkg_participants
		let active_parties = vec![10, 20, 99];

		let result = recover_share(&shares, 10, &active_parties, 2, 3, &dkg_participants);

		assert!(result.is_err());
		match result {
			Err(err) => {
				let err_msg = err.to_string();
				assert!(
					err_msg.contains("Active party 99 not found"),
					"Expected error about unknown party 99, got: {}",
					err_msg
				);
			},
			Ok(_) => panic!("Expected error for unknown active party"),
		}
	}

	#[test]
	fn test_recover_share_rejects_missing_share() {
		use crate::participants::ParticipantList;
		use alloc::collections::BTreeMap;

		// Create DKG participants: [10, 20, 30]
		let dkg_participants = ParticipantList::new(&[10, 20, 30]).unwrap();

		// Empty shares map - no shares at all
		let shares: BTreeMap<u16, SecretShare> = BTreeMap::new();

		// Valid active parties
		let active_parties = vec![10, 20];

		// This should fail because the required shares are missing
		let result = recover_share(&shares, 10, &active_parties, 2, 3, &dkg_participants);

		assert!(result.is_err());
		match result {
			Err(err) => {
				let err_msg = err.to_string();
				assert!(
					err_msg.contains("Missing required share"),
					"Expected error about missing share, got: {}",
					err_msg
				);
			},
			Ok(_) => panic!("Expected error for missing share"),
		}
	}
}
