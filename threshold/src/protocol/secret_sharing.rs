//! Secret sharing primitives for threshold ML-DSA-87.
//!
//! This module provides the secret share recovery functionality used in the
//! threshold signing protocol. It uses hardcoded sharing patterns to avoid
//! the coefficient explosion problem with general Lagrange interpolation.

use std::collections::HashMap;

use qp_rusty_crystals_dilithium::{params as dilithium_params, polyvec};

use crate::error::{ThresholdError, ThresholdResult};
use crate::protocol::primitives::mod_q;

/// Secret share for a single party.
#[derive(Clone)]
pub struct SecretShare {
    /// Party identifier for this secret share.
    #[allow(dead_code)]
    pub party_id: u8,
    /// Share of the s1 polynomial vector.
    pub s1_share: polyvec::Polyvecl,
    /// Share of the s2 polynomial vector.
    pub s2_share: polyvec::Polyveck,
}

/// Get hardcoded sharing patterns for specific (threshold, parties) combinations.
///
/// These patterns avoid the large Lagrange coefficients by using precomputed
/// share combinations. Based on Threshold-ML-DSA implementation.
pub(crate) fn get_sharing_patterns(threshold: u8, parties: u8) -> Result<Vec<Vec<u8>>, &'static str> {
    // These patterns must match the Go implementation CODE (not comments)
    // The Go code uses different patterns than what's in the comments
    match (threshold, parties) {
        (2, 2) => Ok(vec![vec![3]]),
        (2, 3) => Ok(vec![vec![3, 5], vec![6]]),
        (2, 4) => Ok(vec![vec![11, 13], vec![7, 14]]),
        (3, 3) => Ok(vec![vec![7]]),
        (3, 4) => Ok(vec![vec![3, 9], vec![6, 10], vec![12, 5]]),
        (2, 5) => Ok(vec![vec![27, 29, 23], vec![30, 15]]),
        (3, 5) => Ok(vec![vec![25, 11, 19, 13], vec![7, 14, 22, 26], vec![28, 21]]),
        (4, 4) => Ok(vec![vec![15]]),
        (4, 5) => Ok(vec![vec![3, 9, 17], vec![6, 10, 18], vec![12, 5, 20], vec![24]]),
        (5, 5) => Ok(vec![vec![31]]),
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
        (6, 6) => Ok(vec![vec![63]]),
        _ => Err("Unsupported threshold/parties combination"),
    }
}

/// Recover share using hardcoded sharing patterns instead of Lagrange interpolation.
///
/// This avoids the coefficient explosion problem with general Lagrange interpolation
/// by using precomputed share combinations that match the Go reference implementation.
///
/// # Arguments
///
/// * `shares` - Map of shares keyed by subset ID (bitmask)
/// * `party_id` - The party ID recovering the share
/// * `active_parties` - List of active party IDs participating in signing
/// * `threshold` - The threshold value (t)
/// * `parties` - Total number of parties (n)
///
/// # Returns
///
/// A tuple of (s1_ntt, s2_ntt) representing the recovered secret shares in NTT domain.
pub fn recover_share_hardcoded(
    shares: &HashMap<u8, SecretShare>,
    party_id: u8,
    active_parties: &[u8],
    threshold: u8,
    parties: u8,
) -> ThresholdResult<(polyvec::Polyvecl, polyvec::Polyveck)> {
    // Base case: when threshold equals total parties
    // In this case, each party uses their single share directly
    // But we still need to convert to NTT domain like Go does
    if threshold == parties {
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
    let current_i = active_parties
        .iter()
        .position(|&p| p == party_id)
        .ok_or_else(|| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sharing_patterns_exist() {
        // Test that all supported configurations have patterns
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

        for (t, n) in configs {
            let result = get_sharing_patterns(t, n);
            assert!(
                result.is_ok(),
                "Expected sharing pattern for ({}, {})",
                t,
                n
            );
        }
    }

    #[test]
    fn test_invalid_sharing_patterns() {
        // Test unsupported configuration
        let result = get_sharing_patterns(1, 3);
        assert!(result.is_err());

        let result = get_sharing_patterns(7, 7);
        assert!(result.is_err());
    }
}
