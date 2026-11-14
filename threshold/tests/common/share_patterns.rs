//! `PrivateKeyShare` secret patterns for the stack zeroization probes.
//!
//! Included only by those probes (via `#[path = ...]`), not by every consumer
//! of `common/`, so the other suites do not see unused items.

use qp_rusty_crystals_threshold::{
	params::{K, L},
	PrivateKeyShare,
};

/// The coefficients of one polynomial.
pub type Coeffs = [i32; 256];

/// Scan pattern for a polynomial: its first 64 coefficients as they lie in
/// memory (little-endian `i32`s). Long enough that it cannot false-positive
/// on unrelated memory even for η-bounded dealer shares.
pub fn poly_pattern(coeffs: &Coeffs) -> Vec<u8> {
	coeffs[..64].iter().flat_map(|c| c.to_le_bytes()).collect()
}

/// The secrets of `share`, decoded from its Borsh serialization (the
/// coefficients have no public accessor): the 32-byte key seed and, per
/// subset mask, the subset share's L + K polynomials (`s1` then `s2`).
///
/// Serialized layout: party_id (4) || total_parties (4) || threshold (4) ||
/// participant list (4 + 4n) || key (32) || rho (32) || tr (64) || shares
/// len (4) || entries, each mask (2) || s1 (L polynomials) || s2 (K).
pub fn decode_share(share: &PrivateKeyShare) -> ([u8; 32], Vec<(u16, Vec<Coeffs>)>) {
	let blob = borsh::to_vec(share).expect("share serializes");
	let key_offset = 16 + 4 * share.total_parties() as usize;
	let entries_offset = key_offset + 32 + 32 + 64 + 4;
	let entry_bytes = 2 + (L + K) * size_of::<Coeffs>();
	assert_eq!(
		(blob.len() - entries_offset) % entry_bytes,
		0,
		"layout drift: entries region is not whole share entries"
	);

	let key = blob[key_offset..key_offset + 32].try_into().expect("32-byte key seed");
	let subsets = blob[entries_offset..]
		.chunks_exact(entry_bytes)
		.map(|entry| {
			let polys = entry[2..]
				.chunks_exact(size_of::<Coeffs>())
				.map(|poly| {
					let (coeffs, _) = poly.as_chunks::<4>();
					core::array::from_fn(|i| i32::from_le_bytes(coeffs[i]))
				})
				.collect();
			(u16::from_le_bytes([entry[0], entry[1]]), polys)
		})
		.collect();
	(key, subsets)
}

/// The secrets of `share` as named scan patterns: the key seed and one
/// pattern per polynomial of every subset share. A copy of a subset share
/// anywhere on the stack contains all of them; scanning every polynomial
/// rather than only `s1[0]` also catches a copy that later frames partly
/// overwrote.
///
/// Subset shares are replicated across the subset's members, so their names
/// carry only the subset mask: collecting several parties' patterns and
/// deduplicating scans each subset once.
pub fn share_patterns(share: &PrivateKeyShare) -> Vec<(String, Vec<u8>)> {
	let (key, subsets) = decode_share(share);
	let mut patterns = vec![(format!("party {} key seed", share.party_id()), key.to_vec())];
	for (mask, polys) in subsets {
		for (i, poly) in polys.iter().enumerate() {
			let name = if i < L { format!("s1[{i}]") } else { format!("s2[{}]", i - L) };
			patterns.push((format!("subset {mask:#b} {name}"), poly_pattern(poly)));
		}
	}
	patterns
}

/// Borrow owned patterns in the shape `probe_stack_for_named` takes.
pub fn named(patterns: &[(String, Vec<u8>)]) -> Vec<(&str, &[u8])> {
	patterns.iter().map(|(name, bytes)| (name.as_str(), bytes.as_slice())).collect()
}
