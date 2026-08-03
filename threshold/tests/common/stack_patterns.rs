//! Secret-pattern helpers shared by the heap and stack zeroization probes.
//!
//! Included only by those tests (via `#[path = ...]`), not by every consumer
//! of `common/`, so resharing/coverage suites do not see unused items.

use qp_rusty_crystals_dilithium::fips202;

/// First 32 bytes of the SHAKE256 stream `sample_hyperball` squeezes for
/// iteration 0 of `round1_commit_with_seed(ssid, seed)`. Recomputed through
/// the public fips202 API (iteration 0 leaves the seed unmodified).
pub fn hyperball_stream_pattern(ssid: &[u8; 32], seed: &[u8; 32]) -> [u8; 32] {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, seed);
	fips202::shake256_absorb(&mut state, ssid);
	fips202::shake256_absorb(&mut state, b"rho_prime");
	fips202::shake256_absorb(&mut state, &[0u8]);
	fips202::shake256_finalize(&mut state);
	let mut iter_rho_prime = [0u8; 64];
	fips202::shake256_squeeze(&mut iter_rho_prime, &mut state);

	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, b"H");
	fips202::shake256_absorb(&mut state, &iter_rho_prime);
	fips202::shake256_absorb(&mut state, &0u16.to_le_bytes());
	fips202::shake256_finalize(&mut state);
	let mut pattern = [0u8; 32];
	fips202::shake256_squeeze(&mut pattern, &mut state);
	pattern
}

/// The 32-byte per-party key seed the dealer squeezes for party 0, recomputed
/// through the public fips202 API in the exact absorb/squeeze order of
/// `generate_with_dealer`: absorb the dealer seed, `[K, L]`, and the `(t, n)`
/// policy binding, then squeeze rho (public matrix seed, discarded) followed
/// by party 0's key seed.
pub fn dealer_party0_seed_pattern(seed: &[u8; 32], threshold: u32, parties: u32) -> [u8; 32] {
	use qp_rusty_crystals_threshold::params::{K, L};

	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, seed);
	fips202::shake256_absorb(&mut state, &[K as u8, L as u8]);
	fips202::shake256_absorb(&mut state, &threshold.to_le_bytes());
	fips202::shake256_absorb(&mut state, &parties.to_le_bytes());
	fips202::shake256_finalize(&mut state);
	let mut rho = [0u8; 32];
	fips202::shake256_squeeze(&mut rho, &mut state);
	let mut key0 = [0u8; 32];
	fips202::shake256_squeeze(&mut key0, &mut state);
	key0
}
