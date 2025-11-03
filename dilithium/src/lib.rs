#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::identity_op)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::precedence)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::enum_variant_names)]

extern crate alloc;

pub mod drbg_wrapper;
mod errors;
pub mod fips202;
pub mod ml_dsa_87;
pub mod ntt;
pub mod packing;
pub mod params;
pub mod poly;
pub mod polyvec;
pub mod reduce;
pub mod rounding;
pub mod sign;

pub enum PH {
	SHA256,
	SHA512,
}

#[cfg(feature = "std")]
use rand::RngCore;
/// Generate random bytes using DRBG
///
/// # Arguments
///
/// * 'bytes' - an array to fill with random data
/// * 'n' - number of bytes to generate
///
/// This function uses DRBG for deterministic randomness. If DRBG is not initialized,
/// it will initialize it with OS entropy on first use.
#[cfg(feature = "std")]
fn random_bytes(bytes: &mut [u8], n: usize) {
	// Try DRBG first
	if drbg_wrapper::randombytes(bytes, n).is_err() {
		// Initialize DRBG with OS entropy for normal use
		let mut seed = [0u8; 48];
		rand::prelude::thread_rng().try_fill_bytes(&mut seed).unwrap();
		drbg_wrapper::randombytes_init(&seed, None, 256).unwrap();
		drbg_wrapper::randombytes(bytes, n).unwrap();
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn params() {
		assert_eq!(crate::params::Q, 8380417);
		assert_eq!(crate::params::N, 256);
		assert_eq!(crate::params::R, 1753);
		assert_eq!(crate::params::D, 13);
	}
	#[test]
	fn params_lvl5() {
		assert_eq!(crate::params::TAU, 60);
		assert_eq!(crate::params::CHALLENGE_ENTROPY, 257);
		assert_eq!(crate::params::GAMMA1, 524288);
		assert_eq!(crate::params::GAMMA2, 261888);
		assert_eq!(crate::params::K, 8);
		assert_eq!(crate::params::L, 7);
		assert_eq!(crate::params::ETA, 2);
		assert_eq!(crate::params::BETA, 120);
		assert_eq!(crate::params::OMEGA, 75);
	}
}
