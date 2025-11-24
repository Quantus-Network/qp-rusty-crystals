#![no_std]
#![allow(clippy::identity_op)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::precedence)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::enum_variant_names)]

extern crate alloc;

pub mod drbg;
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
