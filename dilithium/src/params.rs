//! ML-DSA parameter sets (FIPS 204, Table 1 and Table 2).
//!
//! Constants shared by every parameter set live at the top level. The
//! variant-specific tables live in the [`ml_dsa_44`], [`ml_dsa_65`] and
//! [`ml_dsa_87`] submodules, each exposing the same constant names so generic
//! code can be instantiated uniformly from any of them.
//!
//! The crate's current single-variant frontend is ML-DSA-87, so its constants
//! are additionally re-exported at the top level under the historical names
//! (`params::K`, `params::GAMMA1`, ...). Existing call sites are unaffected.

// Specification defined constants (shared by all variants)
pub const Q: i32 = (1 << 23) - (1 << 13) + 1; //prime defining the field
pub const N: i32 = 256; //ring defining polynomial degree
pub const R: i32 = 1753; //2Nth root of unity mod Q
pub const D: i32 = 13; //dropped bits

// Implementation specific values (shared by all variants)
pub const SEEDBYTES: usize = 32;
pub const CRHBYTES: usize = 64;
pub const POLYT1_PACKEDBYTES: usize = 320;
pub const POLYT0_PACKEDBYTES: usize = 416;
pub const TR_BYTES: usize = 64;

// Packed-size helpers, derived from a variant's base parameters. These are
// `const fn` so const-generic code can assert, at compile time, that the
// buffer sizes it was instantiated with are consistent with the ETA / GAMMA1 /
// GAMMA2 values it was given (the assertions are evaluated at
// monomorphization). Each panics on a value not defined by FIPS 204, so an
// unsupported instantiation fails to compile.

/// Packed byte size of one eta-encoded secret polynomial (`s1`/`s2`).
pub const fn polyeta_packedbytes(eta: usize) -> usize {
	match eta {
		2 => 3 * N as usize / 8, // 3 bits per coefficient (ML-DSA-44/87)
		4 => 4 * N as usize / 8, // 4 bits per coefficient (ML-DSA-65)
		_ => panic!("unsupported ETA parameter"),
	}
}

/// Packed byte size of one mask polynomial (`z`).
pub const fn polyz_packedbytes(gamma1: usize) -> usize {
	match gamma1 {
		0x20000 => 18 * N as usize / 8, // 18 bits per coefficient (ML-DSA-44)
		0x80000 => 20 * N as usize / 8, // 20 bits per coefficient (ML-DSA-65/87)
		_ => panic!("unsupported GAMMA1 parameter"),
	}
}

/// Packed byte size of one commitment high-bits polynomial (`w1`).
pub const fn polyw1_packedbytes(gamma2: usize) -> usize {
	if gamma2 == (Q as usize - 1) / 88 {
		6 * N as usize / 8 // 6 bits per coefficient, values in [0, 43] (ML-DSA-44)
	} else if gamma2 == (Q as usize - 1) / 32 {
		4 * N as usize / 8 // 4 bits per coefficient, values in [0, 15] (ML-DSA-65/87)
	} else {
		panic!("unsupported GAMMA2 parameter")
	}
}

/// Packed public key size: `pk = (rho, t1)`.
pub const fn publickeybytes(k: usize) -> usize {
	SEEDBYTES + k * POLYT1_PACKEDBYTES
}

/// Packed secret key size: `sk = (rho, key, tr, s1, s2, t0)`.
pub const fn secretkeybytes(k: usize, l: usize, eta: usize) -> usize {
	2 * SEEDBYTES + TR_BYTES + (k + l) * polyeta_packedbytes(eta) + k * POLYT0_PACKEDBYTES
}

/// Packed signature size: `sig = (c_tilde, z, h)`.
pub const fn signbytes(
	k: usize,
	l: usize,
	gamma1: usize,
	omega: usize,
	c_dash_bytes: usize,
) -> usize {
	c_dash_bytes + l * polyz_packedbytes(gamma1) + omega + k
}

/// ML-DSA-44 parameter set (FIPS 204 category 2).
pub mod ml_dsa_44 {
	use super::{polyeta_packedbytes, polyw1_packedbytes, polyz_packedbytes, Q};

	pub const TAU: usize = 39; //number of +-1s in c
	pub const CHALLENGE_ENTROPY: usize = 192;
	pub const GAMMA1: usize = 1 << 17; //y coefficient range
	pub const GAMMA2: usize = (Q as usize - 1) / 88; //low-order rounding range
	pub const K: usize = 4; //rows in A
	pub const L: usize = 4; //columns in A
	pub const ETA: usize = 2;
	pub const BETA: usize = TAU * ETA;
	pub const OMEGA: usize = 80;
	pub const COLLISION_STRENGTH: usize = 128;

	pub const C_DASH_BYTES: usize = (COLLISION_STRENGTH * 2) / 8;
	pub const POLYZ_PACKEDBYTES: usize = polyz_packedbytes(GAMMA1);
	pub const POLYW1_PACKEDBYTES: usize = polyw1_packedbytes(GAMMA2);
	pub const POLYETA_PACKEDBYTES: usize = polyeta_packedbytes(ETA);
	pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
	pub const PUBLICKEYBYTES: usize = super::publickeybytes(K);
	pub const SECRETKEYBYTES: usize = super::secretkeybytes(K, L, ETA);
	pub const SIGNBYTES: usize = super::signbytes(K, L, GAMMA1, OMEGA, C_DASH_BYTES);
}

/// ML-DSA-65 parameter set (FIPS 204 category 3).
pub mod ml_dsa_65 {
	use super::{polyeta_packedbytes, polyw1_packedbytes, polyz_packedbytes, Q};

	pub const TAU: usize = 49; //number of +-1s in c
	pub const CHALLENGE_ENTROPY: usize = 225;
	pub const GAMMA1: usize = 1 << 19; //y coefficient range
	pub const GAMMA2: usize = (Q as usize - 1) / 32; //low-order rounding range
	pub const K: usize = 6; //rows in A
	pub const L: usize = 5; //columns in A
	pub const ETA: usize = 4;
	pub const BETA: usize = TAU * ETA;
	pub const OMEGA: usize = 55;
	pub const COLLISION_STRENGTH: usize = 192;

	pub const C_DASH_BYTES: usize = (COLLISION_STRENGTH * 2) / 8;
	pub const POLYZ_PACKEDBYTES: usize = polyz_packedbytes(GAMMA1);
	pub const POLYW1_PACKEDBYTES: usize = polyw1_packedbytes(GAMMA2);
	pub const POLYETA_PACKEDBYTES: usize = polyeta_packedbytes(ETA);
	pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
	pub const PUBLICKEYBYTES: usize = super::publickeybytes(K);
	pub const SECRETKEYBYTES: usize = super::secretkeybytes(K, L, ETA);
	pub const SIGNBYTES: usize = super::signbytes(K, L, GAMMA1, OMEGA, C_DASH_BYTES);
}

/// ML-DSA-87 parameter set (FIPS 204 category 5).
pub mod ml_dsa_87 {
	use super::{polyeta_packedbytes, polyw1_packedbytes, polyz_packedbytes, Q};

	pub const TAU: usize = 60; //number of +-1s in c
	pub const CHALLENGE_ENTROPY: usize = 257;
	pub const GAMMA1: usize = 1 << 19; //y coefficient range
	pub const GAMMA2: usize = (Q as usize - 1) / 32; //low-order rounding range
	pub const K: usize = 8; //rows in A
	pub const L: usize = 7; //columns in A
	pub const ETA: usize = 2;
	pub const BETA: usize = TAU * ETA;
	pub const OMEGA: usize = 75;
	pub const COLLISION_STRENGTH: usize = 256;

	pub const C_DASH_BYTES: usize = (COLLISION_STRENGTH * 2) / 8;
	pub const POLYZ_PACKEDBYTES: usize = polyz_packedbytes(GAMMA1);
	pub const POLYW1_PACKEDBYTES: usize = polyw1_packedbytes(GAMMA2);
	pub const POLYETA_PACKEDBYTES: usize = polyeta_packedbytes(ETA);
	pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
	pub const PUBLICKEYBYTES: usize = super::publickeybytes(K);
	pub const SECRETKEYBYTES: usize = super::secretkeybytes(K, L, ETA);
	pub const SIGNBYTES: usize = super::signbytes(K, L, GAMMA1, OMEGA, C_DASH_BYTES);
}

// Compatibility re-exports: the crate's existing single-variant surface is
// ML-DSA-87, and every current internal call site and downstream consumer
// refers to these constants via the historical top-level names.
pub use ml_dsa_87::{
	BETA, CHALLENGE_ENTROPY, COLLISION_STRENGTH, C_DASH_BYTES, ETA, GAMMA1, GAMMA2, K, L, OMEGA,
	POLYETA_PACKEDBYTES, POLYVECH_PACKEDBYTES, POLYW1_PACKEDBYTES, POLYZ_PACKEDBYTES,
	PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES, TAU,
};

#[cfg(test)]
mod tests {
	use super::*;

	/// Packed object sizes for each variant, pinned against FIPS 204 Table 2.
	#[test]
	fn fips204_table2_sizes() {
		assert_eq!(ml_dsa_44::PUBLICKEYBYTES, 1312);
		assert_eq!(ml_dsa_44::SECRETKEYBYTES, 2560);
		assert_eq!(ml_dsa_44::SIGNBYTES, 2420);

		assert_eq!(ml_dsa_65::PUBLICKEYBYTES, 1952);
		assert_eq!(ml_dsa_65::SECRETKEYBYTES, 4032);
		assert_eq!(ml_dsa_65::SIGNBYTES, 3309);

		assert_eq!(ml_dsa_87::PUBLICKEYBYTES, 2592);
		assert_eq!(ml_dsa_87::SECRETKEYBYTES, 4896);
		assert_eq!(ml_dsa_87::SIGNBYTES, 4627);
	}

	/// The top-level re-exports must keep exposing the ML-DSA-87 values that
	/// all existing call sites were audited against.
	#[test]
	fn top_level_names_are_ml_dsa_87() {
		assert_eq!(K, 8);
		assert_eq!(L, 7);
		assert_eq!(ETA, 2);
		assert_eq!(TAU, 60);
		assert_eq!(GAMMA1, 1 << 19);
		assert_eq!(GAMMA2, (Q as usize - 1) / 32);
		assert_eq!(OMEGA, 75);
		assert_eq!(C_DASH_BYTES, 64);
		assert_eq!(POLYZ_PACKEDBYTES, 640);
		assert_eq!(POLYW1_PACKEDBYTES, 128);
		assert_eq!(POLYETA_PACKEDBYTES, 96);
		assert_eq!(PUBLICKEYBYTES, 2592);
		assert_eq!(SECRETKEYBYTES, 4896);
		assert_eq!(SIGNBYTES, 4627);
	}
}
