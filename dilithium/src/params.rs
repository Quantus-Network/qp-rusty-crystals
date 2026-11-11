//! ML-DSA parameter sets (FIPS 204, Table 1 and Table 2).
//!
//! Constants shared by every parameter set live at the top level. The
//! variant-specific tables live in the [`ml_dsa_44`], [`ml_dsa_65`] and
//! [`ml_dsa_87`] submodules, each exposing the same constant names so generic
//! code can be instantiated uniformly from any of them.
//!
//! ML-DSA-87's constants are additionally re-exported at the top level under
//! the historical names (`params::K`, `params::GAMMA1`, ...) for the internal
//! call sites and downstream consumers that predate the multi-variant
//! frontends and were audited against those names.

pub const SEEDBYTES: usize = 32;
pub const CRHBYTES: usize = 64;
pub const TR_BYTES: usize = 64;
pub const N: i32 = 256;
pub const Q: i32 = 8380417;
pub const D: i32 = 13;
/// A primitive 2N-th root of unity modulo Q.
pub const R: i32 = 1753;

pub const POLYT1_PACKEDBYTES: usize = 320;
pub const POLYT0_PACKEDBYTES: usize = 416;

// Packed-size helpers, derived from a variant's base parameters. These are
// `const fn` so const-generic code can assert, at compile time, that the
// buffer sizes it was instantiated with are consistent with the ETA / GAMMA1 /
// GAMMA2 values it was given (the assertions are evaluated at
// monomorphization). Each panics on a value not defined by FIPS 204, so an
// unsupported instantiation fails to compile.

/// Signing rejection margin `BETA = TAU · ETA` (FIPS 204). Defined once so
/// the const-generic signing core and the per-variant `BETA` constants share
/// the same formula.
pub const fn beta(tau: usize, eta: usize) -> usize {
	tau * eta
}

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

/// Stamp the constants *derived* from a variant's base parameters (`BETA`,
/// `C_DASH_BYTES`, and the packed object sizes). The base constants above the
/// invocation are per-variant data; these derivation formulas are the FIPS 204
/// size arithmetic and are identical for every parameter set, so they are
/// written once here rather than repeated in each module.
macro_rules! derived_params {
	() => {
		pub const BETA: usize = super::beta(TAU, ETA);
		pub const C_DASH_BYTES: usize = COLLISION_STRENGTH / 4;
		pub const POLYZ_PACKEDBYTES: usize = super::polyz_packedbytes(GAMMA1);
		pub const POLYW1_PACKEDBYTES: usize = super::polyw1_packedbytes(GAMMA2);
		pub const POLYETA_PACKEDBYTES: usize = super::polyeta_packedbytes(ETA);
		pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
		pub const PUBLICKEYBYTES: usize = super::publickeybytes(K);
		pub const SECRETKEYBYTES: usize = super::secretkeybytes(K, L, ETA);
		pub const SIGNBYTES: usize = super::signbytes(K, L, GAMMA1, OMEGA, C_DASH_BYTES);
	};
}

/// ML-DSA-44 parameter set (FIPS 204 category 2).
pub mod ml_dsa_44 {
	use super::Q;

	pub const TAU: usize = 39;
	pub const CHALLENGE_ENTROPY: usize = 192;
	pub const GAMMA1: usize = 1 << 17;
	pub const GAMMA2: usize = (Q as usize - 1) / 88;
	pub const K: usize = 4;
	pub const L: usize = 4;
	pub const ETA: usize = 2;
	pub const OMEGA: usize = 80;
	pub const COLLISION_STRENGTH: usize = 128;

	derived_params!();
}

/// ML-DSA-65 parameter set (FIPS 204 category 3).
pub mod ml_dsa_65 {
	use super::Q;

	pub const TAU: usize = 49;
	pub const CHALLENGE_ENTROPY: usize = 225;
	pub const GAMMA1: usize = 1 << 19;
	pub const GAMMA2: usize = (Q as usize - 1) / 32;
	pub const K: usize = 6;
	pub const L: usize = 5;
	pub const ETA: usize = 4;
	pub const OMEGA: usize = 55;
	pub const COLLISION_STRENGTH: usize = 192;

	derived_params!();
}

/// ML-DSA-87 parameter set (FIPS 204 category 5).
pub mod ml_dsa_87 {
	use super::Q;

	pub const TAU: usize = 60;
	pub const CHALLENGE_ENTROPY: usize = 257;
	pub const GAMMA1: usize = 1 << 19;
	pub const GAMMA2: usize = (Q as usize - 1) / 32;
	pub const K: usize = 8;
	pub const L: usize = 7;
	pub const ETA: usize = 2;
	pub const OMEGA: usize = 75;
	pub const COLLISION_STRENGTH: usize = 256;

	derived_params!();
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

	/// Per-variant parameters, pinned against FIPS 204 Table 1 (rows tau, lambda,
	/// gamma1, gamma2, k, l, eta, beta, omega, challenge entropy).
	#[test]
	fn fips204_table1_parameters() {
		macro_rules! row {
			($v:ident) => {
				[
					$v::TAU,
					$v::COLLISION_STRENGTH,
					$v::GAMMA1,
					$v::GAMMA2,
					$v::K,
					$v::L,
					$v::ETA,
					$v::BETA,
					$v::OMEGA,
					$v::CHALLENGE_ENTROPY,
				]
			};
		}
		assert_eq!(row!(ml_dsa_44), [39, 128, 1 << 17, 95232, 4, 4, 2, 78, 80, 192]);
		assert_eq!(row!(ml_dsa_65), [49, 192, 1 << 19, 261888, 6, 5, 4, 196, 55, 225]);
		assert_eq!(row!(ml_dsa_87), [60, 256, 1 << 19, 261888, 8, 7, 2, 120, 75, 257]);

		assert_eq!([ml_dsa_44::C_DASH_BYTES, ml_dsa_44::POLYVECH_PACKEDBYTES], [32, 84]);
		assert_eq!([ml_dsa_65::C_DASH_BYTES, ml_dsa_65::POLYVECH_PACKEDBYTES], [48, 61]);
		assert_eq!([ml_dsa_87::C_DASH_BYTES, ml_dsa_87::POLYVECH_PACKEDBYTES], [64, 83]);
	}

	/// The ring constants, with `R` checked to be a primitive 2N-th root of
	/// unity (`R^N = -1 mod Q`) and the t1/t0 sizes checked as 10 and 13 bits
	/// per coefficient.
	#[test]
	fn shared_constants() {
		assert_eq!([Q, N, D, R], [8380417, 256, 13, 1753]);
		let r_pow_n = (0..N).fold(1i64, |acc, _| acc * R as i64 % Q as i64);
		assert_eq!(r_pow_n, Q as i64 - 1);

		assert_eq!([SEEDBYTES, CRHBYTES, TR_BYTES], [32, 64, 64]);
		assert_eq!(POLYT1_PACKEDBYTES, 10 * N as usize / 8);
		assert_eq!(POLYT0_PACKEDBYTES, D as usize * N as usize / 8);
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
