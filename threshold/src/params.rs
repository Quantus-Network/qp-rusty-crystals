//! Active ML-DSA parameter set for this threshold build.
//!
//! The threshold protocol is compiled for exactly one FIPS 204 parameter set
//! at a time (selected by Cargo feature). All sizes, suite IDs, hyperball
//! tables, and `k_iterations` come from that set so wire layouts cannot be
//! mixed across variants.
//!
//! Enable one of `ml-dsa-44`, `ml-dsa-65`, or `ml-dsa-87` (default). If several
//! are enabled (e.g. workspace `--all-features`), priority is 87 > 65 > 44.

#[cfg(not(any(feature = "ml-dsa-44", feature = "ml-dsa-65", feature = "ml-dsa-87")))]
compile_error!("enable one of: ml-dsa-44, ml-dsa-65, ml-dsa-87");

// Shared ring constants (identical across FIPS 204 parameter sets).
pub use qp_rusty_crystals_dilithium::params::{D, N, Q, SEEDBYTES, TR_BYTES};

#[cfg(feature = "ml-dsa-87")]
mod active {
	pub use qp_rusty_crystals_dilithium::params::ml_dsa_87::*;
	/// SSID / resharing suite identifier for this parameter set.
	pub const SUITE_ID: u32 = 1;
	/// Human-readable label for errors and docs.
	pub const VARIANT_NAME: &str = "ML-DSA-87";
}

#[cfg(all(feature = "ml-dsa-65", not(feature = "ml-dsa-87")))]
mod active {
	pub use qp_rusty_crystals_dilithium::params::ml_dsa_65::*;
	/// SSID / resharing suite identifier for this parameter set.
	pub const SUITE_ID: u32 = 3;
	/// Human-readable label for errors and docs.
	pub const VARIANT_NAME: &str = "ML-DSA-65";
}

#[cfg(all(feature = "ml-dsa-44", not(feature = "ml-dsa-87"), not(feature = "ml-dsa-65")))]
mod active {
	pub use qp_rusty_crystals_dilithium::params::ml_dsa_44::*;
	/// SSID / resharing suite identifier for this parameter set.
	pub const SUITE_ID: u32 = 2;
	/// Human-readable label for errors and docs.
	pub const VARIANT_NAME: &str = "ML-DSA-44";
}

pub use active::*;

/// Packed byte size of one polynomial with 23-bit coefficients (commitment `w`).
pub const POLY_Q_PACKEDBYTES: usize = (N as usize * 23) / 8;

/// Packed size of one Round-1/2 commitment (`K` polynomials of `w`).
pub const SINGLE_COMMITMENT_SIZE: usize = K * POLY_Q_PACKEDBYTES;

/// Worst-case `k_iterations` across supported `(t, n)` on this parameter set.
pub const MAX_K_ITERATIONS: u32 = {
	let mut m = 0u32;
	let mut i = 0usize;
	while i < tables::K_ITERATIONS.len() {
		let k = tables::K_ITERATIONS[i].2;
		if k > m {
			m = k;
		}
		i += 1;
	}
	m
};

/// Upper bound on Round 2 commitment payload size (with margin).
pub const MAX_COMMITMENT_DATA_SIZE: usize =
	MAX_K_ITERATIONS as usize * SINGLE_COMMITMENT_SIZE + 600_000;

/// Upper bound on Round 3 response payload size (with margin).
pub const MAX_RESPONSE_SIZE: usize =
	MAX_K_ITERATIONS as usize * L * POLYZ_PACKEDBYTES + 800_000;

/// Domain-separation / SSID protocol version (bumped for multi-variant suites).
pub const THRESHOLD_SSID_VERSION: u32 = 3;

/// Look up `k_iterations` for a supported `(t, n)` on this parameter set.
pub fn k_iterations(t: u32, n: u32) -> Option<u32> {
	tables::K_ITERATIONS.iter().find(|(tt, nn, _)| *tt == t && *nn == n).map(|(_, _, k)| *k)
}

/// Look up hyperball `(r, r', nu)` for a supported `(t, n)`.
pub fn hyperball_params(t: u32, n: u32) -> Option<(f64, f64, f64)> {
	tables::HYPERBALL
		.iter()
		.find(|(tt, nn, _, _, _)| *tt == t && *nn == n)
		.map(|(_, _, r, rp, nu)| (*r, *rp, *nu))
}

#[cfg(feature = "ml-dsa-87")]
mod tables {
	/// Shipped `(t, n, k_iterations)` for ML-DSA-87 (v5 coset-splitter calibration).
	pub(super) const K_ITERATIONS: &[(u32, u32, u32)] = &[
		(2, 2, 4),
		(2, 3, 5),
		(3, 3, 12),
		(2, 4, 10),
		(3, 4, 24),
		(4, 4, 25),
		(2, 5, 6),
		(3, 5, 60),
		(4, 5, 110),
		(5, 5, 60),
		(2, 6, 8),
		(3, 6, 65),
		(4, 6, 1600),
		(5, 6, 380),
		(6, 6, 180),
	];

	/// Shipped `(t, n, r, r', nu)` for ML-DSA-87.
	pub(super) const HYPERBALL: &[(u32, u32, f64, f64, f64)] = &[
		(2, 2, 503119.0, 503192.0, 7.0),
		(2, 3, 631601.0, 631703.0, 7.0),
		(3, 3, 483107.0, 483180.0, 7.0),
		(2, 4, 696194.0, 696307.0, 7.0),
		(3, 4, 551752.0, 551854.0, 7.0),
		(4, 4, 487958.0, 488031.0, 7.0),
		(2, 5, 607694.0, 607820.0, 7.0),
		(3, 5, 664010.0, 664178.0, 7.0),
		(4, 5, 518384.0, 518510.0, 7.0),
		(5, 5, 468214.0, 468287.0, 7.0),
		(2, 6, 665106.0, 665232.0, 7.0),
		(3, 6, 577541.0, 577704.0, 7.0),
		(4, 6, 647112.0, 647317.0, 7.0),
		(5, 6, 479692.0, 479819.0, 7.0),
		(6, 6, 424124.0, 424197.0, 7.0),
	];
}

#[cfg(all(feature = "ml-dsa-65", not(feature = "ml-dsa-87")))]
mod tables {
	include!("params_tables_65.rs");
}

#[cfg(all(feature = "ml-dsa-44", not(feature = "ml-dsa-87"), not(feature = "ml-dsa-65")))]
mod tables {
	include!("params_tables_44.rs");
}
