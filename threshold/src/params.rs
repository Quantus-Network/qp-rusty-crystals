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
pub const MAX_RESPONSE_SIZE: usize = MAX_K_ITERATIONS as usize * L * POLYZ_PACKEDBYTES + 800_000;

/// Domain-separation / SSID protocol version (bumped for multi-variant suites).
pub const THRESHOLD_SSID_VERSION: u32 = 3;

/// Look up `k_iterations` for a supported `(t, n)` on this parameter set.
pub fn k_iterations(t: u32, n: u32) -> Option<u32> {
	tables::K_ITERATIONS
		.iter()
		.find(|(tt, nn, _)| *tt == t && *nn == n)
		.map(|(_, _, k)| *k)
}

/// Look up hyperball `(r, r', nu)` for a supported `(t, n)`.
pub fn hyperball_params(t: u32, n: u32) -> Option<(f64, f64, f64)> {
	tables::HYPERBALL
		.iter()
		.find(|(tt, nn, _, _, _)| *tt == t && *nn == n)
		.map(|(_, _, r, rp, nu)| (*r, *rp, *nu))
}

/// Resharing enlargement factor `κ` for `(t, n)` on this parameter set.
///
/// `κ` is the factor by which the Round-5 recovered-partial guard bound `B`
/// *and* the shipped hyperball radii `(r, r')` were jointly enlarged to accept
/// honest reshares whose measured overshoot exceeds the keygen bound (see
/// `resharing::resharing_norm_enlargement` for the full analysis). Configs
/// absent from the table reshare at `κ = 1` (base signing parameters).
///
/// Invariant: any entry here with `κ > 1` must have its `HYPERBALL` and
/// `K_ITERATIONS` entries derived at the *enlarged* radii, so the guard bound
/// and the sampling radii stay consistent.
pub fn resharing_kappa(t: u32, n: u32) -> f64 {
	tables::RESHARING_KAPPA
		.iter()
		.find(|(tt, nn, _)| *tt == t && *nn == n)
		.map(|(_, _, k)| *k)
		.unwrap_or(1.0)
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

	/// Resharing enlargement `(t, n, κ)` for ML-DSA-87.
	///
	/// Measured honest overshoots (v5 coset splitter, fixed point):
	/// (2,4) 0.961×, (3,5) 1.012×, (4,6) 1.163×. The (2,4)/(3,5)/(4,6)
	/// `HYPERBALL` and `K_ITERATIONS` entries above are derived at these
	/// enlarged radii.
	pub(super) const RESHARING_KAPPA: &[(u32, u32, f64)] =
		&[(2, 4, 1.10), (3, 5, 1.15), (4, 6, 1.25)];
}

#[cfg(all(feature = "ml-dsa-65", not(feature = "ml-dsa-87")))]
mod tables {
	include!("params_tables_65.rs");
}

#[cfg(all(feature = "ml-dsa-44", not(feature = "ml-dsa-87"), not(feature = "ml-dsa-65")))]
mod tables {
	include!("params_tables_44.rs");
}

#[cfg(test)]
mod tests {
	/// The generator script duplicates the shipped 44/65 tables in its
	/// `SHIPPED_TABLES` structure (used by `--refine-shipped`). A drifted copy
	/// would let a regeneration silently ship different radii or K than the
	/// crate documents, so pin every `(t, n, r, r', nu, K)` row of the active
	/// table against the script text. (ML-DSA-87's tables predate the script's
	/// shipped-table mechanism and are not duplicated there.)
	#[cfg(not(feature = "ml-dsa-87"))]
	#[test]
	fn generator_script_shipped_tables_match_crate_tables() {
		let script = include_str!("../scripts/compute_hyperball_params.py");
		assert_eq!(super::tables::K_ITERATIONS.len(), super::tables::HYPERBALL.len());
		for ((t, n, k), (t2, n2, r, rp, nu)) in
			super::tables::K_ITERATIONS.iter().zip(super::tables::HYPERBALL.iter())
		{
			assert_eq!((t, n), (t2, n2), "K_ITERATIONS and HYPERBALL row order must match");
			// Matches the row up to and including k_shipped; the trailing
			// kappa field is checked separately (its formatting varies).
			let row = alloc::format!("({t}, {n}, {r:.1}, {rp:.1}, {nu:.1}, {k},");
			assert!(
				script.contains(&row),
				"compute_hyperball_params.py SHIPPED_TABLES is missing or stale for \
				 this row of the shipped Rust table: {row}"
			);
		}
	}

	/// `params_tables_44.rs` intentionally omits a `(4, 6)` resharing
	/// enlargement (κ = 1.25 collapses the per-iteration acceptance under
	/// ML-DSA-44's verification ceilings, so reshares into 4-of-6 fail
	/// closed). The generator script's `RESHARING_DATA[44]["kappa"]` must
	/// agree, or regenerating from the script could reintroduce the
	/// enlargement the crate declares infeasible.
	#[cfg(all(feature = "ml-dsa-44", not(feature = "ml-dsa-87"), not(feature = "ml-dsa-65")))]
	#[test]
	fn generator_script_agrees_on_44_fail_closed_4_of_6() {
		let script = include_str!("../scripts/compute_hyperball_params.py");

		// Slice the kappa dict inside the `44: dict(...)` block so the check
		// cannot accidentally match ML-DSA-87's (legitimate) (4,6) entry.
		let block_start = script.find("44: dict(").expect("RESHARING_DATA 44 block");
		let kappa_rel = script[block_start..].find("kappa={").expect("44 kappa dict");
		let kappa_start = block_start + kappa_rel;
		let kappa_end = kappa_start + script[kappa_start..].find('}').expect("kappa dict close");
		let kappa_dict = &script[kappa_start..kappa_end];

		// Every shipped enlargement must appear in the script...
		for (t, n, k) in super::tables::RESHARING_KAPPA {
			let entry = alloc::format!("({t}, {n}): {k:.2}");
			assert!(
				kappa_dict.contains(&entry),
				"script RESHARING_DATA[44] kappa is missing shipped entry {entry}"
			);
		}
		// ...and the fail-closed (4,6) omission must hold on both sides.
		assert!(
			!kappa_dict.contains("(4, 6)"),
			"script RESHARING_DATA[44] kappa reintroduces the (4,6) enlargement that \
			 params_tables_44.rs declares infeasible (fail-closed)"
		);
		assert_eq!(super::resharing_kappa(4, 6), 1.0, "(4,6) must reshare fail-closed at κ = 1");
	}
}
