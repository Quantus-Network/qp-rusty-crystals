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

/// Bind everything that depends on the active parameter set: the dilithium
/// constants and frontend module, the suite identifier, and the calibrated
/// hyperball tables. This macro is the *single* place the 87 > 65 > 44
/// feature-priority selection is written; everything else in the workspace
/// (the `mldsa` module, benches, integration tests) derives the active
/// variant from these re-exports.
macro_rules! define_active_variant {
	($mod_name:ident, $suite_id:expr, $variant_name:literal, $tables_file:literal) => {
		mod active {
			pub use qp_rusty_crystals_dilithium::params::$mod_name::*;
			/// SSID / resharing suite identifier for this parameter set.
			pub const SUITE_ID: u32 = $suite_id;
			/// Human-readable label for errors and docs.
			pub const VARIANT_NAME: &str = $variant_name;
			/// Reason string for `InvalidParameters` when a `(t, n)` has no
			/// calibrated tables on this parameter set.
			pub const UNSUPPORTED_CONFIG_REASON: &str =
				concat!("unsupported threshold configuration for ", $variant_name);
		}

		/// The dilithium *frontend* module (`Keypair`, `PublicKey`, …) for the
		/// active parameter set.
		pub use qp_rusty_crystals_dilithium::$mod_name as active_frontend;

		mod tables {
			include!($tables_file);
		}
	};
}

#[cfg(feature = "ml-dsa-87")]
define_active_variant!(ml_dsa_87, 1, "ML-DSA-87", "params_tables_87.rs");

#[cfg(all(feature = "ml-dsa-65", not(feature = "ml-dsa-87")))]
define_active_variant!(ml_dsa_65, 3, "ML-DSA-65", "params_tables_65.rs");

#[cfg(all(feature = "ml-dsa-44", not(feature = "ml-dsa-87"), not(feature = "ml-dsa-65")))]
define_active_variant!(ml_dsa_44, 2, "ML-DSA-44", "params_tables_44.rs");

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

/// Round-4 sub-share coefficient sanity bound, derived from the active η.
///
/// See [`subshare_coeff_bound`]. Re-exported at
/// [`crate::resharing::SUBSHARE_COEFF_BOUND`] for the protocol API.
pub const SUBSHARE_COEFF_BOUND: i32 = subshare_coeff_bound(ETA);

/// Derive the Round-4 sub-share coefficient sanity bound from η.
///
/// This is a coarse delivery check (catch Q-scale injections from a malicious
/// dealer), not a calibrated security parameter like κ. Honest worst case is a
/// 4-of-6 reshare (`m = C(6, 3) = 20` RSS subsets):
///
/// ```text
/// max_honest ≈ ⌊post_4σ / m⌋ + (m − 1)·η
/// ```
///
/// where `post_4σ` is the 4σ bound on post-resharing coefficients (~150 at
/// η = 2; ~275 at η = 4 from the √(10/3) keygen-variance ratio). The result is
/// multiplied by a fixed 10× margin so the check stays well above honest
/// traffic on every parameter set while still rejecting Q/2-scale attacks.
///
/// # Panics
///
/// Panics at const-eval time if `eta` is not a FIPS 204 value (2 or 4).
pub const fn subshare_coeff_bound(eta: usize) -> i32 {
	const M: i32 = 20; // C(6, 3) — most RSS subsets among supported committees
	const MARGIN: i32 = 10;
	let post_4sigma: i32 = match eta {
		2 => 150,
		4 => 275,
		_ => panic!("unsupported ETA"),
	};
	let max_honest = post_4sigma / M + (M - 1) * (eta as i32);
	MARGIN * max_honest
}

/// Resharing enlargement factor `κ` for `(t, n)` on this parameter set.
///
/// `κ` is the factor by which the Round-5 recovered-partial guard bound `B`
/// *and* the shipped hyperball radii `(r, r')` were jointly enlarged to accept
/// honest reshares whose measured overshoot exceeds the keygen bound (see
/// `resharing::resharing_norm_enlargement` for the full analysis). Configs
/// absent from the table reshare at `κ = 1` (base signing parameters).
///
/// A missing table row alone does **not** mean the reshare can succeed:
/// configs listed in `RESHARING_UNSUPPORTED` (see [`resharing_supported`])
/// have a measured honest overshoot above 1 with no shipped enlargement, so
/// the base κ = 1 guard is guaranteed to reject them. Callers that admit new
/// committees must check [`resharing_supported`]; this function only supplies
/// the guard factor for configurations already admitted.
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

/// Whether resharing *into* a `(t, n)` committee is supported on this
/// parameter set.
///
/// `(t, n)` combinations valid for signing (present in `K_ITERATIONS`) may
/// still be impossible reshare targets: on ML-DSA-44, `(4, 6)` ships no κ
/// enlargement because its verification ceilings collapse the per-iteration
/// acceptance, so the Round-5 recovered-partial guard rejects honest reshares
/// (measured overshoot 1.166 > κ = 1). Such configs are listed in the
/// per-variant `RESHARING_UNSUPPORTED` table and must be rejected when a
/// resharing session is configured, instead of failing after Rounds 1–5.
///
/// Returns `false` for configurations that are not signing-supported at all;
/// callers are expected to validate signing support separately (via
/// [`k_iterations`] / `ThresholdConfig::new`) for a precise error.
pub fn resharing_supported(t: u32, n: u32) -> bool {
	k_iterations(t, n).is_some() &&
		!tables::RESHARING_UNSUPPORTED.iter().any(|&(tt, nn)| tt == t && nn == n)
}

	#[cfg(test)]
mod tests {
	/// `RESHARING_UNSUPPORTED` marks signing-valid configs that cannot be
	/// reshared into. Each entry must therefore (a) exist in `K_ITERATIONS`
	/// (otherwise it is dead — signing validation already rejects it) and
	/// (b) have no `RESHARING_KAPPA` enlargement (an enlargement would mean
	/// the reshare *is* supported, contradicting the listing).
	#[test]
	fn resharing_unsupported_table_is_consistent() {
		for &(t, n) in super::tables::RESHARING_UNSUPPORTED {
			assert!(
				super::k_iterations(t, n).is_some(),
				"RESHARING_UNSUPPORTED ({t}, {n}) is not a signing-supported config"
			);
			assert!(
				!super::tables::RESHARING_KAPPA.iter().any(|&(tt, nn, _)| tt == t && nn == n),
				"RESHARING_UNSUPPORTED ({t}, {n}) contradicts a RESHARING_KAPPA enlargement"
			);
			assert!(!super::resharing_supported(t, n));
		}
		// Everything not listed reshares (κ ≥ 1, guard accepts honest traffic).
		for &(t, n, _) in super::tables::K_ITERATIONS {
			let listed =
				super::tables::RESHARING_UNSUPPORTED.iter().any(|&(tt, nn)| tt == t && nn == n);
			assert_eq!(super::resharing_supported(t, n), !listed);
		}
	}

	#[test]
	fn subshare_coeff_bound_tracks_eta() {
		// 10 × (⌊150/20⌋ + 19·2) = 10 × 45 = 450
		assert_eq!(super::subshare_coeff_bound(2), 450);
		// 10 × (⌊275/20⌋ + 19·4) = 10 × 89 = 890
		assert_eq!(super::subshare_coeff_bound(4), 890);
		assert_eq!(super::SUBSHARE_COEFF_BOUND, super::subshare_coeff_bound(super::ETA));
	}

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
		assert!(
			!super::resharing_supported(4, 6),
			"(4,6) must be declared an unsupported reshare target on ML-DSA-44"
		);
	}
}
