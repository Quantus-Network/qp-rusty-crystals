// ML-DSA-87 hyperball tables (v5 coset-splitter calibration).
//
// These are the pre-existing audited/production values; unlike the 44/65
// tables they were not produced by a scripts/compute_hyperball_params.py
// regeneration run (the script's SHIPPED_TABLES mechanism postdates them).

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
pub(super) const RESHARING_KAPPA: &[(u32, u32, f64)] = &[(2, 4, 1.10), (3, 5, 1.15), (4, 6, 1.25)];

/// Every signing-supported `(t, n)` can also be reshared into on ML-DSA-87
/// (κ enlargements ship for all configs whose overshoot exceeds 1).
pub(super) const RESHARING_UNSUPPORTED: &[(u32, u32)] = &[];
