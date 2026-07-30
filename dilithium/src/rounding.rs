use crate::params::Q;

/// The two low-order rounding ranges permitted by FIPS 204: `(Q-1)/32`
/// (ML-DSA-65 and ML-DSA-87) and `(Q-1)/88` (ML-DSA-44). The high-bits
/// extraction in [`decompose`] uses fixed-point reciprocal constants that are
/// only exact for these two values, so every generic function below asserts
/// its `GAMMA2` parameter is one of them at compile time.
const GAMMA2_32: usize = (Q as usize - 1) / 32;
const GAMMA2_88: usize = (Q as usize - 1) / 88;

/// Compile-time check that a `GAMMA2` const parameter is one of the two
/// FIPS 204 values. Evaluated at monomorphization; an unsupported
/// instantiation fails to compile.
const fn assert_supported_gamma2(gamma2: usize) {
	assert!(gamma2 == GAMMA2_32 || gamma2 == GAMMA2_88, "unsupported GAMMA2 parameter");
}

/// For finite field element a, compute high and low bits a0, a1 such that a mod^+ Q = a1*2^D + a0
/// with -2^{D-1} < a0 <= 2^{D-1}.
///
/// # Arguments
///
/// * 'a' - input element
///
/// # Preconditions
///
/// `a` must lie in `(-Q, Q)` — the range guaranteed by
/// [`Poly::from_coeffs`](crate::poly::Poly::from_coeffs). A signed
/// representative is canonicalized to its standard representative in `[0, Q)`
/// first (the FIPS formula is defined on `a mod^+ Q`), so `a` and `a + Q`
/// decompose identically; the canonicalization is a no-op for inputs already
/// in `[0, Q)`. Inputs outside `(-Q, Q)` violate the contract and can
/// overflow the `i32` arithmetic below: a panic in overflow-checked builds,
/// silent wraparound (and a corrupt decomposition) otherwise. Checked with
/// `debug_assert!`.
///
/// Returns a touple (a0, a1).
pub fn power2round(a: i32) -> (i32, i32) {
	use crate::params::D;
	debug_assert!(-Q < a && a < Q, "power2round input outside (-Q, Q)");
	// Canonicalize to the standard representative in [0, Q); branchless, so
	// constant-time, and identity for inputs already in [0, Q).
	let a = crate::reduce::caddq(a);
	let a1: i32 = (a + (1 << (D - 1)) - 1) >> D;
	let a0: i32 = a - (a1 << D);
	(a0, a1)
}

/// For finite field element a, compute high and low bits a0, a1 such that a mod^+ Q = a1*ALPHA + a0
/// with -ALPHA/2 < a0 <= ALPHA/2 except if a1 = (Q-1)/ALPHA where we set a1 = 0 and -ALPHA/2 <= a0
/// = a mod^+ Q - Q < 0.
///
/// The high-bits extraction divides by `ALPHA = 2*GAMMA2` with a fixed-point
/// reciprocal that is exact over the whole input domain `[0, Q)`:
/// `(1025, >> 22)` for `GAMMA2 = (Q-1)/32` (16 high values, wrapped with a
/// mask) and `(11275, >> 24)` for `GAMMA2 = (Q-1)/88` (44 high values; 44
/// does not divide a power of two, so the wrap to 0 is a branchless
/// conditional instead of a mask). Both arms are verified exhaustively over
/// `[0, Q)` against the FIPS 204 definition in this module's tests.
///
/// # Arguments
///
/// * 'a' - input element
///
/// # Preconditions
///
/// `a` must lie in `(-Q, Q)` — the range guaranteed by
/// [`Poly::from_coeffs`](crate::poly::Poly::from_coeffs). A signed
/// representative is canonicalized to its standard representative in `[0, Q)`
/// first (the FIPS formula is defined on `a mod^+ Q`), so `a` and `a + Q`
/// decompose identically; the canonicalization is a no-op for inputs already
/// in `[0, Q)`. Inputs outside `(-Q, Q)` violate the contract and can
/// overflow the `i32` arithmetic below (panic in overflow-checked builds,
/// silent wraparound otherwise). Checked with `debug_assert!`.
///
/// Returns a touple (a0, a1).
pub fn decompose<const GAMMA2: usize>(a: i32) -> (i32, i32) {
	const {
		assert_supported_gamma2(GAMMA2);
	}
	debug_assert!(-Q < a && a < Q, "decompose input outside (-Q, Q)");
	// Canonicalize to the standard representative in [0, Q); branchless, so
	// constant-time, and identity for inputs already in [0, Q).
	let a = crate::reduce::caddq(a);
	let gamma2 = GAMMA2 as i32;
	let mut a1: i32 = (a + 127) >> 7;
	if GAMMA2 == GAMMA2_32 {
		a1 = (a1 * 1025 + (1 << 21)) >> 22;
		a1 &= 15;
	} else {
		a1 = (a1 * 11275 + (1 << 23)) >> 24;
		// Branchless wrap of the top high-bits value: a1 == 44 maps to 0.
		// (43 - a1) is negative only for a1 == 44, so the arithmetic-shift
		// mask is all-ones exactly then, and 44 ^ 44 == 0.
		a1 ^= ((43 - a1) >> 31) & a1;
	}
	let mut a0: i32 = a - a1 * 2 * gamma2;
	a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
	(a0, a1)
}

/// Compute hint bit indicating whether the low bits of the input element overflow into the high
/// bits.
///
/// Branchless via sign-bit arithmetic: the inputs are derived from secret data
/// (w0 - c*s2 + c*t0) and this runs on rejected signing attempts whose hints are never
/// published, so a data-dependent branch here could leak.
///
/// # Preconditions
///
/// `a0` and `a1` are a [`decompose`] output (`a0` the centered low part, `a1`
/// the high part). `a0` must satisfy `|a0| < Q`: the branchless comparisons
/// below add/subtract `GAMMA2` to it, so an out-of-domain `a0` near the `i32`
/// extremes overflows (panic in overflow-checked builds, silent wraparound
/// otherwise). This function deliberately does **not** validate at runtime —
/// a data-dependent branch on the secret `a0` would defeat its constant-time
/// purpose — so callers reaching it with peer-controlled integers (e.g. an
/// FFI wrapper) must bound them first. The bound holds automatically for any
/// `a0` produced by [`decompose`].
///
/// Returns 1 if overflow, i.e. if a0 > GAMMA2, or a0 < -GAMMA2, or (a0 == -GAMMA2 && a1 != 0).
pub fn make_hint<const GAMMA2: usize>(a0: i32, a1: i32) -> i32 {
	const {
		assert_supported_gamma2(GAMMA2);
	}
	let gamma2 = GAMMA2 as i32;
	// -1 iff a0 > GAMMA2
	let gt = (gamma2 - a0) >> 31;
	// -1 iff a0 < -GAMMA2; t == 0 iff a0 == -GAMMA2
	let t = a0 + gamma2;
	let lt = t >> 31;
	// -1 iff t == 0 (i.e. a0 == -GAMMA2)
	let eq = !((t | t.wrapping_neg()) >> 31);
	// -1 iff a1 != 0
	let a1_nonzero = (a1 | a1.wrapping_neg()) >> 31;
	(gt | lt | (eq & a1_nonzero)) & 1
}

/// Correct high bits according to hint.
///
/// The corrected value is `(a1 ± 1) mod m` where `m = (Q-1)/(2*GAMMA2)` is the
/// number of distinct high-bits values: 16 for `GAMMA2 = (Q-1)/32` (a mask)
/// and 44 for `GAMMA2 = (Q-1)/88` (explicit wrap-around, as 44 is not a power
/// of two). Runs only on public data (signature verification), so the
/// branches are not a timing concern.
///
/// Returns corrected high bits.
pub fn use_hint<const GAMMA2: usize>(a: i32, hint: i32) -> i32 {
	const {
		assert_supported_gamma2(GAMMA2);
	}
	let (a0, a1) = decompose::<GAMMA2>(a);
	if hint == 0 {
		return a1;
	}
	if GAMMA2 == GAMMA2_32 {
		if a0 > 0 {
			(a1 + 1) & 15
		} else {
			(a1 - 1) & 15
		}
	} else if a0 > 0 {
		if a1 == 43 {
			0
		} else {
			a1 + 1
		}
	} else if a1 == 0 {
		43
	} else {
		a1 - 1
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// FIPS 204 Algorithm 36 (Decompose), computed directly from the
	/// definition: r0 = r mod± (2*GAMMA2); if r - r0 == Q - 1 then r1 = 0 and
	/// r0 = r0 - 1, else r1 = (r - r0) / (2*GAMMA2).
	fn reference_decompose(r: i32, gamma2: i32) -> (i32, i32) {
		let alpha = 2 * gamma2;
		let mut r0 = r % alpha;
		if r0 > alpha / 2 {
			r0 -= alpha;
		}
		if r - r0 == Q - 1 {
			(r0 - 1, 0)
		} else {
			(r0, (r - r0) / alpha)
		}
	}

	/// FIPS 204 Algorithm 40 (UseHint), computed directly from the definition.
	fn reference_use_hint(r: i32, hint: i32, gamma2: i32) -> i32 {
		let m = (Q - 1) / (2 * gamma2);
		let (r0, r1) = reference_decompose(r, gamma2);
		if hint == 0 {
			return r1;
		}
		if r0 > 0 {
			(r1 + 1).rem_euclid(m)
		} else {
			(r1 - 1).rem_euclid(m)
		}
	}

	/// Exhaustively verify one GAMMA2 arm of `decompose` and `use_hint` over
	/// the full input domain [0, Q). The fixed-point reciprocal constants in
	/// `decompose` are correct-by-verification, not by inspection, and the
	/// domain is small enough (~8.4M values) to check every input.
	fn exhaustive_check<const GAMMA2: usize>() {
		let gamma2 = GAMMA2 as i32;
		for a in 0..Q {
			let (a0, a1) = decompose::<GAMMA2>(a);
			let (r0, r1) = reference_decompose(a, gamma2);
			assert_eq!(
				(a0, a1),
				(r0, r1),
				"decompose(GAMMA2={}) diverged from FIPS 204 at a={}",
				GAMMA2,
				a
			);
			// Reconstruction invariant: a == a1*2*GAMMA2 + a0 (mod Q).
			let reconstructed = (a1 as i64 * 2 * gamma2 as i64 + a0 as i64).rem_euclid(Q as i64);
			assert_eq!(reconstructed, a as i64, "reconstruction failed at a={}", a);

			for hint in 0..=1 {
				assert_eq!(
					use_hint::<GAMMA2>(a, hint),
					reference_use_hint(a, hint, gamma2),
					"use_hint(GAMMA2={}) diverged from FIPS 204 at a={}, hint={}",
					GAMMA2,
					a,
					hint
				);
			}
		}
	}

	#[test]
	fn decompose_and_use_hint_exhaustive_gamma2_32() {
		exhaustive_check::<GAMMA2_32>();
	}

	#[test]
	fn decompose_and_use_hint_exhaustive_gamma2_88() {
		exhaustive_check::<GAMMA2_88>();
	}

	/// make_hint must return 1 exactly when the low bits would overflow into
	/// the high bits: a0 > GAMMA2, a0 < -GAMMA2, or (a0 == -GAMMA2 && a1 != 0).
	fn make_hint_check<const GAMMA2: usize>() {
		let gamma2 = GAMMA2 as i32;
		let interesting = [
			-2 * gamma2,
			-gamma2 - 1,
			-gamma2,
			-gamma2 + 1,
			-1,
			0,
			1,
			gamma2 - 1,
			gamma2,
			gamma2 + 1,
			2 * gamma2,
		];
		for &a0 in &interesting {
			for a1 in [0, 1, 15, 43] {
				let expected = (a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0)) as i32;
				assert_eq!(
					make_hint::<GAMMA2>(a0, a1),
					expected,
					"make_hint(GAMMA2={}) wrong at a0={}, a1={}",
					GAMMA2,
					a0,
					a1
				);
			}
		}
	}

	#[test]
	fn make_hint_boundaries_gamma2_32() {
		make_hint_check::<GAMMA2_32>();
	}

	#[test]
	fn make_hint_boundaries_gamma2_88() {
		make_hint_check::<GAMMA2_88>();
	}

	/// Security review: the rounding helpers are defined on the field element
	/// `a mod^+ Q`, so a signed representative and its standard representative
	/// (`a` and `a + Q`) must decompose identically. `Poly::from_coeffs`
	/// admits all of `(-Q, Q)` and the module contract promises that range is
	/// valid for every public routine, but before canonicalization a
	/// negative-but-valid input was fed straight into the FIPS formula and
	/// produced non-canonical bits (e.g. `power2round(-1)` returned `(-1, 0)`
	/// instead of `power2round(Q-1) = (0, 1023)`).
	#[test]
	fn power2round_canonicalizes_signed_representatives() {
		for a in [-1, -2, -1000, -(GAMMA2_32 as i32), -(Q - 1)] {
			assert_eq!(
				power2round(a),
				power2round(a + Q),
				"power2round({a}) must equal power2round({}) (same field element)",
				a + Q
			);
		}
	}

	#[test]
	fn decompose_canonicalizes_signed_representatives() {
		for a in [-1, -2, -1000, -(GAMMA2_32 as i32), -(GAMMA2_88 as i32), -(Q - 1)] {
			assert_eq!(
				decompose::<GAMMA2_32>(a),
				decompose::<GAMMA2_32>(a + Q),
				"decompose::<32>({a}) must equal decompose::<32>({})",
				a + Q
			);
			assert_eq!(
				decompose::<GAMMA2_88>(a),
				decompose::<GAMMA2_88>(a + Q),
				"decompose::<88>({a}) must equal decompose::<88>({})",
				a + Q
			);
		}
	}
}
