use crate::{params, poly, poly::Poly};
use core::array;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Unstable accessors for the crate-internal secret samplers, used only by the
/// in-crate constant-time harness (`examples/ct_bench.rs`).
///
/// The samplers themselves stay `pub(crate)`; these are thin pass-through
/// wrappers gated behind the off-by-default `ct-internals` feature, so they do
/// not appear in the public API of a normal build. Not covered by semver; do not
/// depend on this module outside the crate's own timing tests.
#[cfg(feature = "ct-internals")]
pub mod ct_internals {
	use super::Polyvec;
	use crate::params;

	/// Pass-through for [`super::uniform_eta`].
	///
	/// Parameterized so the constant-time harness can time both FIPS 204
	/// secret-sampling paths (`ETA = 2` for ML-DSA-44/87, `ETA = 4` for
	/// ML-DSA-65) rather than only the historical ML-DSA-87 monomorphization.
	/// `ETA` must be 2 or 4 (enforced by the callee at monomorphization).
	pub fn uniform_eta<const N: usize, const ETA: usize>(
		v: &mut Polyvec<N>,
		seed: &[u8; params::CRHBYTES],
		base_nonce: u16,
	) {
		super::uniform_eta::<N, ETA>(v, seed, base_nonce);
	}

	/// Pass-through for [`super::uniform_gamma1`].
	pub fn uniform_gamma1<const N: usize, const GAMMA1: usize, const PZ: usize>(
		v: &mut Polyvec<N>,
		seed: &[u8; params::CRHBYTES],
		nonce: u16,
	) {
		super::uniform_gamma1::<N, GAMMA1, PZ>(v, seed, nonce);
	}
}

/// A vector of `N` polynomials.
///
/// `N` is a compile-time parameter so the same audited code serves every
/// ML-DSA parameter set: the two shapes used by the scheme are `Polyvec<K>`
/// (rows of `A`, e.g. `t`, `w`, `s2`) and `Polyvec<L>` (columns of `A`, e.g.
/// `s1`, `y`, `z`). Monomorphization gives each instantiation the same code
/// shape regardless of parameter set.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Polyvec<const N: usize> {
	pub vec: [Poly; N],
}

impl<const N: usize> Default for Polyvec<N> {
	fn default() -> Self {
		Polyvec { vec: array::from_fn(|_| Poly::default()) }
	}
}

/// Implementation of ExpandA. Generates matrix A with uniformly random coefficients a_{i,j} by
/// performing rejection sampling on the output stream of SHAKE128(rho|j|i).
pub fn matrix_expand<const K: usize, const L: usize>(
	mat: &mut [Polyvec<L>; K],
	rho: &[u8; params::SEEDBYTES],
) {
	for (i, mat_i) in mat.iter_mut().enumerate() {
		for j in 0..L {
			poly::uniform(&mut mat_i.vec[j], rho, ((i << 8) + j) as u16);
		}
	}
}

/// Pointwise multiply vectors of polynomials of length N, multiply resulting vector by 2^{-32} and
/// add (accumulate) polynomials in it. Input/output vectors are in NTT domain representation. Input
/// coefficients are assumed to be less than 22*Q. Output coeffcient are less than 2*N*Q.
pub fn pointwise_acc_montgomery<const N: usize>(w: &mut Poly, u: &Polyvec<N>, v: &Polyvec<N>) {
	poly::pointwise_montgomery(w, &u.vec[0], &v.vec[0]);
	let mut t = Poly::default();
	for i in 1..N {
		poly::pointwise_montgomery(&mut t, &u.vec[i], &v.vec[i]);
		poly::add_ip(w, &t);
	}
}

pub fn matrix_pointwise_montgomery<const K: usize, const L: usize>(
	t: &mut Polyvec<K>,
	mat: &[Polyvec<L>; K],
	v: &Polyvec<L>,
) {
	for (i, t_i) in t.vec.iter_mut().enumerate() {
		pointwise_acc_montgomery(t_i, &mat[i], v);
	}
}

/// Streaming equivalent of `matrix_expand` followed by `matrix_pointwise_montgomery`.
///
/// Computes `t = A * v` (NTT domain) while generating each element `A[i][j]` of ExpandA on the
/// fly from `rho`, so the full matrix (K*L polynomials, ~56 KB for ML-DSA-87) is never
/// materialized. Peak extra working memory is two polynomials (~2 KB). The arithmetic and the
/// accumulation order are identical to the non-streaming path, so the result is bit-for-bit the
/// same; only peak stack usage differs.
pub fn matrix_pointwise_montgomery_streamed<const K: usize, const L: usize>(
	t: &mut Polyvec<K>,
	rho: &[u8; params::SEEDBYTES],
	v: &Polyvec<L>,
) {
	let mut a_ij = Poly::default();
	let mut prod = Poly::default();
	for (i, t_i) in t.vec.iter_mut().enumerate() {
		poly::uniform(&mut a_ij, rho, (i << 8) as u16);
		poly::pointwise_montgomery(t_i, &a_ij, &v.vec[0]);
		for j in 1..L {
			poly::uniform(&mut a_ij, rho, ((i << 8) + j) as u16);
			poly::pointwise_montgomery(&mut prod, &a_ij, &v.vec[j]);
			poly::add_ip(t_i, &prod);
		}
	}
}

/// Sample an N-vector of eta-bounded polynomials, one per SHAKE stream nonce
/// `base_nonce + i` for `i in 0..N`.
///
/// Crate-internal: only the low two nonce bytes are absorbed into the SHAKE
/// stream, so callers must keep `base_nonce + (N - 1) <= u16::MAX` to avoid
/// aliasing distinct sampler invocations onto the same stream. The in-crate
/// callers (keygen, using constant nonces) satisfy this by construction; the
/// helper is deliberately not part of the public API so external callers cannot
/// supply an out-of-range nonce.
pub(crate) fn uniform_eta<const N: usize, const ETA: usize>(
	v: &mut Polyvec<N>,
	seed: &[u8; params::CRHBYTES],
	base_nonce: u16,
) {
	for i in 0..N {
		poly::uniform_eta::<ETA>(&mut v.vec[i], seed, base_nonce + i as u16);
	}
}

/// Sample an N-vector of gamma1 mask polynomials, one per SHAKE stream nonce
/// `N * nonce + i` for `i in 0..N`.
///
/// Crate-internal: only the low two nonce bytes are absorbed into the SHAKE
/// stream, so `nonce` must satisfy `N * nonce + (N - 1) <= u16::MAX` — otherwise
/// distinct mask samples alias onto the same stream, reusing a mask `y` across
/// signing attempts (which leaks the secret via `z = y + c*s1`). The sole
/// in-crate caller (the signer) enforces this with its `MAX_SAFE_ATTEMPT_NONCE`
/// check before calling, and the helper is not exported, so an external caller
/// cannot reach it with an unchecked nonce.
pub(crate) fn uniform_gamma1<const N: usize, const GAMMA1: usize, const PZ: usize>(
	v: &mut Polyvec<N>,
	seed: &[u8; params::CRHBYTES],
	nonce: u16,
) {
	for i in 0..N {
		poly::uniform_gamma1::<GAMMA1, PZ>(&mut v.vec[i], seed, N as u16 * nonce + i as u16);
	}
}

/// Reduce coefficients of polynomials in vector of length N
/// to representatives in [-6283008, 6283008].
pub fn reduce<const N: usize>(v: &mut Polyvec<N>) {
	for i in 0..N {
		poly::reduce(&mut v.vec[i]);
	}
}

/// For all coefficients of polynomials in vector of length N
/// add Q if coefficient is negative.
pub fn caddq<const N: usize>(v: &mut Polyvec<N>) {
	for i in 0..N {
		poly::caddq(&mut v.vec[i]);
	}
}

/// Add vectors of polynomials of length N.
/// No modular reduction is performed.
pub fn add<const N: usize>(w: &mut Polyvec<N>, v: &Polyvec<N>) {
	for i in 0..N {
		poly::add_ip(&mut w.vec[i], &v.vec[i]);
	}
}

/// Subtract vectors of polynomials of length N.
/// Assumes coefficients of polynomials in second input vector
/// to be less than 2*Q. No modular reduction is performed.
pub fn sub<const N: usize>(w: &mut Polyvec<N>, v: &Polyvec<N>) {
	for i in 0..N {
		poly::sub_ip(&mut w.vec[i], &v.vec[i]);
	}
}

/// Multiply vector of polynomials of length N by 2^D without modular
/// reduction. Input coefficients must be less than 2^{31-D} in absolute
/// value — narrower than the `(-Q, Q)` range accepted by
/// [`Poly::from_coeffs`](crate::poly::Poly::from_coeffs) — so this routine
/// is `pub(crate)`; see [`poly::shiftl`].
pub(crate) fn shiftl<const N: usize>(v: &mut Polyvec<N>) {
	for i in 0..N {
		poly::shiftl(&mut v.vec[i]);
	}
}

/// Forward NTT of all polynomials in vector of length N. Output coefficients can be up to 16*Q
/// larger than input coefficients.
pub fn ntt<const N: usize>(v: &mut Polyvec<N>) {
	for i in 0..N {
		poly::ntt(&mut v.vec[i]);
	}
}

/// Inverse NTT and multiplication by 2^{32} of polynomials
/// in vector of length N.
///
/// # Preconditions
///
/// Input coefficients must be less than Q in absolute value — the same
/// contract as the per-polynomial [`poly::invntt_tomont`] this delegates to
/// (this doc previously promised `< 2*Q`, which can overflow the inverse
/// butterflies; security review). Checked there with `debug_assert!`.
/// Forward-NTT output (which can reach 8*Q) must be brought back into range
/// with [`reduce`] before being passed here.
pub fn invntt_tomont<const N: usize>(v: &mut Polyvec<N>) {
	for i in 0..N {
		poly::invntt_tomont(&mut v.vec[i]);
	}
}

pub fn pointwise_poly_montgomery<const N: usize>(r: &mut Polyvec<N>, a: &Poly, v: &Polyvec<N>) {
	for i in 0..N {
		poly::pointwise_montgomery(&mut r.vec[i], a, &v.vec[i]);
	}
}

/// Check if the infinity norm of a Polyvec is within the given bound.
///
/// # Arguments
/// * `v` - The polynomial vector to check
/// * `bound` - The norm bound
///
/// Returns true if all polynomials in the vector have infinity norm < bound, false otherwise.
pub fn is_norm_within_bound<const N: usize>(v: &Polyvec<N>, bound: i32) -> bool {
	let mut result = true;
	for i in 0..N {
		let norm_check = poly::check_norm(&v.vec[i], bound);
		result = result && !norm_check;
	}
	result
}

/// Reject public keys whose `t1` fails to bind the verification challenge.
///
/// The verification relation contains the term `c * 2^D * t1`. Its contribution
/// is `HighBits(c * 2^D * t1)`, and `HighBits(x) = 0` for every coefficient whose
/// centered representative `r_j = (2^D * t1_j) mod± q` satisfies `|r_j| <= GAMMA2`.
/// If (nearly) every coefficient stays inside that window the challenge drops out
/// of the relation and a signature can be forged with no secret key (`z = 0`,
/// empty hint, `c = H(mu || w1Encode(0))`) — see the `verify_var` guard and the
/// `test_forged_signature_with_nonzero_degenerate_t1_is_rejected` regression. The
/// all-zero check that previously guarded this is a strict subset of this family
/// (`2^D * v <= GAMMA2` for small `v`, plus the wrap-around near `v = 1023` where
/// `2^D * 1023 ≡ -1`), so it let non-zero degenerate keys through.
///
/// Honest key generation draws `t1` uniformly on `[0, 1024)^{K*N}`, so each
/// coefficient has `|r_j| > GAMMA2` with probability `15/16` (ML-DSA-87/65) or
/// `~0.977` (ML-DSA-44). Requiring at least `K * N / 4` coefficients above the
/// window rejects the whole degenerate family while its false-positive rate on
/// honest keys is `2^{-Ω(K*N)}` (mean count of large coefficients is `>= 1000`
/// for every parameter set, versus a threshold of `K * N / 4`).
pub fn t1_is_degenerate<const K: usize, const GAMMA2: usize>(t1: &Polyvec<K>) -> bool {
	const HALF_Q: i64 = (params::Q as i64) / 2;
	let mut large = 0usize;
	for p in t1.vec.iter() {
		for &coeff in p.coeffs.iter() {
			// `t1` coefficients are 10-bit unsigned ([0, 1024)); scaling by `2^D`
			// stays below `q`, so the only reduction needed is centering.
			let scaled = (coeff as i64) << (params::D as u32);
			let centered = if scaled > HALF_Q { scaled - params::Q as i64 } else { scaled };
			if centered.unsigned_abs() > GAMMA2 as u64 {
				large += 1;
			}
		}
	}
	large < (K * params::N as usize) / 4
}

/// For all coefficients a of polynomials in vector of length N, compute a0, a1 such that a mod Q =
/// a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be standard representatives.
pub fn power2round<const N: usize>(v1: &mut Polyvec<N>, v0: &mut Polyvec<N>) {
	for i in 0..N {
		poly::power2round(&mut v1.vec[i], &mut v0.vec[i]);
	}
}

pub fn decompose<const N: usize, const GAMMA2: usize>(v1: &mut Polyvec<N>, v0: &mut Polyvec<N>) {
	for i in 0..N {
		poly::decompose::<GAMMA2>(&mut v1.vec[i], &mut v0.vec[i]);
	}
}

pub fn make_hint<const N: usize, const GAMMA2: usize>(
	h: &mut Polyvec<N>,
	v0: &Polyvec<N>,
	v1: &Polyvec<N>,
) -> i32 {
	let mut s: i32 = 0;
	for i in 0..N {
		s += poly::make_hint::<GAMMA2>(&mut h.vec[i], &v0.vec[i], &v1.vec[i]);
	}
	s
}

pub fn use_hint<const N: usize, const GAMMA2: usize>(a: &mut Polyvec<N>, hint: &Polyvec<N>) {
	for i in 0..N {
		poly::use_hint::<GAMMA2>(&mut a.vec[i], &hint.vec[i]);
	}
}

/// Pack polynomial vector w1 into byte array.
///
/// The output is an exact-size array (`N` polynomials at the packed-w1 size
/// for `GAMMA2`, enforced by a compile-time assertion) so a too-short
/// destination buffer is rejected at compile time rather than panicking on an
/// out-of-bounds write.
pub fn pack_w1<const N: usize, const GAMMA2: usize, const W1BYTES: usize>(
	r: &mut [u8; W1BYTES],
	a: &Polyvec<N>,
) {
	const {
		assert!(W1BYTES == N * params::polyw1_packedbytes(GAMMA2));
	}
	let stride = params::polyw1_packedbytes(GAMMA2);
	for i in 0..N {
		poly::w1_pack::<GAMMA2>(&mut r[i * stride..], &a.vec[i]);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	const K: usize = params::K;
	const L: usize = params::L;
	const N: usize = params::N as usize;

	#[test]
	fn test_polyvecl_default() {
		let polyvecl = Polyvec::<L>::default();
		for i in 0..L {
			for j in 0..N {
				assert_eq!(polyvecl.vec[i].coeffs[j], 0);
			}
		}
	}

	#[test]
	fn test_polyveck_default() {
		let polyveck = Polyvec::<K>::default();
		for i in 0..K {
			for j in 0..N {
				assert_eq!(polyveck.vec[i].coeffs[j], 0);
			}
		}
	}

	#[test]
	fn test_l_uniform_eta_produces_valid_coefficients() {
		let seed = [0x42u8; params::CRHBYTES];
		let nonce = 1234;
		let mut polyvecl = Polyvec::<L>::default();

		uniform_eta::<L, { params::ETA }>(&mut polyvecl, &seed, nonce);

		// All coefficients should be in the range [-ETA, ETA]
		for i in 0..L {
			for j in 0..N {
				assert!(polyvecl.vec[i].coeffs[j] >= -(params::ETA as i32));
				assert!(polyvecl.vec[i].coeffs[j] <= params::ETA as i32);
			}
		}
	}

	#[test]
	fn test_k_uniform_eta_produces_valid_coefficients() {
		let seed = [0x77u8; params::CRHBYTES];
		let nonce = 5678;
		let mut polyveck = Polyvec::<K>::default();

		uniform_eta::<K, { params::ETA }>(&mut polyveck, &seed, nonce);

		// All coefficients should be in the range [-ETA, ETA]
		for i in 0..K {
			for j in 0..N {
				assert!(polyveck.vec[i].coeffs[j] >= -(params::ETA as i32));
				assert!(polyveck.vec[i].coeffs[j] <= params::ETA as i32);
			}
		}
	}

	#[test]
	fn test_l_uniform_gamma1_produces_valid_coefficients() {
		let seed = [0x55u8; params::CRHBYTES];
		let nonce = 100; // Use smaller nonce to prevent overflow in L * nonce
		let mut polyvecl = Polyvec::<L>::default();

		uniform_gamma1::<L, { params::GAMMA1 }, { params::POLYZ_PACKEDBYTES }>(
			&mut polyvecl,
			&seed,
			nonce,
		);

		// All coefficients should be in the range [-GAMMA1, GAMMA1]
		for i in 0..L {
			for j in 0..N {
				let coeff = polyvecl.vec[i].coeffs[j];
				assert!(
					coeff >= -(params::GAMMA1 as i32) && coeff <= params::GAMMA1 as i32,
					"Coefficient {} at [{},{}] is out of range",
					coeff,
					i,
					j
				);
			}
		}
	}

	// The samplers are `pub(crate)`: external callers cannot reach them, so the
	// only nonces they ever see come from in-crate callers that keep them in the
	// valid u16 range (keygen uses constants; the signer checks
	// `MAX_SAFE_ATTEMPT_NONCE` before expanding the mask). This test confirms the
	// largest in-range nonces still sample correctly.
	#[test]
	fn samplers_accept_maximum_in_range_nonce() {
		let seed = [0x13u8; params::CRHBYTES];

		let mut vl = Polyvec::<L>::default();
		uniform_eta::<L, { params::ETA }>(&mut vl, &seed, u16::MAX - (L as u16 - 1));

		let mut vk = Polyvec::<K>::default();
		uniform_eta::<K, { params::ETA }>(&mut vk, &seed, u16::MAX - (K as u16 - 1));

		// Largest `nonce` with L * nonce + (L - 1) <= u16::MAX.
		let max_gamma1_nonce = (u16::MAX - (L as u16 - 1)) / L as u16;
		let mut vg = Polyvec::<L>::default();
		uniform_gamma1::<L, { params::GAMMA1 }, { params::POLYZ_PACKEDBYTES }>(
			&mut vg,
			&seed,
			max_gamma1_nonce,
		);
	}

	// The generic operations must be shape-agnostic: the same code instantiated
	// at a vector length used by no current variant still behaves correctly.
	#[test]
	fn generic_polyvec_operations_at_arbitrary_length() {
		let mut a = Polyvec::<3>::default();
		let mut b = Polyvec::<3>::default();
		for i in 0..3 {
			for j in 0..N {
				a.vec[i].coeffs[j] = (i * 100 + j) as i32;
				b.vec[i].coeffs[j] = (i * 7 + 2 * j) as i32;
			}
		}
		let original_a = a.clone();
		add(&mut a, &b);
		for i in 0..3 {
			for j in 0..N {
				assert_eq!(a.vec[i].coeffs[j], original_a.vec[i].coeffs[j] + b.vec[i].coeffs[j]);
			}
		}
		assert!(is_norm_within_bound(&Polyvec::<3>::default(), 1));
	}

	#[test]
	fn test_l_add() {
		let mut a = Polyvec::<L>::default();
		let mut b = Polyvec::<L>::default();

		// Initialize with test data
		for i in 0..L {
			for j in 0..N {
				a.vec[i].coeffs[j] = (i * 100 + j) as i32;
				b.vec[i].coeffs[j] = (i * 200 + j * 2) as i32;
			}
		}

		let original_a = a.clone();
		add(&mut a, &b);

		// Check addition was performed correctly
		for i in 0..L {
			for j in 0..N {
				assert_eq!(
					a.vec[i].coeffs[j],
					original_a.vec[i].coeffs[j] + b.vec[i].coeffs[j],
					"Addition failed at [{},{}]",
					i,
					j
				);
			}
		}
	}

	#[test]
	fn test_k_add() {
		let mut a = Polyvec::<K>::default();
		let mut b = Polyvec::<K>::default();

		// Initialize with test data
		for i in 0..K {
			for j in 0..N {
				a.vec[i].coeffs[j] = (i * 50 + j) as i32;
				b.vec[i].coeffs[j] = (i * 75 + j * 3) as i32;
			}
		}

		let original_a = a.clone();
		add(&mut a, &b);

		// Check addition was performed correctly
		for i in 0..K {
			for j in 0..N {
				assert_eq!(
					a.vec[i].coeffs[j],
					original_a.vec[i].coeffs[j] + b.vec[i].coeffs[j],
					"Addition failed at [{},{}]",
					i,
					j
				);
			}
		}
	}

	#[test]
	fn test_k_sub() {
		let mut a = Polyvec::<K>::default();
		let mut b = Polyvec::<K>::default();

		// Initialize with test data
		for i in 0..K {
			for j in 0..N {
				a.vec[i].coeffs[j] = (i * 1000 + j * 10) as i32;
				b.vec[i].coeffs[j] = (i * 100 + j) as i32;
			}
		}

		let original_a = a.clone();
		sub(&mut a, &b);

		// Check subtraction was performed correctly
		for i in 0..K {
			for j in 0..N {
				assert_eq!(
					a.vec[i].coeffs[j],
					original_a.vec[i].coeffs[j] - b.vec[i].coeffs[j],
					"Subtraction failed at [{},{}]",
					i,
					j
				);
			}
		}
	}

	/// The wrapper's documented contract must match the per-polynomial
	/// implementation it delegates to: coefficients below Q in absolute
	/// value. The doc previously promised `< 2*Q` (security review); a
	/// coefficient in `[Q, 2*Q)` — permitted by that stale contract — must
	/// fail loudly wherever debug assertions are on rather than silently
	/// overflowing the inverse butterflies in release builds.
	#[test]
	#[cfg(debug_assertions)]
	#[should_panic(expected = "invntt_tomont precondition violated")]
	fn invntt_tomont_rejects_coefficients_between_q_and_2q() {
		let mut v = Polyvec::<L>::default();
		v.vec[0].coeffs[0] = params::Q; // in [Q, 2*Q): allowed by the old doc
		invntt_tomont(&mut v);
	}

	#[test]
	fn test_l_ntt_invntt_roundtrip() {
		let mut polyvecl = Polyvec::<L>::default();

		// Initialize with test data
		for i in 0..L {
			for j in 0..N {
				polyvecl.vec[i].coeffs[j] = ((i * j + 123) % 1000) as i32;
			}
		}

		let original = polyvecl.clone();
		ntt(&mut polyvecl);
		// Forward-NTT output can reach 8*Q; the inverse transform requires
		// coefficients below Q in absolute value.
		reduce(&mut polyvecl);
		invntt_tomont(&mut polyvecl);

		// After NTT and inverse NTT, values should be close to original
		for i in 0..L {
			for j in 0..N {
				let diff = (polyvecl.vec[i].coeffs[j] - original.vec[i].coeffs[j]).abs();
				assert!(
					diff < params::Q,
					"NTT roundtrip failed at [{},{}]: {} vs {}",
					i,
					j,
					polyvecl.vec[i].coeffs[j],
					original.vec[i].coeffs[j]
				);
			}
		}
	}

	#[test]
	fn test_k_ntt_invntt_roundtrip() {
		let mut polyveck = Polyvec::<K>::default();

		// Initialize with test data
		for i in 0..K {
			for j in 0..N {
				polyveck.vec[i].coeffs[j] = ((i * j * 2 + 456) % 800) as i32;
			}
		}

		let original = polyveck.clone();
		ntt(&mut polyveck);
		// Forward-NTT output can reach 8*Q; the inverse transform requires
		// coefficients below Q in absolute value.
		reduce(&mut polyveck);
		invntt_tomont(&mut polyveck);

		// After NTT and inverse NTT, values should be close to original
		for i in 0..K {
			for j in 0..N {
				let diff = (polyveck.vec[i].coeffs[j] - original.vec[i].coeffs[j]).abs();
				assert!(
					diff < params::Q,
					"NTT roundtrip failed at [{},{}]: {} vs {}",
					i,
					j,
					polyveck.vec[i].coeffs[j],
					original.vec[i].coeffs[j]
				);
			}
		}
	}

	#[test]
	fn test_l_chknorm_zero_vector() {
		let polyvecl = Polyvec::<L>::default(); // All coefficients are 0
		assert!(is_norm_within_bound(&polyvecl, 1)); // Should be within any positive bound
		assert!(is_norm_within_bound(&polyvecl, 1000));
	}

	#[test]
	fn test_l_chknorm_exceeds_bound() {
		let mut polyvecl = Polyvec::<L>::default();
		polyvecl.vec[0].coeffs[0] = 100;
		polyvecl.vec[1].coeffs[10] = -150;

		assert!(is_norm_within_bound(&polyvecl, 200)); // Within bound
		assert!(!is_norm_within_bound(&polyvecl, 149)); // Exceeds bound
		assert!(!is_norm_within_bound(&polyvecl, 99)); // Exceeds bound
	}

	#[test]
	fn test_k_chknorm_zero_vector() {
		let polyveck = Polyvec::<K>::default(); // All coefficients are 0
		assert!(is_norm_within_bound(&polyveck, 1)); // Should be within any positive bound
		assert!(is_norm_within_bound(&polyveck, 1000));
	}

	#[test]
	fn test_k_chknorm_exceeds_bound() {
		let mut polyveck = Polyvec::<K>::default();
		polyveck.vec[0].coeffs[5] = 200;
		polyveck.vec[2].coeffs[15] = -250;

		assert!(is_norm_within_bound(&polyveck, 300)); // Within bound
		assert!(!is_norm_within_bound(&polyveck, 249)); // Exceeds bound
		assert!(!is_norm_within_bound(&polyveck, 199)); // Exceeds bound
	}

	#[test]
	fn test_k_shiftl() {
		let mut polyveck = Polyvec::<K>::default();

		// Initialize with small test values
		for i in 0..K {
			for j in 0..N {
				polyveck.vec[i].coeffs[j] = (j % 10) as i32;
			}
		}

		let original = polyveck.clone();
		shiftl(&mut polyveck);

		// Check that all coefficients were left-shifted by D
		for i in 0..K {
			for j in 0..N {
				assert_eq!(
					polyveck.vec[i].coeffs[j],
					original.vec[i].coeffs[j] << params::D,
					"Left shift failed at [{},{}]",
					i,
					j
				);
			}
		}
	}

	#[test]
	fn test_matrix_expand_produces_different_matrices() {
		let rho1 = [0x42u8; params::SEEDBYTES];
		let rho2 = [0x43u8; params::SEEDBYTES];

		let mut mat1: [Polyvec<L>; K] = array::from_fn(|_| Polyvec::<L>::default());
		let mut mat2: [Polyvec<L>; K] = array::from_fn(|_| Polyvec::<L>::default());

		matrix_expand(&mut mat1, &rho1);
		matrix_expand(&mut mat2, &rho2);

		// Different rho values should produce different matrices
		let mut matrices_different = false;
		'outer: for i in 0..K {
			for j in 0..L {
				for k in 0..N {
					if mat1[i].vec[j].coeffs[k] != mat2[i].vec[j].coeffs[k] {
						matrices_different = true;
						break 'outer;
					}
				}
			}
		}
		assert!(matrices_different, "Different rho should produce different matrices");
	}

	#[test]
	fn test_matrix_pointwise_montgomery() {
		let mut mat: [Polyvec<L>; K] = array::from_fn(|_| Polyvec::<L>::default());
		let mut v = Polyvec::<L>::default();
		let mut result = Polyvec::<K>::default();

		// Initialize matrix and vector with very small test values to avoid overflow
		for i in 0..K {
			for j in 0..L {
				for k in 0..N {
					mat[i].vec[j].coeffs[k] = ((i + j + k) % 10) as i32;
				}
			}
		}

		for i in 0..L {
			for j in 0..N {
				v.vec[i].coeffs[j] = ((i + j) % 5) as i32;
			}
		}

		matrix_pointwise_montgomery(&mut result, &mat, &v);

		// Result should be well-defined (we can't predict exact values due to Montgomery
		// arithmetic) Just check that the function completes without panicking and produces
		// reasonable values
		for i in 0..K {
			for j in 0..N {
				let coeff = result.vec[i].coeffs[j];
				// Allow for a broader range due to Montgomery arithmetic and potential reduction
				assert!(
					coeff.abs() < params::Q * 2,
					"Coefficient {} at [{},{}] is unreasonably large",
					coeff,
					i,
					j
				);
			}
		}
	}

	#[test]
	fn test_k_make_hint_returns_valid_count() {
		let mut h = Polyvec::<K>::default();
		let mut w0 = Polyvec::<K>::default();
		let mut w1 = Polyvec::<K>::default();

		// Initialize with test data
		for i in 0..K {
			for j in 0..N {
				w0.vec[i].coeffs[j] = ((i * j) % 1000) as i32;
				w1.vec[i].coeffs[j] = ((i + j * 2) % 500) as i32;
			}
		}

		let hint_count = make_hint::<K, { params::GAMMA2 }>(&mut h, &w0, &w1);

		// Hint count should be non-negative and reasonable
		assert!(hint_count >= 0);
		assert!(hint_count <= (K * N) as i32);

		// Count the actual number of 1's in h
		let mut actual_count = 0;
		for i in 0..K {
			for j in 0..N {
				if h.vec[i].coeffs[j] == 1 {
					actual_count += 1;
				}
				assert!(
					h.vec[i].coeffs[j] == 0 || h.vec[i].coeffs[j] == 1,
					"Hint should be 0 or 1, got {}",
					h.vec[i].coeffs[j]
				);
			}
		}
		assert_eq!(hint_count, actual_count, "Hint count mismatch");
	}

	#[test]
	fn test_k_use_hint() {
		let mut w = Polyvec::<K>::default();
		let mut h = Polyvec::<K>::default();

		// Initialize w with test data
		for i in 0..K {
			for j in 0..N {
				w.vec[i].coeffs[j] = ((i * 100 + j) % 2000) as i32;
			}
		}

		// Set some hints
		h.vec[0].coeffs[0] = 1;
		h.vec[1].coeffs[10] = 1;
		h.vec[2].coeffs[50] = 1;

		let _original_w = w.clone();
		use_hint::<K, { params::GAMMA2 }>(&mut w, &h);

		// Values with hints should potentially be modified
		// Values without hints should remain the same
		for i in 0..K {
			for j in 0..N {
				if h.vec[i].coeffs[j] == 0 {
					// No change expected for coefficients without hints (in many cases)
					// This is a simplified check as use_hint can be complex
				}
				// All results should be in valid range
				assert!(w.vec[i].coeffs[j] >= 0, "use_hint result should be non-negative");
			}
		}
	}
}
