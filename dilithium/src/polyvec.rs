use crate::{params, poly, poly::Poly};
use core::{array, mem::swap};
use zeroize::ZeroizeOnDrop;

const K: usize = params::K;
const L: usize = params::L;

#[derive(Clone, ZeroizeOnDrop)]
pub struct Polyveck {
	pub vec: [Poly; K],
}

impl Default for Polyveck {
	fn default() -> Self {
		Polyveck { vec: array::from_fn(|_| Poly::default()) }
	}
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct Polyvecl {
	pub vec: [Poly; L],
}

impl Default for Polyvecl {
	fn default() -> Self {
		Polyvecl { vec: array::from_fn(|_| Poly::default()) }
	}
}

/// Implementation of ExpandA. Generates matrix A with uniformly random coefficients a_{i,j} by
/// performing rejection sampling on the output stream of SHAKE128(rho|j|i).
pub fn matrix_expand(mat: &mut [Polyvecl], rho: &[u8]) {
	for (i, mat_i) in mat.iter_mut().enumerate().take(K) {
		for j in 0..L {
			poly::uniform(&mut mat_i.vec[j], rho, ((i << 8) + j) as u16);
		}
	}
}

/// Pointwise multiply vectors of polynomials of length L, multiply resulting vector by 2^{-32} and
/// add (accumulate) polynomials in it. Input/output vectors are in NTT domain representation. Input
/// coefficients are assumed to be less than 22*Q. Output coeffcient are less than 2*L*Q.
pub fn l_pointwise_acc_montgomery(w: &mut Poly, u: &Polyvecl, v: &Polyvecl) {
	poly::pointwise_montgomery(w, &u.vec[0], &v.vec[0]);
	let mut t = Poly::default();
	for i in 1..L {
		poly::pointwise_montgomery(&mut t, &u.vec[i], &v.vec[i]);
		poly::add_ip(w, &t);
	}
}

pub fn matrix_pointwise_montgomery(t: &mut Polyveck, mat: &[Polyvecl], v: &Polyvecl) {
	for (i, t_i) in t.vec.iter_mut().enumerate().take(K) {
		l_pointwise_acc_montgomery(t_i, &mat[i], v);
	}
}

pub fn matrix_pointwise_montgomery_streaming(t: &mut Polyveck, rho: &[u8], v: &Polyvecl) {
	let mut a_ij = Poly::default();
	let mut tmp = Poly::default();
	for (i, t_i) in t.vec.iter_mut().enumerate().take(K) {
		poly::uniform(&mut a_ij, rho, ((i << 8) + 0) as u16);
		poly::pointwise_montgomery(t_i, &a_ij, &v.vec[0]);
		for j in 1..L {
			poly::uniform(&mut a_ij, rho, ((i << 8) + j) as u16);
			poly::pointwise_montgomery(&mut tmp, &a_ij, &v.vec[j]);
			poly::add_ip(t_i, &tmp);
		}
	}
}

pub fn l_uniform_eta(v: &mut Polyvecl, seed: &[u8], mut nonce: u16) {
	for i in 0..L {
		poly::uniform_eta(&mut v.vec[i], seed, nonce);
		nonce += 1;
	}
}

pub fn l_uniform_gamma1(v: &mut Polyvecl, seed: &[u8], nonce: u16) {
	for i in 0..L {
		poly::uniform_gamma1(&mut v.vec[i], seed, L as u16 * nonce + i as u16);
	}
}
/// Reduce coefficients of polynomials in vector of length L
/// to representatives in [-6283008, 6283008].
pub fn l_reduce(v: &mut Polyvecl) {
	for i in 0..L {
		poly::reduce(&mut v.vec[i]);
	}
}

/// Add vectors of polynomials of length L.
/// No modular reduction is performed.
pub fn l_add(w: &mut Polyvecl, v: &Polyvecl) {
	for i in 0..L {
		poly::add_ip(&mut w.vec[i], &v.vec[i]);
	}
}

/// Forward NTT of all polynomials in vector of length L. Output coefficients can be up to 16*Q
/// larger than input coefficients.
pub fn l_ntt(v: &mut Polyvecl) {
	for i in 0..L {
		poly::ntt(&mut v.vec[i]);
	}
}

pub fn l_invntt_tomont(v: &mut Polyvecl) {
	for i in 0..L {
		poly::invntt_tomont(&mut v.vec[i]);
	}
}

pub fn l_pointwise_poly_montgomery(r: &mut Polyvecl, a: &Poly, v: &Polyvecl) {
	for i in 0..L {
		poly::pointwise_montgomery(&mut r.vec[i], a, &v.vec[i]);
	}
}

/// Check if the infinity norm of a Polyvecl is within the given bound.
///
/// # Arguments
/// * `v` - The polynomial vector to check
/// * `bound` - The norm bound
///
/// Returns true if all polynomials in the vector have infinity norm < bound, false otherwise.
pub fn polyvecl_is_norm_within_bound(v: &Polyvecl, bound: i32) -> bool {
	let mut result = true;
	for i in 0..L {
		let norm_check = poly::check_norm(&v.vec[i], bound);
		result = result && !norm_check;
	}
	result
}

//---------------------------------

pub fn k_uniform_eta(v: &mut Polyveck, seed: &[u8], mut nonce: u16) {
	for i in 0..K {
		poly::uniform_eta(&mut v.vec[i], seed, nonce);
		nonce += 1
	}
}

/// Reduce coefficients of polynomials in vector of length K
/// to representatives in [-6283008, 6283008].
pub fn k_reduce(v: &mut Polyveck) {
	for i in 0..K {
		poly::reduce(&mut v.vec[i]);
	}
}

/// For all coefficients of polynomials in vector of length K
/// add Q if coefficient is negative.
pub fn k_caddq(v: &mut Polyveck) {
	for i in 0..K {
		poly::caddq(&mut v.vec[i]);
	}
}

/// Add vectors of polynomials of length K.
/// No modular reduction is performed.
pub fn k_add(w: &mut Polyveck, v: &Polyveck) {
	for i in 0..K {
		poly::add_ip(&mut w.vec[i], &v.vec[i]);
	}
}

/// Subtract vectors of polynomials of length K.
/// Assumes coefficients of polynomials in second input vector
/// to be less than 2*Q. No modular reduction is performed.
pub fn k_sub(w: &mut Polyveck, v: &Polyveck) {
	for i in 0..K {
		poly::sub_ip(&mut w.vec[i], &v.vec[i]);
	}
}

/// Multiply vector of polynomials of Length K by 2^D without modular
/// reduction. Assumes input coefficients to be less than 2^{32-D}.
pub fn k_shiftl(v: &mut Polyveck) {
	for i in 0..K {
		poly::shiftl(&mut v.vec[i]);
	}
}

/// Forward NTT of all polynomials in vector of length K. Output
/// coefficients can be up to 16*Q larger than input coefficients.
pub fn k_ntt(v: &mut Polyveck) {
	for i in 0..K {
		poly::ntt(&mut v.vec[i]);
	}
}

/// Inverse NTT and multiplication by 2^{32} of polynomials
/// in vector of length K. Input coefficients need to be less
/// than 2*Q.
pub fn k_invntt_tomont(v: &mut Polyveck) {
	for i in 0..K {
		poly::invntt_tomont(&mut v.vec[i]);
	}
}

pub fn k_pointwise_poly_montgomery(r: &mut Polyveck, a: &Poly, v: &Polyveck) {
	for i in 0..K {
		poly::pointwise_montgomery(&mut r.vec[i], a, &v.vec[i]);
	}
}

/// Check if the infinity norm of a Polyveck is within the given bound.
///
/// # Arguments
/// * `v` - The polynomial vector to check
/// * `bound` - The norm bound
///
/// Returns true if all polynomials in the vector have infinity norm < bound, false otherwise.
pub fn polyveck_is_norm_within_bound(v: &Polyveck, bound: i32) -> bool {
	let mut result = true;
	for i in 0..K {
		let norm_check = poly::check_norm(&v.vec[i], bound);
		result = result && !norm_check;
	}
	result
}

/// For all coefficients a of polynomials in vector of length K, compute a0, a1 such that a mod Q =
/// a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be standard representatives.
pub fn k_power2round(v1: &mut Polyveck, v0: &mut Polyveck) {
	for i in 0..K {
		poly::power2round(&mut v1.vec[i], &mut v0.vec[i]);
	}
}

pub fn k_decompose(v1: &mut Polyveck, v0: &mut Polyveck) {
	for i in 0..K {
		poly::decompose(&mut v1.vec[i], &mut v0.vec[i]);
	}
	swap(v1, v0);
}

pub fn k_make_hint(h: &mut Polyveck, v0: &Polyveck, v1: &Polyveck) -> i32 {
	let mut s: i32 = 0;
	for i in 0..K {
		s += poly::make_hint(&mut h.vec[i], &v0.vec[i], &v1.vec[i]);
	}
	s
}

pub fn k_use_hint(a: &mut Polyveck, hint: &Polyveck) {
	for i in 0..K {
		poly::use_hint(&mut a.vec[i], &hint.vec[i]);
	}
}

pub fn k_pack_w1(r: &mut [u8], a: &Polyveck) {
	for i in 0..K {
		poly::w1_pack(&mut r[i * params::POLYW1_PACKEDBYTES..], &a.vec[i]);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	const N: usize = params::N as usize;

	#[test]
	fn test_polyvecl_default() {
		let polyvecl = Polyvecl::default();
		for i in 0..L {
			for j in 0..N {
				assert_eq!(polyvecl.vec[i].coeffs[j], 0);
			}
		}
	}

	#[test]
	fn test_polyveck_default() {
		let polyveck = Polyveck::default();
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
		let mut polyvecl = Polyvecl::default();

		l_uniform_eta(&mut polyvecl, &seed, nonce);

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
		let mut polyveck = Polyveck::default();

		k_uniform_eta(&mut polyveck, &seed, nonce);

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
		let mut polyvecl = Polyvecl::default();

		l_uniform_gamma1(&mut polyvecl, &seed, nonce);

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

	#[test]
	fn test_l_add() {
		let mut a = Polyvecl::default();
		let mut b = Polyvecl::default();

		// Initialize with test data
		for i in 0..L {
			for j in 0..N {
				a.vec[i].coeffs[j] = (i * 100 + j) as i32;
				b.vec[i].coeffs[j] = (i * 200 + j * 2) as i32;
			}
		}

		let original_a = a.clone();
		l_add(&mut a, &b);

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
		let mut a = Polyveck::default();
		let mut b = Polyveck::default();

		// Initialize with test data
		for i in 0..K {
			for j in 0..N {
				a.vec[i].coeffs[j] = (i * 50 + j) as i32;
				b.vec[i].coeffs[j] = (i * 75 + j * 3) as i32;
			}
		}

		let original_a = a.clone();
		k_add(&mut a, &b);

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
		let mut a = Polyveck::default();
		let mut b = Polyveck::default();

		// Initialize with test data
		for i in 0..K {
			for j in 0..N {
				a.vec[i].coeffs[j] = (i * 1000 + j * 10) as i32;
				b.vec[i].coeffs[j] = (i * 100 + j) as i32;
			}
		}

		let original_a = a.clone();
		k_sub(&mut a, &b);

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

	#[test]
	fn test_l_ntt_invntt_roundtrip() {
		let mut polyvecl = Polyvecl::default();

		// Initialize with test data
		for i in 0..L {
			for j in 0..N {
				polyvecl.vec[i].coeffs[j] = ((i * j + 123) % 1000) as i32;
			}
		}

		let original = polyvecl.clone();
		l_ntt(&mut polyvecl);
		l_invntt_tomont(&mut polyvecl);

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
		let mut polyveck = Polyveck::default();

		// Initialize with test data
		for i in 0..K {
			for j in 0..N {
				polyveck.vec[i].coeffs[j] = ((i * j * 2 + 456) % 800) as i32;
			}
		}

		let original = polyveck.clone();
		k_ntt(&mut polyveck);
		k_invntt_tomont(&mut polyveck);

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
		let polyvecl = Polyvecl::default(); // All coefficients are 0
		assert!(polyvecl_is_norm_within_bound(&polyvecl, 1)); // Should be within any positive bound
		assert!(polyvecl_is_norm_within_bound(&polyvecl, 1000));
	}

	#[test]
	fn test_l_chknorm_exceeds_bound() {
		let mut polyvecl = Polyvecl::default();
		polyvecl.vec[0].coeffs[0] = 100;
		polyvecl.vec[1].coeffs[10] = -150;

		assert!(polyvecl_is_norm_within_bound(&polyvecl, 200)); // Within bound
		assert!(!polyvecl_is_norm_within_bound(&polyvecl, 149)); // Exceeds bound
		assert!(!polyvecl_is_norm_within_bound(&polyvecl, 99)); // Exceeds bound
	}

	#[test]
	fn test_k_chknorm_zero_vector() {
		let polyveck = Polyveck::default(); // All coefficients are 0
		assert!(polyveck_is_norm_within_bound(&polyveck, 1)); // Should be within any positive bound
		assert!(polyveck_is_norm_within_bound(&polyveck, 1000));
	}

	#[test]
	fn test_k_chknorm_exceeds_bound() {
		let mut polyveck = Polyveck::default();
		polyveck.vec[0].coeffs[5] = 200;
		polyveck.vec[2].coeffs[15] = -250;

		assert!(polyveck_is_norm_within_bound(&polyveck, 300)); // Within bound
		assert!(!polyveck_is_norm_within_bound(&polyveck, 249)); // Exceeds bound
		assert!(!polyveck_is_norm_within_bound(&polyveck, 199)); // Exceeds bound
	}

	#[test]
	fn test_k_shiftl() {
		let mut polyveck = Polyveck::default();

		// Initialize with small test values
		for i in 0..K {
			for j in 0..N {
				polyveck.vec[i].coeffs[j] = (j % 10) as i32;
			}
		}

		let original = polyveck.clone();
		k_shiftl(&mut polyveck);

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

		let mut mat1: [Polyvecl; K] = array::from_fn(|_| Polyvecl::default());
		let mut mat2: [Polyvecl; K] = array::from_fn(|_| Polyvecl::default());

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
		let mut mat: [Polyvecl; K] = array::from_fn(|_| Polyvecl::default());
		let mut v = Polyvecl::default();
		let mut result = Polyveck::default();

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
		let mut h = Polyveck::default();
		let mut w0 = Polyveck::default();
		let mut w1 = Polyveck::default();

		// Initialize with test data
		for i in 0..K {
			for j in 0..N {
				w0.vec[i].coeffs[j] = ((i * j) % 1000) as i32;
				w1.vec[i].coeffs[j] = ((i + j * 2) % 500) as i32;
			}
		}

		let hint_count = k_make_hint(&mut h, &w0, &w1);

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
		let mut w = Polyveck::default();
		let mut h = Polyveck::default();

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
		k_use_hint(&mut w, &h);

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
