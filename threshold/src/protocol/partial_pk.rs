//! Partial public-key arithmetic shared by DKG and resharing.
//!
//! Both protocols need to (1) derive a per-subset partial public-key contribution
//! `t_J = A·s1_J + s2_J mod Q` from a pair of polynomial vectors and (2) sum these
//! partial contributions and pack them into the canonical ML-DSA-87 public-key
//! encoding (`rho || t1`).

use alloc::vec::Vec;

use qp_rusty_crystals_dilithium::{
	fips202, packing,
	params::{K, N, Q},
	polyvec,
};

use crate::keys::{PublicKey, PUBLIC_KEY_SIZE, TR_SIZE};

/// Compute the unrounded partial PK polynomial vector `t = A·s1 + s2 mod Q`.
///
/// `s1` must contain `L` polynomials and `s2` must contain `K` polynomials, each
/// of length `N`. Coefficients of `s1` and `s2` need not be `eta`-bounded; they
/// only need to live in `i32` and the final result is reduced into `[0, Q)`.
///
/// Returns a fixed-size array of K polynomials.
pub fn compute_partial_pk_t(
	rho: &[u8; 32],
	s1: &[[i32; N as usize]],
	s2: &[[i32; N as usize]],
) -> [[i32; N as usize]; K] {
	let mut mat: Vec<polyvec::Polyvecl> = (0..K).map(|_| polyvec::Polyvecl::default()).collect();
	polyvec::matrix_expand(&mut mat, rho);

	let mut s1_pv = polyvec::Polyvecl::default();
	for (i, poly_coeffs) in s1.iter().enumerate() {
		s1_pv.vec[i].coeffs.copy_from_slice(poly_coeffs);
	}

	let mut s2_pv = polyvec::Polyveck::default();
	for (i, poly_coeffs) in s2.iter().enumerate() {
		s2_pv.vec[i].coeffs.copy_from_slice(poly_coeffs);
	}

	let mut s1_hat = s1_pv.clone();
	polyvec::l_ntt(&mut s1_hat);

	let mut t = polyvec::Polyveck::default();
	polyvec::matrix_pointwise_montgomery(&mut t, &mat, &s1_hat);
	polyvec::k_invntt_tomont(&mut t);
	polyvec::k_add(&mut t, &s2_pv);
	polyvec::k_reduce(&mut t);
	polyvec::k_caddq(&mut t);

	let mut t_coeffs = [[0i32; N as usize]; K];
	for (i, poly) in t.vec.iter().enumerate() {
		t_coeffs[i].copy_from_slice(&poly.coeffs);
	}
	t_coeffs
}

/// Sum a collection of partial-PK polynomial vectors and pack into the canonical
/// ML-DSA-87 public-key encoding (`rho || t1`).
///
/// Each partial PK is a fixed-size `[[i32; N]; K]` array, guaranteeing the correct
/// shape at compile time.
pub fn pack_combined_pk<'a, I>(rho: &[u8; 32], partial_ts: I) -> PublicKey
where
	I: IntoIterator<Item = &'a [[i32; N as usize]; K]>,
{
	let mut t = polyvec::Polyveck::default();
	for partial in partial_ts {
		for (i, poly_coeffs) in partial.iter().enumerate() {
			for (j, &coeff) in poly_coeffs.iter().enumerate() {
				t.vec[i].coeffs[j] = (t.vec[i].coeffs[j] + coeff) % Q;
			}
		}
	}
	polyvec::k_reduce(&mut t);
	polyvec::k_caddq(&mut t);

	let mut t0 = polyvec::Polyveck::default();
	let mut t1 = t.clone();
	polyvec::k_power2round(&mut t1, &mut t0);

	let mut pk_packed = [0u8; PUBLIC_KEY_SIZE];
	packing::pack_pk(&mut pk_packed, rho, &t1);

	let mut tr = [0u8; TR_SIZE];
	let mut h_tr = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut h_tr, &pk_packed, pk_packed.len());
	fips202::shake256_finalize(&mut h_tr);
	fips202::shake256_squeeze(&mut tr, TR_SIZE, &mut h_tr);

	PublicKey::new(pk_packed, tr)
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;

	const L: usize = 7;

	#[test]
	fn pack_combined_pk_is_additive() {
		let rho = [3u8; 32];
		let s1_a: Vec<[i32; N as usize]> = vec![[1i32; N as usize]; L];
		let s2_a: Vec<[i32; N as usize]> = vec![[2i32; N as usize]; K];
		let s1_b: Vec<[i32; N as usize]> = vec![[5i32; N as usize]; L];
		let s2_b: Vec<[i32; N as usize]> = vec![[7i32; N as usize]; K];

		let mut s1_sum: Vec<[i32; N as usize]> = vec![[0i32; N as usize]; L];
		let mut s2_sum: Vec<[i32; N as usize]> = vec![[0i32; N as usize]; K];
		for i in 0..L {
			for j in 0..N as usize {
				s1_sum[i][j] = s1_a[i][j] + s1_b[i][j];
			}
		}
		for i in 0..K {
			for j in 0..N as usize {
				s2_sum[i][j] = s2_a[i][j] + s2_b[i][j];
			}
		}

		let t_a = compute_partial_pk_t(&rho, &s1_a, &s2_a);
		let t_b = compute_partial_pk_t(&rho, &s1_b, &s2_b);
		let t_sum = compute_partial_pk_t(&rho, &s1_sum, &s2_sum);

		let combined = pack_combined_pk(&rho, [&t_a, &t_b]);
		let expected = pack_combined_pk(&rho, [&t_sum]);

		assert_eq!(
			combined.as_bytes(),
			expected.as_bytes(),
			"sum of partial PKs must match PK of summed shares"
		);
	}

	#[test]
	fn pack_combined_pk_detects_tampering() {
		// Tamper by enough to flip a high bit (the low 13 bits get rounded away
		// by `power2round`, so we shift by `1 << 13` to guarantee the packed PK
		// differs).
		let rho = [9u8; 32];
		let s1: Vec<[i32; N as usize]> = vec![[1i32; N as usize]; L];
		let s2: Vec<[i32; N as usize]> = vec![[2i32; N as usize]; K];
		let mut t = compute_partial_pk_t(&rho, &s1, &s2);
		let honest = pack_combined_pk(&rho, [&t]);
		t[0][0] = (t[0][0] + (1 << 13)) % Q;
		let tampered = pack_combined_pk(&rho, [&t]);
		assert_ne!(
			honest.as_bytes(),
			tampered.as_bytes(),
			"high-bit tamper must change the packed PK"
		);
	}
}
