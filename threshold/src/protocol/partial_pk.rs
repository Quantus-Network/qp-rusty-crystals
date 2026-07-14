//! Partial public-key arithmetic shared by DKG and resharing.
//!
//! Both protocols need to (1) derive a per-subset partial public-key contribution
//! `t_J = A·s1_J + s2_J mod Q` from a pair of polynomial vectors and (2) sum these
//! partial contributions and pack them into the canonical ML-DSA-87 public-key
//! encoding (`rho || t1`).

use qp_rusty_crystals_dilithium::{
	packing,
	params::{K, N, Q},
	polyvec,
};

use crate::keys::{PublicKey, PUBLIC_KEY_SIZE};

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
	let mut mat: [polyvec::Polyvecl; K] = core::array::from_fn(|_| polyvec::Polyvecl::default());
	polyvec::matrix_expand(&mut mat, rho);

	let mut s1_pv = polyvec::Polyvecl::default();
	for (i, poly_coeffs) in s1.iter().enumerate() {
		s1_pv.vec[i].coeffs_mut().copy_from_slice(poly_coeffs);
	}

	let mut s2_pv = polyvec::Polyveck::default();
	for (i, poly_coeffs) in s2.iter().enumerate() {
		s2_pv.vec[i].coeffs_mut().copy_from_slice(poly_coeffs);
	}

	let mut s1_hat = s1_pv.clone();
	polyvec::l_ntt(&mut s1_hat);

	let mut t = polyvec::Polyveck::default();
	polyvec::matrix_pointwise_montgomery(&mut t, &mat, &s1_hat);
	// The accumulated dot products can reach L*Q in absolute value; the
	// inverse NTT requires coefficients below Q (same as the keygen flow in
	// dilithium's sign.rs).
	polyvec::k_reduce(&mut t);
	polyvec::k_invntt_tomont(&mut t);
	polyvec::k_add(&mut t, &s2_pv);
	polyvec::k_reduce(&mut t);
	polyvec::k_caddq(&mut t);

	let mut t_coeffs = [[0i32; N as usize]; K];
	for (i, poly) in t.vec.iter().enumerate() {
		t_coeffs[i].copy_from_slice(poly.coeffs());
	}
	t_coeffs
}

/// Error returned when combining partial public keys fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackCombinedPkError {
	/// A partial-PK coefficient was outside the canonical range `[0, Q)`.
	///
	/// Legitimate partial PKs come from [`compute_partial_pk_t`], whose output
	/// is always reduced into `[0, Q)`. A value outside that range indicates a
	/// malformed or attacker-supplied contribution.
	CoefficientOutOfRange,
}

/// Sum a collection of partial-PK polynomial vectors and pack into the canonical
/// ML-DSA-87 public-key encoding (`rho || t1`).
///
/// Each partial PK is a fixed-size `[[i32; N]; K]` array, guaranteeing the correct
/// shape at compile time.
///
/// # Coefficient validation
///
/// Every coefficient must already be reduced into `[0, Q)` (as produced by
/// [`compute_partial_pk_t`]). Peer-supplied partial PKs (e.g. from resharing
/// Round 5 or DKG Round 4 broadcasts) are attacker-controlled, so an unvalidated
/// `i32 + i32` accumulation could overflow before the mod-`Q` reduction — a
/// crafted coefficient near `i32::MAX` would panic in debug builds and wrap
/// silently in release builds. Rejecting out-of-range coefficients up front keeps
/// the running sum bounded below `2Q` and makes the accumulation overflow-free.
pub fn pack_combined_pk<'a, I>(
	rho: &[u8; 32],
	partial_ts: I,
) -> Result<PublicKey, PackCombinedPkError>
where
	I: IntoIterator<Item = &'a [[i32; N as usize]; K]>,
{
	let mut t = polyvec::Polyveck::default();
	for partial in partial_ts {
		for (i, poly_coeffs) in partial.iter().enumerate() {
			for (j, &coeff) in poly_coeffs.iter().enumerate() {
				// Reject non-canonical coefficients. This bounds the running sum
				// (each accumulator stays in `[0, Q)`, so `acc + coeff < 2Q`) and
				// prevents the i32 overflow that an attacker-supplied coefficient
				// near `i32::MAX` would otherwise trigger.
				if !(0..Q).contains(&coeff) {
					return Err(PackCombinedPkError::CoefficientOutOfRange);
				}
				t.vec[i].coeffs_mut()[j] = (t.vec[i].coeffs()[j] + coeff) % Q;
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

	Ok(PublicKey::new(pk_packed))
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

		let combined = pack_combined_pk(&rho, [&t_a, &t_b]).unwrap();
		let expected = pack_combined_pk(&rho, [&t_sum]).unwrap();

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
		let honest = pack_combined_pk(&rho, [&t]).unwrap();
		t[0][0] = (t[0][0] + (1 << 13)) % Q;
		let tampered = pack_combined_pk(&rho, [&t]).unwrap();
		assert_ne!(
			honest.as_bytes(),
			tampered.as_bytes(),
			"high-bit tamper must change the packed PK"
		);
	}

	/// Regression test (security review): a peer-supplied partial PK coefficient
	/// near `i32::MAX` must be rejected rather than overflowing the i32
	/// accumulation. Before the fix this addition panicked in debug builds and
	/// wrapped silently in release builds.
	#[test]
	fn pack_combined_pk_rejects_overflowing_coefficient() {
		let rho = [1u8; 32];

		// A first, canonical contribution makes the accumulator non-zero so that
		// the malicious second addition would overflow `i32` (Q-1 + i32::MAX).
		let honest = [[1i32; N as usize]; K];
		let mut malicious = [[0i32; N as usize]; K];
		malicious[0][0] = i32::MAX;

		let result = pack_combined_pk(&rho, [&honest, &malicious]);
		assert_eq!(
			result,
			Err(PackCombinedPkError::CoefficientOutOfRange),
			"out-of-range coefficient must be rejected, not summed"
		);

		// A negative out-of-range coefficient is likewise rejected.
		let mut negative = [[0i32; N as usize]; K];
		negative[0][0] = -1;
		assert_eq!(
			pack_combined_pk(&rho, [&negative]),
			Err(PackCombinedPkError::CoefficientOutOfRange),
		);

		// Q itself is out of range (canonical is [0, Q)).
		let mut at_q = [[0i32; N as usize]; K];
		at_q[0][0] = Q;
		assert_eq!(
			pack_combined_pk(&rho, [&at_q]),
			Err(PackCombinedPkError::CoefficientOutOfRange),
		);
	}
}
