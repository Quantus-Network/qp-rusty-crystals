//! Low-level primitives for threshold ML-DSA-87.
//!
//! This module provides the basic types and functions needed by the threshold protocol,
//! including hyperball sampling, matrix operations, and modular arithmetic helpers.

use qp_rusty_crystals_dilithium::{fips202, packing, params as dilithium_params, poly, polyvec};

// ============================================================================
// Constants for ML-DSA-87
// ============================================================================

pub(crate) const N: usize = 256;
pub(crate) const K: usize = 8;
pub(crate) const L: usize = 7;
pub(crate) const Q: i32 = 8380417;

// Constants for decompose (ML-DSA-87)
const ALPHA: u32 = 2 * 261888; // 2 * Gamma2 = 523776
const Q_U32: u32 = 8380417;

// ============================================================================
// Modular Arithmetic Helpers
// ============================================================================

/// Reduce x to a value ≤ 2Q.
#[inline]
pub(crate) fn reduce_le2q(x: u32) -> u32 {
	let x1 = x >> 23;
	let x2 = x & 0x7FFFFF;
	x2 + (x1 << 13) - x1
}

/// Returns x mod q for 0 ≤ x < 2q.
#[inline]
pub(crate) fn le2q_mod_q(x: u32) -> u32 {
	let q = Q_U32;
	let result = x.wrapping_sub(q);
	let mask = (result as i32 >> 31) as u32;
	result.wrapping_add(mask & q)
}

/// Returns x mod q.
#[inline]
pub(crate) fn mod_q(x: u32) -> u32 {
	le2q_mod_q(reduce_le2q(x))
}

/// Normalize polynomial coefficients assuming they are ≤ 2Q.
/// Converts to [0, Q) range. Matches reference implementation behavior.
pub(crate) fn normalize_assuming_le2q(poly: &mut poly::Poly) {
	for j in 0..dilithium_params::N as usize {
		let coeff = poly.coeffs[j];
		// First ensure value is positive and in reasonable range
		let coeff_u32 = if coeff < 0 { (coeff + Q) as u32 } else { coeff as u32 };
		// Apply le2q_mod_q to get into [0, Q) range
		poly.coeffs[j] = le2q_mod_q(coeff_u32) as i32;
	}
}

// ============================================================================
// Decomposition Functions (Go-compatible)
// ============================================================================

/// Decompose a coefficient into low and high parts for ML-DSA rounding.
///
/// Splits 0 ≤ a < q into (a₀, a₁) where a = a₁*α + a₀ with -α/2 < a₀ ≤ α/2,
/// except when a₁ would equal (q-1)/α, in which case a₁=0 and -α/2 ≤ a₀ < 0.
/// Returns (a₀ + q, a₁) where 0 ≤ a₁ < 16 and α = 2γ₂ = 523776.
///
/// This matches the reference Threshold-ML-DSA implementation for compatibility.
pub(crate) fn decompose_coefficient(a: u32) -> (u32, u32) {
	// a₁ = ⌈a / 128⌉
	let mut a1 = (a + 127) >> 7;

	// For Alpha == 523776 (ML-DSA-87):
	// 1025/2²² is close enough to 1/4092 so that a₁
	// becomes a/α rounded down.
	a1 = ((a1 as u64 * 1025 + (1 << 21)) >> 22) as u32;

	// For the corner-case a₁ = (q-1)/α = 16, we have to set a₁=0.
	a1 &= 15;

	let mut a0_plus_q = a.wrapping_sub(a1.wrapping_mul(ALPHA));

	// In the corner-case, when we set a₁=0, we will incorrectly
	// have a₀ > (q-1)/2 and we'll need to subtract q.  As we
	// return a₀ + q, that comes down to adding q if a₀ < (q-1)/2.
	let threshold = (Q_U32 - 1) / 2;
	// Use i32 arithmetic to handle the comparison correctly
	let cond = ((a0_plus_q as i32).wrapping_sub(threshold as i32)) >> 31; // -1 if a0_plus_q < threshold, 0 otherwise
	a0_plus_q = a0_plus_q.wrapping_add((cond as u32) & Q_U32);

	(a0_plus_q, a1)
}

/// Decompose a vector of K polynomials into low and high parts.
///
/// Matches the reference implementation's rounding behavior for compatibility.
pub(crate) fn decompose_polyveck(
	input: &polyvec::Polyveck,
	w0: &mut polyvec::Polyveck,
	w1: &mut polyvec::Polyveck,
) {
	for i in 0..dilithium_params::K {
		for j in 0..dilithium_params::N as usize {
			let a = input.vec[i].coeffs[j] as u32;
			let (a0, a1) = decompose_coefficient(a);
			w0.vec[i].coeffs[j] = a0 as i32;
			w1.vec[i].coeffs[j] = a1 as i32;
		}
	}
}

// ============================================================================
// NTT Operations
// ============================================================================

/// Compute dot product of polynomial vectors in NTT domain.
///
/// Computes result = Σ(a[i] * b[i]) for all polynomials in the vectors,
/// using Montgomery multiplication. Compatible with the reference implementation.
pub(crate) fn compute_ntt_dot_product(
	result: &mut poly::Poly,
	a: &polyvec::Polyvecl,
	b: &polyvec::Polyvecl,
) {
	// Zero out result
	for i in 0..dilithium_params::N as usize {
		result.coeffs[i] = 0;
	}

	// Compute dot product
	for i in 0..dilithium_params::L {
		let mut tmp = poly::Poly::default();
		crate::circl_ntt::mul_hat(&mut tmp, &a.vec[i], &b.vec[i]);
		for j in 0..dilithium_params::N as usize {
			result.coeffs[j] += tmp.coeffs[j];
		}
	}
}

// ============================================================================
// HyperballSampleVector - Floating-point vector for hyperball sampling
// ============================================================================

/// Floating-point vector for threshold signature hyperball sampling.
///
/// Used for rejection sampling in the threshold signing protocol. Samples are
/// drawn from a hyperball of specified radius and scaled by nu for the s1
/// components.
pub struct HyperballSampleVector {
	data: Box<[f64]>,
}

impl HyperballSampleVector {
	/// Create a new vector with given size, initialized to zero.
	pub fn new(size: usize) -> Self {
		Self { data: vec![0.0f64; size].into_boxed_slice() }
	}

	/// Sample from hyperball with given radius and nu parameter.
	/// This uses SHAKE256 for cryptographic randomness and Box-Muller
	/// transform for normally distributed samples.
	pub fn sample_hyperball(&mut self, radius: f64, nu: f64, rhop: &[u8; 64], nonce: u16) {
		use std::f64::consts::PI;

		let size = self.data.len();
		let mut samples = vec![0.0f64; size + 2];

		// Use SHAKE256 for cryptographic randomness
		let mut keccak_state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut keccak_state, b"H", 1); // Domain separator
		fips202::shake256_absorb(&mut keccak_state, rhop, 64);
		let nonce_bytes = nonce.to_le_bytes();
		fips202::shake256_absorb(&mut keccak_state, &nonce_bytes, 2);
		fips202::shake256_finalize(&mut keccak_state);

		let mut buf = vec![0u8; (size + 2) * 8]; // 8 bytes per f64
		let buf_len = buf.len();
		fips202::shake256_squeeze(&mut buf, buf_len, &mut keccak_state);

		// Generate normally distributed random numbers using Box-Muller transform
		// CRITICAL: Must compute sq BEFORE applying nu scaling (matching reference)
		let mut sq = 0.0f64;
		for i in (0..size + 2).step_by(2) {
			// Convert bytes to u64
			let u1_bytes: [u8; 8] = buf[i * 8..(i + 1) * 8].try_into().unwrap();
			let u2_bytes: [u8; 8] = buf[(i + 1) * 8..(i + 2) * 8].try_into().unwrap();
			let u1 = u64::from_le_bytes(u1_bytes);
			let u2 = u64::from_le_bytes(u2_bytes);

			// Convert to f64 in [0,1) - matching Golang exactly
			let f1 = (u1 as f64) / 18446744073709551616.0; // 2^64 as f64
			let f2 = (u2 as f64) / 18446744073709551616.0;

			// Ensure f1 > 0 for log to avoid NaN
			let f1 = if f1 <= 0.0 { f64::MIN_POSITIVE } else { f1 };

			// Box-Muller transform
			let z1 = (-2.0 * f1.ln()).sqrt() * (2.0 * PI * f2).cos();
			let z2 = (-2.0 * f1.ln()).sqrt() * (2.0 * PI * f2).sin();

			// Store samples and add to sq BEFORE nu scaling (critical!)
			samples[i] = z1;
			sq += z1 * z1;

			samples[i + 1] = z2;
			sq += z2 * z2;

			// Apply nu scaling to first N*L components AFTER adding to sq
			if i < dilithium_params::N as usize * dilithium_params::L {
				samples[i] *= nu;
				samples[i + 1] *= nu;
			}
		}

		let factor = radius / sq.sqrt();
		for (data_val, sample_val) in self.data.iter_mut().zip(samples.iter()).take(size) {
			*data_val = *sample_val * factor;
		}
	}

	/// Round the z response component (s1 portion) to integer polynomial.
	/// Used in signing when only the z response is needed.
	/// Keeps values in centered representation [-(Q-1)/2, (Q-1)/2].
	pub fn round_z_response(&self, z: &mut polyvec::Polyvecl) {
		for i in 0..dilithium_params::L {
			for j in 0..dilithium_params::N as usize {
				let idx = i * dilithium_params::N as usize + j;
				let u = self.data[idx].round() as i32;
				let mut reduced = u % Q;
				if reduced > Q / 2 {
					reduced -= Q;
				} else if reduced < -(Q / 2) {
					reduced += Q;
				}
				z.vec[i].coeffs[j] = reduced;
			}
		}
	}

	/// Round floating-point values back to integer polynomials.
	/// Keeps values in centered representation [-(Q-1)/2, (Q-1)/2].
	pub fn round(&self, s1: &mut polyvec::Polyvecl, s2: &mut polyvec::Polyveck) {
		// Round s1 components - keep in centered range
		for i in 0..dilithium_params::L {
			for j in 0..dilithium_params::N as usize {
				let idx = i * dilithium_params::N as usize + j;
				let u = self.data[idx].round() as i32;
				// Keep values centered: if outside [-Q/2, Q/2], reduce modulo Q
				let mut reduced = u % Q;
				if reduced > Q / 2 {
					reduced -= Q;
				} else if reduced < -(Q / 2) {
					reduced += Q;
				}
				s1.vec[i].coeffs[j] = reduced;
			}
		}

		// Round s2 components - keep in centered range
		for i in 0..dilithium_params::K {
			for j in 0..dilithium_params::N as usize {
				let idx = (dilithium_params::L + i) * dilithium_params::N as usize + j;
				let u = self.data[idx].round() as i32;
				// Keep values centered: if outside [-Q/2, Q/2], reduce modulo Q
				let mut reduced = u % Q;
				if reduced > Q / 2 {
					reduced -= Q;
				} else if reduced < -(Q / 2) {
					reduced += Q;
				}
				s2.vec[i].coeffs[j] = reduced;
			}
		}
	}

	/// Check if norm exceeds rejection bounds for rejection sampling.
	pub fn excess(&self, r: f64, nu: f64) -> bool {
		let mut sq = 0.0;

		for i in 0..(dilithium_params::L + dilithium_params::K) {
			for j in 0..dilithium_params::N as usize {
				let idx = i * dilithium_params::N as usize + j;
				let val = self.data[idx];
				if i < dilithium_params::L {
					// For s1 components, divide by nu^2
					sq += val * val / (nu * nu);
				} else {
					// For s2 components, use directly
					sq += val * val;
				}
			}
		}

		sq > r * r
	}

	/// Add another vector to this one element-wise.
	pub fn add(&mut self, other: &HyperballSampleVector) {
		for i in 0..self.data.len() {
			self.data[i] += other.data[i];
		}
	}

	/// Clone this vector.
	pub fn clone(&self) -> Self {
		Self { data: self.data.clone() }
	}

	/// Create a vector from polynomial vectors (s1, s2).
	pub fn from_polyvecs(s1: &polyvec::Polyvecl, s2: &polyvec::Polyveck) -> Self {
		let size = dilithium_params::N as usize * (dilithium_params::L + dilithium_params::K);
		let mut data = vec![0.0f64; size];

		// Copy s1 polynomials (first L polynomials)
		for i in 0..dilithium_params::L {
			for j in 0..dilithium_params::N as usize {
				let mut u = s1.vec[i].coeffs[j];
				// Center modulo Q
				u += Q / 2;
				let t = u - Q;
				u = t + ((t >> 31) & Q);
				u -= Q / 2;

				data[i * dilithium_params::N as usize + j] = u as f64;
			}
		}

		// Copy s2 polynomials (next K polynomials)
		for i in 0..dilithium_params::K {
			for j in 0..dilithium_params::N as usize {
				let mut u = s2.vec[i].coeffs[j];
				// Center modulo Q
				u += Q / 2;
				let t = u - Q;
				u = t + ((t >> 31) & Q);
				u -= Q / 2;

				data[(dilithium_params::L + i) * dilithium_params::N as usize + j] = u as f64;
			}
		}

		Self { data: data.into_boxed_slice() }
	}
}

// ============================================================================
// Hint Computation
// ============================================================================

/// Compute Dilithium hint for signature.
/// Returns the hint population count.
pub(crate) fn compute_dilithium_hint(
	hint: &mut polyvec::Polyveck,
	w0pf: &polyvec::Polyveck,
	w1: &polyvec::Polyveck,
) -> usize {
	let mut pop = 0;
	for i in 0..dilithium_params::K {
		for j in 0..dilithium_params::N as usize {
			let h = make_hint_single(w0pf.vec[i].coeffs[j], w1.vec[i].coeffs[j]);
			hint.vec[i].coeffs[j] = h;
			pop += h as usize;
		}
	}
	pop
}

/// Compute hint bit for a single coefficient pair.
fn make_hint_single(z0: i32, r1: i32) -> i32 {
	// Compute highBits(z0 + r1 * ALPHA)
	let z0_u32 = if z0 < 0 { (z0 + Q) as u32 } else { z0 as u32 };
	let r1_times_alpha = (r1 as u32) * ALPHA;
	let sum = z0_u32.wrapping_add(r1_times_alpha);
	let sum_mod = mod_q(sum);
	let (_, high1) = decompose_coefficient(sum_mod);

	// Compare with r1
	if high1 != r1 as u32 {
		1
	} else {
		0
	}
}

// ============================================================================
// Packing Functions
// ============================================================================

/// Pack a polynomial with coefficients < Q using 23-bit encoding.
pub(crate) fn poly_pack_w(p: &poly::Poly, buf: &mut [u8]) {
	// 23 bits per coefficient, 256 coefficients = 736 bytes
	assert!(buf.len() >= 736);

	let mut bit_pos = 0usize;
	for i in 0..dilithium_params::N as usize {
		let coeff = p.coeffs[i] as u32;

		// Write 23 bits starting at bit_pos
		let byte_pos = bit_pos / 8;
		let bit_offset = bit_pos % 8;

		// This coefficient spans up to 4 bytes
		let mut val = coeff;
		let mut bits_remaining = 23;
		let mut current_byte = byte_pos;
		let mut current_offset = bit_offset;

		while bits_remaining > 0 {
			let bits_in_byte = 8 - current_offset;
			let bits_to_write = bits_remaining.min(bits_in_byte);

			let mask = (1u32 << bits_to_write) - 1;
			buf[current_byte] |= ((val & mask) << current_offset) as u8;

			val >>= bits_to_write;
			bits_remaining -= bits_to_write;
			current_byte += 1;
			current_offset = 0;
		}

		bit_pos += 23;
	}
}

/// Unpack a polynomial with coefficients < Q from 23-bit encoding.
pub(crate) fn poly_unpack_w(buf: &[u8]) -> poly::Poly {
	assert!(buf.len() >= 736);
	let mut p = poly::Poly::default();

	let mut bit_pos = 0usize;
	for i in 0..dilithium_params::N as usize {
		let byte_pos = bit_pos / 8;
		let bit_offset = bit_pos % 8;

		// Read 23 bits starting at bit_pos
		let mut val = 0u32;
		let mut bits_remaining = 23;
		let mut current_byte = byte_pos;
		let mut current_offset = bit_offset;
		let mut val_offset = 0;

		while bits_remaining > 0 {
			let bits_in_byte = 8 - current_offset;
			let bits_to_read = bits_remaining.min(bits_in_byte);

			let mask = (1u32 << bits_to_read) - 1;
			let byte_val = (buf[current_byte] >> current_offset) as u32;
			val |= (byte_val & mask) << val_offset;

			val_offset += bits_to_read;
			bits_remaining -= bits_to_read;
			current_byte += 1;
			current_offset = 0;
		}

		p.coeffs[i] = val as i32;
		bit_pos += 23;
	}

	p
}

/// Unpack a Polyveck from 23-bit encoding.
pub(crate) fn unpack_polyveck_w(buf: &[u8]) -> polyvec::Polyveck {
	const POLY_W_SIZE: usize = 736;
	let mut w = polyvec::Polyveck::default();
	for i in 0..dilithium_params::K {
		let offset = i * POLY_W_SIZE;
		w.vec[i] = poly_unpack_w(&buf[offset..offset + POLY_W_SIZE]);
	}
	w
}

// ============================================================================
// Signature Packing
// ============================================================================

/// Pack a threshold signature into the standard ML-DSA-87 format.
pub(crate) fn pack_signature(
	c_tilde: &[u8],
	z: &polyvec::Polyvecl,
	hint: &polyvec::Polyveck,
) -> Result<Vec<u8>, &'static str> {
	let mut sig = vec![0u8; dilithium_params::SIGNBYTES];

	// Use dilithium's pack_sig function
	packing::pack_sig(&mut sig, Some(c_tilde), z, hint);

	Ok(sig)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_mod_q() {
		assert_eq!(mod_q(0), 0);
		assert_eq!(mod_q(Q_U32 - 1), Q_U32 - 1);
		assert_eq!(mod_q(Q_U32), 0);
		assert_eq!(mod_q(Q_U32 + 1), 1);
		assert_eq!(mod_q(2 * Q_U32 - 1), Q_U32 - 1);
	}

	#[test]
	fn test_decompose_coefficient() {
		// Test that high part is always < 16
		let (_a0, a1) = decompose_coefficient(0);
		assert!(a1 < 16);

		let (_a0, a1) = decompose_coefficient(Q_U32 - 1);
		assert!(a1 < 16);

		// Test various values to ensure a1 is always < 16
		for a in [0u32, 1, 100, 1000, Q_U32 / 2, Q_U32 - 1, ALPHA, ALPHA * 2, ALPHA * 15] {
			let (_a0, a1) = decompose_coefficient(a);
			assert!(a1 < 16, "a1 should be < 16 for a={}, got a1={}", a, a1);
		}
	}

	#[test]
	fn test_hyperball_vector_new() {
		let vec = HyperballSampleVector::new(100);
		assert_eq!(vec.data.len(), 100);
		for &v in vec.data.iter() {
			assert_eq!(v, 0.0);
		}
	}

	#[test]
	fn test_hyperball_vector_add() {
		let mut vec1 = HyperballSampleVector::new(10);
		let mut vec2 = HyperballSampleVector::new(10);

		for i in 0..10 {
			vec1.data[i] = i as f64;
			vec2.data[i] = (10 - i) as f64;
		}

		vec1.add(&vec2);

		for i in 0..10 {
			assert_eq!(vec1.data[i], 10.0);
		}
	}

	#[test]
	fn test_poly_pack_unpack_w() {
		let mut p = poly::Poly::default();
		for i in 0..N {
			p.coeffs[i] = (i * 12345) as i32 % Q;
		}

		let mut buf = vec![0u8; 736];
		poly_pack_w(&p, &mut buf);

		let p2 = poly_unpack_w(&buf);

		for i in 0..N {
			assert_eq!(p.coeffs[i], p2.coeffs[i], "Mismatch at index {}", i);
		}
	}
}
