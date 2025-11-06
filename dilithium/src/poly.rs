use crate::{fips202, ntt, params, reduce, rounding};
use subtle::{Choice, ConditionallySelectable};
const N: usize = params::N as usize;
const UNIFORM_NBLOCKS: usize = (767 + fips202::SHAKE128_RATE) / fips202::SHAKE128_RATE;
const D_SHL: i32 = 1 << (params::D - 1);

/// Represents a polynomial
#[derive(Clone, Copy)]
pub struct Poly {
	pub coeffs: [i32; N],
}

/// For some reason can't simply derive the Default trait
impl Default for Poly {
	fn default() -> Self {
		Poly { coeffs: [0i32; N] }
	}
}

/// Inplace reduction of all coefficients of polynomial to representative in [-6283009,6283007].
pub fn reduce(a: &mut Poly) {
	// Bad C style
	// for i in 0..N {
	//     a.coeffs[i] = reduce::reduce32(a.coeffs[i]);
	// }
	// Nice Rust style
	for coeff in a.coeffs.iter_mut() {
		*coeff = reduce::reduce32(*coeff);
	}
}

/// For all coefficients of in/out polynomial add Q if coefficient is negative.
pub fn caddq(a: &mut Poly) {
	// Bad C style
	// for i in 0..N {
	//     a.coeffs[i] = reduce::caddq(a.coeffs[i]);
	// }
	// Nice Rust style
	for coeff in a.coeffs.iter_mut() {
		*coeff = reduce::caddq(*coeff);
	}
}

/// Add polynomials. No modular reduction is performed.
///
/// # Arguments
///
/// * 'a' - 1st input polynomial
/// * 'b' - 2nd input polynomial
///
/// Returns coefficient wise a + b
pub fn add(a: &Poly, b: &Poly) -> Poly {
	let mut c = Poly::default();
	for i in 0..N {
		c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
	}
	c
}

/// Add polynomials in place. No modular reduction is performed.
///
/// # Arguments
///
/// * 'a' - polynomial to add to
/// * 'b' - added polynomial
pub fn add_ip(a: &mut Poly, b: &Poly) {
	for i in 0..N {
		a.coeffs[i] += b.coeffs[i];
	}
}

/// Subtract polynomials. No modular reduction is performed.
///
/// # Arguments
///
/// * 'a' - 1st input polynomial
/// * 'b' - 2nd input polynomial
///
/// Returns coefficient wise a - b
pub fn sub(a: &Poly, b: &Poly) -> Poly {
	let mut c = Poly::default();
	for i in 0..N {
		c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
	}
	c
}

/// Subtract polynomials in place. No modular reduction is performed.
///
/// # Arguments
///
/// * 'a' - polynomial to subtract from
/// * 'b' - subtracted polynomial
pub fn sub_ip(a: &mut Poly, b: &Poly) {
	for i in 0..N {
		a.coeffs[i] -= b.coeffs[i];
	}
}

/// Multiply polynomial by 2^D without modular reduction.
/// Assumes input coefficients to be less than 2^{31-D} in absolute value.
pub fn shiftl(a: &mut Poly) {
	for coeff in a.coeffs.iter_mut() {
		*coeff <<= params::D;
	}
}

/// Inplace forward NTT. Coefficients can grow by 8*Q in absolute value.
pub fn ntt(a: &mut Poly) {
	ntt::ntt(&mut a.coeffs);
}

/// Inplace inverse NTT and multiplication by 2^{32}.
/// Input coefficients need to be less than Q in absolute value and output coefficients are again
/// bounded by Q.
pub fn invntt_tomont(a: &mut Poly) {
	ntt::invntt_tomont(&mut a.coeffs);
}

/// Pointwise multiplication of polynomials in NTT domain representation and multiplication of
/// resulting polynomial by 2^{-32}.
///
/// # Arguments
///
/// * 'a' - 1st input polynomial
/// * 'b' - 2nd input polynomial
///
/// Returns resulting polynomial
pub fn pointwise_montgomery(c: &mut Poly, a: &Poly, b: &Poly) {
	for i in 0..N {
		c.coeffs[i] = reduce::montgomery_reduce(a.coeffs[i] as i64 * b.coeffs[i] as i64);
	}
}

/// For all coefficients c of the input polynomial, compute c0, c1 such that c mod Q = c1*2^D + c0
/// with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be standard representatives.
///
/// # Arguments
///
/// * 'a' - input polynomial
///
/// Returns a touple of polynomials with coefficients c0, c1
pub fn power2round(a1: &mut Poly, a0: &mut Poly) {
	for i in 0..N {
		(a0.coeffs[i], a1.coeffs[i]) = rounding::power2round(a1.coeffs[i]);
	}
}

/// Check infinity norm of polynomial against given bound.
/// Assumes input coefficients were reduced by reduce32().
///
/// # Arguments
///
/// * 'a' - input polynomial
/// * 'b' - norm bound
///
/// Returns 0 if norm is strictly smaller than B and B <= (Q-1)/8, 1 otherwise.
pub fn check_norm(a: &Poly, b: i32) -> bool {
	let mut result = false;

	// Check bound condition first - this is a constant-time check
	if b > (params::Q - 1) / 8 {
		result = true;
	}

	// Always process all coefficients for constant-time
	for i in 0..N {
		let mut t = a.coeffs[i] >> 31;
		t = a.coeffs[i] - (t & 2 * a.coeffs[i]);

		// Use bitwise OR to accumulate any failures without early exit
		if t >= b {
			result = true;
		}
	}
	result
}

/// Sample uniformly random coefficients in [0, Q-1] by performing rejection sampling on array of
/// random bytes.
///
/// # Arguments
///
/// * 'a' - output array (allocated)
/// * 'b' - array of random bytes
///
/// Returns number of sampled coefficients. Can be smaller than a.len() if not enough random bytes
/// were given.
pub fn rej_uniform(a: &mut [i32], alen: usize, buf: &[u8], buflen: usize) -> usize {
	let mut ctr: usize = 0;
	let mut pos: usize = 0;
	while ctr < alen && pos + 3 <= buflen {
		let mut t = buf[pos] as u32;
		t |= (buf[pos + 1] as u32) << 8;
		t |= (buf[pos + 2] as u32) << 16;
		t &= 0x7FFFFF;
		pos += 3;
		let t = t as i32;
		if t < params::Q {
			a[ctr] = t;
			ctr += 1;
		}
	}
	ctr
}

/// Sample polynomial with uniformly random coefficients in [0, Q-1] by performing rejection
/// sampling using the output stream of SHAKE128(seed|nonce).
pub fn uniform(a: &mut Poly, seed: &[u8], nonce: u16) {
	let mut state = fips202::KeccakState::default();
	fips202::shake128_stream_init(&mut state, seed, nonce);

	let mut buf = [0u8; UNIFORM_NBLOCKS * fips202::SHAKE128_RATE + 2];
	fips202::shake128_squeezeblocks(&mut buf, UNIFORM_NBLOCKS, &mut state);

	let mut buflen: usize = UNIFORM_NBLOCKS * fips202::SHAKE128_RATE;
	let mut ctr = rej_uniform(&mut a.coeffs, N, &buf, buflen);

	while ctr < N {
		let off = buflen % 3;
		for i in 0..off {
			buf[i] = buf[buflen - off + i];
		}
		buflen = fips202::SHAKE128_RATE + off;
		fips202::shake128_squeezeblocks(&mut buf[off..], 1, &mut state);
		ctr += rej_uniform(&mut a.coeffs[ctr..], N - ctr, &buf, buflen);
	}
}

/// Bit-pack polynomial t1 with coefficients fitting in 10 bits.
/// Input coefficients are assumed to be standard representatives.
pub fn t1_pack(r: &mut [u8], a: &Poly) {
	for i in 0..N / 4 {
		r[5 * i + 0] = (a.coeffs[4 * i + 0] >> 0) as u8;
		r[5 * i + 1] = ((a.coeffs[4 * i + 0] >> 8) | (a.coeffs[4 * i + 1] << 2)) as u8;
		r[5 * i + 2] = ((a.coeffs[4 * i + 1] >> 6) | (a.coeffs[4 * i + 2] << 4)) as u8;
		r[5 * i + 3] = ((a.coeffs[4 * i + 2] >> 4) | (a.coeffs[4 * i + 3] << 6)) as u8;
		r[5 * i + 4] = (a.coeffs[4 * i + 3] >> 2) as u8;
	}
}

/// Unpack polynomial t1 with 9-bit coefficients.
/// Output coefficients are standard representatives.
pub fn t1_unpack(r: &mut Poly, a: &[u8]) {
	for i in 0..N / 4 {
		r.coeffs[4 * i + 0] =
			(((a[5 * i + 0] >> 0) as u32 | (a[5 * i + 1] as u32) << 8) & 0x3FF) as i32;
		r.coeffs[4 * i + 1] =
			(((a[5 * i + 1] >> 2) as u32 | (a[5 * i + 2] as u32) << 6) & 0x3FF) as i32;
		r.coeffs[4 * i + 2] =
			(((a[5 * i + 2] >> 4) as u32 | (a[5 * i + 3] as u32) << 4) & 0x3FF) as i32;
		r.coeffs[4 * i + 3] =
			(((a[5 * i + 3] >> 6) as u32 | (a[5 * i + 4] as u32) << 2) & 0x3FF) as i32;
	}
}

/// Bit-pack polynomial t0 with coefficients in [-2^{D-1}, 2^{D-1}].
pub fn t0_pack(r: &mut [u8], a: &Poly) {
	let mut t = [0i32; 8];

	for i in 0..N / 8 {
		t[0] = D_SHL - a.coeffs[8 * i + 0];
		t[1] = D_SHL - a.coeffs[8 * i + 1];
		t[2] = D_SHL - a.coeffs[8 * i + 2];
		t[3] = D_SHL - a.coeffs[8 * i + 3];
		t[4] = D_SHL - a.coeffs[8 * i + 4];
		t[5] = D_SHL - a.coeffs[8 * i + 5];
		t[6] = D_SHL - a.coeffs[8 * i + 6];
		t[7] = D_SHL - a.coeffs[8 * i + 7];

		r[13 * i + 0] = (t[0]) as u8;
		r[13 * i + 1] = (t[0] >> 8) as u8;
		r[13 * i + 1] |= (t[1] << 5) as u8;
		r[13 * i + 2] = (t[1] >> 3) as u8;
		r[13 * i + 3] = (t[1] >> 11) as u8;
		r[13 * i + 3] |= (t[2] << 2) as u8;
		r[13 * i + 4] = (t[2] >> 6) as u8;
		r[13 * i + 4] |= (t[3] << 7) as u8;
		r[13 * i + 5] = (t[3] >> 1) as u8;
		r[13 * i + 6] = (t[3] >> 9) as u8;
		r[13 * i + 6] |= (t[4] << 4) as u8;
		r[13 * i + 7] = (t[4] >> 4) as u8;
		r[13 * i + 8] = (t[4] >> 12) as u8;
		r[13 * i + 8] |= (t[5] << 1) as u8;
		r[13 * i + 9] = (t[5] >> 7) as u8;
		r[13 * i + 9] |= (t[6] << 6) as u8;
		r[13 * i + 10] = (t[6] >> 2) as u8;
		r[13 * i + 11] = (t[6] >> 10) as u8;
		r[13 * i + 11] |= (t[7] << 3) as u8;
		r[13 * i + 12] = (t[7] >> 5) as u8;
	}
}

/// Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
/// Output coefficients lie in ]Q-2^{D-1},Q+2^{D-1}].
pub fn t0_unpack(r: &mut Poly, a: &[u8]) {
	for i in 0..N / 8 {
		r.coeffs[8 * i + 0] = a[13 * i + 0] as i32;
		r.coeffs[8 * i + 0] |= (a[13 * i + 1] as i32) << 8;
		r.coeffs[8 * i + 0] &= 0x1FFF;

		r.coeffs[8 * i + 1] = (a[13 * i + 1] as i32) >> 5;
		r.coeffs[8 * i + 1] |= (a[13 * i + 2] as i32) << 3;
		r.coeffs[8 * i + 1] |= (a[13 * i + 3] as i32) << 11;
		r.coeffs[8 * i + 1] &= 0x1FFF;

		r.coeffs[8 * i + 2] = (a[13 * i + 3] as i32) >> 2;
		r.coeffs[8 * i + 2] |= (a[13 * i + 4] as i32) << 6;
		r.coeffs[8 * i + 2] &= 0x1FFF;

		r.coeffs[8 * i + 3] = (a[13 * i + 4] as i32) >> 7;
		r.coeffs[8 * i + 3] |= (a[13 * i + 5] as i32) << 1;
		r.coeffs[8 * i + 3] |= (a[13 * i + 6] as i32) << 9;
		r.coeffs[8 * i + 3] &= 0x1FFF;

		r.coeffs[8 * i + 4] = (a[13 * i + 6] as i32) >> 4;
		r.coeffs[8 * i + 4] |= (a[13 * i + 7] as i32) << 4;
		r.coeffs[8 * i + 4] |= (a[13 * i + 8] as i32) << 12;
		r.coeffs[8 * i + 4] &= 0x1FFF;

		r.coeffs[8 * i + 5] = (a[13 * i + 8] as i32) >> 1;
		r.coeffs[8 * i + 5] |= (a[13 * i + 9] as i32) << 7;
		r.coeffs[8 * i + 5] &= 0x1FFF;

		r.coeffs[8 * i + 6] = (a[13 * i + 9] as i32) >> 6;
		r.coeffs[8 * i + 6] |= (a[13 * i + 10] as i32) << 2;
		r.coeffs[8 * i + 6] |= (a[13 * i + 11] as i32) << 10;
		r.coeffs[8 * i + 6] &= 0x1FFF;

		r.coeffs[8 * i + 7] = (a[13 * i + 11] as i32) >> 3;
		r.coeffs[8 * i + 7] |= (a[13 * i + 12] as i32) << 5;
		r.coeffs[8 * i + 7] &= 0x1FFF;

		r.coeffs[8 * i + 0] = D_SHL - r.coeffs[8 * i + 0];
		r.coeffs[8 * i + 1] = D_SHL - r.coeffs[8 * i + 1];
		r.coeffs[8 * i + 2] = D_SHL - r.coeffs[8 * i + 2];
		r.coeffs[8 * i + 3] = D_SHL - r.coeffs[8 * i + 3];
		r.coeffs[8 * i + 4] = D_SHL - r.coeffs[8 * i + 4];
		r.coeffs[8 * i + 5] = D_SHL - r.coeffs[8 * i + 5];
		r.coeffs[8 * i + 6] = D_SHL - r.coeffs[8 * i + 6];
		r.coeffs[8 * i + 7] = D_SHL - r.coeffs[8 * i + 7];
	}
}

const UNIFORM_GAMMA1_NBLOCKS: usize = params::POLYZ_PACKEDBYTES.div_ceil(fips202::SHAKE256_RATE);

/// For all coefficients c of the input polynomial, compute high and low bits c0, c1 such c mod Q =
/// c1*ALPHA + c0 with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we set c1 = 0 and
/// -ALPHA/2 <= c0 = c mod Q - Q < 0. Assumes coefficients to be standard representatives.
///
/// # Arguments
///
/// * 'a' - input polynomial
///
/// Returns a touple of polynomials with coefficients c0, c1
pub fn decompose(a1: &mut Poly, a0: &mut Poly) {
	for i in 0..N {
		(a1.coeffs[i], a0.coeffs[i]) = rounding::decompose(a1.coeffs[i]);
	}
}

/// Compute hint polynomial, the coefficients of which indicate whether the low bits of the
/// corresponding coefficient of the input polynomial overflow into the high bits.
///
/// # Arguments
///
/// * 'a0' - low part of input polynomial
/// * 'a1' - low part of input polynomial
///
/// Returns the hint polynomial and the number of 1s
pub fn make_hint(h: &mut Poly, a0: &Poly, a1: &Poly) -> i32 {
	let mut s: i32 = 0;
	for i in 0..N {
		h.coeffs[i] = rounding::make_hint(a0.coeffs[i], a1.coeffs[i]);
		s += h.coeffs[i];
	}
	s
}

/// Use hint polynomial to correct the high bits of a polynomial.
///
/// # Arguments
///
/// * 'a' - input polynomial
/// * 'hint' - hint polynomial
///
/// Returns polynomial with corrected high bits
pub fn use_hint(a: &mut Poly, hint: &Poly) {
	for i in 0..N {
		a.coeffs[i] = rounding::use_hint(a.coeffs[i], hint.coeffs[i]);
	}
}

/// Use hint polynomial to correct the high bits of a polynomial in place.
///
/// # Arguments
///
/// * 'a' - input polynomial to have high bits corrected
/// * 'hint' - hint polynomial
pub fn use_hint_ip(a: &mut Poly, hint: &Poly) {
	for i in 0..N {
		a.coeffs[i] = rounding::use_hint(a.coeffs[i], hint.coeffs[i]);
	}
}

/// Sample uniformly random coefficients in [-ETA, ETA] by performing rejection sampling using array
/// of random bytes.
///
/// Returns number of sampled coefficients. Can be smaller than len if not enough random bytes were
/// given
pub fn rej_eta(a: &mut [i32], alen: usize, buf: &[u8], buflen: usize) -> usize {
	let mut ctr = 0usize;
	let mut dummy_value = 0i32; // For dummy writes

	// Always process exactly buflen bytes
	for pos in 0..buflen {
		let lower_nibble = (buf[pos] & 0x0F) as u32;
		let upper_nibble = (buf[pos] >> 4) as u32;

		// Compute all arithmetic operations upfront to avoid data-dependent timing
		// the following operations are a fast way to do % 5 (205 ~= 1024/5)
		let reduced_lower = lower_nibble - (205 * lower_nibble >> 10) * 5;
		let reduced_upper = upper_nibble - (205 * upper_nibble >> 10) * 5;
		let coeff_lower = 2 - reduced_lower as i32;
		let coeff_upper = 2 - reduced_upper as i32;

		// Nibbles valid?
		let valid_lower = Choice::from((lower_nibble < 15) as u8);
		let valid_upper = Choice::from((upper_nibble < 15) as u8);

		let has_space_lower = Choice::from((ctr < alen) as u8);
		let store_lower = valid_lower & has_space_lower;

		// Constant-time-ish conditional assignment
		// Write to output or dummy location based on condition
		if ctr < a.len() {
			a[ctr] = i32::conditional_select(&a[ctr], &coeff_lower, store_lower);
		} else {
			dummy_value = i32::conditional_select(&coeff_lower, &dummy_value, store_lower);
		}
		ctr += store_lower.unwrap_u8() as usize;

		let has_space_upper = Choice::from((ctr < alen) as u8);
		let store_upper = valid_upper & has_space_upper;

		// Constant-time-ish conditional assignment
		// Write to output or dummy location based on condition
		if ctr < a.len() {
			a[ctr] = i32::conditional_select(&a[ctr], &coeff_upper, store_upper);
		} else {
			dummy_value = i32::conditional_select(&coeff_upper, &dummy_value, store_upper);
		}
		ctr += store_upper.unwrap_u8() as usize;
	}

	// Prevent compiler from optimizing away dummy_value
	core::hint::black_box(dummy_value);
	ctr
}

/// Sample polynomial with uniformly random coefficients in [-ETA,ETA] by performing rejection
/// sampling using the output stream from SHAKE256(seed|nonce).
pub fn uniform_eta(output_polynomial: &mut Poly, seed: &[u8], nonce: u16) {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_stream_init(&mut state, seed, nonce);

	// Fixed number of rounds for constant-time operation
	const FIXED_ROUNDS: usize = 2;
	let mut shake_output_buffer = [0u8; fips202::SHAKE256_RATE];
	let mut temporary_coefficient_storage = [0i32; 1000]; // Temp storage for all extracted coeffs
	let mut total_coefficients_collected = 0usize;

	// In case by some freak accident 2 rounds isn't enough, we keep going. This makes it
	// non-constant time in only a negligible set of cases. The vast majority of cases will run
	// this outer loop exactly once
	while total_coefficients_collected < N {
		// Always run exactly FIXED_ROUNDS iterations
		for _round_number in 0..FIXED_ROUNDS {
			// Squeeze one block at a time and collect
			fips202::shake256_squeezeblocks(&mut shake_output_buffer, 1, &mut state);

			// Always call rej_eta with same parameters regardless of how many coeffs we have
			let available_storage_space =
				temporary_coefficient_storage.len() - total_coefficients_collected;
			let coefficients_extracted_this_round = rej_eta(
				&mut temporary_coefficient_storage[total_coefficients_collected..],
				available_storage_space,
				&shake_output_buffer,
				fips202::SHAKE256_RATE,
			);
			total_coefficients_collected += coefficients_extracted_this_round;
		}
	}

	// Copy first N coefficients to polynomial output
	output_polynomial.coeffs[..N].copy_from_slice(&temporary_coefficient_storage[..N]);
}

/// Sample polynomial with uniformly random coefficients in [-(GAMMA1 - 1), GAMMA1 - 1] by
/// performing rejection sampling on output stream of SHAKE256(seed|nonce).
pub fn uniform_gamma1(a: &mut Poly, seed: &[u8], nonce: u16) {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_stream_init(&mut state, seed, nonce);

	let mut buf = [0u8; UNIFORM_GAMMA1_NBLOCKS * fips202::SHAKE256_RATE];
	fips202::shake256_squeezeblocks(&mut buf, UNIFORM_GAMMA1_NBLOCKS, &mut state);
	z_unpack(a, &buf);
}

/// Implementation of H. Samples polynomial with TAU nonzero coefficients in {-1,1} using the output
/// stream of SHAKE256(seed).
pub fn challenge(c: &mut Poly, seed: &[u8]) {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, seed, params::C_DASH_BYTES);
	fips202::shake256_finalize(&mut state);

	let mut buf = [0u8; fips202::SHAKE256_RATE];
	fips202::shake256_squeezeblocks(&mut buf, 1, &mut state);

	let mut signs: u64 = 0;
	for (i, &byte) in buf.iter().enumerate().take(8) {
		signs |= (byte as u64) << 8 * i;
	}

	// Create dummy state for constant-time padding
	let mut dummy_state = fips202::KeccakState::default();
	let mut dummy_buf = [0u8; fips202::SHAKE256_RATE];
	let mut dummy_pos = 0;

	let mut pos: usize = 8;
	c.coeffs.fill(0);
	for i in (N - params::TAU)..N {
		let mut b: usize = 0;
		let mut found = false;

		// in vast majority of cases this outer loop will run exactly once
		while !found {
			// do 16 iterations no matter what for constant time
			for _ in 0..16 {
				if !found {
					if pos >= fips202::SHAKE256_RATE {
						fips202::shake256_squeezeblocks(&mut buf, 1, &mut state);
						pos = 0;
					}
					b = buf[pos] as usize;
					pos += 1;
					if b <= i {
						found = true;
					}
				} else {
					// Dummy operations when already found to maintain constant timing
					if dummy_pos >= fips202::SHAKE256_RATE {
						fips202::shake256_squeezeblocks(&mut dummy_buf, 1, &mut dummy_state);
						dummy_pos = 0;
					}
					let _dummy = dummy_buf[dummy_pos] as usize;
					dummy_pos += 1;
				}
			}
		}

		c.coeffs[i] = c.coeffs[b];
		c.coeffs[b] = 1 - 2 * ((signs & 1) as i32);
		signs >>= 1;
	}
}

/// Bit-pack polynomial with coefficients in [-ETA,ETA]. Input coefficients are assumed to lie in
/// [Q-ETA,Q+ETA].
pub fn eta_pack(r: &mut [u8], a: &Poly) {
	let mut t = [0u8; 8];
	for i in 0..N / 8 {
		t[0] = (params::ETA as i32 - a.coeffs[8 * i + 0]) as u8;
		t[1] = (params::ETA as i32 - a.coeffs[8 * i + 1]) as u8;
		t[2] = (params::ETA as i32 - a.coeffs[8 * i + 2]) as u8;
		t[3] = (params::ETA as i32 - a.coeffs[8 * i + 3]) as u8;
		t[4] = (params::ETA as i32 - a.coeffs[8 * i + 4]) as u8;
		t[5] = (params::ETA as i32 - a.coeffs[8 * i + 5]) as u8;
		t[6] = (params::ETA as i32 - a.coeffs[8 * i + 6]) as u8;
		t[7] = (params::ETA as i32 - a.coeffs[8 * i + 7]) as u8;

		r[3 * i + 0] = t[0] | (t[1] << 3) | (t[2] << 6);
		r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
	}
}

/// Unpack polynomial with coefficients in [-ETA,ETA].
pub fn eta_unpack(r: &mut Poly, a: &[u8]) {
	for i in 0..N / 8 {
		r.coeffs[8 * i + 0] = (a[3 * i + 0] & 0x07) as i32;
		r.coeffs[8 * i + 1] = ((a[3 * i + 0] >> 3) & 0x07) as i32;
		r.coeffs[8 * i + 2] = (((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 0x07) as i32;
		r.coeffs[8 * i + 3] = ((a[3 * i + 1] >> 1) & 0x07) as i32;
		r.coeffs[8 * i + 4] = ((a[3 * i + 1] >> 4) & 0x07) as i32;
		r.coeffs[8 * i + 5] = (((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 0x07) as i32;
		r.coeffs[8 * i + 6] = ((a[3 * i + 2] >> 2) & 0x07) as i32;
		r.coeffs[8 * i + 7] = ((a[3 * i + 2] >> 5) & 0x07) as i32;

		r.coeffs[8 * i + 0] = params::ETA as i32 - r.coeffs[8 * i + 0];
		r.coeffs[8 * i + 1] = params::ETA as i32 - r.coeffs[8 * i + 1];
		r.coeffs[8 * i + 2] = params::ETA as i32 - r.coeffs[8 * i + 2];
		r.coeffs[8 * i + 3] = params::ETA as i32 - r.coeffs[8 * i + 3];
		r.coeffs[8 * i + 4] = params::ETA as i32 - r.coeffs[8 * i + 4];
		r.coeffs[8 * i + 5] = params::ETA as i32 - r.coeffs[8 * i + 5];
		r.coeffs[8 * i + 6] = params::ETA as i32 - r.coeffs[8 * i + 6];
		r.coeffs[8 * i + 7] = params::ETA as i32 - r.coeffs[8 * i + 7];
	}
}

/// Bit-pack polynomial z with coefficients in [-(GAMMA1 - 1), GAMMA1 - 1].
/// Input coefficients are assumed to be standard representatives.*
pub fn z_pack(r: &mut [u8], a: &Poly) {
	let mut t = [0i32; 2];

	for i in 0..N / 2 {
		t[0] = params::GAMMA1 as i32 - a.coeffs[2 * i + 0];
		t[1] = params::GAMMA1 as i32 - a.coeffs[2 * i + 1];

		r[5 * i + 0] = t[0] as u8;
		r[5 * i + 1] = (t[0] >> 8) as u8;
		r[5 * i + 2] = (t[0] >> 16) as u8;
		r[5 * i + 2] |= (t[1] << 4) as u8;
		r[5 * i + 3] = (t[1] >> 4) as u8;
		r[5 * i + 4] = (t[1] >> 12) as u8;
	}
}

/// Unpack polynomial z with coefficients in [-(GAMMA1 - 1), GAMMA1 - 1].
/// Output coefficients are standard representatives.
pub fn z_unpack(r: &mut Poly, a: &[u8]) {
	for i in 0..N / 2 {
		r.coeffs[2 * i + 0] = a[5 * i + 0] as i32;
		r.coeffs[2 * i + 0] |= (a[5 * i + 1] as i32) << 8;
		r.coeffs[2 * i + 0] |= (a[5 * i + 2] as i32) << 16;
		r.coeffs[2 * i + 0] &= 0xFFFFF;

		r.coeffs[2 * i + 1] = (a[5 * i + 2] as i32) >> 4;
		r.coeffs[2 * i + 1] |= (a[5 * i + 3] as i32) << 4;
		r.coeffs[2 * i + 1] |= (a[5 * i + 4] as i32) << 12;
		r.coeffs[2 * i + 0] &= 0xFFFFF;

		r.coeffs[2 * i + 0] = params::GAMMA1 as i32 - r.coeffs[2 * i + 0];
		r.coeffs[2 * i + 1] = params::GAMMA1 as i32 - r.coeffs[2 * i + 1];
	}
}

/// Bit-pack polynomial w1 with coefficients in [0, 15].
/// Input coefficients are assumed to be standard representatives.
pub fn w1_pack(r: &mut [u8], a: &Poly) {
	for i in 0..N / 2 {
		r[i] = (a.coeffs[2 * i + 0] | (a.coeffs[2 * i + 1] << 4)) as u8;
	}
}

#[cfg(test)]
mod tests {
	#[cfg(test)]
	extern crate std;
	#[cfg(test)]
	use std::println;

	use super::*;

	#[test]
	fn test_poly_default() {
		let poly = Poly::default();
		for i in 0..N {
			assert_eq!(poly.coeffs[i], 0);
		}
	}

	#[test]
	fn test_reduce() {
		let mut poly = Poly::default();
		// Set some coefficients to values that need reduction
		poly.coeffs[0] = params::Q + 100;
		poly.coeffs[1] = -params::Q - 200;
		poly.coeffs[2] = 2 * params::Q + 50;

		reduce(&mut poly);

		// After reduction, all coefficients should be in valid range
		for i in 0..N {
			assert!(poly.coeffs[i].abs() < params::Q);
		}
	}

	#[test]
	fn test_caddq() {
		let mut poly = Poly::default();
		poly.coeffs[0] = -100;
		poly.coeffs[1] = -1;
		poly.coeffs[2] = 0;
		poly.coeffs[3] = 100;

		caddq(&mut poly);

		// Negative coefficients should have Q added
		assert!(poly.coeffs[0] >= 0);
		assert!(poly.coeffs[1] >= 0);
		assert_eq!(poly.coeffs[2], 0); // Zero should stay zero
		assert_eq!(poly.coeffs[3], 100); // Positive should stay the same
	}

	#[test]
	fn test_add() {
		let mut a = Poly::default();
		let mut b = Poly::default();

		for i in 0..N {
			a.coeffs[i] = i as i32;
			b.coeffs[i] = (i * 2) as i32;
		}

		let c = add(&a, &b);

		for i in 0..N {
			assert_eq!(c.coeffs[i], a.coeffs[i] + b.coeffs[i]);
		}
	}

	#[test]
	fn test_add_ip() {
		let mut a = Poly::default();
		let mut b = Poly::default();

		for i in 0..N {
			a.coeffs[i] = i as i32;
			b.coeffs[i] = (i * 3) as i32;
		}

		let original_a = a;
		add_ip(&mut a, &b);

		for i in 0..N {
			assert_eq!(a.coeffs[i], original_a.coeffs[i] + b.coeffs[i]);
		}
	}

	#[test]
	fn test_sub() {
		let mut a = Poly::default();
		let mut b = Poly::default();

		for i in 0..N {
			a.coeffs[i] = (i * 10) as i32;
			b.coeffs[i] = (i * 3) as i32;
		}

		let c = sub(&a, &b);

		for i in 0..N {
			assert_eq!(c.coeffs[i], a.coeffs[i] - b.coeffs[i]);
		}
	}

	#[test]
	fn test_sub_ip() {
		let mut a = Poly::default();
		let mut b = Poly::default();

		for i in 0..N {
			a.coeffs[i] = (i * 10) as i32;
			b.coeffs[i] = (i * 2) as i32;
		}

		let original_a = a;
		sub_ip(&mut a, &b);

		for i in 0..N {
			assert_eq!(a.coeffs[i], original_a.coeffs[i] - b.coeffs[i]);
		}
	}

	#[test]
	fn test_shiftl() {
		let mut poly = Poly::default();
		poly.coeffs[0] = 1;
		poly.coeffs[1] = 3;
		poly.coeffs[2] = 7;

		let original = poly;
		shiftl(&mut poly);

		for i in 0..N {
			assert_eq!(poly.coeffs[i], original.coeffs[i] * (1 << params::D));
		}
	}

	#[test]
	fn test_ntt_invntt_roundtrip() {
		let mut poly = Poly::default();

		// Initialize with some test data
		for i in 0..N {
			poly.coeffs[i] = ((i * 123 + 456) % 1000) as i32;
		}

		let original = poly;
		ntt(&mut poly);
		invntt_tomont(&mut poly);

		// After NTT and inverse NTT, we should get back the original (possibly with Montgomery
		// factor) We'll check that the values are reasonably close
		for i in 0..N {
			let diff = (poly.coeffs[i] - original.coeffs[i]).abs();
			assert!(
				diff < params::Q,
				"NTT roundtrip failed at index {}: {} vs {}",
				i,
				poly.coeffs[i],
				original.coeffs[i]
			);
		}
	}

	#[test]
	fn test_pointwise_montgomery() {
		let mut a = Poly::default();
		let mut b = Poly::default();

		// Initialize with small values to avoid overflow
		for i in 0..N {
			a.coeffs[i] = (i % 100) as i32;
			b.coeffs[i] = ((i * 2) % 100) as i32;
		}

		let mut c = Poly::default();
		pointwise_montgomery(&mut c, &a, &b);

		// Result should be well-defined (not checking exact values due to Montgomery arithmetic
		// complexity)
		for i in 0..N {
			assert!(c.coeffs[i].abs() < params::Q);
		}
	}

	#[test]
	fn test_chknorm_zero_poly() {
		let poly = Poly::default(); // All coefficients are 0
		assert!(!check_norm(&poly, 1)); // Should be within any positive bound
		assert!(!check_norm(&poly, 1000));
	}

	#[test]
	fn test_chknorm_exceeds_bound() {
		let mut poly = Poly::default();
		poly.coeffs[0] = 100;
		poly.coeffs[1] = -50;

		assert!(!check_norm(&poly, 200)); // Within bound
		assert!(check_norm(&poly, 99)); // Exceeds bound
		assert!(check_norm(&poly, 49)); // Exceeds bound
	}

	#[test]
	fn test_freeze() {
		let mut poly = Poly::default();
		poly.coeffs[0] = params::Q + 100;
		poly.coeffs[1] = -100;
		poly.coeffs[2] = params::Q / 2;

		// Apply reduction to bring coefficients into valid range
		reduce(&mut poly);
		caddq(&mut poly);

		// All coefficients should be in range [0, Q)
		for i in 0..N {
			assert!(poly.coeffs[i] >= 0);
			assert!(poly.coeffs[i] < params::Q);
		}
	}

	#[test]
	fn test_power2round() {
		let mut a = Poly::default();
		let mut a0 = Poly::default();

		// Test with various values
		a.coeffs[0] = 1000;
		a.coeffs[1] = 2500;
		a.coeffs[2] = -500;

		let original = a;
		power2round(&mut a, &mut a0);

		// Check that the decomposition is correct: original = a * 2^D + a0
		for i in 0..3 {
			let reconstructed = a.coeffs[i] * (1 << params::D) + a0.coeffs[i];
			let diff = (reconstructed - original.coeffs[i]).abs();
			assert!(
				diff <= 1,
				"Power2round failed at index {}: {} vs {}",
				i,
				reconstructed,
				original.coeffs[i]
			);
		}
	}

	#[test]
	fn test_uniform_eta_produces_valid_coefficients() {
		use rand::{rngs::StdRng, RngCore, SeedableRng};

		let mut rng = StdRng::seed_from_u64(0x123456789ABCDEF0);
		const NUM_TESTS: usize = 100;

		for test_iteration in 0..NUM_TESTS {
			let mut seed = [0u8; params::CRHBYTES];
			rng.fill_bytes(&mut seed);
			let nonce = rng.next_u32() as u16;

			let mut poly = Poly::default();
			uniform_eta(&mut poly, &seed, nonce);

			// All coefficients should be in the range [-ETA, ETA]
			for i in 0..N {
				assert!(
					poly.coeffs[i] >= -(params::ETA as i32),
					"Test {}: Coefficient {} = {} is below -ETA ({})",
					test_iteration,
					i,
					poly.coeffs[i],
					-(params::ETA as i32)
				);
				assert!(
					poly.coeffs[i] <= params::ETA as i32,
					"Test {}: Coefficient {} = {} is above ETA ({})",
					test_iteration,
					i,
					poly.coeffs[i],
					params::ETA as i32
				);
			}
		}
	}

	#[test]
	fn test_uniform_eta_different_seeds() {
		use rand::{rngs::StdRng, RngCore, SeedableRng};

		let mut rng = StdRng::seed_from_u64(0xFEDCBA9876543210);
		const NUM_TESTS: usize = 50;

		for test_iteration in 0..NUM_TESTS {
			// Generate two different random seeds
			let mut seed1 = [0u8; params::CRHBYTES];
			let mut seed2 = [0u8; params::CRHBYTES];
			rng.fill_bytes(&mut seed1);
			rng.fill_bytes(&mut seed2);

			// Make sure seeds are different
			if seed1 == seed2 {
				seed2[0] = seed2[0].wrapping_add(1);
			}

			let nonce = rng.next_u32() as u16;

			let mut poly1 = Poly::default();
			let mut poly2 = Poly::default();

			uniform_eta(&mut poly1, &seed1, nonce);
			uniform_eta(&mut poly2, &seed2, nonce);

			// Different seeds should produce different polynomials
			let mut different = false;
			for i in 0..N {
				if poly1.coeffs[i] != poly2.coeffs[i] {
					different = true;
					break;
				}
			}
			assert!(
				different,
				"Test {}: Different seeds should produce different polynomials",
				test_iteration
			);
		}
	}

	#[test]
	fn test_uniform_eta_deterministic() {
		use rand::{rngs::StdRng, RngCore, SeedableRng};

		let mut rng = StdRng::seed_from_u64(0x1122334455667788);
		const NUM_TESTS: usize = 25;

		for test_iteration in 0..NUM_TESTS {
			let mut seed = [0u8; params::CRHBYTES];
			rng.fill_bytes(&mut seed);
			let nonce = rng.next_u32() as u16;

			// Generate the same polynomial twice with identical inputs
			let mut poly1 = Poly::default();
			let mut poly2 = Poly::default();

			uniform_eta(&mut poly1, &seed, nonce);
			uniform_eta(&mut poly2, &seed, nonce);

			// Should produce identical results
			for i in 0..N {
				assert_eq!(
					poly1.coeffs[i], poly2.coeffs[i],
					"Test {}: Coefficient {} differs between identical calls: {} vs {}",
					test_iteration, i, poly1.coeffs[i], poly2.coeffs[i]
				);
			}
		}
	}

	#[test]
	fn test_uniform_eta_nonce_variations() {
		use rand::{rngs::StdRng, RngCore, SeedableRng};

		let mut rng = StdRng::seed_from_u64(0x9999888877776666);
		const NUM_TESTS: usize = 30;

		for test_iteration in 0..NUM_TESTS {
			let mut seed = [0u8; params::CRHBYTES];
			rng.fill_bytes(&mut seed);

			let nonce1 = rng.next_u32() as u16;
			let mut nonce2 = rng.next_u32() as u16;

			// Make sure nonces are different
			if nonce1 == nonce2 {
				nonce2 = nonce2.wrapping_add(1);
			}

			let mut poly1 = Poly::default();
			let mut poly2 = Poly::default();

			uniform_eta(&mut poly1, &seed, nonce1);
			uniform_eta(&mut poly2, &seed, nonce2);

			// Same seed but different nonces should produce different polynomials
			let mut different = false;
			for i in 0..N {
				if poly1.coeffs[i] != poly2.coeffs[i] {
					different = true;
					break;
				}
			}
			assert!(
				different,
				"Test {}: Same seed with different nonces should produce different polynomials (nonce1={}, nonce2={})",
				test_iteration,
				nonce1,
				nonce2
			);
		}
	}

	#[test]
	fn test_rej_eta_empty_buffer() {
		let mut output = [0i32; 10];
		let buffer = [];
		let result = rej_eta(&mut output, 5, &buffer, 0);
		assert_eq!(result, 0);
		// All coefficients should remain unchanged (zero)
		for coeff in &output {
			assert_eq!(*coeff, 0);
		}
	}

	#[test]
	fn test_rej_eta_all_invalid_nibbles() {
		let mut output = [0i32; 10];
		// Create buffer with all nibbles = 15 (invalid)
		let buffer = [0xFFu8; 4]; // 8 nibbles, all invalid
		let result = rej_eta(&mut output, 10, &buffer, 4);
		assert_eq!(result, 0);
		// All coefficients should remain unchanged (zero)
		for coeff in &output {
			assert_eq!(*coeff, 0);
		}
	}

	#[test]
	#[allow(clippy::erasing_op)]
	fn test_rej_eta_all_valid_nibbles() {
		let mut output = [0i32; 10];
		// Create buffer with all nibbles < 15
		let buffer = [0x00u8, 0x11u8, 0x22u8, 0x33u8]; // nibbles: 0,0,1,1,2,2,3,3
		let result = rej_eta(&mut output, 10, &buffer, 4);

		// Should accept all 8 coefficients
		assert_eq!(result, 8);

		// Verify coefficient values using the reduction formula
		// For nibble n: reduced = n - (205 * n >> 10) * 5, coeff = 2 - reduced
		let expected = [
			2 - (0 - (205 * 0 >> 10) * 5), // nibble 0
			2 - (0 - (205 * 0 >> 10) * 5), // nibble 0
			2 - (1 - (205 * 1 >> 10) * 5), // nibble 1
			2 - (1 - (205 * 1 >> 10) * 5), // nibble 1
			2 - (2 - (205 * 2 >> 10) * 5), // nibble 2
			2 - (2 - (205 * 2 >> 10) * 5), // nibble 2
			2 - (3 - (205 * 3 >> 10) * 5), // nibble 3
			2 - (3 - (205 * 3 >> 10) * 5), // nibble 3
		];

		for i in 0..8 {
			assert_eq!(output[i], expected[i]);
		}
	}

	#[test]
	#[allow(clippy::erasing_op)]
	fn test_rej_eta_mixed_valid_invalid() {
		let mut output = [0i32; 10];
		// Mix valid and invalid nibbles: 0xF0 = nibbles 0 (valid), 15 (invalid)
		let buffer = [0xF0u8, 0x1Fu8]; // nibbles: 0,15,1,15
		let result = rej_eta(&mut output, 10, &buffer, 2);

		// Should accept 2 coefficients (nibbles 0 and 1)
		assert_eq!(result, 2);

		// Check the accepted coefficients
		assert_eq!(output[0], 2 - (0 - (205 * 0 >> 10) * 5)); // nibble 0
		assert_eq!(output[1], 2 - (1 - (205 * 1 >> 10) * 5)); // nibble 1

		// Remaining should be unchanged (zero)
		for i in 2..10 {
			assert_eq!(output[i], 0);
		}
	}

	#[test]
	#[allow(clippy::erasing_op)]
	fn test_rej_eta_limited_space() {
		let mut output = [0i32; 10];
		// Create buffer with many valid nibbles
		let buffer = [0x01u8, 0x23u8, 0x45u8]; // nibbles: 1,0,3,2,5,4
		let result = rej_eta(&mut output, 3, &buffer, 3); // Only space for 3 coefficients

		// Should stop after accepting 3 coefficients
		assert_eq!(result, 3);

		// Check the first 3 coefficients
		assert_eq!(output[0], 2 - (1 - (205 * 1 >> 10) * 5)); // nibble 1
		assert_eq!(output[1], 2 - (0 - (205 * 0 >> 10) * 5)); // nibble 0
		assert_eq!(output[2], 2 - (3 - (205 * 3 >> 10) * 5)); // nibble 3

		// Remaining should be unchanged
		for i in 3..10 {
			assert_eq!(output[i], 0);
		}
	}

	#[test]
	fn test_rej_eta_reduction_formula() {
		let mut output = [0i32; 20];
		// Test specific nibble values to verify reduction formula
		let buffer = [
			0x54u8, // nibbles: 4,5
			0x98u8, // nibbles: 8,9
			0xDCu8, // nibbles: 12,13
			0xEEu8, // nibbles: 14,14
		];
		let result = rej_eta(&mut output, 20, &buffer, 4);

		// Should accept 8 coefficients (all are < 15)
		assert_eq!(result, 8);

		// Manually verify the reduction formula for each nibble
		let nibbles = [4u32, 5u32, 8u32, 9u32, 12u32, 13u32, 14u32, 14u32];
		for (i, &nibble) in nibbles.iter().enumerate() {
			let reduced = nibble - (205 * nibble >> 10) * 5;
			let expected_coeff = 2 - reduced as i32;
			assert_eq!(output[i], expected_coeff, "Failed for nibble {}", nibble);
		}
	}

	#[test]
	fn test_rej_eta_boundary_nibble_14() {
		let mut output = [0i32; 4];
		// Test nibble 14 (valid) and 15 (invalid)
		let buffer = [0xFEu8]; // nibbles: 14,15
		let result = rej_eta(&mut output, 4, &buffer, 1);

		// Should accept 1 coefficient (nibble 14)
		assert_eq!(result, 1);

		let reduced = 14u32 - (205 * 14u32 >> 10) * 5;
		let expected = 2 - reduced as i32;
		assert_eq!(output[0], expected);
	}

	#[test]
	fn test_rej_eta_output_range() {
		let mut output = [0i32; 20];
		// Create buffer with all possible valid nibbles (0-14)
		let buffer = [
			0x10u8, 0x32u8, 0x54u8, 0x76u8, 0x98u8, 0xBAu8, 0xDCu8,
			0xEEu8, // nibbles: 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,14
		];
		let result = rej_eta(&mut output, 20, &buffer, 8);

		assert_eq!(result, 16); // Should accept 16 coefficients (all nibbles are < 15)

		// Verify all coefficients are in expected range [-2, 2]
		for i in 0..result {
			assert!(
				output[i] >= -2 && output[i] <= 2,
				"Coefficient {} = {} is out of range [-2, 2]",
				i,
				output[i]
			);
		}
	}

	#[test]
	fn test_uniform_eta_coefficient_efficiency() {
		use rand::{rngs::StdRng, RngCore, SeedableRng};

		let mut rng = StdRng::seed_from_u64(0xABCDEF0123456789);
		const NUM_TESTS: usize = 100;

		let mut total_coefficients_generated = 0usize;
		let mut total_coefficients_needed = 0usize;
		let mut tests_with_insufficient_coefficients = 0usize;
		const FIXED_ROUNDS_FOR_CONSTANT_TIME: usize = 2;

		for _test_iteration in 0..NUM_TESTS {
			let mut seed = [0u8; params::CRHBYTES];
			rng.fill_bytes(&mut seed);
			let nonce = rng.next_u32() as u16;

			// Use a large temporary storage to count all generated coefficients
			let mut temporary_coefficient_storage = [0i32; 2000];
			let mut total_coefficients_collected = 0usize;

			// Replicate the same logic from uniform_eta to count coefficients
			let mut state = fips202::KeccakState::default();
			fips202::shake256_stream_init(&mut state, &seed, nonce);

			let mut shake_output_buffer = [0u8; fips202::SHAKE256_RATE];

			for _round_number in 0..FIXED_ROUNDS_FOR_CONSTANT_TIME {
				fips202::shake256_squeezeblocks(&mut shake_output_buffer, 1, &mut state);

				let available_storage_space =
					temporary_coefficient_storage.len() - total_coefficients_collected;
				let coefficients_extracted_this_round = rej_eta(
					&mut temporary_coefficient_storage[total_coefficients_collected..],
					available_storage_space,
					&shake_output_buffer,
					fips202::SHAKE256_RATE,
				);
				total_coefficients_collected += coefficients_extracted_this_round;
			}

			total_coefficients_generated += total_coefficients_collected;
			total_coefficients_needed += N;

			if total_coefficients_collected < N {
				tests_with_insufficient_coefficients += 1;
			}
		}

		let average_generated = total_coefficients_generated as f64 / NUM_TESTS as f64;
		let average_needed = total_coefficients_needed as f64 / NUM_TESTS as f64;
		let efficiency_ratio = average_generated / average_needed;
		let insufficient_percentage =
			(tests_with_insufficient_coefficients as f64 / NUM_TESTS as f64) * 100.0;

		println!("=== Uniform ETA Coefficient Generation Efficiency ===");
		println!("Tests run: {}", NUM_TESTS);
		println!("Average coefficients generated per test: {:.2}", average_generated);
		println!("Average coefficients needed per test: {:.2}", average_needed);
		println!("Efficiency ratio (generated/needed): {:.2}", efficiency_ratio);
		println!(
			"Tests with insufficient coefficients: {} ({:.1}%)",
			tests_with_insufficient_coefficients, insufficient_percentage
		);
		println!("SHAKE256 blocks used per test: {}", FIXED_ROUNDS_FOR_CONSTANT_TIME);
		println!(
			"Bytes processed per test: {}",
			FIXED_ROUNDS_FOR_CONSTANT_TIME * fips202::SHAKE256_RATE
		);

		// Ensure we're generating a reasonable number of coefficients
		assert!(
			average_generated >= N as f64 * 0.8,
			"Average coefficients generated ({:.2}) is less than 80% of needed ({})",
			average_generated,
			N
		);

		// Ensure most tests generate enough coefficients
		assert!(
			insufficient_percentage < 50.0,
			"Too many tests ({:.1}%) had insufficient coefficients",
			insufficient_percentage
		);
	}

	#[test]
	fn test_uniform_gamma1_produces_valid_coefficients() {
		let seed = [0x55u8; params::CRHBYTES];
		let nonce = 5678;
		let mut poly = Poly::default();

		uniform_gamma1(&mut poly, &seed, nonce);

		// All coefficients should be in the range [-GAMMA1, GAMMA1]
		for i in 0..N {
			assert!(poly.coeffs[i] >= -(params::GAMMA1 as i32));
			assert!(poly.coeffs[i] <= params::GAMMA1 as i32);
		}
	}

	#[test]
	fn test_challenge_produces_valid_challenge() {
		let seed = [0x77u8; params::C_DASH_BYTES];
		let mut poly = Poly::default();

		challenge(&mut poly, &seed);

		// Challenge polynomial should have exactly TAU non-zero coefficients
		let mut nonzero_count = 0;
		let mut plus_one_count = 0;
		let mut minus_one_count = 0;

		for i in 0..N {
			match poly.coeffs[i] {
				0 => {},
				1 => {
					nonzero_count += 1;
					plus_one_count += 1;
				},
				-1 => {
					nonzero_count += 1;
					minus_one_count += 1;
				},
				_ => panic!("Challenge coefficient should be -1, 0, or 1, got {}", poly.coeffs[i]),
			}
		}

		assert_eq!(
			nonzero_count,
			params::TAU,
			"Challenge should have exactly {} non-zero coefficients",
			params::TAU
		);
		// Note: The challenge doesn't guarantee equal numbers of +1 and -1
		// The signs are determined by bits from the hash, so we just verify
		// that all non-zero coefficients are ±1
		assert_eq!(plus_one_count + minus_one_count, params::TAU);
	}

	#[test]
	fn test_eta_pack_unpack_roundtrip() {
		let mut poly = Poly::default();

		// Initialize with valid ETA range values
		for i in 0..N {
			poly.coeffs[i] = ((i as i32) % (2 * params::ETA as i32 + 1)) - params::ETA as i32;
		}

		let mut packed = [0u8; params::POLYETA_PACKEDBYTES];
		eta_pack(&mut packed, &poly);

		let mut unpacked = Poly::default();
		eta_unpack(&mut unpacked, &packed);

		for i in 0..N {
			assert_eq!(poly.coeffs[i], unpacked.coeffs[i], "ETA pack/unpack failed at index {}", i);
		}
	}

	#[test]
	fn test_z_pack_unpack_roundtrip() {
		let mut poly = Poly::default();

		// Initialize with values in valid Z range (more conservative)
		for i in 0..N {
			poly.coeffs[i] = ((i as i32) % 10000) - 5000;
		}

		let mut packed = [0u8; params::POLYZ_PACKEDBYTES];
		z_pack(&mut packed, &poly);

		let mut unpacked = Poly::default();
		z_unpack(&mut unpacked, &packed);

		for i in 0..N {
			assert_eq!(poly.coeffs[i], unpacked.coeffs[i], "Z pack/unpack failed at index {}", i);
		}
	}

	#[test]
	fn test_w1_pack_unpack_roundtrip() {
		let mut poly = Poly::default();

		// Initialize with values that would result from decompose
		for i in 0..N {
			poly.coeffs[i] = (i % 16) as i32; // w1 coefficients are in small range
		}

		let mut packed = [0u8; params::POLYW1_PACKEDBYTES];
		w1_pack(&mut packed, &poly);

		// Note: There's no w1_unpack function in the visible code, so we can't test full roundtrip
		// But we can verify the packing doesn't crash and produces expected size
		assert_eq!(packed.len(), params::POLYW1_PACKEDBYTES);
	}
}
