use super::{Poly, N};
use crate::{fips202, params, rounding};
use subtle::{Choice, ConditionallySelectable};

const UNIFORM_ETA_NBLOCKS: usize = (135 + fips202::SHAKE256_RATE) / fips202::SHAKE256_RATE;
const UNIFORM_GAMMA1_NBLOCKS: usize =
	params::lvl5::POLYZ_PACKEDBYTES.div_ceil(fips202::SHAKE256_RATE);

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
		(a1.coeffs[i], a0.coeffs[i]) = rounding::lvl5::decompose(a1.coeffs[i]);
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
		h.coeffs[i] = rounding::lvl5::make_hint(a0.coeffs[i], a1.coeffs[i]);
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
		a.coeffs[i] = rounding::lvl5::use_hint(a.coeffs[i], hint.coeffs[i]);
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
		a.coeffs[i] = rounding::lvl5::use_hint(a.coeffs[i], hint.coeffs[i]);
	}
}

/// Sample uniformly random coefficients in [-ETA, ETA] by performing rejection sampling using array
/// of random bytes. CONSTANT-TIME version using subtle crate.
///
/// Returns number of sampled coefficients. Can be smaller than len if not enough random bytes were
/// given
pub fn rej_eta(
	output_coeffs: &mut [i32],
	needed_count: usize,
	random_bytes: &[u8],
	bytes_available: usize,
) -> usize {
	let mut accepted_coeffs = 0usize;
	let mut dummy_value = 0i32; // For dummy writes

	// Always process exactly bytes_available bytes
	for byte_position in 0..bytes_available {
		let lower_nibble = (random_bytes[byte_position] & 0x0F) as u32;
		let upper_nibble = (random_bytes[byte_position] >> 4) as u32;

		// Process lower nibble
		let reduced_lower = lower_nibble - (205 * lower_nibble >> 10) * 5;
		let coeff_lower = 2 - reduced_lower as i32;

		let valid_lower = Choice::from((lower_nibble < 15) as u8);
		let has_space_lower = Choice::from((accepted_coeffs < needed_count) as u8);
		let store_lower = valid_lower & has_space_lower;

		// Constant-time conditional assignment
		// Write to output or dummy location based on condition
		if accepted_coeffs < output_coeffs.len() {
			output_coeffs[accepted_coeffs] =
				i32::conditional_select(&output_coeffs[accepted_coeffs], &coeff_lower, store_lower);
		}
		dummy_value = i32::conditional_select(&coeff_lower, &dummy_value, store_lower);
		accepted_coeffs += store_lower.unwrap_u8() as usize;

		// Process upper nibble
		let reduced_upper = upper_nibble - (205 * upper_nibble >> 10) * 5;
		let coeff_upper = 2 - reduced_upper as i32;

		let valid_upper = Choice::from((upper_nibble < 15) as u8);
		let has_space_upper = Choice::from((accepted_coeffs < needed_count) as u8);
		let store_upper = valid_upper & has_space_upper;

		// Constant-time conditional assignment
		// Write to output or dummy location based on condition
		if accepted_coeffs < output_coeffs.len() {
			output_coeffs[accepted_coeffs] =
				i32::conditional_select(&output_coeffs[accepted_coeffs], &coeff_upper, store_upper);
		}
		dummy_value = i32::conditional_select(&coeff_upper, &dummy_value, store_upper);
		accepted_coeffs += store_upper.unwrap_u8() as usize;
	}

	// Prevent compiler from optimizing away dummy_value
	core::hint::black_box(dummy_value);
	accepted_coeffs
}

/// Sample polynomial with uniformly random coefficients in [-ETA,ETA] by performing rejection
/// sampling using the output stream from SHAKE256(seed|nonce).
pub fn uniform_eta(a: &mut Poly, seed: &[u8], nonce: u16) {
	let mut state = fips202::KeccakState::default();
	fips202::shake256_stream_init(&mut state, seed, nonce);

	let mut buf = [0u8; UNIFORM_ETA_NBLOCKS * fips202::SHAKE256_RATE];
	fips202::shake256_squeezeblocks(&mut buf, UNIFORM_ETA_NBLOCKS, &mut state);

	let buflen = UNIFORM_ETA_NBLOCKS * fips202::SHAKE256_RATE;
	let mut ctr = rej_eta(&mut a.coeffs, N, &buf, buflen);
	while ctr < N {
		fips202::shake256_squeezeblocks(&mut buf, 1, &mut state);
		ctr += rej_eta(&mut a.coeffs[ctr..], N - ctr, &buf, fips202::SHAKE256_RATE);
	}
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
	fips202::shake256_absorb(&mut state, seed, params::SEEDBYTES);
	fips202::shake256_finalize(&mut state);

	let mut buf = [0u8; fips202::SHAKE256_RATE];
	fips202::shake256_squeezeblocks(&mut buf, 1, &mut state);

	let mut signs: u64 = 0;
	for (i, &byte) in buf.iter().enumerate().take(8) {
		signs |= (byte as u64) << 8 * i;
	}

	let mut pos: usize = 8;
	c.coeffs.fill(0);
	for i in (N - params::lvl5::TAU)..N {
		let mut b: usize;
		loop {
			if pos >= fips202::SHAKE256_RATE {
				fips202::shake256_squeezeblocks(&mut buf, 1, &mut state);
				pos = 0;
			}
			b = buf[pos] as usize;
			pos += 1;
			if b <= i {
				break;
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
		t[0] = (params::lvl5::ETA as i32 - a.coeffs[8 * i + 0]) as u8;
		t[1] = (params::lvl5::ETA as i32 - a.coeffs[8 * i + 1]) as u8;
		t[2] = (params::lvl5::ETA as i32 - a.coeffs[8 * i + 2]) as u8;
		t[3] = (params::lvl5::ETA as i32 - a.coeffs[8 * i + 3]) as u8;
		t[4] = (params::lvl5::ETA as i32 - a.coeffs[8 * i + 4]) as u8;
		t[5] = (params::lvl5::ETA as i32 - a.coeffs[8 * i + 5]) as u8;
		t[6] = (params::lvl5::ETA as i32 - a.coeffs[8 * i + 6]) as u8;
		t[7] = (params::lvl5::ETA as i32 - a.coeffs[8 * i + 7]) as u8;

		r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
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

		r.coeffs[8 * i + 0] = params::lvl5::ETA as i32 - r.coeffs[8 * i + 0];
		r.coeffs[8 * i + 1] = params::lvl5::ETA as i32 - r.coeffs[8 * i + 1];
		r.coeffs[8 * i + 2] = params::lvl5::ETA as i32 - r.coeffs[8 * i + 2];
		r.coeffs[8 * i + 3] = params::lvl5::ETA as i32 - r.coeffs[8 * i + 3];
		r.coeffs[8 * i + 4] = params::lvl5::ETA as i32 - r.coeffs[8 * i + 4];
		r.coeffs[8 * i + 5] = params::lvl5::ETA as i32 - r.coeffs[8 * i + 5];
		r.coeffs[8 * i + 6] = params::lvl5::ETA as i32 - r.coeffs[8 * i + 6];
		r.coeffs[8 * i + 7] = params::lvl5::ETA as i32 - r.coeffs[8 * i + 7];
	}
}

/// Bit-pack polynomial z with coefficients in [-(GAMMA1 - 1), GAMMA1 - 1].
/// Input coefficients are assumed to be standard representatives.*
pub fn z_pack(r: &mut [u8], a: &Poly) {
	let mut t = [0i32; 2];

	for i in 0..N / 2 {
		t[0] = params::lvl5::GAMMA1 as i32 - a.coeffs[2 * i + 0];
		t[1] = params::lvl5::GAMMA1 as i32 - a.coeffs[2 * i + 1];

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

		r.coeffs[2 * i + 0] = params::lvl5::GAMMA1 as i32 - r.coeffs[2 * i + 0];
		r.coeffs[2 * i + 1] = params::lvl5::GAMMA1 as i32 - r.coeffs[2 * i + 1];
	}
}

/// Bit-pack polynomial w1 with coefficients in [0, 15].
/// Input coefficients are assumed to be standard representatives.
pub fn w1_pack(r: &mut [u8], a: &Poly) {
	for i in 0..N / 2 {
		r[i] = (a.coeffs[2 * i + 0] | (a.coeffs[2 * i + 1] << 4)) as u8;
	}
}
