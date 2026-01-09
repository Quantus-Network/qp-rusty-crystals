//! Low-level cryptographic primitives for threshold ML-DSA-87.
//!
//! This module re-exports the internal types and functions needed by the
//! signing protocol. These are implementation details and not part of the
//! public API.

// Re-export dilithium types used internally
pub(crate) use qp_rusty_crystals_dilithium::{
    fips202,
    params as dilithium_params,
    poly,
    polyvec,
    packing,
};

// Re-export field types
// Field types available if needed in the future
// pub(crate) use crate::field::{FieldElement, Polynomial, VecK, VecL};

// Constants for ML-DSA-87
pub(crate) const N: usize = 256;
pub(crate) const K: usize = 8;
pub(crate) const L: usize = 7;
pub(crate) const Q: i32 = 8380417;
pub(crate) const GAMMA1: i32 = 1 << 19; // 524288
pub(crate) const GAMMA2: i32 = 261888;
pub(crate) const ALPHA: u32 = 2 * GAMMA2 as u32; // 523776

// Sizes
pub(crate) const POLY_Q_SIZE: usize = (N * 23) / 8; // 736 bytes
pub(crate) const POLY_LE_GAMMA1_SIZE: usize = 640; // For ML-DSA-87 with 19-bit packing
pub(crate) const SINGLE_COMMITMENT_SIZE: usize = K * POLY_Q_SIZE; // 5888 bytes
pub(crate) const SINGLE_RESPONSE_SIZE: usize = L * POLY_LE_GAMMA1_SIZE; // 4480 bytes

/// Floating-point vector for threshold signature hyperball sampling.
/// This matches the Go reference implementation's FVec type.
#[derive(Clone)]
pub(crate) struct FVec {
    data: Box<[f64]>,
}

impl FVec {
    /// Create new FVec with given size.
    pub(crate) fn new(size: usize) -> Self {
        Self {
            data: vec![0.0f64; size].into_boxed_slice(),
        }
    }

    /// Sample from hyperball with given radius and nu parameter.
    pub(crate) fn sample_hyperball(&mut self, radius: f64, nu: f64, rhop: &[u8; 64], nonce: u16) {
        use std::f64::consts::PI;

        let size = self.data.len();
        let mut samples = vec![0.0f64; size + 2];

        // Use SHAKE256 for cryptographic randomness
        let mut keccak_state = fips202::KeccakState::default();
        fips202::shake256_absorb(&mut keccak_state, b"H", 1);
        fips202::shake256_absorb(&mut keccak_state, rhop, 64);
        let nonce_bytes = nonce.to_le_bytes();
        fips202::shake256_absorb(&mut keccak_state, &nonce_bytes, 2);
        fips202::shake256_finalize(&mut keccak_state);

        let mut buf = vec![0u8; (size + 2) * 8];
        let buf_len = buf.len();
        fips202::shake256_squeeze(&mut buf, buf_len, &mut keccak_state);

        // Generate normally distributed random numbers using Box-Muller transform
        let mut sq = 0.0f64;
        for i in (0..size + 2).step_by(2) {
            let u1_bytes: [u8; 8] = buf[i * 8..(i + 1) * 8].try_into().unwrap();
            let u2_bytes: [u8; 8] = buf[(i + 1) * 8..(i + 2) * 8].try_into().unwrap();
            let u1 = u64::from_le_bytes(u1_bytes);
            let u2 = u64::from_le_bytes(u2_bytes);

            let f1 = (u1 as f64) / 18446744073709551616.0;
            let f2 = (u2 as f64) / 18446744073709551616.0;

            let f1 = if f1 <= 0.0 { f64::MIN_POSITIVE } else { f1 };

            let z1 = (-2.0 * f1.ln()).sqrt() * (2.0 * PI * f2).cos();
            let z2 = (-2.0 * f1.ln()).sqrt() * (2.0 * PI * f2).sin();

            samples[i] = z1;
            sq += z1 * z1;

            samples[i + 1] = z2;
            sq += z2 * z2;

            // Apply nu scaling to first N*L components AFTER adding to sq
            if i < N * L {
                samples[i] *= nu;
                samples[i + 1] *= nu;
            }
        }

        let factor = radius / sq.sqrt();
        for i in 0..size {
            self.data[i] = samples[i] * factor;
        }
    }

    /// Round floating-point values back to integer polynomials.
    pub(crate) fn round(&self, s1: &mut polyvec::Polyvecl, s2: &mut polyvec::Polyveck) {
        for i in 0..L {
            for j in 0..N {
                let idx = i * N + j;
                let u = self.data[idx].round() as i32;
                let mut reduced = u % Q;
                if reduced > Q / 2 {
                    reduced -= Q;
                } else if reduced < -(Q / 2) {
                    reduced += Q;
                }
                s1.vec[i].coeffs[j] = reduced;
            }
        }

        for i in 0..K {
            for j in 0..N {
                let idx = (L + i) * N + j;
                let u = self.data[idx].round() as i32;
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

    /// Add another FVec to this one.
    pub(crate) fn add(&mut self, other: &FVec) {
        for i in 0..self.data.len() {
            self.data[i] += other.data[i];
        }
    }

    /// Create FVec from polynomial vectors.
    pub(crate) fn from_polyvecs(s1: &polyvec::Polyvecl, s2: &polyvec::Polyveck) -> Self {
        let size = N * (L + K);
        let mut data = vec![0.0f64; size];

        for i in 0..L {
            for j in 0..N {
                let mut u = s1.vec[i].coeffs[j];
                u += Q / 2;
                let t = u - Q;
                u = t + ((t >> 31) & Q);
                u = u - Q / 2;
                data[i * N + j] = u as f64;
            }
        }

        for i in 0..K {
            for j in 0..N {
                let mut u = s2.vec[i].coeffs[j];
                u += Q / 2;
                let t = u - Q;
                u = t + ((t >> 31) & Q);
                u = u - Q / 2;
                data[(L + i) * N + j] = u as f64;
            }
        }

        Self {
            data: data.into_boxed_slice(),
        }
    }
}

/// Go-compatible decompose function.
/// Splits 0 ≤ a < q into a₀ and a₁ with a = a₁*α + a₀.
pub(crate) fn decompose_go(a: u32) -> (u32, u32) {
    let q = Q as u32;
    let mut a1 = (a + 127) >> 7;
    a1 = ((a1 as u64 * 1025 + (1 << 21)) >> 22) as u32;
    a1 &= 15;

    let mut a0_plus_q = a.wrapping_sub(a1.wrapping_mul(ALPHA));

    let threshold = (q - 1) / 2;
    let cond = ((a0_plus_q as i32).wrapping_sub(threshold as i32)) >> 31;
    a0_plus_q = a0_plus_q.wrapping_add((cond as u32) & q);

    (a0_plus_q, a1)
}

/// Decompose a VecK using Go-compatible decompose.
pub(crate) fn veck_decompose_go(
    v: &polyvec::Polyveck,
    v0: &mut polyvec::Polyveck,
    v1: &mut polyvec::Polyveck,
) {
    for i in 0..K {
        for j in 0..N {
            let a = v.vec[i].coeffs[j] as u32;
            let (a0_plus_q, a1) = decompose_go(a);
            v0.vec[i].coeffs[j] = a0_plus_q as i32;
            v1.vec[i].coeffs[j] = a1 as i32;
        }
    }
}

/// Reduces x to a value ≤ 2Q.
pub(crate) fn reduce_le2q(x: u32) -> u32 {
    let x1 = x >> 23;
    let x2 = x & 0x7FFFFF;
    x2 + (x1 << 13) - x1
}

/// Returns x mod q for 0 ≤ x < 2q.
pub(crate) fn le2q_mod_q(x: u32) -> u32 {
    let q = Q as u32;
    let result = x.wrapping_sub(q);
    let mask = (result as i32 >> 31) as u32;
    result.wrapping_add(mask & q)
}

/// Normalizes coefficients assuming they're ≤ 2Q.
pub(crate) fn normalize_assuming_le2q(p: &mut poly::Poly) {
    for coeff in p.coeffs.iter_mut() {
        let mut x = *coeff;
        if x < 0 {
            x += Q;
        }
        let y = x - Q;
        let mask = y >> 31;
        *coeff = y + (mask & Q);
    }
}

/// Pointwise dot product in NTT domain using CIRCL implementation.
pub(crate) fn poly_dot_hat_circl(
    result: &mut poly::Poly,
    a: &polyvec::Polyvecl,
    b: &polyvec::Polyvecl,
) {
    let mut t = poly::Poly::default();
    *result = poly::Poly::default();
    for i in 0..L {
        crate::circl_ntt::mul_hat(&mut t, &a.vec[i], &b.vec[i]);
        let mut temp = poly::Poly::default();
        crate::circl_ntt::poly_add(&mut temp, result, &t);
        *result = temp;
    }
}

/// Compute μ = SHAKE256(tr || 0x00 || ctx_len || ctx || msg).
pub(crate) fn compute_mu(tr: &[u8; 64], message: &[u8], context: &[u8]) -> [u8; 64] {
    let mut input = Vec::new();
    input.extend_from_slice(tr);
    input.push(0u8);
    input.push(context.len() as u8);
    if !context.is_empty() {
        input.extend_from_slice(context);
    }
    input.extend_from_slice(message);

    let mut mu = [0u8; 64];
    let mut state = fips202::KeccakState::default();
    fips202::shake256_absorb(&mut state, &input, input.len());
    fips202::shake256_finalize(&mut state);
    fips202::shake256_squeeze(&mut mu, 64, &mut state);
    mu
}

/// Center a polynomial to [-(Q-1)/2, (Q-1)/2] range.
pub(crate) fn center_poly(p: &mut poly::Poly) {
    let q_half = Q / 2;
    for coeff in p.coeffs.iter_mut() {
        if *coeff > q_half {
            *coeff -= Q;
        } else if *coeff < -q_half {
            *coeff += Q;
        }
    }
}

/// Pack a polynomial in LeGamma1 format.
pub(crate) fn poly_pack_le_gamma1(p: &poly::Poly, buf: &mut [u8]) {
    let gamma1 = GAMMA1 as u32;
    let mut j = 0;
    for i in (0..640).step_by(5) {
        let mut p0 = gamma1.wrapping_sub(p.coeffs[j] as u32);
        p0 = p0.wrapping_add(((p0 as i32) >> 31) as u32 & (Q as u32));
        let mut p1 = gamma1.wrapping_sub(p.coeffs[j + 1] as u32);
        p1 = p1.wrapping_add(((p1 as i32) >> 31) as u32 & (Q as u32));

        buf[i] = (p0 & 0xFF) as u8;
        buf[i + 1] = ((p0 >> 8) & 0xFF) as u8;
        buf[i + 2] = (((p0 >> 16) & 0x0F) | ((p1 & 0x0F) << 4)) as u8;
        buf[i + 3] = ((p1 >> 4) & 0xFF) as u8;
        buf[i + 4] = ((p1 >> 12) & 0xFF) as u8;

        j += 2;
    }
}

/// Unpack a polynomial from LeGamma1 format.
pub(crate) fn poly_unpack_le_gamma1(p: &mut poly::Poly, buf: &[u8]) {
    let gamma1 = GAMMA1 as u32;
    let q = Q as u32;
    let mut j = 0;
    for i in (0..640).step_by(5) {
        let mut p0 =
            (buf[i] as u32) | ((buf[i + 1] as u32) << 8) | (((buf[i + 2] & 0x0F) as u32) << 16);
        let mut p1 = ((buf[i + 2] >> 4) as u32)
            | ((buf[i + 3] as u32) << 4)
            | ((buf[i + 4] as u32) << 12);

        p0 = gamma1.wrapping_sub(p0);
        p1 = gamma1.wrapping_sub(p1);

        p0 = p0.wrapping_add(((p0 as i32) >> 31) as u32 & q);
        p1 = p1.wrapping_add(((p1 as i32) >> 31) as u32 & q);

        p.coeffs[j] = p0 as i32;
        p.coeffs[j + 1] = p1 as i32;

        j += 2;
    }
}

/// Pack a polynomial with full Q-bit precision (23 bits per coefficient).
pub(crate) fn poly_pack_q(p: &poly::Poly, buf: &mut [u8]) {
    for i in (0..N).step_by(8) {
        let mut vals = [0u32; 8];
        for j in 0..8 {
            let c = p.coeffs[i + j];
            vals[j] = if c < 0 { (c + Q) as u32 } else { c as u32 };
        }

        // Pack 8 23-bit values into 23 bytes
        let offset = (i * 23) / 8;
        buf[offset] = (vals[0] & 0xFF) as u8;
        buf[offset + 1] = ((vals[0] >> 8) & 0xFF) as u8;
        buf[offset + 2] = (((vals[0] >> 16) & 0x7F) | ((vals[1] & 0x01) << 7)) as u8;
        buf[offset + 3] = ((vals[1] >> 1) & 0xFF) as u8;
        buf[offset + 4] = ((vals[1] >> 9) & 0xFF) as u8;
        buf[offset + 5] = (((vals[1] >> 17) & 0x3F) | ((vals[2] & 0x03) << 6)) as u8;
        buf[offset + 6] = ((vals[2] >> 2) & 0xFF) as u8;
        buf[offset + 7] = ((vals[2] >> 10) & 0xFF) as u8;
        buf[offset + 8] = (((vals[2] >> 18) & 0x1F) | ((vals[3] & 0x07) << 5)) as u8;
        buf[offset + 9] = ((vals[3] >> 3) & 0xFF) as u8;
        buf[offset + 10] = ((vals[3] >> 11) & 0xFF) as u8;
        buf[offset + 11] = (((vals[3] >> 19) & 0x0F) | ((vals[4] & 0x0F) << 4)) as u8;
        buf[offset + 12] = ((vals[4] >> 4) & 0xFF) as u8;
        buf[offset + 13] = ((vals[4] >> 12) & 0xFF) as u8;
        buf[offset + 14] = (((vals[4] >> 20) & 0x07) | ((vals[5] & 0x1F) << 3)) as u8;
        buf[offset + 15] = ((vals[5] >> 5) & 0xFF) as u8;
        buf[offset + 16] = ((vals[5] >> 13) & 0xFF) as u8;
        buf[offset + 17] = (((vals[5] >> 21) & 0x03) | ((vals[6] & 0x3F) << 2)) as u8;
        buf[offset + 18] = ((vals[6] >> 6) & 0xFF) as u8;
        buf[offset + 19] = ((vals[6] >> 14) & 0xFF) as u8;
        buf[offset + 20] = (((vals[6] >> 22) & 0x01) | ((vals[7] & 0x7F) << 1)) as u8;
        buf[offset + 21] = ((vals[7] >> 7) & 0xFF) as u8;
        buf[offset + 22] = ((vals[7] >> 15) & 0xFF) as u8;
    }
}

/// Unpack a polynomial from Q-bit format.
pub(crate) fn poly_unpack_q(p: &mut poly::Poly, buf: &[u8]) {
    for i in (0..N).step_by(8) {
        let offset = (i * 23) / 8;
        let mut vals = [0u32; 8];

        vals[0] = (buf[offset] as u32)
            | ((buf[offset + 1] as u32) << 8)
            | (((buf[offset + 2] & 0x7F) as u32) << 16);
        vals[1] = ((buf[offset + 2] >> 7) as u32)
            | ((buf[offset + 3] as u32) << 1)
            | ((buf[offset + 4] as u32) << 9)
            | (((buf[offset + 5] & 0x3F) as u32) << 17);
        vals[2] = ((buf[offset + 5] >> 6) as u32)
            | ((buf[offset + 6] as u32) << 2)
            | ((buf[offset + 7] as u32) << 10)
            | (((buf[offset + 8] & 0x1F) as u32) << 18);
        vals[3] = ((buf[offset + 8] >> 5) as u32)
            | ((buf[offset + 9] as u32) << 3)
            | ((buf[offset + 10] as u32) << 11)
            | (((buf[offset + 11] & 0x0F) as u32) << 19);
        vals[4] = ((buf[offset + 11] >> 4) as u32)
            | ((buf[offset + 12] as u32) << 4)
            | ((buf[offset + 13] as u32) << 12)
            | (((buf[offset + 14] & 0x07) as u32) << 20);
        vals[5] = ((buf[offset + 14] >> 3) as u32)
            | ((buf[offset + 15] as u32) << 5)
            | ((buf[offset + 16] as u32) << 13)
            | (((buf[offset + 17] & 0x03) as u32) << 21);
        vals[6] = ((buf[offset + 17] >> 2) as u32)
            | ((buf[offset + 18] as u32) << 6)
            | ((buf[offset + 19] as u32) << 14)
            | (((buf[offset + 20] & 0x01) as u32) << 22);
        vals[7] = ((buf[offset + 20] >> 1) as u32)
            | ((buf[offset + 21] as u32) << 7)
            | ((buf[offset + 22] as u32) << 15);

        for j in 0..8 {
            p.coeffs[i + j] = vals[j] as i32;
        }
    }
}

/// Pack commitment (K polynomials in Q-bit format).
pub(crate) fn pack_commitment(w: &polyvec::Polyveck, buf: &mut [u8]) {
    for i in 0..K {
        let offset = i * POLY_Q_SIZE;
        poly_pack_q(&w.vec[i], &mut buf[offset..offset + POLY_Q_SIZE]);
    }
}

/// Unpack commitment from bytes.
pub(crate) fn unpack_commitment(buf: &[u8]) -> polyvec::Polyveck {
    let mut w = polyvec::Polyveck::default();
    for i in 0..K {
        let offset = i * POLY_Q_SIZE;
        poly_unpack_q(&mut w.vec[i], &buf[offset..offset + POLY_Q_SIZE]);
    }
    w
}

/// Pack response (L polynomials in LeGamma1 format).
pub(crate) fn pack_response(z: &polyvec::Polyvecl, buf: &mut [u8]) {
    for i in 0..L {
        let offset = i * POLY_LE_GAMMA1_SIZE;
        poly_pack_le_gamma1(&z.vec[i], &mut buf[offset..offset + POLY_LE_GAMMA1_SIZE]);
    }
}

/// Unpack response from bytes.
pub(crate) fn unpack_response(buf: &[u8]) -> polyvec::Polyvecl {
    let mut z = polyvec::Polyvecl::default();
    for i in 0..L {
        let offset = i * POLY_LE_GAMMA1_SIZE;
        poly_unpack_le_gamma1(&mut z.vec[i], &buf[offset..offset + POLY_LE_GAMMA1_SIZE]);
    }
    z
}

/// Aggregate two commitments by adding polynomials.
pub(crate) fn aggregate_commitments(acc: &mut polyvec::Polyveck, other: &polyvec::Polyveck) {
    for i in 0..K {
        for j in 0..N {
            let sum = acc.vec[i].coeffs[j] as i64 + other.vec[i].coeffs[j] as i64;
            acc.vec[i].coeffs[j] = (sum % (Q as i64)) as i32;
        }
    }
}

/// Aggregate two responses by adding polynomials.
pub(crate) fn aggregate_responses(acc: &mut polyvec::Polyvecl, other: &polyvec::Polyvecl) {
    for i in 0..L {
        for j in 0..N {
            let sum = acc.vec[i].coeffs[j] as i64 + other.vec[i].coeffs[j] as i64;
            acc.vec[i].coeffs[j] = (sum % (Q as i64)) as i32;
        }
    }
}
