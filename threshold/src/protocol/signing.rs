//! Core signing protocol logic for threshold ML-DSA-87.
//!
//! This module implements the cryptographic operations for the threshold signing
//! protocol, including commitment generation, response computation, and signature
//! combination.

use std::collections::HashMap;

use qp_rusty_crystals_dilithium::{fips202, params as dilithium_params, poly, polyvec};
use zeroize::Zeroize;

use crate::config::ThresholdConfig;
use crate::error::{ThresholdError, ThresholdResult};
use crate::keys::{PrivateKeyShare, PublicKey};
use crate::protocol::primitives::{
    compute_dilithium_hint, mod_q, normalize_assuming_le2q, pack_signature, poly_dot_hat_circl,
    poly_pack_w, reduce_le2q, unpack_polyveck_w, veck_decompose_go, FVec, K, L, N, Q,
};
use crate::protocol::secret_sharing::{recover_share_hardcoded, SecretShare};

// ============================================================================
// Internal State Types
// ============================================================================

/// Internal state after Round 1 completes.
pub(crate) struct Round1Data {
    /// K different w commitments for canonical iterations.
    pub(crate) w_commitments: Vec<polyvec::Polyveck>,
    /// K different hyperball samples for reuse in Round 3.
    pub(crate) hyperball_samples: Vec<FVec>,
    /// The commitment hash that was broadcast.
    pub(crate) commitment_hash: [u8; 32],
    /// Random bytes used for commitment.
    pub(crate) rho_prime: [u8; 64],
}

impl Zeroize for Round1Data {
    fn zeroize(&mut self) {
        self.commitment_hash.zeroize();
        self.rho_prime.zeroize();
        // w_commitments and hyperball_samples will be cleared when dropped
        self.w_commitments.clear();
        self.hyperball_samples.clear();
    }
}

/// Internal state after Round 2 completes.
#[derive(Clone)]
pub(crate) struct Round2Data {
    /// Message hash μ.
    pub(crate) mu: [u8; 64],
    /// Aggregated w values for all K iterations.
    pub(crate) w_aggregated: Vec<polyvec::Polyveck>,
    /// Active party bitmask.
    pub(crate) active_parties_mask: u8,
}

impl Zeroize for Round2Data {
    fn zeroize(&mut self) {
        self.mu.zeroize();
        for w in &mut self.w_aggregated {
            for i in 0..K {
                w.vec[i].coeffs.fill(0);
            }
        }
        self.w_aggregated.clear();
        self.active_parties_mask = 0;
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute message hash μ using ML-DSA specification.
/// μ = SHAKE256(tr || 0x00 || ctx_len || ctx || msg)
pub(crate) fn compute_mu(tr: &[u8; 64], message: &[u8], context: &[u8]) -> [u8; 64] {
    let mut mu = [0u8; 64];
    let mut state = fips202::KeccakState::default();

    fips202::shake256_absorb(&mut state, tr, 64);
    fips202::shake256_absorb(&mut state, &[0u8], 1); // Domain separator for pure signatures
    fips202::shake256_absorb(&mut state, &[context.len() as u8], 1);
    if !context.is_empty() {
        fips202::shake256_absorb(&mut state, context, context.len());
    }
    fips202::shake256_absorb(&mut state, message, message.len());
    fips202::shake256_finalize(&mut state);
    fips202::shake256_squeeze(&mut mu, 64, &mut state);

    mu
}

/// Convert PrivateKeyShare to the internal share format.
fn convert_shares(share: &PrivateKeyShare) -> HashMap<u8, SecretShare> {
    let mut shares: HashMap<u8, SecretShare> = HashMap::new();

    for (subset_id, share_data) in share.shares() {
        let mut s1_share = polyvec::Polyvecl::default();
        let mut s2_share = polyvec::Polyveck::default();

        for i in 0..L.min(share_data.s1.len()) {
            for j in 0..N {
                s1_share.vec[i].coeffs[j] = share_data.s1[i][j];
            }
        }

        for i in 0..K.min(share_data.s2.len()) {
            for j in 0..N {
                s2_share.vec[i].coeffs[j] = share_data.s2[i][j];
            }
        }

        shares.insert(
            *subset_id,
            SecretShare {
                party_id: *subset_id,
                s1_share,
                s2_share,
            },
        );
    }

    shares
}

/// Unpack a commitment from 23-bit packed format.
pub(crate) fn unpack_commitment_dilithium(
    commitment: &[u8],
) -> ThresholdResult<polyvec::Polyveck> {
    let poly_q_size = (N * 23 + 7) / 8; // 736 bytes per poly
    let expected_len = K * poly_q_size;

    if commitment.len() != expected_len {
        return Err(ThresholdError::InvalidCommitmentSize {
            expected: expected_len,
            actual: commitment.len(),
        });
    }

    Ok(unpack_polyveck_w(commitment))
}

/// Aggregate commitment vectors.
pub(crate) fn aggregate_commitments_dilithium(
    w_final: &mut polyvec::Polyveck,
    w_temp: &polyvec::Polyveck,
) {
    for i in 0..K {
        poly::add_ip(&mut w_final.vec[i], &w_temp.vec[i]);
        normalize_assuming_le2q(&mut w_final.vec[i]);
    }
}

/// Aggregate response polynomials.
pub(crate) fn aggregate_responses(
    zfinals: &mut [polyvec::Polyvecl],
    zs: &[polyvec::Polyvecl],
) {
    for i in 0..zs.len().min(zfinals.len()) {
        for j in 0..L {
            for k in 0..N {
                zfinals[i].vec[j].coeffs[k] += zs[i].vec[j].coeffs[k];
            }
        }
        // Normalize
        for j in 0..L {
            for coeff in zfinals[i].vec[j].coeffs.iter_mut() {
                let c = *coeff;
                let c_u32 = if c < 0 { (c + Q) as u32 } else { c as u32 };
                *coeff = mod_q(c_u32) as i32;
            }
        }
    }
}

// ============================================================================
// Round 1: Commitment Generation
// ============================================================================

/// Generate Round 1 commitment data.
pub(crate) fn generate_round1(
    private_key: &PrivateKeyShare,
    config: &ThresholdConfig,
    seed: &[u8; 32],
) -> ThresholdResult<Round1Data> {
    // Generate deterministic random bytes for commitment
    let mut rho_prime = [0u8; 64];
    let mut state = fips202::KeccakState::default();
    fips202::shake256_absorb(&mut state, seed, 32);
    fips202::shake256_absorb(&mut state, b"rho_prime", 9);
    fips202::shake256_finalize(&mut state);
    fips202::shake256_squeeze(&mut rho_prime, 64, &mut state);

    let k_iterations = config.k_iterations() as usize;
    let mut w_commitments = Vec::with_capacity(k_iterations);
    let mut hyperball_samples = Vec::with_capacity(k_iterations);

    // Initialize matrix A once for all computations
    let mut a_matrix: Vec<polyvec::Polyvecl> =
        (0..K).map(|_| polyvec::Polyvecl::default()).collect();
    polyvec::matrix_expand(&mut a_matrix, private_key.rho());

    // Generate K different (w, y) pairs using different seeds
    for k_iter in 0..k_iterations {
        let fvec_size = N * (L + K);
        let mut fvec = FVec::new(fvec_size);

        // Create unique seed for this iteration
        let mut iter_seed = [0u8; 32];
        iter_seed.copy_from_slice(seed);
        iter_seed[0] ^= k_iter as u8;
        iter_seed[31] ^= (k_iter >> 8) as u8;

        let mut iter_rho_prime = [0u8; 64];
        let mut state = fips202::KeccakState::default();
        fips202::shake256_absorb(&mut state, &iter_seed, 32);
        fips202::shake256_absorb(&mut state, b"rho_prime", 9);
        fips202::shake256_absorb(&mut state, &[k_iter as u8], 1);
        fips202::shake256_finalize(&mut state);
        fips202::shake256_squeeze(&mut iter_rho_prime, 64, &mut state);

        // Sample from hyperball using threshold parameters
        let (_, r_prime, nu) = get_threshold_params(config);
        fvec.sample_hyperball(r_prime, nu, &iter_rho_prime, k_iter as u16);

        // Store hyperball sample for reuse in Round 3
        hyperball_samples.push(fvec.clone());

        // Round to integer polynomials
        let mut y_k = polyvec::Polyvecl::default();
        let mut e_k = polyvec::Polyveck::default();
        fvec.round(&mut y_k, &mut e_k);

        // Compute w_k = A·y_k using NTT
        let mut w_k = polyvec::Polyveck::default();
        let mut y_k_ntt = y_k.clone();
        for i in 0..L {
            crate::circl_ntt::ntt(&mut y_k_ntt.vec[i]);
        }

        for i in 0..K {
            poly_dot_hat_circl(&mut w_k.vec[i], &a_matrix[i], &y_k_ntt);

            // Apply ReduceLe2Q in NTT domain BEFORE InvNTT
            for j in 0..N {
                let coeff = w_k.vec[i].coeffs[j];
                let coeff_u32 = if coeff < 0 { (coeff + Q) as u32 } else { coeff as u32 };
                w_k.vec[i].coeffs[j] = reduce_le2q(coeff_u32) as i32;
            }

            crate::circl_ntt::inv_ntt(&mut w_k.vec[i]);

            // Add error term e_k for threshold scheme
            poly::add_ip(&mut w_k.vec[i], &e_k.vec[i]);

            // Apply ReduceLe2Q after Add
            for j in 0..N {
                let coeff = w_k.vec[i].coeffs[j];
                let coeff_u32 = if coeff < 0 { (coeff + Q) as u32 } else { coeff as u32 };
                w_k.vec[i].coeffs[j] = reduce_le2q(coeff_u32) as i32;
            }
        }

        // Apply NormalizeAssumingLe2Q
        for i in 0..K {
            normalize_assuming_le2q(&mut w_k.vec[i]);
        }

        w_commitments.push(w_k);
    }

    // Pack w for commitment hash using 23-bit packing
    const POLY_Q_SIZE: usize = (N * 23) / 8; // 736 bytes
    let single_commitment_size = K * POLY_Q_SIZE;
    let w_packed_size = k_iterations * single_commitment_size;
    let mut w_packed = vec![0u8; w_packed_size];

    let mut offset = 0;
    for k_idx in 0..k_iterations {
        if k_idx < w_commitments.len() && offset + single_commitment_size <= w_packed.len() {
            pack_w_dilithium(&w_commitments[k_idx], &mut w_packed[offset..offset + single_commitment_size]);
            offset += single_commitment_size;
        }
    }

    // Generate commitment hash
    let mut commitment_hash = [0u8; 32];
    let mut state = fips202::KeccakState::default();
    fips202::shake256_absorb(&mut state, private_key.tr(), 64);
    fips202::shake256_absorb(&mut state, &[private_key.party_id()], 1);
    fips202::shake256_absorb(&mut state, &w_packed, w_packed.len());
    fips202::shake256_finalize(&mut state);
    fips202::shake256_squeeze(&mut commitment_hash, 32, &mut state);

    Ok(Round1Data {
        w_commitments,
        hyperball_samples,
        commitment_hash,
        rho_prime,
    })
}

/// Pack w using 23-bit encoding.
fn pack_w_dilithium(w: &polyvec::Polyveck, buf: &mut [u8]) {
    const POLY_Q_SIZE: usize = (N * 23) / 8; // 736 bytes
    for i in 0..K {
        let offset = i * POLY_Q_SIZE;
        poly_pack_w(&w.vec[i], &mut buf[offset..offset + POLY_Q_SIZE]);
    }
}

/// Get threshold parameters (r, r', nu) for a configuration.
/// Returns (r, r_prime, nu) where:
/// - r is the rejection sampling radius
/// - r_prime is the hyperball sampling radius
/// - nu is the scaling factor
fn get_threshold_params(config: &ThresholdConfig) -> (f64, f64, f64) {
    // These values come from the Go reference implementation
    match (config.threshold(), config.total_parties()) {
        (2, 2) => (503119.0, 503192.0, 3.0),
        (2, 3) => (631601.0, 631703.0, 3.0),
        (3, 3) => (483107.0, 483180.0, 3.0),
        (2, 4) => (632903.0, 633006.0, 3.0),
        (3, 4) => (551752.0, 551854.0, 3.0),
        (4, 4) => (487958.0, 488031.0, 3.0),
        (2, 5) => (607694.0, 607820.0, 3.0),
        (3, 5) => (577400.0, 577546.0, 3.0),
        (4, 5) => (518384.0, 518510.0, 3.0),
        (5, 5) => (468214.0, 468287.0, 3.0),
        (2, 6) => (665106.0, 665232.0, 3.0),
        (3, 6) => (577541.0, 577704.0, 3.0),
        (4, 6) => (517689.0, 517853.0, 3.0),
        (5, 6) => (479692.0, 479819.0, 3.0),
        (6, 6) => (424124.0, 424197.0, 3.0),
        _ => (503119.0, 503192.0, 3.0), // Default to 2-of-2 values
    }
}

/// Pack Round 1 commitment data for broadcast.
pub(crate) fn pack_round1_commitment(round1: &Round1Data, config: &ThresholdConfig) -> Vec<u8> {
    let k = config.k_iterations() as usize;
    const POLY_Q_SIZE: usize = (N * 23) / 8;
    let single_commitment_size = K * POLY_Q_SIZE;
    let total_size = k * single_commitment_size;
    let mut buf = vec![0u8; total_size];

    for k_idx in 0..k.min(round1.w_commitments.len()) {
        let offset = k_idx * single_commitment_size;
        pack_w_dilithium(&round1.w_commitments[k_idx], &mut buf[offset..offset + single_commitment_size]);
    }

    buf
}

// ============================================================================
// Round 2: Process Commitments
// ============================================================================

/// Process Round 2: aggregate commitments and compute message hash.
pub(crate) fn process_round2(
    private_key: &PrivateKeyShare,
    public_key: &PublicKey,
    config: &ThresholdConfig,
    round1: &Round1Data,
    message: &[u8],
    context: &[u8],
    other_party_ids: &[u8],
    other_commitments: &[Vec<u8>],
) -> ThresholdResult<Round2Data> {
    crate::error::validate_context(context)?;

    let k = config.k_iterations() as usize;

    // Start with our own w_commitments
    let mut w_aggregated: Vec<polyvec::Polyveck> = round1.w_commitments.clone();

    // Ensure we have k entries
    while w_aggregated.len() < k {
        w_aggregated.push(polyvec::Polyveck::default());
    }

    // Build active parties mask
    let mut active_parties_mask: u8 = 1 << private_key.party_id();
    for &party_id in other_party_ids {
        active_parties_mask |= 1 << party_id;
    }

    // Aggregate commitments from other parties
    let single_commitment_size = K * 736; // K * POLY_Q_SIZE
    for commitment_data in other_commitments {
        if !commitment_data.is_empty() {
            for k_idx in 0..k {
                let start = k_idx * single_commitment_size;
                let end = start + single_commitment_size;

                if end <= commitment_data.len() && k_idx < w_aggregated.len() {
                    if let Ok(w_other) = unpack_commitment_dilithium(&commitment_data[start..end]) {
                        aggregate_commitments_dilithium(&mut w_aggregated[k_idx], &w_other);
                    }
                }
            }
        }
    }

    // Compute message hash μ
    let mut tr = [0u8; 64];
    tr.copy_from_slice(public_key.tr());
    let mu = compute_mu(&tr, message, context);

    Ok(Round2Data {
        mu,
        w_aggregated,
        active_parties_mask,
    })
}

// ============================================================================
// Round 3: Response Generation
// ============================================================================

/// Generate Round 3 response.
pub(crate) fn generate_round3_response(
    private_key: &PrivateKeyShare,
    config: &ThresholdConfig,
    round1: &Round1Data,
    round2: &Round2Data,
) -> ThresholdResult<Vec<polyvec::Polyvecl>> {
    // Convert shares
    let shares = convert_shares(private_key);

    // Build active parties list
    let mut active_party_list = Vec::new();
    for i in 0..config.total_parties() {
        if round2.active_parties_mask & (1 << i) != 0 {
            active_party_list.push(i);
        }
    }

    // Recover the partial secret for this party
    let (s1h, s2h) = recover_share_hardcoded(
        &shares,
        private_key.party_id(),
        &active_party_list,
        config.threshold(),
        config.total_parties(),
    )?;

    let k = config.k_iterations() as usize;
    let mut zs: Vec<polyvec::Polyvecl> = vec![polyvec::Polyvecl::default(); k];

    let (r, _, nu) = get_threshold_params(config);

    // For each commitment iteration
    for i in 0..k {
        if i >= round2.w_aggregated.len() || i >= round1.hyperball_samples.len() {
            continue;
        }

        // Decompose w into w0 and w1
        let mut w0 = polyvec::Polyveck::default();
        let mut w1 = polyvec::Polyveck::default();
        veck_decompose_go(&round2.w_aggregated[i], &mut w0, &mut w1);

        // c~ = H(μ || w1)
        let mut w1_packed = vec![0u8; K * dilithium_params::POLYW1_PACKEDBYTES];
        polyvec::k_pack_w1(&mut w1_packed, &w1);

        let mut c_bytes = [0u8; dilithium_params::C_DASH_BYTES];
        let mut keccak_state = fips202::KeccakState::default();
        fips202::shake256_absorb(&mut keccak_state, &round2.mu, 64);
        fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
        fips202::shake256_finalize(&mut keccak_state);
        fips202::shake256_squeeze(&mut c_bytes, dilithium_params::C_DASH_BYTES, &mut keccak_state);

        // Derive challenge polynomial
        let mut ch = poly::Poly::default();
        poly::challenge(&mut ch, &c_bytes);
        crate::circl_ntt::ntt(&mut ch);

        // Compute c·s1
        let mut z = polyvec::Polyvecl::default();
        for j in 0..L {
            crate::circl_ntt::mul_hat(&mut z.vec[j], &ch, &s1h.vec[j]);
            crate::circl_ntt::inv_ntt(&mut z.vec[j]);
        }
        // Normalize z
        for j in 0..L {
            for coeff in z.vec[j].coeffs.iter_mut() {
                let c = *coeff;
                let c_u32 = if c < 0 { (c + Q) as u32 } else { c as u32 };
                *coeff = mod_q(c_u32) as i32;
            }
        }

        // Compute c·s2
        let mut y = polyvec::Polyveck::default();
        for j in 0..K {
            crate::circl_ntt::mul_hat(&mut y.vec[j], &ch, &s2h.vec[j]);
            crate::circl_ntt::inv_ntt(&mut y.vec[j]);
        }
        // Normalize y
        for j in 0..K {
            for coeff in y.vec[j].coeffs.iter_mut() {
                let c = *coeff;
                let c_u32 = if c < 0 { (c + Q) as u32 } else { c as u32 };
                *coeff = mod_q(c_u32) as i32;
            }
        }

        // Convert to FVec and add hyperball sample
        let mut zf = FVec::from_polyvecs(&z, &y);
        zf.add(&round1.hyperball_samples[i]);

        // Rejection sampling check
        if zf.excess(r, nu) {
            continue;
        }

        // Round back to integers
        let mut z_out = polyvec::Polyvecl::default();
        let mut y_out = polyvec::Polyveck::default();
        zf.round(&mut z_out, &mut y_out);

        // Convert from centered format to [0, Q) format
        for j in 0..L {
            for coeff in z_out.vec[j].coeffs.iter_mut() {
                if *coeff < 0 {
                    *coeff += Q;
                }
            }
        }

        zs[i] = z_out;
    }

    Ok(zs)
}

/// Pack responses for broadcast.
pub(crate) fn pack_responses(responses: &[polyvec::Polyvecl]) -> Vec<u8> {
    let single_response_size = L * dilithium_params::POLYZ_PACKEDBYTES;
    let mut buf = vec![0u8; responses.len() * single_response_size];

    for (i, z) in responses.iter().enumerate() {
        let offset = i * single_response_size;
        // Convert to centered format for packing
        let mut z_centered = z.clone();
        for j in 0..L {
            for coeff in z_centered.vec[j].coeffs.iter_mut() {
                if *coeff > Q / 2 {
                    *coeff -= Q;
                }
            }
        }
        // Pack each polynomial
        for j in 0..L {
            let poly_offset = offset + j * dilithium_params::POLYZ_PACKEDBYTES;
            poly::z_pack(
                &mut buf[poly_offset..poly_offset + dilithium_params::POLYZ_PACKEDBYTES],
                &z_centered.vec[j],
            );
        }
    }

    buf
}

/// Unpack responses from broadcast.
pub(crate) fn unpack_responses(
    data: &[u8],
    config: &ThresholdConfig,
) -> ThresholdResult<Vec<polyvec::Polyvecl>> {
    let k = config.k_iterations() as usize;
    let single_response_size = L * 640; // L * POLY_LE_GAMMA1_SIZE
    let mut responses = Vec::with_capacity(k);

    for i in 0..k {
        let start = i * single_response_size;
        let end = start + single_response_size;

        if end <= data.len() {
            let mut z = polyvec::Polyvecl::default();
            for j in 0..L {
                let poly_start = start + j * 640;
                let poly_end = poly_start + 640;
                if poly_end <= data.len() {
                    poly::z_unpack(&mut z.vec[j], &data[poly_start..poly_end]);
                }
            }
            responses.push(z);
        } else {
            responses.push(polyvec::Polyvecl::default());
        }
    }

    Ok(responses)
}

// ============================================================================
// Signature Combination
// ============================================================================

/// Combine all responses into a final signature.
pub(crate) fn combine_signature(
    public_key: &PublicKey,
    config: &ThresholdConfig,
    message: &[u8],
    context: &[u8],
    w_aggregated: &[polyvec::Polyveck],
    all_responses: &[Vec<polyvec::Polyvecl>],
) -> ThresholdResult<Vec<u8>> {
    crate::error::validate_context(context)?;

    let k_iterations = config.k_iterations() as usize;

    // Aggregate all responses
    let mut z_aggregated: Vec<polyvec::Polyvecl> = vec![polyvec::Polyvecl::default(); k_iterations];
    for party_responses in all_responses {
        aggregate_responses(&mut z_aggregated, party_responses);
    }

    // Compute μ
    let mut tr = [0u8; 64];
    tr.copy_from_slice(public_key.tr());
    let mu = compute_mu(&tr, message, context);

    // Extract rho and build matrix A
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&public_key.as_bytes()[..32]);
    let mut a_matrix: Vec<polyvec::Polyvecl> =
        (0..K).map(|_| polyvec::Polyvecl::default()).collect();
    polyvec::matrix_expand(&mut a_matrix, &rho);

    // Extract t1 from public key
    let t1 = unpack_t1(public_key.as_bytes());

    // For each commitment iteration
    for i in 0..k_iterations.min(w_aggregated.len()).min(z_aggregated.len()) {
        // Decompose w into w0 and w1
        let mut w0 = polyvec::Polyveck::default();
        let mut w1 = polyvec::Polyveck::default();
        veck_decompose_go(&w_aggregated[i], &mut w0, &mut w1);

        // Ensure ||z||_∞ < γ1 - β
        let gamma1_minus_beta = (dilithium_params::GAMMA1 - dilithium_params::BETA) as i32;
        let mut z_exceeds = false;
        for j in 0..L {
            for k in 0..N {
                let coeff = z_aggregated[i].vec[j].coeffs[k];
                let centered = if coeff > Q / 2 { coeff - Q } else { coeff };
                if centered.abs() >= gamma1_minus_beta {
                    z_exceeds = true;
                    break;
                }
            }
            if z_exceeds {
                break;
            }
        }
        if z_exceeds {
            continue;
        }

        // Compute Az (z in NTT domain)
        let mut zh = z_aggregated[i].clone();
        for j in 0..L {
            for k in 0..N {
                if zh.vec[j].coeffs[k] > Q / 2 {
                    zh.vec[j].coeffs[k] -= Q;
                }
            }
            crate::circl_ntt::ntt(&mut zh.vec[j]);
        }

        let mut az = polyvec::Polyveck::default();
        for j in 0..K {
            for l in 0..L {
                let mut tmp = poly::Poly::default();
                crate::circl_ntt::mul_hat(&mut tmp, &a_matrix[j].vec[l], &zh.vec[l]);
                for k in 0..N {
                    az.vec[j].coeffs[k] += tmp.coeffs[k];
                }
            }
        }

        // c~ = H(μ || w1)
        let mut w1_packed = vec![0u8; K * dilithium_params::POLYW1_PACKEDBYTES];
        polyvec::k_pack_w1(&mut w1_packed, &w1);

        let mut c_bytes = [0u8; dilithium_params::C_DASH_BYTES];
        let mut keccak_state = fips202::KeccakState::default();
        fips202::shake256_absorb(&mut keccak_state, &mu, 64);
        fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
        fips202::shake256_finalize(&mut keccak_state);
        fips202::shake256_squeeze(&mut c_bytes, dilithium_params::C_DASH_BYTES, &mut keccak_state);

        // Derive challenge polynomial
        let mut ch = poly::Poly::default();
        poly::challenge(&mut ch, &c_bytes);
        crate::circl_ntt::ntt(&mut ch);

        // Compute Az - 2^d * c * t1
        let mut az2dct1 = polyvec::Polyveck::default();
        for j in 0..K {
            for k in 0..N {
                az2dct1.vec[j].coeffs[k] = (t1.vec[j].coeffs[k] << dilithium_params::D) as i32;
            }
            crate::circl_ntt::ntt(&mut az2dct1.vec[j]);
            let tmp = az2dct1.vec[j].clone();
            crate::circl_ntt::mul_hat(&mut az2dct1.vec[j], &tmp, &ch);
        }

        // Az - 2^d * c * t1
        for j in 0..K {
            for k in 0..N {
                az2dct1.vec[j].coeffs[k] = az.vec[j].coeffs[k] - az2dct1.vec[j].coeffs[k];
            }
            poly::reduce(&mut az2dct1.vec[j]);
            crate::circl_ntt::inv_ntt(&mut az2dct1.vec[j]);
            normalize_assuming_le2q(&mut az2dct1.vec[j]);
        }

        // f = Az2dct1 - wfinals[i]
        let mut f = polyvec::Polyveck::default();
        for j in 0..K {
            for k in 0..N {
                f.vec[j].coeffs[k] = az2dct1.vec[j].coeffs[k] - w_aggregated[i].vec[j].coeffs[k];
            }
            // Normalize
            for k in 0..N {
                let c = f.vec[j].coeffs[k];
                let c_u32 = if c < 0 { (c + Q) as u32 } else { c as u32 };
                f.vec[j].coeffs[k] = mod_q(c_u32) as i32;
            }
        }

        // Ensure ||f||_∞ < γ2
        let gamma2 = dilithium_params::GAMMA2 as i32;
        let mut f_exceeds = false;
        for j in 0..K {
            for k in 0..N {
                let coeff = f.vec[j].coeffs[k];
                let centered = if coeff > Q / 2 { coeff - Q } else { coeff };
                if centered.abs() >= gamma2 {
                    f_exceeds = true;
                    break;
                }
            }
            if f_exceeds {
                break;
            }
        }
        if f_exceeds {
            continue;
        }

        // w0pf = w0 + f
        let mut w0pf = polyvec::Polyveck::default();
        for j in 0..K {
            for k in 0..N {
                w0pf.vec[j].coeffs[k] = w0.vec[j].coeffs[k] + f.vec[j].coeffs[k];
            }
            // Normalize
            for k in 0..N {
                let c = w0pf.vec[j].coeffs[k];
                let c_u32 = if c < 0 { (c + Q) as u32 } else { c as u32 };
                w0pf.vec[j].coeffs[k] = mod_q(c_u32) as i32;
            }
        }

        // Compute hint
        let mut hint = polyvec::Polyveck::default();
        let hint_pop = compute_dilithium_hint(&mut hint, &w0pf, &w1);

        if hint_pop <= dilithium_params::OMEGA {
            // Convert z to centered form for packing
            let mut z_centered = z_aggregated[i].clone();
            for j in 0..L {
                for k in 0..N {
                    if z_centered.vec[j].coeffs[k] > Q / 2 {
                        z_centered.vec[j].coeffs[k] -= Q;
                    }
                }
            }

            // Pack signature
            let mut c_full = [0u8; 64];
            c_full[..dilithium_params::C_DASH_BYTES].copy_from_slice(&c_bytes);
            if let Ok(sig) = pack_signature(&c_full, &z_centered, &hint) {
                return Ok(sig);
            }
        }
    }

    Err(ThresholdError::CombinationFailed)
}

/// Unpack t1 from public key bytes.
fn unpack_t1(pk_bytes: &[u8]) -> polyvec::Polyveck {
    let mut t1 = polyvec::Polyveck::default();
    let t1_bytes = &pk_bytes[32..]; // Skip rho

    // Unpack t1 (320 bytes per polynomial = 256 * 10 / 8)
    for poly_idx in 0..K {
        let poly_start = poly_idx * 320;
        for i in (0..N).step_by(4) {
            let byte_idx = poly_start + (i * 10) / 8;
            if byte_idx + 4 < t1_bytes.len() {
                let b0 = t1_bytes[byte_idx] as i32;
                let b1 = t1_bytes[byte_idx + 1] as i32;
                let b2 = t1_bytes[byte_idx + 2] as i32;
                let b3 = t1_bytes[byte_idx + 3] as i32;
                let b4 = t1_bytes[byte_idx + 4] as i32;

                t1.vec[poly_idx].coeffs[i] = b0 | ((b1 & 0x03) << 8);
                t1.vec[poly_idx].coeffs[i + 1] = (b1 >> 2) | ((b2 & 0x0F) << 6);
                t1.vec[poly_idx].coeffs[i + 2] = (b2 >> 4) | ((b3 & 0x3F) << 4);
                t1.vec[poly_idx].coeffs[i + 3] = (b3 >> 6) | (b4 << 2);
            }
        }
    }

    t1
}
