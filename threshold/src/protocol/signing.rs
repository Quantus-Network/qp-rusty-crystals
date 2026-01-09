//! Core signing protocol logic for threshold ML-DSA-87.
//!
//! This module delegates to the existing working functions in ml_dsa_87
//! rather than reimplementing the cryptographic logic.

use crate::config::ThresholdConfig;
use crate::error::{ThresholdError, ThresholdResult};
use crate::keys::{PrivateKeyShare, PublicKey};
use crate::ml_dsa_87::{
    self, aggregate_commitments_dilithium, aggregate_responses, combine_from_parts, compute_mu,
    compute_responses_deterministic, PrivateKey, PublicKey as OldPublicKey, Round1State,
};

use qp_rusty_crystals_dilithium::polyvec;
use std::collections::HashMap;
use zeroize::Zeroize;

/// Internal state after Round 1 completes.
/// Note: Not Clone because Round1State contains large internal state.
pub(crate) struct Round1Data {
    /// The internal Round1State from ml_dsa_87.
    pub(crate) state: Round1State,
    /// The commitment hash that was broadcast.
    pub(crate) commitment_hash: [u8; 32],
}

impl Zeroize for Round1Data {
    fn zeroize(&mut self) {
        self.commitment_hash.zeroize();
        // Round1State has its own Zeroize impl
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
            for i in 0..8 {
                w.vec[i].coeffs.fill(0);
            }
        }
        self.w_aggregated.clear();
        self.active_parties_mask = 0;
    }
}

/// Convert new PrivateKeyShare to old PrivateKey format.
pub(crate) fn to_old_private_key(share: &PrivateKeyShare) -> ThresholdResult<PrivateKey> {
    // Convert SecretShareData to old SecretShare format
    let mut old_shares: HashMap<u8, ml_dsa_87::secret_sharing::SecretShare> = HashMap::new();

    for (subset_id, share_data) in share.shares() {
        let mut s1_share = polyvec::Polyvecl::default();
        let mut s2_share = polyvec::Polyveck::default();

        for i in 0..7.min(share_data.s1.len()) {
            for j in 0..256 {
                s1_share.vec[i].coeffs[j] = share_data.s1[i][j];
            }
        }

        for i in 0..8.min(share_data.s2.len()) {
            for j in 0..256 {
                s2_share.vec[i].coeffs[j] = share_data.s2[i][j];
            }
        }

        old_shares.insert(
            *subset_id,
            ml_dsa_87::secret_sharing::SecretShare {
                party_id: *subset_id,
                s1_share,
                s2_share,
            },
        );
    }

    // Build the matrix A from rho
    let mut a = ml_dsa_87::Mat::zero();
    a.derive_from_seed(share.rho());

    Ok(PrivateKey {
        id: share.party_id(),
        key: *share.key(),
        rho: *share.rho(),
        tr: *share.tr(),
        a,
        shares: old_shares,
        s_total: None,
    })
}

/// Convert new PublicKey to old PublicKey format.
pub(crate) fn to_old_public_key(public_key: &PublicKey) -> ThresholdResult<OldPublicKey> {
    use crate::field::{FieldElement, VecK};

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&public_key.as_bytes()[..32]);

    // Build matrix A from rho
    let mut a_ntt = ml_dsa_87::Mat::zero();
    a_ntt.derive_from_seed(&rho);

    // Extract t1 from packed public key (after rho)
    // t1 is packed as 10-bit coefficients, 8 polynomials of 256 coefficients each
    let mut t1 = VecK::<8>::zero();
    let t1_bytes = &public_key.as_bytes()[32..];

    // Unpack t1 (320 bytes per polynomial = 256 * 10 / 8)
    for poly_idx in 0..8 {
        let poly_start = poly_idx * 320;
        for i in (0..256).step_by(4) {
            let byte_idx = poly_start + (i * 10) / 8;
            if byte_idx + 4 < t1_bytes.len() {
                let b0 = t1_bytes[byte_idx] as u32;
                let b1 = t1_bytes[byte_idx + 1] as u32;
                let b2 = t1_bytes[byte_idx + 2] as u32;
                let b3 = t1_bytes[byte_idx + 3] as u32;
                let b4 = t1_bytes[byte_idx + 4] as u32;

                t1.get_mut(poly_idx)
                    .set(i, FieldElement::new(b0 | ((b1 & 0x03) << 8)));
                t1.get_mut(poly_idx)
                    .set(i + 1, FieldElement::new((b1 >> 2) | ((b2 & 0x0F) << 6)));
                t1.get_mut(poly_idx)
                    .set(i + 2, FieldElement::new((b2 >> 4) | ((b3 & 0x3F) << 4)));
                t1.get_mut(poly_idx)
                    .set(i + 3, FieldElement::new((b3 >> 6) | (b4 << 2)));
            }
        }
    }

    let mut packed = [0u8; 2592];
    packed.copy_from_slice(public_key.as_bytes());

    let mut tr = [0u8; 64];
    tr.copy_from_slice(public_key.tr());

    Ok(OldPublicKey {
        rho,
        a_ntt,
        t1,
        tr,
        packed,
    })
}

/// Convert new ThresholdConfig to old format.
pub(crate) fn to_old_config(config: &ThresholdConfig) -> ThresholdResult<ml_dsa_87::ThresholdConfig> {
    ml_dsa_87::ThresholdConfig::new(config.threshold(), config.total_parties())
        .map_err(|e| ThresholdError::InvalidConfiguration(format!("{:?}", e)))
}

/// Generate Round 1 commitment data.
pub(crate) fn generate_round1(
    private_key: &PrivateKeyShare,
    config: &ThresholdConfig,
    seed: &[u8; 32],
) -> ThresholdResult<Round1Data> {
    let old_sk = to_old_private_key(private_key)?;
    let old_config = to_old_config(config)?;

    let (commitment_hash, state) = Round1State::new(&old_sk, &old_config, seed)
        .map_err(|e| ThresholdError::InvalidData(format!("Round1 error: {:?}", e)))?;

    let mut hash = [0u8; 32];
    if commitment_hash.len() >= 32 {
        hash.copy_from_slice(&commitment_hash[..32]);
    }

    Ok(Round1Data {
        state,
        commitment_hash: hash,
    })
}

/// Pack Round 1 commitment data for broadcast.
pub(crate) fn pack_round1_commitment(round1: &Round1Data, config: &ThresholdConfig) -> Vec<u8> {
    let old_config = to_old_config(config).expect("valid config");
    round1.state.pack_commitment_canonical(&old_config)
}

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

    let old_pk = to_old_public_key(public_key)?;
    let k = config.k_iterations() as usize;

    // Start with our own w_commitments
    let mut w_aggregated: Vec<polyvec::Polyveck> = if !round1.state.w_commitments.is_empty() {
        round1.state.w_commitments.clone()
    } else {
        vec![round1.state.w.clone()]
    };

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
    let single_commitment_size = 8 * 736; // K * POLY_Q_SIZE
    for commitment_data in other_commitments {
        if !commitment_data.is_empty() {
            for k_idx in 0..k {
                let start = k_idx * single_commitment_size;
                let end = start + single_commitment_size;

                if end <= commitment_data.len() && k_idx < w_aggregated.len() {
                    if let Ok(w_other) =
                        ml_dsa_87::unpack_commitment_dilithium(&commitment_data[start..end])
                    {
                        aggregate_commitments_dilithium(&mut w_aggregated[k_idx], &w_other);
                    }
                }
            }
        }
    }

    // Compute message hash μ
    let mu = compute_mu(&old_pk.tr, message, context);

    Ok(Round2Data {
        mu,
        w_aggregated,
        active_parties_mask,
    })
}

/// Generate Round 3 response using the existing working function.
pub(crate) fn generate_round3_response(
    private_key: &PrivateKeyShare,
    config: &ThresholdConfig,
    round1: &Round1Data,
    round2: &Round2Data,
) -> ThresholdResult<Vec<polyvec::Polyvecl>> {
    let old_sk = to_old_private_key(private_key)?;
    let old_config = to_old_config(config)?;

    // Use the existing working function
    let responses = compute_responses_deterministic(
        &old_sk,
        round2.active_parties_mask,
        &round2.mu,
        &round2.w_aggregated,
        &round1.state.hyperball_samples,
        &old_config,
    );

    Ok(responses)
}

/// Pack responses for broadcast.
pub(crate) fn pack_responses(responses: &[polyvec::Polyvecl]) -> Vec<u8> {
    ml_dsa_87::pack_responses(responses)
}

/// Unpack responses from broadcast.
pub(crate) fn unpack_responses(
    data: &[u8],
    config: &ThresholdConfig,
) -> ThresholdResult<Vec<polyvec::Polyvecl>> {
    let k = config.k_iterations() as usize;
    let single_response_size = 7 * 640; // L * POLY_LE_GAMMA1_SIZE
    let mut responses = Vec::with_capacity(k);

    for i in 0..k {
        let start = i * single_response_size;
        let end = start + single_response_size;

        if end <= data.len() {
            let mut z = polyvec::Polyvecl::default();
            // Unpack using z_unpack for each polynomial
            for j in 0..7 {
                let poly_start = start + j * 640;
                let poly_end = poly_start + 640;
                if poly_end <= data.len() {
                    qp_rusty_crystals_dilithium::poly::z_unpack(
                        &mut z.vec[j],
                        &data[poly_start..poly_end],
                    );
                }
            }
            responses.push(z);
        } else {
            responses.push(polyvec::Polyvecl::default());
        }
    }

    Ok(responses)
}

/// Combine all responses into a final signature using the existing working function.
pub(crate) fn combine_signature(
    public_key: &PublicKey,
    config: &ThresholdConfig,
    message: &[u8],
    context: &[u8],
    w_aggregated: &[polyvec::Polyveck],
    all_responses: &[Vec<polyvec::Polyvecl>],
) -> ThresholdResult<Vec<u8>> {
    crate::error::validate_context(context)?;

    let old_pk = to_old_public_key(public_key)?;
    let old_config = to_old_config(config)?;

    let k = config.k_iterations() as usize;

    // Aggregate all responses
    let mut z_aggregated: Vec<polyvec::Polyvecl> = vec![polyvec::Polyvecl::default(); k];

    for party_responses in all_responses {
        aggregate_responses(&mut z_aggregated, party_responses);
    }

    // Use the existing working combine function
    let (signature, ok) =
        combine_from_parts(&old_pk, message, context, w_aggregated, &z_aggregated, &old_config);

    if !ok {
        return Err(ThresholdError::CombinationFailed);
    }

    Ok(signature)
}
