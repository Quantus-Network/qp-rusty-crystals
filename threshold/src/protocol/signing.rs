//! Core signing protocol logic for threshold ML-DSA-87.
//!
//! This module implements the cryptographic operations for the threshold signing
//! protocol, including commitment generation, response computation, and signature
//! combination.

use alloc::{collections::BTreeMap, string::ToString, vec, vec::Vec};

use qp_rusty_crystals_dilithium::{
	fips202,
	params::{
		BETA, C_DASH_BYTES, D, GAMMA1, GAMMA2, K, L, N, OMEGA, POLYW1_PACKEDBYTES,
		POLYZ_PACKEDBYTES, Q,
	},
	poly, polyvec,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
	config::ThresholdConfig,
	error::{ThresholdError, ThresholdResult},
	keys::{PrivateKeyShare, PublicKey},
	participants::{ParticipantId, ParticipantList},
	protocol::{
		primitives::{
			compute_dilithium_hint, compute_ntt_dot_product, decompose_polyveck, mod_q,
			normalize_assuming_le2q, pack_signature, poly_pack_w, reduce_le2q, unpack_polyveck_w,
			HyperballSampleVector,
		},
		secret_sharing::{recover_share, SecretShare},
	},
};

// ============================================================================
// Internal State Types
// ============================================================================

/// Internal state after Round 1 completes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Round1Data {
	/// K different w commitments for canonical iterations.
	pub(crate) w_commitments: Vec<polyvec::Polyveck>,
	/// K different hyperball samples for reuse in Round 3.
	pub(crate) hyperball_samples: Vec<HyperballSampleVector>,
	/// The commitment hash that was broadcast.
	pub(crate) commitment_hash: [u8; 32],
	/// Random bytes used for commitment.
	pub(crate) rho_prime: [u8; 64],
}

/// Internal state after Round 2 completes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Round2Data {
	/// Message hash μ.
	pub(crate) mu: [u8; 64],
	/// Aggregated w values for all K iterations.
	pub(crate) w_aggregated: Vec<polyvec::Polyveck>,
	/// Active participants in this signing session.
	/// Stores the actual participant IDs (which can be arbitrary u32 values).
	/// The ParticipantList provides index mapping for internal bitmask operations.
	pub(crate) active_participants: ParticipantList,
}

// ============================================================================
// Session Identifier (SSID)
// ============================================================================

/// Size of the session identifier in bytes.
pub const SSID_SIZE: usize = 32;

/// Compute the session identifier (SSID) for a signing session.
///
/// The SSID binds:
/// - The public key (prevents cross-key replay)
/// - The threshold configuration (t, n)
/// - The signing participant set (prevents cross-session replay with different participants)
/// - An attempt nonce (prevents replay across signing attempts for the same message)
///
/// ```text
/// ssid = SHAKE256(
///     "dilithium-threshold-ssid-v1" ||
///     pubkey_bytes[2592] ||
///     threshold (u32 LE) ||
///     total_parties (u32 LE) ||
///     num_participants (u32 LE) ||
///     sorted_participant_ids (each u32 LE) ||
///     attempt_nonce[32]
/// )
/// ```
pub fn compute_ssid(
	public_key: &PublicKey,
	threshold: u32,
	total_parties: u32,
	participants: &ParticipantList,
	attempt_nonce: &[u8; 32],
) -> [u8; SSID_SIZE] {
	const DOMAIN_SEPARATOR: &[u8] = b"dilithium-threshold-ssid-v1";

	let mut ssid = [0u8; SSID_SIZE];
	let mut state = fips202::KeccakState::default();

	// Domain separator
	fips202::shake256_absorb(&mut state, DOMAIN_SEPARATOR, DOMAIN_SEPARATOR.len());

	// Public key bytes
	fips202::shake256_absorb(&mut state, public_key.as_bytes(), public_key.as_bytes().len());

	// Threshold configuration
	fips202::shake256_absorb(&mut state, &threshold.to_le_bytes(), 4);
	fips202::shake256_absorb(&mut state, &total_parties.to_le_bytes(), 4);

	// Number of participants
	let num_participants = participants.len() as u32;
	fips202::shake256_absorb(&mut state, &num_participants.to_le_bytes(), 4);

	// Sorted participant IDs (ParticipantList maintains sorted order internally)
	for participant_id in participants.iter() {
		fips202::shake256_absorb(&mut state, &participant_id.to_le_bytes(), 4);
	}

	// Attempt nonce
	fips202::shake256_absorb(&mut state, attempt_nonce, 32);

	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut ssid, SSID_SIZE, &mut state);

	ssid
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

/// Compute the commitment hash for Round 1.
///
/// The hash is computed as: SHAKE256(ssid || party_id || commitment_data)
/// where commitment_data is the packed w polynomials.
///
/// The SSID binds the commitment to this specific signing session, preventing
/// cross-session replay attacks (CVE-2022-47930 class vulnerabilities).
///
/// This function is used both when generating the commitment (Round 1) and
/// when verifying it (before Round 3) to ensure consistency.
pub(crate) fn compute_commitment_hash(
	ssid: &[u8; SSID_SIZE],
	party_id: ParticipantId,
	commitment_data: &[u8],
) -> [u8; 32] {
	let mut hash = [0u8; 32];
	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, ssid, SSID_SIZE);
	fips202::shake256_absorb(&mut state, &party_id.to_le_bytes(), 4);
	fips202::shake256_absorb(&mut state, commitment_data, commitment_data.len());
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut hash, 32, &mut state);
	hash
}

/// Verify that commitment data matches the commitment hash from Round 1.
///
/// This prevents rushing adversary attacks where a malicious party could
/// adaptively choose their w_i values after seeing other parties' commitments.
pub(crate) fn verify_commitment_hash(
	ssid: &[u8; SSID_SIZE],
	party_id: ParticipantId,
	commitment_data: &[u8],
	expected_hash: &[u8; 32],
) -> bool {
	let computed_hash = compute_commitment_hash(ssid, party_id, commitment_data);
	computed_hash == *expected_hash
}

/// Convert PrivateKeyShare to the internal share format.
/// Uses u16 subset masks to support up to 16 parties.
fn convert_shares(share: &PrivateKeyShare) -> BTreeMap<u16, SecretShare> {
	let mut shares: BTreeMap<u16, SecretShare> = BTreeMap::new();

	for (subset_id, share_data) in share.shares() {
		let mut s1_share = polyvec::Polyvecl::default();
		let mut s2_share = polyvec::Polyveck::default();

		for i in 0..L {
			s1_share.vec[i].coeffs.copy_from_slice(&share_data.s1[i]);
		}

		for i in 0..K {
			s2_share.vec[i].coeffs.copy_from_slice(&share_data.s2[i]);
		}

		shares.insert(*subset_id, SecretShare { s1_share, s2_share });
	}

	shares
}

/// Unpack a commitment from 23-bit packed format.
///
/// Returns an error if the commitment has an invalid size or contains
/// coefficients >= Q (which would indicate malicious input).
pub(crate) fn unpack_commitment_dilithium(commitment: &[u8]) -> ThresholdResult<polyvec::Polyveck> {
	let poly_q_size = ((N as usize) * 23).div_ceil(8); // 736 bytes per poly
	let expected_len = K * poly_q_size;

	if commitment.len() != expected_len {
		return Err(ThresholdError::InvalidCommitmentSize {
			expected: expected_len,
			actual: commitment.len(),
		});
	}

	unpack_polyveck_w(commitment).map_err(|e| ThresholdError::InvalidCommitmentData {
		party_id: 0, // Caller will provide the actual party_id in the error context
		reason: e.to_string(),
	})
}

/// Aggregate commitment vectors.
pub(crate) fn aggregate_commitments_dilithium(
	w_final: &mut polyvec::Polyveck,
	w_temp: &polyvec::Polyveck,
) {
	for (w_final_poly, w_temp_poly) in w_final.vec.iter_mut().zip(w_temp.vec.iter()).take(K) {
		poly::add_ip(w_final_poly, w_temp_poly);
		normalize_assuming_le2q(w_final_poly);
	}
}

// ============================================================================
// Round 1: Commitment Generation
// ============================================================================

/// Generate Round 1 commitment data.
///
/// # Arguments
///
/// * `ssid` - Session identifier binding this commitment to the current signing session
/// * `private_key` - This party's private key share
/// * `config` - Threshold configuration
/// * `seed` - Random seed for commitment generation
pub(crate) fn generate_round1(
	ssid: &[u8; SSID_SIZE],
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
		let sample_size = (N as usize) * (L + K);
		let mut hyperball_sample = HyperballSampleVector::new(sample_size);

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
		let (_, r_prime, nu) = get_threshold_params(config)?;
		hyperball_sample.sample_hyperball(r_prime, nu, &iter_rho_prime, k_iter as u16);

		// Store hyperball sample for reuse in Round 3
		hyperball_samples.push(hyperball_sample.clone());

		// Round to integer polynomials
		let mut y_k = polyvec::Polyvecl::default();
		let mut e_k = polyvec::Polyveck::default();
		hyperball_sample.round(&mut y_k, &mut e_k);

		// Compute w_k = A·y_k using NTT
		let mut w_k = polyvec::Polyveck::default();
		let mut y_k_ntt = y_k.clone();
		for y_poly in y_k_ntt.vec.iter_mut().take(L) {
			crate::circl_ntt::ntt(y_poly);
		}

		for (i, a_row) in a_matrix.iter().enumerate().take(K) {
			compute_ntt_dot_product(&mut w_k.vec[i], a_row, &y_k_ntt);

			// Apply ReduceLe2Q in NTT domain BEFORE InvNTT
			for j in 0..N as usize {
				let coeff = w_k.vec[i].coeffs[j];
				let coeff_u32 = if coeff < 0 { (coeff + Q) as u32 } else { coeff as u32 };
				w_k.vec[i].coeffs[j] = reduce_le2q(coeff_u32) as i32;
			}

			crate::circl_ntt::inv_ntt(&mut w_k.vec[i]);

			// Add error term e_k for threshold scheme
			poly::add_ip(&mut w_k.vec[i], &e_k.vec[i]);

			// Apply ReduceLe2Q after Add
			for j in 0..N as usize {
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
	const POLY_Q_SIZE: usize = ((N as usize) * 23) / 8; // 736 bytes
	let single_commitment_size = K * POLY_Q_SIZE;
	let w_packed_size = k_iterations * single_commitment_size;
	let mut w_packed = vec![0u8; w_packed_size];

	let mut offset = 0;
	for k_idx in 0..k_iterations {
		if k_idx < w_commitments.len() && offset + single_commitment_size <= w_packed.len() {
			pack_w_dilithium(
				&w_commitments[k_idx],
				&mut w_packed[offset..offset + single_commitment_size],
			);
			offset += single_commitment_size;
		}
	}

	// Generate commitment hash using the shared function to ensure consistency with verification
	// The SSID binds this commitment to the specific signing session
	let commitment_hash = compute_commitment_hash(ssid, private_key.party_id(), &w_packed);

	Ok(Round1Data { w_commitments, hyperball_samples, commitment_hash, rho_prime })
}

/// Pack w using 23-bit encoding.
fn pack_w_dilithium(w: &polyvec::Polyveck, buf: &mut [u8]) {
	const POLY_Q_SIZE: usize = ((N as usize) * 23) / 8; // 736 bytes
	for i in 0..K {
		let offset = i * POLY_Q_SIZE;
		poly_pack_w(&w.vec[i], &mut buf[offset..offset + POLY_Q_SIZE]);
	}
}

/// Get threshold parameters (r, r', nu) for a configuration.
///
/// Returns (r, r_prime, nu) where:
/// - r is the rejection sampling radius
/// - r_prime is the hyperball sampling radius
/// - nu is the scaling factor (7 for ML-DSA-87)
///
/// # Errors
///
/// Returns an error if the (threshold, parties) configuration does not have
/// pre-computed hyperball parameters. Currently supports n ≤ 6.
fn get_threshold_params(config: &ThresholdConfig) -> ThresholdResult<(f64, f64, f64)> {
	// Threshold parameters (r, r', nu) from the reference implementation
	// nu = 7 for ML-DSA-87 (was incorrectly set to 3.0)
	match (config.threshold(), config.total_parties()) {
		(2, 2) => Ok((503119.0, 503192.0, 7.0)),
		(2, 3) => Ok((631601.0, 631703.0, 7.0)),
		(3, 3) => Ok((483107.0, 483180.0, 7.0)),
		(2, 4) => Ok((632903.0, 633006.0, 7.0)),
		(3, 4) => Ok((551752.0, 551854.0, 7.0)),
		(4, 4) => Ok((487958.0, 488031.0, 7.0)),
		(2, 5) => Ok((607694.0, 607820.0, 7.0)),
		(3, 5) => Ok((577400.0, 577546.0, 7.0)),
		(4, 5) => Ok((518384.0, 518510.0, 7.0)),
		(5, 5) => Ok((468214.0, 468287.0, 7.0)),
		(2, 6) => Ok((665106.0, 665232.0, 7.0)),
		(3, 6) => Ok((577541.0, 577704.0, 7.0)),
		(4, 6) => Ok((517689.0, 517853.0, 7.0)),
		(5, 6) => Ok((479692.0, 479819.0, 7.0)),
		(6, 6) => Ok((424124.0, 424197.0, 7.0)),
		(t, n) => Err(ThresholdError::InvalidConfiguration(alloc::format!(
			"No hyperball parameters for ({}, {}) configuration. Supported: n ≤ 6",
			t,
			n
		))),
	}
}

/// Pack Round 1 commitment data for broadcast.
pub(crate) fn pack_round1_commitment(round1: &Round1Data, config: &ThresholdConfig) -> Vec<u8> {
	let k = config.k_iterations() as usize;
	const POLY_Q_SIZE: usize = ((N as usize) * 23) / 8;
	let single_commitment_size = K * POLY_Q_SIZE;
	let total_size = k * single_commitment_size;
	let mut buf = vec![0u8; total_size];

	for k_idx in 0..k.min(round1.w_commitments.len()) {
		let offset = k_idx * single_commitment_size;
		pack_w_dilithium(
			&round1.w_commitments[k_idx],
			&mut buf[offset..offset + single_commitment_size],
		);
	}

	buf
}

// ============================================================================
// Round 2: Process Commitments
// ============================================================================

/// Process Round 2: initialize aggregation state and compute message hash.
///
/// This function sets up the Round 2 state with our own commitments. Aggregation
/// of other parties' commitments and verification happens in `round3_respond()`.
///
/// # Arguments
///
/// * `other_party_ids` - IDs of other parties in this signing session
pub(crate) fn process_round2(
	private_key: &PrivateKeyShare,
	public_key: &PublicKey,
	config: &ThresholdConfig,
	round1: &Round1Data,
	message: &[u8],
	context: &[u8],
	other_party_ids: &[ParticipantId],
) -> ThresholdResult<Round2Data> {
	crate::error::validate_context(context)?;

	let k = config.k_iterations() as usize;

	// Start with our own w_commitments
	let mut w_aggregated: Vec<polyvec::Polyveck> = round1.w_commitments.clone();

	// Ensure we have k entries
	while w_aggregated.len() < k {
		w_aggregated.push(polyvec::Polyveck::default());
	}

	// Build active participants list from our ID and other party IDs
	// This supports arbitrary participant IDs (not necessarily sequential)
	let mut all_party_ids: Vec<ParticipantId> = vec![private_key.party_id()];
	all_party_ids.extend_from_slice(other_party_ids);
	let active_participants = ParticipantList::new(&all_party_ids).ok_or_else(|| {
		ThresholdError::InvalidConfiguration("Duplicate party IDs in signing session".to_string())
	})?;

	// Compute message hash μ
	let mut tr = [0u8; 64];
	tr.copy_from_slice(public_key.tr());
	let mu = compute_mu(&tr, message, context);

	Ok(Round2Data { mu, w_aggregated, active_participants })
}

// ============================================================================
// Round 3: Response Generation
// ============================================================================

/// Generate Round 3 response.
///
/// # Arguments
///
/// * `ssid` - Session identifier binding this response to the current signing session
/// * `private_key` - This party's private key share
/// * `config` - Threshold configuration
/// * `round1` - This party's Round 1 data
/// * `round2` - Aggregated Round 2 data
///
/// # Errors
///
/// Returns an error if internal data structures have inconsistent lengths.
pub(crate) fn generate_round3_response(
	private_key: &PrivateKeyShare,
	config: &ThresholdConfig,
	round1: &Round1Data,
	round2: &Round2Data,
) -> ThresholdResult<Vec<polyvec::Polyvecl>> {
	// Convert shares
	let shares = convert_shares(private_key);

	// Get active parties directly from the ParticipantList
	// This supports arbitrary participant IDs (not necessarily sequential)
	let active_party_ids: Vec<ParticipantId> = round2.active_participants.iter().collect();

	// Recover the partial secret for this party (in NTT domain)
	// The recover_share function uses dkg_participants to map arbitrary IDs to indices
	let (s1_ntt, s2_ntt) = recover_share(
		&shares,
		private_key.party_id(),
		&active_party_ids,
		private_key.threshold(),
		private_key.total_parties(),
		private_key.dkg_participants(),
	)?;

	let k = config.k_iterations() as usize;

	// Validate internal data consistency - never silently produce zero responses
	if round2.w_aggregated.len() < k {
		return Err(ThresholdError::InvalidData(alloc::format!(
			"w_aggregated has {} entries, expected at least {}",
			round2.w_aggregated.len(),
			k
		)));
	}
	if round1.hyperball_samples.len() < k {
		return Err(ThresholdError::InvalidData(alloc::format!(
			"hyperball_samples has {} entries, expected at least {}",
			round1.hyperball_samples.len(),
			k
		)));
	}

	let mut zs: Vec<polyvec::Polyvecl> = vec![polyvec::Polyvecl::default(); k];

	let (r, _, nu) = get_threshold_params(config)?;

	// For each commitment iteration (lengths already validated above)
	for (i, z_out_slot) in zs.iter_mut().enumerate().take(k) {
		// Decompose w into w0 and w1
		let mut w0 = polyvec::Polyveck::default();
		let mut w1 = polyvec::Polyveck::default();
		decompose_polyveck(&round2.w_aggregated[i], &mut w0, &mut w1);

		// Compute challenge: c~ = H(μ || w1)
		// Note: SSID is NOT included in the challenge to maintain compatibility
		// with standard ML-DSA verification. Cross-session replay protection is
		// provided by SSID binding in commitment hashes and message validation.
		let mut w1_packed = vec![0u8; K * POLYW1_PACKEDBYTES];
		polyvec::k_pack_w1(&mut w1_packed, &w1);

		let mut challenge_bytes = [0u8; C_DASH_BYTES];
		let mut keccak_state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut keccak_state, &round2.mu, 64);
		fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
		fips202::shake256_finalize(&mut keccak_state);
		fips202::shake256_squeeze(&mut challenge_bytes, C_DASH_BYTES, &mut keccak_state);

		// Derive challenge polynomial and convert to NTT domain
		let mut challenge_ntt = poly::Poly::default();
		poly::challenge(&mut challenge_ntt, &challenge_bytes);
		crate::circl_ntt::ntt(&mut challenge_ntt);

		// Compute z = c·s1 (challenge times secret share)
		let mut z = polyvec::Polyvecl::default();
		for j in 0..L {
			crate::circl_ntt::mul_hat(&mut z.vec[j], &challenge_ntt, &s1_ntt.vec[j]);
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
		let mut cs2 = polyvec::Polyveck::default();
		for j in 0..K {
			crate::circl_ntt::mul_hat(&mut cs2.vec[j], &challenge_ntt, &s2_ntt.vec[j]);
			crate::circl_ntt::inv_ntt(&mut cs2.vec[j]);
		}
		// Normalize cs2
		for j in 0..K {
			for coeff in cs2.vec[j].coeffs.iter_mut() {
				let c = *coeff;
				let c_u32 = if c < 0 { (c + Q) as u32 } else { c as u32 };
				*coeff = mod_q(c_u32) as i32;
			}
		}

		// Convert to floating-point and add hyperball sample
		let mut response_float = HyperballSampleVector::from_polyvecs(&z, &cs2);
		response_float.add(&round1.hyperball_samples[i]);

		// Rejection sampling check
		if response_float.excess(r, nu) {
			continue;
		}

		// Round back to integers (only need z response, not the s2 component)
		let mut z_out = polyvec::Polyvecl::default();
		response_float.round_z_response(&mut z_out);

		// Convert from centered format to [0, Q) format
		for j in 0..L {
			for coeff in z_out.vec[j].coeffs.iter_mut() {
				if *coeff < 0 {
					*coeff += Q;
				}
			}
		}

		*z_out_slot = z_out;
	}

	Ok(zs)
}

/// Pack responses for broadcast.
pub(crate) fn pack_responses(responses: &[polyvec::Polyvecl]) -> Vec<u8> {
	let single_response_size = L * POLYZ_PACKEDBYTES;
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
			let poly_offset = offset + j * POLYZ_PACKEDBYTES;
			poly::z_pack(
				&mut buf[poly_offset..poly_offset + POLYZ_PACKEDBYTES],
				&z_centered.vec[j],
			);
		}
	}

	buf
}

/// Unpack responses from broadcast.
///
/// # Errors
///
/// Returns `InvalidResponseSize` if the data length doesn't match the expected
/// size for k iterations. This prevents silent zero-padding of malformed input
/// from malicious parties.
pub(crate) fn unpack_responses(
	data: &[u8],
	config: &ThresholdConfig,
) -> ThresholdResult<Vec<polyvec::Polyvecl>> {
	let k = config.k_iterations() as usize;
	let single_response_size = L * 640; // L * POLY_LE_GAMMA1_SIZE
	let expected_size = k * single_response_size;

	// Validate input size upfront - never silently zero-pad malformed data
	if data.len() != expected_size {
		return Err(ThresholdError::InvalidResponseSize {
			expected: expected_size,
			actual: data.len(),
		});
	}

	let mut responses = Vec::with_capacity(k);

	for i in 0..k {
		let start = i * single_response_size;
		let mut z = polyvec::Polyvecl::default();
		for j in 0..L {
			let poly_start = start + j * 640;
			let poly_end = poly_start + 640;
			// Size already validated, so this slice is guaranteed to be valid
			poly::z_unpack(&mut z.vec[j], &data[poly_start..poly_end]);
		}
		responses.push(z);
	}

	Ok(responses)
}

// ============================================================================
// Signature Combination
// ============================================================================

/// Check if a single party's z response for one iteration satisfies the norm bound.
/// Returns true if the response is valid (within bounds).
///
/// Checks the norm bound on a party's response vector.
fn check_party_z_norm(z_i: &polyvec::Polyvecl, gamma1_minus_beta: i32) -> bool {
	for z_poly in z_i.vec.iter().take(L) {
		for coeff in z_poly.coeffs.iter() {
			let centered = if *coeff > Q / 2 { *coeff - Q } else { *coeff };
			if centered.abs() >= gamma1_minus_beta {
				return false;
			}
		}
	}
	true
}

/// Combine all responses into a final signature.
///
/// # Security Note (M3)
/// This function validates per-party z-norms before aggregation to prevent
/// a single malicious party from causing all signature attempts to fail
/// by contributing an out-of-bounds response. Parties with invalid z-norms
/// are excluded on a per-iteration basis, maximizing the chance of producing
/// a valid signature as long as at least t honest parties participate.
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
	let threshold = config.threshold() as usize;

	// Per-party z-norm bound: γ1 - β (same as individual Dilithium bound)
	let gamma1_minus_beta = (GAMMA1 - BETA) as i32;

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
	let t1 = unpack_t1(public_key.as_bytes())?;

	// For each commitment iteration, try to find a valid signature
	for i in 0..k_iterations.min(w_aggregated.len()) {
		// M3: Per-iteration exclusion - filter parties with valid z-norms for this iteration
		let mut z_aggregated = polyvec::Polyvecl::default();
		let mut valid_party_count = 0usize;

		for party_responses in all_responses.iter() {
			if i < party_responses.len() {
				let z_i = &party_responses[i];
				// Only include parties with valid z-norm for this iteration
				if check_party_z_norm(z_i, gamma1_minus_beta) {
					// Aggregate this party's response
					for (agg_poly, party_poly) in
						z_aggregated.vec.iter_mut().zip(z_i.vec.iter()).take(L)
					{
						for (agg_coeff, party_coeff) in
							agg_poly.coeffs.iter_mut().zip(party_poly.coeffs.iter())
						{
							*agg_coeff = (*agg_coeff + *party_coeff) % Q;
						}
					}
					valid_party_count += 1;
				}
				// Parties with invalid z-norm are silently excluded for this iteration
			}
		}

		// Need at least t valid parties to produce a signature
		if valid_party_count < threshold {
			continue; // Try next iteration
		}

		// Decompose w into w0 and w1
		let mut w0 = polyvec::Polyveck::default();
		let mut w1 = polyvec::Polyveck::default();
		decompose_polyveck(&w_aggregated[i], &mut w0, &mut w1);

		// Check aggregated z-norm (may still exceed due to sum of valid parties)
		let mut z_exceeds = false;
		'z_check: for z_poly in z_aggregated.vec.iter().take(L) {
			for coeff in z_poly.coeffs.iter() {
				let centered = if *coeff > Q / 2 { *coeff - Q } else { *coeff };
				if centered.abs() >= gamma1_minus_beta {
					z_exceeds = true;
					break 'z_check;
				}
			}
		}
		if z_exceeds {
			continue;
		}

		// Compute Az (z in NTT domain)
		let mut zh = z_aggregated.clone();
		for zh_poly in zh.vec.iter_mut().take(L) {
			for coeff in zh_poly.coeffs.iter_mut() {
				if *coeff > Q / 2 {
					*coeff -= Q;
				}
			}
			crate::circl_ntt::ntt(zh_poly);
		}

		let mut az = polyvec::Polyveck::default();
		for (az_poly, a_row) in az.vec.iter_mut().zip(a_matrix.iter()).take(K) {
			compute_ntt_dot_product(az_poly, a_row, &zh);
		}

		// Compute challenge: c~ = H(μ || w1)
		// Note: SSID is NOT included in the challenge to maintain compatibility
		// with standard ML-DSA verification. Cross-session replay protection is
		// provided by SSID binding in commitment hashes and message validation.
		let mut w1_packed = vec![0u8; K * POLYW1_PACKEDBYTES];
		polyvec::k_pack_w1(&mut w1_packed, &w1);

		let mut challenge_bytes = [0u8; C_DASH_BYTES];
		let mut keccak_state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut keccak_state, &mu, 64);
		fips202::shake256_absorb(&mut keccak_state, &w1_packed, w1_packed.len());
		fips202::shake256_finalize(&mut keccak_state);
		fips202::shake256_squeeze(&mut challenge_bytes, C_DASH_BYTES, &mut keccak_state);

		// Derive challenge polynomial and convert to NTT domain
		let mut challenge_ntt = poly::Poly::default();
		poly::challenge(&mut challenge_ntt, &challenge_bytes);
		crate::circl_ntt::ntt(&mut challenge_ntt);

		// Compute 2^d * c * t1 (scaled challenge times public key component)
		let mut scaled_challenge_t1 = polyvec::Polyveck::default();
		for (scaled_poly, t1_poly) in scaled_challenge_t1.vec.iter_mut().zip(t1.vec.iter()).take(K)
		{
			for (scaled_coeff, t1_coeff) in scaled_poly.coeffs.iter_mut().zip(t1_poly.coeffs.iter())
			{
				*scaled_coeff = *t1_coeff << D;
			}
			crate::circl_ntt::ntt(scaled_poly);
			let tmp = scaled_poly.clone();
			crate::circl_ntt::mul_hat(scaled_poly, &tmp, &challenge_ntt);
		}

		// Compute Az - 2^d * c * t1
		for (scaled_poly, az_poly) in scaled_challenge_t1.vec.iter_mut().zip(az.vec.iter()).take(K)
		{
			for (scaled_coeff, az_coeff) in scaled_poly.coeffs.iter_mut().zip(az_poly.coeffs.iter())
			{
				*scaled_coeff = *az_coeff - *scaled_coeff;
			}
			poly::reduce(scaled_poly);
			crate::circl_ntt::inv_ntt(scaled_poly);
			normalize_assuming_le2q(scaled_poly);
		}

		// Compute difference: f = (Az - 2^d*c*t1) - w_aggregated
		let mut difference = polyvec::Polyveck::default();
		for (diff_poly, (scaled_poly, w_poly)) in difference
			.vec
			.iter_mut()
			.zip(scaled_challenge_t1.vec.iter().zip(w_aggregated[i].vec.iter()))
			.take(K)
		{
			for (diff_coeff, (scaled_coeff, w_coeff)) in diff_poly
				.coeffs
				.iter_mut()
				.zip(scaled_poly.coeffs.iter().zip(w_poly.coeffs.iter()))
			{
				*diff_coeff = *scaled_coeff - *w_coeff;
			}
			// Normalize coefficients to [0, Q)
			for coeff in diff_poly.coeffs.iter_mut() {
				let coeff_u32 = if *coeff < 0 { (*coeff + Q) as u32 } else { *coeff as u32 };
				*coeff = mod_q(coeff_u32) as i32;
			}
		}

		// Ensure ||difference||_∞ < γ2
		let gamma2 = GAMMA2 as i32;
		let mut difference_exceeds = false;
		'diff_check: for diff_poly in difference.vec.iter().take(K) {
			for coeff in diff_poly.coeffs.iter() {
				let centered = if *coeff > Q / 2 { *coeff - Q } else { *coeff };
				if centered.abs() >= gamma2 {
					difference_exceeds = true;
					break 'diff_check;
				}
			}
		}
		if difference_exceeds {
			continue;
		}

		// Compute w0 + difference for hint computation
		let mut w0_plus_diff = polyvec::Polyveck::default();
		for (w0pd_poly, (w0_poly, diff_poly)) in w0_plus_diff
			.vec
			.iter_mut()
			.zip(w0.vec.iter().zip(difference.vec.iter()))
			.take(K)
		{
			for (w0pd_coeff, (w0_coeff, diff_coeff)) in w0pd_poly
				.coeffs
				.iter_mut()
				.zip(w0_poly.coeffs.iter().zip(diff_poly.coeffs.iter()))
			{
				*w0pd_coeff = *w0_coeff + *diff_coeff;
			}
			// Normalize coefficients to [0, Q)
			for coeff in w0pd_poly.coeffs.iter_mut() {
				let coeff_u32 = if *coeff < 0 { (*coeff + Q) as u32 } else { *coeff as u32 };
				*coeff = mod_q(coeff_u32) as i32;
			}
		}

		// Compute hint for signature
		let mut hint = polyvec::Polyveck::default();
		let hint_pop = compute_dilithium_hint(&mut hint, &w0_plus_diff, &w1);

		if hint_pop <= OMEGA {
			// Convert z to centered form for packing
			let mut z_centered = z_aggregated.clone();
			for z_poly in z_centered.vec.iter_mut().take(L) {
				for coeff in z_poly.coeffs.iter_mut() {
					if *coeff > Q / 2 {
						*coeff -= Q;
					}
				}
			}

			// Pack signature with challenge and hint
			let mut challenge_full = [0u8; 64];
			challenge_full[..C_DASH_BYTES].copy_from_slice(&challenge_bytes);
			let sig = pack_signature(&challenge_full, &z_centered, &hint);
			return Ok(sig);
		}
	}

	Err(ThresholdError::CombinationFailed)
}

/// Unpack t1 from public key bytes.
///
/// # Errors
///
/// Returns `InvalidPublicKeySize` if `pk_bytes` is not the expected size (2592 bytes).
fn unpack_t1(pk_bytes: &[u8]) -> ThresholdResult<polyvec::Polyveck> {
	// Validate size: 32 (rho) + K * 320 (t1) = 32 + 8 * 320 = 2592
	const EXPECTED_SIZE: usize = 32 + K * 320;
	if pk_bytes.len() != EXPECTED_SIZE {
		return Err(ThresholdError::InvalidPublicKeySize {
			expected: EXPECTED_SIZE,
			actual: pk_bytes.len(),
		});
	}

	let mut t1 = polyvec::Polyveck::default();
	let t1_bytes = &pk_bytes[32..]; // Skip rho

	// Unpack t1 (320 bytes per polynomial = 256 * 10 / 8)
	for poly_idx in 0..K {
		let poly_start = poly_idx * 320;
		for i in (0..(N as usize)).step_by(4) {
			let byte_idx = poly_start + (i * 10) / 8;
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

	Ok(t1)
}
