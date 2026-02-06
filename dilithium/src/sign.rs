use crate::{
	fips202, packing, params, poly,
	poly::Poly,
	polyvec,
	polyvec::Polyveck,
	SensitiveBytes32,
};
#[cfg(not(feature = "embedded"))]
use crate::polyvec::Polyvecl;
#[cfg(not(feature = "embedded"))]
use core::array;
use zeroize::Zeroize;
#[cfg(not(feature = "embedded"))]
use zeroize::ZeroizeOnDrop;

const K: usize = params::K;
const L: usize = params::L;
#[cfg(feature = "embedded")]
const N: usize = params::N as usize;

/// Generate public and private key.
///
/// # Arguments
///
/// * 'pk' - preallocated buffer for public key
/// * 'sk' - preallocated buffer for private key
/// * 'seed' - required seed
pub fn keypair(pk: &mut [u8], sk: &mut [u8], seed: SensitiveBytes32) {
	let mut seed_bytes = seed.into_bytes();
	const SEEDBUF_LEN: usize = 2 * params::SEEDBYTES + params::CRHBYTES;
	let mut seedbuf = [0u8; SEEDBUF_LEN];
	// Build preimage = seed || K || L (accept any seed length when provided)
	let mut preimage: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
	preimage.extend_from_slice(&seed_bytes);

	preimage.push(params::K as u8);
	preimage.push(params::L as u8);
	fips202::shake256(&mut seedbuf, SEEDBUF_LEN, &preimage, preimage.len());

	let mut rho = [0u8; params::SEEDBYTES];
	rho.copy_from_slice(&seedbuf[..params::SEEDBYTES]);

	let mut rhoprime = [0u8; params::CRHBYTES];
	rhoprime.copy_from_slice(&seedbuf[params::SEEDBYTES..params::SEEDBYTES + params::CRHBYTES]);

	let mut key = [0u8; params::SEEDBYTES];
	key.copy_from_slice(&seedbuf[params::SEEDBYTES + params::CRHBYTES..]);

	#[cfg(feature = "embedded")]
	{
		sk[packing::SK_RHO_OFF..packing::SK_RHO_OFF + params::SEEDBYTES]
			.copy_from_slice(&rho[..params::SEEDBYTES]);
		sk[packing::SK_KEY_OFF..packing::SK_KEY_OFF + params::SEEDBYTES]
			.copy_from_slice(&key[..params::SEEDBYTES]);

		let mut t1 = crate::boxed::zeroed_box::<Polyveck>();
		let mut nonce: u16 = 0;
		for j in 0..L {
			let mut p = Poly::default();
			poly::uniform_eta(&mut p, &rhoprime, nonce);
			poly::eta_pack(
				&mut sk[packing::SK_S1_OFF + j * params::POLYETA_PACKEDBYTES..],
				&p,
			);
			poly::ntt(&mut p);
			polyvec::matrix_accum_column(&mut t1, &rho, &p, j);
			nonce += 1;
		}
		polyvec::k_reduce(&mut t1);
		polyvec::k_invntt_tomont(&mut t1);

		for i in 0..K {
			let mut p = Poly::default();
			poly::uniform_eta(&mut p, &rhoprime, nonce);
			poly::eta_pack(
				&mut sk[packing::SK_S2_OFF + i * params::POLYETA_PACKEDBYTES..],
				&p,
			);
			poly::add_ip(&mut t1.vec[i], &p);
			nonce += 1;
		}
		polyvec::k_caddq(&mut t1);

		for i in 0..K {
			let mut t0 = Poly::default();
			poly::power2round(&mut t1.vec[i], &mut t0);
			poly::t0_pack(
				&mut sk[packing::SK_T0_OFF + i * params::POLYT0_PACKEDBYTES..],
				&t0,
			);
		}

		packing::pack_pk(pk, &rho, &t1);

		let mut tr = [0u8; params::TR_BYTES];
		fips202::shake256(&mut tr, params::TR_BYTES, pk, params::PUBLICKEYBYTES);
		sk[packing::SK_TR_OFF..packing::SK_TR_OFF + params::TR_BYTES]
			.copy_from_slice(&tr[..params::TR_BYTES]);
	}

	#[cfg(not(feature = "embedded"))]
	{
		let mut s1 = Polyvecl::default();
		polyvec::l_uniform_eta(&mut s1, &rhoprime, 0);

		let mut s2 = Polyveck::default();
		polyvec::k_uniform_eta(&mut s2, &rhoprime, L as u16);

		let mut s1hat = s1.clone();
		polyvec::l_ntt(&mut s1hat);

		let mut t1 = Polyveck::default();
		polyvec::matrix_pointwise_montgomery_streaming(&mut t1, &rho, &s1hat);
		polyvec::k_reduce(&mut t1);
		polyvec::k_invntt_tomont(&mut t1);
		polyvec::k_add(&mut t1, &s2);
		polyvec::k_caddq(&mut t1);

		let mut t0 = Polyveck::default();
		polyvec::k_power2round(&mut t1, &mut t0);

		packing::pack_pk(pk, &rho, &t1);

		let mut tr = [0u8; params::TR_BYTES];
		fips202::shake256(&mut tr, params::TR_BYTES, pk, params::PUBLICKEYBYTES);

		packing::pack_sk(sk, &rho, &tr, &key, &t0, &s1, &s2);
	}

	// Zeroize sensitive intermediate seed material
	seedbuf.zeroize();
	seed_bytes.zeroize();
	preimage.zeroize();
	rhoprime.zeroize();
	key.zeroize();
}

/// Compute a signature for a given message from a private (secret) key.
///
/// # Arguments
///
/// * 'sig' - preallocated with at least SIGNBYTES buffer
/// * 'msg' - message to sign
/// * 'sk' - private key to use
/// * 'hedged' - indicates wether to randomize the signature or to act deterministicly
///
/// Note signature depends on std because k_decompose depends on swap which depends on std
/// Unpacked secret key components
#[cfg(not(feature = "embedded"))]
#[derive(ZeroizeOnDrop)]
struct UnpackedSecretKey {
	public_seed_rho: [u8; params::SEEDBYTES],
	public_key_hash_tr: [u8; params::TR_BYTES],
	private_key_seed: [u8; params::SEEDBYTES],
	secret_poly_t0_ntt: Polyveck,
	secret_poly_s1_ntt: Polyvecl,
	secret_poly_s2_ntt: Polyveck,
}

/// Signing context containing precomputed values
#[cfg(not(feature = "embedded"))]
struct SigningContext {
	#[cfg(not(feature = "embedded"))]
	expanded_matrix_a: [Polyvecl; K],
	#[cfg(feature = "embedded")]
	public_seed_rho: [u8; params::SEEDBYTES],
	message_hash_mu: [u8; params::CRHBYTES],
	signing_entropy_rho_prime: [u8; params::CRHBYTES],
}

#[cfg(not(feature = "embedded"))]
impl Drop for SigningContext {
	fn drop(&mut self) {
		// Only zeroize the sensitive entropy, not the polynomial matrix or message hash
		self.signing_entropy_rho_prime.zeroize();
	}
}

/// Unpack secret key and prepare for signing
#[cfg(not(feature = "embedded"))]
fn unpack_secret_key_for_signing(secret_key_bytes: &[u8]) -> UnpackedSecretKey {
	let mut public_seed_rho = [0u8; params::SEEDBYTES];
	let mut public_key_hash_tr = [0u8; params::TR_BYTES];
	let mut private_key_seed = [0u8; params::SEEDBYTES];
	let mut secret_poly_t0 = Polyveck::default();
	let mut secret_poly_s1 = Polyvecl::default();
	let mut secret_poly_s2 = Polyveck::default();

	packing::unpack_sk(
		&mut public_seed_rho,
		&mut public_key_hash_tr,
		&mut private_key_seed,
		&mut secret_poly_t0,
		&mut secret_poly_s1,
		&mut secret_poly_s2,
		secret_key_bytes,
	);

	// Convert secret polynomials to NTT domain for efficiency
	polyvec::l_ntt(&mut secret_poly_s1);
	polyvec::k_ntt(&mut secret_poly_s2);
	polyvec::k_ntt(&mut secret_poly_t0);

	UnpackedSecretKey {
		public_seed_rho,
		public_key_hash_tr,
		private_key_seed,
		secret_poly_t0_ntt: secret_poly_t0,
		secret_poly_s1_ntt: secret_poly_s1,
		secret_poly_s2_ntt: secret_poly_s2,
	}
}

/// Compute message hash and signing randomness
#[cfg(not(feature = "embedded"))]
fn prepare_signing_context(
	unpacked_sk: &UnpackedSecretKey,
	message: &[u8],
	hedge_randomness: Option<[u8; params::SEEDBYTES]>,
) -> SigningContext {
	// Compute message hash μ = H(tr || pre || msg) where pre = (0, 0) for pure signatures
	let mut keccak_state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut keccak_state, &unpacked_sk.public_key_hash_tr, params::TR_BYTES);
	fips202::shake256_absorb(&mut keccak_state, message, message.len());
	fips202::shake256_finalize(&mut keccak_state);
	let mut message_hash_mu = [0u8; params::CRHBYTES];
	fips202::shake256_squeeze(&mut message_hash_mu, params::CRHBYTES, &mut keccak_state);

	// Generate signing randomness ρ' = H(K || rnd || μ)
	let mut hedge_bytes = hedge_randomness.unwrap_or([0u8; params::SEEDBYTES]);
	keccak_state.init();
	fips202::shake256_absorb(&mut keccak_state, &unpacked_sk.private_key_seed, params::SEEDBYTES);
	fips202::shake256_absorb(&mut keccak_state, &hedge_bytes, params::SEEDBYTES);
	fips202::shake256_absorb(&mut keccak_state, &message_hash_mu, params::CRHBYTES);
	fips202::shake256_finalize(&mut keccak_state);
	let mut signing_entropy_rho_prime = [0u8; params::CRHBYTES];
	fips202::shake256_squeeze(&mut signing_entropy_rho_prime, params::CRHBYTES, &mut keccak_state);

	// Zeroize sensitive hedge bytes after use
	hedge_bytes.zeroize();

	#[cfg(feature = "embedded")]
	{
		SigningContext {
			public_seed_rho: unpacked_sk.public_seed_rho,
			message_hash_mu,
			signing_entropy_rho_prime,
		}
	}

	#[cfg(not(feature = "embedded"))]
	{
		let mut expanded_matrix_a: [Polyvecl; K] = array::from_fn(|_| Polyvecl::default());
		polyvec::matrix_expand(&mut expanded_matrix_a, &unpacked_sk.public_seed_rho);
		SigningContext { expanded_matrix_a, message_hash_mu, signing_entropy_rho_prime }
	}
}

/// Compute z = y + cs1 and check if ||z||∞ < γ₁ - β
#[cfg(not(feature = "embedded"))]
fn compute_and_check_signature_z(
	signature_z: &mut Polyvecl,
	masking_vector_y: &Polyvecl,
	challenge_poly_c: &Poly,
	secret_poly_s1_ntt: &Polyvecl,
) -> bool {
	// Compute z = y + cs1
	polyvec::l_pointwise_poly_montgomery(signature_z, challenge_poly_c, secret_poly_s1_ntt);
	polyvec::l_invntt_tomont(signature_z);
	polyvec::l_add(signature_z, masking_vector_y);
	polyvec::l_reduce(signature_z);

	// Check ||z||∞ < γ₁ - β
	polyvec::polyvecl_is_norm_within_bound(signature_z, (params::GAMMA1 - params::BETA) as i32)
}

/// Compute w0 - cs2 and check if ||w0 - cs2||∞ < γ₂ - β
#[cfg(not(feature = "embedded"))]
fn compute_and_check_commitment_w0(
	commitment_w0: &mut Polyveck,
	challenge_poly_c: &Poly,
	secret_poly_s2_ntt: &Polyveck,
) -> bool {
	let mut temp_vector = Polyveck::default();

	// Compute cs2
	polyvec::k_pointwise_poly_montgomery(&mut temp_vector, challenge_poly_c, secret_poly_s2_ntt);
	polyvec::k_invntt_tomont(&mut temp_vector);

	// Compute w0 - cs2
	polyvec::k_sub(commitment_w0, &temp_vector);
	polyvec::k_reduce(commitment_w0);

	// Check ||w0 - cs2||∞ < γ₂ - β
	polyvec::polyveck_is_norm_within_bound(commitment_w0, (params::GAMMA2 - params::BETA) as i32)
}

/// Compute challenge_t0 and check if ||challenge_t0||∞ < γ₂
#[cfg(not(feature = "embedded"))]
fn compute_and_check_challenge_t0(
	challenge_t0: &mut Polyveck,
	challenge_poly_c: &Poly,
	secret_poly_t0_ntt: &Polyveck,
) -> bool {
	// Compute challenge_t0 = c * t0
	polyvec::k_pointwise_poly_montgomery(challenge_t0, challenge_poly_c, secret_poly_t0_ntt);
	polyvec::k_invntt_tomont(challenge_t0);
	polyvec::k_reduce(challenge_t0);

	// Check ||challenge_t0||∞ < γ₂
	polyvec::polyveck_is_norm_within_bound(challenge_t0, params::GAMMA2 as i32)
}

/// Compute hint vector and check if weight ≤ ω
#[cfg(not(feature = "embedded"))]
fn compute_and_check_hint_vector(
	hint_vector_h: &mut Polyveck,
	commitment_w0: &Polyveck,
	challenge_t0: &Polyveck,
	commitment_w1: &Polyveck,
) -> bool {
	// Compute w0 + challenge_t0 for hint generation
	let mut w0_plus_challenge_t0 = commitment_w0.clone();
	polyvec::k_add(&mut w0_plus_challenge_t0, challenge_t0);

	// Generate hint vector
	let hint_weight = polyvec::k_make_hint(hint_vector_h, &w0_plus_challenge_t0, commitment_w1);

	// Check hint weight ≤ ω
	hint_weight <= params::OMEGA as i32
}

#[cfg(not(feature = "embedded"))]
fn generate_masking_vector_and_commitment(
	masking_vector_y: &mut Polyvecl,
	commitment_w1: &mut Polyveck,
	commitment_w0: &mut Polyveck,
	signature_z_temp: &mut Polyvecl,
	expanded_matrix_a: &[Polyvecl; K],
	signing_entropy: &[u8],
	attempt_nonce: u16,
) {
	polyvec::l_uniform_gamma1(masking_vector_y, signing_entropy, attempt_nonce);

	*signature_z_temp = masking_vector_y.clone();
	polyvec::l_ntt(signature_z_temp);
	polyvec::matrix_pointwise_montgomery(commitment_w1, expanded_matrix_a, signature_z_temp);
	polyvec::k_reduce(commitment_w1);
	polyvec::k_invntt_tomont(commitment_w1);
	polyvec::k_caddq(commitment_w1);
	polyvec::k_decompose(commitment_w1, commitment_w0);
}

/// Generate challenge polynomial from commitment and message hash
#[cfg(not(feature = "embedded"))]
fn generate_challenge_polynomial(
	signature_buffer: &mut [u8],
	commitment_w1: &Polyveck,
	message_hash_mu: &[u8],
) -> Poly {
	// Pack w1 into signature buffer temporarily
	polyvec::k_pack_w1(signature_buffer, commitment_w1);

	let mut keccak_state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut keccak_state, message_hash_mu, params::CRHBYTES);
	fips202::shake256_absorb(&mut keccak_state, signature_buffer, K * params::POLYW1_PACKEDBYTES);
	fips202::shake256_finalize(&mut keccak_state);
	fips202::shake256_squeeze(signature_buffer, params::C_DASH_BYTES, &mut keccak_state);

	let mut challenge_poly_c = Poly::default();
	poly::challenge(&mut challenge_poly_c, signature_buffer);
	poly::ntt(&mut challenge_poly_c);
	challenge_poly_c
}

/// Main signature generation function
#[cfg(not(feature = "embedded"))]
pub(crate) fn signature(
	signature_output: &mut [u8],
	message: &[u8],
	secret_key_bytes: &[u8],
	hedge: Option<[u8; params::SEEDBYTES]>,
) {
	// Step 1: Unpack secret key components
	let unpacked_sk = unpack_secret_key_for_signing(secret_key_bytes);

	// Step 2: Prepare signing context (message hash, randomness, expanded matrix)
	let signing_ctx = prepare_signing_context(&unpacked_sk, message, hedge);

	// Step 3: Make the rejection sampling lumpy to smear out timing signals
	// Set this to 1 to revert to standard rejection sampling
	const MIN_SIGNING_ATTEMPTS: u16 = 16; // covers most cases, |max tau| < 0.1, while keeping runtime short (~1ms)

	let mut masking_vector_y = Polyvecl::default();
	let mut commitment_w1 = Polyveck::default();
	let mut commitment_w0 = Polyveck::default();
	let mut challenge_poly_c: Poly;
	let mut hint_vector_h = Polyveck::default();
	let mut signature_found = false;
	let mut dummy_output = [0u8; params::SIGNBYTES]; // Dummy buffer for timing countermeasures
	let mut valid_challenge = [0u8; params::C_DASH_BYTES];
	let mut valid_signature_z = Polyvecl::default();
	let mut valid_hint_h = Polyveck::default();
	let mut attempt_nonce = 0;

	// this outer loop should run exactly once in the vast majority of cases
	loop {
		for _ in 0..MIN_SIGNING_ATTEMPTS {
			// Generate masking vector and compute commitment
			let mut signature_z = Polyvecl::default();
			#[cfg(feature = "embedded")]
			generate_masking_vector_and_commitment(
				&mut masking_vector_y,
				&mut commitment_w1,
				&mut commitment_w0,
				&mut signature_z,
				&signing_ctx.public_seed_rho,
				&signing_ctx.signing_entropy_rho_prime,
				attempt_nonce,
			);
			#[cfg(not(feature = "embedded"))]
			generate_masking_vector_and_commitment(
				&mut masking_vector_y,
				&mut commitment_w1,
				&mut commitment_w0,
				&mut signature_z,
				&signing_ctx.expanded_matrix_a,
				&signing_ctx.signing_entropy_rho_prime,
				attempt_nonce,
			);

			// Generate challenge c = H(μ, w1) - use dummy buffer to avoid overwriting output
			challenge_poly_c = generate_challenge_polynomial(
				&mut dummy_output,
				&commitment_w1,
				&signing_ctx.message_hash_mu,
			);

			// Check first rejection condition: compute z = y + cs1 and check ||z||∞ < γ₁ - β
			let condition1 = compute_and_check_signature_z(
				&mut signature_z,
				&masking_vector_y,
				&challenge_poly_c,
				&unpacked_sk.secret_poly_s1_ntt,
			);

			// Check second rejection condition: compute w0 - cs2 and check ||w0 - cs2||∞ < γ₂ - β
			let condition2 = compute_and_check_commitment_w0(
				&mut commitment_w0,
				&challenge_poly_c,
				&unpacked_sk.secret_poly_s2_ntt,
			);

			// Compute challenge_t0 for third norm check and hint generation
			let mut challenge_t0 = Polyveck::default();
			let condition3 = compute_and_check_challenge_t0(
				&mut challenge_t0,
				&challenge_poly_c,
				&unpacked_sk.secret_poly_t0_ntt,
			);

			// Check fourth rejection condition: compute hint vector and check weight ≤ ω
			let condition4 = compute_and_check_hint_vector(
				&mut hint_vector_h,
				&commitment_w0,
				&challenge_t0,
				&commitment_w1,
			);

			let all_conditions_met = condition1 && condition2 && condition3 && condition4;

			// Always call pack_sig to dummy buffer for constant timing
			// Use empty hint vector when conditions aren't met to prevent out-of-bounds access
			let safe_hint = if all_conditions_met { &hint_vector_h } else { &Polyveck::default() };
			packing::pack_sig(&mut dummy_output, None, &signature_z, safe_hint);

			// Store valid signature components if this is the first valid one
			// This branch is data-dependent but the alternative complex branchless operations
			// may actually introduce more timing variations due to memory access patterns
			if all_conditions_met && !signature_found {
				valid_challenge.copy_from_slice(&dummy_output[..params::C_DASH_BYTES]);
				valid_signature_z = signature_z;
				valid_hint_h = hint_vector_h.clone();
				signature_found = true;
			}

			attempt_nonce += 1;
			// Continue loop regardless to maintain constant timing
		}

		// After fixed iterations, pack the final signature and return if found
		if signature_found {
			packing::pack_sig(
				signature_output,
				Some(&valid_challenge),
				&valid_signature_z,
				&valid_hint_h,
			);
			return;
		}
	}
}

#[cfg(feature = "embedded")]
fn decompose_w0_pack_w1(w0: &mut Polyveck, w1_packed: &mut [u8; K * params::POLYW1_PACKEDBYTES]) {
	for i in 0..K {
		let base = i * params::POLYW1_PACKEDBYTES;
		for j in 0..(N / 2) {
			let (a0_0, a1_0) = crate::rounding::decompose(w0.vec[i].coeffs[2 * j]);
			let (a0_1, a1_1) = crate::rounding::decompose(w0.vec[i].coeffs[2 * j + 1]);
			w0.vec[i].coeffs[2 * j] = a0_0;
			w0.vec[i].coeffs[2 * j + 1] = a0_1;
			w1_packed[base + j] = (a1_0 as u8) | ((a1_1 as u8) << 4);
		}
	}
}

#[cfg(feature = "embedded")]
fn w1_coeff(w1_packed: &[u8; K * params::POLYW1_PACKEDBYTES], i: usize, j: usize) -> i32 {
	let b = w1_packed[i * params::POLYW1_PACKEDBYTES + (j >> 1)];
	if (j & 1) == 0 { (b & 0x0F) as i32 } else { (b >> 4) as i32 }
}

#[cfg(feature = "embedded")]
pub(crate) fn signature(
	signature_output: &mut [u8],
	message: &[u8],
	secret_key_bytes: &[u8],
	hedge: Option<[u8; params::SEEDBYTES]>,
) {
	let public_seed_rho: &[u8] = &secret_key_bytes[packing::SK_RHO_OFF..packing::SK_RHO_OFF + params::SEEDBYTES];
	let private_key_seed: &[u8] = &secret_key_bytes[packing::SK_KEY_OFF..packing::SK_KEY_OFF + params::SEEDBYTES];
	let public_key_hash_tr: &[u8] = &secret_key_bytes[packing::SK_TR_OFF..packing::SK_TR_OFF + params::TR_BYTES];

	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, public_key_hash_tr, params::TR_BYTES);
	fips202::shake256_absorb(&mut state, message, message.len());
	fips202::shake256_finalize(&mut state);
	let mut mu = [0u8; params::CRHBYTES];
	fips202::shake256_squeeze(&mut mu, params::CRHBYTES, &mut state);

	let mut hedge_bytes = hedge.unwrap_or([0u8; params::SEEDBYTES]);
	state.init();
	fips202::shake256_absorb(&mut state, private_key_seed, params::SEEDBYTES);
	fips202::shake256_absorb(&mut state, &hedge_bytes, params::SEEDBYTES);
	fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
	fips202::shake256_finalize(&mut state);
	let mut rhoprime = [0u8; params::CRHBYTES];
	fips202::shake256_squeeze(&mut rhoprime, params::CRHBYTES, &mut state);
	hedge_bytes.zeroize();

	const MIN_SIGNING_ATTEMPTS: u16 = 16;
	let mut signature_found = false;
	let mut attempt_nonce: u16 = 0;

	let mut vk = crate::boxed::zeroed_box::<Polyveck>();
	let mut candidate_sig = crate::boxed::zeroed_box::<[u8; params::SIGNBYTES]>();
	let mut w1_packed = [0u8; K * params::POLYW1_PACKEDBYTES];
	let mut c = [0u8; params::C_DASH_BYTES];
	let mut cp = Poly::default();
	let mut tmp = Poly::default();
	let mut tmp2 = Poly::default();
	let mut y_i = Poly::default();

	loop {
		for _ in 0..MIN_SIGNING_ATTEMPTS {
			polyvec::k_zero(&mut vk);
			for j in 0..L {
				poly::uniform_gamma1(&mut tmp, &rhoprime, L as u16 * attempt_nonce + j as u16);
				poly::ntt(&mut tmp);
				polyvec::matrix_accum_column(&mut vk, public_seed_rho, &tmp, j);
			}
			polyvec::k_reduce(&mut vk);
			polyvec::k_invntt_tomont(&mut vk);
			polyvec::k_caddq(&mut vk);
			decompose_w0_pack_w1(&mut vk, &mut w1_packed);

			state.init();
			fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
			fips202::shake256_absorb(&mut state, &w1_packed, K * params::POLYW1_PACKEDBYTES);
			fips202::shake256_finalize(&mut state);
			fips202::shake256_squeeze(&mut c, params::C_DASH_BYTES, &mut state);

			candidate_sig[..params::C_DASH_BYTES].copy_from_slice(&c);
			poly::challenge(&mut cp, &c);
			poly::ntt(&mut cp);

			let mut all_ok = true;

			for i in 0..L {
				poly::uniform_gamma1(&mut y_i, &rhoprime, L as u16 * attempt_nonce + i as u16);
				let off = packing::SK_S1_OFF + i * params::POLYETA_PACKEDBYTES;
				poly::eta_unpack(&mut tmp, &secret_key_bytes[off..off + params::POLYETA_PACKEDBYTES]);
				poly::ntt(&mut tmp);
				poly::pointwise_montgomery(&mut tmp2, &cp, &tmp);
				poly::invntt_tomont(&mut tmp2);
				poly::reduce(&mut tmp2);
				poly::add_ip(&mut y_i, &tmp2);
				poly::reduce(&mut y_i);
				all_ok &= !poly::check_norm(&y_i, (params::GAMMA1 - params::BETA) as i32);
				let sig_off = params::C_DASH_BYTES + i * params::POLYZ_PACKEDBYTES;
				poly::z_pack(&mut candidate_sig[sig_off..sig_off + params::POLYZ_PACKEDBYTES], &y_i);
			}

			for i in 0..K {
				let off = packing::SK_S2_OFF + i * params::POLYETA_PACKEDBYTES;
				poly::eta_unpack(&mut tmp, &secret_key_bytes[off..off + params::POLYETA_PACKEDBYTES]);
				poly::ntt(&mut tmp);
				poly::pointwise_montgomery(&mut tmp2, &cp, &tmp);
				poly::invntt_tomont(&mut tmp2);
				poly::reduce(&mut tmp2);
				poly::sub_ip(&mut vk.vec[i], &tmp2);
				poly::reduce(&mut vk.vec[i]);
				all_ok &= !poly::check_norm(&vk.vec[i], (params::GAMMA2 - params::BETA) as i32);
			}

			for i in 0..K {
				let off = packing::SK_T0_OFF + i * params::POLYT0_PACKEDBYTES;
				poly::t0_unpack(&mut tmp, &secret_key_bytes[off..off + params::POLYT0_PACKEDBYTES]);
				poly::ntt(&mut tmp);
				poly::pointwise_montgomery(&mut tmp2, &cp, &tmp);
				poly::invntt_tomont(&mut tmp2);
				poly::reduce(&mut tmp2);
				all_ok &= !poly::check_norm(&tmp2, params::GAMMA2 as i32);
				poly::add_ip(&mut vk.vec[i], &tmp2);
			}

			let hint_off = params::C_DASH_BYTES + L * params::POLYZ_PACKEDBYTES;
			candidate_sig[hint_off..hint_off + params::OMEGA + K].fill(0);
			let mut k_total: usize = 0;
			for i in 0..K {
				for j in 0..N {
					let hint = crate::rounding::make_hint(vk.vec[i].coeffs[j], w1_coeff(&w1_packed, i, j));
					if hint != 0 {
						if k_total >= params::OMEGA {
							all_ok = false;
						} else {
							candidate_sig[hint_off + k_total] = j as u8;
							k_total += 1;
						}
					}
				}
				candidate_sig[hint_off + params::OMEGA + i] = k_total as u8;
			}

			if all_ok && !signature_found {
				signature_output.copy_from_slice(&candidate_sig[..params::SIGNBYTES]);
				signature_found = true;
			}
			attempt_nonce = attempt_nonce.wrapping_add(1);
		}

		if signature_found {
			return;
		}
	}
}

/// Verify a signature for a given message with a public key.
///
/// # Arguments
///
/// * 'sig' - signature to verify
/// * 'm' - message that is claimed to be signed
/// * 'pk' - public key
///
/// Returns 'true' if the verification process was successful, 'false' otherwise
#[cfg(not(feature = "embedded"))]
pub(crate) fn verify(sig: &[u8], m: &[u8], pk: &[u8]) -> bool {
	let mut buf = [0u8; K * crate::params::POLYW1_PACKEDBYTES];
	let mut rho = [0u8; params::SEEDBYTES];
	let mut mu = [0u8; params::CRHBYTES];
	let mut c = [0u8; params::C_DASH_BYTES];
	let mut c2 = [0u8; params::C_DASH_BYTES];
	// Allocate polynomial structures
	let mut cp = Poly::default();
	let mut z = Polyvecl::default();
	let mut t1 = Polyveck::default();
	let mut w1 = Polyveck::default();
	let mut h = Polyveck::default();
	let mut state = fips202::KeccakState::default(); // shake256_init()

	if sig.len() != crate::params::SIGNBYTES {
		return false;
	}

	packing::unpack_pk(&mut rho, &mut t1, pk);
	if !packing::unpack_sig(&mut c, &mut z, &mut h, sig) {
		return false;
	}
	if !polyvec::polyvecl_is_norm_within_bound(
		&z,
		(crate::params::GAMMA1 - crate::params::BETA) as i32,
	) {
		return false;
	}

	// Compute CRH(H(rho, t1), pre, msg) with pre=(0,0)
	fips202::shake256(&mut mu, params::CRHBYTES, pk, crate::params::PUBLICKEYBYTES);
	fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
	fips202::shake256_absorb(&mut state, m, m.len());
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut mu, params::CRHBYTES, &mut state);

	// Matrix-vector multiplication; compute Az - c2^dt1
	poly::challenge(&mut cp, &c);

	polyvec::l_ntt(&mut z);
	polyvec::matrix_pointwise_montgomery_streaming(&mut w1, &rho, &z);

	poly::ntt(&mut cp);
	polyvec::k_shiftl(&mut t1);
	polyvec::k_ntt(&mut t1);
	let t1_2 = t1.clone();
	polyvec::k_pointwise_poly_montgomery(&mut t1, &cp, &t1_2);

	polyvec::k_sub(&mut w1, &t1);
	polyvec::k_reduce(&mut w1);
	polyvec::k_invntt_tomont(&mut w1);

	// Reconstruct w1
	polyvec::k_caddq(&mut w1);
	polyvec::k_use_hint(&mut w1, &h);
	polyvec::k_pack_w1(&mut buf, &w1);

	// Call random oracle and verify challenge
	state.init();
	fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
	fips202::shake256_absorb(&mut state, &buf, K * crate::params::POLYW1_PACKEDBYTES);
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut c2, params::C_DASH_BYTES, &mut state);
	c == c2
}

#[cfg(feature = "embedded")]
pub(crate) fn verify(sig: &[u8], m: &[u8], pk: &[u8]) -> bool {
	let mut buf = [0u8; K * crate::params::POLYW1_PACKEDBYTES];
	let mut rho = [0u8; params::SEEDBYTES];
	let mut mu = [0u8; params::CRHBYTES];
	let mut c = [0u8; params::C_DASH_BYTES];
	let mut c2 = [0u8; params::C_DASH_BYTES];
	let mut cp = Poly::default();
	let mut t = Poly::default();
	let mut tmp = Poly::default();
	let mut w1 = crate::boxed::zeroed_box::<Polyveck>();
	let mut state = fips202::KeccakState::default();

	if sig.len() != crate::params::SIGNBYTES {
		return false;
	}
	if pk.len() != crate::params::PUBLICKEYBYTES {
		return false;
	}

	rho.copy_from_slice(&pk[..params::SEEDBYTES]);
	c.copy_from_slice(&sig[..params::C_DASH_BYTES]);

	let z_off = params::C_DASH_BYTES;
	for j in 0..L {
		poly::z_unpack(&mut tmp, &sig[z_off + j * params::POLYZ_PACKEDBYTES..]);
		if poly::check_norm(&tmp, (params::GAMMA1 - params::BETA) as i32) {
			return false;
		}
		poly::ntt(&mut tmp);
		polyvec::matrix_accum_column(&mut w1, &rho, &tmp, j);
	}

	fips202::shake256(&mut mu, params::CRHBYTES, pk, crate::params::PUBLICKEYBYTES);
	fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
	fips202::shake256_absorb(&mut state, m, m.len());
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut mu, params::CRHBYTES, &mut state);

	poly::challenge(&mut cp, &c);
	poly::ntt(&mut cp);

	for i in 0..K {
		let off = params::SEEDBYTES + i * params::POLYT1_PACKEDBYTES;
		poly::t1_unpack(&mut t, &pk[off..off + params::POLYT1_PACKEDBYTES]);
		poly::shiftl(&mut t);
		poly::ntt(&mut t);
		poly::pointwise_montgomery(&mut tmp, &cp, &t);
		poly::sub_ip(&mut w1.vec[i], &tmp);
	}

	polyvec::k_reduce(&mut w1);
	polyvec::k_invntt_tomont(&mut w1);
	polyvec::k_caddq(&mut w1);

	let h_off = params::C_DASH_BYTES + L * params::POLYZ_PACKEDBYTES;
	let mut prev_k: usize = 0;
	for i in 0..K {
		let cur_k = sig[h_off + params::OMEGA + i] as usize;
		if cur_k < prev_k || cur_k > params::OMEGA {
			return false;
		}
		let mut h_i = Poly::default();
		for j in prev_k..cur_k {
			if j > prev_k && sig[h_off + j] <= sig[h_off + j - 1] {
				return false;
			}
			h_i.coeffs[sig[h_off + j] as usize] = 1;
		}
		poly::use_hint(&mut w1.vec[i], &h_i);
		prev_k = cur_k;
	}
	for j in prev_k..params::OMEGA {
		if sig[h_off + j] > 0 {
			return false;
		}
	}

	polyvec::k_pack_w1(&mut buf, &w1);

	state.init();
	fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
	fips202::shake256_absorb(&mut state, &buf, K * crate::params::POLYW1_PACKEDBYTES);
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut c2, params::C_DASH_BYTES, &mut state);
	c == c2
}

#[cfg(test)]
mod tests {
	use alloc::{string::String, vec};
	use rand::Rng;

	use crate::SensitiveBytes32;

	fn get_random_bytes() -> SensitiveBytes32 {
		let mut rng = rand::rng();
		let mut bytes = [0u8; 32];
		rng.fill(&mut bytes);
		(&mut bytes).into()
	}

	fn get_random_msg() -> [u8; 128] {
		let mut rng = rand::rng();
		let mut bytes = [0u8; 128];
		rng.fill(&mut bytes);
		bytes
	}

	#[test]
	fn self_verify_hedged() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());
		let msg = get_random_msg();
		let mut sig = [0u8; crate::params::SIGNBYTES];
		let hedge = get_random_bytes();
		super::signature(&mut sig, &msg, &sk, Some(hedge.0));
		assert!(super::verify(&sig, &msg, &pk));
	}

	#[test]
	fn self_verify() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());
		let msg = get_random_msg();
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &msg, &sk, None);
		assert!(super::verify(&sig, &msg, &pk));
	}

	#[test]
	fn test_empty_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let empty_msg: &[u8] = &[];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, empty_msg, &sk, None);
		assert!(super::verify(&sig, empty_msg, &pk));
	}

	#[test]
	fn test_single_byte_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let msg = [0x42u8];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &msg, &sk, None);
		assert!(super::verify(&sig, &msg, &pk));
	}

	#[test]
	fn test_large_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let large_msg = vec![0xABu8; 10000];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &large_msg, &sk, None);
		assert!(super::verify(&sig, &large_msg, &pk));
	}

	#[test]
	fn test_deterministic_signing() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let msg = b"test message for deterministic signing";
		let mut sig1 = [0u8; crate::params::SIGNBYTES];
		let mut sig2 = [0u8; crate::params::SIGNBYTES];

		let hedge = get_random_bytes();

		super::signature(&mut sig1, msg, &sk, Some(hedge.0));
		super::signature(&mut sig2, msg, &sk, Some(hedge.0));

		// Deterministic signing should produce identical signatures
		assert_eq!(sig1, sig2);
		assert!(super::verify(&sig1, msg, &pk));
		assert!(super::verify(&sig2, msg, &pk));
	}

	#[test]
	fn test_hedged_signing_differs() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let msg = b"test message for hedged signing";
		let mut sig1 = [0u8; crate::params::SIGNBYTES];
		let mut sig2 = [0u8; crate::params::SIGNBYTES];

		let hedge1 = get_random_bytes();
		let hedge2 = get_random_bytes();

		super::signature(&mut sig1, msg, &sk, Some(hedge1.0));
		super::signature(&mut sig2, msg, &sk, Some(hedge2.0));

		// Hedged signing should produce different signatures (with high probability)
		assert_ne!(sig1, sig2);
		assert!(super::verify(&sig1, msg, &pk));
		assert!(super::verify(&sig2, msg, &pk));
	}

	#[test]
	fn test_wrong_message_fails() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let msg1 = b"original message";
		let msg2 = b"different message";
		let mut sig = [0u8; crate::params::SIGNBYTES];

		super::signature(&mut sig, msg1, &sk, None);

		// Should verify with correct message
		assert!(super::verify(&sig, msg1, &pk));
		// Should fail with wrong message
		assert!(!super::verify(&sig, msg2, &pk));
	}

	#[test]
	fn test_wrong_public_key_fails() {
		let mut pk1 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk1 = [0u8; crate::params::SECRETKEYBYTES];
		let mut pk2 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk2 = [0u8; crate::params::SECRETKEYBYTES];

		super::keypair(&mut pk1, &mut sk1, get_random_bytes());
		super::keypair(&mut pk2, &mut sk2, get_random_bytes());

		let msg = b"test message";
		let mut sig = [0u8; crate::params::SIGNBYTES];

		super::signature(&mut sig, msg, &sk1, None);

		// Should verify with correct key
		assert!(super::verify(&sig, msg, &pk1));
		// Should fail with wrong key
		assert!(!super::verify(&sig, msg, &pk2));
	}

	#[test]
	fn test_corrupted_signature_fails() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let msg = b"test message";
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, msg, &sk, None);

		// Original signature should verify
		assert!(super::verify(&sig, msg, &pk));

		// Corrupt first byte
		let original_byte = sig[0];
		sig[0] = sig[0].wrapping_add(1);
		assert!(!super::verify(&sig, msg, &pk));

		// Restore and corrupt last byte
		sig[0] = original_byte;
		let last_idx = sig.len() - 1;
		let original_last = sig[last_idx];
		sig[last_idx] = sig[last_idx].wrapping_add(1);
		assert!(!super::verify(&sig, msg, &pk));

		// Restore and verify it works again
		sig[last_idx] = original_last;
		assert!(super::verify(&sig, msg, &pk));
	}

	#[test]
	fn test_invalid_signature_length() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let msg = b"test message";

		// Test with too short signature
		let short_sig = [0u8; crate::params::SIGNBYTES - 1];
		assert!(!super::verify(&short_sig, msg, &pk));

		// Test with too long signature
		let long_sig = [0u8; crate::params::SIGNBYTES + 1];
		assert!(!super::verify(&long_sig, msg, &pk));
	}

	#[test]
	fn test_fixed_seed_keypair() {
		let seed = get_random_bytes();

		let mut pk1 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk1 = [0u8; crate::params::SECRETKEYBYTES];
		let mut pk2 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk2 = [0u8; crate::params::SECRETKEYBYTES];

		super::keypair(&mut pk1, &mut sk1, seed.clone());
		super::keypair(&mut pk2, &mut sk2, seed);

		// Same seed should produce same keypair
		assert_eq!(pk1, pk2);
		assert_eq!(sk1, sk2);
	}

	#[test]
	fn test_different_seeds_different_keys() {
		let mut seed1 = [0x42u8; crate::params::SEEDBYTES];
		let mut seed2 = [0x43u8; crate::params::SEEDBYTES];

		let mut pk1 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk1 = [0u8; crate::params::SECRETKEYBYTES];
		let mut pk2 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk2 = [0u8; crate::params::SECRETKEYBYTES];

		super::keypair(&mut pk1, &mut sk1, (&mut seed1).into());
		super::keypair(&mut pk2, &mut sk2, (&mut seed2).into());

		// Different seeds should produce different keypairs
		assert_ne!(pk1, pk2);
		assert_ne!(sk1, sk2);
	}

	#[test]
	fn test_multiple_messages_same_key() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let messages = [
			b"message 1".as_slice(),
			b"message 2",
			b"a much longer message that tests handling of various lengths",
			b"",
			b"single char: X",
		];

		for msg in &messages {
			let mut sig = [0u8; crate::params::SIGNBYTES];
			super::signature(&mut sig, msg, &sk, None);
			assert!(
				super::verify(&sig, msg, &pk),
				"Failed to verify message: {:?}",
				String::from_utf8_lossy(msg)
			);
		}
	}
	// Note: Test vector validation is handled in integration tests
	// (tests/src/verify_integration_tests.rs) which use proper NIST KAT test vectors for
	// comprehensive validation.
}
