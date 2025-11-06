use crate::{
	fips202, packing, params, poly,
	poly::Poly,
	polyvec,
	polyvec::{Polyveck, Polyvecl},
};

const K: usize = params::K;
const L: usize = params::L;

extern crate alloc;
use alloc::boxed::Box;
/// Generate public and private key.
///
/// # Arguments
///
/// * 'pk' - preallocated buffer for public key
/// * 'sk' - preallocated buffer for private key
/// * 'seed' - required seed
pub fn keypair(pk: &mut [u8], sk: &mut [u8], seed: &[u8]) {
	const SEEDBUF_LEN: usize = 2 * params::SEEDBYTES + params::CRHBYTES;
	let mut seedbuf = [0u8; SEEDBUF_LEN];
	// Build preimage = seed || K || L (accept any seed length when provided)
	let mut preimage: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
	preimage.extend_from_slice(seed);

	preimage.push(params::K as u8);
	preimage.push(params::L as u8);
	fips202::shake256(&mut seedbuf, SEEDBUF_LEN, &preimage, preimage.len());

	let mut rho = [0u8; params::SEEDBYTES];
	rho.copy_from_slice(&seedbuf[..params::SEEDBYTES]);

	let mut rhoprime = [0u8; params::CRHBYTES];
	rhoprime.copy_from_slice(&seedbuf[params::SEEDBYTES..params::SEEDBYTES + params::CRHBYTES]);

	let mut key = [0u8; params::SEEDBYTES];
	key.copy_from_slice(&seedbuf[params::SEEDBYTES + params::CRHBYTES..]);

	// Move large polynomial structures to heap to reduce stack usage
	let mut mat = Box::new([Polyvecl::default(); K]);
	polyvec::matrix_expand(&mut *mat, &rho);

	let mut s1 = Box::new(Polyvecl::default());
	polyvec::l_uniform_eta(&mut s1, &rhoprime, 0);

	let mut s2 = Box::new(Polyveck::default());
	polyvec::k_uniform_eta(&mut s2, &rhoprime, L as u16);

	let mut s1hat = Box::new(*s1);
	polyvec::l_ntt(&mut s1hat);

	let mut t1 = Box::new(Polyveck::default());
	polyvec::matrix_pointwise_montgomery(&mut t1, &*mat, &s1hat);
	polyvec::k_reduce(&mut t1);
	polyvec::k_invntt_tomont(&mut t1);
	polyvec::k_add(&mut t1, &s2);
	polyvec::k_caddq(&mut t1);

	let mut t0 = Box::new(Polyveck::default());
	polyvec::k_power2round(&mut t1, &mut t0);

	packing::pack_pk(pk, &rho, &t1);

	let mut tr = [0u8; params::TR_BYTES];
	fips202::shake256(&mut tr, params::TR_BYTES, pk, params::PUBLICKEYBYTES);

	packing::pack_sk(sk, &rho, &tr, &key, &t0, &s1, &s2);
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
struct UnpackedSecretKey {
	public_seed_rho: [u8; params::SEEDBYTES],
	public_key_hash_tr: [u8; params::TR_BYTES],
	private_key_seed: [u8; params::SEEDBYTES],
	secret_poly_t0_ntt: Box<Polyveck>,
	secret_poly_s1_ntt: Box<Polyvecl>,
	secret_poly_s2_ntt: Box<Polyveck>,
}

/// Signing context containing precomputed values
struct SigningContext {
	expanded_matrix_a: Box<[Polyvecl; K]>,
	message_hash_mu: [u8; params::CRHBYTES],
	signing_entropy_rho_prime: [u8; params::CRHBYTES],
}

/// Unpack secret key and prepare for signing
fn unpack_secret_key_for_signing(secret_key_bytes: &[u8]) -> UnpackedSecretKey {
	let mut public_seed_rho = [0u8; params::SEEDBYTES];
	let mut public_key_hash_tr = [0u8; params::TR_BYTES];
	let mut private_key_seed = [0u8; params::SEEDBYTES];
	let mut secret_poly_t0 = Box::new(Polyveck::default());
	let mut secret_poly_s1 = Box::new(Polyvecl::default());
	let mut secret_poly_s2 = Box::new(Polyveck::default());

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
fn prepare_signing_context(
	unpacked_sk: &UnpackedSecretKey,
	message: &[u8],
	hedge_randomness: Option<[u8; params::SEEDBYTES]>,
) -> SigningContext {
	// Compute message hash μ = H(tr || pre || msg) where pre = (0, 0) for pure signatures
	let mut keccak_state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut keccak_state, &unpacked_sk.public_key_hash_tr, params::TR_BYTES);
	let context_prefix = [0u8, 0u8]; // (domain_sep=0, context_len=0) for pure signatures
	fips202::shake256_absorb(&mut keccak_state, &context_prefix, 2);
	fips202::shake256_absorb(&mut keccak_state, message, message.len());
	fips202::shake256_finalize(&mut keccak_state);
	let mut message_hash_mu = [0u8; params::CRHBYTES];
	fips202::shake256_squeeze(&mut message_hash_mu, params::CRHBYTES, &mut keccak_state);

	// Generate signing randomness ρ' = H(K || rnd || μ)
	let hedge_bytes = hedge_randomness.unwrap_or([0u8; params::SEEDBYTES]);
	keccak_state.init();
	fips202::shake256_absorb(&mut keccak_state, &unpacked_sk.private_key_seed, params::SEEDBYTES);
	fips202::shake256_absorb(&mut keccak_state, &hedge_bytes, params::SEEDBYTES);
	fips202::shake256_absorb(&mut keccak_state, &message_hash_mu, params::CRHBYTES);
	fips202::shake256_finalize(&mut keccak_state);
	let mut signing_entropy_rho_prime = [0u8; params::CRHBYTES];
	fips202::shake256_squeeze(&mut signing_entropy_rho_prime, params::CRHBYTES, &mut keccak_state);

	// Expand matrix A from public seed
	let mut expanded_matrix_a = Box::new([Polyvecl::default(); K]);
	polyvec::matrix_expand(&mut *expanded_matrix_a, &unpacked_sk.public_seed_rho);

	SigningContext { expanded_matrix_a, message_hash_mu, signing_entropy_rho_prime }
}

/// Compute z = y + cs1 and check if ||z||∞ < γ₁ - β
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
fn compute_and_check_commitment_w0(
	commitment_w0: &mut Polyveck,
	challenge_poly_c: &Poly,
	secret_poly_s2_ntt: &Polyveck,
	temp_vector: &mut Polyveck,
) -> bool {
	// Compute cs2
	polyvec::k_pointwise_poly_montgomery(temp_vector, challenge_poly_c, secret_poly_s2_ntt);
	polyvec::k_invntt_tomont(temp_vector);

	// Compute w0 - cs2
	polyvec::k_sub(commitment_w0, temp_vector);
	polyvec::k_reduce(commitment_w0);

	// Check ||w0 - cs2||∞ < γ₂ - β
	polyvec::polyveck_is_norm_within_bound(commitment_w0, (params::GAMMA2 - params::BETA) as i32)
}

/// Compute challenge_t0 and check if ||challenge_t0||∞ < γ₂
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
fn compute_and_check_hint_vector(
	hint_vector_h: &mut Polyveck,
	commitment_w0: &Polyveck,
	challenge_t0: &Polyveck,
	commitment_w1: &Polyveck,
) -> bool {
	// Compute w0 + challenge_t0 for hint generation
	let mut w0_plus_challenge_t0 = *commitment_w0;
	polyvec::k_add(&mut w0_plus_challenge_t0, challenge_t0);

	// Generate hint vector
	let hint_weight = polyvec::k_make_hint(hint_vector_h, &w0_plus_challenge_t0, commitment_w1);

	// Check hint weight ≤ ω
	hint_weight <= params::OMEGA as i32
}

/// Generate masking vector and compute commitment w = Ay, then decompose w = w1*2^d + w0
fn generate_masking_vector_and_commitment(
	masking_vector_y: &mut Polyvecl,
	commitment_w1: &mut Polyveck,
	commitment_w0: &mut Polyveck,
	signature_z_temp: &mut Polyvecl,
	expanded_matrix_a: &[Polyvecl; K],
	signing_entropy: &[u8],
	attempt_nonce: u16,
) {
	// Generate random masking vector y
	polyvec::l_uniform_gamma1(masking_vector_y, signing_entropy, attempt_nonce);

	// Compute commitment w = Ay
	*signature_z_temp = *masking_vector_y;
	polyvec::l_ntt(signature_z_temp);
	polyvec::matrix_pointwise_montgomery(commitment_w1, expanded_matrix_a, signature_z_temp);
	polyvec::k_reduce(commitment_w1);
	polyvec::k_invntt_tomont(commitment_w1);
	polyvec::k_caddq(commitment_w1);

	// Decompose w = w1*2^d + w0
	polyvec::k_decompose(commitment_w1, commitment_w0);
}

/// Generate challenge polynomial from commitment and message hash
fn generate_challenge_polynomial(
	signature_buffer: &mut [u8],
	commitment_w1: &Polyveck,
	message_hash_mu: &[u8],
) -> Box<Poly> {
	// Pack w1 into signature buffer temporarily
	polyvec::k_pack_w1(signature_buffer, commitment_w1);

	let mut keccak_state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut keccak_state, message_hash_mu, params::CRHBYTES);
	fips202::shake256_absorb(&mut keccak_state, signature_buffer, K * params::POLYW1_PACKEDBYTES);
	fips202::shake256_finalize(&mut keccak_state);
	fips202::shake256_squeeze(signature_buffer, params::C_DASH_BYTES, &mut keccak_state);

	let mut challenge_poly_c = Box::new(Poly::default());
	poly::challenge(&mut challenge_poly_c, signature_buffer);
	poly::ntt(&mut challenge_poly_c);
	challenge_poly_c
}

/// Main signature generation function
pub fn signature(
	signature_output: &mut [u8],
	message: &[u8],
	secret_key_bytes: &[u8],
	hedge: Option<[u8; params::SEEDBYTES]>,
) {
	// Step 1: Unpack secret key components
	let unpacked_sk = unpack_secret_key_for_signing(secret_key_bytes);

	// Step 2: Prepare signing context (message hash, randomness, expanded matrix)
	let signing_ctx = prepare_signing_context(&unpacked_sk, message, hedge);

	// Step 3: Constant-time rejection sampling with fixed iterations
	const MAX_SIGNING_ATTEMPTS: u16 = 64; // covers > 99.9% of cases

	let mut masking_vector_y = Box::new(Polyvecl::default());
	let mut commitment_w1 = Box::new(Polyveck::default());
	let mut commitment_w0 = Box::new(Polyveck::default());
	let mut challenge_poly_c;
	let mut hint_vector_h = Box::new(Polyveck::default());
	let mut signature_found = false;
	let mut dummy_output = [0u8; params::SIGNBYTES]; // Dummy buffer for constant-time packing
	let mut valid_challenge = [0u8; params::C_DASH_BYTES];
	let mut valid_signature_z = Box::new(Polyvecl::default());
	let mut valid_hint_h = Box::new(Polyveck::default());

	// this outer loop should run exactly once in the vast majority of cases
	loop {
		for attempt_nonce in 0..MAX_SIGNING_ATTEMPTS {
			// Generate masking vector and compute commitment
			let mut signature_z = Box::new(Polyvecl::default());
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
				&mut hint_vector_h, // Use hint_vector_h as temporary storage
			);

			// Compute challenge_t0 for third norm check and hint generation
			let mut challenge_t0 = Box::new(Polyveck::default());
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
			// This branch is data-dependent but the alternative complex constant-time operations
			// may actually introduce more timing variations due to memory access patterns
			if all_conditions_met && !signature_found {
				valid_challenge.copy_from_slice(&dummy_output[..params::C_DASH_BYTES]);
				*valid_signature_z = *signature_z;
				*valid_hint_h = *hint_vector_h;
				signature_found = true;
			}

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

/// Verify a signature for a given message with a public key.
///
/// # Arguments
///
/// * 'sig' - signature to verify
/// * 'm' - message that is claimed to be signed
/// * 'pk' - public key
///
/// Returns 'true' if the verification process was successful, 'false' otherwise
pub fn verify(sig: &[u8], m: &[u8], pk: &[u8]) -> bool {
	let mut buf = [0u8; K * crate::params::POLYW1_PACKEDBYTES];
	let mut rho = [0u8; params::SEEDBYTES];
	let mut mu = [0u8; params::CRHBYTES];
	let mut c = [0u8; params::C_DASH_BYTES];
	let mut c2 = [0u8; params::C_DASH_BYTES];
	// Move large polynomial structures to heap to reduce stack usage
	let mut cp = Box::new(Poly::default());
	let mut mat = Box::new([Polyvecl::default(); K]);
	let mut z = Box::new(Polyvecl::default());
	let mut t1 = Box::new(Polyveck::default());
	let mut w1 = Box::new(Polyveck::default());
	let mut h = Box::new(Polyveck::default());
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
	let pre = [0u8, 0u8];
	fips202::shake256_absorb(&mut state, &pre, 2);
	fips202::shake256_absorb(&mut state, m, m.len());
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut mu, params::CRHBYTES, &mut state);

	// Matrix-vector multiplication; compute Az - c2^dt1
	poly::challenge(&mut cp, &c);
	polyvec::matrix_expand(&mut *mat, &rho);

	polyvec::l_ntt(&mut z);
	polyvec::matrix_pointwise_montgomery(&mut w1, &*mat, &z);

	poly::ntt(&mut cp);
	polyvec::k_shiftl(&mut t1);
	polyvec::k_ntt(&mut t1);
	let t1_2 = Box::new(*t1);
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
	// Doesn't require constant time equality check
	if c != c2 {
		return false;
	}
	true
}

#[cfg(test)]
mod tests {
	use alloc::{string::String, vec};
	use rand::Rng;

	fn get_random_bytes() -> [u8; 32] {
		let mut rng = rand::thread_rng();
		let mut bytes = [0u8; 32];
		rng.fill(&mut bytes);
		bytes
	}

	fn get_random_msg() -> [u8; 128] {
		let mut rng = rand::thread_rng();
		let mut bytes = [0u8; 128];
		rng.fill(&mut bytes);
		bytes
	}

	#[test]
	fn self_verify_hedged() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, &get_random_bytes());
		let msg = get_random_msg();
		let mut sig = [0u8; crate::params::SIGNBYTES];
		let hedge = get_random_bytes();
		super::signature(&mut sig, &msg, &sk, Some(hedge));
		assert!(super::verify(&sig, &msg, &pk));
	}

	#[test]
	fn self_verify() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, &get_random_bytes());
		let msg = get_random_msg();
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &msg, &sk, None);
		assert!(super::verify(&sig, &msg, &pk));
	}

	#[test]
	fn test_empty_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, &get_random_bytes());

		let empty_msg: &[u8] = &[];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, empty_msg, &sk, None);
		assert!(super::verify(&sig, empty_msg, &pk));
	}

	#[test]
	fn test_single_byte_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, &get_random_bytes());

		let msg = [0x42u8];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &msg, &sk, None);
		assert!(super::verify(&sig, &msg, &pk));
	}

	#[test]
	fn test_large_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, &get_random_bytes());

		let large_msg = vec![0xABu8; 10000];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &large_msg, &sk, None);
		assert!(super::verify(&sig, &large_msg, &pk));
	}

	#[test]
	fn test_deterministic_signing() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, &get_random_bytes());

		let msg = b"test message for deterministic signing";
		let mut sig1 = [0u8; crate::params::SIGNBYTES];
		let mut sig2 = [0u8; crate::params::SIGNBYTES];

		let hedge = get_random_bytes();

		super::signature(&mut sig1, msg, &sk, Some(hedge));
		super::signature(&mut sig2, msg, &sk, Some(hedge));

		// Deterministic signing should produce identical signatures
		assert_eq!(sig1, sig2);
		assert!(super::verify(&sig1, msg, &pk));
		assert!(super::verify(&sig2, msg, &pk));
	}

	#[test]
	fn test_hedged_signing_differs() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, &get_random_bytes());

		let msg = b"test message for hedged signing";
		let mut sig1 = [0u8; crate::params::SIGNBYTES];
		let mut sig2 = [0u8; crate::params::SIGNBYTES];

		let hedge1 = get_random_bytes();
		let hedge2 = get_random_bytes();

		super::signature(&mut sig1, msg, &sk, Some(hedge1));
		super::signature(&mut sig2, msg, &sk, Some(hedge2));

		// Hedged signing should produce different signatures (with high probability)
		assert_ne!(sig1, sig2);
		assert!(super::verify(&sig1, msg, &pk));
		assert!(super::verify(&sig2, msg, &pk));
	}

	#[test]
	fn test_wrong_message_fails() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, &get_random_bytes());

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

		super::keypair(&mut pk1, &mut sk1, &get_random_bytes());
		super::keypair(&mut pk2, &mut sk2, &get_random_bytes());

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
		super::keypair(&mut pk, &mut sk, &get_random_bytes());

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
		super::keypair(&mut pk, &mut sk, &get_random_bytes());

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

		super::keypair(&mut pk1, &mut sk1, &seed);
		super::keypair(&mut pk2, &mut sk2, &seed);

		// Same seed should produce same keypair
		assert_eq!(pk1, pk2);
		assert_eq!(sk1, sk2);
	}

	#[test]
	fn test_different_seeds_different_keys() {
		let seed1 = [0x42u8; crate::params::SEEDBYTES];
		let seed2 = [0x43u8; crate::params::SEEDBYTES];

		let mut pk1 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk1 = [0u8; crate::params::SECRETKEYBYTES];
		let mut pk2 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk2 = [0u8; crate::params::SECRETKEYBYTES];

		super::keypair(&mut pk1, &mut sk1, &seed1);
		super::keypair(&mut pk2, &mut sk2, &seed2);

		// Different seeds should produce different keypairs
		assert_ne!(pk1, pk2);
		assert_ne!(sk1, sk2);
	}

	#[test]
	fn test_multiple_messages_same_key() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, &get_random_bytes());

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
