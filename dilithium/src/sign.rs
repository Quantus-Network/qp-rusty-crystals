use crate::{
	fips202, packing, params, poly,
	poly::Poly,
	polyvec,
	polyvec::{Polyveck, Polyvecl},
	SensitiveBytes32,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const K: usize = params::K;
const L: usize = params::L;

/// Derive the public high bits `t1` and secret low bits `t0` from the public
/// seed `rho` and secret vectors `s1`, `s2`.
///
/// Computes `t = A(rho)·s1 + s2` (streaming `A` from `rho` so the full matrix
/// is never materialized) and splits it via `power2round` into `t1` (public)
/// and `t0` (secret). Both key generation and the `Keypair` consistency check
/// go through this single routine, so the public key derived at import can
/// never disagree with the one produced at generation. The transient NTT copy
/// of `s1` is zeroized before returning.
fn derive_public_components(
	rho: &[u8; params::SEEDBYTES],
	s1: &Polyvecl,
	s2: &Polyveck,
) -> (Polyveck, Polyveck) {
	let mut s1hat = s1.clone();
	polyvec::l_ntt(&mut s1hat);

	let mut t1 = Polyveck::default();
	polyvec::matrix_pointwise_montgomery_streamed(&mut t1, rho, &s1hat);
	polyvec::k_reduce(&mut t1);
	polyvec::k_invntt_tomont(&mut t1);
	polyvec::k_add(&mut t1, s2);
	polyvec::k_caddq(&mut t1);

	let mut t0 = Polyveck::default();
	polyvec::k_power2round(&mut t1, &mut t0);

	s1hat.zeroize();
	(t1, t0)
}

/// Generate public and private key.
///
/// # Arguments
///
/// * 'pk' - output buffer for public key (PUBLICKEYBYTES)
/// * 'sk' - output buffer for private key (SECRETKEYBYTES)
/// * 'seed' - required seed
pub fn keypair(
	pk: &mut [u8; params::PUBLICKEYBYTES],
	sk: &mut [u8; params::SECRETKEYBYTES],
	seed: SensitiveBytes32,
) {
	let mut seed_bytes = seed.into_bytes();
	const SEEDBUF_LEN: usize = 2 * params::SEEDBYTES + params::CRHBYTES;
	let mut seedbuf = [0u8; SEEDBUF_LEN];
	// Build preimage = seed || K || L in a fixed stack buffer. A growable
	// Vec would reallocate while holding the seed (Vec::new +
	// extend_from_slice sizes capacity exactly, so the pushes force a
	// realloc), freeing a seed-bearing heap block that zeroize() can no
	// longer reach.
	let mut preimage = [0u8; params::SEEDBYTES + 2];
	preimage[..params::SEEDBYTES].copy_from_slice(&seed_bytes);
	preimage[params::SEEDBYTES] = params::K as u8;
	preimage[params::SEEDBYTES + 1] = params::L as u8;
	fips202::shake256(&mut seedbuf, &preimage);

	let mut rho = [0u8; params::SEEDBYTES];
	rho.copy_from_slice(&seedbuf[..params::SEEDBYTES]);

	let mut rhoprime = [0u8; params::CRHBYTES];
	rhoprime.copy_from_slice(&seedbuf[params::SEEDBYTES..params::SEEDBYTES + params::CRHBYTES]);

	let mut key = [0u8; params::SEEDBYTES];
	key.copy_from_slice(&seedbuf[params::SEEDBYTES + params::CRHBYTES..]);

	// Allocate polynomial structures
	let mut s1 = Polyvecl::default();
	polyvec::l_uniform_eta(&mut s1, &rhoprime, 0);

	let mut s2 = Polyveck::default();
	polyvec::k_uniform_eta(&mut s2, &rhoprime, L as u16);

	// t1 = high bits of A*s1 + s2 (public); t0 = low bits (kept in the secret key).
	let (t1, mut t0) = derive_public_components(&rho, &s1, &s2);

	packing::pack_pk(pk, &rho, &t1);

	let mut tr = [0u8; params::TR_BYTES];
	fips202::shake256(&mut tr, pk);

	packing::pack_sk(sk, &rho, &tr, &key, &t0, &s1, &s2);

	// Zeroize sensitive intermediate material. `s1`, `s2`, and `t0` are the
	// secret polynomials; now that they're packed into `sk` the working copies
	// must not linger on the stack. (`rho`/`tr`/`t1` are public.)
	seedbuf.zeroize();
	seed_bytes.zeroize();
	preimage.zeroize();
	rhoprime.zeroize();
	key.zeroize();
	s1.zeroize();
	s2.zeroize();
	t0.zeroize();
}

/// Re-derive the public key that corresponds to a secret key, verifying the
/// secret key's internal invariants along the way.
///
/// Recomputes `t1` and `t0` from the secret key's `(rho, s1, s2)` exactly as
/// [`keypair`] does, and packs `pk = (rho, t1)`. In addition to re-deriving
/// the public key, this checks the two remaining packed-SK invariants:
///
/// - the stored `t0` must equal the re-derived low bits of `A·s1 + s2`,
/// - the stored `tr` must equal `SHAKE256(pk)`, and
/// - the derived `t1` must not be all-zero, matching the degenerate-key rejection in [`verify`] and
///   `ml_dsa_87::PublicKey::from_bytes`. A blob with `s1 = s2 = 0` derives `t1 = t0 = 0` and passes
///   the two consistency checks by construction, but its public key is exactly the forgeable class
///   the verifier rejects, so signing with it can only produce unverifiable signatures.
///
/// Signing uses the stored `tr` (bound into the message digest) and `t0`
/// (hint computation), so a blob with a corrupted `tr`/`t0` region would
/// import "successfully" and then produce signatures that fail under the
/// advertised public key. Rejecting such blobs here fails fast at import and
/// avoids ever signing with an inconsistent key (corrupted-key signing is the
/// setup for fault-style analyses on Dilithium).
///
/// Returns `None` if either invariant is violated. The comparisons are not
/// constant-time; timing can only differ for an already-corrupted blob, and
/// the honest path compares all-equal data.
///
/// The secret polynomials are zeroized before returning.
pub(crate) fn public_key_from_secret(
	sk: &[u8; params::SECRETKEYBYTES],
) -> Option<[u8; params::PUBLICKEYBYTES]> {
	let mut rho = [0u8; params::SEEDBYTES];
	let mut tr = [0u8; params::TR_BYTES];
	let mut key = [0u8; params::SEEDBYTES];
	let mut t0 = Polyveck::default();
	let mut s1 = Polyvecl::default();
	let mut s2 = Polyveck::default();
	packing::unpack_sk(&mut rho, &mut tr, &mut key, &mut t0, &mut s1, &mut s2, sk);

	// Same derivation as key generation.
	let (t1, mut t0_derived) = derive_public_components(&rho, &s1, &s2);

	// Invariant: the derived public key must not be the degenerate all-zero
	// t1 key that verify() rejects (see the doc comment above).
	let t1_nonzero = !t1.vec.iter().all(|p| p.coeffs().iter().all(|&c| c == 0));

	let mut pk = [0u8; params::PUBLICKEYBYTES];
	packing::pack_pk(&mut pk, &rho, &t1);

	// Invariant: stored t0 must be the low bits actually derived from (rho, s1, s2).
	let t0_consistent = t0
		.vec
		.iter()
		.zip(t0_derived.vec.iter())
		.all(|(stored, derived)| stored.coeffs == derived.coeffs);

	// Invariant: stored tr must be the hash of the (re-derived) public key.
	let mut tr_derived = [0u8; params::TR_BYTES];
	fips202::shake256(&mut tr_derived, &pk);
	let tr_consistent = tr == tr_derived;

	// Only rho/t1 are public; wipe the secret copies.
	key.zeroize();
	s1.zeroize();
	s2.zeroize();
	t0.zeroize();
	t0_derived.zeroize();

	if t0_consistent && tr_consistent && t1_nonzero {
		Some(pk)
	} else {
		None
	}
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
#[derive(ZeroizeOnDrop)]
struct UnpackedSecretKey {
	public_seed_rho: [u8; params::SEEDBYTES],
	public_key_hash_tr: [u8; params::TR_BYTES],
	private_key_seed: [u8; params::SEEDBYTES],
	secret_poly_t0_ntt: Polyveck,
	secret_poly_s1_ntt: Polyvecl,
	secret_poly_s2_ntt: Polyveck,
}

/// Signing context containing precomputed values.
///
/// Holds the public seed `rho` rather than the expanded matrix A: A is regenerated on the fly
/// per rejection-sampling attempt (see `matrix_pointwise_montgomery_streamed`), trading a small
/// amount of recomputation for ~56 KB less peak stack on memory-constrained targets.
struct SigningContext {
	public_seed_rho: [u8; params::SEEDBYTES],
	message_hash_mu: [u8; params::CRHBYTES],
	signing_entropy_rho_prime: [u8; params::CRHBYTES],
}

impl Drop for SigningContext {
	fn drop(&mut self) {
		// rho and mu are public; only the mask seed is sensitive.
		self.signing_entropy_rho_prime.zeroize();
	}
}

/// Unpack secret key and prepare for signing
fn unpack_secret_key_for_signing(
	secret_key_bytes: &[u8; params::SECRETKEYBYTES],
) -> UnpackedSecretKey {
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

/// Compute the message representative μ = H(tr || pre || M).
///
/// The domain prefix `pre` (FIPS 204 domain separator + context) and the caller's
/// message `M` are absorbed as separate slices rather than a single concatenated
/// buffer. SHAKE256 absorption is incremental, so this is bit-identical to hashing
/// `pre || M` while avoiding a heap copy of the (attacker-controlled, up to 64 MiB)
/// message — closing an allocation-amplification DoS on the signing path.
fn derive_message_hash(
	public_key_hash_tr: &[u8; params::TR_BYTES],
	domain_prefix: &[u8],
	message: &[u8],
) -> [u8; params::CRHBYTES] {
	let mut keccak_state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut keccak_state, public_key_hash_tr);
	fips202::shake256_absorb(&mut keccak_state, domain_prefix);
	fips202::shake256_absorb(&mut keccak_state, message);
	fips202::shake256_finalize(&mut keccak_state);
	let mut message_hash_mu = [0u8; params::CRHBYTES];
	fips202::shake256_squeeze(&mut message_hash_mu, &mut keccak_state);
	message_hash_mu
}

/// Derive the mask seed ρ' = H(K || rnd || μ) (FIPS 204 ExpandMask seed).
///
/// `K`, `rnd` and `μ` are always absorbed at their full length, so distinct messages
/// (distinct `μ`) or distinct `rnd` always yield distinct mask seeds, and hence distinct
/// masks `y`. This is the single chokepoint that prevents nonce reuse across signatures.
fn derive_mask_seed(
	private_key_seed: &[u8; params::SEEDBYTES],
	hedge_bytes: &[u8; params::SEEDBYTES],
	message_hash_mu: &[u8; params::CRHBYTES],
) -> [u8; params::CRHBYTES] {
	let mut keccak_state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut keccak_state, private_key_seed);
	fips202::shake256_absorb(&mut keccak_state, hedge_bytes);
	fips202::shake256_absorb(&mut keccak_state, message_hash_mu);
	fips202::shake256_finalize(&mut keccak_state);
	let mut signing_entropy_rho_prime = [0u8; params::CRHBYTES];
	fips202::shake256_squeeze(&mut signing_entropy_rho_prime, &mut keccak_state);
	signing_entropy_rho_prime
}

/// Compute message hash and signing randomness
fn prepare_signing_context(
	unpacked_sk: &UnpackedSecretKey,
	domain_prefix: &[u8],
	message: &[u8],
	hedge_randomness: Option<[u8; params::SEEDBYTES]>,
) -> SigningContext {
	// Compute message hash μ = H(tr || pre || msg) where pre is the domain prefix.
	let message_hash_mu =
		derive_message_hash(&unpacked_sk.public_key_hash_tr, domain_prefix, message);

	// Generate signing randomness ρ' = H(K || rnd || μ)
	let mut hedge_bytes = hedge_randomness.unwrap_or([0u8; params::SEEDBYTES]);
	let signing_entropy_rho_prime =
		derive_mask_seed(&unpacked_sk.private_key_seed, &hedge_bytes, &message_hash_mu);

	// Zeroize sensitive hedge bytes after use
	hedge_bytes.zeroize();

	// Keep the public seed; matrix A is streamed from it per attempt instead of materialized.
	let public_seed_rho = unpacked_sk.public_seed_rho;

	SigningContext { public_seed_rho, message_hash_mu, signing_entropy_rho_prime }
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
	let mut w0_plus_challenge_t0 = commitment_w0.clone();
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
	public_seed_rho: &[u8; params::SEEDBYTES],
	signing_entropy: &[u8; params::CRHBYTES],
	attempt_nonce: u16,
) {
	// Generate random masking vector y
	polyvec::l_uniform_gamma1(masking_vector_y, signing_entropy, attempt_nonce);

	// Compute commitment w = Ay, streaming A from rho instead of using a materialized matrix.
	*signature_z_temp = masking_vector_y.clone();
	polyvec::l_ntt(signature_z_temp);
	polyvec::matrix_pointwise_montgomery_streamed(commitment_w1, public_seed_rho, signature_z_temp);
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
	message_hash_mu: &[u8; params::CRHBYTES],
) -> Poly {
	// Pack w1 into signature buffer temporarily. The buffer is the full
	// signature buffer, comfortably larger than K * POLYW1_PACKEDBYTES.
	let w1_region = signature_buffer
		.first_chunk_mut::<{ K * params::POLYW1_PACKEDBYTES }>()
		.expect("signature buffer covers the packed w1 region");
	polyvec::k_pack_w1(w1_region, commitment_w1);

	let mut keccak_state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut keccak_state, message_hash_mu);
	fips202::shake256_absorb(
		&mut keccak_state,
		&signature_buffer[..K * params::POLYW1_PACKEDBYTES],
	);
	fips202::shake256_finalize(&mut keccak_state);
	fips202::shake256_squeeze(&mut signature_buffer[..params::C_DASH_BYTES], &mut keccak_state);

	let mut challenge_poly_c = Poly::default();
	poly::challenge(&mut challenge_poly_c, &signature_buffer[..params::C_DASH_BYTES]);
	poly::ntt(&mut challenge_poly_c);
	challenge_poly_c
}

/// Main signature generation function.
///
/// The message to be hashed is `domain_prefix || message`; the two are absorbed
/// as separate slices (never concatenated) so the caller-controlled `message` is
/// not copied into a fresh heap buffer.
pub(crate) fn signature(
	signature_output: &mut [u8; params::SIGNBYTES],
	domain_prefix: &[u8],
	message: &[u8],
	secret_key_bytes: &[u8; params::SECRETKEYBYTES],
	hedge: Option<[u8; params::SEEDBYTES]>,
) {
	// Step 1: Unpack secret key components
	let unpacked_sk = unpack_secret_key_for_signing(secret_key_bytes);

	// Step 2: Prepare signing context (message hash, randomness, public seed rho)
	let signing_ctx = prepare_signing_context(&unpacked_sk, domain_prefix, message, hedge);

	// Step 3: Fiat-Shamir with aborts. The *number* of rejection-sampling attempts is
	// independent of the long-term secret key and is treated as public information, as in
	// FIPS 204 and the reference implementation. What must not leak through timing is the
	// arithmetic *within* each attempt; those operations are constant-time.
	let mut masking_vector_y = Polyvecl::default();
	let mut commitment_w1 = Polyveck::default();
	let mut commitment_w0 = Polyveck::default();
	let mut hint_vector_h = Polyveck::default();
	let mut attempt_nonce: u16 = 0;

	// Largest attempt_nonce for which the per-polynomial mask nonce (L*attempt_nonce + i,
	// i < L) still fits in u16. Reaching this requires an astronomically improbable run of
	// rejection-sampling failures, which would signal a broken RNG/entropy source.
	const MAX_SAFE_ATTEMPT_NONCE: u16 = (u16::MAX - (L as u16 - 1)) / L as u16;

	loop {
		// Fail loudly rather than silently wrap the nonce and reuse a mask y.
		assert!(
			attempt_nonce <= MAX_SAFE_ATTEMPT_NONCE,
			"ML-DSA signing nonce overflow: rejection sampling failed implausibly many times"
		);

		// Generate masking vector and compute commitment
		let mut signature_z = Polyvecl::default();
		generate_masking_vector_and_commitment(
			&mut masking_vector_y,
			&mut commitment_w1,
			&mut commitment_w0,
			&mut signature_z,
			&signing_ctx.public_seed_rho,
			&signing_ctx.signing_entropy_rho_prime,
			attempt_nonce,
		);

		// Generate challenge c = H(μ, w1); the challenge bytes land in
		// signature_output[..C_DASH_BYTES] and are kept there if this attempt is accepted.
		let challenge_poly_c = generate_challenge_polynomial(
			signature_output,
			&commitment_w1,
			&signing_ctx.message_hash_mu,
		);

		// All four rejection checks are always evaluated (no short-circuit between them),
		// so a rejected attempt reveals only that it was rejected, not which bound failed.

		// First rejection condition: compute z = y + cs1 and check ||z||∞ < γ₁ - β
		let condition1 = compute_and_check_signature_z(
			&mut signature_z,
			&masking_vector_y,
			&challenge_poly_c,
			&unpacked_sk.secret_poly_s1_ntt,
		);

		// Second rejection condition: compute w0 - cs2 and check ||w0 - cs2||∞ < γ₂ - β
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

		// Fourth rejection condition: compute hint vector and check weight ≤ ω
		let condition4 = compute_and_check_hint_vector(
			&mut hint_vector_h,
			&commitment_w0,
			&challenge_t0,
			&commitment_w1,
		);

		if condition1 & condition2 & condition3 & condition4 {
			// Challenge bytes are already in place; pack z and h around them.
			packing::pack_sig(signature_output, None, &signature_z, &hint_vector_h);
			return;
		}

		attempt_nonce += 1;
	}
}

/// Verify a signature for a given message with a public key.
///
/// # Arguments
///
/// * 'sig' - signature to verify (must be SIGNBYTES)
/// * 'domain_prefix' - FIPS 204 domain separator + context (hashed before the message)
/// * 'm' - message that is claimed to be signed
/// * 'pk' - public key (must be PUBLICKEYBYTES)
///
/// The message representative is hashed over `domain_prefix || m`, with the two
/// absorbed as separate slices so the caller-controlled `m` is never copied into a
/// fresh heap buffer (avoids allocation-amplification DoS on the verify path).
///
/// Returns 'true' if the verification process was successful, 'false' otherwise
pub(crate) fn verify(
	sig: &[u8; params::SIGNBYTES],
	domain_prefix: &[u8],
	m: &[u8],
	pk: &[u8; params::PUBLICKEYBYTES],
) -> bool {
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

	packing::unpack_pk(&mut rho, &mut t1, pk);

	// Reject the degenerate all-zero t1 public key. With t1 = 0 the term c*2^d*t1 in the
	// verification relation vanishes for every challenge c, so w1 = UseHint(h, Az) no longer
	// binds the challenge to the key. An attacker can then forge a signature (z = 0, empty
	// hint, c = H(mu || w1Encode(0))) with no secret key. Honest key generation never yields
	// t1 = 0, so rejecting it costs nothing and closes the malicious-key forgery.
	if t1.vec.iter().all(|p| p.coeffs.iter().all(|&c| c == 0)) {
		return false;
	}

	if !packing::unpack_sig(&mut c, &mut z, &mut h, sig) {
		return false;
	}
	if !polyvec::polyvecl_is_norm_within_bound(
		&z,
		(crate::params::GAMMA1 - crate::params::BETA) as i32,
	) {
		return false;
	}

	// Compute CRH(H(rho, t1) || pre || msg). The domain prefix and message are
	// absorbed as separate slices (SHAKE256 is incremental), matching the signer.
	fips202::shake256(&mut mu, pk);
	fips202::shake256_absorb(&mut state, &mu);
	fips202::shake256_absorb(&mut state, domain_prefix);
	fips202::shake256_absorb(&mut state, m);
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut mu, &mut state);

	// Matrix-vector multiplication; compute Az - c2^dt1 (A streamed from rho)
	poly::challenge(&mut cp, &c);

	polyvec::l_ntt(&mut z);
	polyvec::matrix_pointwise_montgomery_streamed(&mut w1, &rho, &z);

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
	fips202::shake256_absorb(&mut state, &mu);
	fips202::shake256_absorb(&mut state, &buf);
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut c2, &mut state);
	c == c2
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::{string::String, vec};
	use rand::RngExt;

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
		super::signature(&mut sig, &[], &msg, &sk, Some(hedge.0));
		assert!(super::verify(&sig, &[], &msg, &pk));
	}

	#[test]
	fn self_verify() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());
		let msg = get_random_msg();
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &[], &msg, &sk, None);
		assert!(super::verify(&sig, &[], &msg, &pk));
	}

	#[test]
	fn test_empty_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let empty_msg: &[u8] = &[];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &[], empty_msg, &sk, None);
		assert!(super::verify(&sig, &[], empty_msg, &pk));
	}

	#[test]
	fn test_single_byte_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let msg = [0x42u8];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &[], &msg, &sk, None);
		assert!(super::verify(&sig, &[], &msg, &pk));
	}

	#[test]
	fn test_large_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let large_msg = vec![0xABu8; 10000];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &[], &large_msg, &sk, None);
		assert!(super::verify(&sig, &[], &large_msg, &pk));
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

		super::signature(&mut sig1, &[], msg, &sk, Some(hedge.0));
		super::signature(&mut sig2, &[], msg, &sk, Some(hedge.0));

		// Deterministic signing should produce identical signatures
		assert_eq!(sig1, sig2);
		assert!(super::verify(&sig1, &[], msg, &pk));
		assert!(super::verify(&sig2, &[], msg, &pk));
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

		super::signature(&mut sig1, &[], msg, &sk, Some(hedge1.0));
		super::signature(&mut sig2, &[], msg, &sk, Some(hedge2.0));

		// Hedged signing should produce different signatures (with high probability)
		assert_ne!(sig1, sig2);
		assert!(super::verify(&sig1, &[], msg, &pk));
		assert!(super::verify(&sig2, &[], msg, &pk));
	}

	#[test]
	fn test_wrong_message_fails() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let msg1 = b"original message";
		let msg2 = b"different message";
		let mut sig = [0u8; crate::params::SIGNBYTES];

		super::signature(&mut sig, &[], msg1, &sk, None);

		// Should verify with correct message
		assert!(super::verify(&sig, &[], msg1, &pk));
		// Should fail with wrong message
		assert!(!super::verify(&sig, &[], msg2, &pk));
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

		super::signature(&mut sig, &[], msg, &sk1, None);

		// Should verify with correct key
		assert!(super::verify(&sig, &[], msg, &pk1));
		// Should fail with wrong key
		assert!(!super::verify(&sig, &[], msg, &pk2));
	}

	#[test]
	fn test_corrupted_signature_fails() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let msg = b"test message";
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &[], msg, &sk, None);

		// Original signature should verify
		assert!(super::verify(&sig, &[], msg, &pk));

		// Corrupt first byte
		let original_byte = sig[0];
		sig[0] = sig[0].wrapping_add(1);
		assert!(!super::verify(&sig, &[], msg, &pk));

		// Restore and corrupt last byte
		sig[0] = original_byte;
		let last_idx = sig.len() - 1;
		let original_last = sig[last_idx];
		sig[last_idx] = sig[last_idx].wrapping_add(1);
		assert!(!super::verify(&sig, &[], msg, &pk));

		// Restore and verify it works again
		sig[last_idx] = original_last;
		assert!(super::verify(&sig, &[], msg, &pk));
	}

	// Note: Invalid signature length tests are in ml_dsa_87.rs since the internal
	// verify() function now requires fixed-size arrays. The public API handles
	// length validation before calling the internal function.

	#[test]
	fn test_fixed_seed_keypair() {
		let seed_bytes = [0x55u8; crate::params::SEEDBYTES];

		let mut pk1 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk1 = [0u8; crate::params::SECRETKEYBYTES];
		let mut pk2 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk2 = [0u8; crate::params::SECRETKEYBYTES];

		super::keypair(&mut pk1, &mut sk1, (&mut seed_bytes.clone()).into());
		super::keypair(&mut pk2, &mut sk2, (&mut seed_bytes.clone()).into());

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
			super::signature(&mut sig, &[], msg, &sk, None);
			assert!(
				super::verify(&sig, &[], msg, &pk),
				"Failed to verify message: {:?}",
				String::from_utf8_lossy(msg)
			);
		}
	}
	// Note: Test vector validation is handled in integration tests
	// (tests/src/verify_integration_tests.rs) which use proper NIST KAT test vectors for
	// comprehensive validation.

	/// Recover the masking vector y = z - c·s1 that the signer actually used, directly from a
	/// produced signature plus the secret key. Used to observe y without exposing it in the API.
	fn recover_masking_y(
		sig: &[u8; params::SIGNBYTES],
		sk: &[u8; params::SECRETKEYBYTES],
	) -> Polyvecl {
		let mut challenge_seed = [0u8; params::C_DASH_BYTES];
		let mut z = Polyvecl::default();
		let mut h = Polyveck::default();
		assert!(packing::unpack_sig(&mut challenge_seed, &mut z, &mut h, sig));

		let unpacked = unpack_secret_key_for_signing(sk); // s1 already in NTT domain
		let mut challenge_poly = Poly::default();
		poly::challenge(&mut challenge_poly, &challenge_seed);
		poly::ntt(&mut challenge_poly);

		let mut cs1 = Polyvecl::default();
		polyvec::l_pointwise_poly_montgomery(
			&mut cs1,
			&challenge_poly,
			&unpacked.secret_poly_s1_ntt,
		);
		polyvec::l_invntt_tomont(&mut cs1);

		// y ≡ z - c·s1 (mod q); normalise to the canonical [0, Q) representative for comparison.
		for i in 0..L {
			poly::sub_ip(&mut z.vec[i], &cs1.vec[i]);
			poly::reduce(&mut z.vec[i]);
			poly::caddq(&mut z.vec[i]);
		}
		z
	}

	fn polyvecl_eq(a: &Polyvecl, b: &Polyvecl) -> bool {
		(0..L).all(|i| a.vec[i].coeffs == b.vec[i].coeffs)
	}

	// Bug Class 3 (repeated y nonce across messages): two different messages signed
	// deterministically (hedge=None) with the same key must use different masks y.
	#[test]
	fn test_y_differs_across_messages_deterministic() {
		let mut pk = [0u8; params::PUBLICKEYBYTES];
		let mut sk = [0u8; params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let mut sig1 = [0u8; params::SIGNBYTES];
		let mut sig2 = [0u8; params::SIGNBYTES];
		super::signature(&mut sig1, &[], b"message one", &sk, None);
		super::signature(&mut sig2, &[], b"message two", &sk, None);

		assert_ne!(sig1, sig2, "deterministic signatures of different messages must differ");

		let y1 = recover_masking_y(&sig1, &sk);
		let y2 = recover_masking_y(&sig2, &sk);
		assert!(
			!polyvecl_eq(&y1, &y2),
			"mask y was reused across two different messages (Bug Class 3)"
		);
	}

	// Malicious-key forgery (degenerate all-zero t1): a public key whose t1 is entirely zero
	// makes the verification relation w1 = UseHint(h, Az - c*2^d*t1) independent of the
	// challenge c, because the c*2^d*t1 term vanishes for every c. An attacker can then pick
	// z = 0 and an empty hint, so the verifier reconstructs w1 = 0, precompute
	// c = H(mu || w1Encode(0)), and place that c in the signature. Verification then finds
	// c == c2 and accepts, even though the attacker possesses no secret key. A successful
	// verify must imply possession of a real secret key, so this key must be rejected.
	#[test]
	fn test_forged_signature_with_zero_t1_is_rejected() {
		// Public key with arbitrary rho and an all-zero t1 (the t1 byte region stays zero).
		let mut pk = [0u8; params::PUBLICKEYBYTES];
		pk[..params::SEEDBYTES].copy_from_slice(&[0x42u8; params::SEEDBYTES]);

		let m = b"forge me without a secret key";

		// Recompute mu exactly as verify() does: mu = CRH(H(pk) || m).
		let mut mu = [0u8; params::CRHBYTES];
		fips202::shake256(&mut mu, &pk);
		let mut state = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut state, &mu);
		fips202::shake256_absorb(&mut state, m);
		fips202::shake256_finalize(&mut state);
		fips202::shake256_squeeze(&mut mu, &mut state);

		// With z = 0, h = 0 and t1 = 0 the verifier reconstructs w1 = 0.
		let w1 = Polyveck::default();
		let mut buf = [0u8; K * params::POLYW1_PACKEDBYTES];
		polyvec::k_pack_w1(&mut buf, &w1);

		// Pick the challenge to equal the verifier's own recomputation: c = H(mu || w1Encode(0)).
		let mut c = [0u8; params::C_DASH_BYTES];
		let mut cstate = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut cstate, &mu);
		fips202::shake256_absorb(&mut cstate, &buf);
		fips202::shake256_finalize(&mut cstate);
		fips202::shake256_squeeze(&mut c, &mut cstate);

		// Assemble the forged signature (c, z = 0, empty hint).
		let z = Polyvecl::default();
		let h = Polyveck::default();
		let mut sig = [0u8; params::SIGNBYTES];
		packing::pack_sig(&mut sig, Some(&c), &z, &h);

		assert!(
			!super::verify(&sig, &[], m, &pk),
			"signature forged under an all-zero-t1 public key must be rejected"
		);
	}

	// Bug Class 2 (K zeroing/omission): K seeds the mask ρ', so mutating one byte of the
	// stored K must change the produced signature while still yielding a valid signature.
	#[test]
	fn test_secret_key_k_affects_signature() {
		let mut pk = [0u8; params::PUBLICKEYBYTES];
		let mut sk = [0u8; params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, get_random_bytes());

		let msg = b"K must influence the mask";
		let mut sig_original = [0u8; params::SIGNBYTES];
		super::signature(&mut sig_original, &[], msg, &sk, None);

		// K is stored at offset [SEEDBYTES, 2*SEEDBYTES) in the packed secret key.
		let mut sk_flipped = sk;
		sk_flipped[params::SEEDBYTES] ^= 0x01;
		assert_ne!(sk, sk_flipped, "test setup should change the stored K");

		let mut sig_flipped = [0u8; params::SIGNBYTES];
		super::signature(&mut sig_flipped, &[], msg, &sk_flipped, None);

		assert_ne!(
			sig_original, sig_flipped,
			"flipping a byte of K did not change the signature (Bug Class 2)"
		);
		// K only seeds the mask; the signature stays valid under the unchanged public key.
		assert!(super::verify(&sig_flipped, &[], msg, &pk));
	}

	// Bug Class 3 (truncated/incorrect hash-input assembly): pin ρ' = H(K || rnd || μ) for
	// fixed inputs against an independent Python reference (hashlib.shake_256), and cross-check
	// the incremental-absorb production path against a one-shot SHAKE256 over the concatenation.
	#[test]
	fn test_mask_seed_golden_vector() {
		let key = [1u8; params::SEEDBYTES];
		let rnd = [2u8; params::SEEDBYTES];
		let mu = [3u8; params::CRHBYTES];

		// python3 -c "import hashlib;
		// print(hashlib.shake_256(bytes([1]*32)+bytes([2]*32)+bytes([3]*64)).hexdigest(64))"
		let expected: [u8; params::CRHBYTES] = [
			0x4d, 0xfd, 0xda, 0xba, 0x94, 0x98, 0x12, 0xaa, 0xc7, 0x9f, 0xc8, 0xc2, 0xa7, 0xa6,
			0x2e, 0x36, 0xc6, 0xd2, 0x69, 0x58, 0xbb, 0x73, 0x9e, 0x81, 0xd7, 0x48, 0xdc, 0xec,
			0x0b, 0x85, 0x2d, 0x9c, 0x24, 0x4d, 0x08, 0x07, 0xa3, 0xa2, 0x3c, 0x44, 0x98, 0x89,
			0xba, 0x59, 0x2c, 0xa4, 0x47, 0x0d, 0x8e, 0xb6, 0x96, 0xd7, 0x20, 0xa4, 0xc3, 0x4e,
			0x2c, 0x30, 0x98, 0xf5, 0xc7, 0xaa, 0xea, 0xc3,
		];

		let rho_prime = super::derive_mask_seed(&key, &rnd, &mu);
		assert_eq!(rho_prime, expected, "rho' diverged from the independent SHAKE256 reference");

		// Independent internal path: one-shot SHAKE256 over K || rnd || μ.
		let mut concatenated = [0u8; 2 * params::SEEDBYTES + params::CRHBYTES];
		concatenated[..params::SEEDBYTES].copy_from_slice(&key);
		concatenated[params::SEEDBYTES..2 * params::SEEDBYTES].copy_from_slice(&rnd);
		concatenated[2 * params::SEEDBYTES..].copy_from_slice(&mu);
		let mut one_shot = [0u8; params::CRHBYTES];
		fips202::shake256(&mut one_shot, &concatenated);
		assert_eq!(rho_prime, one_shot, "incremental absorb diverged from one-shot SHAKE256");
	}
}
