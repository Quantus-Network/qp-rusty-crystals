use crate::{
	fips202, packing, params, poly, poly::Poly, polyvec, polyvec::Polyvec, SensitiveBytes32,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Compile-time consistency checks for a full parameter-set instantiation.
const fn assert_sign_params<
	const K: usize,
	const L: usize,
	const ETA: usize,
	const GAMMA1: usize,
	const GAMMA2: usize,
	const OMEGA: usize,
	const CD: usize,
	const PZ: usize,
	const W1: usize,
	const KW1: usize,
	const PK: usize,
	const SK: usize,
	const SIG: usize,
>() {
	assert!(PZ == params::polyz_packedbytes(GAMMA1));
	assert!(W1 == params::polyw1_packedbytes(GAMMA2));
	assert!(KW1 == K * W1);
	assert!(PK == params::publickeybytes(K));
	assert!(SK == params::secretkeybytes(K, L, ETA));
	assert!(SIG == params::signbytes(K, L, GAMMA1, OMEGA, CD));
}

/// Derive the public high bits `t1` and secret low bits `t0` from the public
/// seed `rho` and secret vectors `s1`, `s2`.
///
/// Computes `t = A(rho)·s1 + s2` (streaming `A` from `rho` so the full matrix
/// is never materialized) and splits it via `power2round` into `t1` (public)
/// and `t0` (secret). Both key generation and the `Keypair` consistency check
/// go through this single routine, so the public key derived at import can
/// never disagree with the one produced at generation. The transient NTT copy
/// of `s1` is zeroized before returning.
fn derive_public_components<const K: usize, const L: usize>(
	rho: &[u8; params::SEEDBYTES],
	s1: &Polyvec<L>,
	s2: &Polyvec<K>,
) -> (Polyvec<K>, Polyvec<K>) {
	let mut s1hat = s1.clone();
	polyvec::ntt(&mut s1hat);

	let mut t1 = Polyvec::<K>::default();
	polyvec::matrix_pointwise_montgomery_streamed(&mut t1, rho, &s1hat);
	polyvec::reduce(&mut t1);
	polyvec::invntt_tomont(&mut t1);
	polyvec::add(&mut t1, s2);
	polyvec::caddq(&mut t1);

	let mut t0 = Polyvec::<K>::default();
	polyvec::power2round(&mut t1, &mut t0);

	s1hat.zeroize();
	(t1, t0)
}

/// Generate public and private key for an arbitrary ML-DSA parameter set.
pub(crate) fn keypair_var<
	const K: usize,
	const L: usize,
	const ETA: usize,
	const PK: usize,
	const SK: usize,
>(
	pk: &mut [u8; PK],
	sk: &mut [u8; SK],
	seed: SensitiveBytes32,
) {
	const {
		assert!(PK == params::publickeybytes(K));
		assert!(SK == params::secretkeybytes(K, L, ETA));
	}
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
	preimage[params::SEEDBYTES] = K as u8;
	preimage[params::SEEDBYTES + 1] = L as u8;
	fips202::shake256(&mut seedbuf, &preimage);

	let mut rho = [0u8; params::SEEDBYTES];
	rho.copy_from_slice(&seedbuf[..params::SEEDBYTES]);

	let mut rhoprime = [0u8; params::CRHBYTES];
	rhoprime.copy_from_slice(&seedbuf[params::SEEDBYTES..params::SEEDBYTES + params::CRHBYTES]);

	let mut key = [0u8; params::SEEDBYTES];
	key.copy_from_slice(&seedbuf[params::SEEDBYTES + params::CRHBYTES..]);

	let mut s1 = Polyvec::<L>::default();
	polyvec::uniform_eta::<L, ETA>(&mut s1, &rhoprime, 0);

	let mut s2 = Polyvec::<K>::default();
	polyvec::uniform_eta::<K, ETA>(&mut s2, &rhoprime, L as u16);

	let (t1, mut t0) = derive_public_components(&rho, &s1, &s2);

	packing::pack_pk(pk, &rho, &t1);

	let mut tr = [0u8; params::TR_BYTES];
	fips202::shake256(&mut tr, pk);

	packing::pack_sk::<K, L, ETA, SK>(sk, &rho, &tr, &key, &t0, &s1, &s2);

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
/// [`keypair_var`] does, and packs `pk = (rho, t1)`. In addition to re-deriving
/// the public key, this checks the remaining packed-SK invariants:
///
/// - the unpacked `s1` and `s2` coefficients must lie in `[-ETA, ETA]`. Non-canonical
///   packed slots decode outside that range — encodings key generation never emits.
///   They cannot be caught by the algebraic checks below (an attacker recomputes
///   `t0`/`tr`/pk *from* the oversized coefficients), yet such a key lies outside
///   the key distribution that the `BETA = TAU * ETA` rejection margin in
///   [`signature_var`] is sized for,
/// - the stored `t0` must equal the re-derived low bits of `A·s1 + s2`,
/// - the stored `tr` must equal `SHAKE256(pk)`, and
/// - the derived `t1` must not be all-zero, matching the degenerate-key rejection in
///   [`verify_var`] and the public frontend `PublicKey::from_bytes`. A blob with
///   `s1 = s2 = 0` derives `t1 = t0 = 0` and passes the two consistency checks by
///   construction, but its public key is exactly the forgeable class the verifier
///   rejects, so signing with it can only produce unverifiable signatures.
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
pub(crate) fn public_key_from_secret_var<
	const K: usize,
	const L: usize,
	const ETA: usize,
	const PK: usize,
	const SK: usize,
>(
	sk: &[u8; SK],
) -> Option<[u8; PK]> {
	const {
		assert!(PK == params::publickeybytes(K));
		assert!(SK == params::secretkeybytes(K, L, ETA));
	}
	let mut rho = [0u8; params::SEEDBYTES];
	let mut tr = [0u8; params::TR_BYTES];
	let mut key = [0u8; params::SEEDBYTES];
	let mut t0 = Polyvec::<K>::default();
	let mut s1 = Polyvec::<L>::default();
	let mut s2 = Polyvec::<K>::default();
	let s_in_range = packing::unpack_sk::<K, L, ETA, SK>(
		&mut rho, &mut tr, &mut key, &mut t0, &mut s1, &mut s2, sk,
	);

	let (t1, mut t0_derived) = derive_public_components(&rho, &s1, &s2);

	let t1_nonzero = !t1.vec.iter().all(|p| p.coeffs().iter().all(|&c| c == 0));

	let mut pk = [0u8; PK];
	packing::pack_pk(&mut pk, &rho, &t1);

	let t0_consistent = t0
		.vec
		.iter()
		.zip(t0_derived.vec.iter())
		.all(|(stored, derived)| stored.coeffs == derived.coeffs);

	let mut tr_derived = [0u8; params::TR_BYTES];
	fips202::shake256(&mut tr_derived, &pk);
	let tr_consistent = tr == tr_derived;

	key.zeroize();
	s1.zeroize();
	s2.zeroize();
	t0.zeroize();
	t0_derived.zeroize();

	if s_in_range && t0_consistent && tr_consistent && t1_nonzero {
		Some(pk)
	} else {
		None
	}
}

#[derive(ZeroizeOnDrop)]
struct UnpackedSecretKey<const K: usize, const L: usize> {
	public_seed_rho: [u8; params::SEEDBYTES],
	public_key_hash_tr: [u8; params::TR_BYTES],
	private_key_seed: [u8; params::SEEDBYTES],
	secret_poly_t0_ntt: Polyvec<K>,
	secret_poly_s1_ntt: Polyvec<L>,
	secret_poly_s2_ntt: Polyvec<K>,
}

/// Signing context containing precomputed values.
///
/// Holds the public seed `rho` rather than the expanded matrix A: A is regenerated on the fly
/// per rejection-sampling attempt (see `matrix_pointwise_montgomery_streamed`), trading a small
/// amount of recomputation for less peak stack on memory-constrained targets.
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

fn unpack_secret_key_for_signing<
	const K: usize,
	const L: usize,
	const ETA: usize,
	const SK: usize,
>(
	secret_key_bytes: &[u8; SK],
) -> UnpackedSecretKey<K, L> {
	const {
		assert!(SK == params::secretkeybytes(K, L, ETA));
	}
	let mut public_seed_rho = [0u8; params::SEEDBYTES];
	let mut public_key_hash_tr = [0u8; params::TR_BYTES];
	let mut private_key_seed = [0u8; params::SEEDBYTES];
	let mut secret_poly_t0 = Polyvec::<K>::default();
	let mut secret_poly_s1 = Polyvec::<L>::default();
	let mut secret_poly_s2 = Polyvec::<K>::default();

	// Every signing entry point receives key bytes that already passed the
	// import validation (`SecretKey`'s storage is private and only filled by
	// `generate`/`from_bytes`), so a non-canonical encoding here is a crate
	// bug, not reachable attacker input.
	let canonical = packing::unpack_sk::<K, L, ETA, SK>(
		&mut public_seed_rho,
		&mut public_key_hash_tr,
		&mut private_key_seed,
		&mut secret_poly_t0,
		&mut secret_poly_s1,
		&mut secret_poly_s2,
		secret_key_bytes,
	);
	debug_assert!(canonical, "signing with a secret key that failed import validation");

	polyvec::ntt(&mut secret_poly_s1);
	polyvec::ntt(&mut secret_poly_s2);
	polyvec::ntt(&mut secret_poly_t0);

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

fn prepare_signing_context<const K: usize, const L: usize>(
	unpacked_sk: &UnpackedSecretKey<K, L>,
	domain_prefix: &[u8],
	message: &[u8],
	hedge_randomness: Option<[u8; params::SEEDBYTES]>,
) -> SigningContext {
	let message_hash_mu =
		derive_message_hash(&unpacked_sk.public_key_hash_tr, domain_prefix, message);

	let mut hedge_bytes = hedge_randomness.unwrap_or([0u8; params::SEEDBYTES]);
	let signing_entropy_rho_prime =
		derive_mask_seed(&unpacked_sk.private_key_seed, &hedge_bytes, &message_hash_mu);

	hedge_bytes.zeroize();

	let public_seed_rho = unpacked_sk.public_seed_rho;

	SigningContext { public_seed_rho, message_hash_mu, signing_entropy_rho_prime }
}

fn compute_and_check_signature_z<
	const L: usize,
	const GAMMA1: usize,
	const TAU: usize,
	const ETA: usize,
>(
	signature_z: &mut Polyvec<L>,
	masking_vector_y: &Polyvec<L>,
	challenge_poly_c: &Poly,
	secret_poly_s1_ntt: &Polyvec<L>,
) -> bool {
	polyvec::pointwise_poly_montgomery(signature_z, challenge_poly_c, secret_poly_s1_ntt);
	polyvec::invntt_tomont(signature_z);
	polyvec::add(signature_z, masking_vector_y);
	polyvec::reduce(signature_z);

	let beta = TAU * ETA;
	polyvec::is_norm_within_bound(signature_z, (GAMMA1 - beta) as i32)
}

fn compute_and_check_commitment_w0<
	const K: usize,
	const GAMMA2: usize,
	const TAU: usize,
	const ETA: usize,
>(
	commitment_w0: &mut Polyvec<K>,
	challenge_poly_c: &Poly,
	secret_poly_s2_ntt: &Polyvec<K>,
) -> bool {
	let mut temp_vector = Polyvec::<K>::default();

	polyvec::pointwise_poly_montgomery(&mut temp_vector, challenge_poly_c, secret_poly_s2_ntt);
	polyvec::invntt_tomont(&mut temp_vector);

	polyvec::sub(commitment_w0, &temp_vector);
	polyvec::reduce(commitment_w0);

	let beta = TAU * ETA;
	polyvec::is_norm_within_bound(commitment_w0, (GAMMA2 - beta) as i32)
}

fn compute_and_check_challenge_t0<const K: usize, const GAMMA2: usize>(
	challenge_t0: &mut Polyvec<K>,
	challenge_poly_c: &Poly,
	secret_poly_t0_ntt: &Polyvec<K>,
) -> bool {
	polyvec::pointwise_poly_montgomery(challenge_t0, challenge_poly_c, secret_poly_t0_ntt);
	polyvec::invntt_tomont(challenge_t0);
	polyvec::reduce(challenge_t0);

	polyvec::is_norm_within_bound(challenge_t0, GAMMA2 as i32)
}

fn compute_and_check_hint_vector<const K: usize, const GAMMA2: usize, const OMEGA: usize>(
	hint_vector_h: &mut Polyvec<K>,
	commitment_w0: &Polyvec<K>,
	challenge_t0: &Polyvec<K>,
	commitment_w1: &Polyvec<K>,
) -> bool {
	let mut w0_plus_challenge_t0 = commitment_w0.clone();
	polyvec::add(&mut w0_plus_challenge_t0, challenge_t0);

	let hint_weight =
		polyvec::make_hint::<K, GAMMA2>(hint_vector_h, &w0_plus_challenge_t0, commitment_w1);

	hint_weight <= OMEGA as i32
}

fn generate_masking_vector_and_commitment<
	const K: usize,
	const L: usize,
	const GAMMA1: usize,
	const GAMMA2: usize,
	const PZ: usize,
>(
	masking_vector_y: &mut Polyvec<L>,
	commitment_w1: &mut Polyvec<K>,
	commitment_w0: &mut Polyvec<K>,
	signature_z_temp: &mut Polyvec<L>,
	public_seed_rho: &[u8; params::SEEDBYTES],
	signing_entropy: &[u8; params::CRHBYTES],
	attempt_nonce: u16,
) {
	polyvec::uniform_gamma1::<L, GAMMA1, PZ>(masking_vector_y, signing_entropy, attempt_nonce);

	*signature_z_temp = masking_vector_y.clone();
	polyvec::ntt(signature_z_temp);
	polyvec::matrix_pointwise_montgomery_streamed(commitment_w1, public_seed_rho, signature_z_temp);
	polyvec::reduce(commitment_w1);
	polyvec::invntt_tomont(commitment_w1);
	polyvec::caddq(commitment_w1);

	polyvec::decompose::<K, GAMMA2>(commitment_w1, commitment_w0);
}

fn generate_challenge_polynomial<
	const K: usize,
	const TAU: usize,
	const GAMMA2: usize,
	const CD: usize,
	const W1: usize,
	const KW1: usize,
>(
	signature_buffer: &mut [u8],
	commitment_w1: &Polyvec<K>,
	message_hash_mu: &[u8; params::CRHBYTES],
) -> Poly {
	const {
		assert!(KW1 == K * W1);
		assert!(W1 == params::polyw1_packedbytes(GAMMA2));
	}
	let w1_region = signature_buffer
		.first_chunk_mut::<KW1>()
		.expect("signature buffer covers the packed w1 region");
	polyvec::pack_w1::<K, GAMMA2, KW1>(w1_region, commitment_w1);

	let mut keccak_state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut keccak_state, message_hash_mu);
	fips202::shake256_absorb(&mut keccak_state, &signature_buffer[..KW1]);
	fips202::shake256_finalize(&mut keccak_state);
	fips202::shake256_squeeze(&mut signature_buffer[..CD], &mut keccak_state);

	let mut challenge_poly_c = Poly::default();
	poly::challenge::<TAU>(&mut challenge_poly_c, &signature_buffer[..CD]);
	poly::ntt(&mut challenge_poly_c);
	challenge_poly_c
}

/// Main signature generation function for an arbitrary ML-DSA parameter set.
///
/// The message to be hashed is `domain_prefix || message`; the two are absorbed
/// as separate slices (never concatenated) so the caller-controlled `message` is
/// not copied into a fresh heap buffer.
pub(crate) fn signature_var<
	const K: usize,
	const L: usize,
	const ETA: usize,
	const TAU: usize,
	const GAMMA1: usize,
	const GAMMA2: usize,
	const OMEGA: usize,
	const CD: usize,
	const PZ: usize,
	const W1: usize,
	const KW1: usize,
	const PK: usize,
	const SK: usize,
	const SIG: usize,
>(
	signature_output: &mut [u8; SIG],
	domain_prefix: &[u8],
	message: &[u8],
	secret_key_bytes: &[u8; SK],
	hedge: Option<[u8; params::SEEDBYTES]>,
) {
	const {
		assert_sign_params::<K, L, ETA, GAMMA1, GAMMA2, OMEGA, CD, PZ, W1, KW1, PK, SK, SIG>();
	}

	let unpacked_sk = unpack_secret_key_for_signing::<K, L, ETA, SK>(secret_key_bytes);
	let signing_ctx = prepare_signing_context(&unpacked_sk, domain_prefix, message, hedge);

	// Fiat-Shamir with aborts. The *number* of rejection-sampling attempts is
	// independent of the long-term secret key and is treated as public information, as in
	// FIPS 204 and the reference implementation. What must not leak through timing is the
	// arithmetic *within* each attempt; those operations are constant-time.
	let mut masking_vector_y = Polyvec::<L>::default();
	let mut commitment_w1 = Polyvec::<K>::default();
	let mut commitment_w0 = Polyvec::<K>::default();
	let mut hint_vector_h = Polyvec::<K>::default();
	let mut attempt_nonce: u16 = 0;

	// Largest attempt_nonce for which the per-polynomial mask nonce (L*attempt_nonce + i,
	// i < L) still fits in u16. Reaching this requires an astronomically improbable run of
	// rejection-sampling failures, which would signal a broken RNG/entropy source.
	let max_safe_attempt_nonce: u16 = (u16::MAX - (L as u16 - 1)) / (L as u16);

	loop {
		assert!(
			attempt_nonce <= max_safe_attempt_nonce,
			"ML-DSA signing nonce overflow: rejection sampling failed implausibly many times"
		);

		let mut signature_z = Polyvec::<L>::default();
		generate_masking_vector_and_commitment::<K, L, GAMMA1, GAMMA2, PZ>(
			&mut masking_vector_y,
			&mut commitment_w1,
			&mut commitment_w0,
			&mut signature_z,
			&signing_ctx.public_seed_rho,
			&signing_ctx.signing_entropy_rho_prime,
			attempt_nonce,
		);

		let challenge_poly_c = generate_challenge_polynomial::<K, TAU, GAMMA2, CD, W1, KW1>(
			signature_output,
			&commitment_w1,
			&signing_ctx.message_hash_mu,
		);

		// All four rejection checks are always evaluated (no short-circuit between them),
		// so a rejected attempt reveals only that it was rejected, not which bound failed.
		let condition1 = compute_and_check_signature_z::<L, GAMMA1, TAU, ETA>(
			&mut signature_z,
			&masking_vector_y,
			&challenge_poly_c,
			&unpacked_sk.secret_poly_s1_ntt,
		);

		let condition2 = compute_and_check_commitment_w0::<K, GAMMA2, TAU, ETA>(
			&mut commitment_w0,
			&challenge_poly_c,
			&unpacked_sk.secret_poly_s2_ntt,
		);

		let mut challenge_t0 = Polyvec::<K>::default();
		let condition3 = compute_and_check_challenge_t0::<K, GAMMA2>(
			&mut challenge_t0,
			&challenge_poly_c,
			&unpacked_sk.secret_poly_t0_ntt,
		);

		let condition4 = compute_and_check_hint_vector::<K, GAMMA2, OMEGA>(
			&mut hint_vector_h,
			&commitment_w0,
			&challenge_t0,
			&commitment_w1,
		);

		if condition1 & condition2 & condition3 & condition4 {
			packing::pack_sig::<K, L, GAMMA1, OMEGA, CD, PZ, SIG>(
				signature_output,
				None,
				&signature_z,
				&hint_vector_h,
			);
			return;
		}

		attempt_nonce += 1;
	}
}

/// Verify a signature for a given message with a public key (parameterized).
pub(crate) fn verify_var<
	const K: usize,
	const L: usize,
	const ETA: usize,
	const TAU: usize,
	const GAMMA1: usize,
	const GAMMA2: usize,
	const OMEGA: usize,
	const CD: usize,
	const PZ: usize,
	const W1: usize,
	const KW1: usize,
	const PK: usize,
	const SK: usize,
	const SIG: usize,
>(
	sig: &[u8; SIG],
	domain_prefix: &[u8],
	m: &[u8],
	pk: &[u8; PK],
) -> bool {
	const {
		assert_sign_params::<K, L, ETA, GAMMA1, GAMMA2, OMEGA, CD, PZ, W1, KW1, PK, SK, SIG>();
	}

	let mut buf = [0u8; KW1];
	let mut rho = [0u8; params::SEEDBYTES];
	let mut mu = [0u8; params::CRHBYTES];
	let mut c = [0u8; CD];
	let mut c2 = [0u8; CD];
	let mut cp = Poly::default();
	let mut z = Polyvec::<L>::default();
	let mut t1 = Polyvec::<K>::default();
	let mut w1 = Polyvec::<K>::default();
	let mut h = Polyvec::<K>::default();
	let mut state = fips202::KeccakState::default();

	packing::unpack_pk(&mut rho, &mut t1, pk);

	// Reject the degenerate all-zero t1 public key. With t1 = 0 the term c*2^d*t1 in the
	// verification relation vanishes for every challenge c, so w1 = UseHint(h, Az) no longer
	// binds the challenge to the key. An attacker can then forge a signature (z = 0, empty
	// hint, c = H(mu || w1Encode(0))) with no secret key. Honest key generation never yields
	// t1 = 0, so rejecting it costs nothing and closes the malicious-key forgery.
	if t1.vec.iter().all(|p| p.coeffs.iter().all(|&c| c == 0)) {
		return false;
	}

	if !packing::unpack_sig::<K, L, GAMMA1, OMEGA, CD, PZ, SIG>(&mut c, &mut z, &mut h, sig) {
		return false;
	}
	let beta = TAU * ETA;
	if !polyvec::is_norm_within_bound(&z, (GAMMA1 - beta) as i32) {
		return false;
	}

	fips202::shake256(&mut mu, pk);
	fips202::shake256_absorb(&mut state, &mu);
	fips202::shake256_absorb(&mut state, domain_prefix);
	fips202::shake256_absorb(&mut state, m);
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut mu, &mut state);

	poly::challenge::<TAU>(&mut cp, &c);

	polyvec::ntt(&mut z);
	polyvec::matrix_pointwise_montgomery_streamed(&mut w1, &rho, &z);

	poly::ntt(&mut cp);
	polyvec::shiftl(&mut t1);
	polyvec::ntt(&mut t1);
	let t1_2 = t1.clone();
	polyvec::pointwise_poly_montgomery(&mut t1, &cp, &t1_2);

	polyvec::sub(&mut w1, &t1);
	polyvec::reduce(&mut w1);
	polyvec::invntt_tomont(&mut w1);

	polyvec::caddq(&mut w1);
	polyvec::use_hint::<K, GAMMA2>(&mut w1, &h);
	polyvec::pack_w1::<K, GAMMA2, KW1>(&mut buf, &w1);

	state.init();
	fips202::shake256_absorb(&mut state, &mu);
	fips202::shake256_absorb(&mut state, &buf);
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut c2, &mut state);
	c == c2
}

// ---------------------------------------------------------------------------
// ML-DSA-87 convenience wrappers (test-only)
//
// Thin monomorphizations used by the in-module unit tests so their bodies
// stay readable. Production call sites (frontends, ACVP) invoke the generic
// `*_var` cores directly.
// ---------------------------------------------------------------------------

#[cfg(test)]
fn keypair(
	pk: &mut [u8; params::PUBLICKEYBYTES],
	sk: &mut [u8; params::SECRETKEYBYTES],
	seed: SensitiveBytes32,
) {
	keypair_var::<
		{ params::K },
		{ params::L },
		{ params::ETA },
		{ params::PUBLICKEYBYTES },
		{ params::SECRETKEYBYTES },
	>(pk, sk, seed)
}

#[cfg(test)]
fn signature(
	signature_output: &mut [u8; params::SIGNBYTES],
	domain_prefix: &[u8],
	message: &[u8],
	secret_key_bytes: &[u8; params::SECRETKEYBYTES],
	hedge: Option<[u8; params::SEEDBYTES]>,
) {
	signature_var::<
		{ params::K },
		{ params::L },
		{ params::ETA },
		{ params::TAU },
		{ params::GAMMA1 },
		{ params::GAMMA2 },
		{ params::OMEGA },
		{ params::C_DASH_BYTES },
		{ params::POLYZ_PACKEDBYTES },
		{ params::POLYW1_PACKEDBYTES },
		{ params::K * params::POLYW1_PACKEDBYTES },
		{ params::PUBLICKEYBYTES },
		{ params::SECRETKEYBYTES },
		{ params::SIGNBYTES },
	>(signature_output, domain_prefix, message, secret_key_bytes, hedge)
}

#[cfg(test)]
fn verify(
	sig: &[u8; params::SIGNBYTES],
	domain_prefix: &[u8],
	m: &[u8],
	pk: &[u8; params::PUBLICKEYBYTES],
) -> bool {
	verify_var::<
		{ params::K },
		{ params::L },
		{ params::ETA },
		{ params::TAU },
		{ params::GAMMA1 },
		{ params::GAMMA2 },
		{ params::OMEGA },
		{ params::C_DASH_BYTES },
		{ params::POLYZ_PACKEDBYTES },
		{ params::POLYW1_PACKEDBYTES },
		{ params::K * params::POLYW1_PACKEDBYTES },
		{ params::PUBLICKEYBYTES },
		{ params::SECRETKEYBYTES },
		{ params::SIGNBYTES },
	>(sig, domain_prefix, m, pk)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::polyvec::Polyvec;
	use alloc::{string::String, vec};
	use rand::RngExt;

	const K: usize = params::K;
	const L: usize = params::L;

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
	) -> Polyvec<L> {
		let mut challenge_seed = [0u8; params::C_DASH_BYTES];
		let mut z = Polyvec::<L>::default();
		let mut h = Polyvec::<K>::default();
		assert!(packing::unpack_sig::<
			K,
			L,
			{ params::GAMMA1 },
			{ params::OMEGA },
			{ params::C_DASH_BYTES },
			{ params::POLYZ_PACKEDBYTES },
			{ params::SIGNBYTES },
		>(&mut challenge_seed, &mut z, &mut h, sig));

		let unpacked =
			unpack_secret_key_for_signing::<K, L, { params::ETA }, { params::SECRETKEYBYTES }>(sk); // s1 already in NTT domain
		let mut challenge_poly = Poly::default();
		poly::challenge::<{ params::TAU }>(&mut challenge_poly, &challenge_seed);
		poly::ntt(&mut challenge_poly);

		let mut cs1 = Polyvec::<L>::default();
		polyvec::pointwise_poly_montgomery(&mut cs1, &challenge_poly, &unpacked.secret_poly_s1_ntt);
		polyvec::invntt_tomont(&mut cs1);

		// y ≡ z - c·s1 (mod q); normalise to the canonical [0, Q) representative for comparison.
		for i in 0..L {
			poly::sub_ip(&mut z.vec[i], &cs1.vec[i]);
			poly::reduce(&mut z.vec[i]);
			poly::caddq(&mut z.vec[i]);
		}
		z
	}

	fn polyvecl_eq(a: &Polyvec<L>, b: &Polyvec<L>) -> bool {
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
		let w1 = Polyvec::<K>::default();
		let mut buf = [0u8; K * params::POLYW1_PACKEDBYTES];
		polyvec::pack_w1::<K, { params::GAMMA2 }, { params::K * params::POLYW1_PACKEDBYTES }>(
			&mut buf, &w1,
		);

		// Pick the challenge to equal the verifier's own recomputation: c = H(mu || w1Encode(0)).
		let mut c = [0u8; params::C_DASH_BYTES];
		let mut cstate = fips202::KeccakState::default();
		fips202::shake256_absorb(&mut cstate, &mu);
		fips202::shake256_absorb(&mut cstate, &buf);
		fips202::shake256_finalize(&mut cstate);
		fips202::shake256_squeeze(&mut c, &mut cstate);

		// Assemble the forged signature (c, z = 0, empty hint).
		let z = Polyvec::<L>::default();
		let h = Polyvec::<K>::default();
		let mut sig = [0u8; params::SIGNBYTES];
		packing::pack_sig::<
			K,
			L,
			{ params::GAMMA1 },
			{ params::OMEGA },
			{ params::C_DASH_BYTES },
			{ params::POLYZ_PACKEDBYTES },
			{ params::SIGNBYTES },
		>(&mut sig, Some(&c), &z, &h);

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
