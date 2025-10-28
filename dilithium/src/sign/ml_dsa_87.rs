use crate::{
	fips202, packing, params, poly,
	poly::Poly,
	polyvec,
	polyvec::lvl5::{Polyveck, Polyvecl},
};
const K: usize = params::ml_dsa_87::K;
const L: usize = params::ml_dsa_87::L;

extern crate alloc; // this makes Vec work
use alloc::vec::Vec;
/// Generate public and private key.
///
/// # Arguments
///
/// * 'pk' - preallocated buffer for public key
/// * 'sk' - preallocated buffer for private key
/// * 'seed' - optional seed; if None [random_bytes()] is used for randomness generation
pub fn keypair(pk: &mut [u8], sk: &mut [u8], seed: Option<&[u8]>) {
	#[allow(unused_mut)]
	let mut init_seed: Vec<u8>;
	match seed {
		Some(x) => init_seed = x.to_vec(),
		None => {
			#[cfg(not(feature = "std"))]
			unimplemented!("must provide entropy in verifier only mode");
			#[cfg(feature = "std")]
			{
				init_seed = vec![0u8; params::SEEDBYTES];
				crate::random_bytes(&mut init_seed, params::SEEDBYTES)
			}
		},
	};

	const SEEDBUF_LEN: usize = 2 * params::SEEDBYTES + params::CRHBYTES;
	let mut seedbuf = [0u8; SEEDBUF_LEN];
	fips202::shake256(&mut seedbuf, SEEDBUF_LEN, &init_seed, params::SEEDBYTES);

	let mut rho = [0u8; params::SEEDBYTES];
	rho.copy_from_slice(&seedbuf[..params::SEEDBYTES]);

	let mut rhoprime = [0u8; params::CRHBYTES];
	rhoprime.copy_from_slice(&seedbuf[params::SEEDBYTES..params::SEEDBYTES + params::CRHBYTES]);

	let mut key = [0u8; params::SEEDBYTES];
	key.copy_from_slice(&seedbuf[params::SEEDBYTES + params::CRHBYTES..]);

	// Move large polynomial structures to heap to reduce stack usage
	let mut mat = Box::new([Polyvecl::default(); K]);
	polyvec::lvl5::matrix_expand(&mut *mat, &rho);

	let mut s1 = Box::new(Polyvecl::default());
	polyvec::lvl5::l_uniform_eta(&mut s1, &rhoprime, 0);

	let mut s2 = Box::new(Polyveck::default());
	polyvec::lvl5::k_uniform_eta(&mut s2, &rhoprime, L as u16);

	let mut s1hat = Box::new(*s1);
	polyvec::lvl5::l_ntt(&mut s1hat);

	let mut t1 = Box::new(Polyveck::default());
	polyvec::lvl5::matrix_pointwise_montgomery(&mut t1, &*mat, &s1hat);
	polyvec::lvl5::k_reduce(&mut t1);
	polyvec::lvl5::k_invntt_tomont(&mut t1);
	polyvec::lvl5::k_add(&mut t1, &s2);
	polyvec::lvl5::k_caddq(&mut t1);

	let mut t0 = Box::new(Polyveck::default());
	polyvec::lvl5::k_power2round(&mut t1, &mut t0);

	packing::ml_dsa_87::pack_pk(pk, &rho, &t1);

	let mut tr = [0u8; params::TR_BYTES];
	fips202::shake256(&mut tr, params::TR_BYTES, pk, params::ml_dsa_87::PUBLICKEYBYTES);

	packing::ml_dsa_87::pack_sk(sk, &rho, &tr, &key, &t0, &s1, &s2);
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
pub fn signature(
	output_signature: &mut [u8],
	message_to_sign: &[u8],
	secret_key: &[u8],
	use_randomization: bool,
) {
	let mut public_seed_rho = [0u8; params::SEEDBYTES];
	let mut public_key_hash_tr = [0u8; params::TR_BYTES];
	let mut key_and_message_hash = [0u8; params::SEEDBYTES + params::CRHBYTES];
	let mut secret_t0_vector = Box::new(Polyveck::default());
	let mut secret_s1_vector = Box::new(Polyvecl::default());
	let mut secret_s2_vector = Box::new(Polyveck::default());

	packing::ml_dsa_87::unpack_sk(
		&mut public_seed_rho,
		&mut public_key_hash_tr,
		&mut key_and_message_hash[..params::SEEDBYTES],
		&mut secret_t0_vector,
		&mut secret_s1_vector,
		&mut secret_s2_vector,
		secret_key,
	);

	let mut keccak_state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut keccak_state, &public_key_hash_tr, params::TR_BYTES);
	fips202::shake256_absorb(&mut keccak_state, message_to_sign, message_to_sign.len());
	fips202::shake256_finalize(&mut keccak_state);
	fips202::shake256_squeeze(
		&mut key_and_message_hash[params::SEEDBYTES..],
		params::CRHBYTES,
		&mut keccak_state,
	);

	#[allow(unused_mut)]
	let mut randomness_for_hedging = [0u8; params::SEEDBYTES];
	if use_randomization {
		#[cfg(feature = "std")]
		crate::random_bytes(&mut randomness_for_hedging, params::SEEDBYTES);
		#[cfg(not(feature = "std"))]
		unimplemented!("hedged mode doesn't work in verifier only mode");
	}
	keccak_state.init();
	fips202::shake256_absorb(
		&mut keccak_state,
		&key_and_message_hash[..params::SEEDBYTES],
		params::SEEDBYTES,
	);
	fips202::shake256_absorb(&mut keccak_state, &randomness_for_hedging, params::SEEDBYTES);
	fips202::shake256_absorb(
		&mut keccak_state,
		&key_and_message_hash[params::SEEDBYTES..],
		params::CRHBYTES,
	);
	fips202::shake256_finalize(&mut keccak_state);
	let mut signing_randomness_rhoprime = [0u8; params::CRHBYTES];
	fips202::shake256_squeeze(
		&mut signing_randomness_rhoprime,
		params::CRHBYTES,
		&mut keccak_state,
	);

	// Move large polynomial structures to heap to reduce stack usage
	let mut public_matrix_a = Box::new([Polyvecl::default(); K]);
	polyvec::lvl5::matrix_expand(&mut *public_matrix_a, &public_seed_rho);
	polyvec::lvl5::l_ntt(&mut secret_s1_vector);
	polyvec::lvl5::k_ntt(&mut secret_s2_vector);
	polyvec::lvl5::k_ntt(&mut secret_t0_vector);

	let mut rejection_sampling_nonce: u16 = 0;
	let mut masking_vector_y = Box::new(Polyvecl::default());
	let mut commitment_high_w1 = Box::new(Polyveck::default());
	let mut commitment_low_w0 = Box::new(Polyveck::default());
	let mut challenge_polynomial_c = Box::new(Poly::default());
	let mut hint_vector_h = Box::new(Polyveck::default());
	// REJECTION SAMPLING LOOP - Variable iterations cause timing leak!
	loop {
		polyvec::lvl5::l_uniform_gamma1(
			&mut masking_vector_y,
			&signing_randomness_rhoprime,
			rejection_sampling_nonce,
		);
		rejection_sampling_nonce += 1;

		let mut signature_z_candidate = Box::new(*masking_vector_y);
		polyvec::lvl5::l_ntt(&mut signature_z_candidate);
		polyvec::lvl5::matrix_pointwise_montgomery(
			&mut commitment_high_w1,
			&*public_matrix_a,
			&signature_z_candidate,
		);
		polyvec::lvl5::k_reduce(&mut commitment_high_w1);
		polyvec::lvl5::k_invntt_tomont(&mut commitment_high_w1);
		polyvec::lvl5::k_caddq(&mut commitment_high_w1);

		polyvec::lvl5::k_decompose(&mut commitment_high_w1, &mut commitment_low_w0);
		polyvec::lvl5::k_pack_w1(output_signature, &commitment_high_w1);

		keccak_state.init();
		fips202::shake256_absorb(
			&mut keccak_state,
			&key_and_message_hash[params::SEEDBYTES..],
			params::CRHBYTES,
		);
		fips202::shake256_absorb(
			&mut keccak_state,
			output_signature,
			K * params::ml_dsa_87::POLYW1_PACKEDBYTES,
		);
		fips202::shake256_finalize(&mut keccak_state);
		fips202::shake256_squeeze(
			output_signature,
			params::ml_dsa_87::C_DASH_BYTES,
			&mut keccak_state,
		);

		poly::ml_dsa_87::challenge(&mut challenge_polynomial_c, output_signature);
		poly::ntt(&mut challenge_polynomial_c);

		polyvec::lvl5::l_pointwise_poly_montgomery(
			&mut signature_z_candidate,
			&challenge_polynomial_c,
			&secret_s1_vector,
		);
		polyvec::lvl5::l_invntt_tomont(&mut signature_z_candidate);
		polyvec::lvl5::l_add(&mut signature_z_candidate, &masking_vector_y);
		polyvec::lvl5::l_reduce(&mut signature_z_candidate);

		// REJECTION CHECK 1: z vector norm - TIMING LEAK SOURCE!
		if polyvec::lvl5::l_chknorm(
			&signature_z_candidate,
			(params::ml_dsa_87::GAMMA1 - params::ml_dsa_87::BETA) as i32,
		) > 0
		{
			continue;
		}

		polyvec::lvl5::k_pointwise_poly_montgomery(
			&mut hint_vector_h,
			&challenge_polynomial_c,
			&secret_s2_vector,
		);
		polyvec::lvl5::k_invntt_tomont(&mut hint_vector_h);
		polyvec::lvl5::k_sub(&mut commitment_low_w0, &hint_vector_h);
		polyvec::lvl5::k_reduce(&mut commitment_low_w0);

		// REJECTION CHECK 2: w0 vector norm - TIMING LEAK SOURCE!
		if polyvec::lvl5::k_chknorm(
			&commitment_low_w0,
			(params::ml_dsa_87::GAMMA2 - params::ml_dsa_87::BETA) as i32,
		) > 0
		{
			continue;
		}

		polyvec::lvl5::k_pointwise_poly_montgomery(
			&mut hint_vector_h,
			&challenge_polynomial_c,
			&secret_t0_vector,
		);
		polyvec::lvl5::k_invntt_tomont(&mut hint_vector_h);
		polyvec::lvl5::k_reduce(&mut hint_vector_h);

		// REJECTION CHECK 3: h vector norm - TIMING LEAK SOURCE!
		if polyvec::lvl5::k_chknorm(&hint_vector_h, params::ml_dsa_87::GAMMA2 as i32) > 0 {
			continue;
		}

		polyvec::lvl5::k_add(&mut commitment_low_w0, &hint_vector_h);

		let hint_weight =
			polyvec::lvl5::k_make_hint(&mut hint_vector_h, &commitment_low_w0, &commitment_high_w1);

		// REJECTION CHECK 4: hint weight - TIMING LEAK SOURCE!
		if hint_weight > params::ml_dsa_87::OMEGA as i32 {
			continue;
		}

		packing::ml_dsa_87::pack_sig(
			output_signature,
			None,
			&signature_z_candidate,
			&hint_vector_h,
		);

		return;
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
	let mut buf = [0u8; K * crate::params::ml_dsa_87::POLYW1_PACKEDBYTES];
	let mut rho = [0u8; params::SEEDBYTES];
	let mut mu = [0u8; params::CRHBYTES];
	let mut c = [0u8; params::ml_dsa_87::C_DASH_BYTES];
	let mut c2 = [0u8; params::ml_dsa_87::C_DASH_BYTES];
	// Move large polynomial structures to heap to reduce stack usage
	let mut cp = Box::new(Poly::default());
	let mut mat = Box::new([Polyvecl::default(); K]);
	let mut z = Box::new(Polyvecl::default());
	let mut t1 = Box::new(Polyveck::default());
	let mut w1 = Box::new(Polyveck::default());
	let mut h = Box::new(Polyveck::default());
	let mut state = fips202::KeccakState::default(); // shake256_init()

	if sig.len() != crate::params::ml_dsa_87::SIGNBYTES {
		return false;
	}

	packing::ml_dsa_87::unpack_pk(&mut rho, &mut t1, pk);
	if !packing::ml_dsa_87::unpack_sig(&mut c, &mut z, &mut h, sig) {
		return false;
	}
	if polyvec::lvl5::l_chknorm(
		&z,
		(crate::params::ml_dsa_87::GAMMA1 - crate::params::ml_dsa_87::BETA) as i32,
	) > 0
	{
		return false;
	}

	// Compute CRH(CRH(rho, t1), msg)
	fips202::shake256(&mut mu, params::CRHBYTES, pk, crate::params::ml_dsa_87::PUBLICKEYBYTES);
	fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
	fips202::shake256_absorb(&mut state, m, m.len());
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut mu, params::CRHBYTES, &mut state);

	// Matrix-vector multiplication; compute Az - c2^dt1
	poly::ml_dsa_87::challenge(&mut cp, &c);
	polyvec::lvl5::matrix_expand(&mut *mat, &rho);

	polyvec::lvl5::l_ntt(&mut z);
	polyvec::lvl5::matrix_pointwise_montgomery(&mut w1, &*mat, &z);

	poly::ntt(&mut cp);
	polyvec::lvl5::k_shiftl(&mut t1);
	polyvec::lvl5::k_ntt(&mut t1);
	let t1_2 = Box::new(*t1);
	polyvec::lvl5::k_pointwise_poly_montgomery(&mut t1, &cp, &t1_2);

	polyvec::lvl5::k_sub(&mut w1, &t1);
	polyvec::lvl5::k_reduce(&mut w1);
	polyvec::lvl5::k_invntt_tomont(&mut w1);

	// Reconstruct w1
	polyvec::lvl5::k_caddq(&mut w1);
	polyvec::lvl5::k_use_hint(&mut w1, &h);
	polyvec::lvl5::k_pack_w1(&mut buf, &w1);

	// Call random oracle and verify challenge
	state.init();
	fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
	fips202::shake256_absorb(&mut state, &buf, K * crate::params::ml_dsa_87::POLYW1_PACKEDBYTES);
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut c2, params::ml_dsa_87::C_DASH_BYTES, &mut state);
	// Doesn't require constant time equality check
	if c != c2 {
		return false;
	}
	true
}

#[cfg(test)]
mod tests {
	#[test]
	fn self_verify_hedged() {
		let mut pk = [0u8; crate::params::ml_dsa_87::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::ml_dsa_87::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let mut sig = [0u8; crate::params::ml_dsa_87::SIGNBYTES];
		super::signature(&mut sig, &msg, &sk, true);
		assert!(super::verify(&sig, &msg, &pk));
	}
	#[test]
	fn self_verify() {
		let mut pk = [0u8; crate::params::ml_dsa_87::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::ml_dsa_87::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let mut sig = [0u8; crate::params::ml_dsa_87::SIGNBYTES];
		super::signature(&mut sig, &msg, &sk, false);
		assert!(super::verify(&sig, &msg, &pk));
	}
	//    #[test]
	//    fn keypair() {
	//        let seed: [u8; crate::params::SEEDBYTES] = [];
	//        let mut pk = [0u8; crate::params::ml_dsa_44::PUBLICKEYBYTES];
	//        let mut sk = [0u8; crate::params::ml_dsa_44::SECRETKEYBYTES];
	//        super::keypair(&mut pk, &mut sk, Some(&seed));
	//
	//        let test_pk: [u8; crate::params::ml_dsa_44::PUBLICKEYBYTES] = [];
	//        let test_sk: [u8; crate::params::ml_dsa_44::SECRETKEYBYTES] = [];
	//        assert_eq!(test_pk, pk);
	//    #[test]
	//    fn keypair() {
	//        let seed: [u8; crate::params::SEEDBYTES] = [];
	//        let mut pk = [0u8; crate::params::ml_dsa_87::PUBLICKEYBYTES];
	//        let mut sk = [0u8; crate::params::ml_dsa_87::SECRETKEYBYTES];
	//        super::keypair(&mut pk, &mut sk, Some(&seed));
	//
	//        let test_pk: [u8; crate::params::ml_dsa_87::PUBLICKEYBYTES] = [];
	//        let test_sk: [u8; crate::params::ml_dsa_87::SECRETKEYBYTES] = [];
	//        assert_eq!(test_pk, pk);
	//        assert_eq!(test_sk, sk);
	//        assert_eq!(pk[..crate::params::SEEDBYTES], sk[..crate::params::SEEDBYTES]);
	//    }
	//
	//    #[test]
	//    fn signature() {
	//        let msg: [u8; 33] = [];
	//        let sk: [u8; crate::params::ml_dsa_87::SECRETKEYBYTES] = [];
	//        let mut sig = [0u8; crate::params::ml_dsa_87::SIGNBYTES];
	//        super::signature(&mut sig, &msg, &sk, false);
	//
	//        let test_sig: [u8; crate::params::ml_dsa_87::SIGNBYTES + 33] =  [];
	//        assert!(test_sig[..crate::params::ml_dsa_87::SIGNBYTES] == sig);
	//    }
	//
	//    #[test]
	//    fn verify() {
	//        let msg: [u8; 33] = [];
	//        let sig: [u8; crate::params::ml_dsa_87::SIGNBYTES + 33] = [];
	//        let pk: [u8; crate::params::ml_dsa_87::PUBLICKEYBYTES] = [];
	//        assert!(super::verify(&sig[..crate::params::ml_dsa_87::SIGNBYTES], &msg, &pk));
	//    }
}
