use crate::{
	fips202, packing, params, poly,
	poly::Poly,
	polyvec,
	polyvec::{Polyveck, Polyvecl},
};
const K: usize = params::K;
const L: usize = params::L;

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
pub fn signature(sig: &mut [u8], msg: &[u8], sk: &[u8], hedged: bool) {
	let mut rho = [0u8; params::SEEDBYTES];
	let mut tr = [0u8; params::TR_BYTES];
	let mut keymu = [0u8; params::SEEDBYTES + params::CRHBYTES];
	let mut t0 = Box::new(Polyveck::default());
	let mut s1 = Box::new(Polyvecl::default());
	let mut s2 = Box::new(Polyveck::default());

	packing::unpack_sk(
		&mut rho,
		&mut tr,
		&mut keymu[..params::SEEDBYTES],
		&mut t0,
		&mut s1,
		&mut s2,
		sk,
	);

	let mut state = fips202::KeccakState::default();
	fips202::shake256_absorb(&mut state, &tr, params::TR_BYTES);
	fips202::shake256_absorb(&mut state, msg, msg.len());
	fips202::shake256_finalize(&mut state);
	fips202::shake256_squeeze(&mut keymu[params::SEEDBYTES..], params::CRHBYTES, &mut state);

	#[allow(unused_mut)]
	let mut rnd = [0u8; params::SEEDBYTES];
	if hedged {
		#[cfg(feature = "std")]
		crate::random_bytes(&mut rnd, params::SEEDBYTES);
		#[cfg(not(feature = "std"))]
		unimplemented!("hedged mode doesn't work in verifier only mode");
	}
	state.init();
	fips202::shake256_absorb(&mut state, &keymu[..params::SEEDBYTES], params::SEEDBYTES);
	fips202::shake256_absorb(&mut state, &rnd, params::SEEDBYTES);
	fips202::shake256_absorb(&mut state, &keymu[params::SEEDBYTES..], params::CRHBYTES);
	fips202::shake256_finalize(&mut state);
	let mut rhoprime = [0u8; params::CRHBYTES];
	fips202::shake256_squeeze(&mut rhoprime, params::CRHBYTES, &mut state);

	// Move large polynomial structures to heap to reduce stack usage
	let mut mat = Box::new([Polyvecl::default(); K]);
	polyvec::matrix_expand(&mut *mat, &rho);
	polyvec::l_ntt(&mut s1);
	polyvec::k_ntt(&mut s2);
	polyvec::k_ntt(&mut t0);

	let mut nonce: u16 = 0;
	let mut y = Box::new(Polyvecl::default());
	let mut w1 = Box::new(Polyveck::default());
	let mut w0 = Box::new(Polyveck::default());
	let mut cp = Box::new(Poly::default());
	let mut h = Box::new(Polyveck::default());
	loop {
		polyvec::l_uniform_gamma1(&mut y, &rhoprime, nonce);
		nonce += 1;

		let mut z = Box::new(*y);
		polyvec::l_ntt(&mut z);
		polyvec::matrix_pointwise_montgomery(&mut w1, &*mat, &z);
		polyvec::k_reduce(&mut w1);
		polyvec::k_invntt_tomont(&mut w1);
		polyvec::k_caddq(&mut w1);

		polyvec::k_decompose(&mut w1, &mut w0);
		polyvec::k_pack_w1(sig, &w1);

		state.init();
		fips202::shake256_absorb(&mut state, &keymu[params::SEEDBYTES..], params::CRHBYTES);
		fips202::shake256_absorb(&mut state, sig, K * params::POLYW1_PACKEDBYTES);
		fips202::shake256_finalize(&mut state);
		fips202::shake256_squeeze(sig, params::C_DASH_BYTES, &mut state);

		poly::challenge(&mut cp, sig);
		poly::ntt(&mut cp);

		polyvec::l_pointwise_poly_montgomery(&mut z, &cp, &s1);
		polyvec::l_invntt_tomont(&mut z);
		polyvec::l_add(&mut z, &y);
		polyvec::l_reduce(&mut z);

		if polyvec::l_chknorm(&z, (params::GAMMA1 - params::BETA) as i32) > 0 {
			continue;
		}

		polyvec::k_pointwise_poly_montgomery(&mut h, &cp, &s2);
		polyvec::k_invntt_tomont(&mut h);
		polyvec::k_sub(&mut w0, &h);
		polyvec::k_reduce(&mut w0);

		if polyvec::k_chknorm(&w0, (params::GAMMA2 - params::BETA) as i32) > 0 {
			continue;
		}

		polyvec::k_pointwise_poly_montgomery(&mut h, &cp, &t0);
		polyvec::k_invntt_tomont(&mut h);
		polyvec::k_reduce(&mut h);

		if polyvec::k_chknorm(&h, params::GAMMA2 as i32) > 0 {
			continue;
		}

		polyvec::k_add(&mut w0, &h);

		let n = polyvec::k_make_hint(&mut h, &w0, &w1);

		if n > params::OMEGA as i32 {
			continue;
		}

		packing::pack_sig(sig, None, &z, &h);

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
	if polyvec::l_chknorm(&z, (crate::params::GAMMA1 - crate::params::BETA) as i32) > 0 {
		return false;
	}

	// Compute CRH(CRH(rho, t1), msg)
	fips202::shake256(&mut mu, params::CRHBYTES, pk, crate::params::PUBLICKEYBYTES);
	fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
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
	#[test]
	fn self_verify_hedged() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &msg, &sk, true);
		assert!(super::verify(&sig, &msg, &pk));
	}

	#[test]
	fn self_verify() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);
		const MSG_BYTES: usize = 94;
		let mut msg = [0u8; MSG_BYTES];
		crate::random_bytes(&mut msg, MSG_BYTES);
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &msg, &sk, false);
		assert!(super::verify(&sig, &msg, &pk));
	}

	#[test]
	fn test_empty_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);

		let empty_msg: &[u8] = &[];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, empty_msg, &sk, false);
		assert!(super::verify(&sig, empty_msg, &pk));
	}

	#[test]
	fn test_single_byte_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);

		let msg = [0x42u8];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &msg, &sk, false);
		assert!(super::verify(&sig, &msg, &pk));
	}

	#[test]
	fn test_large_message() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);

		let large_msg = vec![0xABu8; 10000];
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, &large_msg, &sk, false);
		assert!(super::verify(&sig, &large_msg, &pk));
	}

	#[test]
	fn test_deterministic_signing() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);

		let msg = b"test message for deterministic signing";
		let mut sig1 = [0u8; crate::params::SIGNBYTES];
		let mut sig2 = [0u8; crate::params::SIGNBYTES];

		super::signature(&mut sig1, msg, &sk, false);
		super::signature(&mut sig2, msg, &sk, false);

		// Deterministic signing should produce identical signatures
		assert_eq!(sig1, sig2);
		assert!(super::verify(&sig1, msg, &pk));
		assert!(super::verify(&sig2, msg, &pk));
	}

	#[test]
	fn test_hedged_signing_differs() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);

		let msg = b"test message for hedged signing";
		let mut sig1 = [0u8; crate::params::SIGNBYTES];
		let mut sig2 = [0u8; crate::params::SIGNBYTES];

		super::signature(&mut sig1, msg, &sk, true);
		super::signature(&mut sig2, msg, &sk, true);

		// Hedged signing should produce different signatures (with high probability)
		assert_ne!(sig1, sig2);
		assert!(super::verify(&sig1, msg, &pk));
		assert!(super::verify(&sig2, msg, &pk));
	}

	#[test]
	fn test_wrong_message_fails() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);

		let msg1 = b"original message";
		let msg2 = b"different message";
		let mut sig = [0u8; crate::params::SIGNBYTES];

		super::signature(&mut sig, msg1, &sk, false);

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

		super::keypair(&mut pk1, &mut sk1, None);
		super::keypair(&mut pk2, &mut sk2, None);

		let msg = b"test message";
		let mut sig = [0u8; crate::params::SIGNBYTES];

		super::signature(&mut sig, msg, &sk1, false);

		// Should verify with correct key
		assert!(super::verify(&sig, msg, &pk1));
		// Should fail with wrong key
		assert!(!super::verify(&sig, msg, &pk2));
	}

	#[test]
	fn test_corrupted_signature_fails() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);

		let msg = b"test message";
		let mut sig = [0u8; crate::params::SIGNBYTES];
		super::signature(&mut sig, msg, &sk, false);

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
		super::keypair(&mut pk, &mut sk, None);

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
		let seed = [0x42u8; crate::params::SEEDBYTES];

		let mut pk1 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk1 = [0u8; crate::params::SECRETKEYBYTES];
		let mut pk2 = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk2 = [0u8; crate::params::SECRETKEYBYTES];

		super::keypair(&mut pk1, &mut sk1, Some(&seed));
		super::keypair(&mut pk2, &mut sk2, Some(&seed));

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

		super::keypair(&mut pk1, &mut sk1, Some(&seed1));
		super::keypair(&mut pk2, &mut sk2, Some(&seed2));

		// Different seeds should produce different keypairs
		assert_ne!(pk1, pk2);
		assert_ne!(sk1, sk2);
	}

	#[test]
	fn test_multiple_messages_same_key() {
		let mut pk = [0u8; crate::params::PUBLICKEYBYTES];
		let mut sk = [0u8; crate::params::SECRETKEYBYTES];
		super::keypair(&mut pk, &mut sk, None);

		let messages = [
			b"message 1".as_slice(),
			b"message 2",
			b"a much longer message that tests handling of various lengths",
			b"",
			b"single char: X",
		];

		for msg in &messages {
			let mut sig = [0u8; crate::params::SIGNBYTES];
			super::signature(&mut sig, msg, &sk, false);
			assert!(
				super::verify(&sig, msg, &pk),
				"Failed to verify message: {:?}",
				String::from_utf8_lossy(msg)
			);
		}
	}
	// Note: Test vector validation is handled in integration tests (tests/src/verify_integration_tests.rs)
	// which use proper NIST KAT test vectors for comprehensive validation.
}
