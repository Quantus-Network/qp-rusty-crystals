//! ML-DSA-87 (FIPS 204 category 5) public API.
//!
//! Thin frontend over the const-generic signing core, instantiated at the
//! [`crate::params::ml_dsa_87`] parameter set.

crate::frontend::define_ml_dsa!(ml_dsa_87, crate::params::ml_dsa_87);

#[cfg(test)]
mod tests {
	use super::{Keypair, MAX_MESSAGE_SIZE, SIGNBYTES};
	use crate::{errors::SignatureError, SensitiveBytes32};
	use alloc::vec;
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
		let msg = get_random_msg();
		let entropy = get_random_bytes();
		let keys = Keypair::generate(entropy);
		let hedge = get_random_bytes();
		let sig = keys.sign(&msg, None, Some(hedge.0)).unwrap();
		assert!(keys.verify(&msg, &sig, None));
	}

	#[test]
	fn self_verify() {
		let msg = get_random_msg();
		let entropy = get_random_bytes();
		let keys = Keypair::generate(entropy);
		let hedge = get_random_bytes();
		let sig = keys.sign(&msg, None, Some(hedge.0)).unwrap();
		assert!(keys.verify(&msg, &sig, None));
	}

	#[test]
	fn verify_fails_with_different_context() {
		let msg = get_random_msg();
		let entropy = get_random_bytes();
		let keys = Keypair::generate(entropy);
		let hedge = get_random_bytes();

		// Sign with context "test1"
		let ctx1 = b"test1";
		let sig = keys.sign(&msg, Some(ctx1), Some(hedge.0)).unwrap();

		// Try to verify with different context "test2" - should fail
		let ctx2 = b"test2";
		assert!(!keys.verify(&msg, &sig, Some(ctx2)));

		// Verify with correct context should still work
		assert!(keys.verify(&msg, &sig, Some(ctx1)));
	}

	#[test]
	fn sign_rejects_oversized_message() {
		let keys = Keypair::generate(get_random_bytes());
		let big_msg = vec![0u8; MAX_MESSAGE_SIZE + 1];
		let result = keys.sign(&big_msg, None, None);
		assert!(matches!(result, Err(SignatureError::MessageTooLong)));
	}

	#[test]
	fn verify_rejects_oversized_message() {
		let keys = Keypair::generate(get_random_bytes());
		let big_msg = vec![0u8; MAX_MESSAGE_SIZE + 1];
		assert!(!keys.verify(&big_msg, &[0u8; SIGNBYTES], None));
	}

	// A keypair blob whose public half does not correspond to its secret half must
	// be rejected. Otherwise an imported keypair could sign with one key while
	// advertising an unrelated public key (e.g. an unspendable receive address).
	#[test]
	fn from_bytes_rejects_mismatched_public_key() {
		use super::{KeyParsingError, Keypair, KEYPAIRBYTES, SECRETKEYBYTES};

		let keys_a = Keypair::generate(get_random_bytes());
		let keys_b = Keypair::generate(get_random_bytes());

		// Genuine keypair bytes must round-trip.
		let good = keys_a.to_bytes();
		assert!(Keypair::from_bytes(good.as_slice()).is_ok(), "honest keypair must be accepted");

		// Splice A's secret key with B's (unrelated) public key.
		let mut forged = [0u8; KEYPAIRBYTES];
		forged[..SECRETKEYBYTES].copy_from_slice(keys_a.secret.to_bytes().as_slice());
		forged[SECRETKEYBYTES..].copy_from_slice(&keys_b.public.to_bytes());

		assert!(
			matches!(Keypair::from_bytes(&forged), Err(KeyParsingError::BadKeypair)),
			"public key not derived from the secret key must be rejected"
		);
	}

	// `from_parts` is the only way to assemble a `Keypair` from separately
	// imported halves (the fields are private), so it must enforce the same
	// secret/public correspondence as `from_bytes`: a keypair that signs
	// under one key while advertising another must be unrepresentable.
	#[test]
	fn from_parts_enforces_secret_public_correspondence() {
		use super::{KeyParsingError, Keypair, SecretKey};

		let keys_a = Keypair::generate(get_random_bytes());
		let keys_b = Keypair::generate(get_random_bytes());

		let secret_a = SecretKey::from_bytes(keys_a.secret.to_bytes().as_slice()).unwrap();
		assert!(
			matches!(
				Keypair::from_parts(secret_a, keys_b.public.clone()),
				Err(KeyParsingError::BadKeypair)
			),
			"unrelated halves must be rejected"
		);

		let secret_a = SecretKey::from_bytes(keys_a.secret.to_bytes().as_slice()).unwrap();
		let assembled = Keypair::from_parts(secret_a, keys_a.public.clone())
			.expect("matching halves must be accepted");
		assert_eq!(*assembled.to_bytes(), *keys_a.to_bytes());
	}

	// The packed secret key stores tr = SHAKE256(pk) and t0 (low bits of
	// A·s1 + s2) alongside (rho, s1, s2). Signing uses the stored tr and t0, so
	// a blob with honest rho/s1/s2/pk but a corrupted tr or t0 region would
	// import cleanly and then produce signatures that fail under the advertised
	// public key. `from_bytes` must reject such blobs at import.
	#[test]
	fn from_bytes_rejects_corrupted_tr_or_t0() {
		use super::{KeyParsingError, Keypair, SECRETKEYBYTES};
		use crate::params::{POLYT0_PACKEDBYTES, SEEDBYTES, TR_BYTES};

		let keys = Keypair::generate(get_random_bytes());
		let good = keys.to_bytes();
		assert!(Keypair::from_bytes(good.as_slice()).is_ok(), "honest keypair must be accepted");

		// SK layout: rho (32) || key (32) || tr (64) || s1 || s2 || t0.
		let tr_offset = 2 * SEEDBYTES;
		let t0_offset = SECRETKEYBYTES - crate::params::K * POLYT0_PACKEDBYTES;

		// Corrupt one byte inside the stored tr region only.
		let mut bad_tr = good.clone();
		bad_tr[tr_offset + TR_BYTES / 2] ^= 0x01;
		assert!(
			matches!(Keypair::from_bytes(bad_tr.as_slice()), Err(KeyParsingError::BadKeypair)),
			"secret key with corrupted tr must be rejected"
		);

		// Corrupt one byte inside the stored t0 region only.
		let mut bad_t0 = good;
		bad_t0[t0_offset] ^= 0x01;
		assert!(
			matches!(Keypair::from_bytes(bad_t0.as_slice()), Err(KeyParsingError::BadKeypair)),
			"secret key with corrupted t0 must be rejected"
		);
	}

	// The standalone SecretKey import path must enforce the same tr/t0
	// consistency defense as Keypair::from_bytes. Signing consumes the stored
	// tr (bound into the message digest) and t0 (hint computation), so a
	// corrupted standalone key would otherwise import cleanly and then emit
	// signatures that fail under the corresponding public key — a persistent,
	// hard-to-diagnose signing outage for callers that store SecretKey alone.
	#[test]
	fn secret_key_from_bytes_rejects_corrupted_tr_or_t0() {
		use super::{KeyParsingError, Keypair, SecretKey, SECRETKEYBYTES};
		use crate::params::{POLYT0_PACKEDBYTES, SEEDBYTES, TR_BYTES};

		let keys = Keypair::generate(get_random_bytes());
		let good = keys.secret.to_bytes();
		assert!(
			SecretKey::from_bytes(good.as_slice()).is_ok(),
			"honest secret key must be accepted"
		);

		// SK layout: rho (32) || key (32) || tr (64) || s1 || s2 || t0.
		let tr_offset = 2 * SEEDBYTES;
		let t0_offset = SECRETKEYBYTES - crate::params::K * POLYT0_PACKEDBYTES;

		// Corrupt one byte inside the stored tr region only.
		let mut bad_tr = good.clone();
		bad_tr[tr_offset + TR_BYTES / 2] ^= 0x01;
		assert!(
			matches!(SecretKey::from_bytes(bad_tr.as_slice()), Err(KeyParsingError::BadSecretKey)),
			"standalone secret key with corrupted tr must be rejected"
		);

		// Corrupt one byte inside the stored t0 region only.
		let mut bad_t0 = good;
		bad_t0[t0_offset] ^= 0x01;
		assert!(
			matches!(SecretKey::from_bytes(bad_t0.as_slice()), Err(KeyParsingError::BadSecretKey)),
			"standalone secret key with corrupted t0 must be rejected"
		);
	}

	// The standalone SecretKey import path must reject a secret key whose
	// derived public key has all-zero t1, matching PublicKey::from_bytes and
	// sign::verify. Such a blob (s1 = s2 = 0, hence t1 = t0 = 0) passes the
	// tr/t0 consistency checks by construction, so without an explicit t1
	// check it imports cleanly and then produces signatures that can never
	// verify — while the degenerate public key it corresponds to is exactly
	// the malicious-key forgery class the verifier rejects.
	#[test]
	fn secret_key_from_bytes_rejects_zero_t1() {
		use super::{KeyParsingError, SecretKey, SECRETKEYBYTES};
		use crate::{
			packing,
			params::{self, K, L},
			polyvec,
		};

		// Craft a fully self-consistent secret key with s1 = s2 = 0:
		// t = A·0 + 0 = 0, so t1 = 0 and t0 = 0, and tr = SHAKE256(pk).
		let rho = [0x42u8; params::SEEDBYTES];
		let key = [0x17u8; params::SEEDBYTES];
		let s1 = polyvec::Polyvec::<L>::default();
		let s2 = polyvec::Polyvec::<K>::default();
		let t0 = polyvec::Polyvec::<K>::default();
		let t1 = polyvec::Polyvec::<K>::default();

		let mut pk = [0u8; super::PUBLICKEYBYTES];
		packing::pack_pk(&mut pk, &rho, &t1);
		let mut tr = [0u8; params::TR_BYTES];
		crate::fips202::shake256(&mut tr, &pk);

		let mut sk = [0u8; SECRETKEYBYTES];
		packing::pack_sk::<{ params::K }, { params::L }, { params::ETA }, SECRETKEYBYTES>(
			&mut sk, &rho, &tr, &key, &t0, &s1, &s2,
		);

		assert!(
			matches!(SecretKey::from_bytes(&sk), Err(KeyParsingError::BadSecretKey)),
			"secret key deriving an all-zero t1 public key must be rejected"
		);
	}

	// The packed s1/s2 regions use 3 bits per coefficient, decoded as
	// `ETA - slot`. With ETA = 2, slots 5..7 decode to coefficients -3..-5 —
	// outside the [-ETA, ETA] key distribution the parameters advertise and
	// the BETA rejection margin is sized for. An attacker can recompute
	// t0/tr/pk *from* the oversized coefficients, so every algebraic
	// consistency check passes; the import paths must therefore enforce the
	// coefficient range explicitly.
	#[test]
	fn from_bytes_rejects_out_of_range_secret_coefficients() {
		use super::{
			KeyParsingError, Keypair, SecretKey, KEYPAIRBYTES, PUBLICKEYBYTES, SECRETKEYBYTES,
		};
		use crate::{
			fips202, packing,
			params::{self, K, L},
			polyvec,
		};

		// Start from an honest key and re-derive everything after planting
		// the out-of-range coefficient, so the forged blob is fully
		// self-consistent (valid t0, tr, and matching public key).
		let keys = Keypair::generate(get_random_bytes());
		let sk_bytes = keys.secret.to_bytes();

		let mut rho = [0u8; params::SEEDBYTES];
		let mut tr = [0u8; params::TR_BYTES];
		let mut key = [0u8; params::SEEDBYTES];
		let mut t0 = polyvec::Polyvec::<K>::default();
		let mut s1 = polyvec::Polyvec::<L>::default();
		let mut s2 = polyvec::Polyvec::<K>::default();
		assert!(
			packing::unpack_sk::<{ params::K }, { params::L }, { params::ETA }, SECRETKEYBYTES>(
				&mut rho, &mut tr, &mut key, &mut t0, &mut s1, &mut s2, &sk_bytes,
			),
			"honest key unpacks canonically"
		);

		// -3 packs as the 3-bit slot 5 (eta_pack stores ETA - coeff), so the
		// forged coefficient survives the pack/unpack round trip.
		s1.vec[0].coeffs_mut()[0] = -(params::ETA as i32) - 1;

		// Same derivation as keygen: t = A·s1 + s2, split into (t1, t0).
		let mut s1hat = s1.clone();
		polyvec::ntt(&mut s1hat);
		let mut t1 = polyvec::Polyvec::<K>::default();
		polyvec::matrix_pointwise_montgomery_streamed(&mut t1, &rho, &s1hat);
		polyvec::reduce(&mut t1);
		polyvec::invntt_tomont(&mut t1);
		polyvec::add(&mut t1, &s2);
		polyvec::caddq(&mut t1);
		let mut t0_forged = polyvec::Polyvec::<K>::default();
		polyvec::power2round(&mut t1, &mut t0_forged);

		let mut pk = [0u8; PUBLICKEYBYTES];
		packing::pack_pk(&mut pk, &rho, &t1);
		let mut tr_forged = [0u8; params::TR_BYTES];
		fips202::shake256(&mut tr_forged, &pk);

		let mut forged_sk = [0u8; SECRETKEYBYTES];
		packing::pack_sk::<{ params::K }, { params::L }, { params::ETA }, SECRETKEYBYTES>(
			&mut forged_sk,
			&rho,
			&tr_forged,
			&key,
			&t0_forged,
			&s1,
			&s2,
		);

		assert!(
			matches!(SecretKey::from_bytes(&forged_sk), Err(KeyParsingError::BadSecretKey)),
			"secret key with a coefficient outside [-ETA, ETA] must be rejected"
		);

		let mut forged_kp = [0u8; KEYPAIRBYTES];
		forged_kp[..SECRETKEYBYTES].copy_from_slice(&forged_sk);
		forged_kp[SECRETKEYBYTES..].copy_from_slice(&pk);
		assert!(
			matches!(Keypair::from_bytes(&forged_kp), Err(KeyParsingError::BadKeypair)),
			"keypair with a secret coefficient outside [-ETA, ETA] must be rejected"
		);

		// Honest keys must still round-trip.
		assert!(
			SecretKey::from_bytes(sk_bytes.as_slice()).is_ok(),
			"honest secret key must be accepted"
		);
	}

	// Malicious-key forgery defense: a public key with an all-zero t1 makes verification
	// independent of the challenge, enabling signature forgery without a secret key.
	// `from_bytes` must reject such a key so it can never be constructed or stored.
	#[test]
	fn from_bytes_rejects_zero_t1_public_key() {
		use super::{KeyParsingError, PublicKey, PUBLICKEYBYTES};

		// Arbitrary rho, all-zero t1 region.
		let mut pk = [0u8; PUBLICKEYBYTES];
		pk[..crate::params::SEEDBYTES].copy_from_slice(&[0x42u8; crate::params::SEEDBYTES]);

		assert!(matches!(PublicKey::from_bytes(&pk), Err(KeyParsingError::BadPublicKey)));

		// A genuine public key must still round-trip through from_bytes.
		let keys = Keypair::generate(get_random_bytes());
		let good = keys.public.to_bytes();
		assert!(PublicKey::from_bytes(&good).is_ok());
	}
}
