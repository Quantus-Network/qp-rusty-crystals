// tests/verify_integration_test.rs

use crate::helpers::{
	drbg::Drbg,
	kat::{parse_test_vectors, TestVector},
};
use qp_rusty_crystals_hdwallet::SensitiveBytes32;
use rand::RngExt;

/// Run the PQCrystals NIST KAT suite for one ML-DSA parameter set.
///
/// Dilithium2/3/5 map to ML-DSA-44/65/87. Vectors are generated with
/// `PQCgenKAT_sign{2,3,5}` from https://github.com/pq-crystals/dilithium.
macro_rules! nist_kat_for {
	($test_name:ident, $module:ident, $rsp:expr) => {
		#[test]
		fn $test_name() {
			use qp_rusty_crystals_dilithium::$module::{Keypair, PUBLICKEYBYTES};

			let kat_data = include_str!($rsp);
			let test_vectors = parse_test_vectors(kat_data);
			assert!(!test_vectors.is_empty(), "KAT file must contain vectors");
			for test in &test_vectors {
				verify_test_vector(
					test,
					PUBLICKEYBYTES,
					|mut entropy| Keypair::generate(&mut entropy),
					|bytes| Keypair::from_bytes(bytes).expect("KAT keypair bytes must deserialize"),
				);
			}
		}
	};
}

nist_kat_for!(test_nist_kat_ml_dsa_44, ml_dsa_44, "../../test_vectors/PQCsignKAT_Dilithium2.rsp");
nist_kat_for!(test_nist_kat_ml_dsa_65, ml_dsa_65, "../../test_vectors/PQCsignKAT_Dilithium3.rsp");
nist_kat_for!(test_nist_kat_ml_dsa_87, ml_dsa_87, "../../test_vectors/PQCsignKAT_Dilithium5.rsp");

fn get_random_bytes() -> SensitiveBytes32 {
	let mut rng = rand::rng();
	let mut bytes = [0u8; 32];
	rng.fill(&mut bytes);
	(&mut bytes).into()
}

fn keypair_bytes(sk: &[u8], pk: &[u8]) -> Vec<u8> {
	let mut result = vec![0; sk.len() + pk.len()];
	result[..sk.len()].copy_from_slice(sk);
	result[sk.len()..].copy_from_slice(pk);
	result
}

/// Verifies a single PQCrystals NIST KAT vector.
fn verify_test_vector<K, FGen, FFromBytes>(
	test: &TestVector,
	public_key_bytes: usize,
	generate: FGen,
	from_bytes: FFromBytes,
) where
	FGen: FnOnce(SensitiveBytes32) -> K,
	FFromBytes: FnOnce(&[u8]) -> K,
	K: HasNistKatApi,
{
	// Keypair generation KAT uses AES-256-CTR DRBG seeded like the C reference.
	let mut drbg = Drbg::new(&test.seed, None).unwrap();
	let mut entropy = [0u8; 32];
	assert!(drbg.randombytes(&mut entropy, 32).is_ok());
	let generated_keypair = generate(SensitiveBytes32::new(&mut entropy));
	assert_eq!(
		generated_keypair.public_bytes().as_slice(),
		test.pk.as_slice(),
		"Generated public key doesn't match NIST KAT for count {}",
		test.count
	);
	assert_eq!(
		generated_keypair.secret_bytes().as_slice(),
		test.sk.as_slice(),
		"Generated secret key doesn't match NIST KAT for count {}",
		test.count
	);

	assert_eq!(test.msg.len(), test.mlen, "Message length mismatch from test vector");
	assert_eq!(test.sm.len(), test.smlen, "Signed message length mismatch from test vector");
	assert_eq!(test.pk.len(), public_key_bytes, "Public key length mismatch");

	let nist_signature = test.extract_signature();
	let keypair = from_bytes(&keypair_bytes(&test.sk, &test.pk));
	assert!(
		keypair.verify_msg(&test.msg, nist_signature),
		"Signature verification failed for count {}",
		test.count
	);

	let mut hedge = [0u8; 32];
	assert!(drbg.randombytes(&mut hedge, 32).is_ok());
	// Move the DRBG output into a self-wiping wrapper (zeroes `hedge`);
	// `sign` borrows the hedge instead of taking it by value.
	let hedge = SensitiveBytes32::new(&mut hedge);
	let our_signature = keypair.sign_msg(&test.msg, Some(&hedge));
	assert_eq!(
		our_signature.as_slice(),
		nist_signature,
		"Our generated signature doesn't match NIST signature for count {}",
		test.count
	);

	let mut rng = rand::rng();
	for _ in 0..20 {
		let mut fuzzed_signature = nist_signature.to_vec();
		if fuzzed_signature.is_empty() {
			continue;
		}

		match rng.random_range(0..4) {
			0 => {
				let byte_index = rng.random_range(0..fuzzed_signature.len());
				let bit_index = rng.random_range(0..8);
				fuzzed_signature[byte_index] ^= 1 << bit_index;
			},
			1 => {
				let byte_index = rng.random_range(0..fuzzed_signature.len());
				let previous = fuzzed_signature[byte_index];
				let mut new_value = rng.random();
				while new_value == previous {
					new_value = rng.random();
				}
				fuzzed_signature[byte_index] = new_value;
			},
			2 => {
				let byte_index = rng.random_range(0..fuzzed_signature.len());
				if fuzzed_signature[byte_index] != 0 {
					fuzzed_signature[byte_index] = 0;
				} else {
					fuzzed_signature[byte_index] = rng.random_range(1..=255);
				}
			},
			_ => {
				let num_bytes_to_modify = rng.random_range(1..=5.min(fuzzed_signature.len()));
				for _ in 0..num_bytes_to_modify {
					let byte_index = rng.random_range(0..fuzzed_signature.len());
					let previous = fuzzed_signature[byte_index];
					let mut new_value = rng.random();
					while new_value == previous {
						new_value = rng.random();
					}
					fuzzed_signature[byte_index] = new_value;
				}
			},
		}

		assert!(
			!keypair.verify_msg(&test.msg, &fuzzed_signature),
			"Fuzzed signature unexpectedly passed verification for count {}",
			test.count
		);
	}
}

/// Thin adapter so the KAT harness can share one body across parameter-set modules.
trait HasNistKatApi {
	fn public_bytes(&self) -> Vec<u8>;
	fn secret_bytes(&self) -> Vec<u8>;
	fn verify_msg(&self, msg: &[u8], sig: &[u8]) -> bool;
	fn sign_msg(&self, msg: &[u8], hedge: Option<&SensitiveBytes32>) -> Vec<u8>;
}

macro_rules! impl_has_nist_kat_api {
	($module:ident) => {
		impl HasNistKatApi for qp_rusty_crystals_dilithium::$module::Keypair {
			fn public_bytes(&self) -> Vec<u8> {
				self.public().to_bytes().to_vec()
			}

			fn secret_bytes(&self) -> Vec<u8> {
				self.secret().to_bytes().to_vec()
			}

			fn verify_msg(&self, msg: &[u8], sig: &[u8]) -> bool {
				self.verify(msg, sig, None)
			}

			fn sign_msg(&self, msg: &[u8], hedge: Option<&SensitiveBytes32>) -> Vec<u8> {
				self.sign(msg, None, hedge).expect("Signing should succeed").to_vec()
			}
		}
	};
}

impl_has_nist_kat_api!(ml_dsa_44);
impl_has_nist_kat_api!(ml_dsa_65);
impl_has_nist_kat_api!(ml_dsa_87);

#[test]
fn test_verify_invalid_signature() {
	use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;

	let mut entropy1 = get_random_bytes();
	let mut entropy2 = get_random_bytes();
	let mut entropy3 = get_random_bytes();
	let keys_1 = Keypair::generate(&mut entropy1);
	let keys_2 = Keypair::generate(&mut entropy2);
	let keys_3 = Keypair::generate(&mut entropy3);

	let message = b"Hello, Resonance!";
	let signature = keys_2.sign(message, None, None).unwrap();

	assert!(!keys_1.verify(message, signature.as_slice(), None));
	assert!(!keys_3.verify(message, signature.as_slice(), None));
}
